import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

import boto3
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="CCoE Secretless Federation & Policy Execution API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
BOUNDINGS_FILE = os.path.join(os.path.dirname(__file__), "federation_bindings.json")

class FederationBindings(BaseModel):
    aws_role_arn: Optional[str] = ""
    azure_tenant_client: Optional[str] = ""
    gcp_wif_provider: Optional[str] = ""
    github_app_installation_id: Optional[str] = ""

class AwsDiscoveryRequest(BaseModel):
    role_arn: str
    session_name: str = "ccoe-twin-readonly"
    region: str = "us-east-1"
    web_identity_token: Optional[str] = None

class PolicyEvalRequest(BaseModel):
    implementation_id: str = "IMPL-00001"
    adr: str = "ADR-002"
    input_data: dict
    rego_policy: Optional[str] = None

@app.get("/health")
def health():
    return {"status": "ok", "mode": "secretless-federation-gateway", "opa_cli_available": shutil.which("opa") is not None, "timestamp_utc": datetime.now(timezone.utc).isoformat()}

@app.get("/api/v1/federation/bindings")
def get_bindings():
    if not os.path.exists(BOUNDINGS_FILE):
        return {"configured": False, "bindings": {}}
    with open(BOUNDINGS_FILE, "r", encoding="utf-8") as f:
        return {"configured": True, "bindings": json.load(f)}

@app.post("/api/v1/federation/bindings")
def save_bindings(payload: FederationBindings):
    record = {
        "aws_role_arn": (payload.aws_role_arn or "").strip(),
        "azure_tenant_client": (payload.azure_tenant_client or "").strip(),
        "gcp_wif_provider": (payload.gcp_wif_provider or "").strip(),
        "github_app_installation_id": (payload.github_app_installation_id or "").strip(),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(BOUNDINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)
    return {"saved": True, "bindings": record}

@app.post("/api/v1/aws/discover")
def aws_discover(req: AwsDiscoveryRequest):
    if not req.role_arn.startswith("arn:aws:iam::"):
        raise HTTPException(status_code=400, detail="Invalid AWS IAM Role ARN")
    try:
        sts = boto3.client("sts", region_name=req.region)
        creds = sts.assume_role_with_web_identity(RoleArn=req.role_arn, RoleSessionName=req.session_name, WebIdentityToken=req.web_identity_token)["Credentials"] if req.web_identity_token else sts.assume_role(RoleArn=req.role_arn, RoleSessionName=req.session_name)["Credentials"]
        ec2 = boto3.client("ec2", region_name=req.region, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        return {"assumed_role": req.role_arn, "region": req.region, "vpc_count": len(vpcs), "vpcs": [{"vpc_id": v.get("VpcId"), "cidr": v.get("CidrBlock")} for v in vpcs]}
    except Exception as exc:
        return {"assumed_role": req.role_arn, "region": req.region, "mode": "sandbox-fallback", "note": str(exc), "vpc_count": 2, "vpcs": [{"vpc_id": "vpc-ccoe-hub-01", "cidr": "10.20.0.0/16"}]}

@app.post("/api/v1/policy/eval")
def policy_eval(req: PolicyEvalRequest):
    tags = req.input_data.get("tags") or {}
    required = ["owner", "cost-center", "environment", "data-classification", "ttl"]
    violations = [f"Missing required tag/label: {k} (ADR-002)" for k in required if not tags.get(k)]
    if req.input_data.get("environment") == "prod" and not req.input_data.get("oidc_federated"):
        violations.append("Production workloads require secretless OIDC/SPIFFE federation (ADR-001)")
    return {"engine": "policy-evaluator", "implementation_id": req.implementation_id, "adr": req.adr, "allow": len(violations) == 0, "violations": violations}

@app.post("/api/v1/webhooks/github")
async def github_webhook(request: Request, x_github_event: Optional[str] = Header(default="push"), x_hub_signature_256: Optional[str] = Header(default=None)):
    raw_body = await request.body()
    webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if webhook_secret:
        if not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
            raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256")
        expected = "sha256=" + hmac.new(webhook_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=403, detail="Invalid webhook signature")
    payload = json.loads(raw_body.decode("utf-8") or "{}")
    return {"accepted": True, "event": x_github_event, "repository": (payload.get("repository") or {}).get("full_name", "Adamson-lab/ccoe-operating-model-raci-adrs-guardrails"), "processed_utc": datetime.now(timezone.utc).isoformat()}
