import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="CCoE FastAPI Backend (AWS-First)", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

BINDINGS_PATH = os.path.join(os.path.dirname(__file__), "federation_bindings.json")

class FederateRequest(BaseModel):
    aws_role_arn: Optional[str] = ""
    azure_tenant_client: Optional[str] = ""
    gcp_wif_provider: Optional[str] = ""
    github_app_installation_id: Optional[str] = ""
    aws_region: str = "us-east-1"
    web_identity_token: Optional[str] = None

class LintRequest(BaseModel):
    implementation_id: str = "IMPL-00001"
    adr: str = "ADR-002"
    payload: Dict[str, Any] = {}
    rego_policy: Optional[str] = None

class DispatchRequest(BaseModel):
    implementation_id: str = "IMPL-00001"
    subsystem: str = "S01"
    auth_mode: str = "oidc-jwt"
    execution_mode: str = "dry-run"
    scenario: str = "steady-state"

DEFAULT_REGO = ""package ccoe.guardrail

default allow := false

required_tags := ["owner", "cost-center", "environment", "data-classification", "ttl"]

allow if {
    every k in required_tags {
        input.tags[k] != ""
    }
}

violations contains msg if {
    some k in required_tags
    not input.tags[k]
    msg := sprintf("Missing required tag/label: %s (ADR-002)", [k])
}

violations contains msg if {
    input.environment == "prod"
    input.oidc_federated == false
    msg := "Production workloads require OIDC/SPIFFE federation (ADR-001)"
}""

@app.get("/health")
def health():
    return {
        "status": "ok",
        "runtime": "python-fastapi",
        "primary_cloud": "AWS",
        "opa_cli_available": shutil.which("opa") is not None,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/v1/federate")
def federate(req: FederateRequest):
    role = (req.aws_role_arn or "").strip()
    if role and not role.startswith("arn:aws:iam::"):
        raise HTTPException(status_code=400, detail="aws_role_arn must start with arn:aws:iam::")

    providers = []
    if role: providers.append("AWS-OIDC")
    if (req.azure_tenant_client or "").strip(): providers.append("Azure-WIF")
    if (req.gcp_wif_provider or "").strip(): providers.append("GCP-WIF")
    if (req.github_app_installation_id or "").strip(): providers.append("GitHub-App:" + req.github_app_installation_id.strip())

    aws_discovery: Dict[str, Any] = {"connected": False}
    if role:
        try:
            sts = boto3.client("sts", region_name=req.aws_region)
            if req.web_identity_token:
                creds = sts.assume_role_with_web_identity(
                    RoleArn=role,
                    RoleSessionName="ccoe-fastapi-readonly",
                    WebIdentityToken=req.web_identity_token,
                )["Credentials"]
            else:
                creds = sts.assume_role(
                    RoleArn=role,
                    RoleSessionName="ccoe-fastapi-readonly",
                )["Credentials"]
            ec2 = boto3.client(
                "ec2",
                region_name=req.aws_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            aws_discovery = {
                "connected": True,
                "region": req.aws_region,
                "vpc_count": len(vpcs),
                "vpcs": [{"vpc_id": v.get("VpcId"), "cidr": v.get("CidrBlock")} for v in vpcs],
            }
        except Exception as exc:
            aws_discovery = {
                "connected": False,
                "mode": "sandbox-fallback",
                "region": req.aws_region,
                "note": str(exc),
                "vpc_count": 2,
                "vpcs": [{"vpc_id": "vpc-ccoe-aws-hub", "cidr": "10.10.0.0/16"}],
            }

    record = {
        "aws_role_arn": role,
        "azure_tenant_client": (req.azure_tenant_client or "").strip(),
        "gcp_wif_provider": (req.gcp_wif_provider or "").strip(),
        "github_app_installation_id": (req.github_app_installation_id or "").strip(),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(BINDINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return {
        "federated": len(providers) > 0,
        "providers": providers,
        "aws_discovery": aws_discovery,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/v1/lint")
def lint(req: LintRequest):
    opa_bin = shutil.which("opa")
    if opa_bin:
        with tempfile.TemporaryDirectory() as tmp:
            p_file = os.path.join(tmp, "policy.rego")
            i_file = os.path.join(tmp, "input.json")
            with open(p_file, "w", encoding="utf-8") as pf:
                pf.write(req.rego_policy or DEFAULT_REGO)
            with open(i_file, "w", encoding="utf-8") as inf:
                json.dump(req.payload, inf)
            proc = subprocess.run(
                [opa_bin, "eval", "-d", p_file, "-i", i_file, "data.ccoe.guardrail", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                return {
                    "engine": "opa-cli",
                    "implementation_id": req.implementation_id,
                    "adr": req.adr,
                    "opa_result": json.loads(proc.stdout),
                }

    tags = req.payload.get("tags") if isinstance(req.payload.get("tags"), dict) else req.payload
    required = ["owner", "cost-center", "environment", "data-classification", "ttl"]
    violations = [f"Missing required tag/label: {k} (ADR-002)" for k in required if not tags.get(k)]
    if req.payload.get("environment") == "prod" and req.payload.get("oidc_federated") is False:
        violations.append("Production workloads require OIDC/SPIFFE federation (ADR-001)")
    if req.payload.get("private_egress_only") is False:
        violations.append("Public egress not restricted to hub-spoke (ADR-004)")
    if req.payload.get("pii_scrubbed") is False:
        violations.append("PII/PAN/DLP redaction disabled (ADR-007)")
    if req.payload.get("hyok_hsm_active") is False:
        violations.append("Customer HYOK HSM key inactive (ADR-005)")
    if req.payload.get("pqc_tls_hybrid") is False:
        violations.append("Post-Quantum hybrid TLS disabled (ADR-001)")

    return {
        "engine": "fastapi-policy-evaluator",
        "implementation_id": req.implementation_id,
        "adr": req.adr,
        "pass": len(violations) == 0,
        "violations": violations,
        "evaluated_utc": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/v1/dispatch")
async def dispatch(
    req: DispatchRequest,
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
):
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if secret:
        raw = await request.body()
        if not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256=">):
            raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256")
        expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=403, detail="Invalid GitHub webhook signature")

    run_id = f"py-run-{int(datetime.now(timezone.utc).timestamp())}"
    return {
        "dispatched": True,
        "run_id": run_id,
        "implementation_id": req.implementation_id,
        "subsystem": req.subsystem,
        "auth_mode": req.auth_mode,
        "execution_mode": req.execution_mode,
        "scenario": req.scenario,
        "dispatched_utc": datetime.now(timezone.utc).isoformat(),
    }
