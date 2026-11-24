package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"
)

type FederateRequest struct {
    AWSRoleARN             string `json:"aws_role_arn"`
    AzureTenantClient      string `json:"azure_tenant_client"`
    GCPWIFProvider         string `json:"gcp_wif_provider"`
    GitHubAppInstallation  string `json:"github_app_installation_id"`
}

type LintRequest struct {
    ImplementationID string         `json:"implementation_id"`
    ADR              string         `json:"adr"`
    Payload          map[string]any `json:"payload"`
}

type DispatchRequest struct {
    ImplementationID string `json:"implementation_id"`
    Subsystem        string `json:"subsystem"`
    AuthMode         string `json:"auth_mode"`
    ExecutionMode    string `json:"execution_mode"`
    Scenario         string `json:"scenario"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(data)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Hub-Signature-256, X-GitHub-Event")
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next(w, r)
    }
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
    _, opaErr := exec.LookPath("opa")
    writeJSON(w, http.StatusOK, map[string]any{
        "status":           "ok",
        "runtime":          "go",
        "opa_cli_available": opaErr == nil,
        "timestamp_utc":    time.Now().UTC().Format(time.RFC3339),
    })
}

func handleFederate(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
        return
    }
    var req FederateRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
        return
    }
    if req.AWSRoleARN != "" && !strings.HasPrefix(req.AWSRoleARN, "arn:aws:iam::") {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aws_role_arn must start with arn:aws:iam::"})
        return
    }
    bound := []string{}
    if req.AWSRoleARN != "" { bound = append(bound, "AWS-OIDC") }
    if req.AzureTenantClient != "" { bound = append(bound, "Azure-WIF") }
    if req.GCPWIFProvider != "" { bound = append(bound, "GCP-WIF") }
    if req.GitHubAppInstallation != "" { bound = append(bound, "GitHub-App:"+req.GitHubAppInstallation) }

    b, _ := json.MarshalIndent(req, "", "  ")
    _ = os.WriteFile("federation_bindings.json", b, 0600)

    writeJSON(w, http.StatusOK, map[string]any{
        "federated":      len(bound) > 0,
        "providers":      bound,
        "secretless":     true,
        "timestamp_utc":  time.Now().UTC().Format(time.RFC3339),
    })
}

func handleLint(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
        return
    }
    var req LintRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
        return
    }
    required := []string{"owner", "cost-center", "environment", "data-classification", "ttl"}
    violations := []string{}
    for _, k := range required {
        val, ok := req.Payload[k]
        if !ok || strings.TrimSpace(fmt.Sprint(val)) == "" || fmt.Sprint(val) == "<nil>" {
            violations = append(violations, fmt.Sprintf("Missing required tag/label: %s (ADR-002)", k))
        }
    }
    if fmt.Sprint(req.Payload["environment"]) == "prod" {
        if oidc, ok := req.Payload["oidc_federated"].(bool); ok && !oidc {
            violations = append(violations, "OIDC/SPIFFE disabled in prod (ADR-001)")
        }
    }
    if egress, ok := req.Payload["private_egress_only"].(bool); ok && !egress {
        violations = append(violations, "Public egress not restricted to hub-spoke (ADR-004)")
    }
    if pii, ok := req.Payload["pii_scrubbed"].(bool); ok && !pii {
        violations = append(violations, "PII/PAN/DLP redaction disabled (ADR-007)")
    }
    if hyok, ok := req.Payload["hyok_hsm_active"].(bool); ok && !hyok {
        violations = append(violations, "Customer HYOK HSM key inactive (ADR-005)")
    }
    if pqc, ok := req.Payload["pqc_tls_hybrid"].(bool); ok && !pqc {
        violations = append(violations, "Post-Quantum hybrid TLS disabled (ADR-001)")
    }
    writeJSON(w, http.StatusOK, map[string]any{
        "implementation_id": req.ImplementationID,
        "adr":               req.ADR,
        "pass":              len(violations) == 0,
        "violations":        violations,
        "evaluated_utc":     time.Now().UTC().Format(time.RFC3339),
    })
}

func verifyGitHubSig(secret string, body []byte, sigHeader string) bool {
    if secret == "" { return true }
    if !strings.HasPrefix(sigHeader, "sha256=") { return false }
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(sigHeader))
}

func handleDispatch(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
        return
    }
    rawBody, err := io.ReadAll(r.Body)
    if err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unable to read body"})
        return
    }
    secret := os.Getenv("GITHUB_WEBHOOK_SECRET")
    if sig := r.Header.Get("X-Hub-Signature-256"); sig != "" || secret != "" {
        if !verifyGitHubSig(secret, rawBody, sig) {
            writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid X-Hub-Signature-256"})
            return
        }
    }
    var req DispatchRequest
    if err := json.Unmarshal(rawBody, &req); err != nil {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid dispatch JSON"})
        return
    }
    if req.ImplementationID == "" { req.ImplementationID = "IMPL-00001" }
    if req.AuthMode == "" { req.AuthMode = "oidc-jwt" }
    if req.ExecutionMode == "" { req.ExecutionMode = "dry-run" }
    runID := fmt.Sprintf("run-%d", time.Now().UTC().Unix())
    writeJSON(w, http.StatusAccepted, map[string]any{
        "dispatched":        true,
        "run_id":            runID,
        "implementation_id": req.ImplementationID,
        "subsystem":         req.Subsystem,
        "auth_mode":         req.AuthMode,
        "execution_mode":    req.ExecutionMode,
        "scenario":          req.Scenario,
        "dispatched_utc":    time.Now().UTC().Format(time.RFC3339),
    })
}

func main() {
    port := os.Getenv("PORT")
    if port == "" { port = "8080" }
    mux := http.NewServeMux()
    mux.HandleFunc("/health", withCORS(handleHealth))
    mux.HandleFunc("/api/v1/federate", withCORS(handleFederate))
    mux.HandleFunc("/api/v1/lint", withCORS(handleLint))
    mux.HandleFunc("/api/v1/dispatch", withCORS(handleDispatch))
    log.Printf("CCoE Go backend listening on :%s", port)
    log.Fatal(http.ListenAndServe(":"+port, mux))
}
