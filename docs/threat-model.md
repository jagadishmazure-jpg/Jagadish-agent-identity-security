# Threat model

What can go wrong with the scanner itself, and how each risk is handled. Three lenses: STRIDE for the
system, the OWASP Top 10 for LLM Applications for the agent, and MITRE ATLAS for AI-specific techniques.
The weaknesses the scanner *finds* in a tenant are mapped to MITRE ATT&CK in the
[detections catalogue](detections-catalog.md).

## Assets

* Read access to a whole tenant (the reader identity).
* Scan results: lists of privileged identities and attack paths.
* The integrity of findings, scores and remediation approvals.

## STRIDE

| Threat | Example | Control | Where |
|---|---|---|---|
| Spoofing | A workflow from a fork or another branch requests a token | Federated subject pinned to `repo:<owner>/<repo>:environment:<env>`; environments with reviewers | `infra/terraform/main.tf`, `identity.bicep` |
| Spoofing | An agent or service principal approves remediation | `approve` refuses `agent:`, `sp:`, `mcp:` and anyone not a configured, enabled person | `remediation.py` |
| Tampering | An approval is reused for a changed plan item | Approval bound to the item's SHA-256 digest; 24h TTL | `remediation.py` |
| Tampering | A collector bug issues a write | Transport refuses everything except GET (and the Resource Graph query POST) to allow-listed HTTPS hosts | `collectors/http.py`, gate |
| Repudiation | Who asked the agent what | Gateway records every tool call | `tools.py` |
| Information disclosure | Secret values leak into results | Role has `readMetadata`, not `get`; inventory has no value field | role JSON, `inventory.py` |
| Information disclosure | Reports leak via a public repo | `out/` and `refs/` git-ignored; reports are never committed | `.gitignore` |
| Denial of service | Throttling loop against Graph | Bounded Retry-After retries, then a clear error; job retry 0 | `http.py`, `job.tf` |
| Elevation of privilege | The scanner identity is over-granted | Custom role of reads; tests forbid built-in privileged roles | `tests/test_iac.py` |

## OWASP Top 10 for LLM Applications

| Risk | How it applies | Control |
|---|---|---|
| LLM01 Prompt injection | Display names, notes and agent instructions in tool results | Quoted as untrusted data; closing tags neutralised; answer validation; measured with guard on and off |
| LLM02 Sensitive information disclosure | Agent repeats secrets | No secret values exist in the inventory |
| LLM05 Improper output handling | Model output rendered in HTML | Reports are built from code results, escaped, CSP with script hash |
| LLM06 Excessive agency | Agent changes the tenant | Seven read-only tools; no approval or execution tool |
| LLM09 Misinformation | Invented findings or "all clear" claims | Validator rejects unknown IDs and clean claims while findings are open |

The scanner also *finds* these risks in scanned agents: tools beyond purpose (excessive agency), agents
reading untrusted content with a path to a crown jewel (prompt injection), key-based connections.

## MITRE ATLAS

| Technique | Relevance | Control |
|---|---|---|
| AML.T0051.001 LLM Prompt Injection: Indirect | Tenant text reaching the explainer | Quoting, validation, read-only tools |
| AML.T0053 (plugin or agent tool compromise) | A tool used to act beyond its purpose | No write tools; MCP tools annotated read-only and checked by the gate |
| AML.T0054 LLM Jailbreak | Instructions to ignore rules | Code computes results; the model cannot change them |

## Residual risks

* The phrase screen is a regex; it is an indicator, not a defence. Prompt Shields would be the
  production choice (planned).
* `AIServices/agents/read` also covers threads and messages; an adopter should scope it to the projects
  they mean to scan.
* `AuditLog.Read.All` exposes sign-in logs to the scanner identity.
* The live collectors have not been run, so API-side surprises are possible.
