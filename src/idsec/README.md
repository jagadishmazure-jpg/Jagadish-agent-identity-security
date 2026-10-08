# src/idsec

The scanner, from raw files to findings, paths, scores, plans, reports and the explainer agent.

| File | What it does |
|---|---|
| `__init__.py` | Repository paths (config, data, detections) |
| `synth.py` | Generates the synthetic tenant and its planted risks |
| `collectors/` | Offline validator and the live, read-only collectors |
| `inventory.py` | Normalises Graph, ARM, Key Vault, Foundry and SaaS files into one inventory |
| `graph.py` | Builds the identity graph (who can control or act as what) |
| `paths.py` | Crown jewels, shortest and riskiest paths, blast radius |
| `detections.py` | The 28 rule implementations |
| `scoring.py` | Posture score per area and overall |
| `remediation.py` | Remediation plan with Terraform and Bicep snippets, approvals, dry-run execution and the what-if simulation |
| `report.py` | Static HTML, markdown, CSV, JSON and the executive summary |
| `soc.py` | Exports findings as SecurityAlert rows for Jagadish-azure-ai-soc |
| `guardrails.py` | Injection screen, untrusted-data quoting, answer validation, escaping |
| `tools.py` | The read-only tool gateway the agent and the MCP server use |
| `llm.py` | The explainer agent (Microsoft Agent Framework) with a deterministic mock model and a Foundry adapter |
| `mcp_server.py` | MCP server over the same read-only tools |
| `labels.py` | Reads the ground truth; only the metrics may import it |
| `metrics.py` | Precision and recall, path summary, injection matrix, runtime |
| `iac.py` | Summaries of the Terraform, Bicep, role and workflow files |
| `gate.py` | The 14-check release gate |
| `cli.py` | The `idsec` command |
