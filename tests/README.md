# tests

All offline: synthetic data, a fake cloud for the collectors, a mock model for the agent. `pytest -q` runs them.

| File | What it does |
|---|---|
| `conftest.py` | Shared fixtures (inventory, graph, results) and helpers |
| `test_synth_inventory.py` | Generator determinism and drift, mock identifiers, and the normaliser |
| `test_graph_paths.py` | Graph edges, crown jewels, shortest and riskiest paths, blast radius |
| `test_detections.py` | Catalogue integrity, every planted case, look-alikes that must not fire, and mutation tests per rule |
| `test_scoring_remediation.py` | Score maths, plan, digest-bound approvals, dry-run execution, simulation |
| `test_guardrails_agent.py` | Injection screen, quoting, answer validation, tool gateway, agent routing and the injection matrix, MCP |
| `test_reports_soc.py` | HTML escaping and CSP, CSV formula guard, reports, SOC alert schema |
| `test_collectors.py` | Read-only transport, paging, throttling, offline validation and a live round trip against a fake cloud |
| `test_iac.py` | Role, Terraform, Bicep and workflow structure, offline |
| `test_cli_metrics_gate.py` | Every CLI command, metrics and the release gate |
| `test_render_docs.py` | The doc renderer |
| `test_repo_hygiene.py` | Folder READMEs, doc sections, no dates, no real identifiers, honest claims, credit by link |
