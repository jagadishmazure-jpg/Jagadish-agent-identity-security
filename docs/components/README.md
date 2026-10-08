# Component docs

One document per part of the pipeline, each with the same 16 sections (purpose, architecture, how it
works, key files, code excerpts, configuration, commands, real output, tests, guardrails, security,
observability, failure modes, Azure mapping, limitations, interview talking points). Outputs and code
excerpts are rendered from the current code and checked in CI.

| File | What it does |
|---|---|
| `synthetic-data.md` | The deterministic fictional tenant and its planted weaknesses |
| `collectors.md` | Read-only live collectors and offline import |
| `inventory.md` | Normalising raw data into one typed inventory |
| `identity-graph.md` | The "can control or act as" graph |
| `privilege-paths.md` | Paths to crown jewels and blast radius |
| `detections.md` | The 28 rules |
| `scoring.md` | Area scores and grades |
| `findings-reports.md` | HTML, markdown, CSV, JSON and executive summary |
| `remediation.md` | Plan, approvals and simulation (dry run only) |
| `explainer-agent.md` | The Agent Framework explainer and its guardrails |
| `mcp-server.md` | Read-only MCP tools |
| `soc-export.md` | Findings as SOC alerts for the companion SOC repository |
| `metrics-gate.md` | Metrics from real runs and the 14-check release gate |
