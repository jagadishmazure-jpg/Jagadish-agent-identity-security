# Architecture

How the pieces fit, from raw tenant data to findings, paths, a remediation plan, an explainer agent and
SOC alerts. Every arrow below is implemented and tested offline unless marked *planned*.

## Pipeline

```mermaid
flowchart LR
  subgraph Sources
    SY[idsec synth<br/>fictional tenant] --> RAW
    LV[idsec collect --live<br/>read-only, never run] -.-> RAW
    OF[idsec collect --offline<br/>exported files] --> RAW
  end
  RAW[(data/tenant<br/>Graph, ARM, Key Vault,<br/>Foundry, SaaS files)] --> INV[inventory]
  INV --> G[identity graph]
  G --> P[paths + blast radius]
  INV & G & P --> D[28 detections]
  D --> S[scores]
  D --> R[reports]
  D --> PL[remediation plan]
  PL --> AP[approvals, dry run]
  PL --> SIM[simulation + re-scan]
  D --> SOC[SOC export]
  D & P & S --> GW[read-only tool gateway]
  GW --> AG[explainer agent]
  GW --> MCP[MCP server]
  D & SIM --> M[metrics + gate]
```

## Layers

| Layer | Modules | What it guarantees |
|---|---|---|
| Collection | `collectors/http.py`, `live.py`, `offline.py`, `synth.py` | Only reads; the same file format whether synthetic, exported or collected |
| Model | `inventory.py`, `graph.py` | One typed model for humans, workload identities and agents; edges carry reasons |
| Analysis | `paths.py`, `detections.py`, `scoring.py` | Deterministic results; every rule reports how much it evaluated |
| Action | `remediation.py`, `report.py`, `soc.py` | Proposals only; outputs escape tenant text |
| Explanation | `tools.py`, `llm.py`, `guardrails.py`, `mcp_server.py` | Read-only tools; tenant text quoted; answers validated |
| Assurance | `metrics.py`, `gate.py`, `scripts/render_docs.py` | Numbers come from runs; CI fails on drift or a broken guarantee |

## Trust boundaries

```mermaid
flowchart TB
  subgraph Untrusted["Untrusted: anyone who can edit an object in the tenant"]
    N[display names, descriptions, notes]
    I[agent instructions and the content agents read]
  end
  subgraph Code["Trusted code"]
    C[collectors -> inventory -> graph -> rules]
  end
  subgraph Model["Model (never trusted to decide)"]
    A[explainer agent]
  end
  N & I -->|data only| C
  C -->|quoted as untrusted_data| A
  A -->|validated against code facts| OUT[answer]
  C -->|escaped| REP[HTML / CSV / markdown]
```

## Data flow for a live scan (written, not run)

1. A workflow job in a protected GitHub Environment gets an OIDC token for the reader identity.
2. `idsec collect --live` reads Microsoft Graph, Azure Resource Manager, Key Vault metadata and Foundry
   agents through the read-only transport and writes files to a folder.
3. `IDSEC_DATA=<folder> idsec scan` runs the same pipeline as the offline demo, with the current time.
4. `idsec soc-export` produces alert rows; `idsec report` produces the artefacts.

## Where to read more

* Each component: [components](components/README.md).
* Deployment shape: [infra](infra/README.md) and [deployment](deployment.md).
* Decisions: [ADRs](adr/README.md).
