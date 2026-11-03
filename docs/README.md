# Documentation

Commands and numbers in these pages are rendered from the code and checked in CI.

## Reading order

1. [Architecture](architecture.md): the pipeline and trust boundaries.
2. [Use cases](USE_CASES.md): the questions it answers, with the command for each.
3. [Components](components/README.md): one doc per part, starting with synthetic data and detections.
4. Posture packs: [drift and rollback](components/drift-rollback.md), [report-only impact](components/report-only-impact.md),
   [session hardening](components/session-hardening.md), [Exchange and SharePoint](components/m365-posture.md),
   [extension theft](components/extension-theft.md), [incident links](components/incident-link.md),
   [AD Tier 0](components/ad-tier0.md).
5. [Threat model](threat-model.md) and [metrics](metrics.md): how it could fail and how it is measured.
6. [Limitations](limitations.md): what it does not do.
7. [Adopt this](adopt-this.md) and [deployment](deployment.md): trying it on a real tenant, safely.
8. [Presentation guide](PRESENTATION_GUIDE.md) and [interview guide](interview-guide.md).

| File | What it does |
|---|---|
| `architecture.md` | Pipeline, layers, trust boundaries |
| `USE_CASES.md` | Questions it answers, the command for each and what the synthetic run shows |
| `PRESENTATION_GUIDE.md` | A ten-minute demo script and what to say about the numbers |
| `threat-model.md` | STRIDE, OWASP LLM and MITRE ATLAS view of the scanner itself |
| `detections-catalog.md` | All 28 rules with explanations, fixes and mappings |
| `metrics.md` | Every metric from real runs, with how to read them |
| `azure-mapping.md` | Data sources and overlap with Microsoft services |
| `soc-integration.md` | How findings reach the companion SOC repository |
| `adopt-this.md` | Safe, ordered steps to try it on your own tenant |
| `deployment.md` | What would be deployed and how (nothing is deployed) |
| `best-practices.md` | Practices checked or followed, labelled Built or Planned |
| `interview-guide.md` | Pitch, walkthrough and likely questions |
| `limitations.md` | What it does not do or does not yet know |
| `components/` | One 16-section doc per component |
| `infra/` | Identity, role, scan job, Terraform, Bicep and workflows |
| `adr/` | Architecture decision records |
