# Changelog

All notable changes to this project are documented here.

## Unreleased

- Synthetic Graph and ARM-shaped tenant for a fictional mortgage lender with 47 planted risks across 28
  rules, look-alikes that must not fire, and a drift check.
- Normaliser for users, groups, apps, managed identities, external apps, Entra agent identities, PIM,
  Conditional Access, Azure RBAC, Key Vault metadata, Foundry agents and SaaS admins.
- Identity graph with shortest and riskiest paths to four crown jewels, blast radius, and a PIM-eligible
  view.
- 28 detections mapped to MITRE ATT&CK, MITRE ATLAS, OWASP Top 10 for LLM Applications, CIS Controls and
  Zero Trust; posture scores per area.
- Remediation plan with Terraform and Bicep snippets, digest-bound approvals with dual control and expiry,
  dry-run execution and a what-if simulation.
- Reports (static HTML with CSP, markdown, CSV, JSON, executive summary) and SOC alert export for
  Jagadish-azure-ai-soc.
- Explainer agent on Microsoft Agent Framework with a deterministic mock model, a Foundry adapter path,
  prompt-injection guardrails and answer validation; read-only MCP server.
- Posture packs on synthetic, labelled data: configuration drift with human-approved rollback, report-only
  impact replay, Entra ID session hardening, Exchange Online and SharePoint checks, malicious-extension
  cookie theft with approved revoke and organization-wide block, SOC incident to hardening task links, and
  on-premises AD Tier 0 checks with choke-point ranking; seven new release-gate checks and a hashed brand check in CI.
- Offline and live read-only collectors (live tested against a fake cloud only).
- Terraform and Bicep for a least-privilege reader identity, custom read-only role, Log Analytics,
  optional scan job and private networking; gated deploy and teardown workflows with OIDC.
