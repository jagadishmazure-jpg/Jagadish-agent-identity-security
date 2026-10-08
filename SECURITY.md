# Security policy

## Scope

This repository contains offline code, a synthetic identity tenant for a fictional mortgage lender,
read-only collectors and infrastructure templates. It holds no credentials, tenant or subscription
identifiers, model keys or real people, and its tests enforce that. The only GUID that does not start
with `00000000-` is Microsoft Graph's public application ID, allow-listed by a test.

## Reporting a vulnerability

1. Open a private security advisory on GitHub (Security tab, "Report a vulnerability"). Include the file,
   the problem and how to reproduce it.
2. If that button is not shown, open an issue titled `Security contact request` with no technical
   details, and I will reply with a private channel.

I aim to acknowledge a report within 5 working days. This is a personal portfolio maintained by one
person, so there is no formal SLA or bug bounty.

## Design choices that matter for security

- **Read-only by construction.** The live transport refuses anything but GET (and POST to Azure
  Resource Graph) before a request leaves the process. The custom Azure role has 19 read actions and two
  data actions: Key Vault secret metadata and Foundry agent definitions. No secret value is ever requested.
- **No secrets anywhere.** The reader is a managed identity; GitHub Actions reach it through a federated
  credential pinned to one protected environment. Log Analytics has shared keys disabled.
- **Remediation needs people.** Plans are dry runs. Approvals are bound to the item's digest, expire after
  24 hours, need two people for privileged changes and can never come from an agent or service principal.
  Live execution is not implemented on purpose.
- **Tenant text is untrusted.** Names, descriptions, notes and agent instructions are screened, quoted as
  data before they reach the model, never echoed as raw matches, and escaped in HTML and CSV. Answers are
  validated against facts computed by code.
- **Supply chain:** SHA-pinned actions, Dependabot, CodeQL (Python and Actions), gitleaks over full
  history, an SPDX SBOM, pinned Python dependencies, checkov with no skips, tflint and Terraform tests.
- **Deployment gated off** until `DEPLOY_ENABLED` is set; prod needs environment reviewers.

See [docs/threat-model.md](docs/threat-model.md).

## Supported versions

Only the `main` branch is maintained.
