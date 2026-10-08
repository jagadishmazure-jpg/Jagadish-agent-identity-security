# Limitations

What this repository does not do, or does not yet know. Read this before relying on any result.

## Nothing is deployed, nothing has run against a real tenant

* The live collectors are written and tested against a fake transport only. Real API responses may
  differ, especially for newer endpoints (Foundry agents, Entra Agent ID sponsors).
* The Terraform and Bicep stacks are validated, linted, scanned and plan-tested with mocked providers;
  they have never been applied.
* The deploy and teardown workflows have never run past their gate.
* No container image for the scan job exists.
* The Foundry chat-client path for the explainer agent has never been run.

## Measurement limits

* Precision and recall of 1.0 are a regression check on synthetic data written by the same author.
* Injection results come from three seeded cases and a deterministic mock client.
* Runtime figures are from a small synthetic tenant on one machine.

## Modelling limits

* `config/roles.yaml` covers common escalation routes, not every Entra role, Graph permission or Azure
  action.
* Conditional Access is reduced to users, groups, roles, MFA or authentication strength, and client app
  types. Locations, device filters and risk conditions are not modelled, and Conditional Access is not
  subtracted from paths.
* Edge ease values are judgement, not measured probabilities.
* No administrative units, restricted management units, management groups or on-premises Active
  Directory.
* SaaS coverage is a file import of admin accounts, not a connector.

## Permission caveats

* `Microsoft.CognitiveServices/accounts/AIServices/agents/read` also allows reading threads and messages.
* `AuditLog.Read.All` exposes sign-in logs; `signInActivity` needs Entra ID P1 or P2.

## Operational gaps (planned)

* Ingestion of results into a workspace table; trends across scans.
* Prompt Shields instead of the regex phrase screen.
* Persistent approval store; management group scope; signed scan image.
