# data/tenant

One folder per source. The live collectors write the same layout, so the scanner cannot tell the
difference between synthetic and collected data.

| File | What it does |
|---|---|
| `graph/` | Microsoft Graph objects: users, groups, applications, service principals (including agent identities), grants, roles, PIM, Conditional Access |
| `arm/` | Azure Resource Graph rows: subscriptions, resource groups, resources, role definitions and assignments, PIM eligibility, managed-identity federated credentials |
| `foundry/` | Foundry agent definitions with their tools |
| `keyvault/` | Secret metadata per vault (names, dates, tags; never a value) |
| `saas/` | Admin account exports from two SaaS apps |
