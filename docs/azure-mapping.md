# Azure mapping

Where each piece of data comes from, which Microsoft service already covers part of the same ground, and
what this repository adds. "Read" means the live collector is written for it (never run); everything is
exercised offline on the fictional tenant.

## Data sources

| Area | Service | API (read) | Used for |
|---|---|---|---|
| People and guests | Entra ID | Graph `users` with `signInActivity`, `reports/authenticationMethods/userRegistrationDetails` | Dormant accounts, MFA registration, phishing-resistant methods |
| Groups | Entra ID | Graph `groups`, `members` | Transitive membership, role-assignable groups, CA exclusions |
| Apps and service principals | Entra ID | Graph `applications`, `servicePrincipals`, owners, `federatedIdentityCredentials` | Ownership, credentials, federated trust, external apps |
| Permissions and consent | Entra ID | Graph `appRoleAssignedTo`, `oauth2PermissionGrants` | Tier 0 app permissions, tenant-wide consent |
| Directory roles | PIM | Graph `roleManagement/directory/roleAssignmentScheduleInstances`, `roleEligibilitySchedules` | Standing, activated and eligible admin roles |
| Conditional Access | Entra ID | Graph `identity/conditionalAccess/policies` | Enforced MFA, legacy authentication blocking |
| Agent identities | Entra Agent ID | Graph service principals typed `agentIdentity`, blueprints, sponsors | Unsponsored and shared agent identities |
| Azure roles | Azure RBAC and PIM for Azure resources | Resource Graph `authorizationresources`; ARM `roleEligibilityScheduleInstances` | Standing Owner, workload subscription rights, paths |
| Resources and identities | ARM | Resource Graph `resources` | Which identity runs where (VMs, apps, jobs, Logic Apps) |
| Secrets | Key Vault | `GET /secrets` (metadata) | Expiry, rotation, shared credentials, access model |
| Agents, tools, connections | Foundry | Project agents (`assistants`) API; ARM `connections` | Agent tools beyond purpose, key-based connections, untrusted input |
| SaaS admins | SaaS exports | Files | Admins outside SSO |

## Overlap with Microsoft services

| Service | What it already does | What this repository adds |
|---|---|---|
| Microsoft Entra ID Protection and identity secure score | Risky users and sign-ins; recommendations | Graph-based paths across directory roles, app permissions, Azure RBAC and agents |
| PIM | Just-in-time roles, access reviews, alerts for permanent assignments | Shows how many paths disappear when roles are eligible (88 standing vs 92 with activation) |
| Entra Agent ID | Identities, blueprints and sponsors for agents | Rules over sponsorship, shared identities and agent privilege, joined to Foundry tools |
| Defender for Identity | Identity threat detection and posture for AD and Entra ID | A transparent, open rule set with tests; SOC export as context |
| Defender for Cloud | CSPM, attack path analysis for cloud resources, AI threat protection | Adds directory roles, app permissions and agent tool chains to the path picture |
| Microsoft Graph | The data | Normalisation into one model for humans, workloads and agents |
| Foundry | Agent hosting, tools, connections | Least-purpose tool checks and untrusted-input path checks |

This is a portfolio project, not a replacement for any of these products. In a real environment the
native services remain the primary controls; this shows how the reasoning works and how it can be tested.

## Permissions needed

See [adopt this](adopt-this.md): seven Graph application permissions, all `.Read`, and the custom
"Identity Posture Reader" role.
