# Best practices

The identity and engineering practices this repository follows or checks for, each labelled
**Built** (implemented and tested here) or **Planned** (designed, not built). Nothing is deployed.

## Identity practices the rules check in a tenant

| Practice | Rule(s) | Status |
|---|---|---|
| No standing admin roles; use PIM with MFA, justification and approval | P01, P02 | Built |
| Workload identities scoped to the resources they touch | P03 | Built |
| No tenant-control app permissions without strong reason | P04 | Built |
| Non-admins have no standing route to crown jewels | P05 | Built |
| Guests and external apps hold no write or admin rights | P06, P07 | Built |
| User consent restricted to verified publishers | P08 | Built |
| MFA registered and enforced by Conditional Access, exclusions reviewed | F01, F02 | Built |
| Dormant accounts disabled | F03 | Built |
| Emergency accounts use phishing-resistant methods | F04 | Built |
| Legacy authentication blocked | F05 | Built |
| Key Vault uses Azure RBAC, not access policies | F06 | Built |
| SaaS admins go through SSO | F07 | Built |
| Short-lived app credentials, or federation instead | E01 | Built |
| Secrets rotated and given expiry dates | E02, E03 | Built |
| One credential per consumer | E04 | Built |
| Every workload identity has an active owner | E05 | Built |
| Every agent identity has an active sponsor | E06 | Built |
| Agents have no write, admin or secret rights they do not need | E07, E08 | Built |
| Agent tools limited to the agent's purpose | E09 | Built |
| Agent connections use Entra ID auth, not keys | E10 | Built |
| One identity per agent | E11 | Built |
| Federated credentials pinned to protected environments | E12 | Built |
| Agents that read untrusted content have no route to crown jewels | E13 | Built |
| Continuous evaluation from sign-in logs | none | Planned |

## Practices in the scanner itself

| Practice | How | Status |
|---|---|---|
| Least privilege for the scanner | Custom role of reads, secret metadata only, Graph `.Read` permissions | Built (never deployed) |
| No stored credentials | OIDC federation pinned to GitHub Environments | Built (never deployed) |
| Read-only enforced in code | Transport refuses non-GET and non-allow-listed hosts | Built |
| Humans approve, tools propose | Digest-bound approvals, dual control, TTL, dry run only | Built |
| Model never decides | Read-only gateway, quoting, answer validation | Built |
| Output encoding | HTML escaping with CSP hash, CSV formula guard, markdown escaping | Built |
| Keyless logging | Workspace local auth disabled; diagnostic settings | Built (never deployed) |
| Docs cannot drift from code | Rendered outputs and excerpts, checked in CI | Built |
| Supply chain | SHA-pinned actions, Dependabot, CodeQL, gitleaks, SBOM | Built |
| Prompt Shields instead of a regex screen | Azure AI Content Safety | Planned |
| Results into a workspace table | Logs Ingestion API and a data collection rule | Planned |
| Trend across scans | Store scores per scan, chart them | Planned |
| Signed container image for the scan job | Build, sign, push to a private registry | Planned |
| Management group scope | Role and assignments at management group | Planned |
