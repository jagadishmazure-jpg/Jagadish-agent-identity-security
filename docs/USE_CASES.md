# Use cases

Each row is something a small or mid-sized security team asks, the command that answers it on the
fictional Kestrel Ridge Mortgage tenant, and what the synthetic run shows. Numbers come from the commands
(rendered and checked in CI where the component docs show them); all data is synthetic.

| # | Question | Command | What the synthetic run shows |
|---|---|---|---|
| 1 | How exposed is our identity estate overall? | `idsec scan` | Three area scores and an overview of 35.8 (F) with 47 findings |
| 2 | Who can reach Global Administrator or production? | `idsec paths --people` | 48 standing paths, riskiest first, each step explained |
| 3 | What would the fix plan change? | `idsec simulate` | Overview 35.8 to 90.5; paths 48 to 13 |
| 4 | Did someone weaken Conditional Access since the last review? | `idsec drift` | 6 changes found, 3 unapproved weakenings rolled back after approval, one needing two approvers |
| 5 | If we enforce the legacy-authentication block, who breaks? | `idsec impact` | 5 accounts, 2 of them excused from MFA for a scanner; no emergency account in scope |
| 6 | Would a stolen session cookie still work? | `idsec session` | 4 of 4 session checks fail today; a report-only set closes them |
| 7 | Is mail being forwarded out, or files shared anonymously? | `idsec m365` | 9 findings across 7 checks, 5 look-alikes cleared |
| 8 | A browser extension went rogue. What do we do? | `idsec extension` | 1 risky extension, 3 replayed sessions; revoke and org-wide block only after a person approves |
| 9 | The SOC closed an incident. What do we harden? | `idsec incident-link --out out/` | 14 hardening tasks for 5 confirmed incidents, none for the benign one; preview file only |
| 10 | How does an ordinary domain user become domain admin? | `idsec ad-tier0` | 7 paths; fixing one group cuts 4; 4 fixes cut all |
| 11 | Are our AI agents over-privileged? | `idsec findings --area emerging` | Agent findings such as a shared identity and tools beyond purpose |
| 12 | Can the explainer be talked into unsafe answers? | `idsec injection` | Guard on: 0 of 3 injections obeyed |
| 13 | Can I send these findings to the SOC? | `idsec soc-export` | Alerts in the companion SOC's schema |
| 14 | Is every claim still true after a change? | `idsec gate` | 21 of 21 release checks |
