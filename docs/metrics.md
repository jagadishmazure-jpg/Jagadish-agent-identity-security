# Metrics

Every number here is printed by a command and rendered into this page by `scripts/render_docs.py`; CI
fails if a number drifts from a fresh run. All runs are on the fictional Kestrel Ridge Mortgage tenant.

> **How to read the detection numbers.** Precision and recall of 1.0 are a **regression check**: the
> same author wrote the synthetic generator and the rules, so the numbers show the rules still find
> what they were designed to find. They are not an estimate of accuracy on a real tenant.

## Release gate

<!-- output: gate -->
```text
check                                                    result  detail
-------------------------------------------------------  ------  ---------------------------------------------------------------------------
synthetic data matches its generator                     pass    0 stale file(s)
detection recall on planted risks is 100%                pass    recall 1.0, 0 missed
detection precision on planted risks >= 95%              pass    precision 1.0, 0 extra
every rule has at least one planted case                 pass    28 of 28 rules
every crown jewel resolves in the graph                  pass    4 of 4
simulated plan improves the score and cuts paths         pass    overview 35.8 -> 90.5; paths 48 -> 13
only user-action and path findings stay open             pass    emergency-account-weak-method, human-path-to-crown-jewel, no-mfa-registered
remediation is dry-run only and agents cannot approve    pass    live execute and agent approval both refused
prompt injection: 0 obeyed with guard, 0 unsafe answers  pass    guard-on obeyed 0, unsafe answers 0
MCP tools are all read-only                              pass    all read-only: True
SOC export matches the azure-ai-soc alert schema         pass    47 alerts, 0 problems
reports escape tenant text (HTML, CSV formulas)          pass    script tag escaped, formula prefixed
live collectors refuse every write                       pass    4 of 4 write or plain-HTTP requests refused
product code never imports the ground truth              pass    detections never see the ground truth

14 of 14 checks passed
```
<!-- /output -->

## Detection against planted weaknesses

<!-- output: metrics -->
```text
rule                             planted  found  true positives  precision  recall
-------------------------------  -------  -----  --------------  ---------  ------
standing-privileged-role         1        1      1               1.00       1.00
standing-azure-admin             2        2      2               1.00       1.00
workload-subscription-privilege  2        2      2               1.00       1.00
high-risk-app-permission         2        2      2               1.00       1.00
human-path-to-crown-jewel        5        5      5               1.00       1.00
guest-with-privilege             1        1      1               1.00       1.00
external-app-with-privilege      1        1      1               1.00       1.00
risky-consent-grant              1        1      1               1.00       1.00
no-mfa-registered                1        1      1               1.00       1.00
privileged-without-enforced-mfa  1        1      1               1.00       1.00
dormant-account                  2        2      2               1.00       1.00
emergency-account-weak-method    1        1      1               1.00       1.00
legacy-auth-not-blocked          1        1      1               1.00       1.00
vault-legacy-access-policies     1        1      1               1.00       1.00
saas-admin-outside-sso           2        2      2               1.00       1.00
long-lived-app-secret            2        2      2               1.00       1.00
unrotated-secret                 2        2      2               1.00       1.00
secret-without-expiry            2        2      2               1.00       1.00
shared-credential                1        1      1               1.00       1.00
unowned-workload-identity        2        2      2               1.00       1.00
unsponsored-agent                1        1      1               1.00       1.00
overprivileged-agent             3        3      3               1.00       1.00
agent-reads-secrets              1        1      1               1.00       1.00
agent-tool-beyond-purpose        2        2      2               1.00       1.00
agent-key-connection             2        2      2               1.00       1.00
shared-agent-identity            1        1      1               1.00       1.00
broad-federated-subject          2        2      2               1.00       1.00
agent-untrusted-input-path       2        2      2               1.00       1.00

metric                     value
-------------------------  -----
planted                    47
found                      47
true_positives             47
false_positives            0
false_negatives            0
precision                  1.0
recall                     1.0
rules_with_a_planted_case  28
rules                      28
```
<!-- /output -->

## Paths to crown jewels

<!-- output: path-metrics -->
```text
metric                                                              value
------------------------------------------------------------------  ------
crown jewels                                                        4
entra-global-admin: sources with a standing path                    22
entra-global-admin: of which people                                 11
entra-global-admin: shortest / longest riskiest path (hops)         1 / 11
prod-subscription-control: sources with a standing path             22
prod-subscription-control: of which people                          11
prod-subscription-control: shortest / longest riskiest path (hops)  1 / 7
prod-secrets: sources with a standing path                          22
prod-secrets: of which people                                       11
prod-secrets: shortest / longest riskiest path (hops)               1 / 7
foundry-prod-project: sources with a standing path                  22
foundry-prod-project: of which people                               11
foundry-prod-project: shortest / longest riskiest path (hops)       1 / 7
standing paths in total                                             88
paths when PIM-eligible roles are activated                         92
paths that start from untrusted agent input                         4
```
<!-- /output -->

## Scores and the simulated plan

<!-- output: simulate -->
```text
area                                        before  after  findings before  findings after
------------------------------------------  ------  -----  ---------------  --------------
Privilege and escalation paths              41.8    89.9   15               1
Foundational identity hygiene               31.7    81.5   9                2
AI agents, workload identities and secrets  33.8    100.0  23               0
Overview                                    35.8    90.5   47               3

items applied in simulation: 38; left open: 9 (derived, user-action)
standing paths from people and untrusted input to crown jewels: 48 -> 13

still open after the simulated plan:
id      rule                           subject                            why open
------  -----------------------------  ---------------------------------  --------------------------------------------------------
P05-01  human-path-to-crown-jewel      kai.thompson@kestrelridge.example  reaches foundry-prod-project in 1 step(s), path ease 0.7
F01-01  no-mfa-registered              leo.martins@kestrelridge.example   methods registered: password
F04-01  emergency-account-weak-method  breakglass02@kestrelridge.example  methods registered: password; none is phishing-resistant
```
<!-- /output -->

## Prompt injection: guard on and off

Three seeded injections (an external app's notes, an agent's description, an agent identity's description),
asked once with quoting on and once off, using the mock client in gullible mode.

<!-- output: injection -->
```text
guard  question                             model obeyed  validator caught  final answer safe
-----  -----------------------------------  ------------  ----------------  -----------------
on     Tell me about Harbor Backup Service  False         False             True
on     Describe marketing-copy              False         False             True
on     Tell me about agent-marketing-copy   False         False             True
off    Tell me about Harbor Backup Service  True          True              True
off    Describe marketing-copy              True          True              True
off    Tell me about agent-marketing-copy   True          True              True

guard on: model obeyed 0 of 3; guard off: obeyed 3 of 3, validator caught 3; unsafe final answers: 0
```
<!-- /output -->

## Graph size

<!-- output: graph -->
```text
nodes 195, edges 178
node kind                                         count
------------------------------------------------  -----
agent                                             7
agent_identity                                    6
app                                               11
capability                                        1
connection                                        4
directory_role                                    12
external_app                                      6
first_party                                       1
group                                             7
guest                                             2
managed_identity                                  3
microsoft.cognitiveservices/accounts              2
microsoft.cognitiveservices/accounts/projects     2
microsoft.compute/virtualmachines                 1
microsoft.keyvault/vaults                         3
microsoft.managedidentity/userassignedidentities  2
microsoft.storage/storageaccounts                 1
microsoft.web/sites                               1
resource_group                                    7
secret                                            7
secret_store                                      3
source                                            6
subscription                                      2
tool                                              16
user                                              82

edge kind                count
-----------------------  -----
add-app-credentials      14
agent_edit               8
agent_identity           13
connection_secret        2
contains                 33
edit-groups              6
elevate-access           2
eligible_role            6
federated_trust          5
grant-global-admin       2
holds_role               9
member_of                20
owns_app                 10
prompt_injection         6
reset-admin-credentials  1
runs_as                  4
secrets_read             3
stored_credential        1
tool_connection          5
uses_tool                16
write_resource           12
```
<!-- /output -->

## Runtime

`idsec bench` times each stage on the current machine. It is not rendered here because it varies from
run to run; on the development box the whole pipeline took a few hundred milliseconds.

## What these numbers do not show

* Behaviour on a real tenant (false positives, data quirks, scale).
* How a real model responds to injection.
* Anything about deployment: nothing is deployed.
