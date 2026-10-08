# Interview guide

A short guide for talking about this project: the one-minute pitch, a five-minute walkthrough, and
answers to likely questions. All numbers come from real runs on the fictional tenant (see
[metrics](metrics.md)).

## One minute

"It's an identity posture scanner for humans, workload identities and AI agents on Microsoft's stack. It
reads Entra ID, PIM, Azure RBAC, Key Vault metadata and Foundry agents (read-only), builds a graph of who
can control what, finds paths to four crown jewels, runs 28 rules, scores three areas, and proposes fixes
that a human has to approve, but never applies them. An Agent Framework agent explains results through
read-only tools, with prompt-injection defences measured layer by layer. It runs entirely offline on a
fictional mortgage company, with a 14-check release gate in CI. The Terraform and Bicep to deploy it are
written and tested, and nothing is deployed."

## Five-minute walkthrough

1. `idsec scan`: three area scores and the overview (35.8, grade F, 47 findings).
2. `idsec paths --people --limit 3`: a person who reaches Global Administrator; explain the edges.
3. `idsec show P04-01`: an app permission that equals tenant control, with the fix and mappings.
4. `idsec plan --show F06-01`: a plan item with Terraform and Bicep; explain digest-bound approvals.
5. `idsec simulate`: the plan would take the overview to 90.5 and standing paths from people and
   untrusted input from 48 to 13; 3 findings need people to act.
6. `idsec injection`: guard on, 0 of 3 injections obeyed; guard off, 3 of 3 obeyed and 3 caught.
7. `idsec gate`: 14 of 14 checks.

## Likely questions

**Why a graph?** Because privilege is indirect. Owning an app with `RoleManagement.ReadWrite.Directory`
is the same as being Global Administrator; a list of role assignments would miss it.

**How do you rank paths?** Each edge has an ease between 0 and 1; Dijkstra on −log(ease) finds the path
with the highest product. Shortest paths are shown too, so a judgement call never hides reachability.

**Precision and recall are 1.0. Isn't that suspicious?** Yes, and the docs say so. I wrote the
generator and the rules, so it's a regression check. The honest unknown is the false-positive rate on a
real tenant.

**What stops the agent from doing damage?** It has seven read-only tools and no approval or execution
tool. Tenant text is quoted as untrusted data, and answers are validated against facts from code.

**What did you find hard?** Keeping logging keyless: Container Apps wants the workspace shared key, so I
used azure-monitor with a diagnostic setting. And discovering that the Foundry `agents/read` data action
also covers threads and messages; I documented it as a limitation.

**What would you do next?** Run the collectors against a test tenant, replace the regex screen with
Prompt Shields, ingest results into a workspace table, and add trends across scans.

**Is it deployed?** No. The deploy workflow is gated off and the docs say "nothing is deployed".
