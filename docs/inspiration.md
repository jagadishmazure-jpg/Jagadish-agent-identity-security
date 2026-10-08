# Inspiration and credit

The idea for this project came from reading about BeyondTrust's Identity Security Risk Assessment:
<https://www.beyondtrust.com/products/identity-security-insights/assessment>

This repository is **not affiliated** with BeyondTrust, is not endorsed by them, and does not use their
code, data, product names or trademarks. It is an independent learning and portfolio project.

## What was taken from the idea

* Looking at people, workload identities and AI agents together rather than separately.
* Grouping results into a small number of areas with a score each, plus an overall view.
* Treating routes to high privilege as a first-class result.
* Producing reports for both engineers and leaders.

## What is different here

* Everything is open source, runs offline on a fictional tenant, and is tested in CI.
* Area names, rule names, wording and scoring method are this repository's own.
* It focuses only on Microsoft's stack: Entra ID, PIM, Azure RBAC, Key Vault and Foundry agents.
* Remediation is a reviewed, dry-run plan with digest-bound approvals.
* A release gate and rendered metrics make every claim checkable.

## Originality check

Before publishing, the reference page text was saved outside the repository (`refs/`, git-ignored) and
`scripts/overlap_check.py` confirmed there is no run of six consecutive words shared with it.
