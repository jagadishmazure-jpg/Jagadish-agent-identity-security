# ADR 0004: Dry-run remediation with digest-bound approvals

**Status:** Accepted

## Context

Proposing fixes is useful; applying identity changes automatically is dangerous (lockouts, broken apps)
and would make the scanner a write-capable target.

## Decision

Every finding becomes a plan item with a plain-language change and Terraform and Bicep snippets.
Approvals come only from configured, enabled people, are bound to a SHA-256 digest of the item, need two
distinct approvers for critical findings and listed actions, and expire after 24 hours. Execution is dry
run only; the live path raises `NotImplementedError`. A simulation applies the plan to a copy and
re-scores it.

## Consequences

* The tool cannot change a tenant, by construction.
* Owners apply changes through their own pipelines, using the snippets as a starting point.
* The simulated improvement shows intent, not side effects.
