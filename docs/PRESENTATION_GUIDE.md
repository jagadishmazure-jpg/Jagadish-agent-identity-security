# Presentation guide

A ten-minute demo for an interview or a team review. Every step is one command on the fictional tenant;
all data is synthetic and every number is printed by the command itself.

## Before you start

```bash
pip install -e ".[dev]"
idsec gate          # confirm 21 of 21 checks pass
```

## Story (ten minutes)

1. **The problem (one minute).** Identity is how most small-business incidents start: a password over an
   old protocol, a forwarded inbox, a copied session cookie, an over-privileged service account.
2. **The baseline (two minutes).** `idsec scan`, then `idsec paths --people --limit 3`. Explain one path
   step by step.
3. **Change without surprises (two minutes).** `idsec drift` shows weakening caught and rolled back only
   after approval; `idsec impact` shows who a block would stop before anyone enforces it.
4. **After sign-in (two minutes).** `idsec session` then `idsec extension`: MFA was not broken, the session
   was copied; the response is two approved changes, verified afterwards.
5. **Mail, files and the domain (two minutes).** `idsec m365` and `idsec ad-tier0`: the top choke point and
   the fix order.
6. **Closing the loop (one minute).** `idsec incident-link`: confirmed SOC incidents become hardening
   tasks; benign ones do not.

## What to say about the numbers

* Perfect precision and recall on these packs are regression checks on labelled synthetic data written by
  the same author, not accuracy on a real tenant.
* Nothing is deployed and nothing is sent; changes run against an in-memory copy of the state.

## Likely follow-ups

* *Why not let the agent approve?* Because the approval is the control. Agents can propose and explain;
  only configured people can approve, and the approval is bound to the exact change.
* *What would go live first?* Read-only collection of sign-in logs for the impact replay, because it
  changes nothing and pays off before the first policy is enforced.
