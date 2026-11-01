"""Configuration drift: compare today's identity settings with an approved baseline, classify each change,
and propose a rollback that a person must approve.

The baseline is the synthetic tenant's Conditional Access policies (`data/tenant/graph`) plus a small set of
tenant settings. `current()` is the same configuration after six synthetic changes, some made through an
approved change ticket and some not. Each change is classified as:

* weakening, no ticket -> rollback proposed (needs approval; dual control when the policy protects admins)
* weakening, with an approved ticket -> reported, no rollback
* strengthening or cosmetic -> recorded only

Ground truth for the synthetic changes sits in `EXPECTED` and is read only by `evaluate`."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass

from idsec import TENANT_DATA, changegate

STATE_RANK = {"disabled": 0, "enabledForReportingButNotEnforced": 1, "enabled": 2}
CONSENT_RANK = {"none": 2, "verified-publishers-low-risk": 1, "all-apps": 0}
INVITE_RANK = {"adminsOnly": 2, "adminsAndGuestInviters": 1, "everyone": 0}
FINANCE_USER = "00000000-0000-0000-0001-00000000000b"
TICKETS = {
    "CHG-1042": {"key": "ca.CA02.state", "by": "ava.chen@kestrelridge.example", "why": "enforce legacy-auth block after report-only review"},
    "CHG-1047": {"key": "settings.guestInvite", "by": "priya.nair@kestrelridge.example", "why": "partner onboarding window (temporary)"},
}
EXPECTED = {  # evaluation only
    "ca.CA01.excludeUsers": "rollback",
    "ca.CA03.state": "rollback",
    "settings.userConsent": "rollback",
    "settings.guestInvite": "approved-weakening",
    "ca.CA02.state": "strengthening",
    "ca.CA04.displayName": "cosmetic",
}


def _policies() -> list[dict]:
    d = json.loads((TENANT_DATA / "graph/conditionalAccessPolicies.json").read_text())
    return d.get("value", d) if isinstance(d, dict) else d


def flatten(policies: list[dict], settings: dict) -> dict:
    out: dict = {"ca": {}, "settings": dict(settings)}
    for p in policies:
        short = p["displayName"].split()[0]
        u = p["conditions"]["users"]
        out["ca"][short] = {
            "displayName": p["displayName"],
            "state": p["state"],
            "excludeUsers": sorted(u.get("excludeUsers", [])),
            "excludeGroups": sorted(u.get("excludeGroups", [])),
            "includeRoles": sorted(u.get("includeRoles", [])),
            "controls": sorted(p["grantControls"].get("builtInControls", [])),
            "strength": (p["grantControls"].get("authenticationStrength") or {}).get("displayName"),
        }
    return out


def baseline() -> dict:
    return flatten(_policies(), {"userConsent": "none", "guestInvite": "adminsOnly", "securityDefaults": False})


def current() -> dict:
    s = copy.deepcopy(baseline())
    s["ca"]["CA01"]["excludeUsers"] = sorted([*s["ca"]["CA01"]["excludeUsers"], FINANCE_USER])
    s["ca"]["CA03"]["state"] = "enabledForReportingButNotEnforced"
    s["ca"]["CA02"]["state"] = "enabled"
    s["ca"]["CA04"]["displayName"] = "CA04 Require MFA for guests (pilot, renamed)"
    s["settings"]["userConsent"] = "all-apps"
    s["settings"]["guestInvite"] = "everyone"
    return s


def _items(state: dict, prefix: str = ""):
    for k, v in state.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from _items(v, key + ".")
        else:
            yield key, v


@dataclass
class Drift:
    key: str
    before: object
    after: object
    direction: str  # weakening | strengthening | cosmetic
    ticket: str | None
    action: str  # rollback | approved-weakening | strengthening | cosmetic
    protects_admins: bool


def _direction(key: str, before, after) -> str:
    field = key.rsplit(".", 1)[1]
    if field == "displayName":
        return "cosmetic"
    if field == "state":
        return "weakening" if STATE_RANK[after] < STATE_RANK[before] else "strengthening"
    if field in ("excludeUsers", "excludeGroups"):
        return "weakening" if len(after) > len(before) else "strengthening"
    if field == "userConsent":
        return "weakening" if CONSENT_RANK[after] < CONSENT_RANK[before] else "strengthening"
    if field == "guestInvite":
        return "weakening" if INVITE_RANK[after] < INVITE_RANK[before] else "strengthening"
    if field in ("controls", "includeRoles"):
        return "weakening" if len(after) < len(before) else "strengthening"
    if field == "strength":
        return "weakening" if after is None else "strengthening"
    if field == "securityDefaults":
        return "weakening" if before and not after else "strengthening"
    return "weakening"  # unknown fields are treated as risky


def detect(base: dict, now: dict) -> list[Drift]:
    b, n = dict(_items(base)), dict(_items(now))
    out = []
    for key in sorted(set(b) | set(n)):
        if b.get(key) == n.get(key):
            continue
        d = _direction(key, b.get(key), n.get(key))
        ticket = next((t for t, v in TICKETS.items() if v["key"] == key), None)
        action = {"cosmetic": "cosmetic", "strengthening": "strengthening"}.get(d) or ("approved-weakening" if ticket else "rollback")
        admins = key.startswith("ca.") and "admin" in str(n["ca." + key.split(".")[1] + ".displayName"]).lower()
        out.append(Drift(key, b.get(key), n.get(key), d, ticket, action, admins))
    return out


def rollback(drifts: list[Drift]) -> list[changegate.Change]:
    return [
        changegate.Change(
            f"RB-{i:02d}",
            f"restore {d.key} to the approved baseline",
            [changegate.Step(d.key, d.before, f"changed without a ticket ({d.before!r} -> {d.after!r})")],
            dual_control=d.protects_admins,
        )
        for i, d in enumerate([d for d in drifts if d.action == "rollback"], 1)
    ]


def walkthrough() -> dict:
    base, now = baseline(), current()
    drifts = detect(base, now)
    changes = rollback(drifts)
    state, results = now, []
    refused_agent = False
    try:
        changegate.approve(changes[0], "agent:identity-explainer")
    except changegate.Refused:
        refused_agent = True
    one = [changegate.approve(c, "ava.chen@kestrelridge.example") for c in changes]
    for c in changes:
        r, state = changegate.apply(c, one, state)
        results.append(r)
    pending = [c for c, r in zip(changes, results, strict=True) if r.status == "refused"]
    second = [changegate.approve(c, "priya.nair@kestrelridge.example") for c in pending]
    retried = []
    for c in pending:
        r, state = changegate.apply(c, one + second, state)
        retried.append(r)
    remaining = [d for d in detect(base, state) if d.action == "rollback"]
    return {"drifts": drifts, "changes": changes, "first": results, "retried": retried, "remaining": remaining, "agent_refused": refused_agent}


def evaluate() -> dict:
    w = walkthrough()
    got = {d.key: d.action for d in w["drifts"]}
    applied = [r for r in w["first"] + w["retried"] if r.status == "applied"]
    return {
        "drifts": len(w["drifts"]),
        "classified_correctly": f"{sum(got.get(k) == v for k, v in EXPECTED.items())}/{len(EXPECTED)}",
        "rollbacks_proposed": len(w["changes"]),
        "refused_with_one_approver": sum(r.status == "refused" for r in w["first"]),
        "applied_after_approval": len(applied),
        "verification_passed": all(ok for r in applied for _, ok in r.verified),
        "unapproved_weakening_left": len(w["remaining"]),
        "agent_approval_refused": w["agent_refused"],
    }


def report() -> str:
    w = walkthrough()
    lines = ["Configuration drift against the approved baseline (synthetic Kestrel Ridge Mortgage)", ""]
    for d in w["drifts"]:
        t = f" ticket {d.ticket}" if d.ticket else " no ticket"
        lines.append(f"  {d.action:<19} {d.key}: {d.before!r} -> {d.after!r} ({d.direction},{t})")
    lines += ["", "Rollback proposals (each needs a human approval bound to its digest):"]
    for c in w["changes"]:
        lines.append(f"  {c.id} {c.summary}  digest {c.digest}  {'dual control' if c.dual_control else 'one approver'}")
    lines.append(f"  agent tried to approve RB-01: {'refused' if w['agent_refused'] else 'ALLOWED'}")
    for r in w["first"]:
        lines.append(f"  {r.change_id} with one approver: {r.status}{' (' + r.reason + ')' if r.status == 'refused' else ''}")
    for r in w["retried"]:
        lines.append(f"  {r.change_id} with two approvers: {r.status}")
    lines += ["", "Measured (synthetic changes, labelled):"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
