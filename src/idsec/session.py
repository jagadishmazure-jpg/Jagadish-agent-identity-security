"""Entra ID session hardening: four checks over Conditional Access session controls, and a proposed
report-only policy set that closes them.

Stolen session cookies and tokens bypass MFA, so the controls that matter after sign-in are how often a
session must re-authenticate on sensitive apps, whether an unmanaged browser may keep a persistent session,
whether tokens are bound to the device (token protection) or revoked in near real time (strict continuous
access evaluation), and whether unmanaged (BYOD) devices get limited, app-enforced access to mail and files.

Policies are Microsoft Graph `conditionalAccessPolicy` shaped. Device conditions use a reduced filter:
`{"deviceFilter": {"mode": "include", "rule": "device.isCompliant -ne True"}}` means unmanaged devices."""

from __future__ import annotations

import copy
from dataclasses import dataclass

SENSITIVE_APPS = ("Payroll (FIN-PAY)", "Azure portal")
MAIL_FILES = ("Office 365 Exchange Online", "Office 365 SharePoint Online")
UNMANAGED = {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -ne True"}}
EMERGENCY_GROUP = "00000000-0000-0000-0002-000000000001"
MAX_SIF_HOURS = 8


def _policy(name: str, apps, controls: dict, *, devices=None, clients=("all",), state="enabledForReportingButNotEnforced") -> dict:
    cond = {
        "applications": {"includeApplications": list(apps)},
        "clientAppTypes": list(clients),
        "users": {
            "includeUsers": ["All"],
            "excludeGroups": [EMERGENCY_GROUP],
            "excludeUsers": [],
            "includeGroups": [],
            "includeRoles": [],
            "excludeRoles": [],
        },
    }
    if devices:
        cond["devices"] = devices
    return {"displayName": name, "state": state, "conditions": cond, "grantControls": None, "sessionControls": controls}


def proposed() -> list[dict]:
    """The hardening set, written report-only so its impact can be measured before anyone enforces it."""
    return [
        _policy("S01 Sign-in frequency 4h on sensitive apps", SENSITIVE_APPS, {"signInFrequency": {"isEnabled": True, "value": 4, "type": "hours"}}),
        _policy(
            "S02 No persistent browser on unmanaged devices",
            ["All"],
            {"persistentBrowser": {"isEnabled": True, "mode": "never"}},
            devices=UNMANAGED,
            clients=("browser",),
        ),
        _policy(
            "S03 Token protection and strict CAE for mail and files",
            MAIL_FILES,
            {"secureSignInSession": {"isEnabled": True}, "continuousAccessEvaluation": {"mode": "strictEnforcement"}},
            clients=("mobileAppsAndDesktopClients",),
        ),
        _policy(
            "S04 App-enforced restrictions for BYOD",
            MAIL_FILES,
            {"applicationEnforcedRestrictions": {"isEnabled": True}},
            devices=UNMANAGED,
            clients=("browser",),
        ),
    ]


def near_misses() -> list[dict]:
    """Policies that look like the controls but do not provide them (evaluation fixtures)."""
    return [
        _policy(
            "N01 Sign-in frequency 30 days on sensitive apps",
            SENSITIVE_APPS,
            {"signInFrequency": {"isEnabled": True, "value": 30, "type": "days"}},
            state="enabled",
        ),
        _policy(
            "N02 Persistent browser always",
            ["All"],
            {"persistentBrowser": {"isEnabled": True, "mode": "always"}},
            devices=UNMANAGED,
            clients=("browser",),
            state="enabled",
        ),
        _policy("N03 CAE disabled", MAIL_FILES, {"continuousAccessEvaluation": {"mode": "disabled"}}, state="enabled"),
        _policy(
            "N04 App-enforced restrictions on Payroll only",
            ["Payroll (FIN-PAY)"],
            {"applicationEnforcedRestrictions": {"isEnabled": True}},
            devices=UNMANAGED,
            state="enabled",
        ),
    ]


def enforced(policies: list[dict]) -> list[dict]:
    out = copy.deepcopy(policies)
    for p in out:
        p["state"] = "enabled"
    return out


def _apps(p: dict) -> set[str]:
    return set(p["conditions"]["applications"]["includeApplications"])


def _covers(p: dict, apps) -> bool:
    return "All" in _apps(p) or set(apps) <= _apps(p)


def _unmanaged(p: dict) -> bool:
    return p["conditions"].get("devices") == UNMANAGED


def _sc(p: dict) -> dict:
    return p.get("sessionControls") or {}


def _hours(sif: dict) -> float:
    return sif["value"] * (24 if sif["type"] == "days" else 1)


CHECKS = {
    "sign-in-frequency-sensitive-apps": (
        f"sensitive apps re-authenticate at least every {MAX_SIF_HOURS} hours",
        lambda p: _covers(p, SENSITIVE_APPS) and (s := _sc(p).get("signInFrequency")) and s.get("isEnabled") and _hours(s) <= MAX_SIF_HOURS,
    ),
    "no-persistent-browser-unmanaged": (
        "unmanaged browsers cannot keep a persistent session",
        lambda p: _unmanaged(p) and _sc(p).get("persistentBrowser", {}).get("mode") == "never" and "All" in _apps(p),
    ),
    "token-protection-or-strict-cae": (
        "mail and file tokens are device-bound or revoked in near real time",
        lambda p: (
            _covers(p, MAIL_FILES)
            and (
                _sc(p).get("secureSignInSession", {}).get("isEnabled")
                or _sc(p).get("continuousAccessEvaluation", {}).get("mode") == "strictEnforcement"
            )
        ),
    ),
    "app-enforced-restrictions-byod": (
        "unmanaged devices get limited, browser-only access to mail and files",
        lambda p: _unmanaged(p) and _covers(p, MAIL_FILES) and _sc(p).get("applicationEnforcedRestrictions", {}).get("isEnabled"),
    ),
}


@dataclass
class Result:
    check: str
    status: str  # pass | report-only | fail
    policy: str | None
    meaning: str


def check(policies: list[dict]) -> list[Result]:
    out = []
    for name, (meaning, fn) in CHECKS.items():
        hits = [p for p in policies if p["state"] != "disabled" and fn(p)]
        on = [p for p in hits if p["state"] == "enabled"]
        if on:
            out.append(Result(name, "pass", on[0]["displayName"], meaning))
        elif hits:
            out.append(Result(name, "report-only", hits[0]["displayName"], meaning))
        else:
            out.append(Result(name, "fail", None, meaning))
    return out


def tenant_policies() -> list[dict]:
    import json

    from idsec import TENANT_DATA

    d = json.loads((TENANT_DATA / "graph/conditionalAccessPolicies.json").read_text())
    return d.get("value", d) if isinstance(d, dict) else d


def evaluate() -> dict:
    def tally(rs):
        return {s: sum(r.status == s for r in rs) for s in ("pass", "report-only", "fail")}

    return {
        "checks": len(CHECKS),
        "tenant_today": tally(check(tenant_policies())),
        "with_proposed_report_only": tally(check(tenant_policies() + proposed())),
        "with_proposed_enforced": tally(check(tenant_policies() + enforced(proposed()))),
        "near_miss_policies_passing": sum(r.status == "pass" for r in check(near_misses())),
        "proposed_exclude_emergency_accounts": all(EMERGENCY_GROUP in p["conditions"]["users"]["excludeGroups"] for p in proposed()),
    }


def report() -> str:
    lines = ["Entra ID session hardening (synthetic Kestrel Ridge Mortgage)", ""]
    for label, pols in (("Today", tenant_policies()), ("With the proposed set in report-only", tenant_policies() + proposed())):
        lines.append(f"{label}:")
        lines += [f"  {r.status:<11} {r.check}: {r.meaning}{' (' + r.policy + ')' if r.policy else ''}" for r in check(pols)]
        lines.append("")
    lines.append("Near-miss policies (look like the control, are not):")
    lines += [f"  {r.status:<11} {r.check}" for r in check(near_misses())]
    lines += ["", "Measured:"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
