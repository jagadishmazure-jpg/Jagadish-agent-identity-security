"""Report-only impact: before a Conditional Access policy is enforced, replay two weeks of synthetic sign-ins
through it and list who it would block or change, so nobody finds out from the help desk.

The evaluator understands the policy fields this repository writes: users (include All / guests, exclude
users and groups), applications, client app types, the reduced unmanaged-device filter from `session`, a
block grant, and session controls. Sign-ins are synthetic and deterministic."""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass

from idsec import TENANT_DATA, session

APPS = ["Office 365 Exchange Online", "Office 365 SharePoint Online", "Microsoft Teams"]
LEGACY = {  # user principal name -> (client app type, client, why it exists)
    "gary.holt@kestrelridge.example": ("other", "IMAP mail client", "old desktop mail app"),
    "nina.patel@kestrelridge.example": ("other", "IMAP mail client", "old desktop mail app"),
    "omar.reyes@kestrelridge.example": ("exchangeActiveSync", "basic-auth ActiveSync phone", "personal phone mail app"),
}


def _load(name: str) -> list[dict]:
    d = json.loads((TENANT_DATA / "graph" / name).read_text())
    return d.get("value", d) if isinstance(d, dict) else d


def users() -> dict[str, dict]:
    return {u["id"]: u for u in _load("users.json") if u["accountEnabled"]}


def memberships() -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for g in _load("groups.json"):
        for m in g.get("members", []):
            out[m["id"]].add(g["id"])
    return out


@dataclass(frozen=True)
class SignIn:
    user: str
    upn: str
    guest: bool
    app: str
    client: str  # browser | mobileAppsAndDesktopClients | exchangeActiveSync | other
    client_name: str
    compliant: bool
    platform: str


def signins(seed: int = 11) -> list[SignIn]:
    rng = random.Random(seed)
    us = users()
    groups = {g["id"]: g for g in _load("groups.json")}
    legacy_group = next(g for g in groups.values() if g["displayName"] == "CA-Exclusions-Legacy")
    legacy_ids = {m["id"] for m in legacy_group["members"]}
    out: list[SignIn] = []
    for uid, u in sorted(us.items()):
        upn, guest = u["userPrincipalName"], u["userType"] == "Guest"
        if upn.startswith("breakglass"):
            out.append(SignIn(uid, upn, False, "Azure portal", "browser", "browser", True, "windows"))
            continue
        for _ in range(3):
            out.append(SignIn(uid, upn, guest, rng.choice(APPS), "browser", "browser", not guest, "windows" if rng.random() < 0.8 else "macOS"))
        if not guest:
            out.append(SignIn(uid, upn, guest, rng.choice(APPS[:2]), "mobileAppsAndDesktopClients", "Outlook desktop", True, "windows"))
        if not guest and rng.random() < 0.3:  # BYOD phone browser
            out.append(SignIn(uid, upn, guest, rng.choice(APPS[:2]), "browser", "phone browser", False, rng.choice(["iOS", "android"])))
        if u.get("department") == "Finance":
            out.append(SignIn(uid, upn, guest, "Payroll (FIN-PAY)", "browser", "browser", True, "windows"))
        if upn in LEGACY:
            ctype, name, _ = LEGACY[upn]
            out += [SignIn(uid, upn, guest, "Office 365 Exchange Online", ctype, name, False, "unknown")] * 4
        if uid in legacy_ids:
            out += [SignIn(uid, upn, guest, "Office 365 Exchange Online", "other", "SMTP AUTH (scan-to-email)", False, "unknown")] * 6
    return out


def applies(p: dict, s: SignIn, member_of: set[str]) -> tuple[bool, str]:
    c = p["conditions"]
    u = c["users"]
    if s.user in u.get("excludeUsers", []) or member_of & set(u.get("excludeGroups", [])):
        return False, "excluded"
    inc = u.get("includeUsers", [])
    if not ("All" in inc or s.user in inc or ("GuestsOrExternalUsers" in inc and s.guest) or member_of & set(u.get("includeGroups", []))):
        return False, "not in scope"
    apps = c["applications"]["includeApplications"]
    if "All" not in apps and s.app not in apps:
        return False, "other app"
    types = c.get("clientAppTypes", ["all"])
    if "all" not in types and s.client not in types:
        return False, "other client"
    if c.get("devices") == session.UNMANAGED and s.compliant:
        return False, "managed device"
    return True, "applies"


def outcome(p: dict) -> str:
    g = p.get("grantControls") or {}
    if "block" in (g.get("builtInControls") or []):
        return "block"
    sc = p.get("sessionControls") or {}
    if sc:
        return "session: " + ", ".join(sorted(sc))
    return "require: " + ", ".join(g.get("builtInControls") or [(g.get("authenticationStrength") or {}).get("displayName", "grant")])


@dataclass
class Impact:
    policy: str
    outcome: str
    signins: int
    users: list[str]
    by_client: dict[str, int]
    excluded_but_active: list[str]
    emergency_affected: int


def impact(p: dict, sis: list[SignIn] | None = None) -> Impact:
    sis = sis or signins()
    mem = memberships()
    hit, excluded = [], set()
    for s in sis:
        ok, why = applies(p, s, mem.get(s.user, set()))
        if ok:
            hit.append(s)
        elif why == "excluded":
            excluded.add(s.upn)
    emergency = sum(s.upn.startswith("breakglass") for s in hit)
    return Impact(
        p["displayName"],
        outcome(p),
        len(hit),
        sorted({s.upn for s in hit}),
        dict(Counter(f"{s.client_name}" for s in hit)),
        sorted(excluded),
        emergency,
    )


def exception_members() -> set[str]:
    """UPNs in CA-Exclusions-Legacy: excluded from the MFA policy, but not from the legacy block."""
    g = next(g for g in _load("groups.json") if g["displayName"] == "CA-Exclusions-Legacy")
    us = users()
    return {us[m["id"]]["userPrincipalName"] for m in g["members"] if m["id"] in us}


def report_only_policies() -> list[dict]:
    return [p for p in session.tenant_policies() if p["state"] == "enabledForReportingButNotEnforced"] + session.proposed()


def evaluate() -> dict:
    sis = signins()
    imps = [impact(p, sis) for p in report_only_policies()]
    ca02 = imps[0]
    return {
        "signins_replayed": len(sis),
        "users": len({s.user for s in sis}),
        "policies_checked": len(imps),
        "legacy_block_would_block_users": len(ca02.users),
        "legacy_block_hits_exception_group": len(exception_members() & set(ca02.users)),
        "emergency_accounts_affected": sum(i.emergency_affected for i in imps),
        "changes_made": 0,
    }


def report() -> str:
    sis = signins()
    lines = [f"Who would this affect? Report-only replay of {len(sis)} synthetic sign-ins over two weeks", ""]
    for p in report_only_policies():
        i = impact(p, sis)
        lines.append(f"{i.policy}  [{i.outcome}]")
        lines.append(f"  {i.signins} sign-in(s), {len(i.users)} user(s); by client: {dict(sorted(i.by_client.items()))}")
        if i.outcome == "block":
            ex = exception_members()
            lines += [
                f"    would block {u}{'  (in CA-Exclusions-Legacy: exempt from MFA, not from this block; move the device to OAuth first)' if u in ex else ''}"
                for u in i.users
            ]
        if i.emergency_affected:
            lines.append(f"  WARNING: {i.emergency_affected} emergency-account sign-in(s) in scope")
        lines.append("")
    lines += ["Measured (synthetic sign-ins; nothing was enforced):"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
