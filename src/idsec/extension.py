"""Cookie theft through a malicious browser extension, end to end on synthetic data.

The story: a popular "PDF Quick Convert" extension changes publisher, and its next update adds the
`cookies` permission and host access to the Microsoft sign-in pages. Shortly after, sessions for three
users who have it installed are replayed from a network none of them has used, with no interactive sign-in.

The pack finds the risky extension from managed-browser inventory, ties the replayed sessions to it, and
proposes two changes: revoke the affected users' sessions, and block the extension for the whole
organization. Both go through `changegate`: nothing happens until a configured human approves, agents can
never approve, and each change is verified after it is applied (a replay of an old session is refused, and
no device still runs the extension). Look-alikes (a vetted password manager that also reads cookies, an
ad blocker with broad host access, and a traveller who signed in fresh with MFA) must not be flagged."""

from __future__ import annotations

from dataclasses import dataclass

from idsec import changegate

LOGIN_HOSTS = ("login.microsoftonline.com", "login.live.com", "<all_urls>")
ALLOWLIST = {"hbmjgpfcneolkadhbmjgpfcneolkadhb"}  # vetted password manager

EXTENSIONS = [
    {"id": "pdqcnvrtaeboimcakdpnlfgjhaeboimc", "name": "PDF Quick Convert", "installs": 23,
     "versions": [{"v": "3.1.0", "publisher": "Quickdoc Tools", "permissions": ["activeTab", "downloads"], "hosts": []},
                  {"v": "3.2.0", "publisher": "QD Labs Ltd", "permissions": ["activeTab", "downloads", "cookies", "webRequest"],
                   "hosts": ["*://login.microsoftonline.com/*", "*://*.sharepoint.com/*"]}]},
    {"id": "hbmjgpfcneolkadhbmjgpfcneolkadhb", "name": "Vaultkeeper Password Manager", "installs": 61,
     "versions": [{"v": "8.4.0", "publisher": "Vaultkeeper Inc", "permissions": ["cookies", "storage"], "hosts": ["<all_urls>"]}]},
    {"id": "adbnclmkgfeihjopadbnclmkgfeihjop", "name": "CleanPage Ad Blocker", "installs": 40,
     "versions": [{"v": "1.9.0", "publisher": "CleanPage", "permissions": ["declarativeNetRequest"], "hosts": ["<all_urls>"]}]},
]  # fmt: skip

INSTALLED = {
    "pdqcnvrtaeboimcakdpnlfgjhaeboimc": ["sara.okafor@kestrelridge.example", "devon.lee@kestrelridge.example", "mia.santos@kestrelridge.example"],
    "hbmjgpfcneolkadhbmjgpfcneolkadhb": ["rosa.walsh@kestrelridge.example", "sara.okafor@kestrelridge.example"],
    "adbnclmkgfeihjopadbnclmkgfeihjop": ["kai.thompson@kestrelridge.example"],
}

SIGNINS = [  # synthetic sign-in log rows after the 3.2.0 update
    {"user": "sara.okafor@kestrelridge.example", "asn": 64500, "interactive": True, "mfa": True, "session": "s-sara-1"},
    {"user": "sara.okafor@kestrelridge.example", "asn": 64511, "interactive": False, "mfa": False, "session": "s-sara-1"},
    {"user": "devon.lee@kestrelridge.example", "asn": 64500, "interactive": True, "mfa": True, "session": "s-devon-1"},
    {"user": "devon.lee@kestrelridge.example", "asn": 64511, "interactive": False, "mfa": False, "session": "s-devon-1"},
    {"user": "mia.santos@kestrelridge.example", "asn": 64501, "interactive": True, "mfa": True, "session": "s-mia-1"},
    {"user": "mia.santos@kestrelridge.example", "asn": 64511, "interactive": False, "mfa": False, "session": "s-mia-1"},
    {"user": "kai.thompson@kestrelridge.example", "asn": 64500, "interactive": True, "mfa": True, "session": "s-kai-1"},
    {"user": "kai.thompson@kestrelridge.example", "asn": 64520, "interactive": True, "mfa": True, "session": "s-kai-2"},  # travel, fresh MFA
    {"user": "rosa.walsh@kestrelridge.example", "asn": 64500, "interactive": True, "mfa": True, "session": "s-rosa-1"},
]

# Ground truth for evaluation only.
EXPECTED_RISKY = {"pdqcnvrtaeboimcakdpnlfgjhaeboimc"}
EXPECTED_REPLAYED = {"sara.okafor@kestrelridge.example", "devon.lee@kestrelridge.example", "mia.santos@kestrelridge.example"}


@dataclass
class Verdict:
    ext: str
    name: str
    risky: bool
    reasons: list[str]


def assess(ext: dict) -> Verdict:
    new = ext["versions"][-1]
    old = ext["versions"][-2] if len(ext["versions"]) > 1 else None
    reads_cookies = "cookies" in new["permissions"]
    login = [h for h in new["hosts"] if any(x in h for x in LOGIN_HOSTS)]
    reasons = []
    if reads_cookies and login:
        reasons.append("can read cookies on sign-in pages")
    if old and old["publisher"] != new["publisher"]:
        reasons.append(f"publisher changed ({old['publisher']} -> {new['publisher']})")
    if old and "cookies" in new["permissions"] and "cookies" not in old["permissions"]:
        reasons.append("cookies permission added in the latest update")
    risky = bool(reads_cookies and login) and ext["id"] not in ALLOWLIST and len(reasons) >= 2
    return Verdict(ext["id"], ext["name"], risky, reasons if risky else (["allowlisted after review"] if ext["id"] in ALLOWLIST else reasons))


def replays(signins: list[dict] | None = None) -> list[dict]:
    """Non-interactive use of a session from a network that session was not issued on."""
    signins = signins or SIGNINS
    issued = {s["session"]: s["asn"] for s in signins if s["interactive"]}
    return [s for s in signins if not s["interactive"] and s["session"] in issued and s["asn"] != issued[s["session"]]]


def initial_state() -> dict:
    return {
        "sessions": {u.split("@")[0].replace(".", "_"): "active" for u in {s["user"] for s in SIGNINS}},
        "browser": {"blocklist": {}, "installs": {e["id"]: e["installs"] for e in EXTENSIONS}},
    }


def proposals() -> list[changegate.Change]:
    risky = [v for v in (assess(e) for e in EXTENSIONS) if v.risky]
    users = sorted({r["user"] for r in replays()} & {u for v in risky for u in INSTALLED[v.ext]})
    revoke = changegate.Change(
        "EXT-01",
        f"revoke sign-in sessions for {len(users)} user(s) whose sessions were replayed",
        [changegate.Step(f"sessions.{u.split('@')[0].replace('.', '_')}", "revoked", "session replayed from a new network") for u in users],
    )
    block = changegate.Change(
        "EXT-02",
        "block and remove " + ", ".join(v.name for v in risky) + " for the whole organization",
        [changegate.Step(f"browser.blocklist.{v.ext}", "blocked", "; ".join(v.reasons)) for v in risky]
        + [changegate.Step(f"browser.installs.{v.ext}", 0, "force-removed by the blocklist policy") for v in risky],
    )
    return [revoke, block]


def walkthrough() -> dict:
    state = initial_state()
    changes = proposals()
    log = []
    for c in changes:
        r, state = changegate.apply(c, [], state)
        log.append((c.id, "no approval", r.status))
    try:
        changegate.approve(changes[0], "agent:identity-responder")
        log.append(("EXT-01", "agent approval", "ALLOWED"))
    except changegate.Refused:
        log.append(("EXT-01", "agent approval", "refused"))
    results = []
    for c in changes:
        r, state = changegate.apply(c, [changegate.approve(c, "ava.chen@kestrelridge.example")], state)
        results.append(r)
        log.append((c.id, "approved by ava.chen", r.status))
    replay_after = [s for s in replays() if state["sessions"][s["user"].split("@")[0].replace(".", "_")] == "active"]
    still_installed = sum(state["browser"]["installs"][v] for v in state["browser"]["blocklist"])
    return {"changes": changes, "results": results, "log": log, "state": state, "replay_after": replay_after, "still_installed": still_installed}


def evaluate() -> dict:
    flagged = {v.ext for v in (assess(e) for e in EXTENSIONS) if v.risky}
    replayed = {s["user"] for s in replays()}
    w = walkthrough()
    return {
        "extensions_reviewed": len(EXTENSIONS),
        "risky_correct": flagged == EXPECTED_RISKY,
        "look_alike_extensions_flagged": len(flagged - EXPECTED_RISKY),
        "replayed_users_found": f"{len(replayed & EXPECTED_REPLAYED)}/{len(EXPECTED_REPLAYED)}",
        "fresh_mfa_travel_flagged": "kai.thompson@kestrelridge.example" in replayed,
        "changes_without_approval": sum(1 for _, how, st in w["log"] if how == "no approval" and st == "applied"),
        "agent_approval_refused": ("EXT-01", "agent approval", "refused") in w["log"],
        "applied_after_approval": sum(r.status == "applied" for r in w["results"]),
        "verification_passed": all(ok for r in w["results"] for _, ok in r.verified),
        "replays_still_accepted": len(w["replay_after"]),
        "devices_still_running_extension": w["still_installed"],
    }


def report() -> str:
    lines = ["Malicious browser extension and session cookie theft (synthetic)", "", "Extension review:"]
    for e in EXTENSIONS:
        v = assess(e)
        lines.append(
            f"  {'RISKY' if v.risky else 'ok   '} {v.name} ({e['installs']} installs): {'; '.join(v.reasons) or 'no cookie access to sign-in pages'}"
        )
    lines += ["", "Session replays (non-interactive, new network, no MFA):"]
    lines += [f"  {s['user']} session {s['session']} from AS{s['asn']}" for s in replays()]
    w = walkthrough()
    lines += ["", "Proposed changes (each needs a human approval bound to its digest):"]
    lines += [f"  {c.id} {c.summary}  digest {c.digest}" for c in w["changes"]]
    lines += [f"  {cid} {how}: {st}" for cid, how, st in w["log"]]
    lines += ["", "Measured (synthetic, labelled):"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
