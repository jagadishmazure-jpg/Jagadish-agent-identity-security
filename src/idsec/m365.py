"""Exchange Online and SharePoint Online posture checks over a synthetic configuration export.

Seven checks cover the settings attackers use after an identity is taken over: mail forwarded outside the
company, mailboxes that skip auditing, password-only SMTP sending, spoofable domains, anonymous sharing links,
sharing links that default to anonymous, and guests that never expire. The export includes look-alikes that
are fine (an approved partner forward, a parked domain, a scanner with a documented SMTP exception), and the
expected answers live in `EXPECTED`, which only `evaluate` reads."""

from __future__ import annotations

from dataclasses import dataclass

CONFIG: dict = {
    "exchange": {
        "org": {"AuditDisabled": False, "SmtpClientAuthenticationDisabled": False},
        "mailboxes": [
            {"id": "MBX-01", "upn": "rosa.walsh@kestrelridge.example", "AuditEnabled": True, "AuditBypass": False, "SmtpAuth": None},
            {"id": "MBX-02", "upn": "svc.reports@kestrelridge.example", "AuditEnabled": True, "AuditBypass": True, "SmtpAuth": None},
            {
                "id": "MBX-03",
                "upn": "scanner.floor2@kestrelridge.example",
                "AuditEnabled": True,
                "AuditBypass": False,
                "SmtpAuth": True,
                "exception": "EXC-311",
            },
            {"id": "MBX-04", "upn": "leo.martins@kestrelridge.example", "AuditEnabled": False, "AuditBypass": False, "SmtpAuth": None},
        ],
        "inboxRules": [
            {"id": "RULE-01", "mailbox": "leo.martins@kestrelridge.example", "ForwardTo": "leo.m.personal@freemail.example", "name": ".."},
            {
                "id": "RULE-02",
                "mailbox": "rosa.walsh@kestrelridge.example",
                "ForwardTo": "finance-team@kestrelridge.example",
                "name": "Invoices to team",
            },
            {
                "id": "RULE-03",
                "mailbox": "ap@kestrelridge.example",
                "ForwardTo": "intake@titleco-partner.example",
                "name": "Closing docs",
                "approval": "CHG-1051",
            },
            {"id": "RULE-04", "mailbox": "gary.holt@kestrelridge.example", "RedirectTo": "archive.gh@mailbox-host.example", "name": "x"},
        ],
        "domains": [
            {"id": "DOM-01", "name": "kestrelridge.example", "mx": True, "dkim": True, "dmarc": "reject"},
            {"id": "DOM-02", "name": "kestrelridge-loans.example", "mx": True, "dkim": False, "dmarc": "none"},
            {"id": "DOM-03", "name": "kestrelridge-old.example", "mx": False, "dkim": False, "dmarc": "reject", "parked": True},
        ],
    },
    "sharepoint": {
        "tenant": {
            "SharingCapability": "ExternalUserAndGuestSharing",
            "DefaultSharingLinkType": "AnonymousAccess",
            "ExternalUserExpirationRequired": False,
        },
        "sites": [
            {
                "id": "SITE-01",
                "url": "/sites/LoanFiles",
                "SharingCapability": "ExternalUserAndGuestSharing",
                "anyoneLinkExpiryDays": None,
                "sensitivity": "Confidential",
            },
            {
                "id": "SITE-02",
                "url": "/sites/Marketing-Public",
                "SharingCapability": "ExternalUserAndGuestSharing",
                "anyoneLinkExpiryDays": 7,
                "sensitivity": "Public",
            },
            {"id": "SITE-03", "url": "/sites/HR", "SharingCapability": "Disabled", "anyoneLinkExpiryDays": None, "sensitivity": "Confidential"},
        ],
    },
}

INTERNAL = ("kestrelridge.example",)
# Ground truth for evaluation only. A finding is (check, object id).
EXPECTED = {
    ("external-forwarding", "RULE-01"),
    ("external-forwarding", "RULE-04"),
    ("mailbox-audit", "MBX-02"),
    ("mailbox-audit", "MBX-04"),
    ("smtp-auth", "ORG"),
    ("domain-spoofing", "DOM-02"),
    ("anyone-links", "SITE-01"),
    ("default-link-anonymous", "TENANT"),
    ("guest-expiry", "TENANT"),
}

LOOK_ALIKES = ("RULE-02", "RULE-03", "MBX-03", "DOM-03", "SITE-02")

FIX = {
    "external-forwarding": "remove the rule and turn off automatic external forwarding in the outbound policy; check the mailbox for takeover",
    "mailbox-audit": "turn auditing on and remove the audit bypass",
    "smtp-auth": "turn SMTP AUTH off for the organization; keep per-mailbox exceptions with a ticket",
    "domain-spoofing": "publish DKIM and move DMARC to quarantine, then reject",
    "anyone-links": "turn off anonymous links on confidential sites or require expiry of 7 days or less",
    "default-link-anonymous": "set the default link type to people in the organization",
    "guest-expiry": "require guest access to expire (for example 60 days)",
}


@dataclass(frozen=True)
class Finding:
    check: str
    obj: str
    detail: str

    @property
    def fix(self) -> str:
        return FIX[self.check]


def _external(addr: str) -> bool:
    return not addr.split("@")[-1].endswith(INTERNAL)


def scan(cfg: dict | None = None) -> list[Finding]:
    cfg = cfg or CONFIG
    ex, sp = cfg["exchange"], cfg["sharepoint"]
    out: list[Finding] = []
    for r in ex["inboxRules"]:
        dest = r.get("ForwardTo") or r.get("RedirectTo")
        if dest and _external(dest) and not r.get("approval"):
            out.append(Finding("external-forwarding", r["id"], f"{r['mailbox']} -> {dest} (rule name {r['name']!r})"))
    for m in ex["mailboxes"]:
        if ex["org"]["AuditDisabled"] or not m["AuditEnabled"] or m["AuditBypass"]:
            out.append(Finding("mailbox-audit", m["id"], f"{m['upn']}: audit {'bypassed' if m['AuditBypass'] else 'off'}"))
    if not ex["org"]["SmtpClientAuthenticationDisabled"]:
        out.append(Finding("smtp-auth", "ORG", "SMTP AUTH is on for every mailbox"))
    for d in ex["domains"]:
        if d.get("parked") and not d["mx"] and d["dmarc"] == "reject":
            continue
        if not d["dkim"] or d["dmarc"] in (None, "none"):
            out.append(Finding("domain-spoofing", d["id"], f"{d['name']}: DKIM {'on' if d['dkim'] else 'off'}, DMARC p={d['dmarc']}"))
    for s in sp["sites"]:
        if s["SharingCapability"] == "ExternalUserAndGuestSharing" and s["sensitivity"] != "Public":
            if s["anyoneLinkExpiryDays"] is None or s["anyoneLinkExpiryDays"] > 7:
                out.append(Finding("anyone-links", s["id"], f"{s['url']} ({s['sensitivity']}): anonymous links, expiry {s['anyoneLinkExpiryDays']}"))
    t = sp["tenant"]
    if t["DefaultSharingLinkType"] == "AnonymousAccess":
        out.append(Finding("default-link-anonymous", "TENANT", "new sharing links default to anyone with the link"))
    if not t["ExternalUserExpirationRequired"]:
        out.append(Finding("guest-expiry", "TENANT", "guest access never expires"))
    return out


def evaluate() -> dict:
    got = {(f.check, f.obj) for f in scan()}
    tp = len(got & EXPECTED)
    return {
        "checks": len(FIX),
        "findings": len(got),
        "expected": len(EXPECTED),
        "true_positives": tp,
        "false_positives": len(got - EXPECTED),
        "missed": len(EXPECTED - got),
        "precision": round(tp / len(got), 3) if got else 1.0,
        "recall": round(tp / len(EXPECTED), 3),
        "look_alikes_cleared": f"{sum(a not in {o for _, o in got} for a in LOOK_ALIKES)}/{len(LOOK_ALIKES)}",
    }


def report() -> str:
    lines = ["Exchange Online and SharePoint posture (synthetic Kestrel Ridge Mortgage export)", ""]
    for f in scan():
        lines += [f"  [{f.check}] {f.obj}: {f.detail}", f"      fix: {f.fix}"]
    lines += ["", "Cleared look-alikes: RULE-02 internal forward, RULE-03 approved partner forward (CHG-1051),"]
    lines += ["  MBX-03 scanner SMTP exception (EXC-311, still counted under the org-wide SMTP finding), DOM-03 parked domain with DMARC reject,"]
    lines += ["  SITE-02 public marketing site with 7-day links", "", "Measured against the labelled export:"]
    lines += [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
