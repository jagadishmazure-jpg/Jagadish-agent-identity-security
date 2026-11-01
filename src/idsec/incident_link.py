"""SOC incident to hardening task: when the companion SOC (Jagadish-azure-ai-soc) closes a true-positive
incident, find the posture weaknesses that let it happen and open a hardening task for each, linked both ways.

Incidents are synthetic and shaped like that repository's incident records (id, title, verdict, ATT&CK
techniques, entities). A posture finding is linked when it names an entity in the incident, or when its rule
maps to one of the incident's techniques and its subject is an incident entity or a tenant-wide setting.
Exchange/SharePoint and session-hardening gaps are linked the same way. Tasks are written as a preview file;
nothing is sent or created in a ticketing system."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from idsec import detections, m365, session

INCIDENTS = [
    {"id": "INC-2041", "title": "Password spray over IMAP, one success", "verdict": "true_positive",
     "techniques": ["T1110.003"], "entities": ["gary.holt@kestrelridge.example"]},
    {"id": "INC-2043", "title": "New inbox rule forwards mail to a free-mail address", "verdict": "true_positive",
     "techniques": ["T1114.003"], "entities": ["leo.martins@kestrelridge.example"]},
    {"id": "INC-2047", "title": "Session cookie replayed from a new network", "verdict": "true_positive",
     "techniques": ["T1539", "T1550.004"], "entities": ["sara.okafor@kestrelridge.example"]},
    {"id": "INC-2050", "title": "Consent granted to an unverified mail archiver", "verdict": "true_positive",
     "techniques": ["T1528"], "entities": ["MailVault Archiver"]},
    {"id": "INC-2052", "title": "Help-desk agent called a role-assignment tool after reading a ticket", "verdict": "true_positive",
     "techniques": ["T1098.003"], "entities": ["it-helpdesk"]},
    {"id": "INC-2055", "title": "Impossible travel (corporate VPN egress)", "verdict": "benign",
     "techniques": ["T1078.004"], "entities": ["jules.romero@kestrelridge.example"]},
]  # fmt: skip

TENANT_WIDE = {"legacy-auth-not-blocked"}
TECH_TO_M365 = {"T1114.003": {"external-forwarding", "mailbox-audit"}}
TECH_TO_SESSION = {"T1539", "T1550.004"}

# Ground truth for evaluation only: (incident, finding id) pairs a reviewer agreed should be linked.
EXPECTED = {
    ("INC-2041", "F05-01"), ("INC-2041", "F03-01"), ("INC-2041", "P02-01"),
    ("INC-2043", "F01-01"), ("INC-2043", "M365:RULE-01"), ("INC-2043", "M365:MBX-04"),
    ("INC-2047", "F02-01"), ("INC-2047", "SESSION:sign-in-frequency-sensitive-apps"),
    ("INC-2047", "SESSION:no-persistent-browser-unmanaged"), ("INC-2047", "SESSION:token-protection-or-strict-cae"),
    ("INC-2047", "SESSION:app-enforced-restrictions-byod"),
    ("INC-2050", "P08-01"),
    ("INC-2052", "E07-03"), ("INC-2052", "E13-01"),
}  # fmt: skip


@dataclass
class Task:
    id: str
    incident: str
    finding: str
    why: str
    action: str
    status: str = "proposed (preview only)"


def _findings():
    from idsec import graph, inventory

    inv = inventory.load()
    results = detections.run(inv, graph.build(inv))
    return [f for r in results for f in r.findings]


def link(incidents: list[dict] | None = None) -> list[Task]:
    incidents = incidents or INCIDENTS
    fs = _findings()
    mfind = m365.scan()
    sess = [r for r in session.check(session.tenant_policies()) if r.status != "pass"]
    tasks: list[Task] = []
    for inc in incidents:
        if inc["verdict"] != "true_positive":
            continue
        ents = set(inc["entities"])
        techs = set(inc["techniques"])
        for f in fs:
            meta = detections.rule_meta(f.rule)
            named = f.label in ents or f.label.split(":")[0] in ents
            tech = bool(techs & set(meta.get("attack", [])))
            if named or (tech and f.rule in TENANT_WIDE):
                why = "names " + f.label if named else "technique " + ", ".join(sorted(techs & set(meta["attack"])))
                tasks.append(Task("", inc["id"], f.id, why, meta["fix"]))
        for t in techs & set(TECH_TO_M365):
            for mf in mfind:
                if mf.check in TECH_TO_M365[t] and any(e in mf.detail for e in ents):
                    tasks.append(Task("", inc["id"], f"M365:{mf.obj}", f"technique {t}; {mf.detail}", mf.fix))
        if techs & TECH_TO_SESSION:
            for r in sess:
                tasks.append(
                    Task(
                        "",
                        inc["id"],
                        f"SESSION:{r.check}",
                        "stolen session; " + r.meaning + " is not enforced",
                        "enforce the proposed report-only policy after the impact review",
                    )
                )
    for i, t in enumerate(tasks, 1):
        t.id = f"HT-{i:03d}"
    return tasks


def evaluate() -> dict:
    got = {(t.incident, t.finding) for t in link()}
    tp = len(got & EXPECTED)
    return {
        "incidents": len(INCIDENTS),
        "true_positive_incidents": sum(i["verdict"] == "true_positive" for i in INCIDENTS),
        "tasks": len(got),
        "precision": round(tp / len(got), 3) if got else 1.0,
        "recall": round(tp / len(EXPECTED), 3),
        "benign_incidents_with_tasks": len({i for i, _ in got} & {x["id"] for x in INCIDENTS if x["verdict"] != "true_positive"}),
        "sent": 0,
    }


def write_preview(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    p = out / "hardening-tasks.preview.json"
    p.write_text(json.dumps([asdict(t) for t in link()], indent=2) + "\n")
    return p


def report() -> str:
    lines = ["SOC incident -> hardening tasks (synthetic incidents; preview only, nothing sent)", ""]
    by = {}
    for t in link():
        by.setdefault(t.incident, []).append(t)
    for inc in INCIDENTS:
        lines.append(f"{inc['id']} {inc['title']} [{inc['verdict']}]")
        for t in by.get(inc["id"], []):
            lines.append(f"  {t.id} -> {t.finding}  ({t.why})")
        if inc["id"] not in by:
            lines.append("  no hardening task (benign)" if inc["verdict"] != "true_positive" else "  no linked weakness")
    lines += ["", "Measured against reviewer-agreed links:"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
