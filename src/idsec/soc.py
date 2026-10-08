"""Export findings as SOC alerts for the companion repository Jagadish-azure-ai-soc.

The rows follow that repository's `SecurityAlert` table shape (the fields its
`aisoc.detections.product_alerts` reads): TimeGenerated, SystemAlertId, AlertName, ProductName,
ProviderName, AlertSeverity (Low / Medium / High), Techniques, Tactics, Entities (Type + Name),
Description and EventIds. Posture findings are not attacks in progress, so they arrive as
informational context for the SOC's triage and risk scoring, and critical and high findings become
High and Medium alerts. Display names are passed as entity values only; descriptions carry the rule
explanation, never tenant free text."""

from __future__ import annotations

import json
from datetime import datetime

from idsec import detections
from idsec.inventory import Inventory

SEVERITY = {"critical": "High", "high": "Medium", "medium": "Low", "low": "Low"}
TACTICS = {
    "T1078.003": ["InitialAccess", "Persistence"], "T1078.004": ["InitialAccess", "Persistence", "PrivilegeEscalation"],
    "T1098.001": ["Persistence"], "T1098.003": ["Persistence", "PrivilegeEscalation"], "T1110": ["CredentialAccess"],
    "T1110.003": ["CredentialAccess"], "T1199": ["InitialAccess"], "T1528": ["CredentialAccess"], "T1550.001": ["DefenseEvasion", "LateralMovement"],
    "T1552": ["CredentialAccess"], "T1552.005": ["CredentialAccess"], "T1555.006": ["CredentialAccess"], "T1651": ["Execution"],
    "T1484.002": ["DefenseEvasion", "PrivilegeEscalation"],
}  # fmt: skip
REQUIRED = (
    "TimeGenerated",
    "SystemAlertId",
    "AlertName",
    "ProductName",
    "ProviderName",
    "AlertSeverity",
    "Techniques",
    "Tactics",
    "Entities",
    "Description",
    "EventIds",
)
PRODUCT = "Agent Identity Security (posture scan)"


def _entity(inv: Inventory, f: detections.Finding) -> dict:
    p = inv.principals.get(f.subject)
    if p is not None:
        return {"Type": "account", "Name": p.upn or p.name}
    if f.subject.startswith("asst_"):
        return {"Type": "account", "Name": f"agent:{f.label}"}
    return {"Type": "account", "Name": f.label}


def export(inv: Inventory, results: list[detections.RuleResult], now: datetime | None = None) -> list[dict]:
    ts = (now or inv.now).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    for f in detections.all_findings(results):
        m = f.meta
        techniques = list(m.get("attack", []))
        tactics = sorted({t for x in techniques for t in TACTICS.get(x, [])})
        rows.append(
            {
                "TimeGenerated": ts,
                "SystemAlertId": f"ids-{f.id.lower()}",
                "AlertName": f"Identity posture: {m['title']}",
                "ProductName": PRODUCT,
                "ProviderName": PRODUCT,
                "AlertSeverity": SEVERITY[f.severity],
                "Techniques": techniques,
                "Tactics": tactics,
                "Entities": [_entity(inv, f)],
                "Description": f"{m['explanation']} Fix: {m['fix']} (finding {f.id}, rule {f.rule}, severity {f.severity})",
                "EventIds": [],
                "ExtendedProperties": {
                    "finding_id": f.id,
                    "rule": f.rule,
                    "area": f.area,
                    "atlas": m.get("atlas", []),
                    "owasp_llm": m.get("owasp_llm", []),
                },
            }
        )
    return rows


def validate(rows: list[dict]) -> list[str]:
    problems = []
    for r in rows:
        missing = [k for k in REQUIRED if k not in r]
        if missing:
            problems.append(f"{r.get('SystemAlertId')}: missing {missing}")
        if r.get("AlertSeverity") not in ("Low", "Medium", "High"):
            problems.append(f"{r.get('SystemAlertId')}: severity {r.get('AlertSeverity')}")
        for e in r.get("Entities", []):
            if "Type" not in e or not any(k in e for k in ("Name", "HostName", "Address", "Url")):
                problems.append(f"{r.get('SystemAlertId')}: entity without a value")
    return problems


def dumps(rows: list[dict]) -> str:
    return json.dumps(rows, indent=1)
