"""On-premises Active Directory Tier 0 checks and choke-point ranking, on a synthetic directory.

Hybrid tenants are only as safe as the domain that syncs into them. Four checks look for the classic ways
an ordinary domain user becomes a domain admin: Kerberoastable service accounts, DCSync rights held by
something that is not a domain controller, unconstrained delegation outside the domain controllers, and
constrained or resource-based delegation that lands on a domain controller. The findings become edges in a
small attack graph from "any domain user" to Tier 0, and the nodes that the most paths pass through are
ranked as choke points: fix one and every path through it is cut. Look-alikes (a group managed service
account with an SPN, a disabled account, the documented directory-sync account, a read-only replication
right, the domain controllers' own delegation, delegation to a file server) must not be flagged."""

from __future__ import annotations

import itertools
from dataclasses import dataclass

import networkx as nx

DOMAIN = "corp.kestrelridge.example"
FOOTHOLD = "Domain Users"
TIER0 = "TIER0"
TIER0_GROUPS = {"Domain Admins", "Enterprise Admins", "Administrators", "Backup Operators", "Server Operators", "Account Operators"}
DCS = {"DC01", "DC02"}

ACCOUNTS = [  # synthetic: user and service accounts
    {
        "name": "svc_sql",
        "spn": ["MSSQLSvc/sql01.corp.kestrelridge.example:1433"],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 2210,
        "rc4": True,
        "member_of": ["Tier1-Server-Admins"],
    },
    {
        "name": "svc_report",
        "spn": ["HTTP/rpt01.corp.kestrelridge.example"],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 1200,
        "rc4": True,
        "member_of": ["Tier1-Server-Admins"],
    },
    {
        "name": "svc_backup",
        "spn": ["backup/bk01.corp.kestrelridge.example"],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 1460,
        "rc4": True,
        "member_of": ["Backup Operators"],
    },
    {
        "name": "svc_web",
        "spn": ["HTTP/web01.corp.kestrelridge.example"],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 80,
        "rc4": False,
        "member_of": ["Web-Admins"],
    },
    {
        "name": "svc_idm",
        "spn": ["idm/idm01.corp.kestrelridge.example"],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 900,
        "rc4": True,
        "member_of": [],
    },
    {
        "name": "gmsa_web$",
        "spn": ["HTTP/web02.corp.kestrelridge.example"],
        "enabled": True,
        "gmsa": True,
        "pwd_age_days": 20,
        "rc4": False,
        "member_of": ["Web-Admins"],
    },
    {
        "name": "svc_old",
        "spn": ["HTTP/legacy.corp.kestrelridge.example"],
        "enabled": False,
        "gmsa": False,
        "pwd_age_days": 3000,
        "rc4": True,
        "member_of": [],
    },
    {
        "name": "Sync_KRCONNECT01",
        "spn": [],
        "enabled": True,
        "gmsa": False,
        "pwd_age_days": 200,
        "rc4": False,
        "member_of": [],
        "exception": "directory sync to Entra ID",
    },
    {"name": "svc_audit", "spn": [], "enabled": True, "gmsa": False, "pwd_age_days": 300, "rc4": False, "member_of": []},
]
REPLICATION = {  # rights on the domain root
    "svc_idm": {"GetChanges", "GetChangesAll"},
    "Sync_KRCONNECT01": {"GetChanges", "GetChangesAll"},
    "svc_audit": {"GetChanges"},
    "Domain Controllers": {"GetChanges", "GetChangesAll"},
}
COMPUTERS = [
    {"name": "DC01", "unconstrained": True, "delegate_to": [], "rbcd_from": []},
    {"name": "DC02", "unconstrained": True, "delegate_to": [], "rbcd_from": ["KR-PRINT01"]},
    {"name": "APP01", "unconstrained": True, "delegate_to": [], "rbcd_from": []},
    {"name": "WEB01", "unconstrained": False, "delegate_to": ["ldap/DC01.corp.kestrelridge.example"], "rbcd_from": []},
    {"name": "FILESVC", "unconstrained": False, "delegate_to": ["cifs/FS01.corp.kestrelridge.example"], "rbcd_from": []},
    {"name": "KR-PRINT01", "unconstrained": False, "delegate_to": [], "rbcd_from": []},
    {"name": "SQL01", "unconstrained": False, "delegate_to": [], "rbcd_from": []},
]
ADMIN_TO = {"Tier1-Server-Admins": ["APP01", "KR-PRINT01", "SQL01"], "Web-Admins": ["WEB01"]}

# Ground truth for evaluation only: (check, object).
EXPECTED = {
    ("kerberoastable", "svc_sql"), ("kerberoastable", "svc_report"), ("kerberoastable", "svc_backup"), ("kerberoastable", "svc_web"), ("kerberoastable", "svc_idm"),
    ("dcsync-non-dc", "svc_idm"),
    ("unconstrained-delegation", "APP01"),
    ("delegation-to-dc", "WEB01"), ("delegation-to-dc", "KR-PRINT01"),
}  # fmt: skip


@dataclass(frozen=True)
class Finding:
    check: str
    obj: str
    severity: str
    detail: str


def _host(spn: str) -> str:
    return spn.split("/")[1].split(".")[0].split(":")[0].upper()


def tier0_reach(name: str) -> bool:
    acct = next((a for a in ACCOUNTS if a["name"] == name), None)
    return bool(acct and set(acct["member_of"]) & TIER0_GROUPS)


def scan() -> list[Finding]:
    out: list[Finding] = []
    for a in ACCOUNTS:
        if a["spn"] and a["enabled"] and not a["gmsa"]:
            weak = a["rc4"] or a["pwd_age_days"] > 365
            sev = "critical" if tier0_reach(a["name"]) else "high" if weak else "medium"
            out.append(
                Finding(
                    "kerberoastable",
                    a["name"],
                    sev,
                    f"SPN {a['spn'][0]}; password {a['pwd_age_days']} days old; RC4 {'allowed' if a['rc4'] else 'off'}",
                )
            )
    for who, rights in REPLICATION.items():
        acct = next((a for a in ACCOUNTS if a["name"] == who), {})
        if {"GetChanges", "GetChangesAll"} <= rights and who != "Domain Controllers" and not acct.get("exception"):
            out.append(Finding("dcsync-non-dc", who, "critical", "can replicate every password hash from the domain"))
    for c in COMPUTERS:
        if c["unconstrained"] and c["name"] not in DCS:
            out.append(
                Finding(
                    "unconstrained-delegation",
                    c["name"],
                    "critical",
                    "keeps the ticket of anyone who connects; a coerced domain controller hands over its own",
                )
            )
        to_dc = [s for s in c["delegate_to"] if _host(s) in DCS]
        if to_dc:
            out.append(Finding("delegation-to-dc", c["name"], "critical", f"constrained delegation to {', '.join(to_dc)}"))
    for c in COMPUTERS:
        for src in c["rbcd_from"]:
            if c["name"] in DCS:
                out.append(Finding("delegation-to-dc", src, "critical", f"resource-based delegation onto {c['name']}"))
    return out


def tier0_assets() -> list[str]:
    exc = [f"{a['name']} ({a['exception']})" for a in ACCOUNTS if a.get("exception")]
    return sorted(DCS) + sorted(TIER0_GROUPS) + exc


def graph() -> nx.DiGraph:
    g = nx.DiGraph()
    fs = scan()
    for f in fs:
        if f.check == "kerberoastable":
            a = next(x for x in ACCOUNTS if x["name"] == f.obj)
            g.add_edge(FOOTHOLD, f.obj, kind="kerberoast", ease=0.8 if (a["rc4"] or a["pwd_age_days"] > 365) else 0.2)
        elif f.check == "dcsync-non-dc":
            g.add_edge(f.obj, TIER0, kind="dcsync", ease=1.0)
        elif f.check == "unconstrained-delegation":
            g.add_edge(f.obj, TIER0, kind="coerce DC authentication", ease=0.7)
        elif f.check == "delegation-to-dc":
            g.add_edge(f.obj, TIER0, kind="delegate to DC", ease=0.8)
    for a in ACCOUNTS:
        if not a["enabled"]:
            continue
        for grp in a["member_of"]:
            g.add_edge(a["name"], grp, kind="member of", ease=1.0)
    for grp in TIER0_GROUPS:
        if grp in g:
            g.add_edge(grp, TIER0, kind="Tier 0 group", ease=1.0)
    for grp, hosts in ADMIN_TO.items():
        for h in hosts:
            g.add_edge(grp, h, kind="admin to", ease=1.0)
    return g


def paths() -> list[list[str]]:
    g = graph()
    return sorted(nx.all_simple_paths(g, FOOTHOLD, TIER0), key=lambda p: (len(p), p)) if FOOTHOLD in g and TIER0 in g else []


def choke_points() -> list[tuple[str, int, int]]:
    """(node, paths through it, paths left if it alone is fixed), most paths first."""
    ps = paths()
    nodes = {n for p in ps for n in p[1:-1]}
    ranked = [(n, sum(n in p for p in ps), sum(n not in p for p in ps)) for n in nodes]
    return sorted(ranked, key=lambda r: (-r[1], r[0]))


def fix_plan() -> list[str]:
    """Greedy: repeatedly fix the node on the most remaining paths until no path is left."""
    left, plan = paths(), []
    while left:
        counts = {}
        for p in left:
            for n in p[1:-1]:
                counts[n] = counts.get(n, 0) + 1
        best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        plan.append(best)
        left = [p for p in left if best not in p]
    return plan


def evaluate() -> dict:
    got = {(f.check, f.obj) for f in scan()}
    tp = len(got & EXPECTED)
    ps = paths()
    top = choke_points()[0] if ps else ("", 0, 0)
    return {
        "checks": 4,
        "findings": len(got),
        "precision": round(tp / len(got), 3) if got else 1.0,
        "recall": round(tp / len(EXPECTED), 3),
        "look_alikes_flagged": len(got - EXPECTED),
        "paths_to_tier0": len(ps),
        "top_choke_point": top[0],
        "paths_cut_by_top_fix": top[1],
        "fixes_to_cut_every_path": len(fix_plan()),
    }


def report() -> str:
    lines = [f"On-premises AD Tier 0 ({DOMAIN}, synthetic)", ""]
    lines += [f"  {f.severity:<8} [{f.check}] {f.obj}: {f.detail}" for f in scan()]
    lines += ["", f"Paths from any domain user to Tier 0 ({len(paths())}):"]
    g = graph()
    for p in paths():
        lines.append("  " + " -> ".join(f"{a} [{g.edges[a, b]['kind']}]" for a, b in itertools.pairwise(p)) + f" -> {TIER0}")
    lines += ["", "Choke points (fix one, cut every path through it):"]
    lines += [f"  {n:<20} on {k} path(s); {left} left after fixing it" for n, k, left in choke_points()]
    lines += ["", "Fix order that cuts every path: " + " -> ".join(fix_plan())]
    lines += ["", "Tier 0 assets to protect: " + ", ".join(tier0_assets())]
    lines += ["", "Measured (synthetic directory, labelled):"] + [f"  {k}: {v}" for k, v in evaluate().items()]
    return "\n".join(lines)
