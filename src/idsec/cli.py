"""Command line: `idsec <command>`. Every number in the docs is printed by one of these commands
and kept current by scripts/render_docs.py.

    idsec synth [--check]          regenerate (or drift-check) the synthetic tenant
    idsec inventory | graph        what was collected, and the identity graph it became
    idsec scan                     posture scores and findings per rule
    idsec findings [filters]       browse findings (CLI)         |  idsec show <ID>
    idsec rules [--detail]         the detections catalogue with framework mappings
    idsec paths [--jewel J]        riskiest paths to crown jewels  |  idsec blast
    idsec plan [--show ID]         remediation items, snippets     |  idsec simulate
    idsec approvals                approval and dry-run execution walkthrough
    idsec report --out DIR         HTML, markdown, CSV and executive summary
    idsec soc-export [--out F]     findings as SOC alerts for Jagadish-azure-ai-soc
    idsec metrics | path-metrics | injection | bench
    idsec ask "question"           explainer agent (mock model offline)
    idsec mcp | mcp-demo           read-only MCP server
    idsec collect --offline DIR | --live ...   collectors
    idsec iac terraform|bicep|workflows        IaC summaries
    idsec gate                     release gate
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

from idsec import detections, inventory, paths, remediation, report, scoring, soc, synth
from idsec import graph as gmod


def table(rows: list[dict], cols: list[str] | None = None) -> str:
    if not rows:
        return "(none)"
    cols = cols or list(rows[0])
    w = {c: max(len(str(c)), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    out = ["  ".join(str(c).ljust(w[c]) for c in cols).rstrip(), "  ".join("-" * w[c] for c in cols)]
    out += ["  ".join(str(r.get(c, "")).ljust(w[c]) for c in cols).rstrip() for r in rows]
    return "\n".join(out)


def _scan():
    # IDSEC_DATA points at a collected tenant (for example the scan job's /tmp/tenant); ages are
    # then measured from the current time instead of the synthetic tenant's fixed scan time.
    data = os.environ.get("IDSEC_DATA")
    inv = inventory.load(Path(data), now=datetime.now(UTC)) if data else inventory.load()
    g = gmod.build(inv)
    return inv, g, detections.run(inv, g)


def cmd_synth(a) -> int:
    stale = synth.write(check=a.check)
    if a.check:
        print("synthetic tenant matches the generator" if not stale else "stale files (run idsec synth):\n  " + "\n  ".join(stale))
        return 1 if stale else 0
    print(f"wrote synthetic tenant; {len(stale)} file(s) changed")
    return 0


def cmd_inventory(a) -> int:
    inv = inventory.load()
    print(f"tenant: {inv.tenant_name} (synthetic)")
    print(table([{"object": k, "count": v} for k, v in inventory.summary(inv).items()]))
    return 0


def cmd_graph(a) -> int:
    inv = inventory.load()
    s = gmod.stats(gmod.build(inv))
    print(f"nodes {s.pop('nodes')}, edges {s.pop('edges')}")
    print(table([{"node kind": k[5:], "count": v} for k, v in s.items() if k.startswith("node:")]))
    print()
    print(table([{"edge kind": k[5:], "count": v} for k, v in s.items() if k.startswith("edge:")]))
    return 0


def cmd_scan(a) -> int:
    _, _, res = _scan()
    sc = scoring.score(res)
    print(table([{"area": scoring.AREA_LABELS.get(k, "Overview"), "score": v.score, "grade": scoring.grade(v.score), "rules": v.rules,
                  "rules clean": v.rules_clean, "findings": v.findings} for k, v in sc.items()]))  # fmt: skip
    print()
    print(table([{"rule": r.rule, "area": detections.rule_meta(r.rule)["area"], "severity": detections.rule_meta(r.rule)["severity"],
                  "checked": r.evaluated, "findings": len(r.findings)} for r in res]))  # fmt: skip
    return 0


def cmd_findings(a) -> int:
    _, _, res = _scan()
    rows = [
        {"id": f.id, "severity": f.severity, "area": f.area, "title": f.title, "subject": f.label[:44]}
        for f in detections.all_findings(res)
        if (not a.severity or f.severity == a.severity) and (not a.area or f.area == a.area) and (not a.rule or f.rule == a.rule)
    ]
    print(table(rows))
    print(f"\n{len(rows)} finding(s)")
    return 0


def cmd_show(a) -> int:
    _, _, res = _scan()
    f = next((x for x in detections.all_findings(res) if x.id == a.id), None)
    if f is None:
        print(f"no finding {a.id}")
        return 2
    m = f.meta
    print(f"{f.id}  {f.severity.upper()}  {f.title}")
    print(f"subject:  {f.label}")
    print("evidence:")
    for e in f.evidence:
        print(f"  - {e}")
    print(f"why:      {m['explanation']}")
    print(f"fix:      {m['fix']}")
    print(f"ATT&CK {' '.join(m.get('attack', [])) or '-'} | ATLAS {' '.join(m.get('atlas', [])) or '-'} | OWASP LLM {' '.join(m.get('owasp_llm', [])) or '-'} | "
          f"CIS {' '.join(m.get('cis', []))} | Zero Trust: {m['zero_trust']}")  # fmt: skip
    return 0


def cmd_rules(a) -> int:
    if a.detail:
        for r in detections.catalogue():
            maps = [f"ATT&CK {' '.join(r['attack'])}" if r.get("attack") else "", f"ATLAS {' '.join(r['atlas'])}" if r.get("atlas") else "",
                    f"OWASP LLM {' '.join(r['owasp_llm'])}" if r.get("owasp_llm") else "", f"CIS {' '.join(r['cis'])}" if r.get("cis") else "",
                    f"Zero Trust: {r['zero_trust']}" if r.get("zero_trust") else ""]  # fmt: skip
            print(f"{r['code']}  {r['id']}  [{r['severity']}, {r['area']}]")
            print(f"  {r['title']}")
            print(textwrap.fill(f"why: {' '.join(r['explanation'].split())}", 100, initial_indent="  ", subsequent_indent="       "))
            print(textwrap.fill(f"fix: {' '.join(r['fix'].split())}", 100, initial_indent="  ", subsequent_indent="       "))
            print(f"  maps to: {'; '.join(m for m in maps if m)}")
            print(f"  remediation action: {r['action']}\n")
        return 0
    rows = [
        {
            "code": r["code"],
            "id": r["id"],
            "area": r["area"],
            "severity": r["severity"],
            "ATT&CK": " ".join(r.get("attack", [])) or "-",
            "ATLAS / OWASP LLM": " ".join(r.get("atlas", []) + r.get("owasp_llm", [])) or "-",
            "CIS": " ".join(r.get("cis", [])),
        }
        for r in detections.catalogue()
    ]
    print(table(rows))
    return 0


def cmd_paths(a) -> int:
    inv, g, _ = _scan()
    ps = paths.analyse(inv, g, include_eligible=a.eligible)
    if a.jewel:
        ps = [p for p in ps if p.jewel == a.jewel]
    if a.people:
        ps = [p for p in ps if g.nodes[p.source]["kind"] in ("user", "guest") or p.source == gmod.UNTRUSTED]
    print(
        f"{len(ps)} {'paths (eligible roles counted as active)' if a.eligible else 'standing paths'}; showing {min(a.limit, len(ps))}, riskiest first"
    )
    for p in ps[: a.limit]:
        print(f"\n[{p.jewel}] hops {p.hops}, ease {p.risk}")
        print(f"  {g.nodes[p.source]['label']}")
        for s in p.steps:
            print(f"    -> {g.nodes[s['to']]['label']}   ({s['why']})")
    return 0


def cmd_blast(a) -> int:
    inv, g, _ = _scan()
    rows = [{"identity": b.label[:40], "kind": g.nodes[b.source]["kind"], "identities": b.identities, "resources": b.resources, "secrets": b.secrets,
             "agents": b.agents, "crown jewels": len(b.jewels)} for b in paths.top_blast(inv, g, a.top)]  # fmt: skip
    print(table(rows))
    return 0


def cmd_plan(a) -> int:
    inv, _, res = _scan()
    p = remediation.plan(res, inv)
    if a.show:
        it = p.by_id(a.show)
        print(f"{it.id} for {it.finding} ({it.rule}) on {it.label}")
        print(f"change: {it.change}\nmode: {it.mode}; approvals needed: {it.approvals_needed}; digest {it.digest}")
        if it.terraform:
            print("\nterraform:\n" + it.terraform)
        if it.bicep:
            print("\nbicep:\n" + it.bicep)
        return 0
    print(table([{"item": i.id, "action": i.action, "mode": i.mode, "approvers": i.approvals_needed, "subject": i.label[:36]} for i in p.items]))
    modes: dict[str, int] = {}
    for i in p.items:
        modes[i.mode] = modes.get(i.mode, 0) + 1
    print("\n" + ", ".join(f"{k}: {v}" for k, v in sorted(modes.items())))
    return 0


def cmd_simulate(a) -> int:
    inv = inventory.load()
    s = remediation.simulate(inv)
    print(table([{"area": scoring.AREA_LABELS.get(k, "Overview"), "before": s.before[k].score, "after": s.after[k].score, "findings before": s.before[k].findings,
                  "findings after": s.after[k].findings} for k in s.before]))  # fmt: skip
    print(f"\nitems applied in simulation: {len(s.applied)}; left open: {len(s.skipped)} ({', '.join(sorted({m for _, m in s.skipped}))})")
    print(f"standing paths from people and untrusted input to crown jewels: {s.paths_before} -> {s.paths_after}")
    print("\nstill open after the simulated plan:")
    print(table([{"id": f.id, "rule": f.rule, "subject": f.label[:40], "why open": f.evidence[0][:60]} for f in s.remaining]))
    return 0


def cmd_approvals(a) -> int:
    inv, _, res = _scan()
    p = remediation.plan(res, inv)
    it = next(i for i in p.items if i.approvals_needed == 2 and i.mode == "simulated")
    now = inv.now
    lines = [f"item {it.id} ({it.action} on {it.label}) needs {it.approvals_needed} approvers; digest {it.digest}"]
    for who in ("agent:identity-explainer", "mallory@kestrelridge.example"):
        try:
            remediation.approve(it, who, now, inv)
        except remediation.ApprovalError as e:
            lines.append(f"approve as {who}: refused ({e})")
    a1 = remediation.approve(it, "ava.chen@kestrelridge.example", now, inv)
    r = next(x for x in remediation.execute(p, [a1], now) if x.item_id == it.id)
    lines.append(f"one approval: {r.status} ({r.reason})")
    a2 = remediation.approve(it, "priya.nair@kestrelridge.example", now, inv)
    r = next(x for x in remediation.execute(p, [a1, a2], now) if x.item_id == it.id)
    lines.append(f"two approvals: {r.status} ({r.reason})")
    stale = remediation.Approval(it.id, "0" * 16, "priya.nair@kestrelridge.example", now)
    r = next(x for x in remediation.execute(p, [a1, stale], now) if x.item_id == it.id)
    lines.append(f"approval for an older version: {r.status} ({r.reason})")
    r = next(x for x in remediation.execute(p, [a1, a2], now + timedelta(hours=30)) if x.item_id == it.id)
    lines.append(f"approvals older than the TTL: {r.status} ({r.reason})")
    try:
        remediation.execute(p, [a1, a2], now, dry_run=False)
    except NotImplementedError as e:
        lines.append(f"live execution: refused ({e})")
    print("\n".join(lines))
    return 0


def cmd_report(a) -> int:
    inv, g, res = _scan()
    sim = remediation.simulate(inv, res)
    for f in report.write_all(Path(a.out), inv, g, res, sim):
        print(f"wrote {f}")
    return 0


def cmd_soc_export(a) -> int:
    inv, _, res = _scan()
    rows = soc.export(inv, res)
    problems = soc.validate(rows)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(soc.dumps(rows))
        print(f"wrote {a.out}")
    sev: dict[str, int] = {}
    for r in rows:
        sev[r["AlertSeverity"]] = sev.get(r["AlertSeverity"], 0) + 1
    print(f"{len(rows)} alerts in the SecurityAlert shape of Jagadish-azure-ai-soc: " + ", ".join(f"{k} {v}" for k, v in sorted(sev.items())))
    print(f"schema problems: {len(problems)}")
    ex = rows[0]
    print(
        f"example: {ex['SystemAlertId']} | {ex['AlertSeverity']} | {ex['AlertName']} | techniques {', '.join(ex['Techniques']) or '-'} | entity {ex['Entities'][0]['Name']}"
    )
    return 1 if problems else 0


def cmd_metrics(a) -> int:
    from idsec import metrics

    rows, total = metrics.detection()
    print(
        table(
            [
                {
                    "rule": r.rule,
                    "planted": r.planted,
                    "found": r.found,
                    "true positives": r.tp,
                    "precision": f"{r.precision:.2f}",
                    "recall": f"{r.recall:.2f}",
                }
                for r in rows
            ]
        )
    )
    print()
    print(table([{"metric": k, "value": v} for k, v in total.items()]))
    return 0


def cmd_path_metrics(a) -> int:
    from idsec import metrics

    print(table([{"metric": k, "value": v} for k, v in metrics.path_summary().items()]))
    return 0


def cmd_injection(a) -> int:
    from idsec import metrics

    rows = metrics.injection_matrix()
    print(table(rows))
    on = [r for r in rows if r["guard"] == "on"]
    off = [r for r in rows if r["guard"] == "off"]
    print(f"\nguard on: model obeyed {sum(r['model obeyed'] for r in on)} of {len(on)}; guard off: obeyed {sum(r['model obeyed'] for r in off)} of {len(off)}, "
          f"validator caught {sum(r['validator caught'] for r in off)}; unsafe final answers: {sum(not r['final answer safe'] for r in rows)}")  # fmt: skip
    return 0


def cmd_bench(a) -> int:
    from idsec import metrics

    print("wall-clock milliseconds on this machine (best of 3; varies run to run)")
    print(table([{"stage": k, "ms": v} for k, v in metrics.runtime().items()]))
    return 0


def cmd_ask(a) -> int:
    from idsec import llm
    from idsec.tools import IdentityTools

    inv, g, res = _scan()
    gw = IdentityTools(inv, g, res, guard=not a.no_guard)
    e = asyncio.run(llm.ask(gw, a.question, gullible=a.gullible))
    print(f"Q: {e.question}\ntools: {', '.join(e.tool_calls)}\nA: {e.answer.answer}")
    print(f"cited: {', '.join(e.answer.cited_findings) or '-'}; validator issues: {len(e.issues)}; fallback used: {e.used_fallback}")
    return 0


def cmd_mcp(a) -> int:  # pragma: no cover - stdio server
    from idsec.mcp_server import build_server

    build_server().run()
    return 0


def cmd_mcp_demo(a) -> int:
    from idsec.mcp_server import demo

    print("\n".join(asyncio.run(demo())))
    return 0


def cmd_collect(a) -> int:
    from idsec.collectors import live, offline

    if a.offline:
        problems = offline.collect(Path(a.offline), Path(a.out))
        print("\n".join(problems) if problems else f"offline data validated and copied to {a.out}")
        return 1 if problems else 0
    if not a.live:
        print("choose --offline DIR or --live (reads a real tenant; see docs/adopt-this.md)")
        return 2
    projects = dict(x.split("=", 1) for x in a.project)  # pragma: no cover - live
    files = live.collect(Path(a.out), a.subscription, a.vault, projects)  # pragma: no cover - live
    print(f"LIVE collection wrote {len(files)} files to {a.out}")  # pragma: no cover - live
    return 0  # pragma: no cover - live


def cmd_iac(a) -> int:
    from idsec import iac

    print("\n".join(iac.PARTS[a.part]()))
    return 0


def cmd_gate(a) -> int:
    from idsec import gate

    checks = gate.run()
    print(table([{"check": c.name, "result": "pass" if c.ok else "FAIL", "detail": c.detail} for c in checks]))
    failed = [c for c in checks if not c.ok]
    print(f"\n{len(checks) - len(failed)} of {len(checks)} checks passed")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="idsec", description="Identity security posture for humans, workload identities and AI agents (offline-first).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth")
    s.add_argument("--check", action="store_true")
    s.set_defaults(fn=cmd_synth)
    s = sub.add_parser("rules")
    s.add_argument("--detail", action="store_true", help="explanation, fix and mappings for every rule")
    s.set_defaults(fn=cmd_rules)
    for name, fn in (("inventory", cmd_inventory), ("graph", cmd_graph), ("scan", cmd_scan), ("simulate", cmd_simulate),
                     ("approvals", cmd_approvals), ("metrics", cmd_metrics), ("path-metrics", cmd_path_metrics), ("injection", cmd_injection),
                     ("bench", cmd_bench), ("mcp", cmd_mcp), ("mcp-demo", cmd_mcp_demo), ("gate", cmd_gate)):  # fmt: skip
        sub.add_parser(name).set_defaults(fn=fn)
    s = sub.add_parser("findings")
    s.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--area", choices=["privilege", "foundational", "emerging"])
    s.add_argument("--rule")
    s.set_defaults(fn=cmd_findings)
    s = sub.add_parser("show")
    s.add_argument("id")
    s.set_defaults(fn=cmd_show)
    s = sub.add_parser("paths")
    s.add_argument("--jewel")
    s.add_argument("--eligible", action="store_true")
    s.add_argument("--people", action="store_true", help="only paths that start from a person or from untrusted agent input")
    s.add_argument("--limit", type=int, default=5)
    s.set_defaults(fn=cmd_paths)
    s = sub.add_parser("blast")
    s.add_argument("--top", type=int, default=10)
    s.set_defaults(fn=cmd_blast)
    s = sub.add_parser("plan")
    s.add_argument("--show")
    s.set_defaults(fn=cmd_plan)
    s = sub.add_parser("report")
    s.add_argument("--out", default="out")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("soc-export")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_soc_export)
    s = sub.add_parser("ask")
    s.add_argument("question")
    s.add_argument("--no-guard", action="store_true")
    s.add_argument("--gullible", action="store_true")
    s.set_defaults(fn=cmd_ask)
    s = sub.add_parser("collect")
    s.add_argument("--offline")
    s.add_argument("--live", action="store_true")
    s.add_argument("--out", default="data/live")
    s.add_argument("--subscription", action="append", default=[x for x in os.environ.get("IDSEC_SUBSCRIPTIONS", "").split(",") if x])
    s.add_argument("--vault", action="append", default=[])
    s.add_argument("--project", action="append", default=[], help="PROJECT_RESOURCE_ID=PROJECT_ENDPOINT")
    s.set_defaults(fn=cmd_collect)
    s = sub.add_parser("iac")
    s.add_argument("part", choices=["terraform", "bicep", "workflows", "role"])
    s.set_defaults(fn=cmd_iac)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
