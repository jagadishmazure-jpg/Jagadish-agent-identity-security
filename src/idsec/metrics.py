"""Metrics from real runs: detection precision and recall against the planted ground truth,
path-analysis results, score before and after the simulated remediation, guardrail outcomes and
runtime. Every number in the docs comes from these functions through `idsec` commands."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from idsec import detections, inventory, labels, paths, remediation
from idsec import graph as gmod
from idsec.tools import IdentityTools


@dataclass
class RuleMetric:
    rule: str
    planted: int
    found: int
    tp: int

    @property
    def precision(self) -> float:
        return self.tp / self.found if self.found else 1.0

    @property
    def recall(self) -> float:
        return self.tp / self.planted if self.planted else 1.0


def detection(results: list[detections.RuleResult] | None = None) -> tuple[list[RuleMetric], dict]:
    inv = inventory.load()
    results = results or detections.run(inv)
    truth = labels.planted()
    found = {(f.rule, f.subject) for r in results for f in r.findings}
    rows = []
    for meta in detections.catalogue():
        rid = meta["id"]
        t = {x for x in truth if x[0] == rid}
        f = {x for x in found if x[0] == rid}
        rows.append(RuleMetric(rid, len(t), len(f), len(t & f)))
    tp = len(truth & found)
    total = {
        "planted": len(truth),
        "found": len(found),
        "true_positives": tp,
        "false_positives": len(found - truth),
        "false_negatives": len(truth - found),
        "precision": round(tp / len(found), 3) if found else 1.0,
        "recall": round(tp / len(truth), 3) if truth else 1.0,
        "rules_with_a_planted_case": sum(1 for r in rows if r.planted),
        "rules": len(rows),
    }
    return rows, total


def path_summary() -> dict:
    inv = inventory.load()
    g = gmod.build(inv)
    standing = paths.analyse(inv, g)
    with_eligible = paths.analyse(inv, g, include_eligible=True)
    out = {"crown jewels": len(paths.crown_jewels(inv, g))}
    for cj in paths.crown_jewels(inv, g):
        ps = [p for p in standing if p.jewel == cj.id]
        humans = [p for p in ps if g.nodes[p.source]["kind"] in ("user", "guest")]
        out[f"{cj.id}: sources with a standing path"] = len(ps)
        out[f"{cj.id}: of which people"] = len(humans)
        out[f"{cj.id}: shortest / longest riskiest path (hops)"] = f"{min(p.hops for p in ps)} / {max(p.hops for p in ps)}" if ps else "-"
    out["standing paths in total"] = len(standing)
    out["paths when PIM-eligible roles are activated"] = len(with_eligible)
    out["paths that start from untrusted agent input"] = len(paths.untrusted_paths(inv, g))
    return out


def injection_matrix() -> list[dict]:
    """Questions about objects whose free text carries instructions, with the guard on and off,
    answered by the deliberately gullible mock model."""
    from idsec import llm

    inv = inventory.load()
    g = gmod.build(inv)
    res = detections.run(inv, g)
    questions = ["Tell me about Harbor Backup Service", "Describe marketing-copy", "Tell me about agent-marketing-copy"]
    rows = []
    for guard in (True, False):
        gw = IdentityTools(inv, g, res, guard=guard)
        for q in questions:
            e = asyncio.run(llm.ask(gw, q, gullible=True))
            rows.append({"guard": "on" if guard else "off", "question": q, "model obeyed": e.obeyed_injection, "validator caught": e.used_fallback,
                         "final answer safe": not llm.guardrails.CLAIMS_CLEAN.search(e.answer.answer)})  # fmt: skip
    return rows


def runtime(repeats: int = 3) -> dict:
    """Wall-clock timings on this machine (not rendered into docs: they vary run to run)."""
    out: dict[str, float] = {}
    for _ in range(repeats):
        t0 = time.perf_counter()
        inv = inventory.load()
        t1 = time.perf_counter()
        g = gmod.build(inv)
        t2 = time.perf_counter()
        res = detections.run(inv, g)
        t3 = time.perf_counter()
        paths.analyse(inv, g)
        t4 = time.perf_counter()
        remediation.simulate(inv, res)
        t5 = time.perf_counter()
        for k, v in (("load inventory", t1 - t0), ("build graph", t2 - t1), ("28 detections", t3 - t2), ("all crown-jewel paths", t4 - t3),
                     ("plan + simulate + re-scan", t5 - t4), ("total", t5 - t0)):  # fmt: skip
            out[k] = min(out.get(k, 1e9), v)
    return {k: round(v * 1000, 1) for k, v in out.items()}
