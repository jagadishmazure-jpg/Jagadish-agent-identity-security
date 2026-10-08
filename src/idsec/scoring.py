"""Posture scores per area, from 0 (every check failing everywhere) to 100 (nothing found).

For each rule: half of its weight is earned by having no findings at all, the other half by the
share of evaluated subjects that pass. Weights come from the rule's severity (config/scan.yaml).
An area score is the weighted average of its rules; the overview is the plain average of the three
areas. Rules that evaluated nothing (no subjects of that kind) are left out rather than counted as a
pass."""

from __future__ import annotations

from dataclasses import dataclass

from idsec.detections import RuleResult, rule_meta
from idsec.inventory import load_yaml

AREAS = ("privilege", "foundational", "emerging")
AREA_LABELS = {
    "privilege": "Privilege and escalation paths",
    "foundational": "Foundational identity hygiene",
    "emerging": "AI agents, workload identities and secrets",
}


@dataclass
class AreaScore:
    area: str
    score: float
    rules: int
    rules_clean: int
    findings: int


def rule_score(r: RuleResult) -> float | None:
    if r.evaluated == 0:
        return None
    f = len(r.findings)
    return 1.0 if f == 0 else 0.5 * max(0.0, 1 - f / r.evaluated)


def score(results: list[RuleResult]) -> dict[str, AreaScore]:
    weights = load_yaml("scan.yaml")["severity_weights"]
    out = {}
    for area in AREAS:
        num = den = 0.0
        rules = clean = n = 0
        for r in results:
            meta = rule_meta(r.rule)
            s = rule_score(r)
            if meta["area"] != area or s is None:
                continue
            w = weights[meta["severity"]]
            num += w * s
            den += w
            rules += 1
            clean += not r.findings
            n += len(r.findings)
        out[area] = AreaScore(area, round(100 * num / den, 1) if den else 100.0, rules, clean, n)
    overview = round(sum(a.score for a in out.values()) / len(out), 1)
    out["overview"] = AreaScore("overview", overview, sum(a.rules for a in out.values()), sum(a.rules_clean for a in out.values()),
                                sum(a.findings for a in out.values()))  # fmt: skip
    return out


def grade(s: float) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
