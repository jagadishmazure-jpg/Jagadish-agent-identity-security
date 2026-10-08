"""Ground truth for the synthetic tenant: the risks planted by idsec.synth.

Only the metrics read this. Product code (detections, scoring, remediation, the agent) must not
import it, and a test enforces that, so detections cannot peek at the answers."""

from __future__ import annotations

import json

from idsec import DATA


def planted() -> set[tuple[str, str]]:
    doc = json.loads((DATA / "ground-truth.json").read_text())
    return {(x["rule"], x["subject"]) for x in doc["planted"]}


def notes() -> dict[tuple[str, str], str]:
    doc = json.loads((DATA / "ground-truth.json").read_text())
    return {(x["rule"], x["subject"]): x["note"] for x in doc["planted"]}
