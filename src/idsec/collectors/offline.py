"""Offline collector: validate a directory of raw files and copy it to the scan location."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

REQUIRED = [
    "graph/users.json", "graph/groups.json", "graph/applications.json", "graph/servicePrincipals.json",
    "graph/roleDefinitions.json", "graph/roleAssignmentScheduleInstances.json", "graph/conditionalAccessPolicies.json",
    "arm/resourceContainers.json", "arm/resources.json", "arm/roleDefinitions.json", "arm/roleAssignments.json",
]  # fmt: skip


def validate(src: Path) -> list[str]:
    problems = []
    for rel in REQUIRED:
        p = src / rel
        if not p.exists():
            problems.append(f"missing {rel}")
            continue
        try:
            json.loads(p.read_text())
        except json.JSONDecodeError as e:
            problems.append(f"{rel}: invalid JSON ({e.msg})")
    return problems


def collect(src: Path, dest: Path) -> list[str]:
    problems = validate(src)
    if problems:
        return problems
    if src.resolve() != dest.resolve():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    return []
