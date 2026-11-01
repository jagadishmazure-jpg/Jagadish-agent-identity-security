"""Human approval for the posture packs' changes (drift rollback, session revocation, extension block).

A change is a list of steps against a simulated state, with a digest over its exact content. Only a
configured, human approver can approve (agents and service principals never can); the approval binds to
the digest; changes marked dual-control need two different approvers. `apply` works on an in-memory copy
of the state and returns it with a verification per step. Nothing here calls a real API."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field

from idsec.inventory import load_yaml

AGENT_PREFIXES = ("agent:", "sp:", "mcp:")


@dataclass(frozen=True)
class Step:
    key: str  # dotted path in the simulated state, e.g. "ca.CA01.state"
    value: object
    why: str


@dataclass
class Change:
    id: str
    summary: str
    steps: list[Step]
    dual_control: bool = False

    @property
    def digest(self) -> str:
        body = json.dumps([self.id, self.summary, [(s.key, s.value) for s in self.steps], self.dual_control], sort_keys=True, default=str)
        return hashlib.sha256(body.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Approval:
    change_id: str
    digest: str
    approver: str


class Refused(ValueError):
    pass


def approvers() -> set[str]:
    return {a["id"] for a in load_yaml("approvers.yaml")["approvers"]}


def approve(change: Change, approver: str) -> Approval:
    if approver.startswith(AGENT_PREFIXES):
        raise Refused("agents and service principals cannot approve changes")
    if approver not in approvers():
        raise Refused(f"{approver} is not a configured approver")
    return Approval(change.id, change.digest, approver)


@dataclass
class Result:
    change_id: str
    status: str  # applied | refused
    reason: str = ""
    verified: list[tuple[str, bool]] = field(default_factory=list)


def _get(state: dict, key: str):
    cur = state
    for part in key.split("."):
        cur = cur[part]
    return cur


def _set(state: dict, key: str, value) -> None:
    *head, last = key.split(".")
    cur = state
    for part in head:
        cur = cur.setdefault(part, {})
    cur[last] = value


def apply(change: Change, approvals: list[Approval], state: dict) -> tuple[Result, dict]:
    """Apply to a copy of `state` only when approvals match; return the result and the new state."""
    mine = [a for a in approvals if a.change_id == change.id]
    if any(a.digest != change.digest for a in mine):
        return Result(change.id, "refused", "an approval was for a different version of this change"), state
    people = {a.approver for a in mine}
    need = 2 if change.dual_control else 1
    if len(people) < need:
        return Result(change.id, "refused", f"needs {need} distinct human approver(s), has {len(people)}"), state
    new = copy.deepcopy(state)
    for s in change.steps:
        _set(new, s.key, s.value)
    checks = [(s.key, _get(new, s.key) == s.value) for s in change.steps]
    return Result(change.id, "applied", "simulated state only; nothing was changed in a tenant", checks), new
