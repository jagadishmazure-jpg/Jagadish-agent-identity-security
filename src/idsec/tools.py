"""Read-only tool gateway over one scan: the only way the explainer agent and the MCP server see
the tenant. Every call is recorded; strings that come from the tenant (names, descriptions, notes,
evidence that embeds them) are wrapped as untrusted data when the guard is on. There is no tool that
changes anything, approves remediation or reveals a secret value (the inventory never holds one)."""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from idsec import detections, guardrails, scoring
from idsec import graph as gmod
from idsec import paths as pmod
from idsec.inventory import Inventory


@dataclass
class Call:
    tool: str
    args: dict
    ok: bool


@dataclass
class IdentityTools:
    inv: Inventory
    g: nx.DiGraph
    results: list[detections.RuleResult]
    guard: bool = True
    calls: list[Call] = field(default_factory=list)

    NAMES = ("posture", "list_findings", "get_finding", "paths_to", "blast_radius", "describe_identity", "explain_rule")

    def _log(self, tool: str, args: dict, ok: bool = True) -> None:
        self.calls.append(Call(tool, args, ok))

    def _q(self, text: str) -> str:
        return guardrails.field(text, self.guard)

    @property
    def findings(self) -> list[detections.Finding]:
        return detections.all_findings(self.results)

    def _resolve(self, ref: str) -> str | None:
        ref_l = ref.lower().strip()
        for p in self.inv.principals.values():
            if ref_l in (p.id.lower(), p.upn.lower(), p.name.lower()):
                return gmod.pnode(p.id)
        for a in self.inv.agents:
            if ref_l in (a.id.lower(), a.name.lower()):
                return f"agent:{a.id}"
        return None

    # -- tools -----------------------------------------------------------------------------------
    def posture(self) -> dict:
        """Posture score per area (0-100) with finding counts."""
        self._log("posture", {})
        return {k: {"score": v.score, "grade": scoring.grade(v.score), "findings": v.findings} for k, v in scoring.score(self.results).items()}

    def list_findings(self, severity: str = "", area: str = "", rule: str = "", limit: int = 20) -> list[dict]:
        """Findings filtered by severity (critical/high/medium/low), area (privilege/foundational/emerging) or rule id."""
        self._log("list_findings", {"severity": severity, "area": area, "rule": rule})
        out = [
            {"id": f.id, "severity": f.severity, "area": f.area, "rule": f.rule, "title": f.title, "subject": self._q(f.label)}
            for f in self.findings
            if (not severity or f.severity == severity) and (not area or f.area == area) and (not rule or f.rule == rule)
        ]
        return out[: max(1, min(limit, 100))]

    def get_finding(self, finding_id: str) -> dict:
        """One finding with its evidence, explanation, fix and framework mappings."""
        f = next((x for x in self.findings if x.id == finding_id), None)
        self._log("get_finding", {"finding_id": finding_id}, f is not None)
        if f is None:
            return {"error": f"no finding {finding_id}"}
        m = f.meta
        return {
            "id": f.id, "severity": f.severity, "title": f.title, "subject": self._q(f.label), "evidence": [self._q(e) for e in f.evidence],
            "explanation": m["explanation"], "fix": m["fix"], "attack": m.get("attack", []), "atlas": m.get("atlas", []),
            "owasp_llm": m.get("owasp_llm", []), "cis": m.get("cis", []), "zero_trust": m.get("zero_trust", ""),
        }  # fmt: skip

    def paths_to(self, jewel: str = "entra-global-admin", limit: int = 5) -> dict:
        """Riskiest standing paths from any identity, agent or outside source to a crown jewel."""
        jewels = {j.id: j for j in pmod.crown_jewels(self.inv, self.g)}
        self._log("paths_to", {"jewel": jewel}, jewel in jewels)
        if jewel not in jewels:
            return {"error": f"unknown crown jewel {jewel}", "known": sorted(jewels)}
        ps = [p for p in pmod.analyse(self.inv, self.g) if p.jewel == jewel]
        return {
            "jewel": jewel, "label": jewels[jewel].label, "sources_with_a_path": len(ps),
            "paths": [{"source": self._q(self.g.nodes[p.source]["label"]), "hops": p.hops, "ease": p.risk, "route": self._q(p.render(self.g))} for p in ps[:limit]],
        }  # fmt: skip

    def blast_radius(self, identity: str) -> dict:
        """What one identity or agent can reach with standing access, and which crown jewels."""
        node = self._resolve(identity)
        self._log("blast_radius", {"identity": identity}, node is not None)
        if node is None:
            return {"error": "identity not found"}
        b = pmod.blast_radius(self.inv, self.g, node)
        return {
            "identity": self._q(b.label),
            "identities": b.identities,
            "resources": b.resources,
            "secrets": b.secrets,
            "agents": b.agents,
            "crown_jewels": b.jewels,
        }

    def describe_identity(self, identity: str) -> dict:
        """Kind, roles, owners and the free-text fields of an identity or agent (free text is untrusted)."""
        node = self._resolve(identity)
        self._log("describe_identity", {"identity": identity}, node is not None)
        if node is None:
            return {"error": "identity not found"}
        if node.startswith("agent:"):
            a = next(x for x in self.inv.agents if f"agent:{x.id}" == node)
            text = f"{a.description} {a.instructions}"
            return {"kind": "agent", "name": self._q(a.name), "purpose": a.purpose, "runs_as": self._q(self.inv.name(a.identity_id)),
                    "tools": [f"{t.name} ({', '.join(t.capabilities)})" for t in a.tools], "description": self._q(a.description),
                    "instruction_like_text": len(guardrails.screen(text)), "findings": [f.id for f in self.findings if f.subject == a.id]}  # fmt: skip
        p = self.inv.principals[node.removeprefix("principal:")]
        roles = [f"{r.state} {r.role}" for r in self.inv.dir_roles_of(p.id)] + [
            f"{r.state} {r.role} on {r.scope.rsplit('/', 1)[-1]}" for r in self.inv.azure_roles_of(p.id)
        ]
        return {
            "kind": p.kind, "name": self._q(self.inv.name(p.id)), "enabled": p.enabled, "roles": sorted(roles),
            "owners": [self._q(self.inv.name(o)) for o in p.owners], "description": self._q(p.description), "notes": self._q(p.notes),
            "instruction_like_text": len(guardrails.screen(f"{p.name} {p.description} {p.notes}")), "findings": [f.id for f in self.findings if f.subject == p.id],
        }  # fmt: skip

    def explain_rule(self, rule_id: str) -> dict:
        """What a detection rule checks, why it matters and how to fix it."""
        ok = rule_id in {r["id"] for r in detections.catalogue()}
        self._log("explain_rule", {"rule_id": rule_id}, ok)
        return detections.rule_meta(rule_id) if ok else {"error": f"unknown rule {rule_id}"}
