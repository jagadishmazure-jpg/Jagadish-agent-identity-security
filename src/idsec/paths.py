"""Privilege-path analysis over the identity graph.

* shortest path: fewest steps from an identity (or outside source) to a crown jewel.
* riskiest path: the path whose steps are easiest to use together (max product of edge ease,
  found with Dijkstra on -log(ease)).
* blast radius: everything an identity can reach, and which crown jewels are among it.

By default only standing access counts (PIM-eligible edges excluded); `include_eligible=True`
adds the paths that need an activation."""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass, field

import networkx as nx

from idsec.graph import UNTRUSTED, pnode, standing_view
from idsec.inventory import Inventory, load_yaml


@dataclass
class CrownJewel:
    id: str
    node: str
    label: str


@dataclass
class Path:
    source: str
    jewel: str
    nodes: list[str]
    hops: int
    risk: float  # product of edge ease along the path (0..1)
    steps: list[dict] = field(default_factory=list)  # {from, to, kind, why}

    def render(self, g: nx.DiGraph) -> str:
        return " -> ".join(g.nodes[n]["label"] for n in self.nodes)


def crown_jewels(inv: Inventory, g: nx.DiGraph) -> list[CrownJewel]:
    out = []
    for cj in load_yaml("crown-jewels.yaml")["crown_jewels"]:
        n = cj["node"]
        if n.startswith("res:") and "/" not in n:
            r = inv.resource_by_name(n[4:])
            n = f"res:{r.id}" if r else n
        if n in g:
            out.append(CrownJewel(cj["id"], n, cj["label"]))
    return out


def _w(a, b, d) -> float:
    return -math.log(max(d["ease"], 1e-9))


def _steps(g, nodes) -> list[dict]:
    return [{"from": a, "to": b, "kind": g[a][b]["kind"], "why": g[a][b]["why"]} for a, b in itertools.pairwise(nodes)]


def best_paths(g: nx.DiGraph, src: str, jewel: CrownJewel, include_eligible: bool = False) -> tuple[Path, Path] | None:
    view = g if include_eligible else standing_view(g)
    if src not in view or jewel.node not in view or src == jewel.node:
        return None
    try:
        short = nx.shortest_path(view, src, jewel.node)
    except nx.NetworkXNoPath:
        return None
    risky = nx.dijkstra_path(view, src, jewel.node, weight=_w)

    def mk(nodes):
        risk = math.prod(g[a][b]["ease"] for a, b in itertools.pairwise(nodes))
        return Path(src, jewel.id, nodes, len(nodes) - 1, round(risk, 3), _steps(g, nodes))

    return mk(short), mk(risky)


def sources(inv: Inventory, g: nx.DiGraph) -> list[str]:
    """Starting points: enabled identities (not groups), agents and outside sources."""
    out = [pnode(p.id) for p in inv.principals.values() if p.kind != "group" and p.enabled and p.kind != "first_party"]
    out += [f"agent:{a.id}" for a in inv.agents]
    out += [n for n, d in g.nodes(data=True) if d["kind"] == "source"]
    return [n for n in out if n in g]


def analyse(inv: Inventory, g: nx.DiGraph, include_eligible: bool = False) -> list[Path]:
    """Riskiest path from every source to every crown jewel it can reach."""
    out = []
    for cj in crown_jewels(inv, g):
        for s in sources(inv, g):
            r = best_paths(g, s, cj, include_eligible)
            if r:
                out.append(r[1])
    return sorted(out, key=lambda p: (-p.risk, p.hops, p.jewel, p.source))


def shortest(inv: Inventory, g: nx.DiGraph, include_eligible: bool = False) -> list[Path]:
    out = []
    for cj in crown_jewels(inv, g):
        for s in sources(inv, g):
            r = best_paths(g, s, cj, include_eligible)
            if r:
                out.append(r[0])
    return sorted(out, key=lambda p: (p.hops, -p.risk, p.jewel, p.source))


@dataclass
class Blast:
    source: str
    label: str
    identities: int
    resources: int
    secrets: int
    agents: int
    jewels: list[str]

    @property
    def total(self) -> int:
        return self.identities + self.resources + self.secrets + self.agents


IDENTITY_KINDS = {"user", "guest", "app", "managed_identity", "agent_identity", "external_app"}


def blast_radius(inv: Inventory, g: nx.DiGraph, src: str, include_eligible: bool = False) -> Blast:
    view = g if include_eligible else standing_view(g)
    reach = nx.descendants(view, src) if src in view else set()
    kinds = [g.nodes[n]["kind"] for n in reach]
    jewels = sorted(cj.id for cj in crown_jewels(inv, g) if cj.node in reach)
    return Blast(
        src,
        g.nodes[src]["label"] if src in g else src,
        sum(k in IDENTITY_KINDS for k in kinds),
        sum(k.startswith("microsoft.") or k in ("subscription", "resource_group") for k in kinds),
        sum(k == "secret" for k in kinds),
        sum(k == "agent" for k in kinds),
        jewels,
    )


def top_blast(inv: Inventory, g: nx.DiGraph, n: int = 10) -> list[Blast]:
    rows = [blast_radius(inv, g, s) for s in sources(inv, g)]
    rows = [r for r in rows if r.total]
    return sorted(rows, key=lambda b: (-len(b.jewels), -b.total, b.label))[:n]


def untrusted_paths(inv: Inventory, g: nx.DiGraph) -> list[Path]:
    return [p for p in analyse(inv, g) if p.source == UNTRUSTED]
