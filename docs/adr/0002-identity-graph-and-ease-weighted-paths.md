# ADR 0002: An identity graph with ease-weighted paths

**Status:** Accepted

## Context

Privilege in Entra ID and Azure is often indirect: owning an app with a dangerous permission, contributing
to a VM whose identity owns production, an agent whose tool uses a connection with a stored key. A list
of role assignments misses these.

## Decision

Build a directed graph (networkx) where each edge means "can control or act as", carries a reason and an
ease score from configuration, and find both the shortest and the riskiest path (Dijkstra on −log ease)
from every source to four crown jewels. A standing view drops PIM-eligible edges.

## Consequences

* Paths explain themselves step by step.
* Ease values are judgement, documented as such; shortest paths are reported alongside so ranking never
  hides reachability.
* networkx is fine for tens of thousands of nodes; a very large tenant would need a different engine.
