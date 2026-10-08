# ADR 0005: The agent explains; code decides

**Status:** Accepted

## Context

A language model is useful for explaining findings but must not be trusted to compute them, and tenant
text (display names, agent instructions) can carry prompt injection.

## Decision

Findings, paths and scores are computed by code. The Microsoft Agent Framework agent and the MCP server
reach the scan only through a read-only gateway with seven tools that quote tenant text as untrusted data.
Answers are validated against known finding IDs and open-finding counts, with a template fallback. A
deterministic mock chat client keeps tests repeatable and lets each defence layer be measured.

## Consequences

* Removing the agent changes no number.
* Injection results come from seeded cases and a mock client; they show the layers work as designed,
  not how a real model behaves.
