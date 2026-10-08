# ADR 0001: Offline first, on a synthetic tenant

**Status:** Accepted

## Context

A portfolio project has no production tenant to scan, and scanning a real tenant would mean handling real
people's data in a public repository. Reviewers still need to run everything in minutes.

## Decision

Everything runs offline on a fictional tenant (Kestrel Ridge Mortgage) produced by a deterministic
generator (`idsec synth`). The generator records every weakness it plants, so detection can be measured.
Live collectors exist, share the file format, and are opt-in (`idsec collect --live`).

## Consequences

* Anyone can clone, install and run the whole pipeline with no cloud account.
* Detection numbers are a regression check, not an accuracy estimate: the same author wrote the generator
  and the rules. Every doc says so.
* The collectors' real behaviour against Microsoft APIs is unverified until someone runs them.
