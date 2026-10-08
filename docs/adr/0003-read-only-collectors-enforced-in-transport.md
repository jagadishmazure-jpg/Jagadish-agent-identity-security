# ADR 0003: Read-only collectors, enforced in the transport

**Status:** Accepted

## Context

A posture scanner holds powerful read access across a tenant. A bug or a malicious change that turns a
read into a write would be serious.

## Decision

All live calls go through one HTTP transport that allows only HTTPS requests to an allow-list of
Microsoft hosts, and only GET, plus POST to the Azure Resource Graph query endpoint (a read). Anything else raises `ReadOnlyViolation` before a request leaves
the process. The Azure role grants only read actions and secret metadata, and the release gate checks
both.

## Consequences

* Read-only is enforced twice: by the permissions and by the code.
* Adding a new endpoint that needs POST (another query API) requires a reviewed change to the allow list.
