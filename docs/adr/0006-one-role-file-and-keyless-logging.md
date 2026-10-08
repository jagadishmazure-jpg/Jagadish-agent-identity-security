# ADR 0006: One role file for both IaC stacks, and keyless logging

**Status:** Accepted

## Context

Offering Terraform and Bicep risks the two drifting, especially on permissions. Container Apps
environments that write straight to Log Analytics need the workspace shared key, which conflicts with
disabling local authentication.

## Decision

The custom role lives in one JSON file loaded by Terraform (`jsondecode(file(...))`) and Bicep
(`loadJsonContent`). The workspace disables local auth; the Container Apps environment sends logs to Azure
Monitor and a diagnostic setting forwards them to the workspace.

## Consequences

* Permission changes happen in one place and tests check both stacks load it.
* The logging path has one more resource (the diagnostic setting) but no shared key anywhere.
