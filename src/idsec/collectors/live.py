"""Live, read-only collectors for a real tenant.

Status: written and exercised against a fake transport in tests; never run against a tenant from
this repository. Endpoints and API versions below are the documented ones at the time of writing;
the Foundry agent list and the Entra Agent ID sponsor relationship are newer APIs, so check them
against the current reference before a first run (docs/adopt-this.md lists the checks).

Least-privilege permissions (application permissions for the reader identity; see docs/adopt-this.md):
  Microsoft Graph: User.Read.All, GroupMember.Read.All, Application.Read.All, DelegatedPermissionGrant.Read.All,
                   RoleManagement.Read.Directory, Policy.Read.All, AuditLog.Read.All
  Azure:           the custom "Identity Posture Reader" role (infra/) at the subscriptions or management group in scope
  Key Vault:       secret metadata only (readMetadata data action); secret values are never requested
  Foundry:         read access to agents in each project in scope
"""

from __future__ import annotations

import json
from pathlib import Path

from idsec.collectors.http import Transport

GRAPH = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com"
G = "https://graph.microsoft.com/.default"
A = "https://management.azure.com/.default"
KV = "https://vault.azure.net/.default"
AI = "https://ai.azure.com/.default"
# Microsoft Graph's well-known application ID (public and identical in every tenant).
MSGRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"

USER_SELECT = "id,displayName,userPrincipalName,mail,userType,accountEnabled,department,jobTitle,createdDateTime,signInActivity,onPremisesSyncEnabled,externalUserState,creationType"
SP_SELECT = "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,tags,notes,description,verifiedPublisher,appRoles,alternativeNames"
APP_SELECT = "id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,tags,notes"
RESOURCE_TYPES = [
    "microsoft.keyvault/vaults", "microsoft.managedidentity/userassignedidentities", "microsoft.compute/virtualmachines",
    "microsoft.web/sites", "microsoft.storage/storageaccounts", "microsoft.cognitiveservices/accounts",
    "microsoft.cognitiveservices/accounts/projects", "microsoft.app/containerapps", "microsoft.app/jobs", "microsoft.logic/workflows",
]  # fmt: skip


def credential_token():  # pragma: no cover - needs azure-identity and a real identity
    from azure.identity import DefaultAzureCredential

    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return lambda scope: cred.get_token(scope).token


def collect_graph(t: Transport) -> dict[str, object]:
    out: dict[str, object] = {}
    out["graph/users.json"] = {"value": t.get_all(f"{GRAPH}/users?$select={USER_SELECT}&$top=999", G)}
    out["graph/userRegistrationDetails.json"] = {"value": t.get_all(f"{GRAPH}/reports/authenticationMethods/userRegistrationDetails", G)}
    groups = t.get_all(f"{GRAPH}/groups?$select=id,displayName,description,securityEnabled,isAssignableToRole&$top=999", G)
    for g in groups:
        g["members"] = t.get_all(f"{GRAPH}/groups/{g['id']}/members?$select=id", G)
    out["graph/groups.json"] = {"value": groups}
    apps = t.get_all(f"{GRAPH}/applications?$select={APP_SELECT}&$expand=owners($select=id)", G)
    for a in apps:
        a["federatedIdentityCredentials"] = t.get_all(f"{GRAPH}/applications/{a['id']}/federatedIdentityCredentials", G)
    out["graph/applications.json"] = {"value": apps}
    sps = t.get_all(f"{GRAPH}/servicePrincipals?$select={SP_SELECT}&$expand=owners($select=id)&$top=999", G)
    agent_ids = {x["id"] for x in t.get_all(f"{GRAPH}/servicePrincipals/microsoft.graph.agentIdentity?$select=id", G)}
    graph_sp = next((s for s in sps if s.get("appId") == MSGRAPH_APP_ID), None)
    assigned = t.get_all(f"{GRAPH}/servicePrincipals/{graph_sp['id']}/appRoleAssignedTo", G) if graph_sp else []
    for s in sps:
        s["appRoleAssignments"] = [a for a in assigned if a.get("principalId") == s["id"]]
        if s["id"] in agent_ids:
            s["@odata.type"] = "#microsoft.graph.agentIdentity"
            s["sponsors"] = t.get_all(f"{GRAPH}/servicePrincipals/{s['id']}/microsoft.graph.agentIdentity/sponsors?$select=id", G)
    out["graph/servicePrincipals.json"] = {"value": sps}
    out["graph/oauth2PermissionGrants.json"] = {"value": t.get_all(f"{GRAPH}/oauth2PermissionGrants", G)}
    out["graph/roleDefinitions.json"] = {
        "value": t.get_all(f"{GRAPH}/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId", G)
    }
    out["graph/roleAssignmentScheduleInstances.json"] = {"value": t.get_all(f"{GRAPH}/roleManagement/directory/roleAssignmentScheduleInstances", G)}
    out["graph/roleEligibilitySchedules.json"] = {"value": t.get_all(f"{GRAPH}/roleManagement/directory/roleEligibilitySchedules", G)}
    out["graph/conditionalAccessPolicies.json"] = {"value": t.get_all(f"{GRAPH}/identity/conditionalAccess/policies", G)}
    return out


def collect_azure(t: Transport, subscriptions: list[str]) -> dict[str, object]:
    out: dict[str, object] = {}
    types = ", ".join(f"'{x}'" for x in RESOURCE_TYPES)
    out["arm/resourceContainers.json"] = {"data": t.resource_graph(
        "resourcecontainers | where type in~ ('microsoft.resources/subscriptions','microsoft.resources/subscriptions/resourcegroups') "
        "| project id, name, type, subscriptionId, location, tags", subscriptions)}  # fmt: skip
    resources = t.resource_graph(
        f"resources | where type in~ ({types}) | project id, name, type, location, resourceGroup, subscriptionId, tags, identity, properties",
        subscriptions,
    )
    for p in [r for r in resources if r["type"].lower() == "microsoft.cognitiveservices/accounts/projects"]:
        for c in t.get_all(f"{ARM}{p['id']}/connections?api-version=2025-06-01", A):
            resources.append({"id": c["id"], "name": c["name"], "type": "microsoft.cognitiveservices/accounts/projects/connections", "location": p.get("location"),
                              "resourceGroup": p["resourceGroup"], "subscriptionId": p["subscriptionId"], "tags": {}, "identity": None,
                              "properties": {k: v for k, v in (c.get("properties") or {}).items() if k in ("category", "authType", "target", "metadata")}})  # fmt: skip
    out["arm/resources.json"] = {"data": resources}
    out["arm/roleDefinitions.json"] = {"data": t.resource_graph(
        "authorizationresources | where type =~ 'microsoft.authorization/roledefinitions' "
        "| project id, type, properties = pack('roleName', properties.roleName, 'type', properties.type)", subscriptions)}  # fmt: skip
    out["arm/roleAssignments.json"] = {"data": t.resource_graph(
        "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | project id, type, properties", subscriptions)}  # fmt: skip
    eligible = []
    for sub in subscriptions:
        eligible += t.get_all(
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=atScope()",
            A,
        )
    out["arm/roleEligibilityScheduleInstances.json"] = {"value": eligible}
    fics = {}
    for r in resources:
        if r["type"].lower() == "microsoft.managedidentity/userassignedidentities":
            fics[r["id"]] = t.get_all(f"{ARM}{r['id']}/federatedIdentityCredentials?api-version=2023-01-31", A)
    out["arm/federatedIdentityCredentials.json"] = fics
    return out


def collect_vaults(t: Transport, vault_names: list[str]) -> dict[str, object]:
    """Secret metadata only (id, attributes, contentType, tags). The secret-value endpoint is never called."""
    return {f"keyvault/{v}.json": {"value": t.get_all(f"https://{v}.vault.azure.net/secrets?api-version=7.4", KV)} for v in vault_names}


def collect_agents(t: Transport, project_endpoints: dict[str, str]) -> dict[str, object]:
    """Agents per Foundry project: project resource ID -> project endpoint
    (https://<account>.services.ai.azure.com/api/projects/<project>)."""
    agents = []
    for project_id, endpoint in project_endpoints.items():
        for a in t.get_all(f"{endpoint}/assistants?api-version=v1", AI):
            a["project"] = project_id
            agents.append(a)
    return {"foundry/agents.json": {"data": agents}}


def write(out_dir: Path, files: dict[str, object]) -> list[Path]:
    written = []
    for rel, payload in files.items():
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
        written.append(p)
    return written


def collect(out_dir: Path, subscriptions: list[str], vaults: list[str], projects: dict[str, str], transport: Transport | None = None) -> list[Path]:
    t = transport or Transport(credential_token())
    files = {**collect_graph(t), **collect_azure(t, subscriptions), **collect_vaults(t, vaults), **collect_agents(t, projects)}
    return write(out_dir, files)
