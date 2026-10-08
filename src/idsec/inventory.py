"""Normalise raw Microsoft Graph and Azure Resource Manager JSON into one typed inventory.

The offline loader and the live collectors write the same raw files (see `data/tenant/`), so this
module is the single place that understands Graph and ARM shapes. Everything downstream (graph,
detections, scores, reports, the agent) works on `Inventory`.

Text fields that anyone with write access to an object can set (display names, descriptions,
notes, agent instructions) are kept verbatim here and treated as untrusted by every consumer."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path

import yaml

from idsec import CONFIG, TENANT_DATA


def load_yaml(name: str) -> dict:
    return yaml.safe_load((CONFIG / name).read_text())


def parse_time(value: str | int | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int):
        return datetime.fromtimestamp(value, tz=UTC)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Principal:
    id: str
    kind: str  # user | guest | group | app | managed_identity | agent_identity | external_app | first_party
    name: str
    upn: str = ""
    enabled: bool = True
    home_tenant: str = ""
    owners: list[str] = field(default_factory=list)
    sponsors: list[str] = field(default_factory=list)
    description: str = ""  # untrusted
    notes: str = ""  # untrusted
    last_sign_in_days: float | None = None
    created_days: float | None = None
    mfa_registered: bool | None = None
    methods: list[str] = field(default_factory=list)
    app_id: str = ""
    verified_publisher: str = ""
    is_blueprint: bool = False
    role_assignable: bool = False
    members: list[str] = field(default_factory=list)  # groups only, direct members

    @property
    def human(self) -> bool:
        return self.kind in ("user", "guest")

    @property
    def workload(self) -> bool:
        return self.kind in ("app", "managed_identity", "agent_identity", "external_app")


@dataclass
class DirRoleAssignment:
    principal_id: str
    role: str
    state: str  # standing | activated | eligible


@dataclass
class AzureRoleAssignment:
    id: str
    principal_id: str
    role: str
    scope: str
    state: str  # standing | eligible


@dataclass
class AppPermission:
    sp_id: str
    resource: str
    permission: str


@dataclass
class ConsentGrant:
    id: str
    client_id: str
    consent_type: str  # AllPrincipals | Principal
    principal_id: str | None
    scopes: list[str]


@dataclass
class AppCredential:
    sp_id: str
    kind: str  # password | certificate
    name: str
    created_days: float
    lifetime_days: float
    expires_in_days: float


@dataclass
class FederatedCredential:
    principal_id: str
    name: str
    issuer: str
    subject: str | None
    expression: str | None = None


@dataclass
class CAPolicy:
    id: str
    name: str
    state: str
    include_users: list[str]
    exclude_users: list[str]
    include_groups: list[str]
    exclude_groups: list[str]
    include_roles: list[str]  # role display names
    grant: list[str]
    client_app_types: list[str]
    auth_strength: str | None = None


@dataclass
class Resource:
    id: str
    name: str
    type: str
    subscription: str
    resource_group: str
    env: str
    identities: list[str] = field(default_factory=list)  # principal IDs this resource runs as
    props: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    parent: str | None = None


@dataclass
class Secret:
    vault: str
    name: str
    created_days: float
    updated_days: float
    expires_in_days: float | None
    credential_for: str | None  # appId of the application whose credential this secret stores
    tags: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"secret:{self.vault}/{self.name}"


@dataclass
class Connection:
    name: str
    project_id: str
    auth_type: str
    target: str
    secret_ref: str | None

    @property
    def key(self) -> str:
        return f"conn:{self.name}"


@dataclass
class Tool:
    name: str
    kind: str
    capabilities: list[str]
    connection: str | None = None


@dataclass
class Agent:
    id: str
    name: str
    project_id: str
    identity_id: str
    purpose: str
    ingests: str  # untrusted | internal
    description: str  # untrusted
    instructions: str  # untrusted
    tools: list[Tool]


@dataclass
class SaasAccount:
    app: str
    slug: str
    user_name: str
    roles: list[str]
    active: bool
    sso: bool
    entra_id: str | None

    @property
    def key(self) -> str:
        return f"saas:{self.slug}:{self.user_name}"

    @property
    def admin(self) -> bool:
        return any("admin" in r.lower() for r in self.roles)


@dataclass
class Inventory:
    tenant_id: str
    tenant_name: str
    now: datetime
    subscriptions: dict[str, str]  # id -> env
    principals: dict[str, Principal]
    dir_roles: list[DirRoleAssignment]
    azure_roles: list[AzureRoleAssignment]
    app_permissions: list[AppPermission]
    consents: list[ConsentGrant]
    app_credentials: list[AppCredential]
    federated: list[FederatedCredential]
    ca_policies: list[CAPolicy]
    resources: dict[str, Resource]
    secrets: list[Secret]
    connections: list[Connection]
    agents: list[Agent]
    saas: list[SaasAccount]
    scopes: list[str]  # subscription and resource group scopes

    # -- lookups -----------------------------------------------------------------------------------
    def name(self, pid: str) -> str:
        p = self.principals.get(pid)
        return p.upn or p.name if p else pid

    @cached_property
    def by_app_id(self) -> dict[str, Principal]:
        return {p.app_id: p for p in self.principals.values() if p.app_id and p.kind != "managed_identity"}

    def groups_of(self, pid: str) -> set[str]:
        """Transitive group membership."""
        out: set[str] = set()
        frontier = {pid}
        while frontier:
            nxt = {g.id for g in self.principals.values() if g.kind == "group" and frontier & set(g.members)} - out
            out |= nxt
            frontier = nxt
        return out

    def holders(self, pid: str) -> set[str]:
        return {pid} | self.groups_of(pid)

    def dir_roles_of(self, pid: str, states=("standing", "activated", "eligible")) -> list[DirRoleAssignment]:
        ids = self.holders(pid)
        return [a for a in self.dir_roles if a.principal_id in ids and a.state in states]

    def azure_roles_of(self, pid: str, states=("standing", "eligible")) -> list[AzureRoleAssignment]:
        ids = self.holders(pid)
        return [a for a in self.azure_roles if a.principal_id in ids and a.state in states]

    def permissions_of(self, sp_id: str) -> list[AppPermission]:
        return [p for p in self.app_permissions if p.sp_id == sp_id]

    def resource_by_name(self, name: str) -> Resource | None:
        return next((r for r in self.resources.values() if r.name == name), None)

    def under(self, scope: str) -> list[Resource]:
        s = scope.lower().rstrip("/")
        return [r for r in self.resources.values() if r.id.lower() == s or r.id.lower().startswith(s + "/")]

    def vaults(self) -> list[Resource]:
        return [r for r in self.resources.values() if r.type == "microsoft.keyvault/vaults"]

    def agents_using(self, identity_id: str) -> list[Agent]:
        return [a for a in self.agents if a.identity_id == identity_id]


def scope_kind(scope: str) -> str:
    parts = scope.strip("/").split("/")
    if scope.startswith("/providers/Microsoft.Management/managementGroups"):
        return "management_group"
    if len(parts) == 2:
        return "subscription"
    if len(parts) == 4:
        return "resource_group"
    return "resource"


# ------------------------------------------------------------------------------------------- loading
def _read(root: Path, rel: str, default=None):
    p = root / rel
    if not p.exists():
        return default
    return json.loads(p.read_text())


def _items(doc) -> list[dict]:
    if doc is None:
        return []
    if isinstance(doc, dict):
        return doc.get("value", doc.get("data", []))
    return doc


def load(root: Path = TENANT_DATA, now: datetime | None = None) -> Inventory:
    """Build the inventory from a directory of raw Graph / ARM / Key Vault / Foundry / SaaS files."""
    scan = load_yaml("scan.yaml")
    now = now or parse_time(scan["scan_time"])
    tenant = scan["tenant"]["tenant_id"]
    first_party = set(scan.get("first_party_tenants") or [])

    def days(value) -> float | None:
        t = parse_time(value)
        return None if t is None else round((now - t).total_seconds() / 86400, 1)

    principals: dict[str, Principal] = {}
    reg = {r["id"]: r for r in _items(_read(root, "graph/userRegistrationDetails.json"))}
    for u in _items(_read(root, "graph/users.json")):
        r = reg.get(u["id"], {})
        sia = u.get("signInActivity") or {}
        last = max(filter(None, [parse_time(sia.get("lastSignInDateTime")), parse_time(sia.get("lastNonInteractiveSignInDateTime"))]), default=None)
        principals[u["id"]] = Principal(
            id=u["id"],
            kind="guest" if u.get("userType") == "Guest" else "user",
            name=u.get("displayName") or "",
            upn=u.get("userPrincipalName") or "",
            enabled=bool(u.get("accountEnabled", True)),
            home_tenant=tenant,
            last_sign_in_days=None if last is None else round((now - last).total_seconds() / 86400, 1),
            created_days=days(u.get("createdDateTime")),
            mfa_registered=r.get("isMfaRegistered"),
            methods=list(r.get("methodsRegistered") or []),
        )
    for g in _items(_read(root, "graph/groups.json")):
        principals[g["id"]] = Principal(
            id=g["id"], kind="group", name=g.get("displayName") or "", description=g.get("description") or "", home_tenant=tenant,
            role_assignable=bool(g.get("isAssignableToRole")), members=[m["id"] for m in g.get("members", [])],
        )  # fmt: skip

    apps = {a["appId"]: a for a in _items(_read(root, "graph/applications.json"))}
    app_roles: dict[tuple[str, str], str] = {}
    sps = _items(_read(root, "graph/servicePrincipals.json"))
    for sp in sps:
        for role in sp.get("appRoles") or []:
            app_roles[(sp["id"], role["id"])] = role["value"]
    for sp in sps:
        app = apps.get(sp.get("appId"))
        if sp.get("@odata.type") == "#microsoft.graph.agentIdentity":
            kind = "agent_identity"
        elif sp.get("servicePrincipalType") == "ManagedIdentity":
            kind = "managed_identity"
        elif sp.get("appOwnerOrganizationId") in first_party:
            kind = "first_party"
        elif sp.get("appOwnerOrganizationId") and sp.get("appOwnerOrganizationId") != tenant:
            kind = "external_app"
        else:
            kind = "app"
        owners = {o["id"] for o in sp.get("owners") or []} | {o["id"] for o in (app or {}).get("owners") or []}
        principals[sp["id"]] = Principal(
            id=sp["id"], kind=kind, name=sp.get("displayName") or "", enabled=bool(sp.get("accountEnabled", True)),
            home_tenant=sp.get("appOwnerOrganizationId") or tenant, owners=sorted(owners),
            sponsors=[s["id"] for s in sp.get("sponsors") or []], description=sp.get("description") or "", notes=sp.get("notes") or "",
            app_id=sp.get("appId") or "", verified_publisher=(sp.get("verifiedPublisher") or {}).get("displayName") or "",
            is_blueprint=bool(app and app.get("@odata.type") == "#microsoft.graph.agentIdentityBlueprint"),
        )  # fmt: skip

    app_permissions = []
    for sp in sps:
        for a in sp.get("appRoleAssignments") or []:
            perm = app_roles.get((a["resourceId"], a["appRoleId"]))
            if perm:
                app_permissions.append(AppPermission(sp["id"], a.get("resourceDisplayName") or "", perm))

    consents = [
        ConsentGrant(g["id"], g["clientId"], g["consentType"], g.get("principalId"), (g.get("scope") or "").split())
        for g in _items(_read(root, "graph/oauth2PermissionGrants.json"))
    ]

    creds, feds = [], []
    sp_by_app = {sp["appId"]: sp["id"] for sp in sps if sp.get("servicePrincipalType") != "ManagedIdentity"}
    for a in apps.values():
        sp_id = sp_by_app.get(a["appId"])
        if not sp_id:
            continue
        for kind, key in (("password", "passwordCredentials"), ("certificate", "keyCredentials")):
            for c in a.get(key) or []:
                start, end = parse_time(c["startDateTime"]), parse_time(c["endDateTime"])
                creds.append(
                    AppCredential(sp_id, kind, c.get("displayName") or "", days(c["startDateTime"]), round((end - start).total_seconds() / 86400, 1),
                                  round((end - now).total_seconds() / 86400, 1))  # fmt: skip
                )
        for f in a.get("federatedIdentityCredentials") or []:
            expr = (f.get("claimsMatchingExpression") or {}).get("value")
            feds.append(FederatedCredential(sp_id, f["name"], f.get("issuer") or "", f.get("subject"), expr))

    role_defs = {r["id"]: r["displayName"] for r in _items(_read(root, "graph/roleDefinitions.json"))}
    dir_roles = []
    for a in _items(_read(root, "graph/roleAssignmentScheduleInstances.json")):
        state = "activated" if a.get("assignmentType") == "Activated" else "standing"
        dir_roles.append(DirRoleAssignment(a["principalId"], role_defs.get(a["roleDefinitionId"], a["roleDefinitionId"]), state))
    for a in _items(_read(root, "graph/roleEligibilitySchedules.json")):
        dir_roles.append(DirRoleAssignment(a["principalId"], role_defs.get(a["roleDefinitionId"], a["roleDefinitionId"]), "eligible"))

    ca = []
    for p in _items(_read(root, "graph/conditionalAccessPolicies.json")):
        u = p["conditions"]["users"]
        g = p.get("grantControls") or {}
        ca.append(
            CAPolicy(p["id"], p["displayName"], p["state"], u.get("includeUsers", []), u.get("excludeUsers", []), u.get("includeGroups", []),
                     u.get("excludeGroups", []), [role_defs.get(r, r) for r in u.get("includeRoles", [])], g.get("builtInControls") or [],
                     p["conditions"].get("clientAppTypes") or ["all"], (g.get("authenticationStrength") or {}).get("displayName"))  # fmt: skip
        )

    az_defs = {r["id"].rsplit("/", 1)[-1]: r["properties"]["roleName"] for r in _items(_read(root, "arm/roleDefinitions.json"))}
    azure_roles = []
    for a in _items(_read(root, "arm/roleAssignments.json")):
        pr = a["properties"]
        azure_roles.append(AzureRoleAssignment(a["id"], pr["principalId"], az_defs.get(pr["roleDefinitionId"].rsplit("/", 1)[-1], "unknown"), pr["scope"], "standing"))
    for a in _items(_read(root, "arm/roleEligibilityScheduleInstances.json")):
        pr = a["properties"]
        azure_roles.append(AzureRoleAssignment(a["id"], pr["principalId"], az_defs.get(pr["roleDefinitionId"].rsplit("/", 1)[-1], "unknown"), pr["scope"], "eligible"))

    subs = {s: e for s, e in scan["subscriptions"].items()}
    scopes = []
    containers = _items(_read(root, "arm/resourceContainers.json"))
    for c in containers:
        scopes.append(c["id"])
        if c["type"] == "microsoft.resources/subscriptions":
            subs.setdefault(c["subscriptionId"], (c.get("tags") or {}).get("env", "unknown"))
    rg_env = {c["id"].lower(): (c.get("tags") or {}).get("env") for c in containers}
    resources: dict[str, Resource] = {}
    connections = []
    for r in _items(_read(root, "arm/resources.json")):
        ident = r.get("identity") or {}
        ids = [ident["principalId"]] if ident.get("principalId") else []
        ids += [v["principalId"] for v in (ident.get("userAssignedIdentities") or {}).values() if v.get("principalId")]
        if r["type"] == "microsoft.managedidentity/userassignedidentities":
            ids.append(r["properties"]["principalId"])
        rg_id = f"/subscriptions/{r['subscriptionId']}/resourceGroups/{r['resourceGroup']}".lower()
        env = rg_env.get(rg_id) or subs.get(r["subscriptionId"], "unknown")
        parent = r["id"].rsplit("/", 2)[0] if r["type"].count("/") > 1 else None
        res = Resource(r["id"], r["name"], r["type"], r["subscriptionId"], r["resourceGroup"], env, ids, r.get("properties") or {}, r.get("tags") or {}, parent)
        if r["type"] == "microsoft.cognitiveservices/accounts/projects/connections":
            pr = res.props
            connections.append(Connection(r["name"], parent or "", pr.get("authType", ""), pr.get("target", ""), (pr.get("metadata") or {}).get("secretRef")))
        else:
            resources[r["id"]] = res

    for mi_id, items in (_read(root, "arm/federatedIdentityCredentials.json", {}) or {}).items():
        res = resources.get(mi_id)
        if res:
            for f in items:
                pr = f["properties"]
                feds.append(FederatedCredential(res.props["principalId"], f["name"], pr.get("issuer", ""), pr.get("subject")))

    secrets = []
    kv_dir = root / "keyvault"
    for f in sorted(kv_dir.glob("*.json")) if kv_dir.exists() else []:
        for s in _items(json.loads(f.read_text())):
            at = s["attributes"]
            exp = parse_time(at.get("exp"))
            tags = s.get("tags") or {}
            secrets.append(
                Secret(f.stem, s["id"].rstrip("/").rsplit("/", 1)[-1], days(at["created"]), days(at["updated"]),
                       None if exp is None else round((exp - now).total_seconds() / 86400, 1), tags.get("credentialFor"), tags)  # fmt: skip
            )

    caps_map = load_yaml("agent-purposes.yaml")["openapi_method_caps"]
    agents = []
    for a in _items(_read(root, "foundry/agents.json")):
        md = a.get("metadata") or {}
        declared = json.loads(md.get("toolCapabilities") or "{}")
        tools = []
        for t in a.get("tools") or []:
            if t["type"] == "openapi":
                o = t["openapi"]
                system = o["name"].split("_")[0]
                caps = sorted({f"{system}.{caps_map.get(op.split()[0], 'write')}" for op in o.get("spec_summary", {}).get("operations", [])})
                conn = ((o.get("auth") or {}).get("security_scheme") or {}).get("connection_id")
                tools.append(Tool(o["name"], "openapi", caps, conn.rsplit("/", 1)[-1] if conn else None))
            elif t["type"] == "function":
                name = t["function"]["name"]
                tools.append(Tool(name, "function", sorted(declared.get(name, []))))
            else:
                name = t.get("server_label") or t["type"]
                tools.append(Tool(name, t["type"], sorted(declared.get(name, []))))
        agents.append(
            Agent(a["id"], a["name"], a["project"], md.get("agentIdentityId", ""), md.get("purpose", ""), md.get("ingests", "untrusted"),
                  a.get("description") or "", a.get("instructions") or "", tools)  # fmt: skip
        )

    saas = []
    saas_dir = root / "saas"
    for f in sorted(saas_dir.glob("*.json")) if saas_dir.exists() else []:
        doc = json.loads(f.read_text())
        for acct in doc["accounts"]:
            saas.append(SaasAccount(doc["app"], f.stem, acct["userName"], acct["roles"], acct["active"], acct["ssoLinked"], acct.get("externalId")))

    return Inventory(
        tenant_id=tenant, tenant_name=scan["tenant"]["name"], now=now, subscriptions=subs, principals=principals, dir_roles=dir_roles,
        azure_roles=azure_roles, app_permissions=app_permissions, consents=consents, app_credentials=creds, federated=feds, ca_policies=ca,
        resources=resources, secrets=secrets, connections=connections, agents=agents, saas=saas, scopes=scopes,
    )  # fmt: skip


def summary(inv: Inventory) -> dict[str, int]:
    kinds: dict[str, int] = {}
    for p in inv.principals.values():
        kinds[p.kind] = kinds.get(p.kind, 0) + 1
    return {
        "human users (members)": kinds.get("user", 0),
        "guest users": kinds.get("guest", 0),
        "groups": kinds.get("group", 0),
        "app service principals (home tenant)": kinds.get("app", 0),
        "external multi-tenant apps": kinds.get("external_app", 0),
        "Microsoft first-party service principals": kinds.get("first_party", 0),
        "managed identities": kinds.get("managed_identity", 0),
        "agent identities": kinds.get("agent_identity", 0),
        "AI agents": len(inv.agents),
        "agent tools": sum(len(a.tools) for a in inv.agents),
        "project connections": len(inv.connections),
        "app credentials (secrets + certificates)": len(inv.app_credentials),
        "federated credentials": len(inv.federated),
        "Key Vault secrets (metadata only)": len(inv.secrets),
        "directory role assignments": len(inv.dir_roles),
        "Azure role assignments": len(inv.azure_roles),
        "application permissions": len(inv.app_permissions),
        "delegated consent grants": len(inv.consents),
        "Conditional Access policies": len(inv.ca_policies),
        "Azure resources": len(inv.resources),
        "SaaS accounts": len(inv.saas),
    }
