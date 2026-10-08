"""Remediation: least-privilege suggestions with Terraform / Bicep snippets, human approval bound to
a digest, a dry-run executor, and a what-if simulation that applies the plan to a copy of the
inventory and re-runs every detection.

Nothing here changes a tenant. `execute(..., dry_run=False)` refuses by design: applying a change
is the job of the owning team's own pipeline, after review of the snippet."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from idsec import detections, scoring
from idsec import graph as gmod
from idsec.detections import Finding, RuleResult
from idsec.inventory import AzureRoleAssignment, Inventory, Principal, Secret, load_yaml, scope_kind

# Actions a person must take themselves (register a method); the simulation leaves them open.
USER_ACTIONS = {"require-mfa-registration", "register-phishing-resistant-method"}
# Findings resolved only by fixing other edges; re-evaluated after the simulation.
DERIVED = {"break-path"}
ORDER = [
    "split-identity", "convert-to-eligible", "narrow-workload-role", "remove-app-permission", "remove-role", "revoke-consent",
    "remove-ca-exclusion", "disable-account", "enforce-ca-policy", "migrate-vault-rbac", "remove-saas-admin", "replace-secret",
    "split-credential", "rotate-secret", "set-expiry", "assign-owner", "assign-sponsor", "remove-agent-role", "remove-tool",
    "switch-connection-auth", "restrict-federated-subject", "break-path", "require-mfa-registration", "register-phishing-resistant-method",
]  # fmt: skip


def slug(text: str) -> str:
    """Safe identifier for snippets: attacker-controlled names never reach HCL or Bicep verbatim."""
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return (s or "subject")[:40]


@dataclass
class Item:
    id: str
    finding: str
    rule: str
    action: str
    subject: str
    label: str
    change: str
    mode: str  # simulated | user-action | derived | needs-decision
    approvals_needed: int
    terraform: str = ""
    bicep: str = ""
    digest: str = ""

    def compute_digest(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "digest"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class Plan:
    items: list[Item]

    def by_id(self, item_id: str) -> Item:
        for i in self.items:
            if i.id == item_id:
                return i
        raise KeyError(item_id)


def _hints() -> dict:
    return load_yaml("remediation-hints.yaml")


def _snippets(action: str, f: Finding, inv: Inventory) -> tuple[str, str]:
    n = slug(f.label)
    p = inv.principals.get(f.subject)
    oid = p.id if p else "<object-id>"
    if action == "convert-to-eligible" and f.rule == "standing-azure-admin":
        tf = (f'resource "azurerm_pim_eligible_role_assignment" "{n}" {{\n  scope              = data.azurerm_subscription.target.id\n'
              f'  role_definition_id = data.azurerm_role_definition.owner.id\n  principal_id       = "{oid}"\n  justification      = "Converted from standing access"\n}}')  # fmt: skip
        bi = (f"resource eligible_{n} 'Microsoft.Authorization/roleEligibilityScheduleRequests@2022-04-01-preview' = {{\n  name: guid(subscription().id, '{oid}', 'eligible')\n"
              f"  properties: {{\n    principalId: '{oid}'\n    roleDefinitionId: ownerRoleId\n    requestType: 'AdminAssign'\n"
              "    scheduleInfo: { expiration: { type: 'AfterDuration', duration: 'P180D' } }\n  }\n}")  # fmt: skip
        return tf, bi
    if action == "convert-to-eligible":
        tf = (f'resource "azuread_directory_role_eligibility_schedule_request" "{n}" {{\n  role_definition_id = data.azuread_directory_role_templates.all.role_templates[0].object_id\n'
              f'  principal_id       = "{oid}"\n  directory_scope_id = "/"\n  justification      = "Converted from standing access"\n}}')  # fmt: skip
        return tf, "// Directory roles are not ARM resources: use the Terraform azuread resource or a Graph roleEligibilityScheduleRequests call."
    if action in ("narrow-workload-role", "remove-role", "remove-agent-role"):
        tf = (f'# remove the broad assignment for {n}, then grant only what the workload needs\nresource "azurerm_role_assignment" "{n}_scoped" {{\n'
              f'  scope                = var.{n}_scope\n  role_definition_name = var.{n}_role\n  principal_id         = "{oid}"\n}}')  # fmt: skip
        bi = (f"resource scoped_{n} 'Microsoft.Authorization/roleAssignments@2022-04-01' = {{\n  name: guid(resourceGroup().id, '{oid}', {n}Role)\n"
              f"  properties: {{ principalId: '{oid}', roleDefinitionId: {n}Role, principalType: 'ServicePrincipal' }}\n}}")  # fmt: skip
        return tf, bi
    if action == "restrict-federated-subject":
        tf = (f'resource "azuread_application_federated_identity_credential" "{n}_prod" {{\n  application_id = data.azuread_application.{n}.id\n'
              f'  display_name   = "{n}-environment-prod"\n  issuer         = "https://token.actions.githubusercontent.com"\n'
              f'  subject        = "repo:<org>/<repo>:environment:prod"\n  audiences      = ["api://AzureADTokenExchange"]\n}}')  # fmt: skip
        bi = ("resource fic 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {\n  parent: uami\n"
              "  name: 'github-environment-prod'\n  properties: {\n    issuer: 'https://token.actions.githubusercontent.com'\n"
              "    subject: 'repo:<org>/<repo>:environment:prod'\n    audiences: [ 'api://AzureADTokenExchange' ]\n  }\n}")  # fmt: skip
        return tf, bi
    if action == "migrate-vault-rbac":
        tf = (f'resource "azurerm_key_vault" "{n}" {{\n  # ...existing arguments...\n  rbac_authorization_enabled    = true\n'
              f'  public_network_access_enabled = false\n}}\n\nresource "azurerm_role_assignment" "{n}_secrets_user" {{\n'
              f'  scope                = azurerm_key_vault.{n}.id\n  role_definition_name = "Key Vault Secrets User"\n  principal_id         = var.consumer_object_id\n}}')  # fmt: skip
        bi = (f"resource {n} 'Microsoft.KeyVault/vaults@2023-07-01' = {{\n  name: '{n}'\n  location: location\n"
              "  properties: { tenantId: tenant().tenantId, sku: { family: 'A', name: 'standard' }, enableRbacAuthorization: true, publicNetworkAccess: 'Disabled' }\n}")  # fmt: skip
        return tf, bi
    if action in ("set-expiry", "rotate-secret"):
        tf = (f'resource "azurerm_key_vault_secret" "{n}" {{\n  # value comes from the rotation job, never from source control\n'
              f'  expiration_date = timeadd(plantimestamp(), "2160h")\n  lifecycle {{ ignore_changes = [value] }}\n}}')  # fmt: skip
        return tf, "// Set attributes.exp on the secret from the rotation job; Bicep should not carry secret values."
    if action == "replace-secret":
        tf = (f'resource "azuread_application_federated_identity_credential" "{n}" {{\n  application_id = data.azuread_application.{n}.id\n'
              f'  display_name   = "{n}-workload"\n  issuer         = var.issuer\n  subject        = var.subject\n  audiences      = ["api://AzureADTokenExchange"]\n}}\n'
              f'# then delete the password credential and set an app management policy (max password lifetime)')  # fmt: skip
        return tf, "// App registrations are Graph objects: use the azuread provider or the Microsoft Graph Bicep extension."
    if action == "switch-connection-auth":
        bi = (f"resource conn_{n} 'Microsoft.CognitiveServices/accounts/projects/connections@2025-06-01' = {{\n  parent: project\n  name: '{n}'\n"
              "  properties: { category: 'CustomKeys', authType: 'AAD', target: target }\n}")  # fmt: skip
        return '# azapi_resource with the same body as the Bicep snippet (authType = "AAD")', bi
    return "", ""


def _change(action: str, f: Finding, inv: Inventory) -> tuple[str, str]:
    """(human-readable change, mode)."""
    h = _hints()
    label = f.label
    if action in USER_ACTIONS:
        return ("Require the person to register MFA (registration campaign / CA registration policy)" if action == "require-mfa-registration"
                else "Register two FIDO2 keys and store them in separate safes"), "user-action"  # fmt: skip
    if action in DERIVED:
        return "Break the weakest edge on the path; re-evaluated after the other changes", "derived"
    if action == "narrow-workload-role":
        hint = h["narrow_role"].get(label)
        if hint:
            where = hint.get("scope_resource") or hint.get("scope_resource_group")
            return f"Replace subscription-wide access with {hint['role']} on {where}", "simulated"
        return "Replace subscription-wide access with Reader until the owner names the needed scope", "needs-decision"
    if action == "assign-owner":
        hint = h["owners"].get(label)
        return (f"Assign owners {', '.join(hint)}", "simulated") if hint else ("Find an owner or disable the app", "needs-decision")
    if action == "assign-sponsor":
        hint = h["sponsors"].get(label)
        return (f"Assign sponsor {', '.join(hint)}", "simulated") if hint else ("Find a sponsor or retire the agent", "needs-decision")
    text = {
        "convert-to-eligible": "Convert the permanent assignment to PIM-eligible with MFA and approval on activation",
        "remove-app-permission": "Remove the application permission; grant the safer alternative in the evidence",
        "remove-role": "Remove write/secret access; keep read-only scope if the contract needs it",
        "revoke-consent": "Revoke the tenant-wide grant; restrict user consent to verified publishers",
        "remove-ca-exclusion": "Remove the person from the MFA exclusion group",
        "disable-account": "Disable the account after manager confirmation",
        "enforce-ca-policy": "Switch the policy from report-only to on",
        "migrate-vault-rbac": "Migrate to Azure RBAC (policies become Key Vault Secrets User/Officer) and disable public access",
        "remove-saas-admin": "Deactivate the SaaS admin account",
        "replace-secret": "Replace the long-lived secret with "
        + {"federated": "a federated credential", "certificate": "a 180-day certificate"}.get(
            h["replace_secret"].get(label, ""), "a secret of at most 180 days"
        ),
        "rotate-secret": "Rotate the secret and automate rotation",
        "set-expiry": "Set an expiry date (90 days) and a near-expiry alert",
        "split-credential": "Issue one credential per consumer",
        "remove-agent-role": "Remove write, admin and secret-read rights from the agent identity",
        "remove-tool": "Remove the tools outside the agent's purpose",
        "switch-connection-auth": "Switch the connection to Microsoft Entra ID authentication",
        "split-identity": "Give each agent its own identity from the blueprint",
        "restrict-federated-subject": "Pin the federated credential to a protected environment",
    }[action]
    return text, "simulated"


def plan(results: list[RuleResult], inv: Inventory) -> Plan:
    cfg = load_yaml("approvers.yaml")
    items = []
    for f in detections.all_findings(results):
        action = f.meta["action"]
        change, mode = _change(action, f, inv)
        tf, bi = _snippets(action, f, inv)
        need = 2 if action in cfg["dual_control_actions"] or f.severity == "critical" else 1
        it = Item(f"R-{f.id}", f.id, f.rule, action, f.subject, f.label, change, mode, need, tf, bi)
        it.digest = it.compute_digest()
        items.append(it)
    return Plan(items)


# ------------------------------------------------------------------------------- approvals and execution
@dataclass
class Approval:
    item_id: str
    digest: str
    approver: str
    at: datetime


class ApprovalError(ValueError):
    pass


def approve(item: Item, approver: str, at: datetime, inv: Inventory | None = None) -> Approval:
    cfg = load_yaml("approvers.yaml")
    known = {a["id"] for a in cfg["approvers"]}
    if approver.startswith(("agent:", "sp:", "mcp:")):
        raise ApprovalError("agents and service principals cannot approve remediation")
    if approver not in known:
        raise ApprovalError(f"{approver} is not a configured approver")
    if inv is not None:
        p = next((x for x in inv.principals.values() if x.upn == approver), None)
        if p is None or not p.enabled or not p.human:
            raise ApprovalError(f"{approver} is not an enabled person in the tenant")
    return Approval(item.id, item.digest, approver, at)


@dataclass
class ExecResult:
    item_id: str
    status: str  # would-apply | blocked
    reason: str = ""
    commands: list[str] = field(default_factory=list)


def execute(p: Plan, approvals: list[Approval], now: datetime, dry_run: bool = True) -> list[ExecResult]:
    if not dry_run:
        raise NotImplementedError("live remediation is not implemented by design; apply the reviewed snippet through the owning team's pipeline")
    ttl = timedelta(hours=load_yaml("approvers.yaml")["approval_ttl_hours"])
    out = []
    for it in p.items:
        mine = [a for a in approvals if a.item_id == it.id]
        valid = {a.approver for a in mine if a.digest == it.digest and now - a.at <= ttl}
        if any(a.digest != it.digest for a in mine):
            out.append(ExecResult(it.id, "blocked", "an approval was for a different version of this item (digest mismatch)"))
        elif len(valid) < it.approvals_needed:
            out.append(ExecResult(it.id, "blocked", f"needs {it.approvals_needed} distinct approver(s), has {len(valid)} valid"))
        else:
            cmds = ["terraform plan -out=remediation.tfplan  # review, then apply from the owning pipeline"] if it.terraform else []
            out.append(ExecResult(it.id, "would-apply", "dry run: nothing was changed", cmds))
    return out


# ------------------------------------------------------------------------------- what-if simulation
def _rm_roles(inv: Inventory, pid: str, caps: set[str], c: detections.Ctx, scope_kinds=None) -> list[AzureRoleAssignment]:
    removed = [
        a
        for a in inv.azure_roles
        if a.principal_id == pid and c.az_caps(a.role) & caps and (scope_kinds is None or scope_kind(a.scope) in scope_kinds)
    ]
    inv.azure_roles = [a for a in inv.azure_roles if a not in removed]
    return removed


def _apply(inv: Inventory, it: Item, c: detections.Ctx) -> bool:
    h = _hints()
    a = it.action
    subj = it.subject
    if it.mode in ("user-action", "derived", "needs-decision"):
        return False
    if a == "convert-to-eligible":
        if it.rule == "standing-privileged-role":
            for r in inv.dir_roles:
                if r.principal_id == subj and r.state == "standing" and c.dir_tier(r.role) <= 1:
                    r.state = "eligible"
        else:
            for r in inv.azure_roles:
                if r.principal_id == subj and r.state == "standing" and r.role in c.roles["azure_admin_roles"]:
                    r.state = "eligible"
        return True
    if a == "narrow-workload-role":
        hint = h["narrow_role"][it.label]
        _rm_roles(inv, subj, {"control", "write"}, c, scope_kinds=("subscription", "management_group"))
        res = inv.resource_by_name(hint["scope_resource"]) if hint.get("scope_resource") else None
        scope = res.id if res else next(s for s in inv.scopes if s.endswith("/" + hint["scope_resource_group"]))
        inv.azure_roles.append(AzureRoleAssignment(f"sim-{it.id}", subj, hint["role"], scope, "standing"))
        return True
    if a == "remove-app-permission":
        perms = c.roles["graph_app_permissions"]
        inv.app_permissions = [x for x in inv.app_permissions if not (x.sp_id == subj and perms.get(x.permission, {"tier": 9})["tier"] <= 1)]
        return True
    if a == "remove-role":
        _rm_roles(inv, subj, {"control", "write", "secrets_read"}, c)
        hint = h["external_role"].get(it.label)
        if hint:
            inv.azure_roles.append(
                AzureRoleAssignment(f"sim-{it.id}", subj, hint["role"], inv.resource_by_name(hint["scope_resource"]).id, "standing")
            )
        return True
    if a == "revoke-consent":
        inv.consents = [g for g in inv.consents if not (g.client_id == subj and g.consent_type == "AllPrincipals")]
        return True
    if a == "remove-ca-exclusion":
        excluded = {g for pol in inv.ca_policies for g in pol.exclude_groups}
        for g in inv.principals.values():
            if g.kind == "group" and g.id in excluded:
                g.members = [m for m in g.members if m != subj]
        return True
    if a == "disable-account":
        inv.principals[subj].enabled = False
        return True
    if a == "enforce-ca-policy":
        for pol in inv.ca_policies:
            if pol.id == subj:
                pol.state = "enabled"
        return True
    if a == "migrate-vault-rbac":
        v = inv.resource_by_name(subj.removeprefix("vault:"))
        for ap in v.props.get("accessPolicies") or []:
            perms = {x.lower() for x in ap["permissions"].get("secrets", [])}
            role = "Key Vault Secrets Officer" if perms & {"set", "delete", "all"} else "Key Vault Secrets User"
            inv.azure_roles.append(AzureRoleAssignment(f"sim-{it.id}-{ap['objectId'][-4:]}", ap["objectId"], role, v.id, "standing"))
        v.props = {**v.props, "enableRbacAuthorization": True, "accessPolicies": [], "publicNetworkAccess": "Disabled"}
        return True
    if a == "remove-saas-admin":
        for s in inv.saas:
            if s.key == subj:
                s.active = False
        return True
    if a == "replace-secret":
        limit = c.th["max_password_lifetime_days"]
        kind = h["replace_secret"].get(it.label)
        keep = [cr for cr in inv.app_credentials if not (cr.sp_id == subj and cr.lifetime_days > limit)]
        if kind == "certificate":
            keep.append(type(inv.app_credentials[0])(subj, "certificate", "rotated-cert", 0, 180, 180))
        elif kind != "federated":
            keep.append(type(inv.app_credentials[0])(subj, "password", "rotated", 0, limit, limit))
        inv.app_credentials = keep
        return True
    if a in ("rotate-secret", "set-expiry"):
        for s in inv.secrets:
            if s.key == subj:
                if a == "rotate-secret":
                    s.updated_days = 0
                if s.expires_in_days is None or a == "set-expiry":
                    s.expires_in_days = 90
        return True
    if a == "split-credential":
        ref = subj.removeprefix("secret:")
        vault, name = ref.split("/", 1)
        users = [conn for conn in inv.connections if conn.secret_ref == ref]
        for i, conn in enumerate(users[1:], 2):
            new = f"{name}-{i}"
            inv.secrets.append(Secret(vault, new, 0, 0, 90, None, {}))
            conn.secret_ref = f"{vault}/{new}"
        return True
    if a in ("assign-owner", "assign-sponsor"):
        names = (h["owners"] if a == "assign-owner" else h["sponsors"])[it.label]
        ids = [p.id for p in inv.principals.values() if p.upn in names]
        if a == "assign-owner":
            inv.principals[subj].owners = ids
        else:
            ag = next(x for x in inv.agents if x.id == subj)
            inv.principals[ag.identity_id].sponsors = ids
        return True
    if a == "remove-agent-role":
        ag = next(x for x in inv.agents if x.id == subj)
        perms = c.roles["graph_app_permissions"]
        _rm_roles(inv, ag.identity_id, {"control", "write", "secrets_read"}, c)
        inv.dir_roles = [r for r in inv.dir_roles if not (r.principal_id == ag.identity_id and c.dir_tier(r.role) <= 1)]
        inv.app_permissions = [
            x for x in inv.app_permissions if not (x.sp_id == ag.identity_id and perms.get(x.permission, {"tier": 9})["tier"] <= 1)
        ]
        return True
    if a == "remove-tool":
        ag = next(x for x in inv.agents if x.id == subj)
        allowed = set(c.purposes.get(ag.purpose, []))
        ag.tools = [t for t in ag.tools if set(t.capabilities) <= allowed]
        return True
    if a == "switch-connection-auth":
        for conn in inv.connections:
            if conn.key == subj:
                conn.auth_type, conn.secret_ref = "AAD", None
        return True
    if a == "split-identity":
        agents = sorted(inv.agents_using(subj), key=lambda x: x.name)
        base = inv.principals[subj]
        for i, ag in enumerate(agents[1:], 2):
            new_id = f"{subj}-split{i}"
            inv.principals[new_id] = Principal(**{**base.__dict__, "id": new_id, "name": f"{base.name}-{ag.name}"})
            for r in [r for r in inv.azure_roles if r.principal_id == subj]:
                inv.azure_roles.append(AzureRoleAssignment(f"{r.id}-split{i}", new_id, r.role, r.scope, r.state))
            ag.identity_id = new_id
        return True
    if a == "restrict-federated-subject":
        hint = h["federated_subject"].get(it.label, {})
        if "remove" in hint:
            inv.federated = [f for f in inv.federated if not (f.principal_id == subj and f.name == hint["remove"])]
        else:
            for f in inv.federated:
                if f.principal_id == subj and detections.federated_breadth(f):
                    f.subject, f.expression = hint.get("subject", "repo:<org>/<repo>:environment:prod"), None
        return True
    raise ValueError(f"unknown action {a}")


@dataclass
class Simulation:
    before: dict[str, scoring.AreaScore]
    after: dict[str, scoring.AreaScore]
    applied: list[str]
    skipped: list[tuple[str, str]]  # (item id, mode)
    remaining: list[Finding]
    paths_before: int
    paths_after: int
    inventory: Inventory | None = None  # the changed copy; the input inventory is never modified


def simulate(inv: Inventory, results: list[RuleResult] | None = None) -> Simulation:
    from idsec import paths as pmod

    g0 = gmod.build(inv)
    results = results or detections.run(inv, g0)
    p = plan(results, inv)
    sim = copy.deepcopy(inv)
    c = detections.Ctx(sim)
    applied, skipped = [], []
    for it in sorted(p.items, key=lambda i: (ORDER.index(i.action), i.id)):
        if _apply(sim, it, c):
            applied.append(it.id)
        else:
            skipped.append((it.id, it.mode))
    sim.__dict__.pop("by_app_id", None)
    g1 = gmod.build(sim)
    after = detections.run(sim, g1)
    human_paths = lambda i, g: sum(  # noqa: E731
        1 for x in pmod.analyse(i, g) if g.nodes[x.source]["kind"] in ("user", "guest", "source")
    )
    return Simulation(
        scoring.score(results),
        scoring.score(after),
        applied,
        skipped,
        detections.all_findings(after),
        human_paths(inv, g0),
        human_paths(sim, g1),
        sim,
    )
