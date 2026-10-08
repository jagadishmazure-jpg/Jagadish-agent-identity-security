"""Detections: one function per rule in detections/rules.yaml.

Each function receives a `Ctx` (inventory, identity graph, configuration) and returns
`(findings, evaluated)`: the findings, and how many subjects it checked (the denominator the posture
score uses). Findings carry evidence lines computed from the data, never from free text in the
data, so an attacker-controlled display name can appear in evidence only as a quoted label."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache, cached_property

import networkx as nx
import yaml

from idsec import DETECTIONS
from idsec import graph as gmod
from idsec import paths as pmod
from idsec.inventory import Inventory, Principal, load_yaml, scope_kind

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@cache
def catalogue() -> list[dict]:
    return yaml.safe_load((DETECTIONS / "rules.yaml").read_text())["rules"]


def rule_meta(rule_id: str) -> dict:
    for r in catalogue():
        if r["id"] == rule_id:
            return r
    raise KeyError(rule_id)


@dataclass
class Finding:
    rule: str
    subject: str
    label: str
    evidence: list[str]
    id: str = ""
    path: list[str] = field(default_factory=list)  # graph nodes, for path findings

    @property
    def meta(self) -> dict:
        return rule_meta(self.rule)

    @property
    def severity(self) -> str:
        return self.meta["severity"]

    @property
    def area(self) -> str:
        return self.meta["area"]

    @property
    def title(self) -> str:
        return self.meta["title"]


class Ctx:
    def __init__(self, inv: Inventory, g: nx.DiGraph | None = None) -> None:
        self.inv = inv
        self.g = g if g is not None else gmod.build(inv)
        self.scan = load_yaml("scan.yaml")
        self.th = self.scan["thresholds"]
        self.roles = load_yaml("roles.yaml")
        self.purposes = load_yaml("agent-purposes.yaml")["purposes"]
        self.emergency = {u.lower() for u in self.scan["emergency_accounts"]}

    @cached_property
    def jewels(self) -> list[pmod.CrownJewel]:
        return pmod.crown_jewels(self.inv, self.g)

    def is_emergency(self, p: Principal) -> bool:
        return p.upn.lower() in self.emergency

    def dir_tier(self, role: str) -> int:
        return self.roles["directory_roles"].get(role, {"tier": 9})["tier"]

    def az_caps(self, role: str) -> set[str]:
        return set(self.roles["azure_roles"].get(role, {"caps": []})["caps"])

    def is_admin(self, p: Principal) -> bool:
        """Holds (or is eligible for) a tier 0/1 directory role or an Azure admin role."""
        if any(self.dir_tier(a.role) <= 1 for a in self.inv.dir_roles_of(p.id)):
            return True
        return any(a.role in self.roles["azure_admin_roles"] for a in self.inv.azure_roles_of(p.id))

    def path_to_jewel(self, src: str) -> pmod.Path | None:
        best = None
        for cj in self.jewels:
            r = pmod.best_paths(self.g, src, cj)
            if r and (best is None or r[1].risk > best.risk):
                best = r[1]
        return best

    def mfa_enforced_for(self, p: Principal) -> bool:
        groups = self.inv.groups_of(p.id)
        active_roles = {a.role for a in self.inv.dir_roles_of(p.id, states=("standing", "activated"))}
        for pol in self.inv.ca_policies:
            if pol.state != "enabled" or not ("mfa" in pol.grant or pol.auth_strength):
                continue
            if p.id in pol.exclude_users or groups & set(pol.exclude_groups):
                continue
            inc = pol.include_users
            if "All" in inc or p.id in inc or groups & set(pol.include_groups) or active_roles & set(pol.include_roles):
                return True
            if p.kind == "guest" and "GuestsOrExternalUsers" in inc:
                return True
        return False


RULES: dict[str, Callable[[Ctx], tuple[list[Finding], int]]] = {}


def rule(fn):
    RULES[fn.__name__.replace("_", "-")] = fn
    return fn


def _people(c: Ctx, guests: bool = True) -> list[Principal]:
    kinds = ("user", "guest") if guests else ("user",)
    return [p for p in c.inv.principals.values() if p.kind in kinds and p.enabled]


def _scope_label(scope: str) -> str:
    return f"{scope_kind(scope).replace('_', ' ')} {scope.rsplit('/', 1)[-1]}"


# ------------------------------------------------------------------------------------- privilege
@rule
def standing_privileged_role(c: Ctx):
    out, people = [], [p for p in _people(c) if not c.is_emergency(p)]
    for p in people:
        roles = [a.role for a in c.inv.dir_roles_of(p.id, states=("standing",)) if c.dir_tier(a.role) <= 1]
        if roles:
            out.append(
                Finding(
                    "standing-privileged-role", p.id, c.inv.name(p.id), [f"permanent assignment: {r} (tier {c.dir_tier(r)})" for r in sorted(roles)]
                )
            )
    return out, len(people)


@rule
def standing_azure_admin(c: Ctx):
    out, people = [], _people(c)
    for p in people:
        ev = [
            f"permanent {a.role} on {_scope_label(a.scope)}" + ("" if a.principal_id == p.id else f" via group {c.inv.name(a.principal_id)}")
            for a in c.inv.azure_roles_of(p.id, states=("standing",))
            if a.role in c.roles["azure_admin_roles"] and scope_kind(a.scope) in ("subscription", "management_group")
        ]
        if ev:
            out.append(Finding("standing-azure-admin", p.id, c.inv.name(p.id), sorted(ev)))
    return out, len(people)


def _workloads(c: Ctx, kinds=("app", "managed_identity")) -> list[Principal]:
    return [p for p in c.inv.principals.values() if p.kind in kinds and p.enabled]


@rule
def workload_subscription_privilege(c: Ctx):
    out, subjects = [], _workloads(c)
    for p in subjects:
        ev = [
            f"{a.role} on {_scope_label(a.scope)}"
            for a in c.inv.azure_roles_of(p.id, states=("standing",))
            if scope_kind(a.scope) in ("subscription", "management_group") and c.az_caps(a.role) & {"control", "write"}
        ]
        if ev:
            out.append(Finding("workload-subscription-privilege", p.id, c.inv.name(p.id), sorted(ev)))
    return out, len(subjects)


@rule
def high_risk_app_permission(c: Ctx):
    perms = c.roles["graph_app_permissions"]
    subjects = [p for p in c.inv.principals.values() if p.workload and p.enabled]
    out = []
    for p in subjects:
        bad = [x.permission for x in c.inv.permissions_of(p.id) if perms.get(x.permission, {"tier": 9})["tier"] <= 1]
        if bad:
            ev = [f"application permission {b} (tier {perms[b]['tier']}); safer: {perms[b].get('safer', 'remove')}" for b in sorted(bad)]
            out.append(Finding("high-risk-app-permission", p.id, c.inv.name(p.id), ev))
    return out, len(subjects)


@rule
def human_path_to_crown_jewel(c: Ctx):
    out, people = [], [p for p in _people(c) if not c.is_admin(p) and not c.is_emergency(p)]
    for p in people:
        path = c.path_to_jewel(gmod.pnode(p.id))
        if path:
            ev = [f"reaches {path.jewel} in {path.hops} step(s), path ease {path.risk}"] + [s["why"] for s in path.steps]
            out.append(Finding("human-path-to-crown-jewel", p.id, c.inv.name(p.id), ev, path=path.nodes))
    return out, len(people)


@rule
def guest_with_privilege(c: Ctx):
    out, guests = [], [p for p in _people(c) if p.kind == "guest"]
    for p in guests:
        ev = [f"{a.role} on {_scope_label(a.scope)}" for a in c.inv.azure_roles_of(p.id) if c.az_caps(a.role) & {"control", "write", "secrets_read"}]
        ev += [f"directory role {a.role}" for a in c.inv.dir_roles_of(p.id) if c.dir_tier(a.role) <= 1]
        if ev:
            out.append(Finding("guest-with-privilege", p.id, c.inv.name(p.id), sorted(ev)))
    return out, len(guests)


@rule
def external_app_with_privilege(c: Ctx):
    perms = c.roles["graph_app_permissions"]
    apps = [p for p in c.inv.principals.values() if p.kind == "external_app" and p.enabled]
    out = []
    for p in apps:
        ev = [f"{a.role} on {_scope_label(a.scope)}" for a in c.inv.azure_roles_of(p.id) if c.az_caps(a.role) & {"control", "write", "secrets_read"}]
        ev += [f"application permission {x.permission}" for x in c.inv.permissions_of(p.id) if perms.get(x.permission, {"tier": 9})["tier"] <= 1]
        if ev:
            ev.append(f"publisher tenant {p.home_tenant[-4:]}, verified publisher: {p.verified_publisher or 'none'}")
            out.append(Finding("external-app-with-privilege", p.id, c.inv.name(p.id), ev))
    return out, len(apps)


@rule
def risky_consent_grant(c: Ctx):
    risky = set(c.roles["risky_delegated_scopes"])
    grants = [g for g in c.inv.consents if g.consent_type == "AllPrincipals"]
    hits: dict[str, list[str]] = {}
    for g in grants:
        app = c.inv.principals.get(g.client_id)
        bad = sorted(risky & set(g.scopes))
        if app and bad and app.kind != "first_party" and not app.verified_publisher:
            hits.setdefault(app.id, []).append(f"tenant-wide consent to {', '.join(bad)}; publisher not verified")
    out = [Finding("risky-consent-grant", k, c.inv.name(k), v) for k, v in hits.items()]
    return out, len(grants)


# ------------------------------------------------------------------------------------- foundational
@rule
def no_mfa_registered(c: Ctx):
    people = [p for p in _people(c, guests=False) if not c.is_emergency(p)]
    out = [
        Finding("no-mfa-registered", p.id, c.inv.name(p.id), [f"methods registered: {', '.join(p.methods) or 'none'}"])
        for p in people
        if p.mfa_registered is False
    ]
    return out, len(people)


@rule
def privileged_without_enforced_mfa(c: Ctx):
    people = [p for p in _people(c) if c.is_admin(p) and not c.is_emergency(p)]
    out = []
    for p in people:
        if not c.mfa_enforced_for(p):
            excl = [c.inv.name(g) for g in c.inv.groups_of(p.id) if any(g in pol.exclude_groups for pol in c.inv.ca_policies)]
            roles = sorted({f"{a.state} {a.role}" for a in c.inv.dir_roles_of(p.id) if c.dir_tier(a.role) <= 1})
            ev = [*roles, "no enabled Conditional Access policy requires MFA for this person"]
            if excl:
                ev.append(f"excluded through group {', '.join(sorted(excl))}")
            out.append(Finding("privileged-without-enforced-mfa", p.id, c.inv.name(p.id), ev))
    return out, len(people)


@rule
def dormant_account(c: Ctx):
    th = c.th
    people = [p for p in _people(c) if (p.created_days or 0) > th["new_account_grace_days"] and not c.is_emergency(p)]
    out = []
    for p in people:
        last = p.last_sign_in_days
        if last is None or last > th["stale_sign_in_days"]:
            ev = [f"last sign-in {'never' if last is None else f'{last:.0f} days ago'} (threshold {th['stale_sign_in_days']})"]
            roles = [a.role for a in c.inv.azure_roles_of(p.id)] + [a.role for a in c.inv.dir_roles_of(p.id)]
            if roles:
                ev.append(f"still holds: {', '.join(sorted(set(roles)))}")
            out.append(Finding("dormant-account", p.id, c.inv.name(p.id), ev))
    return out, len(people)


@rule
def emergency_account_weak_method(c: Ctx):
    strong = set(c.scan["phishing_resistant_methods"])
    accts = [p for p in c.inv.principals.values() if p.human and c.is_emergency(p)]
    out = [
        Finding(
            "emergency-account-weak-method",
            p.id,
            c.inv.name(p.id),
            [f"methods registered: {', '.join(p.methods) or 'none'}; none is phishing-resistant"],
        )
        for p in accts
        if not strong & set(p.methods)
    ]
    return out, len(accts)


@rule
def legacy_auth_not_blocked(c: Ctx):
    legacy = {"exchangeActiveSync", "other"}
    blocking = [p for p in c.inv.ca_policies if "block" in p.grant and legacy & set(p.client_app_types)]
    if any(p.state == "enabled" and "All" in p.include_users for p in blocking):
        return [], 1
    subject = blocking[0] if blocking else None
    ev = [
        f"policy '{subject.name}' is {subject.state}" if subject else "no policy targets legacy client app types",
        "legacy protocols can sign in with a password alone",
    ]
    return [Finding("legacy-auth-not-blocked", subject.id if subject else c.inv.tenant_id, subject.name if subject else "tenant", ev)], 1


@rule
def vault_legacy_access_policies(c: Ctx):
    vaults = c.inv.vaults()
    out = []
    for v in vaults:
        if not v.props.get("enableRbacAuthorization", True):
            ev = [
                f"{len(v.props.get('accessPolicies') or [])} access policies; public network access {v.props.get('publicNetworkAccess', 'unknown')}"
            ]
            for ap in v.props.get("accessPolicies") or []:
                ev.append(f"{c.inv.name(ap['objectId'])}: secrets {', '.join(ap['permissions'].get('secrets', []))}")
            out.append(Finding("vault-legacy-access-policies", f"vault:{v.name}", v.name, ev))
    return out, len(vaults)


@rule
def saas_admin_outside_sso(c: Ctx):
    admins = [a for a in c.inv.saas if a.admin and a.active]
    out = []
    for a in admins:
        ev = []
        if not a.sso:
            ev.append(f"{a.app} admin signs in with a local password (no SSO link)")
        elif a.entra_id:
            p = c.inv.principals.get(a.entra_id)
            if p is None or not p.enabled:
                ev.append(f"{a.app} admin linked to an Entra account that is {'missing' if p is None else 'disabled'}")
        if ev:
            out.append(Finding("saas-admin-outside-sso", a.key, f"{a.app}: {a.user_name}", [*ev, f"roles: {', '.join(a.roles)}"]))
    return out, len(admins)


# ------------------------------------------------------------------------------------- emerging
@rule
def long_lived_app_secret(c: Ctx):
    th = c.th
    by_sp: dict[str, list[str]] = {}
    for cr in c.inv.app_credentials:
        limit = th["max_password_lifetime_days"] if cr.kind == "password" else th["max_certificate_lifetime_days"]
        if cr.lifetime_days > limit and cr.expires_in_days > 0:
            by_sp.setdefault(cr.sp_id, []).append(
                f"{cr.kind} '{cr.name}' lifetime {cr.lifetime_days:.0f} days (limit {limit}), {cr.expires_in_days:.0f} days left"
            )
    out = [Finding("long-lived-app-secret", k, c.inv.name(k), v) for k, v in by_sp.items()]
    return out, len({cr.sp_id for cr in c.inv.app_credentials})


@rule
def unrotated_secret(c: Ctx):
    th = c.th["secret_rotation_days"]
    out = [
        Finding("unrotated-secret", s.key, f"{s.vault}/{s.name}", [f"last updated {s.updated_days:.0f} days ago (window {th})"])
        for s in c.inv.secrets
        if s.updated_days > th
    ]
    return out, len(c.inv.secrets)


@rule
def secret_without_expiry(c: Ctx):
    out = [
        Finding("secret-without-expiry", s.key, f"{s.vault}/{s.name}", ["no expiry attribute set"])
        for s in c.inv.secrets
        if s.expires_in_days is None
    ]
    return out, len(c.inv.secrets)


def consumers(inv: Inventory) -> dict[str, list[str]]:
    """secret key -> consumers (connections and resources that reference it)."""
    out: dict[str, list[str]] = {}
    for conn in inv.connections:
        if conn.secret_ref:
            out.setdefault(f"secret:{conn.secret_ref}", []).append(f"connection {conn.name}")
    for r in inv.resources.values():
        for ref in filter(None, (r.tags.get("kvSecretRefs") or "").split(",")):
            out.setdefault(f"secret:{ref.strip()}", []).append(f"resource {r.name}")
    return out


@rule
def shared_credential(c: Ctx):
    cons = consumers(c.inv)
    out = [
        Finding("shared-credential", k, k.removeprefix("secret:"), [f"used by {len(v)} consumers: {', '.join(sorted(v))}"])
        for k, v in sorted(cons.items())
        if len(v) > 1
    ]
    return out, len(cons)


@rule
def unowned_workload_identity(c: Ctx):
    apps = [p for p in c.inv.principals.values() if p.kind == "app" and p.enabled]
    out = []
    for p in apps:
        active = [o for o in p.owners if (c.inv.principals.get(o) and c.inv.principals[o].enabled)]
        if not active:
            ev = ["no owners" if not p.owners else f"all {len(p.owners)} owner(s) disabled or deleted"]
            out.append(Finding("unowned-workload-identity", p.id, c.inv.name(p.id), ev))
    return out, len(apps)


@rule
def unsponsored_agent(c: Ctx):
    out = []
    for a in c.inv.agents:
        ident = c.inv.principals.get(a.identity_id)
        sponsors = [s for s in (ident.sponsors if ident else []) if c.inv.principals.get(s) and c.inv.principals[s].enabled]
        if not sponsors:
            why = "agent has no Entra identity" if not ident else ("identity has no sponsor" if not ident.sponsors else "every sponsor is disabled")
            out.append(Finding("unsponsored-agent", a.id, a.name, [why, f"identity {c.inv.name(a.identity_id)}"]))
    return out, len(c.inv.agents)


def _agent_privilege(c: Ctx, ident: str) -> list[str]:
    perms = c.roles["graph_app_permissions"]
    ev = [f"{a.role} on {_scope_label(a.scope)}" for a in c.inv.azure_roles_of(ident) if c.az_caps(a.role) & {"control", "write"}]
    ev += [f"directory role {a.role}" for a in c.inv.dir_roles_of(ident) if c.dir_tier(a.role) <= 1]
    ev += [f"application permission {x.permission}" for x in c.inv.permissions_of(ident) if perms.get(x.permission, {"tier": 9})["tier"] <= 1]
    return sorted(ev)


@rule
def overprivileged_agent(c: Ctx):
    out = []
    for a in c.inv.agents:
        ev = _agent_privilege(c, a.identity_id)
        if ev:
            out.append(Finding("overprivileged-agent", a.id, a.name, [f"runs as {c.inv.name(a.identity_id)}", *ev]))
    return out, len(c.inv.agents)


@rule
def agent_reads_secrets(c: Ctx):
    out = []
    for a in c.inv.agents:
        node = gmod.pnode(a.identity_id)
        stores = sorted(c.g.nodes[b]["label"] for b in (c.g.successors(node) if node in c.g else []) if c.g.nodes[b]["kind"] == "secret_store")
        if stores:
            out.append(Finding("agent-reads-secrets", a.id, a.name, [f"runs as {c.inv.name(a.identity_id)}", *[f"can read {s}" for s in stores]]))
    return out, len(c.inv.agents)


@rule
def agent_tool_beyond_purpose(c: Ctx):
    out = []
    for a in c.inv.agents:
        allowed = set(c.purposes.get(a.purpose, []))
        extra = [f"tool {t.name} needs {cap}, outside purpose '{a.purpose}'" for t in a.tools for cap in t.capabilities if cap not in allowed]
        if extra:
            out.append(Finding("agent-tool-beyond-purpose", a.id, a.name, extra))
    return out, len(c.inv.agents)


@rule
def agent_key_connection(c: Ctx):
    out = []
    for conn in c.inv.connections:
        if conn.auth_type in ("ApiKey", "CustomKeys", "AccountKey"):
            users = sorted(a.name for a in c.inv.agents for t in a.tools if t.connection == conn.name)
            ev = [f"auth type {conn.auth_type} to {conn.target}", f"used by agents: {', '.join(sorted(set(users))) or 'none'}"]
            if conn.secret_ref:
                ev.append(f"key source {conn.secret_ref}")
            out.append(Finding("agent-key-connection", conn.key, conn.name, ev))
    return out, len(c.inv.connections)


@rule
def shared_agent_identity(c: Ctx):
    idents: dict[str, list[str]] = {}
    for a in c.inv.agents:
        idents.setdefault(a.identity_id, []).append(a.name)
    out = [
        Finding("shared-agent-identity", k, c.inv.name(k), [f"used by {len(v)} agents: {', '.join(sorted(v))}"])
        for k, v in idents.items()
        if len(v) > 1
    ]
    return out, len(idents)


def federated_breadth(f) -> str | None:
    """Why a GitHub federated credential is too broad, or None."""
    if f.expression:
        if "*" in f.expression or "matches" in f.expression:
            return f"flexible expression {f.expression!r} matches many subjects"
        return None
    s = f.subject or ""
    if ":pull_request" in s:
        return f"subject {s!r} accepts any pull request"
    if s.endswith(":*") or "*" in s:
        return f"subject {s!r} contains a wildcard"
    if s.startswith("repo:") and not any(k in s for k in (":environment:", ":ref:refs/heads/", ":ref:refs/tags/")):
        return f"subject {s!r} is not pinned to an environment, branch or tag"
    return None


@rule
def broad_federated_subject(c: Ctx):
    github = [f for f in c.inv.federated if "token.actions.githubusercontent.com" in f.issuer]
    hits: dict[str, list[str]] = {}
    for f in github:
        why = federated_breadth(f)
        if why:
            roles = [f"{a.role} on {_scope_label(a.scope)}" for a in c.inv.azure_roles_of(f.principal_id)]
            hits.setdefault(f.principal_id, []).extend([f"credential {f.name}: {why}", *(f"identity holds {r}" for r in roles)])
    out = [Finding("broad-federated-subject", k, c.inv.name(k), v) for k, v in hits.items()]
    return out, len(github)


@rule
def agent_untrusted_input_path(c: Ctx):
    out = []
    risky = [a for a in c.inv.agents if a.ingests == "untrusted"]
    for a in risky:
        path = c.path_to_jewel(f"agent:{a.id}")
        if path:
            ev = [f"reads untrusted content; reaches {path.jewel} in {path.hops} step(s), path ease {path.risk}"] + [s["why"] for s in path.steps]
            out.append(Finding("agent-untrusted-input-path", a.id, a.name, ev, path=path.nodes))
    return out, len(risky)


# ------------------------------------------------------------------------------------- running
@dataclass
class RuleResult:
    rule: str
    evaluated: int
    findings: list[Finding]


def run(inv: Inventory, g: nx.DiGraph | None = None) -> list[RuleResult]:
    c = Ctx(inv, g)
    results = []
    for meta in catalogue():
        findings, n = RULES[meta["id"]](c)
        findings.sort(key=lambda f: (f.label.lower(), f.subject))
        for i, f in enumerate(findings, 1):
            f.id = f"{meta['code']}-{i:02d}"
        results.append(RuleResult(meta["id"], n, findings))
    return results


def all_findings(results: list[RuleResult]) -> list[Finding]:
    out = [f for r in results for f in r.findings]
    return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))
