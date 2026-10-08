"""The identity graph: who can become, control or read what.

Nodes are identities (users, groups, service principals, managed identities, agent identities),
directory roles, Azure scopes and resources, Key Vault secret stores and secrets, agents, their tools
and connections, and two kinds of outside source: untrusted content that agents read, and GitHub
workflows that hold a federated credential. An edge A -> B means "whoever controls A can act as, or
gain control of, B", with a `kind`, a plain-language `why` and an `ease` between 0 and 1 (how little
it takes to use that step; see config/roles.yaml). Eligible (PIM) assignments are kept as their own
edge kind with low ease, so analyses can include or exclude them."""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from idsec.inventory import Inventory, load_yaml, scope_kind

UNTRUSTED = "src:untrusted-content"


@dataclass(frozen=True)
class Caps:
    azure: dict
    directory: dict
    graph_perms: dict
    ease: dict
    admin_roles: list


def caps() -> Caps:
    r = load_yaml("roles.yaml")
    return Caps(r["azure_roles"], r["directory_roles"], r["graph_app_permissions"], r["edge_ease"], r["azure_admin_roles"])


def pnode(pid: str) -> str:
    return f"principal:{pid}"


def build(inv: Inventory) -> nx.DiGraph:
    c = caps()
    g = nx.DiGraph()

    def node(n: str, kind: str, label: str, **attrs) -> None:
        if n not in g:
            g.add_node(n, kind=kind, label=label, **attrs)

    def edge(a: str, b: str, kind: str, why: str, ease_key: str | None = None) -> None:
        ease = c.ease[ease_key or kind]
        if g.has_edge(a, b) and g[a][b]["ease"] >= ease:
            return
        g.add_edge(a, b, kind=kind, why=why, ease=ease)

    for p in inv.principals.values():
        label = f"{inv.name(p.id)} (managed identity)" if p.kind == "managed_identity" else inv.name(p.id)
        node(pnode(p.id), p.kind, label, enabled=p.enabled)
    for p in inv.principals.values():
        if p.kind == "group":
            for m in p.members:
                if m in inv.principals:
                    edge(pnode(m), pnode(p.id), "member_of", f"member of group {p.name}")

    # -- directory roles
    for role, spec in c.directory.items():
        node(f"dirrole:{role}", "directory_role", role, tier=spec["tier"])
    node("ctl:app-credentials", "capability", "add credentials to any application")
    for a in inv.dir_roles:
        target = f"dirrole:{a.role}"
        node(target, "directory_role", a.role, tier=9)
        if a.state == "eligible":
            edge(pnode(a.principal_id), target, "eligible_role", f"eligible (PIM) for {a.role}")
        else:
            edge(pnode(a.principal_id), target, "holds_role", f"{a.state} {a.role}")
    for role, spec in c.directory.items():
        for e in spec["edges"]:
            _capability_edge(g, edge, inv, f"dirrole:{role}", e, role)
    for sub in inv.subscriptions:
        node(f"scope:/subscriptions/{sub}", "subscription", f"subscription {sub[-4:]} ({inv.subscriptions[sub]})", env=inv.subscriptions[sub])
        edge("dirrole:Global Administrator", f"scope:/subscriptions/{sub}", "elevate-access", "Global Administrator can elevate to User Access Administrator at root")
    edge("dirrole:Global Administrator", "ctl:app-credentials", "add-app-credentials", "Global Administrator manages every application")
    for p in inv.principals.values():
        if p.kind == "app" or p.is_blueprint:
            edge("ctl:app-credentials", pnode(p.id), "add-app-credentials", f"add a client secret to {p.name} and sign in as it")

    # -- application ownership and Graph application permissions
    for p in inv.principals.values():
        if p.kind in ("app", "agent_identity") or p.is_blueprint:
            for o in p.owners:
                if o in inv.principals:
                    edge(pnode(o), pnode(p.id), "owns_app", f"owner of {p.name} can add a credential and sign in as it")
        if p.is_blueprint:
            for a in inv.principals.values():
                if a.kind == "agent_identity":
                    edge(pnode(p.id), pnode(a.id), "agent_identity", f"blueprint credential can act as agent identity {a.name}")
    for perm in inv.app_permissions:
        spec = c.graph_perms.get(perm.permission)
        if not spec:
            continue
        for e in spec["edges"]:
            _capability_edge(g, edge, inv, pnode(perm.sp_id), e, f"application permission {perm.permission}")

    # -- Azure scopes and resources
    for s in inv.scopes:
        if scope_kind(s) == "resource_group":
            node(f"scope:{s}", "resource_group", s.rsplit("/", 1)[-1])
            edge(f"scope:/subscriptions/{s.split('/')[2]}", f"scope:{s}", "contains", "subscription contains the resource group")
    for r in inv.resources.values():
        node(f"res:{r.id}", r.type, r.name, env=r.env)
        parent = f"res:{r.parent}" if r.parent and r.parent in inv.resources else f"scope:/subscriptions/{r.subscription}/resourceGroups/{r.resource_group}"
        node(parent, "resource_group", parent.rsplit("/", 1)[-1])
        edge(parent, f"res:{r.id}", "contains", f"contains {r.name}")
        for pid in r.identities:
            if pid in inv.principals:
                verb = "create a federated credential on" if r.type.endswith("userassignedidentities") else "run code on"
                edge(f"res:{r.id}", pnode(pid), "runs_as", f"{verb} {r.name} and act as its managed identity")
        if r.type == "microsoft.keyvault/vaults":
            node(f"kvsecrets:{r.name}", "secret_store", f"all secrets in {r.name}", env=r.env)
            edge(f"res:{r.id}", f"kvsecrets:{r.name}", "contains", "vault control includes granting yourself secret access")
            for ap in r.props.get("accessPolicies") or []:
                if {"get", "list", "all"} & {x.lower() for x in ap["permissions"].get("secrets", [])}:
                    edge(pnode(ap["objectId"]), f"kvsecrets:{r.name}", "secrets_read", f"access policy on {r.name} allows secret get")
    for s in inv.secrets:
        node(s.key, "secret", f"{s.vault}/{s.name}")
        edge(f"kvsecrets:{s.vault}", s.key, "contains", f"secret {s.name}")
        if s.credential_for and s.credential_for in inv.by_app_id:
            sp = inv.by_app_id[s.credential_for]
            edge(s.key, pnode(sp.id), "stored_credential", f"secret is the client credential of {sp.name}")

    for a in inv.azure_roles:
        spec = c.azure.get(a.role, {"caps": []})
        src = pnode(a.principal_id)
        state = "eligible_role" if a.state == "eligible" else None
        label = f"{'eligible ' if a.state == 'eligible' else ''}{a.role} on {a.scope.rsplit('/', 1)[-1]}"
        if "control" in spec["caps"]:
            target = f"scope:{a.scope}" if scope_kind(a.scope) in ("subscription", "resource_group", "management_group") else f"res:{a.scope}"
            node(target, scope_kind(a.scope), a.scope.rsplit("/", 1)[-1])
            edge(src, target, state or "holds_role", label)
        types = spec.get("types")
        for r in inv.under(a.scope):
            if types and r.type not in types:
                continue
            if "write" in spec["caps"]:
                if r.type == "microsoft.keyvault/vaults":
                    if not r.props.get("enableRbacAuthorization", True):
                        edge(src, f"kvsecrets:{r.name}", state or "vault_policy_write", f"{label}: can add itself to the vault access policy")
                elif r.identities or r.type == "microsoft.cognitiveservices/accounts/projects":
                    edge(src, f"res:{r.id}", state or "write_resource", f"{label}: write access to {r.name}")
            if "secrets_read" in spec["caps"] and r.type == "microsoft.keyvault/vaults":
                edge(src, f"kvsecrets:{r.name}", state or "secrets_read", f"{label}: read every secret")
            if "agent_edit" in spec["caps"] and r.type == "microsoft.cognitiveservices/accounts/projects":
                edge(src, f"res:{r.id}", state or "agent_edit", f"{label}: create and edit agents, tools and connections")

    # -- agents, tools, connections
    node(UNTRUSTED, "source", "untrusted content read by agents (documents, email, chat, web)")
    for conn in inv.connections:
        node(conn.key, "connection", conn.name)
        if conn.project_id in inv.resources:
            edge(f"res:{conn.project_id}", conn.key, "contains", f"project holds connection {conn.name}")
        if conn.secret_ref:
            key = f"secret:{conn.secret_ref}"
            node(key, "secret", conn.secret_ref)
            edge(conn.key, key, "connection_secret", f"connection authenticates with {conn.secret_ref}")
    for ag in inv.agents:
        an = f"agent:{ag.id}"
        node(an, "agent", ag.name)
        if ag.project_id in inv.resources:
            edge(f"res:{ag.project_id}", an, "agent_edit", f"project control lets you change {ag.name}'s instructions and tools")
        if ag.identity_id:
            edge(an, pnode(ag.identity_id), "agent_identity", f"{ag.name} runs as {inv.name(ag.identity_id)}")
        for t in ag.tools:
            tn = f"tool:{ag.id}/{t.name}"
            node(tn, "tool", f"{ag.name}.{t.name}", caps=",".join(t.capabilities))
            edge(an, tn, "uses_tool", f"{ag.name} can call {t.name} ({', '.join(t.capabilities) or 'no declared capability'})")
            if t.connection:
                edge(tn, f"conn:{t.connection}", "tool_connection", f"{t.name} uses connection {t.connection}")
        if ag.ingests == "untrusted":
            edge(UNTRUSTED, an, "prompt_injection", f"{ag.name} reads untrusted content that can carry instructions")

    # -- federated credentials: an outside workflow that matches the subject can sign in
    for f in inv.federated:
        src = f"src:federated:{f.expression or f.subject}"
        node(src, "source", f"workflows matching {f.expression or f.subject}")
        edge(src, pnode(f.principal_id), "federated_trust", f"federated credential {f.name} trusts {f.expression or f.subject}")
    return g


def _capability_edge(g, edge, inv: Inventory, src: str, cap: str, via: str) -> None:
    if cap == "grant-global-admin":
        edge(src, "dirrole:Global Administrator", "grant-global-admin", f"{via} can assign Global Administrator")
    elif cap == "reset-admin-credentials":
        edge(src, "dirrole:Global Administrator", "reset-admin-credentials", f"{via} can reset an administrator's credentials")
    elif cap == "add-app-credentials":
        edge(src, "ctl:app-credentials", "add-app-credentials", f"{via} can add credentials to any application")
    elif cap == "edit-groups":
        for p in inv.principals.values():
            if p.kind == "group" and not p.role_assignable:
                edge(src, pnode(p.id), "edit-groups", f"{via} can add members to {p.name}")


def standing_view(g: nx.DiGraph) -> nx.DiGraph:
    """The graph without PIM-eligible edges: what can be done right now without an activation."""
    return nx.subgraph_view(g, filter_edge=lambda a, b: g[a][b]["kind"] != "eligible_role")


def stats(g: nx.DiGraph) -> dict[str, int]:
    kinds: dict[str, int] = {}
    for _, d in g.nodes(data=True):
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    ek: dict[str, int] = {}
    for _, _, d in g.edges(data=True):
        ek[d["kind"]] = ek.get(d["kind"], 0) + 1
    return {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(), **{f"node:{k}": v for k, v in sorted(kinds.items())},
            **{f"edge:{k}": v for k, v in sorted(ek.items())}}  # fmt: skip
