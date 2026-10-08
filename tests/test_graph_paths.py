"""Identity graph edges and privilege-path analysis."""

from conftest import pid

from idsec import graph as gmod
from idsec import paths


def edge(g, a, b):
    return g[a][b] if g.has_edge(a, b) else None


def test_owner_can_become_the_app(base_inv, g):
    e = edge(g, gmod.pnode(pid(base_inv, "devon.lee")), gmod.pnode(pid(base_inv, "ops-automation")))
    assert e["kind"] == "owns_app"


def test_tier0_permission_points_at_global_admin(base_inv, g):
    e = edge(g, gmod.pnode(pid(base_inv, "ops-automation")), "dirrole:Global Administrator")
    assert e["kind"] == "grant-global-admin"


def test_directory_write_can_edit_groups(base_inv, g):
    etl = gmod.pnode(pid(base_inv, "legacy-batch-etl"))
    targets = {g.nodes[b]["label"] for b in g.successors(etl)}
    assert "Helpdesk-L2" in targets and "Platform-Owners" not in targets  # role-assignable groups are protected


def test_vm_contributor_reaches_the_vm_identity(base_inv, g):
    vm = base_inv.resource_by_name("vm-kr-batch01")
    helpdesk = next(p.id for p in base_inv.principals.values() if p.name == "Helpdesk-L2")
    assert edge(g, gmod.pnode(helpdesk), f"res:{vm.id}")["kind"] == "write_resource"
    assert edge(g, f"res:{vm.id}", gmod.pnode(vm.identities[0]))["kind"] == "runs_as"


def test_contributor_on_rbac_vault_gives_no_secrets(base_inv, g):
    docs = gmod.pnode(pid(base_inv, "loan-docs-sync"))
    assert not g.has_edge(docs, "kvsecrets:kv-kr-prod-secrets")


def test_access_policy_vault_gives_secrets(base_inv, g):
    devs = next(p.id for p in base_inv.principals.values() if p.name == "All-Developers")
    assert edge(g, gmod.pnode(devs), "kvsecrets:kv-kr-nonprod")["kind"] in ("secrets_read", "vault_policy_write")


def test_untrusted_content_reaches_only_untrusted_agents(base_inv, g):
    targets = {g.nodes[b]["label"] for b in g.successors(gmod.UNTRUSTED)}
    assert "collections-reminder" not in targets and "underwriting-assistant" in targets
    assert len(targets) == sum(a.ingests == "untrusted" for a in base_inv.agents)


def test_eligible_edges_have_low_ease_and_are_excluded_from_standing(base_inv, g):
    ava = gmod.pnode(pid(base_inv, "ava.chen"))
    assert edge(g, ava, "dirrole:Global Administrator")["kind"] == "eligible_role"
    assert not gmod.standing_view(g).has_edge(ava, "dirrole:Global Administrator")


def test_stored_credential_edge(base_inv, g):
    e = edge(g, "secret:kv-kr-prod-secrets/loan-docs-sync-client-secret", gmod.pnode(pid(base_inv, "loan-docs-sync")))
    assert e["kind"] == "stored_credential"


def test_agent_chain_tool_connection_secret(g):
    assert edge(g, "agent:asst_loan_intake", "tool:asst_loan_intake/crm_lookup")["kind"] == "uses_tool"
    assert edge(g, "tool:asst_loan_intake/crm_lookup", "conn:conn-ledgerline-crm")["kind"] == "tool_connection"
    assert edge(g, "conn:conn-ledgerline-crm", "secret:kv-kr-prod-secrets/crm-api-key")["kind"] == "connection_secret"


def test_federated_sources(base_inv, g):
    src = [n for n, d in g.nodes(data=True) if d["kind"] == "source" and n.startswith("src:federated:")]
    assert len(src) == 5


def test_managed_identity_label(base_inv, g):
    vm = base_inv.resource_by_name("vm-kr-batch01")
    assert g.nodes[gmod.pnode(vm.identities[0])]["label"] == "vm-kr-batch01 (managed identity)"


def test_crown_jewels_resolve(base_inv, g):
    assert {j.id for j in paths.crown_jewels(base_inv, g)} == {
        "entra-global-admin",
        "prod-subscription-control",
        "prod-secrets",
        "foundry-prod-project",
    }


def test_devon_reaches_global_admin_in_two_steps(base_inv, g):
    cj = next(j for j in paths.crown_jewels(base_inv, g) if j.id == "entra-global-admin")
    short, risky = paths.best_paths(g, gmod.pnode(pid(base_inv, "devon.lee")), cj)
    assert short.hops == 2 and risky.risk == 0.72


def test_helpdesk_path_runs_through_the_vm(base_inv, g):
    cj = next(j for j in paths.crown_jewels(base_inv, g) if j.id == "prod-subscription-control")
    _, risky = paths.best_paths(g, gmod.pnode(pid(base_inv, "mia.santos")), cj)
    kinds = [s["kind"] for s in risky.steps]
    assert kinds == ["member_of", "write_resource", "runs_as", "holds_role"]


def test_riskiest_is_never_less_likely_than_shortest(base_inv, g):
    for cj in paths.crown_jewels(base_inv, g):
        for s in paths.sources(base_inv, g):
            r = paths.best_paths(g, s, cj)
            if r:
                assert r[1].risk >= r[0].risk and r[0].hops <= r[1].hops


def test_ordinary_staff_have_no_path(base_inv, g):
    cj = paths.crown_jewels(base_inv, g)
    ordinary = [p for p in base_inv.principals.values() if p.kind == "user" and p.name in ("Leo Martins", "Omar Reyes")]
    for p in ordinary:
        assert all(paths.best_paths(g, gmod.pnode(p.id), j) is None for j in cj)


def test_eligible_paths_add_routes(base_inv, g):
    assert len(paths.analyse(base_inv, g, include_eligible=True)) > len(paths.analyse(base_inv, g))


def test_untrusted_paths_reach_secrets_and_global_admin(base_inv, g):
    jewels = {p.jewel for p in paths.untrusted_paths(base_inv, g)}
    assert {"prod-secrets", "entra-global-admin"} <= jewels


def test_blast_radius(base_inv, g):
    b = paths.blast_radius(base_inv, g, gmod.pnode(pid(base_inv, "leo.martins")))
    assert b.total == 0 and b.jewels == []
    top = paths.top_blast(base_inv, g, 3)
    assert len(top) == 3 and all(len(t.jewels) == 4 for t in top)


def test_render_path(base_inv, g):
    p = paths.analyse(base_inv, g)[0]
    assert " -> " in p.render(g)


def test_stats(g):
    s = gmod.stats(g)
    assert s["nodes"] == g.number_of_nodes() and s["edge:prompt_injection"] == 6
