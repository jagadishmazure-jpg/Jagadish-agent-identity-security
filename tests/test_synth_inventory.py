"""Synthetic tenant generation and the Graph / ARM normaliser."""

import json
import re

from conftest import pid

from idsec import DATA, TENANT_DATA, inventory, synth
from idsec.inventory import scope_kind

MOCK_GUID = re.compile(r"^00000000-0000-0000-[0-9a-f]{4}-[0-9a-f]{12}$")


def test_generator_is_deterministic():
    a = synth.files(synth.build())
    b = synth.files(synth.build())
    assert synth.dumps(a) == synth.dumps(b)


def test_committed_data_matches_generator():
    assert synth.write(check=True) == []


def test_every_object_id_is_a_mock_guid():
    for p in TENANT_DATA.rglob("*.json"):
        for guid in re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", p.read_text()):
            assert MOCK_GUID.match(guid), f"{guid} in {p.name}"


def test_domains_are_example_only():
    text = "".join(p.read_text() for p in TENANT_DATA.rglob("*.json"))
    for domain in set(re.findall(r"\w@([a-z0-9.-]+\.[a-z]+)", text)):
        assert domain.endswith(".example"), domain


def test_ground_truth_subjects_exist(base_inv):
    keys = set(base_inv.principals) | {a.id for a in base_inv.agents} | {s.key for s in base_inv.secrets} | {c.key for c in base_inv.connections}
    keys |= {f"vault:{v.name}" for v in base_inv.vaults()} | {s.key for s in base_inv.saas} | {p.id for p in base_inv.ca_policies}
    for x in json.loads((DATA / "ground-truth.json").read_text())["planted"]:
        assert x["subject"] in keys, x


def test_ground_truth_covers_every_rule():
    from idsec import detections

    planted = {x["rule"] for x in json.loads((DATA / "ground-truth.json").read_text())["planted"]}
    assert planted == {r["id"] for r in detections.catalogue()}


def test_summary_counts(base_inv):
    s = inventory.summary(base_inv)
    assert s["AI agents"] == 7 and s["agent identities"] == 6 and s["managed identities"] == 3
    assert s["guest users"] == 2 and s["Conditional Access policies"] == 4
    assert s["Microsoft first-party service principals"] == 1


def test_users_parse_sign_in_and_mfa(base_inv):
    leo = base_inv.principals[pid(base_inv, "leo.martins")]
    assert leo.mfa_registered is False and leo.methods == ["password"]
    gary = base_inv.principals[pid(base_inv, "gary.holt")]
    assert round(gary.last_sign_in_days) == 210
    new = base_inv.principals[pid(base_inv, "omar.reyes")]
    assert new.last_sign_in_days is None and new.created_days < 30


def test_guest_kind(base_inv):
    guests = [p for p in base_inv.principals.values() if p.kind == "guest"]
    assert len(guests) == 2 and all("#EXT#" in p.upn for p in guests)


def test_service_principal_kinds(base_inv):
    kinds = {p.name: p.kind for p in base_inv.principals.values() if p.app_id or p.kind == "managed_identity"}
    assert kinds["agent-underwriting"] == "agent_identity"
    assert kinds["Harbor Backup Service"] == "external_app"
    assert kinds["Microsoft Graph"] == "first_party"
    assert kinds["vm-kr-batch01"] == "managed_identity"
    assert kinds["loan-docs-sync"] == "app"


def test_blueprint_is_recognised(base_inv):
    bp = [p for p in base_inv.principals.values() if p.is_blueprint]
    assert [p.name for p in bp] == ["kr-lending-agents-blueprint"]


def test_app_owners_merge_app_and_sp(base_inv):
    sp = base_inv.principals[pid(base_inv, "ops-automation")]
    assert base_inv.name(sp.owners[0]).startswith("devon.lee")


def test_app_credential_lifetimes(base_inv):
    docs = pid(base_inv, "loan-docs-sync")
    cred = next(c for c in base_inv.app_credentials if c.sp_id == docs)
    assert cred.kind == "password" and cred.lifetime_days == 730 and round(cred.expires_in_days) == 430


def test_federated_credentials_from_apps_and_managed_identities(base_inv):
    names = {f.name for f in base_inv.federated}
    assert {"platform-prod", "platform-pr", "web-any-repo", "docs-main", "data-pipelines-main"} == names
    flex = next(f for f in base_inv.federated if f.name == "web-any-repo")
    assert flex.subject is None and "matches" in flex.expression


def test_app_permissions_resolve_through_resource_app_roles(base_inv):
    perms = {(base_inv.name(p.sp_id), p.permission) for p in base_inv.app_permissions}
    assert ("ops-automation", "RoleManagement.ReadWrite.Directory") in perms
    assert ("legacy-batch-etl", "Directory.ReadWrite.All") in perms


def test_directory_role_states(base_inv):
    states = {(base_inv.name(a.principal_id).split("@")[0], a.role): a.state for a in base_inv.dir_roles}
    assert states[("marcus.reid", "Global Administrator")] == "standing"
    assert states[("ava.chen", "Global Administrator")] == "eligible"
    assert states[("priya.nair", "Global Administrator")] == "activated"


def test_azure_role_names_resolve(base_inv):
    roles = {(base_inv.name(a.principal_id).split("@")[0], a.role, a.state) for a in base_inv.azure_roles}
    assert ("tom.baker", "Owner", "standing") in roles and ("ava.chen", "Owner", "eligible") in roles


def test_ca_policies_resolve_role_names(base_inv):
    admins = next(p for p in base_inv.ca_policies if p.name.startswith("CA03"))
    assert admins.include_roles == ["Global Administrator"] and admins.auth_strength == "Phishing-resistant MFA"


def test_resources_and_identities(base_inv):
    vm = base_inv.resource_by_name("vm-kr-batch01")
    assert vm.identities and vm.env == "prod"
    func = base_inv.resource_by_name("func-kr-loan-intake-prod")
    assert func.identities == [base_inv.resource_by_name("id-kr-loan-intake-func").props["principalId"]]


def test_connections_are_separate_from_resources(base_inv):
    assert {c.name for c in base_inv.connections} == {
        "conn-ledgerline-crm",
        "conn-ledgerline-crm-service",
        "conn-policy-search",
        "conn-credit-bureau",
    }
    assert not any(r.type.endswith("/connections") for r in base_inv.resources.values())


def test_secrets_metadata_only(base_inv):
    crm = next(s for s in base_inv.secrets if s.name == "crm-api-key")
    assert crm.expires_in_days is None and round(crm.updated_days) == 420
    raw = (TENANT_DATA / "keyvault/kv-kr-prod-secrets.json").read_text()
    assert '"value"' in raw and "secretValue" not in raw


def test_agents_tools_and_capabilities(base_inv):
    cs = next(a for a in base_inv.agents if a.name == "customer-service")
    caps = {t.name: t.capabilities for t in cs.tools}
    assert caps["crm_update"] == ["crm.write"] and caps["crm_lookup"] == ["crm.read"]
    assert next(t for t in cs.tools if t.name == "crm_update").connection == "conn-ledgerline-crm-service"


def test_saas_accounts(base_inv):
    local = next(s for s in base_inv.saas if s.user_name == "admin.local")
    assert local.admin and not local.sso and local.key == "saas:ledgerline-crm:admin.local"


def test_transitive_group_membership(base_inv):
    member = next(p for p in base_inv.principals.values() if p.kind == "group" and p.name == "FinOps-Readers").members[0]
    names = {base_inv.name(gid) for gid in base_inv.groups_of(member)}
    assert names == {"FinOps-Readers", "Finance-All"}


def test_scope_kind():
    assert scope_kind("/subscriptions/x") == "subscription"
    assert scope_kind("/subscriptions/x/resourceGroups/rg") == "resource_group"
    assert scope_kind("/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv") == "resource"
    assert scope_kind("/providers/Microsoft.Management/managementGroups/mg") == "management_group"


def test_load_tolerates_missing_optional_files(tmp_path):
    import shutil

    shutil.copytree(TENANT_DATA, tmp_path / "t")
    for rel in ("saas", "keyvault", "foundry"):
        shutil.rmtree(tmp_path / "t" / rel)
    inv = inventory.load(tmp_path / "t")
    assert inv.agents == [] and inv.secrets == [] and inv.saas == []
