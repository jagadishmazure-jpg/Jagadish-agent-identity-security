"""Detection rules: planted cases are found, look-alikes are not, and each rule reacts to change."""

import json
import re

import pytest
from conftest import pid, rescan

from idsec import DATA, detections
from idsec.inventory import AppCredential, AzureRoleAssignment, ConsentGrant, DirRoleAssignment, FederatedCredential

PLANTED = json.loads((DATA / "ground-truth.json").read_text())["planted"]
PROD = "/subscriptions/00000000-0000-0000-0000-0000000000a1"
CAT = detections.catalogue()


# ------------------------------------------------------------------------------------ catalogue
def test_every_rule_has_an_implementation():
    assert {r["id"] for r in CAT} == set(detections.RULES)


def test_codes_are_unique_and_follow_the_area():
    codes = [r["code"] for r in CAT]
    assert len(codes) == len(set(codes)) == 28
    prefix = {"privilege": "P", "foundational": "F", "emerging": "E"}
    assert all(r["code"][0] == prefix[r["area"]] for r in CAT)


@pytest.mark.parametrize("r", CAT, ids=lambda r: r["id"])
def test_rule_metadata_is_complete(r):
    for key in ("title", "explanation", "fix", "severity", "action"):
        assert r[key], key
    assert r["severity"] in ("critical", "high", "medium", "low")
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in r.get("attack", []))
    assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", t) for t in r.get("atlas", []))
    assert all(re.fullmatch(r"LLM(0[1-9]|10)", t) for t in r.get("owasp_llm", []))
    assert r.get("attack") or r.get("atlas"), "every rule maps to an adversary technique"
    assert r.get("cis") or r.get("zero_trust"), "every rule maps to a control framework"


def test_agent_rules_map_to_owasp_llm():
    for r in CAT:
        # agent-key-connection is about a stored credential, not model behaviour
        if "agent" in r["id"] and r["id"] != "agent-key-connection":
            assert r.get("owasp_llm"), r["id"]


def test_rule_meta_lookup():
    assert detections.rule_meta("dormant-account")["code"] == "F03"
    with pytest.raises(KeyError):
        detections.rule_meta("nope")


# ------------------------------------------------------------------------------------ planted truth
@pytest.mark.parametrize("x", PLANTED, ids=lambda x: f"{x['rule']}:{x['subject'][-12:]}")
def test_planted_case_is_found(found, x):
    assert (x["rule"], x["subject"]) in found, x["note"]


def test_no_finding_outside_ground_truth(found):
    assert found == {(x["rule"], x["subject"]) for x in PLANTED}


def test_finding_ids_and_evidence(results):
    for r in results:
        for i, f in enumerate(r.findings, 1):
            assert f.id.endswith(f"-{i:02d}") and f.evidence and f.label
            assert r.evaluated >= len(r.findings)


def test_all_findings_sorted_by_severity(results):
    order = [detections.SEVERITY_ORDER[f.severity] for f in detections.all_findings(results)]
    assert order == sorted(order)


def test_path_findings_carry_their_path(results):
    for f in detections.all_findings(results):
        if f.rule in ("human-path-to-crown-jewel", "agent-untrusted-input-path"):
            assert len(f.path) >= 2


# ------------------------------------------------------------------------------------ look-alikes
def _by(base_inv, who):
    return pid(base_inv, who)


@pytest.mark.parametrize(
    "rule,who,why",
    [
        ("standing-privileged-role", "ava.chen", "eligible through PIM"),
        ("standing-privileged-role", "priya.nair", "PIM activation in progress"),
        ("standing-privileged-role", "breakglass01", "emergency accounts are meant to be standing"),
        ("dormant-account", "omar.reyes", "new hire inside the grace period"),
        ("dormant-account", "former.engineer", "disabled accounts are not dormant risk"),
        ("dormant-account", "breakglass01", "emergency accounts rarely sign in by design"),
        ("no-mfa-registered", "breakglass02", "emergency accounts have their own rule"),
        ("privileged-without-enforced-mfa", "marcus.reid", "covered by the admin MFA policy"),
        ("human-path-to-crown-jewel", "ava.chen", "admins are covered by the standing-role rules"),
        ("human-path-to-crown-jewel", "leo.martins", "no path"),
        ("risky-consent-grant", "Meetly Scheduler", "harmless scopes"),
        ("risky-consent-grant", "Microsoft Graph", "first party"),
        ("broad-federated-subject", "github-deploy-docs", "pinned to the main branch"),
        ("broad-federated-subject", "id-kr-github-data", "pinned to the main branch"),
        ("unowned-workload-identity", "loan-docs-sync", "owned by an active person"),
        ("long-lived-app-secret", "hr-sync-connector", "within the lifetime limit"),
        ("workload-subscription-privilege", "id-kr-loan-intake-func", "resource-scoped roles only"),
        ("external-app-with-privilege", "Northwind Cloud Monitor", "reader only"),
        ("guest-with-privilege", "auditor_auditco.example#EXT#", "reader only"),
    ],
)
def test_look_alike_is_not_flagged(base_inv, found, rule, who, why):
    try:
        subject = _by(base_inv, who)
    except KeyError:
        subject = next(p.id for p in base_inv.principals.values() if p.upn.startswith(who))
    assert (rule, subject) not in found, why


@pytest.mark.parametrize(
    "rule,agent",
    [
        ("overprivileged-agent", "asst_research"),
        ("agent-reads-secrets", "asst_loan_intake"),
        ("agent-tool-beyond-purpose", "asst_collections"),
        ("agent-untrusted-input-path", "asst_collections"),
        ("agent-untrusted-input-path", "asst_research"),
        ("unsponsored-agent", "asst_underwriting"),
    ],
)
def test_agent_look_alike_is_not_flagged(found, rule, agent):
    assert (rule, agent) not in found


def test_rbac_vault_and_aad_connection_are_clean(found):
    assert ("vault-legacy-access-policies", "vault:kv-kr-prod-secrets") not in found
    assert ("agent-key-connection", "conn:conn-policy-search") not in found
    assert ("agent-key-connection", "conn:conn-credit-bureau") not in found


# ------------------------------------------------------------------------------------ mutations
def test_new_standing_tier0_role_fires(inv):
    leo = pid(inv, "leo.martins")
    inv.dir_roles.append(DirRoleAssignment(leo, "Privileged Role Administrator", "standing"))
    assert ("standing-privileged-role", leo) in rescan(inv)


def test_eligible_role_does_not_fire_standing(inv):
    leo = pid(inv, "leo.martins")
    inv.dir_roles.append(DirRoleAssignment(leo, "Privileged Role Administrator", "eligible"))
    assert ("standing-privileged-role", leo) not in rescan(inv)


def test_low_tier_directory_role_does_not_fire(inv):
    leo = pid(inv, "leo.martins")
    inv.dir_roles.append(DirRoleAssignment(leo, "Directory Readers", "standing"))
    assert ("standing-privileged-role", leo) not in rescan(inv)


@pytest.mark.parametrize("scope,fires", [(PROD, True), (PROD + "/resourceGroups/rg-kr-sandbox", False)])
def test_azure_admin_scope_matters(inv, scope, fires):
    leo = pid(inv, "leo.martins")
    inv.azure_roles.append(AzureRoleAssignment("x", leo, "Owner", scope, "standing"))
    assert (("standing-azure-admin", leo) in rescan(inv)) is fires


@pytest.mark.parametrize("role,fires", [("Reader", False), ("Contributor", True)])
def test_workload_subscription_role(inv, role, fires):
    mi = pid(inv, "id-kr-loan-intake-func")
    inv.azure_roles.append(AzureRoleAssignment("x", mi, role, PROD, "standing"))
    assert (("workload-subscription-privilege", mi) in rescan(inv)) is fires


@pytest.mark.parametrize("perm,fires", [("User.Read.All", False), ("AppRoleAssignment.ReadWrite.All", True)])
def test_app_permission_tiers(inv, perm, fires):
    from idsec.inventory import AppPermission

    app = pid(inv, "payments-api")
    inv.app_permissions.append(AppPermission(app, "Microsoft Graph", perm))
    assert (("high-risk-app-permission", app) in rescan(inv)) is fires


def test_guest_with_reader_is_not_privileged_but_contributor_is(inv):
    guest = next(p.id for p in inv.principals.values() if p.kind == "guest" and "auditor" in p.upn)
    inv.azure_roles.append(AzureRoleAssignment("x", guest, "Reader", PROD, "standing"))
    assert ("guest-with-privilege", guest) not in rescan(inv)
    inv.azure_roles.append(AzureRoleAssignment("y", guest, "Key Vault Secrets User", PROD, "standing"))
    assert ("guest-with-privilege", guest) in rescan(inv)


def test_verified_publisher_clears_consent_finding(inv):
    app = pid(inv, "MailVault Archiver")
    inv.principals[app].verified_publisher = "MailVault Ltd"
    assert ("risky-consent-grant", app) not in rescan(inv)


def test_per_user_consent_is_not_tenant_wide(inv):
    app = pid(inv, "Meetly Scheduler")
    inv.consents.append(ConsentGrant("g", app, "Principal", pid(inv, "leo.martins"), ["Mail.Read"]))
    assert ("risky-consent-grant", app) not in rescan(inv)


def test_removing_the_ca_exclusion_covers_sara(inv):
    sara = pid(inv, "sara.okafor")
    for pol in inv.ca_policies:
        pol.exclude_groups = []
    assert ("privileged-without-enforced-mfa", sara) not in rescan(inv)


def test_disabling_the_admin_policy_exposes_admins(inv):
    for pol in inv.ca_policies:
        if pol.include_roles or "All" in pol.include_users:
            pol.state = "disabled"
    hits = {s for r, s in rescan(inv) if r == "privileged-without-enforced-mfa"}
    assert pid(inv, "marcus.reid") in hits


def test_enabling_legacy_block_clears_and_deleting_it_flags_tenant(inv):
    for pol in inv.ca_policies:
        if "block" in pol.grant:
            pol.state = "enabled"
    assert not any(r == "legacy-auth-not-blocked" for r, _ in rescan(inv))
    inv.ca_policies = [p for p in inv.ca_policies if "block" not in p.grant]
    assert ("legacy-auth-not-blocked", inv.tenant_id) in rescan(inv)


def test_emergency_account_with_fido2_is_clean(inv):
    bg = pid(inv, "breakglass02")
    inv.principals[bg].methods = ["fido2SecurityKey"]
    assert ("emergency-account-weak-method", bg) not in rescan(inv)


def test_rbac_vault_clears_access_policy_finding(inv):
    inv.resource_by_name("kv-kr-nonprod").props["enableRbacAuthorization"] = True
    assert ("vault-legacy-access-policies", "vault:kv-kr-nonprod") not in rescan(inv)


def test_saas_admin_with_sso_and_active_link_is_clean(inv):
    acct = next(a for a in inv.saas if a.user_name == "admin.local")
    acct.sso, acct.entra_id = True, pid(inv, "ava.chen")
    assert ("saas-admin-outside-sso", acct.key) not in rescan(inv)


def test_inactive_saas_admin_is_ignored(inv):
    acct = next(a for a in inv.saas if a.user_name == "admin.local")
    acct.active = False
    assert ("saas-admin-outside-sso", acct.key) not in rescan(inv)


@pytest.mark.parametrize(
    "kind,lifetime,left,fires",
    [
        ("password", 365, 100, True),
        ("password", 90, 10, False),
        ("certificate", 300, 100, False),
        ("certificate", 800, 100, True),
        ("password", 730, -5, False),
    ],
)
def test_credential_lifetime(inv, kind, lifetime, left, fires):
    app = pid(inv, "payments-api")
    inv.app_credentials.append(AppCredential(app, kind, "c", 10, lifetime, left))
    assert (("long-lived-app-secret", app) in rescan(inv)) is fires


def test_rotating_a_secret_clears_rotation_and_expiry(inv):
    s = next(x for x in inv.secrets if x.name == "dev-db-password")
    s.updated_days, s.expires_in_days = 3, 87
    hits = rescan(inv)
    assert ("unrotated-secret", s.key) not in hits and ("secret-without-expiry", s.key) not in hits


def test_shared_credential_counts_resource_refs(inv):
    func = inv.resource_by_name("vm-kr-batch01")
    func.tags["kvSecretRefs"] = "kv-kr-prod-secrets/core-banking-db-password"
    assert ("shared-credential", "secret:kv-kr-prod-secrets/core-banking-db-password") in rescan(inv)


def test_adding_an_active_owner_clears_unowned(inv):
    app = pid(inv, "hr-sync-connector")
    inv.principals[app].owners = [pid(inv, "ava.chen")]
    assert ("unowned-workload-identity", app) not in rescan(inv)


def test_disabled_sponsor_counts_as_none(inv):
    agent = next(a for a in inv.agents if a.id == "asst_underwriting")
    for s in inv.principals[agent.identity_id].sponsors:
        inv.principals[s].enabled = False
    assert ("unsponsored-agent", "asst_underwriting") in rescan(inv)


def test_tool_inside_purpose_is_fine(inv):
    agent = next(a for a in inv.agents if a.id == "asst_loan_intake")
    agent.tools = [t for t in agent.tools if "mail.send" not in t.capabilities]
    assert ("agent-tool-beyond-purpose", "asst_loan_intake") not in rescan(inv)


def test_splitting_the_shared_identity(inv):
    shared = next(a for a in inv.agents if a.id == "asst_collections")
    old, shared.identity_id = shared.identity_id, pid(inv, "agent-research-sandbox")
    assert ("shared-agent-identity", old) not in rescan(inv)


def test_internal_agent_has_no_untrusted_path(inv):
    agent = next(a for a in inv.agents if a.id == "asst_underwriting")
    agent.ingests = "internal"
    assert ("agent-untrusted-input-path", "asst_underwriting") not in rescan(inv)


def test_non_github_issuer_is_ignored(inv):
    app = pid(inv, "payments-api")
    inv.federated.append(FederatedCredential(app, "aks", "https://oidc.example/aks", "system:serviceaccount:*"))
    assert ("broad-federated-subject", app) not in rescan(inv)


GH = "https://token.actions.githubusercontent.com"


@pytest.mark.parametrize(
    "subject,expression,broad",
    [
        ("repo:o/r:environment:prod", None, False),
        ("repo:o/r:ref:refs/heads/main", None, False),
        ("repo:o/r:ref:refs/tags/v1", None, False),
        ("repo:o/r:pull_request", None, True),
        ("repo:o/*", None, True),
        ("repo:o/r:ref:refs/heads/*", None, True),
        ("repo:o/r:job_workflow_ref:x", None, True),
        (None, "claims['sub'] matches 'repo:o/*'", True),
        (None, "claims['sub'] eq 'repo:o/r:environment:prod'", False),
    ],
)
def test_federated_breadth(subject, expression, broad):
    f = FederatedCredential("p", "n", GH, subject, expression)
    assert (detections.federated_breadth(f) is not None) is broad


def test_consumers_map(base_inv):
    cons = detections.consumers(base_inv)
    assert len(cons["secret:kv-kr-prod-secrets/crm-api-key"]) == 2


def test_rules_run_without_a_prebuilt_graph(base_inv):
    assert len(detections.run(base_inv)) == 28
