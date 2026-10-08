"""Posture scores, the remediation plan, approvals, dry-run execution and the what-if simulation."""

import copy
from datetime import timedelta

import pytest
from conftest import pid

from idsec import detections, remediation, scoring
from idsec.detections import Finding, RuleResult

AVA, PRIYA = "ava.chen@kestrelridge.example", "priya.nair@kestrelridge.example"


# ------------------------------------------------------------------------------------ scoring
def rr(rule, evaluated, n):
    return RuleResult(rule, evaluated, [Finding(rule, f"s{i}", f"s{i}", ["e"]) for i in range(n)])


@pytest.mark.parametrize("evaluated,n,expected", [(10, 0, 1.0), (10, 1, 0.45), (10, 10, 0.0), (4, 2, 0.25), (0, 0, None)])
def test_rule_score(evaluated, n, expected):
    assert scoring.rule_score(rr("dormant-account", evaluated, n)) == expected


def test_clean_tenant_scores_100():
    res = [rr(r["id"], 5, 0) for r in detections.catalogue()]
    s = scoring.score(res)
    assert all(s[a].score == 100.0 for a in (*scoring.AREAS, "overview"))


def test_rules_with_nothing_evaluated_are_ignored():
    res = [rr("dormant-account", 10, 0), rr("no-mfa-registered", 0, 0)]
    s = scoring.score(res)
    assert s["foundational"].score == 100.0 and s["foundational"].rules == 1


def test_area_without_rules_defaults_to_100():
    s = scoring.score([rr("dormant-account", 10, 10)])
    assert s["privilege"].score == 100.0 and s["foundational"].score == 0.0


def test_severity_weights_matter():
    crit = scoring.score([rr("privileged-without-enforced-mfa", 10, 10), rr("dormant-account", 10, 0)])["foundational"].score
    med = scoring.score([rr("privileged-without-enforced-mfa", 10, 0), rr("dormant-account", 10, 10)])["foundational"].score
    assert crit < med


def test_overview_is_mean_of_areas(results):
    s = scoring.score(results)
    assert s["overview"].score == round(sum(s[a].score for a in scoring.AREAS) / 3, 1)
    assert s["overview"].findings == 47


def test_real_scores(results):
    s = scoring.score(results)
    assert (s["privilege"].score, s["foundational"].score, s["emerging"].score, s["overview"].score) == (41.8, 31.7, 33.8, 35.8)


@pytest.mark.parametrize("value,g", [(95, "A"), (90, "A"), (80, "B"), (60, "C"), (45, "D"), (39.9, "F")])
def test_grade(value, g):
    assert scoring.grade(value) == g


# ------------------------------------------------------------------------------------ plan
@pytest.fixture(scope="module")
def plan(base_inv, results):
    return remediation.plan(results, base_inv)


def test_one_item_per_finding(plan, results):
    assert len(plan.items) == 47 and {i.finding for i in plan.items} == {f.id for f in detections.all_findings(results)}


def test_every_action_is_ordered(plan):
    assert {i.action for i in plan.items} <= set(remediation.ORDER)


def test_digest_is_stable_and_bound_to_content(plan):
    it = plan.items[0]
    assert it.digest == it.compute_digest() and len(it.digest) == 16
    changed = copy.deepcopy(it)
    changed.change += " and also something else"
    assert changed.compute_digest() != it.digest


def test_dual_control_for_critical_and_listed_actions(plan):
    for it in plan.items:
        meta = detections.rule_meta(it.rule)
        if meta["severity"] == "critical" or it.action in ("convert-to-eligible", "remove-app-permission"):
            assert it.approvals_needed == 2, it.id


def test_modes(plan):
    modes = {i.mode for i in plan.items}
    assert modes <= {"simulated", "user-action", "derived", "needs-decision"}
    assert next(i for i in plan.items if i.rule == "no-mfa-registered").mode == "user-action"
    assert next(i for i in plan.items if i.rule == "human-path-to-crown-jewel").mode == "derived"


def test_hints_drive_specific_changes(plan):
    docs = next(i for i in plan.items if i.rule == "workload-subscription-privilege" and i.label == "loan-docs-sync")
    assert docs.mode == "simulated" and "subscription-wide" in docs.change


def test_snippets_present_for_iac_actions(plan):
    marcus = next(i for i in plan.items if i.rule == "standing-privileged-role")
    assert "azuread_directory_role_eligibility_schedule_request" in marcus.terraform
    vault = next(i for i in plan.items if i.rule == "vault-legacy-access-policies")
    assert "rbac_authorization_enabled    = true" in vault.terraform and "enableRbacAuthorization: true" in vault.bicep


@pytest.mark.parametrize(
    "text,expected", [("Harbor Backup Service", "harbor_backup_service"), ('x"; drop } #', "x_drop"), ("!!!", "subject"), ("a" * 80, "a" * 40)]
)
def test_slug_neutralises_names(text, expected):
    assert remediation.slug(text) == expected


def test_snippets_never_carry_raw_labels(inv, results):
    inv.principals[pid(inv, "loan-docs-sync")].name = 'evil" }\nresource "x" "y" {'
    from idsec import graph as gmod

    p = remediation.plan(detections.run(inv, gmod.build(inv)), inv)
    for it in p.items:
        assert 'evil"' not in it.terraform and 'evil"' not in it.bicep


def test_by_id(plan):
    assert plan.by_id(plan.items[0].id) is plan.items[0]
    with pytest.raises(KeyError):
        plan.by_id("R-NOPE")


# ------------------------------------------------------------------------------------ approvals
@pytest.fixture(scope="module")
def dual(plan):
    return next(i for i in plan.items if i.approvals_needed == 2 and i.mode == "simulated")


@pytest.mark.parametrize("who", ["agent:identity-explainer", "sp:ops-automation", "mcp:client", "mallory@kestrelridge.example"])
def test_non_approvers_refused(dual, base_inv, who):
    with pytest.raises(remediation.ApprovalError):
        remediation.approve(dual, who, base_inv.now, base_inv)


def test_disabled_approver_refused(dual, inv):
    inv.principals[pid(inv, "ava.chen")].enabled = False
    with pytest.raises(remediation.ApprovalError):
        remediation.approve(dual, AVA, inv.now, inv)


def _status(plan, approvals, now, item):
    return next(r for r in remediation.execute(plan, approvals, now) if r.item_id == item.id)


def test_one_approval_is_not_enough_for_dual_control(plan, dual, base_inv):
    a1 = remediation.approve(dual, AVA, base_inv.now, base_inv)
    assert _status(plan, [a1], base_inv.now, dual).status == "blocked"


def test_same_approver_twice_counts_once(plan, dual, base_inv):
    a1 = remediation.approve(dual, AVA, base_inv.now, base_inv)
    assert _status(plan, [a1, a1], base_inv.now, dual).status == "blocked"


def test_two_approvers_would_apply_without_changing_anything(plan, dual, base_inv):
    before = copy.deepcopy(base_inv.__dict__.get("dir_roles"))
    a = [remediation.approve(dual, w, base_inv.now, base_inv) for w in (AVA, PRIYA)]
    r = _status(plan, a, base_inv.now, dual)
    assert r.status == "would-apply" and "nothing was changed" in r.reason
    assert base_inv.dir_roles == before


def test_digest_mismatch_blocks(plan, dual, base_inv):
    a1 = remediation.approve(dual, AVA, base_inv.now, base_inv)
    stale = remediation.Approval(dual.id, "0" * 16, PRIYA, base_inv.now)
    assert "digest" in _status(plan, [a1, stale], base_inv.now, dual).reason


def test_expired_approvals_block(plan, dual, base_inv):
    a = [remediation.approve(dual, w, base_inv.now, base_inv) for w in (AVA, PRIYA)]
    assert _status(plan, a, base_inv.now + timedelta(hours=25), dual).status == "blocked"
    assert _status(plan, a, base_inv.now + timedelta(hours=23), dual).status == "would-apply"


def test_unapproved_items_stay_blocked(plan, base_inv):
    assert all(r.status == "blocked" for r in remediation.execute(plan, [], base_inv.now))


def test_live_execution_is_refused(plan, base_inv):
    with pytest.raises(NotImplementedError):
        remediation.execute(plan, [], base_inv.now, dry_run=False)


# ------------------------------------------------------------------------------------ simulation
@pytest.fixture(scope="module")
def sim(base_inv, results):
    return remediation.simulate(base_inv, results)


def test_simulation_numbers(sim):
    assert sim.before["overview"].score == 35.8 and sim.after["overview"].score == 90.5
    assert len(sim.applied) == 38 and len(sim.skipped) == 9 and len(sim.remaining) == 3
    assert (sim.paths_before, sim.paths_after) == (48, 13)


def test_remaining_findings_are_the_ones_left_to_people(sim):
    assert {f.rule for f in sim.remaining} == {"human-path-to-crown-jewel", "no-mfa-registered", "emergency-account-weak-method"}


def test_simulation_never_touches_the_input(base_inv, sim):
    assert sim.inventory is not base_inv
    marcus = pid(base_inv, "marcus.reid")
    assert any(r.principal_id == marcus and r.state == "standing" for r in base_inv.dir_roles)
    assert not any(r.principal_id == marcus and r.state == "standing" and r.role == "Global Administrator" for r in sim.inventory.dir_roles)


@pytest.mark.parametrize(
    "check",
    [
        lambda inv: inv.resource_by_name("kv-kr-nonprod").props["enableRbacAuthorization"] is True,
        lambda inv: all(p.state == "enabled" for p in inv.ca_policies if "block" in p.grant),
        lambda inv: not inv.principals[pid(inv, "gary.holt")].enabled,
        lambda inv: all(c.auth_type == "AAD" for c in inv.connections if c.name.startswith("conn-ledgerline")),
        lambda inv: all(s.expires_in_days is not None for s in inv.secrets),
        lambda inv: inv.principals[pid(inv, "hr-sync-connector")].owners != [],
        lambda inv: len({a.identity_id for a in inv.agents}) == len(inv.agents),
        lambda inv: not any(p.permission == "RoleManagement.ReadWrite.Directory" for p in inv.app_permissions),
        lambda inv: all(c.lifetime_days <= 180 for c in inv.app_credentials if c.kind == "password" and c.expires_in_days > 0),
    ],
    ids=[
        "vault-rbac",
        "legacy-block-on",
        "dormant-disabled",
        "connection-aad",
        "secret-expiry",
        "owner-assigned",
        "identity-split",
        "tier0-removed",
        "short-secrets",
    ],
)
def test_simulated_changes(sim, check):
    assert check(sim.inventory)


def test_simulation_without_precomputed_results(base_inv):
    s = remediation.simulate(base_inv)
    assert s.after["overview"].score == 90.5
