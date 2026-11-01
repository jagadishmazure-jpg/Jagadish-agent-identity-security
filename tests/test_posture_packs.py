"""Posture packs: drift with approved rollback, report-only impact, session hardening, Exchange and
SharePoint, browser-extension cookie theft, SOC incident links and on-prem AD Tier 0."""

import copy
import json

import pytest

from idsec import adtier0, changegate, cli, drift, extension, impact, incident_link, m365, session

AVA, PRIYA = "ava.chen@kestrelridge.example", "priya.nair@kestrelridge.example"


# ------------------------------------------------------------------------------------ change gate
def _change(dual=False):
    return changegate.Change("T-1", "set a", [changegate.Step("a.b", 2, "test")], dual)


@pytest.mark.parametrize("who", ["agent:identity-explainer", "sp:automation", "mcp:client"])
def test_agents_cannot_approve(who):
    with pytest.raises(changegate.Refused):
        changegate.approve(_change(), who)


def test_unknown_human_cannot_approve():
    with pytest.raises(changegate.Refused):
        changegate.approve(_change(), "someone@kestrelridge.example")


def test_no_approval_no_change():
    r, s = changegate.apply(_change(), [], {"a": {"b": 1}})
    assert r.status == "refused" and s == {"a": {"b": 1}}


def test_one_approval_applies_and_verifies():
    c = _change()
    r, s = changegate.apply(c, [changegate.approve(c, AVA)], {"a": {"b": 1}})
    assert r.status == "applied" and s["a"]["b"] == 2 and r.verified == [("a.b", True)]


def test_apply_does_not_mutate_input():
    c, state = _change(), {"a": {"b": 1}}
    changegate.apply(c, [changegate.approve(c, AVA)], state)
    assert state == {"a": {"b": 1}}


def test_dual_control_needs_two_people():
    c = _change(dual=True)
    one = changegate.approve(c, AVA)
    assert changegate.apply(c, [one, one], {"a": {"b": 1}})[0].status == "refused"
    assert changegate.apply(c, [one, changegate.approve(c, PRIYA)], {"a": {"b": 1}})[0].status == "applied"


def test_approval_bound_to_digest():
    c = _change()
    a = changegate.approve(c, AVA)
    edited = changegate.Change("T-1", "set a", [changegate.Step("a.b", 99, "test")])
    r, _ = changegate.apply(edited, [a], {"a": {"b": 1}})
    assert r.status == "refused" and "different version" in r.reason


# ------------------------------------------------------------------------------------ drift
def test_drift_measured():
    e = drift.evaluate()
    assert e["drifts"] == 6 and e["classified_correctly"] == "6/6"
    assert e["rollbacks_proposed"] == 3 and e["refused_with_one_approver"] == 1
    assert e["verification_passed"] and e["unapproved_weakening_left"] == 0 and e["agent_approval_refused"]


def test_no_drift_against_itself():
    assert drift.detect(drift.baseline(), drift.baseline()) == []


def test_ticketed_change_is_not_rolled_back():
    keys = {c.steps[0].key for c in drift.rollback(drift.detect(drift.baseline(), drift.current()))}
    assert not any("guestInvite" in k for k in keys)


def test_admin_policy_rollback_is_dual_control():
    assert any(c.dual_control for c in drift.rollback(drift.detect(drift.baseline(), drift.current())))


# ------------------------------------------------------------------------------------ impact
def test_signins_deterministic():
    assert impact.signins() == impact.signins()


def test_impact_measured():
    e = impact.evaluate()
    assert e["signins_replayed"] == 373 and e["users"] == 82
    assert e["legacy_block_would_block_users"] == 5 and e["legacy_block_hits_exception_group"] == 2
    assert e["emergency_accounts_affected"] == 0 and e["changes_made"] == 0


def test_legacy_block_lists_legacy_users_only():
    i = impact.impact(impact.report_only_policies()[0])
    assert i.outcome == "block" and set(impact.LEGACY) <= set(i.users)
    assert all(k in ("IMAP mail client", "SMTP AUTH (scan-to-email)", "basic-auth ActiveSync phone") for k in i.by_client)


def test_excluded_group_is_respected():
    p = copy.deepcopy(impact.report_only_policies()[0])
    p["conditions"]["users"]["excludeGroups"] = ["00000000-0000-0000-0002-000000000002"]
    i = impact.impact(p)
    assert len(i.users) == 3 and len(i.excluded_but_active) == 2


def test_unmanaged_filter_skips_compliant_devices():
    p = session.proposed()[1]
    s = impact.SignIn("u", "u@x", False, "Microsoft Teams", "browser", "browser", True, "windows")
    assert impact.applies(p, s, set()) == (False, "managed device")


def test_guest_scope():
    p = {"conditions": {"users": {"includeUsers": ["GuestsOrExternalUsers"]}, "applications": {"includeApplications": ["All"]}}}
    g = impact.SignIn("g", "g@x", True, "Microsoft Teams", "browser", "browser", False, "windows")
    m = impact.SignIn("m", "m@x", False, "Microsoft Teams", "browser", "browser", True, "windows")
    assert impact.applies(p, g, set())[0] and not impact.applies(p, m, set())[0]


def test_outcome_labels():
    assert impact.outcome({"grantControls": {"builtInControls": ["block"]}}) == "block"
    assert impact.outcome({"grantControls": {"builtInControls": ["mfa"]}}) == "require: mfa"
    assert impact.outcome(session.proposed()[0]).startswith("session:")


# ------------------------------------------------------------------------------------ session
def test_session_today_fails_everything():
    assert all(r.status == "fail" for r in session.check(session.tenant_policies()))


def test_session_report_only_is_not_pass():
    assert all(r.status == "report-only" for r in session.check(session.tenant_policies() + session.proposed()))


def test_session_enforced_passes():
    assert all(r.status == "pass" for r in session.check(session.enforced(session.proposed())))


@pytest.mark.parametrize("i", range(4))
def test_near_miss_does_not_pass(i):
    assert session.check([session.near_misses()[i]])[i].status == "fail"


def test_disabled_policy_ignored():
    pols = session.enforced(session.proposed())
    for p in pols:
        p["state"] = "disabled"
    assert all(r.status == "fail" for r in session.check(pols))


def test_sign_in_frequency_threshold():
    p = session.enforced(session.proposed())[:1]
    p[0]["sessionControls"]["signInFrequency"]["value"] = 9
    assert session.check(p)[0].status == "fail"


def test_proposed_excludes_emergency_group():
    assert session.evaluate()["proposed_exclude_emergency_accounts"]


# ------------------------------------------------------------------------------------ m365
def test_m365_measured():
    e = m365.evaluate()
    assert e["precision"] == 1.0 and e["recall"] == 1.0 and e["findings"] == 9 and e["look_alikes_cleared"] == "5/5"


@pytest.mark.parametrize("obj", m365.LOOK_ALIKES)
def test_m365_look_alikes_not_flagged(obj):
    assert obj not in {f.obj for f in m365.scan()}


def test_m365_fixed_config_is_clean():
    cfg = copy.deepcopy(m365.CONFIG)
    ex, sp = cfg["exchange"], cfg["sharepoint"]
    ex["org"]["SmtpClientAuthenticationDisabled"] = True
    ex["inboxRules"] = [r for r in ex["inboxRules"] if r["id"] in ("RULE-02", "RULE-03")]
    for m in ex["mailboxes"]:
        m["AuditEnabled"], m["AuditBypass"] = True, False
    ex["domains"][1].update(dkim=True, dmarc="reject")
    sp["sites"][0]["SharingCapability"] = "ExistingExternalUserSharingOnly"
    sp["tenant"].update(DefaultSharingLinkType="Internal", ExternalUserExpirationRequired=True)
    assert m365.scan(cfg) == []


def test_m365_every_finding_has_fix():
    assert all(f.fix for f in m365.scan())


# ------------------------------------------------------------------------------------ extension
def test_extension_measured():
    e = extension.evaluate()
    assert e["risky_correct"] and e["look_alike_extensions_flagged"] == 0 and e["replayed_users_found"] == "3/3"
    assert not e["fresh_mfa_travel_flagged"] and e["changes_without_approval"] == 0 and e["agent_approval_refused"]
    assert e["applied_after_approval"] == 2 and e["verification_passed"]
    assert e["replays_still_accepted"] == 0 and e["devices_still_running_extension"] == 0


def test_allowlisted_cookie_reader_not_flagged():
    assert not extension.assess(extension.EXTENSIONS[1]).risky


def test_cookie_permission_alone_with_publisher_change_needs_login_host():
    e = copy.deepcopy(extension.EXTENSIONS[0])
    e["versions"][-1]["hosts"] = ["*://*.example/*"]
    assert not extension.assess(e).risky


def test_replay_requires_new_network():
    rows = [
        {"user": "a", "asn": 1, "interactive": True, "mfa": True, "session": "s"},
        {"user": "a", "asn": 1, "interactive": False, "mfa": False, "session": "s"},
    ]
    assert extension.replays(rows) == []


def test_extension_block_is_org_wide():
    block = extension.proposals()[1]
    assert "whole organization" in block.summary and any(s.key.startswith("browser.blocklist.") for s in block.steps)


def test_state_unchanged_without_approval():
    w = extension.walkthrough()
    assert [x for x in w["log"] if x[1] == "no approval"] == [("EXT-01", "no approval", "refused"), ("EXT-02", "no approval", "refused")]


# ------------------------------------------------------------------------------------ incident link
def test_incident_link_measured():
    e = incident_link.evaluate()
    assert e["tasks"] == 14 and e["precision"] == 1.0 and e["recall"] == 1.0
    assert e["benign_incidents_with_tasks"] == 0 and e["sent"] == 0


def test_benign_incident_gets_no_task():
    assert not [t for t in incident_link.link() if t.incident == "INC-2055"]


def test_task_ids_unique_and_ordered():
    ids = [t.id for t in incident_link.link()]
    assert ids == [f"HT-{i:03d}" for i in range(1, len(ids) + 1)]


def test_preview_file(tmp_path):
    p = incident_link.write_preview(tmp_path)
    rows = json.loads(p.read_text())
    assert p.name.endswith(".preview.json") and all(r["status"].startswith("proposed") for r in rows)


def test_unknown_entity_links_nothing():
    inc = [{"id": "X", "title": "t", "verdict": "true_positive", "techniques": ["T9999"], "entities": ["nobody"]}]
    assert incident_link.link(inc) == []


# ------------------------------------------------------------------------------------ AD Tier 0
def test_ad_measured():
    e = adtier0.evaluate()
    assert e["precision"] == 1.0 and e["recall"] == 1.0 and e["look_alikes_flagged"] == 0
    assert e["paths_to_tier0"] == 7 and e["top_choke_point"] == "Tier1-Server-Admins" and e["paths_cut_by_top_fix"] == 4
    assert e["fixes_to_cut_every_path"] == 4


@pytest.mark.parametrize("name", ["gmsa_web$", "svc_old", "Sync_KRCONNECT01", "svc_audit", "DC01", "DC02", "FILESVC"])
def test_ad_look_alikes(name):
    assert name not in {f.obj for f in adtier0.scan()}


def test_ad_privileged_roastable_is_critical():
    f = next(f for f in adtier0.scan() if f.obj == "svc_backup" and f.check == "kerberoastable")
    assert f.severity == "critical"


def test_ad_fix_plan_cuts_all_paths():
    plan = set(adtier0.fix_plan())
    assert all(plan & set(p) for p in adtier0.paths())


def test_ad_paths_start_at_foothold_end_at_tier0():
    assert all(p[0] == adtier0.FOOTHOLD and p[-1] == adtier0.TIER0 for p in adtier0.paths())


def test_sync_account_listed_as_tier0_asset():
    assert any(a.startswith("Sync_KRCONNECT01") for a in adtier0.tier0_assets())


# ------------------------------------------------------------------------------------ CLI
@pytest.mark.parametrize(
    "cmd,text",
    [
        ("drift", "Measured"),
        ("impact", "would block"),
        ("session", "report-only"),
        ("m365", "precision"),
        ("extension", "RISKY"),
        ("ad-tier0", "Choke points"),
    ],
)
def test_pack_commands(cmd, text, capsys):
    assert cli.main([cmd]) == 0
    assert text in capsys.readouterr().out


def test_incident_link_command(tmp_path, capsys):
    assert cli.main(["incident-link", "--out", str(tmp_path)]) == 0
    assert "nothing sent" in capsys.readouterr().out
