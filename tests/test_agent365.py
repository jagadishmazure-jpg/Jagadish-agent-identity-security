"""Connected-platform Entra Agent IDs, dynamic risk and the cost/value report. All offline."""

import pytest

from idsec import agent365
from idsec.agent365 import (
    CATALOG,
    SIGNAL_KINDS,
    Decision,
    ExternalAgent,
    RegistryError,
    Signal,
    action,
    assess,
    connect,
    cost_rows,
    decide,
    demo_decisions,
    evaluate,
    forecast_spend,
    issue,
    level_for,
    make_signal,
    recommend,
    registry,
    risk_for,
)

LOAN = CATALOG[0]


def test_each_platform_receives_one_identity():
    issued = registry()
    assert [item.platform for item in issued] == [key for key, _name in agent365.PLATFORMS]
    assert len({item.entra_agent_id for item in issued}) == 6
    assert all(item.stored_secrets == 0 and item.auth == "workload-identity-federation" for item in issued)
    assert len({item.blueprint_id for item in issued}) == 6


def test_issue_is_deterministic_and_keeps_the_sponsor():
    assert issue(LOAN) == issue(LOAN)
    ident = issue(LOAN)
    assert ident.sponsors == ("ava.chen@kestrelridge.example",)
    assert ident.blueprint_id == "blueprint-bedrock"
    assert ident.entra_agent_id == "agentid-bedrock-br-loan-reader"


def test_ownerless_agent_has_no_sponsor_link():
    ident = issue(CATALOG[4])
    assert ident.sponsors == ()
    assert agent365.as_service_principal(ident)["sponsors"] == []


def test_unknown_platform_and_stored_secrets_are_refused():
    with pytest.raises(RegistryError):
        connect("snowflake", "workload-identity-federation")
    with pytest.raises(RegistryError):
        connect("bedrock", "api-key")
    with pytest.raises(RegistryError):
        connect("bedrock", "workload-identity-federation", secret="stored-key")
    assert connect("openai", "workload-identity-federation") == {
        "platform": "openai",
        "auth": "workload-identity-federation",
        "stored_secrets": 0,
    }


def test_duplicate_external_agent_cannot_share_an_id():
    with pytest.raises(RegistryError):
        registry((LOAN, LOAN))


def test_graph_shape_is_an_agent_identity():
    ident = issue(LOAN)
    sp = agent365.as_service_principal(ident)
    blueprint = agent365.as_blueprint("bedrock")
    assert sp["@odata.type"] == "#microsoft.graph.agentIdentity"
    assert sp["servicePrincipalType"] == "ServiceIdentity"
    assert sp["agentIdentityBlueprintId"] == blueprint["appId"]
    assert blueprint["@odata.type"] == "#microsoft.graph.agentIdentityBlueprint"
    assert sp["id"] == ident.entra_agent_id
    assert "no stored secret" in sp["notes"]
    from idsec import inventory

    sponsor = sp["sponsors"][0]["id"]
    assert "@" not in sponsor
    assert inventory.load().principals[sponsor].upn == "ava.chen@kestrelridge.example"


def test_ownerless_signal_is_added_once():
    ident = issue(CATALOG[4])
    once = assess(ident, ())
    again = assess(ident, (make_signal("ownerless"),))
    assert once.signals == ("ownerless",) and once.score == SIGNAL_KINDS["ownerless"]
    assert again.score == once.score


def test_reweighted_or_unknown_signal_is_rejected():
    ident = issue(LOAN)
    with pytest.raises(RegistryError):
        make_signal("not-a-signal")
    with pytest.raises(RegistryError):
        assess(ident, (Signal("sensitive_data", "tampered", 1),))


def test_score_rises_with_a_new_signal_and_caps_at_100():
    ops = issue(CATALOG[5])
    before, after = risk_for(ops), risk_for(ops, follow_up=True)
    assert before.level == "high" and after.level == "critical"
    assert after.score > before.score
    assert "anomalous_cloud_call" in after.signals
    everything = assess(issue(LOAN), tuple(make_signal(kind) for kind in SIGNAL_KINDS))
    assert everything.score == 100 and everything.level == "critical"


@pytest.mark.parametrize(
    ("score", "name"),
    [(0, "low"), (24, "low"), (25, "medium"), (49, "medium"), (50, "high"), (74, "high"), (75, "critical"), (100, "critical")],
)
def test_level_cuts(score, name):
    assert level_for(score) == name


@pytest.mark.parametrize(
    ("external_id", "operation", "tool", "follow", "response", "level"),
    [
        ("br-loan-reader", "read", "", False, "allow", "low"),
        ("gx-rate-sheet", "read", "", False, "allow", "low"),
        ("sf-collections", "tool", "send-email", False, "require_approval", "medium"),
        ("db-loss-model", "tool", "sql-warehouse", False, "require_approval", "medium"),
        ("an-policy-draft", "read", "", False, "allow", "medium"),
        ("an-policy-draft", "write", "", False, "require_approval", "medium"),
        ("oa-ops-copilot", "tool", "role-assign", False, "block", "high"),
        ("oa-ops-copilot", "read", "", False, "restrict", "high"),
        ("oa-ops-copilot", "read", "", True, "block", "critical"),
    ],
)
def test_decisions_follow_the_policy(external_id, operation, tool, follow, response, level):
    found = {item.external_id: item for item in registry()}
    ident = found[external_id]
    decision = decide(ident, action(operation, tool, on_behalf_of="person@kestrelridge.example"), follow_up=follow)
    assert decision.response == response and decision.risk_level == level
    assert decision.evaluated_at == "action" and decision.user_access == "unchanged"
    assert decision.ca_style == agent365.CA_STYLE[response]
    assert decision.risk_score == risk_for(ident, follow_up=follow).score


def test_a_sensitive_tool_stays_sensitive_on_a_read():
    ident = issue(CATALOG[5])
    decision = decide(ident, action("read", "role-assign"))
    assert decision.sensitivity == "sensitive" and decision.response == "block"


def test_sign_in_alone_is_not_a_decision_point():
    ident = issue(LOAN)
    with pytest.raises(RegistryError):
        decide(ident, "sign_in")
    with pytest.raises(RegistryError):
        decide(ident, agent365.ActionContext("read", "", "", object()))


def test_a_forged_low_score_cannot_lower_the_decision():
    ops = issue(CATALOG[5])
    forged = agent365.Risk(ops.entra_agent_id, 0, "low", ())
    with pytest.raises(RegistryError):
        decide(ops, forged)
    decision = decide(ops, action("tool", "role-assign"))
    assert decision.risk_score == 60 and decision.response == "block"


def test_unknown_operation_and_unknown_tool_are_sensitive():
    collections = issue(CATALOG[2])
    deleted = decide(collections, action("delete"))
    assert deleted.sensitivity == "sensitive" and deleted.response == "require_approval"
    weird = issue(ExternalAgent("anthropic", "an-extra", "Extra drafter", "", ("drop-table",)))
    held = decide(weird, action("tool", "drop-table"))
    assert held.risk_level == "medium" and held.sensitivity == "sensitive" and held.response == "require_approval"


def test_a_tool_the_agent_was_not_issued_is_refused():
    with pytest.raises(RegistryError):
        decide(issue(LOAN), action("tool", "role-assign"))


def test_same_external_id_on_two_platforms_does_not_share_a_profile():
    other = ExternalAgent("openai", "br-loan-reader", "Same id elsewhere", "marcus.reid@kestrelridge.example", ("ticket-read",))
    bedrock, copied = issue(LOAN), issue(other)
    assert risk_for(bedrock).score == 10 and risk_for(copied).score == 0
    rows = {row["platform"]: row for row in cost_rows((LOAN, other))}
    assert rows["bedrock"]["spend"] == 400 and rows["openai"]["spend"] == 0
    assert rows["openai"]["recommendation"] == "review"


def test_outcomes_leave_the_person_alone_and_write_nothing():
    for decision in demo_decisions():
        result = agent365.outcome(decision)
        assert result["user"] == "unchanged" and result["written_to_tenant"] is False
        assert result["agent"] in {"proceed", "proceed_reduced", "held", "denied"}
        assert "human access left as-is" in decision.reason
        if decision.response == "block":
            assert result["agent"] == "denied"


@pytest.mark.parametrize(
    ("spend", "value", "success", "sessions", "satisfaction", "want"),
    [
        (100, 300, 80, 5, 70, "invest"),
        (100, 300, 80, 5, 69, "hold"),
        (100, 300, 79, 5, 90, "hold"),
        (100, 100, 50, 1, 90, "hold"),
        (100, 99, 90, 10, 90, "retire"),
        (100, 99, 90, 9, 90, "review"),
        (0, 10, 100, 10, 100, "review"),
    ],
)
def test_recommend_boundaries(spend, value, success, sessions, satisfaction, want):
    assert recommend(spend, value, success, sessions, satisfaction) == want


def test_forecast_grows_only_for_invest_and_stops_for_retire():
    assert forecast_spend(400, "invest") == 500
    assert forecast_spend(200, "hold") == 200
    assert forecast_spend(640, "retire") == 0
    assert forecast_spend(10, "review") == 10


def test_catalog_cost_labels_and_rollup():
    labels = {row["agent"]: row["recommendation"] for row in cost_rows()}
    assert labels == {
        "Loan document reader": "invest",
        "Rate sheet assistant": "hold",
        "Collections outreach": "hold",
        "Loss model explainer": "invest",
        "Policy drafter": "retire",
        "Ops copilot": "retire",
    }
    measured = evaluate()
    assert measured["spend"] == 5340 and measured["assisted_value"] == 9260
    assert measured["invest"] == 2 and measured["hold"] == 2 and measured["retire"] == 2
    assert measured["next_spend"] == 2975
    assert measured["score_before"] == 60 and measured["score_after"] == 75
    assert measured["nothing_written"] and measured["user_access_unchanged"] and measured["responses_used"]


def test_report_names_every_platform_and_the_verify_marker():
    text = agent365.report()
    for key, _name in agent365.PLATFORMS:
        assert key in text
    assert "[verify]" in text
    assert "Ops copilot (after signal)" in text
    assert "unchanged" in text
    assert all(isinstance(item, Decision) for item in demo_decisions())


def test_custom_agent_on_a_supported_platform_can_be_issued():
    agent = ExternalAgent("google", "gx-extra", "Extra assistant", "kai.thompson@kestrelridge.example", ("read-rates",))
    ident = issue(agent)
    assert ident.platform == "google" and ident.stored_secrets == 0
    assert ident.entra_agent_id not in {item.entra_agent_id for item in registry()}
    assert risk_for(ident).score == 0
    assert decide(ident, action("read")).response == "allow"


def test_unknown_sponsor_is_not_written_as_an_email_id():
    ident = issue(ExternalAgent("google", "gx-stranger", "Stranger", "nobody@kestrelridge.example", ("read-rates",)))
    with pytest.raises(RegistryError):
        agent365.as_service_principal(ident)
