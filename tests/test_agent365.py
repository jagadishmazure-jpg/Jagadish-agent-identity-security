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
    decision = decide(ident, risk_for(ident, follow_up=follow), operation, tool, on_behalf_of="person@kestrelridge.example")
    assert decision.response == response and decision.risk_level == level
    assert decision.evaluated_at == "action" and decision.user_access == "unchanged"
    assert decision.ca_style


def test_a_sensitive_tool_stays_sensitive_on_a_read():
    ident = issue(CATALOG[5])
    decision = decide(ident, risk_for(ident), "read", "role-assign")
    assert decision.sensitivity == "sensitive" and decision.response == "block"


def test_sign_in_alone_is_not_a_decision_point():
    ident = issue(LOAN)
    with pytest.raises(RegistryError):
        decide(ident, risk_for(ident), "read", when="sign_in")


def test_risk_from_another_agent_is_refused():
    first, second = registry()[:2]
    with pytest.raises(RegistryError):
        decide(first, risk_for(second), "read")


def test_outcomes_leave_the_person_alone_and_write_nothing():
    for decision in demo_decisions():
        result = agent365.outcome(decision)
        assert result["user"] == "unchanged" and result["written_to_tenant"] is False
        assert result["agent"] in {"proceed", "proceed_reduced", "held", "denied"}
        assert "human access left as-is" in decision.reason
        if decision.response == "block":
            assert result["agent"] == "denied"


@pytest.mark.parametrize(
    ("spend", "value", "success", "sessions", "want"),
    [
        (100, 300, 80, 5, "invest"),
        (100, 300, 79, 5, "hold"),
        (100, 100, 50, 1, "hold"),
        (100, 99, 90, 10, "retire"),
        (100, 99, 90, 9, "review"),
        (0, 10, 100, 10, "review"),
    ],
)
def test_recommend_boundaries(spend, value, success, sessions, want):
    assert recommend(spend, value, success, sessions) == want


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
