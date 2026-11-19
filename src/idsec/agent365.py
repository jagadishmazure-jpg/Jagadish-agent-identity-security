"""Connected-platform Entra Agent IDs, dynamic agent risk and a cost/value report.

Offline model of three ideas from the Agent 365 Ignite announcement: agents built on other platforms
can receive their own Entra Agent ID, a risk level is recomputed from behaviour signals, and spend is
compared with value. Nothing is called over the network and nothing is written to a tenant.

Weights, level cuts, Conditional Access control names, which platforms support secretless federation,
and the product's forecast method are a local model. The docs mark those preview details [verify].
"""

from __future__ import annotations

from dataclasses import dataclass

PLATFORMS = (
    ("bedrock", "Amazon Bedrock"),
    ("google", "Google"),
    ("salesforce", "Salesforce"),
    ("databricks", "Databricks"),
    ("anthropic", "Anthropic"),
    ("openai", "OpenAI"),
)

# Fixed weights. Callers cannot supply their own: assess() rejects a reweighted signal.
SIGNAL_KINDS = {
    "ownerless": 25,
    "new_credential": 15,
    "privilege_expansion": 20,
    "sensitive_tool": 15,
    "sensitive_data": 20,
    "unusual_endpoint": 10,
    "anomalous_cloud_call": 15,
    "unexpected_network": 15,
    "high_blast_radius": 20,
    "became_target": 25,
    "code_or_model_update": 10,
}

SIGNAL_DETAIL = {
    "ownerless": "no active sponsor on the agent identity",
    "new_credential": "a new credential appeared on the identity",
    "privilege_expansion": "the agent gained a broader role or permission",
    "sensitive_tool": "the agent called a sensitive tool",
    "sensitive_data": "the agent read or wrote sensitive data",
    "unusual_endpoint": "the agent ran from an unusual device",
    "anomalous_cloud_call": "the agent called an unusual cloud API",
    "unexpected_network": "the agent contacted an unapproved destination",
    "high_blast_radius": "the agent can reach many resources",
    "became_target": "the agent was targeted",
    "code_or_model_update": "the agent's code or model changed",
}

# Level cuts: 0-24 low, 25-49 medium, 50-74 high, 75-100 critical.
SENSITIVE_TOOLS = frozenset({"send-email", "sql-warehouse", "unity-catalog", "role-assign"})

# (level, sensitivity) -> response. High routine work continues in a reduced form; sensitive work does not.
RESPONSES = {
    ("low", "routine"): "allow",
    ("low", "sensitive"): "allow",
    ("medium", "routine"): "allow",
    ("medium", "sensitive"): "require_approval",
    ("high", "routine"): "restrict",
    ("high", "sensitive"): "block",
    ("critical", "routine"): "block",
    ("critical", "sensitive"): "block",
}

CA_STYLE = {
    "allow": "grant allow",
    "require_approval": "grant require human approval",
    "restrict": "session reduced access",
    "block": "grant block",
}

_EFFECT = {
    "allow": "proceed",
    "restrict": "proceed_reduced",
    "require_approval": "held",
    "block": "denied",
}


class RegistryError(ValueError):
    """A connection or an identity the registry will not issue."""


@dataclass(frozen=True)
class ExternalAgent:
    platform: str
    external_id: str
    name: str
    owner: str
    tools: tuple[str, ...]


@dataclass(frozen=True)
class IssuedIdentity:
    entra_agent_id: str
    platform: str
    external_id: str
    name: str
    sponsors: tuple[str, ...]
    tools: tuple[str, ...]
    app_id: str
    blueprint_id: str
    auth: str
    stored_secrets: int


@dataclass(frozen=True)
class Signal:
    kind: str
    detail: str
    weight: int


@dataclass(frozen=True)
class Risk:
    entra_agent_id: str
    score: int
    level: str
    signals: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    entra_agent_id: str
    agent: str
    operation: str
    sensitivity: str
    risk_level: str
    risk_score: int
    response: str
    ca_style: str
    evaluated_at: str
    on_behalf_of: str
    user_access: str
    reason: str


@dataclass(frozen=True)
class Usage:
    sessions: int
    spend_usd: int
    assisted_hours: int
    assisted_value_usd: int
    success_pct: int
    satisfaction_pct: int


# One fictional agent per platform. Owners are people in the synthetic tenant; an empty owner is unsponsored.
CATALOG = (
    ExternalAgent("bedrock", "br-loan-reader", "Loan document reader", "ava.chen@kestrelridge.example", ("read-blob", "extract-fields")),
    ExternalAgent("google", "gx-rate-sheet", "Rate sheet assistant", "kai.thompson@kestrelridge.example", ("read-rates",)),
    ExternalAgent("salesforce", "sf-collections", "Collections outreach", "priya.nair@kestrelridge.example", ("crm-read", "send-email")),
    ExternalAgent("databricks", "db-loss-model", "Loss model explainer", "ava.chen@kestrelridge.example", ("sql-warehouse", "unity-catalog")),
    ExternalAgent("anthropic", "an-policy-draft", "Policy drafter", "", ("draft-doc",)),
    ExternalAgent("openai", "oa-ops-copilot", "Ops copilot", "marcus.reid@kestrelridge.example", ("ticket-read", "role-assign")),
)

OBSERVATIONS: dict[str, tuple[str, ...]] = {
    "br-loan-reader": ("code_or_model_update",),
    "gx-rate-sheet": (),
    "sf-collections": ("sensitive_data", "unexpected_network"),
    "db-loss-model": ("sensitive_data", "high_blast_radius"),
    "an-policy-draft": (),
    "oa-ops-copilot": ("sensitive_tool", "privilege_expansion", "became_target"),
}

FOLLOW_UP: dict[str, tuple[str, ...]] = {
    "oa-ops-copilot": ("anomalous_cloud_call",),
}

USAGE = {
    "br-loan-reader": Usage(820, 400, 310, 1600, 91, 88),
    "gx-rate-sheet": Usage(210, 200, 40, 280, 74, 66),
    "sf-collections": Usage(1400, 900, 500, 2100, 82, 77),
    "db-loss-model": Usage(90, 1100, 60, 4400, 90, 84),
    "an-policy-draft": Usage(48, 640, 15, 180, 41, 38),
    "oa-ops-copilot": Usage(260, 2100, 80, 700, 52, 40),
}

# Actions the report walks, in order. follow_up uses the extra signal when one is defined.
DEMO_ACTIONS = (
    ("br-loan-reader", "read", "", "ava.chen@kestrelridge.example", False),
    ("gx-rate-sheet", "read", "", "", False),
    ("sf-collections", "tool", "send-email", "priya.nair@kestrelridge.example", False),
    ("db-loss-model", "tool", "sql-warehouse", "", False),
    ("an-policy-draft", "read", "", "", False),
    ("an-policy-draft", "write", "", "", False),
    ("oa-ops-copilot", "tool", "role-assign", "marcus.reid@kestrelridge.example", False),
    ("oa-ops-copilot", "read", "", "marcus.reid@kestrelridge.example", False),
    ("oa-ops-copilot", "read", "", "marcus.reid@kestrelridge.example", True),
)


def connect(platform: str, auth: str, secret: str = "") -> dict:
    """Register a platform. Stored secrets are refused; federation carries no long-lived key."""
    if platform not in {key for key, _name in PLATFORMS}:
        raise RegistryError(f"unsupported platform {platform}")
    if auth != "workload-identity-federation" or secret:
        raise RegistryError("refusing a stored secret; use workload identity federation")
    return {"platform": platform, "auth": auth, "stored_secrets": 0}


def issue(agent: ExternalAgent) -> IssuedIdentity:
    """Issue one Entra Agent ID for a third-party agent. The same agent always gets the same id."""
    connect(agent.platform, "workload-identity-federation")
    return IssuedIdentity(
        entra_agent_id=f"agentid-{agent.platform}-{agent.external_id}",
        platform=agent.platform,
        external_id=agent.external_id,
        name=agent.name,
        sponsors=(agent.owner,) if agent.owner else (),
        tools=agent.tools,
        app_id=f"app-{agent.platform}-{agent.external_id}",
        blueprint_id=f"blueprint-{agent.platform}",
        auth="workload-identity-federation",
        stored_secrets=0,
    )


def registry(agents: tuple[ExternalAgent, ...] = CATALOG) -> tuple[IssuedIdentity, ...]:
    issued = tuple(issue(agent) for agent in agents)
    ids = [item.entra_agent_id for item in issued]
    if len(ids) != len(set(ids)):
        raise RegistryError("two agents resolved to one Entra Agent ID")
    return issued


def as_blueprint(platform: str) -> dict:
    connect(platform, "workload-identity-federation")
    return {
        "@odata.type": "#microsoft.graph.agentIdentityBlueprint",
        "appId": f"blueprint-{platform}",
        "displayName": f"{platform} connected agents",
    }


def as_service_principal(ident: IssuedIdentity) -> dict:
    """Graph-shaped agentIdentity. inventory.py classifies this @odata.type as agent_identity."""
    return {
        "@odata.type": "#microsoft.graph.agentIdentity",
        "id": ident.entra_agent_id,
        "displayName": ident.name,
        "servicePrincipalType": "ServiceIdentity",
        "accountEnabled": True,
        "appId": ident.app_id,
        "agentIdentityBlueprintId": ident.blueprint_id,
        "sponsors": [{"@odata.type": "#microsoft.graph.user", "id": sponsor} for sponsor in ident.sponsors],
        "description": f"connected platform {ident.platform}; external id {ident.external_id}",
        "notes": "issued by the offline connected-platform registry; no stored secret",
    }


def make_signal(kind: str) -> Signal:
    if kind not in SIGNAL_KINDS:
        raise RegistryError(f"unknown signal {kind}")
    return Signal(kind, SIGNAL_DETAIL[kind], SIGNAL_KINDS[kind])


def level_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def assess(ident: IssuedIdentity, signals: tuple[Signal, ...]) -> Risk:
    """Sum behaviour signals into one score. An identity with no sponsor is ownerless, counted once."""
    seen: list[Signal] = []
    kinds: set[str] = set()
    for item in signals:
        if item.kind not in SIGNAL_KINDS or item.weight != SIGNAL_KINDS[item.kind]:
            raise RegistryError(f"unknown or reweighted signal {item.kind}")
        if item.kind in kinds:
            continue
        kinds.add(item.kind)
        seen.append(item)
    if not ident.sponsors and "ownerless" not in kinds:
        seen.append(make_signal("ownerless"))
    score = min(100, sum(item.weight for item in seen))
    return Risk(ident.entra_agent_id, score, level_for(score), tuple(item.kind for item in seen))


def risk_for(ident: IssuedIdentity, *, follow_up: bool = False) -> Risk:
    kinds = list(OBSERVATIONS[ident.external_id])
    if follow_up:
        kinds.extend(FOLLOW_UP.get(ident.external_id, ()))
    return assess(ident, tuple(make_signal(kind) for kind in kinds))


def decide(
    ident: IssuedIdentity,
    risk: Risk,
    operation: str,
    tool: str = "",
    *,
    on_behalf_of: str = "",
    when: str = "action",
) -> Decision:
    """Conditional-access style response at the point of action. The person's own access is not changed."""
    if when != "action":
        raise RegistryError("dynamic controls evaluate at the point of action, not only at sign-in")
    if risk.entra_agent_id != ident.entra_agent_id:
        raise RegistryError("risk was computed for a different agent")
    sensitivity = "sensitive" if operation == "write" or tool in SENSITIVE_TOOLS else "routine"
    response = RESPONSES[(risk.level, sensitivity)]
    shown = f"tool {tool}" if tool else operation
    return Decision(
        entra_agent_id=ident.entra_agent_id,
        agent=ident.name,
        operation=shown,
        sensitivity=sensitivity,
        risk_level=risk.level,
        risk_score=risk.score,
        response=response,
        ca_style=CA_STYLE[response],
        evaluated_at="action",
        on_behalf_of=on_behalf_of,
        user_access="unchanged",
        reason=f"risk {risk.level} ({risk.score}) on a {sensitivity} action; human access left as-is",
    )


def outcome(decision: Decision) -> dict:
    """What the response does to the agent. The user is never the subject, and nothing is written."""
    return {"agent": _EFFECT[decision.response], "user": decision.user_access, "written_to_tenant": False}


def recommend(spend: int, assisted_value: int, success_pct: int, sessions: int) -> str:
    """invest when value is at least 3x spend and success is at least 80; retire when value is below spend and use continues."""
    if spend <= 0:
        return "review"
    ratio = assisted_value / spend
    if ratio >= 3 and success_pct >= 80:
        return "invest"
    if ratio < 1 and sessions >= 10:
        return "retire"
    if ratio >= 1:
        return "hold"
    return "review"


def forecast_spend(spend: int, recommendation: str) -> int:
    """Local scenario, not a bill: invest grows by a quarter, retire goes to zero, otherwise flat."""
    if recommendation == "retire":
        return 0
    if recommendation == "invest":
        return spend * 5 // 4
    return spend


def _lookup() -> dict[str, IssuedIdentity]:
    return {item.external_id: item for item in registry()}


def demo_decisions() -> tuple[Decision, ...]:
    found = _lookup()
    out = []
    for external_id, operation, tool, on_behalf_of, follow_up in DEMO_ACTIONS:
        ident = found[external_id]
        out.append(decide(ident, risk_for(ident, follow_up=follow_up), operation, tool, on_behalf_of=on_behalf_of))
    return tuple(out)


def cost_rows() -> tuple[dict, ...]:
    rows = []
    for ident in registry():
        usage = USAGE[ident.external_id]
        label = recommend(usage.spend_usd, usage.assisted_value_usd, usage.success_pct, usage.sessions)
        ratio = "n/a" if usage.spend_usd <= 0 else f"{usage.assisted_value_usd / usage.spend_usd:.1f}"
        rows.append(
            {
                "agent": ident.name,
                "platform": ident.platform,
                "sessions": usage.sessions,
                "hours": usage.assisted_hours,
                "spend": usage.spend_usd,
                "value": usage.assisted_value_usd,
                "ratio": ratio,
                "success": f"{usage.success_pct / 100:.2f}",
                "satisfaction": f"{usage.satisfaction_pct / 100:.2f}",
                "recommendation": label,
                "next spend": forecast_spend(usage.spend_usd, label),
            }
        )
    return tuple(rows)


def evaluate() -> dict:
    issued = registry()
    ops = _lookup()["oa-ops-copilot"]
    before, after = risk_for(ops), risk_for(ops, follow_up=True)
    decisions = demo_decisions()
    rows = cost_rows()
    by_response = {item.response for item in decisions}

    def seen(response: str, level: str) -> bool:
        return any(item.response == response and item.risk_level == level for item in decisions)

    return {
        "platforms": len(PLATFORMS),
        "agents_issued": len(issued),
        "unique_ids": len({item.entra_agent_id for item in issued}),
        "stored_secrets": sum(item.stored_secrets for item in issued),
        "score_before": before.score,
        "score_after": after.score,
        "level_before": before.level,
        "level_after": after.level,
        "allowed_routine": seen("allow", "low"),
        "approval_for_medium_sensitive": seen("require_approval", "medium"),
        "restricted_high_routine": seen("restrict", "high"),
        "blocked_sensitive": seen("block", "high"),
        "blocked_after_signal": seen("block", "critical"),
        "responses_used": len(by_response) == 4,
        "user_access_unchanged": all(item.user_access == "unchanged" for item in decisions),
        "evaluated_at_action": all(item.evaluated_at == "action" for item in decisions),
        "nothing_written": all(not outcome(item)["written_to_tenant"] for item in decisions),
        "spend": sum(row["spend"] for row in rows),
        "assisted_value": sum(row["value"] for row in rows),
        "invest": sum(row["recommendation"] == "invest" for row in rows),
        "hold": sum(row["recommendation"] == "hold" for row in rows),
        "retire": sum(row["recommendation"] == "retire" for row in rows),
        "next_spend": sum(row["next spend"] for row in rows),
    }


def _table(rows: list[dict], cols: list[str]) -> list[str]:
    width = {col: max(len(col), *(len(str(row[col])) for row in rows)) for col in cols}
    lines = ["  ".join(col.ljust(width[col]) for col in cols).rstrip()]
    lines.append("  ".join("-" * width[col] for col in cols))
    lines += ["  ".join(str(row[col]).ljust(width[col]) for col in cols).rstrip() for row in rows]
    return lines


def report() -> str:
    issued = registry()
    lines = [
        "Connected-platform Entra Agent IDs (synthetic Kestrel Ridge Mortgage)",
        "Offline model of Agent 365 connected platforms, dynamic agent risk and cost against value.",
        "Preview product behaviour this model does not copy exactly is marked [verify] in the docs.",
        "",
        "Registry (one Entra Agent ID per third-party agent; stored secrets 0):",
    ]
    reg_rows = [
        {
            "platform": item.platform,
            "agent": item.name,
            "entra agent id": item.entra_agent_id,
            "sponsor": item.sponsors[0] if item.sponsors else "(none)",
            "secrets": item.stored_secrets,
        }
        for item in issued
    ]
    lines += _table(reg_rows, ["platform", "agent", "entra agent id", "sponsor", "secrets"])
    lines += ["", "Dynamic risk (baseline, then Ops copilot after one new cloud signal):"]
    risk_rows = []
    for item in issued:
        risk = risk_for(item)
        risk_rows.append({"agent": item.name, "score": risk.score, "level": risk.level, "signals": ", ".join(risk.signals) if risk.signals else "-"})
    ops = _lookup()["oa-ops-copilot"]
    later = risk_for(ops, follow_up=True)
    risk_rows.append({"agent": "Ops copilot (after signal)", "score": later.score, "level": later.level, "signals": ", ".join(later.signals)})
    lines += _table(risk_rows, ["agent", "score", "level", "signals"])
    lines += ["", "Access at the point of action (the person's own access stays unchanged):"]
    dec_rows = [
        {
            "agent": item.agent + (" (after signal)" if item.risk_level == "critical" else ""),
            "action": item.operation,
            "on behalf of": item.on_behalf_of or "-",
            "risk": f"{item.risk_level} {item.risk_score}",
            "response": item.response,
            "control": item.ca_style,
            "person": item.user_access,
        }
        for item in demo_decisions()
    ]
    lines += _table(dec_rows, ["agent", "action", "on behalf of", "risk", "response", "control", "person"])
    lines += ["", "Cost and value (dollars are the mock ledger, not a bill):"]
    rows = [dict(row) for row in cost_rows()]
    lines += _table(rows, ["agent", "sessions", "hours", "spend", "value", "ratio", "success", "satisfaction", "recommendation", "next spend"])
    measured = evaluate()
    lines += [
        "",
        f"spend {measured['spend']}  assisted value {measured['assisted_value']}  "
        f"next spend if recommendations are followed {measured['next_spend']}",
        f"invest {measured['invest']}  hold {measured['hold']}  retire {measured['retire']}",
        f"identities {measured['agents_issued']}  unique {measured['unique_ids']}  stored secrets {measured['stored_secrets']}",
        f"ops copilot risk {measured['score_before']} {measured['level_before']} -> {measured['score_after']} {measured['level_after']}",
    ]
    return "\n".join(lines)
