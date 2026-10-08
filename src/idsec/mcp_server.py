"""MCP server exposing the read-only identity tools (idsec.tools) for one scan.

Any MCP client (an Agent Framework agent, Copilot Studio, an IDE) can ask about findings, paths and
blast radius. Every tool is annotated read-only; there is no tool that approves or applies a
remediation, and tenant text in results is wrapped as untrusted data.

    idsec mcp          # stdio transport
    idsec mcp-demo     # scripted in-memory session
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from idsec import detections, inventory
from idsec import graph as gmod
from idsec.tools import IdentityTools

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def build_server(gateway: IdentityTools | None = None) -> MCPServer:
    if gateway is None:
        inv = inventory.load()
        g = gmod.build(inv)
        gateway = IdentityTools(inv, g, detections.run(inv, g))
    gw = gateway
    server = MCPServer("idsec-identity-posture")

    @server.tool(annotations=RO)
    def posture() -> dict[str, Any]:
        """Posture score per area (0-100) with finding counts."""
        return gw.posture()

    @server.tool(annotations=RO)
    def list_findings(severity: str = "", area: str = "", rule: str = "", limit: int = 20) -> list[dict[str, Any]]:
        """Findings filtered by severity, area or rule id."""
        return gw.list_findings(severity, area, rule, limit)

    @server.tool(annotations=RO)
    def get_finding(finding_id: str) -> dict[str, Any]:
        """One finding with evidence, explanation, fix and framework mappings."""
        return gw.get_finding(finding_id)

    @server.tool(annotations=RO)
    def paths_to(jewel: str = "entra-global-admin", limit: int = 5) -> dict[str, Any]:
        """Riskiest standing paths to a crown jewel."""
        return gw.paths_to(jewel, limit)

    @server.tool(annotations=RO)
    def blast_radius(identity: str) -> dict[str, Any]:
        """What one identity or agent can reach with standing access."""
        return gw.blast_radius(identity)

    @server.tool(annotations=RO)
    def describe_identity(identity: str) -> dict[str, Any]:
        """Kind, roles, owners and free-text fields (untrusted) of an identity or agent."""
        return gw.describe_identity(identity)

    @server.tool(annotations=RO)
    def explain_rule(rule_id: str) -> dict[str, Any]:
        """What a detection rule checks and how to fix it."""
        return gw.explain_rule(rule_id)

    server.gateway = gw  # type: ignore[attr-defined]
    return server


async def demo() -> list[str]:
    """Scripted session used by `idsec mcp-demo`."""
    from mcp import Client

    server = build_server()
    lines = []
    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        lines.append("tools: " + ", ".join(sorted(t.name for t in tools)))
        lines.append(f"all read-only: {all(t.annotations and t.annotations.read_only_hint for t in tools)}")
        p = (await client.call_tool("posture", {})).structured_content
        lines.append(f"overview score: {p['overview']['score']} ({p['overview']['grade']}), open findings {p['overview']['findings']}")
        crit = (await client.call_tool("list_findings", {"severity": "critical"})).structured_content["result"]
        lines.append(f"critical findings: {', '.join(f['id'] for f in crit)}")
        ga = (await client.call_tool("paths_to", {"jewel": "entra-global-admin", "limit": 1})).structured_content
        lines.append(f"sources with a standing path to Global Administrator: {ga['sources_with_a_path']}")
        d = (await client.call_tool("describe_identity", {"identity": "Harbor Backup Service"})).structured_content
        lines.append(
            f"Harbor Backup Service notes quoted as data: {d['notes'].startswith('<untrusted_data>')}; instruction-like phrases: {d['instruction_like_text']}"
        )
        bad = (await client.call_tool("get_finding", {"finding_id": "X99-99"})).structured_content
        lines.append(f"unknown finding: {bad.get('error')}")
    calls = server.gateway.calls  # type: ignore[attr-defined]
    lines.append(f"gateway calls recorded: {len(calls)} ({sum(not c.ok for c in calls)} not found)")
    return lines
