"""A Warden-hardened wrapper around any MCP server.

``HardenedServer`` is a drop-in that puts the guardrail between the agent and a
server: it ingests every advertised tool (dropping any that fail the descriptor
scan) and routes every call through :meth:`WardenGuardrail.guard_call`. This is
the "middleware" pattern — the agent's call/response shape is unchanged, but the
guardrail now mediates it.
"""

from __future__ import annotations

from typing import List, Optional

from warden.core.models import Decision, ToolCall, ToolResult
from warden.core.policy import Policy
from warden.engine.guardrail import WardenGuardrail
from warden.servers.mcp_server import MCPServer
from warden.servers.vulnerable_server import build_vulnerable_server


class HardenedServer:
    """Wraps an MCPServer with a WardenGuardrail."""

    def __init__(self, server: MCPServer, guardrail: Optional[WardenGuardrail] = None) -> None:
        self.server = server
        self.guardrail = guardrail or WardenGuardrail()
        # Ingest all advertised tools; poisoned descriptors get blocked here.
        self.ingest_verdicts = self.guardrail.register_tools(server.list_tools())

    @property
    def exposed_tools(self) -> List[str]:
        """Only tools that survived descriptor scanning are callable."""

        return self.guardrail.exposed_tools

    @property
    def rejected_tools(self) -> List[str]:
        exposed = set(self.exposed_tools)
        return [d.name for d in self.server.list_tools() if d.name not in exposed]

    def run(self, call: ToolCall) -> Decision:
        """Guarded call: refuses tools that were never exposed, else mediates."""

        if call.tool_name not in self.guardrail.exposed_tools:
            # Never expose a tool that failed ingestion.
            from warden.core.models import DecisionType, Verdict
            from warden.core.models import Finding, Severity, AttackCategory

            v = Verdict(subject=f"call:{call.tool_name}")
            v.add(
                Finding(
                    detector="hardened_server",
                    rule_id="server.tool_not_exposed",
                    severity=Severity.HIGH,
                    message=f"Tool '{call.tool_name}' is not exposed (failed ingestion).",
                    category=AttackCategory.TOOL_POISONING,
                )
            )
            v.decide(self.guardrail.policy.block_at, self.guardrail.policy.flag_at)
            return Decision(subject=v.subject, decision=DecisionType.BLOCK, verdicts=[v])

        return self.guardrail.guard_call(call, runner=self.server.run)


def build_hardened_server(policy: Optional[Policy] = None) -> HardenedServer:
    """Convenience: the vulnerable demo server, wrapped by Warden."""

    guardrail = WardenGuardrail(policy or Policy.default())
    return HardenedServer(build_vulnerable_server(), guardrail)
