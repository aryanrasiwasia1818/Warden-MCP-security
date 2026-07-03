"""A minimal MCP-shaped server abstraction.

A server advertises tool *descriptors* and dispatches *calls* to Python
implementations. This mirrors the essential MCP contract (``tools/list`` +
``tools/call``) without requiring a live transport, so demos and the benchmark
run instantly and offline.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from warden.core.models import ToolCall, ToolDescriptor, ToolResult

ToolImpl = Callable[[ToolCall], ToolResult]


@dataclass
class ToolSpec:
    """A descriptor paired with its implementation."""

    descriptor: ToolDescriptor
    impl: ToolImpl


class MCPServer:
    """Holds tool specs and dispatches calls — the "server" under test."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._specs: Dict[str, ToolSpec] = {}

    def add_tool(self, descriptor: ToolDescriptor, impl: ToolImpl) -> None:
        # Ensure the descriptor's server field reflects this server.
        descriptor = ToolDescriptor(
            name=descriptor.name,
            description=descriptor.description,
            input_schema=descriptor.input_schema,
            server=self.name,
        )
        self._specs[descriptor.name] = ToolSpec(descriptor=descriptor, impl=impl)

    def list_tools(self) -> List[ToolDescriptor]:
        return [spec.descriptor for spec in self._specs.values()]

    def run(self, call: ToolCall) -> ToolResult:
        spec = self._specs.get(call.tool_name)
        if spec is None:
            return ToolResult(
                tool_name=call.tool_name,
                content=f"error: unknown tool '{call.tool_name}'",
                is_error=True,
                session_id=call.session_id,
            )
        return spec.impl(call)
