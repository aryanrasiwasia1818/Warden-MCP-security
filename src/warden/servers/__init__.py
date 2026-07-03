"""MCP-style demo servers: a vulnerable one and a Warden-hardened one.

These faithfully model the MCP tool shape (descriptors + a call dispatcher) so
the same objects flow through Warden as would come from a real MCP server. A
thin adapter over the official ``mcp`` package could replace ``MCPServer``
without touching the guardrail — see the README's "real MCP" note.
"""

from warden.servers.mcp_server import MCPServer, ToolSpec
from warden.servers.hardened_server import HardenedServer, build_hardened_server
from warden.servers.vulnerable_server import build_vulnerable_server

__all__ = [
    "MCPServer",
    "ToolSpec",
    "HardenedServer",
    "build_hardened_server",
    "build_vulnerable_server",
]
