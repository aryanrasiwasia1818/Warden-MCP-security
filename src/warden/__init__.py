"""Warden — a security guardrail and red-team benchmark for MCP agents.

Warden implements the multi-layer defense the MCP-security literature recommends
(static metadata analysis, provenance/integrity tracking, output-injection
detection, behavioral anomaly detection), enforces least-privilege permissions,
executes tools in a sandbox, keeps a tamper-evident audit ledger, and quantifies
all of it against a red-team corpus mapped to real 2025 CVEs.

Public API:
    from warden import WardenGuardrail, Policy
"""

from warden.core.models import (
    Decision,
    Finding,
    Severity,
    ToolCall,
    ToolDescriptor,
    ToolResult,
    Verdict,
)
from warden.core.policy import Policy
from warden.engine.guardrail import WardenGuardrail

__all__ = [
    "WardenGuardrail",
    "Policy",
    "ToolDescriptor",
    "ToolCall",
    "ToolResult",
    "Finding",
    "Verdict",
    "Decision",
    "Severity",
    "__version__",
]

__version__ = "0.1.0"
