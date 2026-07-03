"""Layer 3a — Output-injection detection (defends CurXecute, CVE-2025-54135).

CurXecute chained an *indirect* prompt injection: untrusted data returned by a
tool (e.g. a Slack message surfaced through an MCP server) contained
instructions that rewrote the agent's MCP config and triggered RCE — before the
user could reject the edit.

The lesson: **tool output is untrusted external data**. This detector scans
every result for instructions that try to steer the agent, rewrite config,
request command execution, or exfiltrate data.
"""

from __future__ import annotations

from typing import List

from warden.core.models import AttackCategory, Finding, Severity, ToolResult
from warden.detectors.base import Detector, DetectorContext, Rule, find_hidden_unicode

_CVE_CURXECUTE = "CVE-2025-54135"


class OutputInjectionDetector(Detector):
    """Scans untrusted tool output for injected agent-directed instructions."""

    name = "output_injection"

    RULES: List[Rule] = [
        Rule.make(
            "output.instruction_injection",
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|your)\b"
            r"[^.\n]{0,20}\b(instruction|prompt|rule|context)"
            r"|\bnew\s+instructions?\s*:"
            r"|\b(you\s+must\s+now|from\s+now\s+on\s+you)\b",
            Severity.CRITICAL,
            AttackCategory.PROMPT_INJECTION,
            "Tool output contains instructions aimed at hijacking the agent.",
            cve=_CVE_CURXECUTE,
        ),
        Rule.make(
            "output.config_write_request",
            r"(\.cursor[\\/]?(rules[\\/])?mcp\.json|\bmcp\.json\b|settings\.json|"
            r"add\s+(an?\s+)?mcp\s+server|edit\s+.{0,20}config|write\s+.{0,20}config)",
            Severity.CRITICAL,
            AttackCategory.PRIVILEGE_ESCALATION,
            "Tool output asks the agent to modify MCP/editor configuration.",
            cve=_CVE_CURXECUTE,
        ),
        Rule.make(
            "output.command_request",
            r"(run|execute|invoke)\b[^.\n]{0,30}(command|shell|script|`[^`]+`)"
            r"|\b(bash|sh|powershell|cmd)\s+-|\bcurl\s+[^\n|]+\|\s*(sh|bash)|/dev/tcp/",
            Severity.HIGH,
            AttackCategory.TOOL_POISONING,
            "Tool output asks the agent to run a shell command.",
        ),
        Rule.make(
            "output.exfiltration_request",
            r"(send|post|upload|forward|email|leak)\b[^.\n]{0,40}"
            r"(to\s+)?(https?://|attacker|webhook|external\s+server|@)",
            Severity.HIGH,
            AttackCategory.DATA_EXFILTRATION,
            "Tool output asks the agent to send data to an external destination.",
        ),
        Rule.make(
            "output.tool_redirection",
            r"(now|then|next)\s+(call|use|invoke)\s+the\s+\w+\s+tool"
            r"|call\s+\w+\s+with\s+the\s+argument",
            Severity.MEDIUM,
            AttackCategory.PROMPT_INJECTION,
            "Tool output tries to redirect the agent to another tool.",
        ),
    ]

    def inspect_result(self, result: ToolResult, ctx: DetectorContext) -> List[Finding]:
        text = result.searchable_text
        findings = self._apply_rules(text, self.RULES)

        hidden = find_hidden_unicode(text)
        if hidden:
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="output.hidden_unicode",
                    severity=Severity.HIGH,
                    message=(
                        "Tool output contains invisible/zero-width characters "
                        "used to smuggle hidden instructions."
                    ),
                    evidence=", ".join(sorted(set(hidden))[:5]),
                    category=AttackCategory.PROMPT_INJECTION,
                )
            )
        return findings
