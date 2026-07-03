"""Layer 1 — Static metadata analysis.

Runs at *ingestion* time, before any tool is exposed to the agent. It scans the
tool descriptor (name, description, input schema) for the tell-tale signatures
of tool poisoning and prompt injection: imperative overrides, hidden directives,
requests to read secrets or rewrite config, command-injection payloads,
exfiltration instructions, and invisible-unicode smuggling.

This is the cheap, deterministic first line of defense — the equivalent of a
signature scanner running before the file is ever opened.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List

from warden.core.models import AttackCategory, Finding, Severity, ToolDescriptor
from warden.detectors.base import Detector, DetectorContext, Rule, find_hidden_unicode

# Long base64-ish tokens are a common way to smuggle a payload past keyword
# scanners. We decode them and re-scan the plaintext.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

_CVE_MCPOISON = "CVE-2025-54136"
_CVE_CURXECUTE = "CVE-2025-54135"


class StaticMetadataAnalyzer(Detector):
    """Pattern-based scanner for poisoned tool descriptors."""

    name = "static_metadata"

    # Rules are ordered high-to-low importance; all matching rules fire.
    RULES: List[Rule] = [
        Rule.make(
            "static.imperative_override",
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(all\s+)?(previous|prior|above|earlier|your)\b"
            r"[^.\n]{0,20}\b(instruction|prompt|rule|context|system)",
            Severity.CRITICAL,
            AttackCategory.TOOL_POISONING,
            "Descriptor tries to override the agent's prior instructions.",
            cve=_CVE_MCPOISON,
        ),
        Rule.make(
            "static.hidden_directive",
            r"do\s+not\s+(tell|mention|inform|reveal|notify)\s+(the\s+)?(user|human|operator)"
            r"|without\s+(telling|informing|notifying)\s+the\s+user"
            r"|(don't|do not)\s+(show|display)\s+this\s+to\s+the\s+user",
            Severity.HIGH,
            AttackCategory.TOOL_POISONING,
            "Descriptor instructs the agent to hide behavior from the user.",
        ),
        Rule.make(
            "static.role_confusion",
            r"(^|\n)\s*(system|assistant|developer)\s*:|<\s*system\s*>|\[\s*system\s*\]|you\s+are\s+now\b",
            Severity.HIGH,
            AttackCategory.PROMPT_INJECTION,
            "Descriptor injects a fake system/role turn to hijack context.",
        ),
        Rule.make(
            "static.sensitive_file_read",
            r"(~/?\.ssh|id_rsa|/etc/(passwd|shadow)|\.aws/credentials|\.env\b|"
            r"secret|api[_-]?key|private\s+key|password)",
            Severity.HIGH,
            AttackCategory.TOOL_POISONING,
            "Descriptor references reading secrets or credential files.",
        ),
        Rule.make(
            "static.config_write",
            r"(\.cursor[\\/]?(rules[\\/])?mcp\.json|mcp\.json|settings\.json|"
            r"\.vscode[\\/]|add\s+(an?\s+)?mcp\s+server|modify\s+.{0,20}config)",
            Severity.HIGH,
            AttackCategory.PRIVILEGE_ESCALATION,
            "Descriptor references rewriting agent/editor configuration.",
            cve=_CVE_CURXECUTE,
        ),
        Rule.make(
            "static.command_injection",
            r"(;\s*rm\s+-rf|\$\(|`[^`]+`|curl\s+[^\n|]+\|\s*(sh|bash)|bash\s+-c|"
            r"powershell|cmd\.exe|calc\.exe|/dev/tcp/|nc\s+-e|reverse\s+shell)",
            Severity.CRITICAL,
            AttackCategory.TOOL_POISONING,
            "Descriptor embeds shell/command-injection payload.",
            cve=_CVE_MCPOISON,
        ),
        Rule.make(
            "static.exfiltration",
            r"(?:send|post|upload|forward|exfiltrat|transmit|leak|upl)\w*[^.\n]{0,40}"
            r"(?:to\s+)?(?:https?://|external|attacker|webhook|endpoint|collector)",
            Severity.HIGH,
            AttackCategory.DATA_EXFILTRATION,
            "Descriptor instructs sending data to an external destination.",
        ),
        Rule.make(
            "static.tool_shadowing",
            r"(before|instead\s+of|when|after)\s+(using|calling|invoking)\s+[^.\n]{0,30}\btool\b"
            r"|override\s+the\s+\w+\s+tool",
            Severity.MEDIUM,
            AttackCategory.TOOL_POISONING,
            "Descriptor tries to shadow or reroute another tool's behavior.",
        ),
    ]

    def _scan_encoded(self, text: str) -> List[Finding]:
        """Decode long base64 tokens and re-scan the plaintext for payloads."""

        findings: List[Finding] = []
        for token in _B64_TOKEN.findall(text):
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                continue
            if len(decoded) < 6:
                continue
            inner = self._apply_rules(decoded, self.RULES)
            if inner:
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id="static.encoded_payload",
                        severity=Severity.HIGH,
                        message=(
                            "Descriptor hides a payload inside a base64 blob that "
                            "decodes to a poisoning instruction."
                        ),
                        evidence=f"decoded: {decoded[:60]}",
                        category=AttackCategory.TOOL_POISONING,
                    )
                )
                break
        return findings

    def inspect_descriptor(
        self, descriptor: ToolDescriptor, ctx: DetectorContext
    ) -> List[Finding]:
        text = descriptor.searchable_text
        findings = self._apply_rules(text, self.RULES)

        # Encoded-payload evasion: decode long base64 tokens and re-scan.
        findings.extend(self._scan_encoded(text))

        # Invisible-unicode smuggling isn't a regex; check it structurally.
        hidden = find_hidden_unicode(text)
        if hidden:
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="static.hidden_unicode",
                    severity=Severity.HIGH,
                    message=(
                        "Descriptor contains invisible/zero-width characters used "
                        "to smuggle hidden instructions."
                    ),
                    evidence=", ".join(sorted(set(hidden))[:5]),
                    category=AttackCategory.TOOL_POISONING,
                )
            )
        return findings
