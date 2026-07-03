"""Detector contract + shared text-analysis helpers.

Design: a detector implements only the hooks relevant to its stage
(*ingest* a descriptor, *pre-call* a tool call, *post-call* a result). The base
class provides no-op defaults so every detector stays focused and small — the
classic "hook method" pattern. This keeps each layer independently testable and
makes adding a new defense layer a matter of subclassing.
"""

from __future__ import annotations

import re
import time
import unicodedata
from abc import ABC
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from warden.core.models import (
    AttackCategory,
    Finding,
    Severity,
    ToolCall,
    ToolDescriptor,
    ToolResult,
)

# Characters abused to smuggle hidden instructions into tool metadata/output:
# zero-width spaces/joiners, BOM, bidi overrides, and the Unicode "tag" block
# (U+E0000–U+E007F) used for invisible ASCII smuggling.
_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
}


def find_hidden_unicode(text: str) -> List[str]:
    """Return human-readable names of any hidden/invisible codepoints present."""

    hits: List[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE_CODEPOINTS or 0xE0000 <= cp <= 0xE007F:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = f"U+{cp:04X}"
            hits.append(name)
    return hits


@dataclass(frozen=True)
class Rule:
    """A compiled pattern rule used by the regex-based detectors."""

    rule_id: str
    pattern: "re.Pattern[str]"
    severity: Severity
    category: AttackCategory
    message: str
    cve: Optional[str] = None

    @classmethod
    def make(
        cls,
        rule_id: str,
        pattern: str,
        severity: Severity,
        category: AttackCategory,
        message: str,
        cve: Optional[str] = None,
    ) -> "Rule":
        return cls(
            rule_id=rule_id,
            pattern=re.compile(pattern, re.IGNORECASE | re.DOTALL),
            severity=severity,
            category=category,
            message=message,
            cve=cve,
        )


def _excerpt(text: str, match: "re.Match[str]", width: int = 48) -> str:
    """Return a short, safe excerpt around a regex match for the finding evidence."""

    start = max(match.start() - width // 2, 0)
    end = min(match.end() + width // 2, len(text))
    snippet = text[start:end].replace("\n", " ").strip()
    return f"…{snippet}…" if start > 0 or end < len(text) else snippet


@dataclass
class DetectorContext:
    """Shared, per-evaluation context passed to every detector hook."""

    policy: Any                     # warden.core.policy.Policy (avoids import cycle)
    session_id: str = "default"
    now: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    """Base class for all detection layers.

    Subclasses set :attr:`name` and override whichever ``inspect_*`` hooks apply
    to their stage. Unused hooks return an empty list by default.
    """

    #: Stable identifier used in policy config and reports.
    name: str = "detector"

    def configure(self, config: Dict[str, Any]) -> None:
        """Apply detector-specific configuration from the policy. Optional."""

    # -- stage hooks (override the ones you need) ------------------------- #
    def inspect_descriptor(
        self, descriptor: ToolDescriptor, ctx: DetectorContext
    ) -> List[Finding]:
        return []

    def inspect_call(self, call: ToolCall, ctx: DetectorContext) -> List[Finding]:
        return []

    def inspect_result(self, result: ToolResult, ctx: DetectorContext) -> List[Finding]:
        return []

    # -- helpers for subclasses ------------------------------------------ #
    def _apply_rules(self, text: str, rules: List[Rule]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in rules:
            match = rule.pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=rule.message,
                        evidence=_excerpt(text, match),
                        category=rule.category,
                        cve=rule.cve,
                    )
                )
        return findings
