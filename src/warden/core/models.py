"""Core domain models for Warden.

These immutable-ish dataclasses are the vocabulary the whole system speaks:
descriptors are *ingested*, calls are *evaluated*, detectors emit *findings*,
and the guardrail returns a *verdict* carrying a *decision*.

Everything is plain-stdlib so Warden has no heavy runtime dependencies.
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Severity(enum.IntEnum):
    """Ordered severity so findings can be compared and thresholded.

    IntEnum (not Enum) is deliberate: it lets us write ``finding.severity >=
    Severity.HIGH`` and sort findings without custom comparators.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class DecisionType(enum.Enum):
    """The three outcomes a guardrail can reach for a given evaluation."""

    ALLOW = "allow"      # nothing suspicious; proceed
    FLAG = "flag"        # suspicious but not blocking; proceed + record
    BLOCK = "block"      # unsafe; refuse the action

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class AttackCategory(str, enum.Enum):
    """Taxonomy of MCP attack classes Warden defends against.

    Values double as human-readable labels in reports.
    """

    TOOL_POISONING = "tool_poisoning"
    PROMPT_INJECTION = "prompt_injection"
    DESCRIPTOR_TAMPERING = "descriptor_tampering"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    BENIGN = "benign"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding used for content hashing.

    Sorting keys makes the hash stable regardless of dict ordering, which is
    what lets provenance detect *content* drift rather than key reordering.
    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# MCP-shaped models
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ToolDescriptor:
    """A tool advertised by an MCP server.

    Mirrors the MCP tool shape (``name`` / ``description`` / ``inputSchema``).
    The ``content_hash`` is the anchor for provenance/integrity: it binds trust
    to the *content* of the descriptor rather than to its name — precisely the
    gap exploited by MCPoison (CVE-2025-54136).
    """

    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    server: str = "unknown"

    @property
    def content_hash(self) -> str:
        """Stable SHA-256 over the fields that define behavior/intent."""

        payload = _canonical_json(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            }
        )
        return _sha256(payload)

    @property
    def searchable_text(self) -> str:
        """All human/LLM-visible text a static analyzer should inspect."""

        return "\n".join(
            [self.name, self.description, _canonical_json(self.input_schema)]
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any], server: str = "unknown") -> "ToolDescriptor":
        """Build from an MCP-style dict (accepts ``inputSchema`` or ``input_schema``)."""

        return cls(
            name=str(data.get("name", "")),
            description=str(data.get("description", "")),
            input_schema=dict(data.get("inputSchema") or data.get("input_schema") or {}),
            server=str(data.get("server", server)),
        )


@dataclass(frozen=True)
class ToolCall:
    """A request from an agent to invoke a tool with arguments."""

    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    session_id: str = "default"
    caller: str = "agent"
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    @property
    def searchable_text(self) -> str:
        return _canonical_json(self.arguments)


@dataclass(frozen=True)
class ToolResult:
    """The output returned by a tool. This is *untrusted external data*.

    CurXecute (CVE-2025-54135) showed that instructions hidden in tool output
    can redirect an agent's control flow — so results are scanned, not trusted.
    """

    tool_name: str
    content: str = ""
    is_error: bool = False
    session_id: str = "default"

    @property
    def searchable_text(self) -> str:
        return self.content


# --------------------------------------------------------------------------- #
# Detection results
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Finding:
    """A single piece of evidence produced by a detector.

    ``cve`` optionally ties the finding to the real-world vulnerability class it
    corresponds to, which powers the per-CVE benchmark breakdown.
    """

    detector: str
    rule_id: str
    severity: Severity
    message: str
    evidence: str = ""
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    cve: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "message": self.message,
            "evidence": self.evidence,
            "category": self.category.value,
            "cve": self.cve,
        }


@dataclass
class Verdict:
    """Aggregate result of evaluating one artifact (descriptor, call, or result).

    The decision is derived from findings via :meth:`decide`, comparing the
    highest-severity finding against the policy's block/flag thresholds.
    """

    subject: str                       # what was evaluated, e.g. "tool:get_weather"
    findings: List[Finding] = field(default_factory=list)
    decision: DecisionType = DecisionType.ALLOW
    reasons: List[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def blocked(self) -> bool:
        return self.decision is DecisionType.BLOCK

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def merge(self, other: "Verdict") -> None:
        """Fold another verdict's findings into this one (decision recomputed later)."""

        self.findings.extend(other.findings)

    def decide(self, block_at: Severity, flag_at: Severity) -> "Verdict":
        """Resolve the final decision from findings and thresholds."""

        top = self.max_severity
        if self.findings and top >= block_at:
            self.decision = DecisionType.BLOCK
        elif self.findings and top >= flag_at:
            self.decision = DecisionType.FLAG
        else:
            self.decision = DecisionType.ALLOW

        self.reasons = [
            f"[{f.severity}] {f.detector}:{f.rule_id} — {f.message}"
            for f in sorted(self.findings, key=lambda x: x.severity, reverse=True)
        ]
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "decision": str(self.decision),
            "max_severity": str(self.max_severity),
            "findings": [f.to_dict() for f in self.findings],
            "reasons": self.reasons,
        }


@dataclass
class Decision:
    """The guardrail's end-to-end answer for a single tool call.

    Bundles the per-stage verdicts (descriptor scan, permission check, output
    scan, behavioral check) plus the final decision the agent must honor.
    """

    subject: str
    decision: DecisionType
    verdicts: List[Verdict] = field(default_factory=list)
    result: Optional[ToolResult] = None

    @property
    def allowed(self) -> bool:
        return self.decision is not DecisionType.BLOCK

    @property
    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for v in self.verdicts:
            out.extend(v.findings)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "decision": str(self.decision),
            "verdicts": [v.to_dict() for v in self.verdicts],
            "result": None if self.result is None else {
                "tool_name": self.result.tool_name,
                "content": self.result.content,
                "is_error": self.result.is_error,
            },
        }
