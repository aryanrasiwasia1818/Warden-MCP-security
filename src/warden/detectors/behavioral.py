"""Layer 3b — Behavioral anomaly detection.

Static analysis catches poisoned *content*; this catches anomalous *behavior*
at runtime by tracking the sequence of tool calls in a session. It flags:

* **Rate spikes** — a burst of calls far above the configured ceiling.
* **Tight loops** — the same tool + arguments hammered repeatedly (a common
  sign of an agent trapped by injected instructions).
* **Privilege escalation pattern** — a session that has only been reading data
  suddenly reaching for an execution-capable tool for the first time.

State is kept per session so concurrent sessions can't mask each other.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Tuple

from warden.core.models import AttackCategory, Finding, Severity, ToolCall
from warden.detectors.base import Detector, DetectorContext

# One history entry: (timestamp, tool_name, exec_capable, args_signature)
_Entry = Tuple[float, str, bool, str]


class BehavioralAnomalyDetector(Detector):
    """Stateful, per-session detector for anomalous tool-call patterns."""

    name = "behavioral"

    def __init__(
        self,
        *,
        max_calls_per_minute: int = 30,
        repetition_threshold: int = 5,
        escalation_window: int = 10,
    ) -> None:
        self.max_calls_per_minute = max_calls_per_minute
        self.repetition_threshold = repetition_threshold
        self.escalation_window = escalation_window
        self._history: Dict[str, Deque[_Entry]] = defaultdict(lambda: deque(maxlen=256))

    def configure(self, config: Dict[str, Any]) -> None:
        self.max_calls_per_minute = int(
            config.get("max_calls_per_minute", self.max_calls_per_minute)
        )
        self.escalation_window = int(
            config.get("escalation_window", self.escalation_window)
        )
        self.repetition_threshold = int(
            config.get("repetition_threshold", self.repetition_threshold)
        )

    def reset(self) -> None:
        self._history.clear()

    def inspect_call(self, call: ToolCall, ctx: DetectorContext) -> List[Finding]:
        findings: List[Finding] = []
        history = self._history[ctx.session_id]

        exec_capable = bool(ctx.policy.permissions.grant_for(call.tool_name).exec)
        args_sig = call.searchable_text

        # --- privilege escalation pattern (evaluate BEFORE recording) ---- #
        if exec_capable and history:
            window = list(history)[-self.escalation_window:]
            if all(not entry[2] for entry in window):
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id="behavioral.privilege_escalation",
                        severity=Severity.MEDIUM,
                        message=(
                            f"Session escalated from read-only tools to an "
                            f"execution-capable tool ('{call.tool_name}') for the "
                            "first time."
                        ),
                        evidence=f"prior_calls={len(window)}",
                        category=AttackCategory.PRIVILEGE_ESCALATION,
                    )
                )

        # --- rate spike -------------------------------------------------- #
        recent = [e for e in history if ctx.now - e[0] <= 60.0]
        if len(recent) + 1 > self.max_calls_per_minute:
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="behavioral.rate_spike",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Call rate exceeded ceiling "
                        f"({len(recent) + 1} calls/min > {self.max_calls_per_minute})."
                    ),
                    evidence=f"session={ctx.session_id}",
                    category=AttackCategory.BEHAVIORAL_ANOMALY,
                )
            )

        # --- tight repetition loop -------------------------------------- #
        identical = sum(
            1 for e in history if e[1] == call.tool_name and e[3] == args_sig
        )
        if identical + 1 >= self.repetition_threshold:
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="behavioral.repetition_loop",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Tool '{call.tool_name}' called identically "
                        f"{identical + 1} times — possible injected loop."
                    ),
                    evidence=f"repetitions={identical + 1}",
                    category=AttackCategory.BEHAVIORAL_ANOMALY,
                )
            )

        history.append((ctx.now, call.tool_name, exec_capable, args_sig))
        return findings
