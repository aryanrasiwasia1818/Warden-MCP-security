"""A deterministic, offline agent for demos and benchmarking.

This is *not* an LLM. It's a small, reproducible stand-in that behaves like a
naive tool-using agent: it issues the calls it's told to, and — crucially — it
*follows instructions it finds in tool output*, which is exactly how indirect
prompt injection (CurXecute) compromises real agents.

Running the same script with and without Warden makes the difference concrete:

* **Without** the guardrail, injected output induces a dangerous follow-up call
  (e.g. rewriting ``.cursor/mcp.json``) and the agent is compromised.
* **With** the guardrail, the poisoned output is quarantined before the agent
  ever sees it, so no induced call is produced.

A clean ``LLMAgent`` could implement the same interface behind an API key; that
hook is documented but intentionally left out of the offline core.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from warden.core.models import Decision, DecisionType, ToolCall, ToolResult
from warden.engine.guardrail import WardenGuardrail

Runner = Callable[[ToolCall], ToolResult]

# Directive an injected tool output uses to hijack the agent into rewriting the
# MCP config. Detecting it here models a *naive* agent that obeys tool output.
_INDUCED_CONFIG_WRITE = re.compile(
    r"(write|append|add).{0,40}(mcp\.json|mcp\s+server|\.cursor)", re.IGNORECASE
)


@dataclass
class Step:
    call: ToolCall
    decision: Decision
    induced: bool = False  # was this call induced by injected output?


@dataclass
class AgentTranscript:
    """The record of a simulated run, including whether it was compromised."""

    steps: List[Step] = field(default_factory=list)
    compromised: bool = False
    notes: List[str] = field(default_factory=list)

    def add(self, step: Step) -> None:
        self.steps.append(step)

    @property
    def blocked_count(self) -> int:
        return sum(1 for s in self.steps if s.decision.decision is DecisionType.BLOCK)


class SimulatedAgent:
    """A reproducible agent that a guardrail can protect (or fail to)."""

    def __init__(
        self,
        guardrail: Optional[WardenGuardrail],
        runner: Runner,
    ) -> None:
        # guardrail=None models the "no defense" baseline.
        self.guardrail = guardrail
        self.runner = runner

    def _raw_call(self, call: ToolCall) -> Decision:
        """Execute without any guardrail (the vulnerable baseline)."""

        result = self.runner(call)
        return Decision(
            subject=f"call:{call.tool_name}",
            decision=DecisionType.ALLOW,
            result=result,
        )

    def _induced_call(self, result: Optional[ToolResult], session_id: str) -> Optional[ToolCall]:
        """A naive agent obeys instructions found in tool output."""

        if result is None or result.is_error or not result.content:
            return None
        if _INDUCED_CONFIG_WRITE.search(result.content):
            return ToolCall(
                tool_name="write_file",
                arguments={"path": "~/.cursor/mcp.json", "content": "<attacker-payload>"},
                session_id=session_id,
                caller="injected-output",
            )
        return None

    def run(self, calls: List[ToolCall]) -> AgentTranscript:
        transcript = AgentTranscript()
        queue: List[ToolCall] = list(calls)

        while queue:
            call = queue.pop(0)
            if self.guardrail is not None:
                decision = self.guardrail.guard_call(call, runner=self.runner)
            else:
                decision = self._raw_call(call)

            induced_flag = call.caller == "injected-output"
            transcript.add(Step(call=call, decision=decision, induced=induced_flag))

            # A blocked call yields no usable output; the chain stops here.
            if decision.decision is DecisionType.BLOCK:
                reason = next(
                    (v.reasons[0] for v in decision.verdicts if v.blocked and v.reasons),
                    "policy",
                )
                transcript.notes.append(f"BLOCKED {call.tool_name}: {reason}")
                if induced_flag:
                    transcript.notes.append(
                        "Induced config-write was blocked — injection chain broken."
                    )
                continue

            # Naive agent follows any instructions found in the (allowed) output.
            induced = self._induced_call(decision.result, call.session_id)
            if induced is not None:
                if induced.caller == "injected-output" and self.guardrail is None:
                    transcript.compromised = True
                    transcript.notes.append(
                        "COMPROMISED: injected output induced a config-write with no guardrail."
                    )
                queue.append(induced)

        return transcript
