"""Benchmark runner — drives each attack case through a fresh guardrail.

Every case is evaluated through the *real* guardrail entry point for its stage
(ingest / call / result / swap / sequence), so the scores reflect genuine
end-to-end behavior, not a mock. A fresh guardrail per case keeps cases
independent (no state bleed between attacks).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from warden.core.models import (
    AttackCategory,
    Decision,
    DecisionType,
    ToolCall,
    ToolDescriptor,
    ToolResult,
    Verdict,
)
from warden.core.policy import Policy
from warden.benchmark.attacks import AttackCase, load_corpus
from warden.engine.guardrail import WardenGuardrail


@dataclass
class CaseOutcome:
    """The scored result of running one case."""

    id: str
    name: str
    category: str
    stage: str
    expected: str
    actual: str
    cve: Optional[str]
    detected: bool          # caught at all (flag or block)
    correct: bool           # matched the expectation
    false_positive: bool    # benign that got blocked
    rule_ids: List[str] = field(default_factory=list)
    max_severity: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "stage": self.stage,
            "expected": self.expected,
            "actual": self.actual,
            "cve": self.cve,
            "detected": self.detected,
            "correct": self.correct,
            "false_positive": self.false_positive,
            "rule_ids": self.rule_ids,
            "max_severity": self.max_severity,
        }


def _descriptor(data: Dict[str, Any]) -> ToolDescriptor:
    return ToolDescriptor.from_dict(data)


def _call(data: Dict[str, Any], session_id: str = "bench") -> ToolCall:
    return ToolCall(
        tool_name=str(data["tool_name"]),
        arguments=dict(data.get("arguments", {}) or {}),
        session_id=session_id,
    )


def _vary(arguments: Dict[str, Any], index: int) -> Dict[str, Any]:
    out = dict(arguments)
    for key, value in out.items():
        if isinstance(value, str):
            out[key] = f"{value}{index}"
            break
    return out


class BenchmarkRunner:
    """Runs the corpus and returns per-case outcomes."""

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or Policy.default()

    # -- per-stage evaluation -------------------------------------------- #
    def _run_ingest(self, guardrail: WardenGuardrail, case: AttackCase) -> Verdict:
        return guardrail.ingest_tool(_descriptor(case.descriptor or {}))

    def _run_swap(self, guardrail: WardenGuardrail, case: AttackCase) -> Verdict:
        baseline = _descriptor(case.baseline or {})
        guardrail.ingest_tool(baseline)
        guardrail.approve_tool(baseline)          # operator approves the benign one
        return guardrail.ingest_tool(_descriptor(case.descriptor or {}))

    def _run_unapproved(self, guardrail: WardenGuardrail, case: AttackCase) -> Verdict:
        for d in case.approve:
            guardrail.approve_tool(_descriptor(d))
        return guardrail.ingest_tool(_descriptor(case.descriptor or {}))

    def _run_call(self, guardrail: WardenGuardrail, case: AttackCase) -> Decision:
        return guardrail.guard_call(_call(case.call or {}), runner=None)

    def _run_result(self, guardrail: WardenGuardrail, case: AttackCase) -> Decision:
        tool = case.tool or "tool"
        content = case.result or ""

        def runner(c: ToolCall) -> ToolResult:
            return ToolResult(tool_name=c.tool_name, content=content, session_id=c.session_id)

        return guardrail.guard_call(
            ToolCall(tool_name=tool, arguments={}, session_id="bench"), runner=runner
        )

    def _run_sequence(self, guardrail: WardenGuardrail, case: AttackCase) -> List[Decision]:
        decisions: List[Decision] = []
        calls: List[ToolCall] = []
        if case.repeat_call:
            for i in range(case.repeat):
                args = case.repeat_call.get("arguments", {}) or {}
                args = _vary(args, i) if case.vary_args else dict(args)
                calls.append(
                    ToolCall(
                        tool_name=str(case.repeat_call["tool_name"]),
                        arguments=args,
                        session_id="bench-seq",
                    )
                )
        for spec in case.sequence:
            calls.append(_call(spec, session_id="bench-seq"))
        for c in calls:
            decisions.append(guardrail.guard_call(c, runner=None))
        return decisions

    # -- scoring --------------------------------------------------------- #
    def _score(self, case: AttackCase, decision: DecisionType, verdicts: List[Verdict]) -> CaseOutcome:
        actual = decision.value
        detected = decision in (DecisionType.BLOCK, DecisionType.FLAG)

        if case.is_benign:
            correct = decision is DecisionType.ALLOW
            false_positive = decision is DecisionType.BLOCK
        elif case.expect == "block":
            correct = decision is DecisionType.BLOCK
            false_positive = False
        else:  # expect flag
            correct = detected
            false_positive = False

        rule_ids: List[str] = []
        max_sev = "INFO"
        for v in verdicts:
            for f in v.findings:
                rule_ids.append(f.rule_id)
                if f.severity.name != "INFO":
                    # track the highest
                    from warden.core.models import Severity
                    if Severity[max_sev] < f.severity:
                        max_sev = f.severity.name

        return CaseOutcome(
            id=case.id,
            name=case.name,
            category=case.category.value,
            stage=case.stage,
            expected=case.expect,
            actual=actual,
            cve=case.cve,
            detected=detected,
            correct=correct,
            false_positive=false_positive,
            rule_ids=rule_ids,
            max_severity=max_sev,
        )

    def run_case(self, case: AttackCase) -> CaseOutcome:
        guardrail = WardenGuardrail(self.policy)

        if case.stage == "ingest":
            v = self._run_ingest(guardrail, case)
            return self._score(case, v.decision, [v])
        if case.stage == "swap":
            v = self._run_swap(guardrail, case)
            return self._score(case, v.decision, [v])
        if case.stage == "unapproved":
            v = self._run_unapproved(guardrail, case)
            return self._score(case, v.decision, [v])
        if case.stage == "call":
            d = self._run_call(guardrail, case)
            return self._score(case, d.decision, d.verdicts)
        if case.stage == "result":
            d = self._run_result(guardrail, case)
            return self._score(case, d.decision, d.verdicts)
        if case.stage == "sequence":
            decisions = self._run_sequence(guardrail, case)
            # A sequence is "caught" if any step is flagged or blocked.
            worst = DecisionType.ALLOW
            verdicts: List[Verdict] = []
            for d in decisions:
                verdicts.extend(d.verdicts)
                if d.decision is DecisionType.BLOCK:
                    worst = DecisionType.BLOCK
                elif d.decision is DecisionType.FLAG and worst is not DecisionType.BLOCK:
                    worst = DecisionType.FLAG
            return self._score(case, worst, verdicts)

        raise ValueError(f"Unknown stage: {case.stage}")

    def run(self, cases: Optional[List[AttackCase]] = None) -> List[CaseOutcome]:
        cases = cases if cases is not None else load_corpus()
        return [self.run_case(c) for c in cases]
