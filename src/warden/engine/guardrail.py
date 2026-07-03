"""WardenGuardrail — the orchestrator.

It wires the layers into two flows:

**Ingestion** (once per tool, before exposure):
    descriptor → static analysis + provenance pinning → verdict → audit
    Only tools that aren't blocked become callable.

**Runtime** (every tool call):
    call → permission check + behavioral analysis  ─┐
                                                     ├─ BLOCK ⇒ refuse, don't run
    (if allowed) run tool ⇒ result → output-injection scan ─┐
                                                             ├─ BLOCK ⇒ quarantine
                                                             └─ else  ⇒ return result
    every decision is written to the tamper-evident audit ledger.

The guardrail is deliberately transport-agnostic: it takes descriptors and
calls as data and a ``runner`` callable to execute a tool. That lets the same
engine sit behind a simulated agent, the demo servers, or (via a thin adapter)
a real MCP server.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from warden.audit.ledger import AuditLedger
from warden.core.models import (
    Decision,
    DecisionType,
    ToolCall,
    ToolDescriptor,
    ToolResult,
    Verdict,
)
from warden.core.policy import Policy
from warden.detectors.base import DetectorContext
from warden.detectors.provenance import ProvenanceGuard
from warden.detectors.registry import DetectorRegistry
from warden.policy.permissions import PermissionEngine
from warden.sandbox.executor import Sandbox

Runner = Callable[[ToolCall], ToolResult]


class WardenGuardrail:
    """Multi-layer defense guardrail for MCP tool use."""

    def __init__(
        self,
        policy: Optional[Policy] = None,
        *,
        ledger: Optional[AuditLedger] = None,
    ) -> None:
        self.policy = policy or Policy.default()
        self.detectors = DetectorRegistry.from_policy(self.policy)
        self.permissions = PermissionEngine(self.policy)
        self.sandbox = Sandbox(self.policy.sandbox)
        self.ledger = ledger or AuditLedger()
        # Tools that passed ingestion and are currently exposed to the agent.
        self._tools: Dict[str, ToolDescriptor] = {}

    # -- context --------------------------------------------------------- #
    def _ctx(self, session_id: str) -> DetectorContext:
        return DetectorContext(policy=self.policy, session_id=session_id)

    def _finalize(self, verdict: Verdict) -> Verdict:
        return verdict.decide(self.policy.block_at, self.policy.flag_at)

    # -- ingestion ------------------------------------------------------- #
    def approve_tool(self, descriptor: ToolDescriptor) -> None:
        """Operator-approve a descriptor's exact content (for provenance)."""

        for det in self.detectors:
            if isinstance(det, ProvenanceGuard):
                det.approve(descriptor)

    def ingest_tool(self, descriptor: ToolDescriptor, session_id: str = "ingest") -> Verdict:
        """Scan a tool descriptor before it is exposed to the agent."""

        ctx = self._ctx(session_id)
        verdict = Verdict(subject=f"tool:{descriptor.name}")
        for det in self.detectors:
            for finding in det.inspect_descriptor(descriptor, ctx):
                verdict.add(finding)
        self._finalize(verdict)

        self.ledger.record(
            event_type="ingest",
            subject=verdict.subject,
            decision=str(verdict.decision),
            data={"server": descriptor.server, "findings": len(verdict.findings)},
        )
        if not verdict.blocked:
            self._tools[descriptor.name] = descriptor
        return verdict

    def register_tools(self, descriptors: List[ToolDescriptor]) -> List[Verdict]:
        return [self.ingest_tool(d) for d in descriptors]

    @property
    def exposed_tools(self) -> List[str]:
        return sorted(self._tools)

    # -- runtime --------------------------------------------------------- #
    def guard_call(
        self,
        call: ToolCall,
        runner: Optional[Runner] = None,
    ) -> Decision:
        """Evaluate (and optionally execute) a single tool call end-to-end."""

        ctx = self._ctx(call.session_id)
        verdicts: List[Verdict] = []

        # -- Stage A: pre-call (permissions + behavioral) ---------------- #
        pre = Verdict(subject=f"call:{call.tool_name}")
        for finding in self.permissions.evaluate(call):
            pre.add(finding)
        for det in self.detectors:
            for finding in det.inspect_call(call, ctx):
                pre.add(finding)
        self._finalize(pre)
        verdicts.append(pre)

        if pre.blocked:
            return self._decide_and_log(call, verdicts, result=None)

        # -- execute (only if a runner was supplied) --------------------- #
        result: Optional[ToolResult] = None
        if runner is not None:
            result = runner(call)

            # -- Stage B: post-call (output injection) ------------------- #
            post = Verdict(subject=f"result:{call.tool_name}")
            for det in self.detectors:
                for finding in det.inspect_result(result, ctx):
                    post.add(finding)
            self._finalize(post)
            verdicts.append(post)

            if post.blocked:
                # Poisoned output must never reach the agent — quarantine it.
                result = ToolResult(
                    tool_name=call.tool_name,
                    content="[warden] tool output quarantined: injection detected",
                    is_error=True,
                    session_id=call.session_id,
                )

        return self._decide_and_log(call, verdicts, result=result)

    # -- decision aggregation + audit ------------------------------------ #
    def _decide_and_log(
        self,
        call: ToolCall,
        verdicts: List[Verdict],
        result: Optional[ToolResult],
    ) -> Decision:
        if any(v.decision is DecisionType.BLOCK for v in verdicts):
            final = DecisionType.BLOCK
        elif any(v.decision is DecisionType.FLAG for v in verdicts):
            final = DecisionType.FLAG
        else:
            final = DecisionType.ALLOW

        decision = Decision(
            subject=f"call:{call.tool_name}",
            decision=final,
            verdicts=verdicts,
            result=result,
        )
        self.ledger.record(
            event_type="call",
            subject=decision.subject,
            decision=str(final),
            data={
                "session": call.session_id,
                "findings": [f.to_dict() for f in decision.all_findings],
            },
        )
        return decision
