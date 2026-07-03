"""Layer 2 — Provenance / integrity tracking (defends MCPoison, CVE-2025-54136).

MCPoison worked because trust was bound to a tool's *name*, not its *content*:
a user approved a benign tool, then the underlying command was silently swapped
and re-executed with no re-prompt.

This detector binds trust to a content hash. On first sight of a tool it *pins*
the descriptor's hash (optionally requiring that the descriptor is already on an
approved baseline). On every subsequent sight it compares hashes; any drift is
a HIGH/CRITICAL finding demanding re-approval — the semantic equivalent of file
integrity monitoring for tool manifests.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from warden.core.models import AttackCategory, Finding, Severity, ToolDescriptor
from warden.detectors.base import Detector, DetectorContext

_CVE_MCPOISON = "CVE-2025-54136"


class ProvenanceGuard(Detector):
    """Content-hash pinning + drift detection for tool descriptors."""

    name = "provenance"

    def __init__(self, *, trust_on_first_use: bool = True) -> None:
        # tool_name -> pinned content hash
        self._baseline: Dict[str, str] = {}
        # Descriptors the operator has explicitly approved (hash set). If
        # non-empty, first-use of an unlisted descriptor is itself suspicious.
        self._approved: Optional[set] = None
        self._trust_on_first_use = trust_on_first_use

    # -- baseline management --------------------------------------------- #
    def approve(self, descriptor: ToolDescriptor) -> None:
        """Mark a specific descriptor content as operator-approved."""

        if self._approved is None:
            self._approved = set()
        self._approved.add(descriptor.content_hash)
        self._baseline[descriptor.name] = descriptor.content_hash

    def pin(self, descriptor: ToolDescriptor) -> None:
        """Record the current descriptor hash as the trusted baseline."""

        self._baseline[descriptor.name] = descriptor.content_hash

    def reset(self) -> None:
        self._baseline.clear()
        self._approved = None

    # -- detection ------------------------------------------------------- #
    def inspect_descriptor(
        self, descriptor: ToolDescriptor, ctx: DetectorContext
    ) -> List[Finding]:
        findings: List[Finding] = []
        current = descriptor.content_hash
        known = self._baseline.get(descriptor.name)

        if known is None:
            # First time we've seen this tool.
            if self._approved is not None and current not in self._approved:
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id="provenance.unapproved_tool",
                        severity=Severity.HIGH,
                        message=(
                            f"Tool '{descriptor.name}' is not on the approved "
                            "baseline; requires explicit approval before use."
                        ),
                        evidence=f"hash={current[:16]}…",
                        category=AttackCategory.DESCRIPTOR_TAMPERING,
                        cve=_CVE_MCPOISON,
                    )
                )
            if self._trust_on_first_use:
                self._baseline[descriptor.name] = current
        elif known != current:
            # The descriptor changed under a previously-trusted name: the exact
            # MCPoison "silent swap". Block and demand re-approval.
            findings.append(
                Finding(
                    detector=self.name,
                    rule_id="provenance.descriptor_drift",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Tool '{descriptor.name}' changed after approval "
                        "(silent swap). Trust must not carry over — re-approval "
                        "required."
                    ),
                    evidence=f"pinned={known[:12]}… now={current[:12]}…",
                    category=AttackCategory.DESCRIPTOR_TAMPERING,
                    cve=_CVE_MCPOISON,
                )
            )
        return findings
