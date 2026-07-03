"""Exception hierarchy for Warden.

A single well-defined hierarchy makes error handling explicit and lets callers
catch broad (`WardenError`) or narrow (`PolicyViolation`) as needed.
"""

from __future__ import annotations


class WardenError(Exception):
    """Base class for every error raised by Warden."""


class PolicyError(WardenError):
    """Raised when a policy document is missing, malformed, or invalid."""


class PolicyViolation(WardenError):
    """Raised when a tool call violates the least-privilege policy.

    Carries the offending scope so callers can log or surface it.
    """

    def __init__(self, message: str, *, scope: str | None = None) -> None:
        super().__init__(message)
        self.scope = scope


class SandboxError(WardenError):
    """Raised when sandboxed execution fails to set up or is force-terminated."""


class SandboxViolation(SandboxError):
    """Raised when sandboxed code breaches a resource, path, or time limit."""


class ProvenanceError(WardenError):
    """Raised when the audit ledger's hash-chain integrity check fails."""


class CorpusError(WardenError):
    """Raised when the red-team attack corpus cannot be loaded or is malformed."""
