"""Tests for the sandbox executor and the tamper-evident audit ledger."""

import sys

import pytest

from warden.audit.ledger import AuditLedger
from warden.core.exceptions import ProvenanceError
from warden.core.policy import SandboxPolicy
from warden.sandbox.executor import Sandbox


# -- sandbox ----------------------------------------------------------------- #
def test_sandbox_runs_benign_command():
    res = Sandbox(SandboxPolicy(allow_network=True)).run(
        [sys.executable, "-c", "print('hello')"]
    )
    assert res.ok
    assert "hello" in res.stdout


def test_sandbox_enforces_timeout():
    policy = SandboxPolicy(timeout_seconds=0.5, allow_network=True)
    res = Sandbox(policy).run([sys.executable, "-c", "import time; time.sleep(5)"])
    assert res.timed_out
    assert not res.ok


# -- audit ------------------------------------------------------------------- #
def test_ledger_chain_verifies():
    led = AuditLedger()
    led.record("call", "a", "allow")
    led.record("call", "b", "block")
    assert led.verify() is True
    assert len(led) == 2


def test_ledger_detects_tampering():
    led = AuditLedger()
    led.record("call", "a", "allow")
    led.record("call", "b", "block")
    # Tamper with a past entry's decision without recomputing the chain.
    led.entries[0].decision = "block"
    led._entries[0].decision = "block"
    with pytest.raises(ProvenanceError):
        led.verify()
