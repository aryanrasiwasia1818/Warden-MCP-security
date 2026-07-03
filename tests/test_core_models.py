"""Tests for core domain models."""

from warden.core.models import (
    AttackCategory,
    DecisionType,
    Finding,
    Severity,
    ToolDescriptor,
    Verdict,
)


def test_content_hash_is_stable_and_content_sensitive():
    a = ToolDescriptor("t", "does a thing", {"type": "object"})
    b = ToolDescriptor("t", "does a thing", {"type": "object"})
    c = ToolDescriptor("t", "does a DIFFERENT thing", {"type": "object"})
    assert a.content_hash == b.content_hash
    assert a.content_hash != c.content_hash


def test_hash_ignores_dict_key_order():
    a = ToolDescriptor("t", "d", {"a": 1, "b": 2})
    b = ToolDescriptor("t", "d", {"b": 2, "a": 1})
    assert a.content_hash == b.content_hash


def test_severity_is_ordered():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_verdict_decision_thresholds():
    v = Verdict(subject="x")
    v.add(Finding("d", "r", Severity.HIGH, "m", category=AttackCategory.TOOL_POISONING))
    v.decide(block_at=Severity.HIGH, flag_at=Severity.MEDIUM)
    assert v.decision is DecisionType.BLOCK

    v2 = Verdict(subject="y")
    v2.add(Finding("d", "r", Severity.MEDIUM, "m"))
    v2.decide(block_at=Severity.HIGH, flag_at=Severity.MEDIUM)
    assert v2.decision is DecisionType.FLAG

    v3 = Verdict(subject="z")
    v3.decide(block_at=Severity.HIGH, flag_at=Severity.MEDIUM)
    assert v3.decision is DecisionType.ALLOW


def test_descriptor_from_dict_accepts_camel_and_snake():
    d = ToolDescriptor.from_dict({"name": "n", "description": "x", "inputSchema": {"a": 1}})
    assert d.input_schema == {"a": 1}
