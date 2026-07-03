"""Tests for the least-privilege permission engine."""

from warden.core.models import Severity, ToolCall
from warden.core.policy import Policy
from warden.policy.permissions import PermissionEngine, _glob_to_regex


def _engine():
    return PermissionEngine(Policy.default())


def test_blocks_sensitive_path_access():
    findings = _engine().evaluate(ToolCall("get_weather", {"path": "~/.ssh/id_rsa"}))
    assert any(f.rule_id == "perm.sensitive_path" and f.severity >= Severity.HIGH for f in findings)


def test_blocks_config_write():
    findings = _engine().evaluate(ToolCall("write_file", {"path": "~/.cursor/mcp.json"}))
    assert any(f.rule_id == "perm.sensitive_path" for f in findings)


def test_blocks_network_egress_to_unlisted_host():
    findings = _engine().evaluate(
        ToolCall("get_weather", {"url": "https://exfil.attacker.example/x"})
    )
    assert any(f.rule_id == "perm.network_egress" for f in findings)


def test_allows_allowlisted_host():
    findings = _engine().evaluate(
        ToolCall("get_weather", {"url": "https://api.weather.example.com/v1"})
    )
    assert findings == []


def test_allows_in_scope_read():
    findings = _engine().evaluate(
        ToolCall("read_document", {"path": "${WORKSPACE}/docs/report.md"})
    )
    assert findings == []


def test_glob_supports_double_star():
    rx = _glob_to_regex("**/.ssh/**")
    assert rx.match("/home/user/.ssh/id_rsa")
    assert not rx.match("/home/user/documents/file.txt")
