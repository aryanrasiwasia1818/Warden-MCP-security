"""Policy model + loader.

The policy is the single source of truth for *what is allowed*. It is loaded
from YAML (human-readable, reviewable, diff-able — important for a security
control) and validated into typed dataclasses so the rest of the code never
touches raw dicts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

from warden.core.exceptions import PolicyError
from warden.core.models import Severity

_DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy" / "default_policy.yaml"


def _severity(value: Any, default: Severity) -> Severity:
    if value is None:
        return default
    try:
        return Severity[str(value).upper()]
    except KeyError as exc:  # pragma: no cover - defensive
        raise PolicyError(f"Unknown severity '{value}'") from exc


@dataclass
class ToolGrant:
    """Least-privilege scopes granted to a single tool. Absent = not allowed."""

    fs_read: List[str] = field(default_factory=list)
    fs_write: List[str] = field(default_factory=list)
    network: List[str] = field(default_factory=list)
    exec: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolGrant":
        return cls(
            fs_read=list(data.get("fs_read", []) or []),
            fs_write=list(data.get("fs_write", []) or []),
            network=list(data.get("network", []) or []),
            exec=bool(data.get("exec", False)),
        )


@dataclass
class PermissionPolicy:
    """Zero-trust permission model: default-deny with explicit per-tool grants."""

    default_effect: str = "deny"           # "deny" (zero-trust) or "allow"
    tools: Dict[str, ToolGrant] = field(default_factory=dict)
    # Paths no tool may touch unless it holds an explicit matching grant.
    # These encode the CurXecute lesson: a data tool must never rewrite config.
    sensitive_paths: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PermissionPolicy":
        tools = {
            name: ToolGrant.from_dict(grant or {})
            for name, grant in (data.get("tools") or {}).items()
        }
        return cls(
            default_effect=str(data.get("default_effect", "deny")),
            tools=tools,
            sensitive_paths=list(data.get("sensitive_paths", []) or []),
        )

    def grant_for(self, tool_name: str) -> ToolGrant:
        """Return the grant for a tool, or an empty (deny-all) grant."""

        return self.tools.get(tool_name, ToolGrant())


@dataclass
class SandboxPolicy:
    """Resource limits applied to sandboxed tool execution."""

    enabled: bool = True
    timeout_seconds: float = 5.0
    memory_mb: int = 256
    cpu_seconds: int = 5
    allow_network: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SandboxPolicy":
        return cls(
            enabled=bool(data.get("enabled", True)),
            timeout_seconds=float(data.get("timeout_seconds", 5.0)),
            memory_mb=int(data.get("memory_mb", 256)),
            cpu_seconds=int(data.get("cpu_seconds", 5)),
            allow_network=bool(data.get("allow_network", False)),
        )


@dataclass
class Policy:
    """Top-level Warden policy."""

    block_at: Severity = Severity.HIGH
    flag_at: Severity = Severity.MEDIUM
    enabled_detectors: List[str] = field(
        default_factory=lambda: [
            "static_metadata",
            "provenance",
            "output_injection",
            "behavioral",
        ]
    )
    detector_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    permissions: PermissionPolicy = field(default_factory=PermissionPolicy)
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)

    # ---- loaders --------------------------------------------------------- #
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Policy":
        thresholds = data.get("thresholds", {}) or {}
        return cls(
            block_at=_severity(thresholds.get("block_at"), Severity.HIGH),
            flag_at=_severity(thresholds.get("flag_at"), Severity.MEDIUM),
            enabled_detectors=list(
                data.get("enabled_detectors")
                or ["static_metadata", "provenance", "output_injection", "behavioral"]
            ),
            detector_config=dict(data.get("detector_config", {}) or {}),
            permissions=PermissionPolicy.from_dict(data.get("permissions", {}) or {}),
            sandbox=SandboxPolicy.from_dict(data.get("sandbox", {}) or {}),
        )

    @classmethod
    def from_yaml(cls, path: os.PathLike | str) -> "Policy":
        p = Path(path)
        if not p.exists():
            raise PolicyError(f"Policy file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"Invalid YAML in {p}: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyError(f"Policy root must be a mapping, got {type(data).__name__}")
        return cls.from_dict(data)

    @classmethod
    def default(cls) -> "Policy":
        """Load the bundled default policy (falls back to code defaults)."""

        if _DEFAULT_POLICY_PATH.exists():
            return cls.from_yaml(_DEFAULT_POLICY_PATH)
        return cls()
