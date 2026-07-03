"""Least-privilege permission engine (zero-trust enforcement).

Every tool call is treated as unauthorized until proven otherwise. The engine
inspects a call's arguments for the resources it would touch — filesystem paths
and network hosts — and checks each against the tool's explicit grant:

* Touching a **sensitive path** (SSH keys, .env, MCP config, /etc/passwd, …)
  without an explicit grant is the CurXecute failure mode → HIGH finding.
* Reaching a **filesystem path** outside the granted globs → out-of-scope.
* Contacting a **network host** not on the allowlist → possible exfiltration.

Findings feed the same verdict machinery as the detectors, so policy violations
and poisoning signals are scored uniformly.
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable, List

from warden.core.models import AttackCategory, Finding, Severity
from warden.core.models import ToolCall
from warden.core.policy import Policy

_CVE_CURXECUTE = "CVE-2025-54135"

# Argument keys that conventionally carry a path or a URL.
_PATH_KEYS = {"path", "file", "filename", "filepath", "target", "dest",
              "destination", "src", "source", "dir", "directory", "output"}
_URL_KEYS = {"url", "uri", "endpoint", "host", "webhook", "callback"}

_URL_RE = re.compile(r"https?://([^/\s\"']+)", re.IGNORECASE)
_PATHLIKE_RE = re.compile(r"(~|\.{0,2}/|[A-Za-z]:\\)[^\s\"']*")


def _glob_to_regex(glob: str) -> "re.Pattern[str]":
    """Translate a glob (supporting ``**``) to a regex.

    ``**`` matches across path separators, ``*`` within a segment, ``?`` one char.
    """

    glob = os.path.expandvars(glob)  # expand ${WORKSPACE} etc.
    out = ["^"]
    i = 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            if glob[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _normalize(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path)).replace("\\", "/")


class PermissionEngine:
    """Evaluates a tool call against the least-privilege policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._sensitive = [_glob_to_regex(p) for p in policy.permissions.sensitive_paths]

    # -- extraction ------------------------------------------------------ #
    def _iter_values(self, args: Any) -> Iterable[Any]:
        if isinstance(args, dict):
            for v in args.values():
                yield from self._iter_values(v)
        elif isinstance(args, (list, tuple)):
            for v in args:
                yield from self._iter_values(v)
        else:
            yield args

    def _paths(self, call: ToolCall) -> List[str]:
        found: List[str] = []
        for key, value in call.arguments.items():
            if isinstance(value, str):
                if key.lower() in _PATH_KEYS or _PATHLIKE_RE.search(value):
                    if not value.lower().startswith(("http://", "https://")):
                        found.append(value)
        return found

    def _hosts(self, call: ToolCall) -> List[str]:
        hosts: List[str] = []
        for key, value in call.arguments.items():
            if not isinstance(value, str):
                continue
            for m in _URL_RE.finditer(value):
                hosts.append(m.group(1).split(":")[0])
            if key.lower() in _URL_KEYS and "://" not in value and "/" not in value:
                hosts.append(value.split(":")[0])
        return hosts

    # -- checks ---------------------------------------------------------- #
    def _is_sensitive(self, path: str) -> bool:
        norm = _normalize(path)
        return any(rx.match(norm) for rx in self._sensitive)

    def _matches_any(self, path: str, globs: List[str]) -> bool:
        norm = _normalize(path)
        return any(_glob_to_regex(g).match(norm) for g in globs)

    def evaluate(self, call: ToolCall) -> List[Finding]:
        findings: List[Finding] = []
        grant = self.policy.permissions.grant_for(call.tool_name)
        default_deny = self.policy.permissions.default_effect == "deny"
        granted_fs = grant.fs_read + grant.fs_write

        for path in self._paths(call):
            explicitly_allowed = self._matches_any(path, granted_fs)
            if self._is_sensitive(path) and not explicitly_allowed:
                findings.append(
                    Finding(
                        detector="permission_engine",
                        rule_id="perm.sensitive_path",
                        severity=Severity.HIGH,
                        message=(
                            f"Tool '{call.tool_name}' attempted to access a "
                            f"sensitive path without a grant: {path}"
                        ),
                        evidence=path,
                        category=AttackCategory.PRIVILEGE_ESCALATION,
                        cve=_CVE_CURXECUTE,
                    )
                )
            elif not explicitly_allowed and default_deny:
                findings.append(
                    Finding(
                        detector="permission_engine",
                        rule_id="perm.out_of_scope_fs",
                        severity=Severity.MEDIUM,
                        message=(
                            f"Tool '{call.tool_name}' accessed a path outside its "
                            f"granted scope: {path}"
                        ),
                        evidence=path,
                        category=AttackCategory.PRIVILEGE_ESCALATION,
                    )
                )

        for host in self._hosts(call):
            if not self._matches_any(host, grant.network) and host not in grant.network:
                findings.append(
                    Finding(
                        detector="permission_engine",
                        rule_id="perm.network_egress",
                        severity=Severity.HIGH,
                        message=(
                            f"Tool '{call.tool_name}' attempted network egress to a "
                            f"non-allowlisted host: {host}"
                        ),
                        evidence=host,
                        category=AttackCategory.DATA_EXFILTRATION,
                    )
                )

        return findings
