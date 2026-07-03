"""Sandboxed subprocess execution with resource, time, path and network limits.

Most MCP tools just return data, but execution-capable tools (a build step, a
shell helper) are where an injected command does real damage. Warden runs those
in a constrained subprocess:

* **Filesystem jail** — a fresh temp working directory; the process is started
  there with a stripped environment.
* **CPU / memory / file-size caps** — applied via POSIX ``resource`` rlimits in
  a ``preexec_fn`` (best-effort, skipped cleanly on non-POSIX).
* **Wall-clock timeout** — hard kill if the tool runs too long.
* **Network isolation** — best-effort via ``unshare -n`` when available; if the
  platform can't provide it, the result records ``network_isolated=False`` so
  callers never assume a guarantee that wasn't delivered.

This is a pragmatic, portable sandbox for a local benchmark — not a substitute
for OS-level container/VM isolation in production, which the README calls out.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import List, Optional

from warden.core.exceptions import SandboxError
from warden.core.policy import SandboxPolicy

try:  # POSIX-only resource limits
    import resource  # type: ignore
    _HAVE_RESOURCE = True
except ImportError:  # pragma: no cover - Windows
    _HAVE_RESOURCE = False


@dataclass
class SandboxResult:
    """Outcome of a sandboxed execution."""

    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    network_isolated: bool = False
    workdir: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class Sandbox:
    """Runs a command under the limits described by a :class:`SandboxPolicy`."""

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self.policy = policy or SandboxPolicy()

    # -- preexec: apply rlimits in the child before exec ----------------- #
    def _limits(self):  # returns a callable or None
        if not (_HAVE_RESOURCE and self.policy.enabled):
            return None
        mem_bytes = self.policy.memory_mb * 1024 * 1024
        cpu_seconds = self.policy.cpu_seconds

        def _apply():  # pragma: no cover - runs in child process
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                resource.setrlimit(resource.RLIMIT_FSIZE,
                                   (50 * 1024 * 1024, 50 * 1024 * 1024))
                os.setsid()
            except (ValueError, OSError):
                pass

        return _apply

    def _wrap_network(self, argv: List[str]) -> (List[str], bool):
        """Prefix with a network-isolating wrapper when possible."""

        if self.policy.allow_network:
            return argv, True  # network intentionally permitted
        unshare = shutil.which("unshare")
        if unshare:
            # -rn: new user + network namespace (no external interfaces).
            return [unshare, "-rn", *argv], True
        return argv, False  # couldn't isolate; report honestly

    def run(self, argv: List[str], *, stdin: str = "") -> SandboxResult:
        """Execute ``argv`` under the sandbox and return a structured result."""

        if not argv:
            raise SandboxError("Sandbox.run requires a non-empty argv.")

        workdir = tempfile.mkdtemp(prefix="warden-sbx-")
        wrapped, isolated = self._wrap_network(argv)
        env = {"PATH": "/usr/bin:/bin", "HOME": workdir, "TMPDIR": workdir}

        start = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                wrapped,
                cwd=workdir,
                env=env,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=self.policy.timeout_seconds,
                preexec_fn=self._limits() if os.name == "posix" else None,
                check=False,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = -9
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = "sandbox: wall-clock timeout exceeded"
        except FileNotFoundError:
            # network wrapper missing at runtime → retry unwrapped, no isolation
            if wrapped is not argv:
                self.policy.allow_network = True  # local retry only
                res = self.run(argv, stdin=stdin)
                res.network_isolated = False
                shutil.rmtree(workdir, ignore_errors=True)
                return res
            raise
        finally:
            duration = time.time() - start

        result = SandboxResult(
            returncode=rc,
            stdout=out,
            stderr=err,
            duration_s=duration,
            timed_out=timed_out,
            network_isolated=isolated and not self.policy.allow_network,
            workdir=workdir,
        )
        shutil.rmtree(workdir, ignore_errors=True)
        return result
