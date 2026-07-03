"""Warden command-line interface.

Subcommands:
    warden scan <manifest.json>   scan an MCP tool manifest for poisoning
    warden bench [--out DIR]      run the red-team benchmark + write reports
    warden demo                   vulnerable-vs-hardened live demo
    warden dashboard [--port N]   serve the offline results dashboard
    warden audit                  run a guarded session, print + verify the ledger

Output uses `rich` when available and degrades gracefully to plain text.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from warden.core.models import DecisionType, ToolCall, ToolDescriptor
from warden.core.policy import Policy

# -- optional pretty output -------------------------------------------------- #
try:
    from rich.console import Console
    from rich.table import Table

    _console = Console()

    def out(msg: str = "") -> None:
        _console.print(msg)

    _RICH = True
except Exception:  # pragma: no cover - rich optional
    _RICH = False

    def out(msg: str = "") -> None:
        # strip simple rich markup for plain terminals
        for tag in ("[bold]", "[/bold]", "[green]", "[/green]", "[red]", "[/red]",
                    "[yellow]", "[/yellow]", "[cyan]", "[/cyan]", "[dim]", "[/dim]"):
            msg = msg.replace(tag, "")
        print(msg)


_DECISION_STYLE = {
    DecisionType.ALLOW: ("green", "ALLOW"),
    DecisionType.FLAG: ("yellow", "FLAG"),
    DecisionType.BLOCK: ("red", "BLOCK"),
}


def _banner() -> None:
    out("[bold]🛡  Warden[/bold] — security guardrail + red-team benchmark for MCP agents")


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def _load_manifest(path: Path) -> List[ToolDescriptor]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        raw = data.get("tools") or data.get("descriptors") or []
    elif isinstance(data, list):
        raw = data
    else:
        raise ValueError("Manifest must be a list of tools or an object with a 'tools' array.")
    return [ToolDescriptor.from_dict(d) for d in raw]


def cmd_scan(args: argparse.Namespace) -> int:
    _banner()
    path = Path(args.manifest)
    if not path.exists():
        out(f"[red]Manifest not found:[/red] {path}")
        return 2

    from warden.engine.guardrail import WardenGuardrail

    guardrail = WardenGuardrail(Policy.default())
    descriptors = _load_manifest(path)
    out(f"\nScanning [bold]{len(descriptors)}[/bold] tool(s) from {path}\n")

    blocked = 0
    for desc in descriptors:
        verdict = guardrail.ingest_tool(desc)
        style, label = _DECISION_STYLE[verdict.decision]
        blocked += int(verdict.blocked)
        out(f"[{style}]{label:<5}[/{style}] {desc.name}")
        for f in sorted(verdict.findings, key=lambda x: x.severity, reverse=True):
            cve = f" ({f.cve})" if f.cve else ""
            out(f"    [dim]· [{f.severity}] {f.rule_id}{cve}: {f.message}[/dim]")

    out(f"\n[bold]Result:[/bold] {blocked}/{len(descriptors)} tool(s) blocked, "
        f"{len(guardrail.exposed_tools)} exposed.")
    return 1 if blocked else 0


# --------------------------------------------------------------------------- #
# bench
# --------------------------------------------------------------------------- #
def cmd_bench(args: argparse.Namespace) -> int:
    from warden.benchmark.report import BenchmarkReport
    from warden.benchmark.runner import BenchmarkRunner

    if not args.quiet:
        _banner()
        out("\nRunning red-team benchmark…\n")

    outcomes = BenchmarkRunner(Policy.default()).run()
    report = BenchmarkReport(outcomes)
    m = report.metrics()
    paths = report.save(args.out)

    if _RICH and not args.quiet:
        table = Table(title="Warden Benchmark", show_edge=False)
        for col in ("Metric", "Value"):
            table.add_column(col)
        table.add_row("Context-injection block rate",
                      f"{m['headline_context_injection_block_rate']}% "
                      f"({m['context_injection_blocked']}/{m['context_injection_total']})")
        table.add_row("Overall detection rate", f"{m['overall_detection_rate']}%")
        table.add_row("False-positive rate", f"{m['false_positive_rate']}%")
        table.add_row("Precision / Recall / F1",
                      f"{m['precision']} / {m['recall']} / {m['f1']}")
        _console.print(table)
    else:
        out(f"Context-injection block rate: {m['headline_context_injection_block_rate']}% "
            f"({m['context_injection_blocked']}/{m['context_injection_total']})")
        out(f"Detection rate: {m['overall_detection_rate']}%  |  "
            f"False positives: {m['false_positive_rate']}%  |  F1: {m['f1']}")

    if not args.quiet:
        out(f"\nReports written to: [bold]{Path(args.out).resolve()}[/bold]")
        out(f"  · {paths['html']}\n  · {paths['markdown']}\n  · {paths['json']}")

    # Non-zero exit if the headline dips below the advertised bar.
    return 0 if m["headline_context_injection_block_rate"] >= 90.0 else 3


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #
def cmd_demo(args: argparse.Namespace) -> int:
    from warden.agent import SimulatedAgent
    from warden.servers import build_hardened_server, build_vulnerable_server

    _banner()
    calls = [ToolCall(tool_name="read_shared_inbox", arguments={}, session_id="demo")]

    out("\n[bold]Scenario:[/bold] agent reads a shared inbox whose message contains an "
        "injected instruction to rewrite ~/.cursor/mcp.json (CurXecute-style).\n")

    # 1) No defense
    out("[bold]1) WITHOUT Warden[/bold] (vulnerable server, no guardrail)")
    vuln = build_vulnerable_server()
    t1 = SimulatedAgent(guardrail=None, runner=vuln.run).run(list(calls))
    verdict = "[red]COMPROMISED[/red]" if t1.compromised else "[green]safe[/green]"
    out(f"   outcome: {verdict}")
    for n in t1.notes:
        out(f"     [dim]· {n}[/dim]")

    # 2) Warden
    out("\n[bold]2) WITH Warden[/bold] (same tools, guardrail in front)")
    hs = build_hardened_server()
    out(f"   ingestion: rejected {hs.rejected_tools} (poisoned descriptor), "
        f"exposed {hs.exposed_tools}")
    t2 = SimulatedAgent(guardrail=hs.guardrail, runner=hs.server.run).run(list(calls))
    verdict2 = "[red]COMPROMISED[/red]" if t2.compromised else "[green]not compromised[/green]"
    out(f"   outcome: {verdict2}  ({t2.blocked_count} action(s) blocked)")
    for n in t2.notes:
        out(f"     [dim]· {n}[/dim]")

    ok = hs.guardrail.ledger.verify()
    out(f"\n   audit ledger: {len(hs.guardrail.ledger)} entries, "
        f"chain {'[green]valid[/green]' if ok else '[red]broken[/red]'}")
    return 0


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
def cmd_dashboard(args: argparse.Namespace) -> int:
    from warden.dashboard import serve_dashboard

    _banner()
    serve_dashboard(port=args.port, open_browser=not args.no_browser)
    return 0


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def cmd_audit(args: argparse.Namespace) -> int:
    from warden.agent import SimulatedAgent
    from warden.servers import build_hardened_server

    _banner()
    out("\nRunning a guarded session to populate the audit ledger…\n")
    hs = build_hardened_server()
    calls = [
        ToolCall(tool_name="read_document", arguments={"path": "${WORKSPACE}/docs/x.md"}, session_id="audit"),
        ToolCall(tool_name="read_shared_inbox", arguments={}, session_id="audit"),
    ]
    SimulatedAgent(guardrail=hs.guardrail, runner=hs.server.run).run(calls)

    for e in hs.guardrail.ledger.entries:
        out(f"  #{e.seq:<2} {e.event_type:<7} {e.decision:<6} {e.subject:<28} "
            f"[dim]{e.entry_hash[:12]}…[/dim]")

    try:
        hs.guardrail.ledger.verify()
        out("\n[green]✓ Ledger hash-chain verified — no tampering.[/green]")
        return 0
    except Exception as exc:  # pragma: no cover
        out(f"\n[red]✗ Ledger verification failed: {exc}[/red]")
        return 1


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="warden",
        description="Security guardrail + red-team benchmark for MCP agents.",
    )
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan an MCP tool manifest for poisoning")
    s.add_argument("manifest", help="path to a JSON manifest of tools")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("bench", help="run the red-team benchmark and write reports")
    b.add_argument("--out", default="reports", help="output directory (default: reports)")
    b.add_argument("--quiet", action="store_true", help="print only the headline metrics")
    b.set_defaults(func=cmd_bench)

    d = sub.add_parser("demo", help="vulnerable-vs-hardened live demo")
    d.set_defaults(func=cmd_demo)

    dash = sub.add_parser("dashboard", help="serve the offline results dashboard")
    dash.add_argument("--port", type=int, default=8787)
    dash.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")
    dash.set_defaults(func=cmd_dashboard)

    a = sub.add_parser("audit", help="run a guarded session and verify the audit ledger")
    a.set_defaults(func=cmd_audit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
