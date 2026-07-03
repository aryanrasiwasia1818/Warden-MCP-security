"""Benchmark scoring + report rendering (JSON, Markdown, self-contained HTML).

The report answers the one question the eye-catch bullet makes: *how many
attacks does the guardrail actually block?* — broken down by category and by the
real CVE each attack class maps to, alongside the false-positive rate on benign
traffic so the number is honest.

The HTML report is fully self-contained (inline CSS + inline SVG charts) so it
opens offline with no CDN or JS dependency.
"""

from __future__ import annotations

import datetime as _dt
import html
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from warden.benchmark.runner import CaseOutcome

# Categories that constitute "context-injection" for the headline metric.
_CONTEXT_INJECTION = {
    "tool_poisoning",
    "prompt_injection",
    "descriptor_tampering",
    "privilege_escalation",
    "data_exfiltration",
}


@dataclass
class BenchmarkReport:
    """Holds outcomes and derives all metrics on demand."""

    outcomes: List[CaseOutcome]
    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = _dt.datetime.now().isoformat(timespec="seconds")

    # -- partitions ------------------------------------------------------ #
    @property
    def attacks(self) -> List[CaseOutcome]:
        return [o for o in self.outcomes if o.category != "benign" and o.expected != "allow"]

    @property
    def benign(self) -> List[CaseOutcome]:
        return [o for o in self.outcomes if o.category == "benign" or o.expected == "allow"]

    # -- headline metrics ------------------------------------------------ #
    def metrics(self) -> Dict[str, Any]:
        attacks = self.attacks
        benign = self.benign

        block_expected = [o for o in attacks if o.expected == "block"]
        blocked_ok = [o for o in block_expected if o.actual == "block"]

        ctx = [o for o in block_expected if o.category in _CONTEXT_INJECTION]
        ctx_blocked = [o for o in ctx if o.actual == "block"]

        detected = [o for o in attacks if o.detected]
        benign_blocked = [o for o in benign if o.actual == "block"]
        benign_flagged = [o for o in benign if o.actual == "flag"]

        tp = len(detected)
        fn = len(attacks) - tp
        fp = len(benign_blocked) + len(benign_flagged)  # any benign caught (conservative)
        tn = len(benign) - fp

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        def pct(n: int, d: int) -> float:
            return round(100.0 * n / d, 1) if d else 0.0

        return {
            "generated_at": self.generated_at,
            "total_cases": len(self.outcomes),
            "total_attacks": len(attacks),
            "total_benign": len(benign),
            "headline_context_injection_block_rate": pct(len(ctx_blocked), len(ctx)),
            "context_injection_blocked": len(ctx_blocked),
            "context_injection_total": len(ctx),
            "block_rate_all_block_expected": pct(len(blocked_ok), len(block_expected)),
            "overall_detection_rate": pct(tp, len(attacks)),
            "false_positive_rate": pct(len(benign_blocked), len(benign)),
            "benign_blocked": len(benign_blocked),
            "benign_flagged": len(benign_flagged),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        }

    def by_category(self) -> Dict[str, Dict[str, int]]:
        agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "detected": 0, "blocked": 0})
        for o in self.attacks:
            agg[o.category]["total"] += 1
            agg[o.category]["detected"] += int(o.detected)
            agg[o.category]["blocked"] += int(o.actual == "block")
        return dict(agg)

    def by_cve(self) -> Dict[str, Dict[str, int]]:
        agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0})
        for o in self.attacks:
            if not o.cve:
                continue
            agg[o.cve]["total"] += 1
            agg[o.cve]["blocked"] += int(o.actual == "block")
        return dict(agg)

    # -- renderers ------------------------------------------------------- #
    def to_json(self) -> str:
        return json.dumps(
            {
                "metrics": self.metrics(),
                "by_category": self.by_category(),
                "by_cve": self.by_cve(),
                "cases": [o.to_dict() for o in self.outcomes],
            },
            indent=2,
        )

    def to_markdown(self) -> str:
        m = self.metrics()
        lines = [
            "# Warden — Red-Team Benchmark Report",
            "",
            f"_Generated: {m['generated_at']}_",
            "",
            "## Headline",
            "",
            f"**Blocks {m['headline_context_injection_block_rate']}% of context-injection "
            f"attacks** ({m['context_injection_blocked']}/{m['context_injection_total']}) "
            "mapped to real 2025 CVEs.",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Total cases | {m['total_cases']} |",
            f"| Attacks | {m['total_attacks']} |",
            f"| Benign | {m['total_benign']} |",
            f"| Context-injection block rate | {m['headline_context_injection_block_rate']}% |",
            f"| Block rate (all block-expected) | {m['block_rate_all_block_expected']}% |",
            f"| Overall detection rate | {m['overall_detection_rate']}% |",
            f"| False-positive rate (benign blocked) | {m['false_positive_rate']}% |",
            f"| Precision | {m['precision']} |",
            f"| Recall | {m['recall']} |",
            f"| F1 | {m['f1']} |",
            "",
            "## By category",
            "",
            "| Category | Detected | Blocked | Total |",
            "| --- | --- | --- | --- |",
        ]
        for cat, s in sorted(self.by_category().items()):
            lines.append(f"| {cat} | {s['detected']} | {s['blocked']} | {s['total']} |")

        lines += ["", "## By CVE", "", "| CVE | Blocked | Total |", "| --- | --- | --- |"]
        for cve, s in sorted(self.by_cve().items()):
            lines.append(f"| {cve} | {s['blocked']} | {s['total']} |")

        lines += ["", "## Cases", "", "| ID | Name | Stage | Expected | Actual | Result |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for o in self.outcomes:
            mark = "✅" if o.correct else "❌"
            lines.append(
                f"| {o.id} | {o.name} | {o.stage} | {o.expected} | {o.actual} | {mark} |"
            )
        return "\n".join(lines) + "\n"

    def to_html(self) -> str:
        m = self.metrics()
        cats = self.by_category()

        # inline SVG bar chart: detection rate per category
        bars = []
        x = 60
        bar_w = 46
        gap = 34
        max_h = 150
        base_y = 190
        for i, (cat, s) in enumerate(sorted(cats.items())):
            rate = (s["blocked"] / s["total"]) if s["total"] else 0
            h = int(max_h * rate)
            cx = x + i * (bar_w + gap)
            bars.append(
                f'<rect x="{cx}" y="{base_y - h}" width="{bar_w}" height="{h}" rx="4" '
                f'fill="#4f7cff"><title>{html.escape(cat)}: {s["blocked"]}/{s["total"]}</title></rect>'
                f'<text x="{cx + bar_w/2:.0f}" y="{base_y - h - 6}" text-anchor="middle" '
                f'font-size="11" fill="#dfe6ff">{int(rate*100)}%</text>'
                f'<text x="{cx + bar_w/2:.0f}" y="{base_y + 14}" text-anchor="middle" '
                f'font-size="9" fill="#9fb0d6">{html.escape(cat[:10])}</text>'
            )
        chart = (
            f'<svg viewBox="0 0 {x + len(cats)*(bar_w+gap)} 220" width="100%" '
            f'style="max-width:640px">'
            f'<line x1="{x-10}" y1="{base_y}" x2="{x + len(cats)*(bar_w+gap)}" y2="{base_y}" '
            f'stroke="#33406b"/>' + "".join(bars) + "</svg>"
        )

        rows = "".join(
            f"<tr class='{ 'ok' if o.correct else 'bad' }'><td>{html.escape(o.id)}</td>"
            f"<td>{html.escape(o.name)}</td><td>{html.escape(o.stage)}</td>"
            f"<td>{html.escape(o.cve or '')}</td><td>{html.escape(o.expected)}</td>"
            f"<td><b>{html.escape(o.actual)}</b></td>"
            f"<td>{'✔' if o.correct else '✗'}</td></tr>"
            for o in self.outcomes
        )

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warden — Red-Team Benchmark</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background:#0d1220; color:#e7ecf7; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color:#8ea0c8; font-size: 13px; margin-bottom: 24px; }}
  .headline {{ background: linear-gradient(135deg,#16204a,#0f2f2a); border:1px solid #26315c;
              border-radius: 14px; padding: 22px 24px; margin-bottom: 24px; }}
  .headline .big {{ font-size: 40px; font-weight: 700; color:#5cf2c0; }}
  .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr));
          gap:12px; margin-bottom:28px; }}
  .card {{ background:#131a30; border:1px solid #232f57; border-radius:12px; padding:14px 16px; }}
  .card .k {{ color:#8ea0c8; font-size:12px; }}
  .card .v {{ font-size:22px; font-weight:650; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #1e2745; }}
  th {{ color:#9fb0d6; font-weight:600; }}
  tr.bad td {{ background:#2a1420; }}
  .panel {{ background:#0f1526; border:1px solid #212c52; border-radius:12px; padding:18px; margin-bottom:24px; }}
  code {{ color:#8fd0ff; }}
</style></head>
<body><div class="wrap">
  <h1>🛡️ Warden — Red-Team Benchmark</h1>
  <div class="sub">Generated {html.escape(m['generated_at'])} · offline / deterministic</div>

  <div class="headline">
    <div>Context-injection attacks blocked</div>
    <div class="big">{m['headline_context_injection_block_rate']}%</div>
    <div class="sub">{m['context_injection_blocked']}/{m['context_injection_total']} attacks mapped to real 2025 CVEs (MCPoison CVE-2025-54136, CurXecute CVE-2025-54135)</div>
  </div>

  <div class="grid">
    <div class="card"><div class="k">Attacks</div><div class="v">{m['total_attacks']}</div></div>
    <div class="card"><div class="k">Detection rate</div><div class="v">{m['overall_detection_rate']}%</div></div>
    <div class="card"><div class="k">False positives</div><div class="v">{m['false_positive_rate']}%</div></div>
    <div class="card"><div class="k">Precision</div><div class="v">{m['precision']}</div></div>
    <div class="card"><div class="k">Recall</div><div class="v">{m['recall']}</div></div>
    <div class="card"><div class="k">F1</div><div class="v">{m['f1']}</div></div>
  </div>

  <div class="panel">
    <div class="k" style="color:#9fb0d6;margin-bottom:8px">Block rate by attack category</div>
    {chart}
  </div>

  <div class="panel">
    <table>
      <thead><tr><th>ID</th><th>Attack</th><th>Stage</th><th>CVE</th><th>Expected</th><th>Result</th><th></th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div></body></html>
"""

    # -- persistence ----------------------------------------------------- #
    def save(self, out_dir: str = "reports") -> Dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": out / "benchmark.json",
            "markdown": out / "benchmark.md",
            "html": out / "benchmark.html",
        }
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        paths["markdown"].write_text(self.to_markdown(), encoding="utf-8")
        paths["html"].write_text(self.to_html(), encoding="utf-8")
        return {k: str(v) for k, v in paths.items()}
