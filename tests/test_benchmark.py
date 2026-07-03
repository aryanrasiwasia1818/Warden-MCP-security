"""End-to-end benchmark tests — these guard the headline claim itself."""

from warden.benchmark.attacks import load_corpus
from warden.benchmark.report import BenchmarkReport
from warden.benchmark.runner import BenchmarkRunner


def test_corpus_loads():
    cases = load_corpus()
    assert len(cases) >= 30
    assert any(c.cve == "CVE-2025-54136" for c in cases)
    assert any(c.cve == "CVE-2025-54135" for c in cases)


def test_headline_block_rate_meets_bar():
    report = BenchmarkReport(BenchmarkRunner().run())
    m = report.metrics()
    # The advertised claim: blocks 90%+ of context-injection attacks.
    assert m["headline_context_injection_block_rate"] >= 90.0


def test_no_false_positives_on_benign():
    report = BenchmarkReport(BenchmarkRunner().run())
    assert report.metrics()["false_positive_rate"] == 0.0


def test_real_cves_fully_blocked():
    report = BenchmarkReport(BenchmarkRunner().run())
    by_cve = report.by_cve()
    for cve, stats in by_cve.items():
        assert stats["blocked"] == stats["total"], f"{cve} not fully blocked"


def test_report_renders_all_formats():
    report = BenchmarkReport(BenchmarkRunner().run())
    assert "Warden" in report.to_markdown()
    assert "<html" in report.to_html().lower()
    assert '"metrics"' in report.to_json()
