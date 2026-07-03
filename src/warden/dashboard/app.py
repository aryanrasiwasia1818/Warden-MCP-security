"""A tiny, dependency-free results dashboard.

Runs the benchmark, renders the self-contained HTML report, and serves it on
localhost via the standard library's HTTP server. No Flask, no CDN, no JS
bundle — it opens offline. This keeps the "full package" promise without adding
runtime dependencies.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import webbrowser
from typing import Optional

from warden.benchmark.report import BenchmarkReport
from warden.benchmark.runner import BenchmarkRunner
from warden.core.policy import Policy


def _render(policy: Optional[Policy]) -> str:
    outcomes = BenchmarkRunner(policy).run()
    return BenchmarkReport(outcomes).to_html()


def serve_dashboard(
    port: int = 8787,
    *,
    open_browser: bool = True,
    policy: Optional[Policy] = None,
) -> None:
    """Serve the live benchmark dashboard until interrupted (Ctrl-C)."""

    html_cache = {"body": _render(policy)}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (stdlib naming)
            if self.path in ("/reload", "/refresh"):
                html_cache["body"] = _render(policy)
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html_cache["body"].encode("utf-8"))

        def log_message(self, *args):  # silence default logging
            return

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
        url = f"http://127.0.0.1:{port}/"
        print(f"Warden dashboard running at {url}  (Ctrl-C to stop)")
        if open_browser:
            threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard stopped.")
