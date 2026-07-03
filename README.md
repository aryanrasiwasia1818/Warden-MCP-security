# 🛡️ Warden

**A security guardrail + red-team benchmark for MCP (Model Context Protocol) agents.**

Warden puts a defense layer in front of MCP tool use — sandboxed execution,
tool-poisoning / prompt-injection detection in tool descriptors *and* outputs,
zero-trust least-privilege permissioning, and a tamper-evident audit trail —
then **quantifies** it against a red-team corpus mapped to the real 2025 CVEs.

> **Headline (reproduce with `warden bench`):** blocks **93.5%** of
> context-injection attacks (29/31), **0% false-positive rate** on benign
> traffic, **100%** of attacks mapped to the real CVEs
> (**MCPoison — CVE-2025-54136** and **CurXecute — CVE-2025-54135**), across a
> corpus of **37 attacks + 13 benign** cases. Precision 1.0 · Recall 0.95 · F1 0.97.

Everything runs **fully offline and deterministically** — no API keys, no
network calls, reproducible scores.

---

## Why this exists

MCP is now the de-facto way agents use tools, and it shipped with real,
under-defended security holes:

| CVE | Name | The flaw | Warden's answer |
| --- | --- | --- | --- |
| **CVE-2025-54136** | **MCPoison** | Trust was bound to a tool's *name*, not its content — an approved tool could be silently swapped for a malicious one with no re-prompt. | **Provenance guard**: content-hash pinning + drift detection. |
| **CVE-2025-54135** | **CurXecute** | Untrusted tool *output* (e.g. a Slack message via MCP) could rewrite `.cursor/mcp.json` and trigger RCE with dev privileges. | **Output-injection detector** + **least-privilege** (a data tool can't write config) + **sandbox**. |
| — | Ambient authority | Servers ran with full, unscoped access. | **Zero-trust permission engine** (default-deny, per-tool scopes). |

Warden implements the multi-layer defense the research recommends — *static
metadata analysis → provenance/decision-path tracking → behavioral anomaly
detection* — and measures exactly how much it stops.

---

## Run it locally (instant setup)

**Requirements:** Python 3.9+ (nothing else).

```bash
cd warden
./install.sh
```

`install.sh` will:

1. Check your Python version.
2. Create an isolated virtualenv in `./.venv` (auto-fallback to a `pip --user`
   install if `python3-venv` isn't present).
3. Install Warden + dependencies (editable).
4. Run the test suite to prove the install works.
5. Run a sample benchmark and print the headline score.

Then activate the environment and try the commands:

```bash
source .venv/bin/activate      # if install.sh created a venv

warden demo         # live vulnerable-vs-hardened MCP server demo (before/after)
warden bench        # run the full red-team benchmark → reports/ (JSON + MD + HTML)
warden dashboard    # open the offline results dashboard in your browser
warden scan examples/poisoned_manifest.json   # scan an MCP tool manifest
warden audit        # print + cryptographically verify the audit ledger
```

> No `make`/bash? Every command also works as `python -m warden <cmd>`.
> Prefer manual steps? `python -m venv .venv && source .venv/bin/activate &&
> pip install -e ".[dev]" && pytest`.

---

## What you'll see

`warden demo` runs the same agent twice on a message containing an injected
"rewrite your MCP config" instruction (the CurXecute pattern):

```
1) WITHOUT Warden   → COMPROMISED: injected output induced a config-write.
2) WITH Warden      → not compromised
     · ingestion rejected ['get_weather'] (poisoned descriptor)
     · BLOCKED read_shared_inbox: [CRITICAL] output_injection — instructions aimed at hijacking the agent
     · audit ledger: 5 entries, chain valid
```

`warden bench` prints a scored table and writes `reports/benchmark.{html,md,json}`.
The HTML report is self-contained (inline SVG charts, no CDN) and opens offline.

---

## Architecture

Small, single-responsibility modules with clean interfaces (a `Detector` ABC,
a data-driven policy, a registry that assembles layers). Adding a new defense
layer is one subclass + one registry line (open/closed principle).

```
src/warden/
├── core/           # domain models, YAML policy loader, exception hierarchy
│   ├── models.py       ToolDescriptor · ToolCall · ToolResult · Finding · Verdict · Decision
│   ├── policy.py       Policy / PermissionPolicy / SandboxPolicy (typed, from YAML)
│   └── exceptions.py
├── detectors/      # the defense layers (all implement Detector)
│   ├── static_analyzer.py     L1  scan descriptors (regex rules + base64 decode + hidden-unicode)
│   ├── provenance.py          L2  content-hash pinning + drift  ← MCPoison
│   ├── injection_detector.py  L3a scan tool OUTPUT for injection ← CurXecute
│   ├── behavioral.py          L3b rate / loop / read→exec escalation
│   └── registry.py            assembles enabled layers from policy
├── policy/         # least-privilege enforcement + bundled default_policy.yaml
│   └── permissions.py         zero-trust PermissionEngine (fs/net scopes, sensitive paths)
├── sandbox/        # subprocess execution with cpu/mem/time/path/network limits
├── audit/          # append-only, hash-chained, tamper-evident ledger
├── engine/         # WardenGuardrail — orchestrates ingest + runtime flows
├── agent/          # deterministic offline agent (for demo + benchmark)
├── servers/        # MCP-shaped demo servers: vulnerable + Warden-hardened
├── benchmark/      # attack corpus (YAML) + runner + JSON/MD/HTML report
│   └── corpus/     # tool_poisoning · prompt_injection · descriptor_tampering …
├── dashboard/      # stdlib HTTP dashboard (no external assets)
└── cli.py          # `warden` entry point
```

### The two flows

**Ingestion** (once per tool, before it's exposed to the agent):

```
descriptor → static analysis + provenance pinning → verdict → audit
             (poisoned or drifted descriptors never become callable)
```

**Runtime** (every tool call):

```
call → permission check + behavioral analysis ─┬─ BLOCK → refuse (don't execute)
                                               └─ else  → run tool
run result → output-injection scan ─┬─ BLOCK → quarantine output (agent never sees it)
                                    └─ else  → return result
every decision → tamper-evident audit ledger
```

---

## Use it as a library

```python
from warden import WardenGuardrail, ToolDescriptor, ToolCall

guard = WardenGuardrail()                       # loads the default policy

# 1) Ingest tools — poisoned/drifted descriptors are blocked here.
guard.ingest_tool(ToolDescriptor("get_weather", "Get the weather for a city."))

# 2) Guard every call. Pass a runner to actually execute + scan the output.
decision = guard.guard_call(
    ToolCall("get_weather", {"city": "SF"}),
    runner=lambda c: my_mcp_server.call(c),
)
if decision.allowed:
    use(decision.result)
```

### Wrapping a real MCP server

The demo `MCPServer` intentionally mirrors the MCP contract (`tools/list` +
`tools/call`) with plain objects, and `HardenedServer` shows the middleware
pattern. To guard a live server built on the official `mcp` package, adapt its
tool list into `ToolDescriptor`s and route `tools/call` through
`WardenGuardrail.guard_call` — no guardrail code changes required.

---

## Testing

```bash
pytest -q          # 37 tests across every layer
```

The benchmark itself is under test: `tests/test_benchmark.py` asserts the
headline stays ≥ 90%, the false-positive rate stays at 0%, and every
CVE-mapped attack is fully blocked — so the claim can't silently regress.

---

## Configuration

All behavior is driven by a reviewable YAML policy
(`src/warden/policy/default_policy.yaml`): severity thresholds, which detectors
run, per-tool least-privilege grants, the sensitive-path denylist, and sandbox
limits. Point Warden at your own with `Policy.from_yaml(path)`.

---

## Honest limitations & roadmap

The static layer is pattern-based, so it deliberately **misses** sophisticated
semantic evasions — the corpus includes such cases (non-English phrasing, a
keyword-free paraphrase) and they show up as misses in the report. That's why
the headline is a credible ~93%, not a suspicious 100%. Closing that gap is the
documented next step, matching the three-stage research design:

- **Neural detector** (fine-tuned embedding classifier) for subtle/multilingual tool poisoning.
- **LLM-based arbitration** for uncertain cases, to cut false positives further.
- **OS-level sandbox** (container/gVisor) to replace the portable subprocess sandbox in production.
- **Live MCP adapter** over the official `mcp` package.

---

## A note on the attack corpus

Every "attack" in `benchmark/corpus/` is an **inert benchmark fixture** — a
string or descriptor scored by the detectors against Warden's own local
harness. There are no working exploits, malware, or payloads that target real
systems. This is defensive security tooling.

## License

Apache-2.0 — see [LICENSE](LICENSE).
