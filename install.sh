#!/usr/bin/env bash
#
# Warden — one-command local setup.
#
# What this does:
#   1. Checks you have a compatible Python (>= 3.9).
#   2. Creates an isolated virtual environment in ./.venv  (falls back to a
#      user-level install if venv isn't available on your system).
#   3. Installs Warden (editable) + its dependencies.
#   4. Runs the test suite to prove the install works.
#   5. Runs a sample red-team benchmark and prints the headline score.
#
# Usage:
#   ./install.sh            # full setup + verification
#   ./install.sh --no-test  # skip the test/benchmark verification step
#
set -euo pipefail

# ----- pretty logging -------------------------------------------------------
GREEN="$(printf '\033[32m')"; BLUE="$(printf '\033[34m')"
YELLOW="$(printf '\033[33m')"; RED="$(printf '\033[31m')"; BOLD="$(printf '\033[1m')"
RESET="$(printf '\033[0m')"
say()  { printf "%s\n" "${BLUE}▸ ${*}${RESET}"; }
ok()   { printf "%s\n" "${GREEN}✓ ${*}${RESET}"; }
warn() { printf "%s\n" "${YELLOW}! ${*}${RESET}"; }
die()  { printf "%s\n" "${RED}✗ ${*}${RESET}" >&2; exit 1; }

RUN_TESTS=1
[[ "${1:-}" == "--no-test" ]] && RUN_TESTS=0

cd "$(dirname "$0")"

# ----- 1. Python check ------------------------------------------------------
say "Checking Python version…"
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "python3 not found. Install Python 3.9+ and retry."
PYV="$($PYTHON_BIN -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
$PYTHON_BIN -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,9) else 1)' \
    || die "Python 3.9+ required, found $PYV."
ok "Python $PYV detected."

# ----- 2. Virtual environment (with graceful fallback) ----------------------
say "Creating virtual environment in ./.venv …"
PY="$PYTHON_BIN"                 # interpreter used for install/run
PIP_FLAGS=""
if $PYTHON_BIN -m venv .venv >/dev/null 2>&1 \
        && [[ -f .venv/bin/activate ]] \
        && source .venv/bin/activate \
        && python -m pip --version >/dev/null 2>&1; then
    PY="python"
    ok "Virtual environment ready (activate later with: source .venv/bin/activate)."
else
    warn "Could not create a virtualenv — 'python3-venv'/ensurepip may be missing."
    warn "Falling back to a user-level install (pip --user)."
    warn "For an isolated env instead:  sudo apt-get install python3-venv  (Debian/Ubuntu)"
    PIP_FLAGS="--user"
    # Respect PEP 668 (externally-managed environments) if applicable.
    if $PYTHON_BIN -m pip install --help 2>/dev/null | grep -q -- "--break-system-packages"; then
        PIP_FLAGS="$PIP_FLAGS --break-system-packages"
    fi
fi

# ----- 3. Install -----------------------------------------------------------
say "Installing Warden and dependencies…"
$PY -m pip install --upgrade pip >/dev/null 2>&1 || true
# shellcheck disable=SC2086
$PY -m pip install $PIP_FLAGS -e ".[dev]" >/dev/null
ok "Warden installed. Run it with 'warden …' or '$PY -m warden …'."

# ----- 4. Tests -------------------------------------------------------------
if [[ "$RUN_TESTS" -eq 1 ]]; then
    say "Running test suite…"
    if $PY -m pytest -q; then
        ok "All tests passed."
    else
        die "Tests failed — see output above."
    fi

    # ----- 5. Sample benchmark ---------------------------------------------
    say "Running a sample red-team benchmark…"
    $PY -m warden.cli bench --quiet
    ok "Benchmark complete. Full reports written to ./reports/"
fi

echo
ok "${BOLD}Setup complete.${RESET}"
echo
echo "Try these (if you used a venv, run 'source .venv/bin/activate' first):"
echo "    ${BOLD}warden demo${RESET}        # live vulnerable-vs-hardened MCP server demo"
echo "    ${BOLD}warden bench${RESET}       # run the full red-team benchmark + reports"
echo "    ${BOLD}warden dashboard${RESET}   # open the offline results dashboard in your browser"
echo "    ${BOLD}warden scan examples/poisoned_manifest.json${RESET}   # scan a tool manifest"
echo "    ${BOLD}warden audit${RESET}       # print + verify the tamper-evident audit ledger"
echo
