# Warden — developer convenience targets.
# These assume you've run ./install.sh and activated the venv (source .venv/bin/activate).

.PHONY: help install test bench demo dashboard scan audit clean

help:
	@echo "Warden targets:"
	@echo "  make install    - one-command local setup (venv + deps + verify)"
	@echo "  make test       - run the pytest suite"
	@echo "  make bench      - run the red-team benchmark and write reports/"
	@echo "  make demo       - run the vulnerable-vs-hardened MCP server demo"
	@echo "  make dashboard  - serve the offline results dashboard"
	@echo "  make clean      - remove build/venv/report artifacts"

install:
	./install.sh

test:
	pytest -q

bench:
	warden bench

demo:
	warden demo

dashboard:
	warden dashboard

scan:
	warden scan examples/poisoned_manifest.json

audit:
	warden audit

clean:
	rm -rf .venv reports .pytest_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
