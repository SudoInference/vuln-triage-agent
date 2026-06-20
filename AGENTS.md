# AGENTS.md

Guidance for AI agents working in this repository.

## Overview

`vuln-triage-agent` is an autonomous security agent. It takes a target IP/hostname,
runs its own tool execution loop (network scan -> CVE lookup -> report), and produces a
Markdown findings report. It runs entirely locally with no cloud dependencies.

- Agent framework: LangGraph
- LLM backend: Ollama (local), model `llama3.1:8b` at `http://localhost:11434`
- External tools/data: `nmap` (must be on PATH), NIST NVD API (free, unauthenticated)

## Layout

- `src/main.py` - CLI entry point (argparse). Accepts multiple targets (positional or
  `--file`), builds the graph once, triages each target, and writes one report per
  target to `reports/` plus an end-of-run summary.
- `targets.example.txt` - tracked template for the gitignored `targets.txt` list.
- `src/agent/graph.py` - LangGraph wiring: nodes, conditional routing, planner loop.
- `src/agent/planner.py` - `planner` node. LLM decides the next action from a 3-line
  state summary.
- `src/agent/tools.py` - tool nodes: `run_nmap`, `lookup_cves`, `write_report`.
- `src/agent/nvd.py` - NIST NVD client: API-key support, rate-limit throttling,
  retry/backoff, and the key-aware service cap. All NVD access goes through here.
- `src/agent/state.py` - `AgentState` TypedDict shared between all nodes.
- `src/agent/__init__.py` - exports `build_graph`, `AgentState`.
- `tests/test_ollama.py` - smoke test for the Ollama connection.
- `docs/` - supporting notes and reports (e.g. `pip-audit-report.md`).
- `requirements.txt` - pinned dependencies.

## Architecture

Planner-executor loop. There is no hardcoded execution order; routing is driven by the
planner prompt. After every tool node, control returns to the planner, which inspects
state and decides what to call next. When everything is complete, it routes to `END`.

```
[START] -> [planner] --> [nmap]        --+
              ^      --> [cve_lookup]    +--> [planner] -> ... -> [END]
              +----- --> [report]       --+
```

Key design points (keep these intact when editing):

- State (`AgentState`) is a shared TypedDict. Each node reads from it and writes back.
  No node calls another node directly.
- The planner receives only a 3-line status summary (`target`, scan done?, CVE done?,
  report done?), not raw data. Keep planner input minimal.
- The planner has a deterministic-fallback block: if the LLM returns an invalid action,
  it infers the next action from state. Preserve this fallback when changing the prompt.
- CVE extraction is LLM-driven (not regex). The model turns nmap output like
  `Apache httpd 2.4.7 ((Ubuntu))` into a clean NVD query string.

## Build / Run / Test

Prerequisites: Python 3.10+, Ollama running with `llama3.1:8b` pulled, and `nmap` on PATH.

Setup:

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
ollama pull llama3.1:8b
```

Run (invoke `main.py` from the `src/` directory or as `src/main.py` so the
`from agent...` imports resolve):

```bash
python src/main.py 127.0.0.1                      # single target
python src/main.py 127.0.0.1 scanme.nmap.org      # multiple targets
python src/main.py --file targets.txt             # one target per line (# comments ok)
```

Each target (IP, hostname, or CIDR) is triaged independently and gets its own
report; the graph is built once and reused, failures are isolated per target, and
an end-of-run summary is printed. CIDR targets are passed to nmap as a single naive
scan (see `docs/network-triage-roadmap.md` for the planned per-host assessment).

Reports are written to `reports/` (auto-created) as
`report_<target>_<timestamp>.md`. The folder is gitignored. `targets.txt` is also
gitignored (may contain sensitive IPs); `targets.example.txt` is the tracked template.

Test (Ollama connectivity smoke test):

```bash
python tests/test_ollama.py           # expects "Ollama is connected"
```

There is no formal test runner configured (no pytest suite yet). New tests can be added
under `tests/`.

## Conventions

- Tool/planner nodes take `state: dict` and return a partial dict of updated keys
  (LangGraph merges it into state). Always carry `messages` forward: read
  `state.get("messages", [])`, append a `[TAG] ...` log line, and return it.
- Log lines use a bracketed tag prefix, e.g. `[PLANNER]`, `[NMAP]`, `[CVE LOOKUP]`,
  `[REPORT]`. `main.py` prints the latest message after each step.
- ChatOllama is instantiated per-node with `model="llama3.1:8b"` and
  `base_url="http://localhost:11434"`. Keep these consistent if adding nodes.
- Adding a new tool node requires three edits: implement the node in `tools.py`, add a
  matching `next_action` string + route in `route_next_action` and `build_graph`
  (`graph.py`), and update the planner prompt/fallback in `planner.py`.
- Network calls have timeouts (nmap 120s, NVD 15s). NVD access is centralized in
  `nvd.py`: it throttles requests (~6s without a key, ~0.7s with), retries on 403/429,
  and caps services via `get_max_services()` (default 5 without `NVD_API_KEY`, 25 with;
  `MAX_SERVICES` overrides). Do not re-add hard-coded caps or un-throttled requests.
- Config is read from environment variables (loaded from a gitignored `.env` via
  `python-dotenv`): `NVD_API_KEY`, `MAX_SERVICES`, `NVD_RESULTS_PER_SERVICE`.
- Reports must not use Markdown tables (the report prompt enforces plain-text lists).

## Safety

Only scan targets you have explicit permission to scan. `scanme.nmap.org` is provided by
Nmap for legal testing. Do not point scans at arbitrary hosts.
