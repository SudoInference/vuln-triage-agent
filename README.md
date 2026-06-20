# Vulnerability Triage Agent

An autonomous security agent that accepts a target IP, orchestrates its own tool execution, and produces a professional findings report — without being told what to do at each step.

Built with LangGraph + Ollama. Runs entirely on local hardware. No cloud dependencies.

---

## What Problem This Solves

Security triage is repetitive: scan a target, look up what you found, write a report. A junior analyst can spend an hour on a workflow that produces the same structured output every time. This agent automates that first pass — scan, CVE lookup, report — so the analyst's time starts at interpretation, not data collection.

The design choice to run locally matters: sensitive target data never leaves the network. That constraint rules out cloud-based alternatives for most enterprise and government environments.

---

## Demo

```
python src\main.py 127.0.0.1

```

```
 Starting vulnerability triage for: 127.0.0.1

  [PLANNER] Next action: run_nmap
  [NMAP] Completed scan of 127.0.0.1
  [PLANNER] Next action: lookup_cves
  [CVE LOOKUP] Found 9 potential vulnerabilities
  [PLANNER] Next action: write_report
  [REPORT] Final report generated
  [PLANNER] Next action: done

 Markdown saved: reports/report_127_0_0_1_20260304_0448.md
```

Findings include real CVEs with CVSS scores pulled live from the NIST NVD API. Reports are saved automatically to a `/reports` folder that creates itself on first run.

> **Warning:** Only scan targets you have explicit permission to scan. `scanme.nmap.org` is provided by Nmap for legal testing.

---

## Architecture

The agent runs a planner-executor loop. There is no hardcoded execution order — routing is driven by the planner prompt.

```
[START] → [Planner] ──→ [Nmap Scan]    ──┐
                  ↑──→ [CVE Lookup]    ──┤→ [Planner] → ... → [END]
                  └──→ [Report Writer] ──┘
```

After every tool completes, control returns to the planner. The LLM reads the current state — what's been done, what hasn't — and decides what to call next. When everything is done, it routes to END.

This is the same planner-executor pattern used in production agentic systems. The tools are interchangeable; the loop is not specific to security work.

> The current planner prompt produces deterministic ordering — nmap, then CVE lookup, then report. The graph wiring does not enforce this; the prompt does. To bypass the scan entirely, pre-populate scan_results in initial_state with existing nmap output. The planner will detect it and route directly to CVE lookup. 

**State** is a shared TypedDict passed between every node. Each node reads from it and writes back to it. No node communicates directly with another.

**The planner** receives a 3-line status summary, not raw data. Keeping the input minimal reduces token cost and improves routing reliability.

**CVE extraction** is LLM-driven rather than regex-based. The model translates nmap output like `Apache httpd 2.4.7 ((Ubuntu))` into `Apache HTTP Server 2.4.7` — a query that actually returns NVD results. Regex breaks on output variance; the LLM handles it.

---

## Stack

| Component        | Tool                                 |
| ---------------- | ------------------------------------ |
| Agent framework  | LangGraph                            |
| LLM backend      | Ollama (local)                       |
| Model            | Llama 3.1 8B                      |
| Network scanning | Nmap                                 |
| CVE data         | NIST NVD API (free, unauthenticated) |
| Hardware         | RTX 3060 Ti 8GB (Thunderbolt 4 eGPU) |

---

## Setup

**Prerequisites:** Python 3.10+, [Ollama](https://ollama.com), [Nmap](https://nmap.org/download.html) in PATH

```bash
git clone https://github.com/sudoinference/vuln-triage-agent.git
cd vuln-triage-agent
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
ollama pull llama3.1:8b
```

**Run:**
```bash
python src\main.py 127.0.0.1          # Windows
python src/main.py 127.0.0.1          # Linux/macOS
python src/main.py scanme.nmap.org    # Nmap's legal test host
```

Reports are saved to `/reports` as `.md`. Delete the folder to clear all reports — it recreates itself on the next run.

### NVD API key & service coverage (optional)

By default the agent runs with **no API key** and triages up to **5 services** per scan, spacing requests ~6s apart to stay under NIST NVD's free rate limit (~5 requests / 30s). This works out of the box with no signup.

To triage more services and run faster, register for a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (raises the limit to ~50 requests / 30s). Configure it with environment variables, e.g. in a `.env` file at the project root:

```bash
# .env  (gitignored — never commit this)
NVD_API_KEY=your-key-here     # optional; enables faster throttle + higher default cap
MAX_SERVICES=25               # optional; default is 5 without a key, 25 with one
NVD_RESULTS_PER_SERVICE=3     # optional; CVEs requested per service (default 3)
```

With a key present the default service cap rises to 25; set `MAX_SERVICES` to any value to override it in either direction. The agent never fails if the key is absent — it simply falls back to the slower, 5-service behavior.

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## Known Issues



**NVD rate limiting** — without an API key, NIST NVD limits requests to ~5 per 30 seconds. The agent throttles requests (~6s apart) and retries on HTTP 403/429 to stay within this limit, capping lookups at 5 services per run by default. Set `NVD_API_KEY` (see [NVD API key & service coverage](#nvd-api-key--service-coverage-optional)) to raise the limit to ~50/30s, throttle faster, and lift the default cap to 25 services.

**CVE relevance** — the agent retrieves CVEs based on keyword search, not fingerprint matching. Some returned CVEs may not apply to the specific version detected. Results should be verified before acting on them.

**Subnet scanning** — CIDR notation is supported (e.g. 192.168.1.0/24) but results are degraded. The default nmap timeout of 120 seconds is insufficient to fingerprint service versions across a full subnet. Without version data, the CVE lookup has no search terms and returns zero findings. The report will reflect real host and port discovery but vulnerability analysis will be incomplete. For subnet scans, increase the timeout in tools.py and expect longer run times. Single target scanning is the validated use case.

---

## What's Next

- Replace keyword-based CVE lookup with `bind_tools()` structured tool calling — the LLM generates precise search parameters rather than free-text queries
- Add LangGraph check points so long scans can resume after interruption
- Expand tool nodes: Shodan lookup, banner grabbing, threat intel feeds
- PDF output — current reports render as Markdown; convert via Obsidian or any Markdown viewer
- Improve subnet scanning — increase timeout handling and version detection reliability across large ranges
- Perimeter scanning — extend agent to enumerate external attack surface
- Web UI — browser-based interface to submit targets and view reports



---

## Why This Project

Built as a portfolio demonstration of agentic AI applied to real security workflows. The goal was to understand the architecture from scratch — state management, conditional routing, LLM-as-orchestrator — not to wrap an existing tool. The security application is real; the agent found CVE-2021-44224 (CVSS 8.2) on a live test target on the first run.