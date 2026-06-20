# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Version tags are applied at release (merge) time.

## [0.2.0] - unreleased

### Added
- Optional NVD API key support via `NVD_API_KEY`, raising the NVD limit from
  ~5 to ~50 requests / 30s.
- Request throttling and retry/backoff on HTTP 403/429 for all NVD lookups,
  centralized in `src/agent/nvd.py`.
- Configurable CVE coverage: `MAX_SERVICES` (default 5 without a key, 25 with one)
  and `NVD_RESULTS_PER_SERVICE` (default 3).
- Multiple-target input: pass several targets as arguments or via `--file`
  (one per line; blank lines and `#` comments ignored). Each target is triaged
  independently into its own report, with an end-of-run summary.
- `targets.example.txt` template for the gitignored `targets.txt` list.
- `AGENTS.md` project guide and `docs/network-triage-roadmap.md` long-term plan.

### Changed
- Replaced the hard-coded 5-service CVE lookup cap with the key-aware,
  configurable `MAX_SERVICES` limit.
- `.env` is loaded at startup so `NVD_API_KEY` / `MAX_SERVICES` are honored.
- Added the required NVD API attribution notice to the README and to every
  generated report.

## [0.1.0] - baseline

- Initial working release: a planner-executor LangGraph agent that scans a single
  target with nmap, looks up CVEs via the NIST NVD API, and writes a Markdown
  vulnerability triage report. Runs locally on Ollama (Llama 3.1 8B).
