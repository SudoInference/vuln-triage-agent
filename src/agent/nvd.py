# agent/nvd.py
"""NIST NVD API client: key support, rate-limit throttling, and retry/backoff.

NVD enforces ~5 requests / 30s without an API key and ~50 / 30s with one.
This module centralizes all NVD access so the agent respects those limits
instead of tripping HTTP 403/429.
"""
import os
import time

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Conservative spacing between requests to stay under NVD's rolling window.
# Without a key: 30s / 5 req -> 6s. With a key: 30s / 50 req -> 0.6s (use 0.7 for margin).
_THROTTLE_NO_KEY_SECONDS = 6.0
_THROTTLE_WITH_KEY_SECONDS = 0.7

# Default service ceilings (overridable via MAX_SERVICES). Keyless default stays at
# the project's original 5 so existing behavior is preserved for most users.
_DEFAULT_MAX_SERVICES_NO_KEY = 5
_DEFAULT_MAX_SERVICES_WITH_KEY = 25

_MAX_RETRIES = 3

# Module-level timestamp of the last request, used to enforce spacing across the
# whole lookup loop (not just per-call).
_last_request_time = 0.0


def get_api_key() -> str | None:
    """Return the NVD API key from the environment, or None if unset/blank."""
    key = os.getenv("NVD_API_KEY", "").strip()
    return key or None


def has_api_key() -> bool:
    return get_api_key() is not None


def get_results_per_service() -> int:
    """How many CVEs to request per service (NVD resultsPerPage)."""
    try:
        return max(1, int(os.getenv("NVD_RESULTS_PER_SERVICE", "3")))
    except ValueError:
        return 3


def get_max_services() -> int:
    """Max services to triage per run.

    Explicit MAX_SERVICES wins. Otherwise the default is key-aware: 5 without a
    key (fast, safely under the strict free limit) and 25 with a key.
    """
    raw = os.getenv("MAX_SERVICES", "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return _DEFAULT_MAX_SERVICES_WITH_KEY if has_api_key() else _DEFAULT_MAX_SERVICES_NO_KEY


def _throttle() -> None:
    """Sleep just enough to keep request spacing under the NVD rate limit."""
    global _last_request_time
    min_interval = _THROTTLE_WITH_KEY_SECONDS if has_api_key() else _THROTTLE_NO_KEY_SECONDS
    elapsed = time.monotonic() - _last_request_time
    wait = min_interval - elapsed
    if wait > 0:
        time.sleep(wait)
    _last_request_time = time.monotonic()


def _format_finding(cve: dict) -> str:
    """Format one NVD CVE object into the report-compatible single-line string."""
    cve_id = cve.get("id", "Unknown")
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    metrics = cve.get("metrics", {})
    score = "N/A"
    if "cvssMetricV31" in metrics:
        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    return f"{cve_id} (CVSS: {score}): {desc[:200]}"


def search_cves(service: str) -> list[str]:
    """Look up CVEs for a single service string, honoring throttle + retries.

    Returns a list of formatted finding strings. On persistent failure (e.g.
    repeated rate-limiting), returns a single explanatory marker string instead
    of raising, so one bad lookup never aborts the whole run.
    """
    api_key = get_api_key()
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": service, "resultsPerPage": get_results_per_service()}

    backoff = _THROTTLE_NO_KEY_SECONDS
    for attempt in range(1, _MAX_RETRIES + 1):
        _throttle()
        try:
            resp = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=15)
        except requests.RequestException as exc:
            if attempt == _MAX_RETRIES:
                return [f"Lookup failed for '{service}': {exc}"]
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 200:
            return [
                _format_finding(v["cve"])
                for v in resp.json().get("vulnerabilities", [])
            ]

        # 403/429 mean we are being rate-limited; back off and retry.
        if resp.status_code in (403, 429) and attempt < _MAX_RETRIES:
            time.sleep(backoff)
            backoff *= 2
            continue

        return [f"Lookup failed for '{service}': HTTP {resp.status_code}"]

    return [f"Lookup failed for '{service}': exhausted retries"]
