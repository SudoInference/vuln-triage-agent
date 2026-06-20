# agent/tools.py
import subprocess
import json

def run_nmap(state: dict) -> dict:
    """Node: runs a basic nmap service scan against the target."""
    target = state["target"]
    messages = state.get("messages", [])
    
    try:
        # -sV = service version detection, -T4 = faster timing, --open = only open ports
        result = subprocess.run(
            ["nmap", "-sV", "-T4", "--open", target],
            capture_output=True, text=True, timeout=120
        )
        scan_output = result.stdout if result.stdout else result.stderr
    except FileNotFoundError:
        scan_output = "ERROR: nmap not found. Install nmap and ensure it's in your PATH."
    except subprocess.TimeoutExpired:
        scan_output = "ERROR: nmap scan timed out after 120 seconds."
    
    messages.append(f"[NMAP] Completed scan of {target}")
    return {"scan_results": scan_output, "messages": messages}


def lookup_cves(state: dict) -> dict:
    from langchain_ollama import ChatOllama
    from agent import nvd

    llm = ChatOllama(model="llama3.1:8b", base_url="http://localhost:11434")
    messages = state.get("messages", [])
    scan_results = state.get("scan_results", "")

    # Let the LLM extract clean search terms instead of regex
    response = llm.invoke(
f"""Extract service names and versions from this nmap output.
Respond with ONLY a JSON array of strings, no explanation, no markdown, no code fences.
Example output: ["OpenSSH 6.6.1", "Apache httpd 2.4.7"]

{scan_results}"""
    )


    try:
        services_to_search = json.loads(response.content.strip())
    except Exception:
        services_to_search = []

    # De-duplicate while preserving order, then cap at the key-aware ceiling.
    seen = set()
    unique_services = []
    for service in services_to_search:
        if service not in seen:
            seen.add(service)
            unique_services.append(service)

    max_services = nvd.get_max_services()
    services_to_query = unique_services[:max_services]

    cve_findings = []
    for service in services_to_query:
        cve_findings.extend(nvd.search_cves(service))

    cve_output = "\n".join(cve_findings) if cve_findings else "No CVEs found."

    key_status = "with API key" if nvd.has_api_key() else "no API key"
    skipped = len(unique_services) - len(services_to_query)
    summary = (
        f"[CVE LOOKUP] Found {len(cve_findings)} potential vulnerabilities "
        f"across {len(services_to_query)} service(s) ({key_status}"
    )
    if skipped > 0:
        summary += f"; {skipped} service(s) skipped over MAX_SERVICES limit"
    summary += ")"
    messages.append(summary)
    return {"cve_results": cve_output, "messages": messages}

def write_report(state: dict) -> dict:
    """Node: asks the LLM to synthesize everything into a findings report."""
    from langchain_ollama import ChatOllama
    
    llm = ChatOllama(model="llama3.1:8b", base_url="http://localhost:11434")
    messages = state.get("messages", [])
    
    prompt = f"""You are a security analyst. Write a professional vulnerability triage report based on the following data.

TARGET: {state['target']}

NMAP SCAN RESULTS:
{state.get('scan_results', 'No scan data')}

CVE FINDINGS:
{state.get('cve_results', 'No CVE data')}

Write the report with these sections:
1. Executive Summary (2-3 sentences)
2. Open Ports & Services
3. Vulnerability Findings (with severity ratings)
4. Recommended Remediation Steps
5. Risk Rating (Critical/High/Medium/Low) with justification

Be specific and actionable.

Do not use markdown tables. Use plain text lists instead.

"""

    response = llm.invoke(prompt)
    messages.append("[REPORT] Final report generated")
    return {"report": response.content, "messages": messages}