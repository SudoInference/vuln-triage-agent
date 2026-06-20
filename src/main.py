# main.py
import os
import sys
from dotenv import load_dotenv
from agent.graph import build_graph

# Load .env (NVD_API_KEY, MAX_SERVICES, etc.) before anything reads the environment.
load_dotenv()

def run_triage(target: str, graph=None):
    # Build the graph once and reuse it across targets when caller supplies one.
    if graph is None:
        graph = build_graph()

    initial_state = {
        "target": target,
        "scan_results": None,
        "cve_results": None,
        "report": None,
        "next_action": None,
        "messages": []
    }
    
    print(f"\n Starting vulnerability triage for: {target}\n")
    
    # stream_mode="values" prints state after every node execution
    for step, state in enumerate(graph.stream(initial_state, stream_mode="values")):
        # Print the latest log message if there is one
        messages = state.get("messages", [])
        if messages:
            print(f"  {messages[-1]}")
        
        # Stop if we hit a runaway loop (safety valve)
        if step > 20:
            print("Safety limit reached — stopping.")
            break
    
    # Print final report
    final_report = state.get("report", "No report generated.")
    print("\n" + "="*60)
    print("FINAL VULNERABILITY TRIAGE REPORT")
    print("="*60)
    print(final_report)
    
    from datetime import datetime
    os.makedirs("reports", exist_ok=True)
    #filename_base = f"reports/report_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}"

    safe_target = target.replace('.', '_').replace('/', '_')
    filename_base = f"reports/report_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M')}"

    report_path = f"{filename_base}.md"
    with open(report_path, "w") as f:
        f.write(f"# Vulnerability Triage Report\n**Target:** {target}\n\n")
        f.write(final_report)
        f.write("\n\n---\n")
        f.write("_This product uses the NVD API but is not endorsed or certified by the NVD._\n")


    print(f"\n Markdown saved: {report_path}")

    return report_path


def parse_targets_file(path: str) -> list:
    """Read targets from a file: one per line, skipping blanks and # comments."""
    with open(path) as f:
        lines = f.readlines()
    targets = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            targets.append(stripped)
    return targets


def collect_targets(positional: list, file_path: str) -> list:
    """Combine positional targets and file targets, de-duplicated, order preserved."""
    combined = list(positional)
    if file_path:
        combined.extend(parse_targets_file(file_path))

    seen = set()
    ordered = []
    for target in combined:
        if target not in seen:
            seen.add(target)
            ordered.append(target)
    return ordered


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Autonomous vulnerability triage agent. Accepts one or more "
                    "targets (IP, hostname, or CIDR) and writes one report per target."
    )
    parser.add_argument(
        "targets", nargs="*",
        help="One or more targets (IP, hostname, or CIDR network). "
             "Defaults to 127.0.0.1 if none are given.",
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to a file with one target per line (# comments and blanks ignored).",
    )
    args = parser.parse_args()

    if args.file and not os.path.isfile(args.file):
        print(
            f"ERROR: target file not found: {args.file}\n"
            "Copy targets.example.txt to targets.txt and add one target per line, e.g.:\n"
            "    cp targets.example.txt targets.txt"
        )
        sys.exit(1)

    targets = collect_targets(args.targets, args.file)
    if not targets:
        targets = ["127.0.0.1"]

    # Build the graph once and reuse it for every target.
    graph = build_graph()

    results = []  # (target, report_path_or_None, error_or_None)
    for target in targets:
        try:
            report_path = run_triage(target, graph=graph)
            results.append((target, report_path, None))
        except Exception as exc:
            # Isolate failures so one bad target does not abort the whole batch.
            print(f"\n ERROR triaging {target}: {exc}")
            results.append((target, None, str(exc)))

    print("\n" + "=" * 60)
    print(f"RUN SUMMARY — {len(results)} target(s)")
    print("=" * 60)
    for target, report_path, error in results:
        if error:
            print(f"  [FAILED] {target}: {error}")
        else:
            print(f"  [OK]     {target} -> {report_path}")


if __name__ == "__main__":
    main()
