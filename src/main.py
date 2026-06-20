# main.py
import os
from dotenv import load_dotenv
from agent.graph import build_graph

# Load .env (NVD_API_KEY, MAX_SERVICES, etc.) before anything reads the environment.
load_dotenv()

def run_triage(target: str):
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

    with open(f"{filename_base}.md", "w") as f:
        f.write(f"# Vulnerability Triage Report\n**Target:** {target}\n\n")
        f.write(final_report)
        f.write("\n\n---\n")
        f.write("_This product uses the NVD API but is not endorsed or certified by the NVD._\n")


    print(f"\n Markdown saved: {filename_base}.md")  

    return state

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_triage(target)
