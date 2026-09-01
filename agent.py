"""
agent.py — Human-approved autonomous recon agent.

The AI decides the next command, you approve it, the tool runs it,
and the output feeds back to the AI — building a real recon chain.

    python agent.py 10.10.10.10

At each step:
    [Enter] run  |  [e] edit  |  [s] skip  |  [q] quit

SECURITY:
    - Use only on AUTHORIZED targets (THM / HTB / personal lab).
      The tool asks for explicit confirmation before starting.
    - Every command requires your approval — nothing runs automatically.
    - Destructive commands (rm -rf, dd, mkfs, curl|sh, …) are blocked
      unconditionally, even if you attempt to approve them.
    - No automated exploit execution — the agent stops when it finds
      an exploit entry point and hands off to you.
"""

import argparse
import html as _html
import re
import subprocess
import sys
import datetime as dt

from llm import next_step, BACKEND

# ── Safety net: blocked regardless of user approval ───────────────────────────
DANGER = re.compile(
    r"\b(rm\s+-rf|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|halt|"
    r"mv\s+/|>\s*/dev/sd|chmod\s+-R\s+777\s+/|wget.*\|\s*sh|curl.*\|\s*sh)\b",
    re.I,
)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_OUTPUT = 2000   # max characters fed back to the AI per step
MAX_STEPS  = 20     # infinite-loop guard
HISTORY_COMPRESS_AFTER = 6   # older steps are summarized after this point

# ── Per-tool timeouts (seconds) ───────────────────────────────────────────────
TOOL_TIMEOUTS = {
    "ftp":          30,    # active-mode FTP stalls on VPN NAT — fail fast
    "nikto":        90,
    "gobuster":     90,
    "feroxbuster":  90,
    "nmap":        240,
    "wpscan":       60,
    "sqlmap":      180,
}
DEFAULT_TIMEOUT = 120


def _timeout_for(cmd: str) -> int:
    """Return the appropriate timeout for the given shell command."""
    first = cmd.strip().split()[0] if cmd.strip() else ""
    return TOOL_TIMEOUTS.get(first, DEFAULT_TIMEOUT)


# ── Python-side searchsploit detection ────────────────────────────────────────
_EXPLOIT_PATH_RE = re.compile(
    r"(php/webapps/\S+|linux/local/\S+|linux/remote/\S+|"
    r"multiple/\S+|unix/\S+|windows/\S+)"
)


def _detect_exploit_hit(cmd: str, output: str) -> str | None:
    """
    Detect a searchsploit match from command output without relying on the AI.
    Returns a human-readable summary if an exploit path is found, else None.
    """
    if "searchsploit" not in cmd.lower():
        return None
    paths = _EXPLOIT_PATH_RE.findall(output)
    paths = [p for p in paths if "." in p]
    if not paths:
        return None
    path_list = "\n  ".join(paths[:5])
    return (
        f"EXPLOIT DOGRU — erisim alabilirsin.\n"
        f"  Bulunan exploit(ler):\n  {path_list}\n"
        f"  Tam path: /usr/share/exploitdb/exploits/{paths[0]}\n"
        f"  Nasil calistirirsin bak: cat /usr/share/exploitdb/exploits/{paths[0]}"
    )


# ── History compression ────────────────────────────────────────────────────────
def _compress_history(history_blocks: list[str], keep_last: int = 5) -> str:
    """
    Summarize old steps to reduce token cost from O(n²) to O(n).
    Keeps the last `keep_last` steps in full; earlier steps become one-liners.
    """
    if len(history_blocks) <= keep_last:
        return "\n".join(history_blocks)

    old   = history_blocks[:-keep_last]
    fresh = history_blocks[-keep_last:]

    summary_lines = []
    for block in old:
        lines = block.strip().splitlines()
        cmd_line = next((l for l in lines if l.startswith("$")), "")
        out_line = next((l for l in lines if l and not l.startswith("$")), "")
        if cmd_line:
            summary_lines.append(f"  {cmd_line}  →  {out_line[:120]}")

    summary = "[OZET — onceki adimlar]\n" + "\n".join(summary_lines)
    return summary + "\n\n[SON ADIMLAR — tam]\n" + "\n".join(fresh)


# ── Command execution ─────────────────────────────────────────────────────────
def run_command(cmd: str) -> str:
    """Run a shell command with per-tool timeout; return combined stdout+stderr."""
    timeout = _timeout_for(cmd)
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        out = f"[!] Command timed out after {timeout}s."
    except Exception as e:
        out = f"[!] Execution error: {e}"
    out = out.strip() or "[empty output]"
    if len(out) > MAX_OUTPUT:
        half = MAX_OUTPUT // 2
        out = out[:half] + "\n...[truncated]...\n" + out[-half:]
    return out


# ── Authorization check ───────────────────────────────────────────────────────
def confirm_authorized(target: str) -> bool:
    print(f"\n[!] Target: {target}")
    print("    Do you confirm you are AUTHORIZED to test this target?")
    print("    (THM/HTB/your own lab = yes.  Someone else's system = NO, illegal.)")
    return input("    I am authorized, continue [yes/no]: ").strip().lower() in (
        "yes", "y", "e", "evet"
    )


# ── HTML report generator ─────────────────────────────────────────────────────
def generate_html_report(
    target: str,
    backend: str,
    started_at: dt.datetime,
    steps: list[dict],
    result_summary: str,
    out_path: str,
) -> None:
    """
    Write a self-contained HTML session report.

    Each entry in `steps` is a dict:
        {"num": int, "thought": str, "cmd": str, "output": str,
         "status": "run" | "skip" | "blocked" | "done"}
    """

    def e(s: str) -> str:
        return _html.escape(str(s))

    exploit_found = "EXPLOIT DOGRU" in result_summary or "KIMLIK BILGISI" in result_summary
    result_class  = "result-exploit" if exploit_found else "result-info"
    result_icon   = "🎯" if exploit_found else "ℹ️"

    step_cards = []
    for s in steps:
        status = s.get("status", "run")
        num    = s["num"]
        thought = s.get("thought", "")
        cmd    = s.get("cmd", "")
        output = s.get("output", "")

        status_label = {
            "run":     ("✅ Executed",  "card-run"),
            "skip":    ("⏭️ Skipped",  "card-skip"),
            "blocked": ("🚫 Blocked",  "card-blocked"),
            "done":    ("🏁 Finished", "card-done"),
        }.get(status, ("▶️ Executed", "card-run"))

        output_section = ""
        if output and status not in ("skip", "blocked", "done"):
            output_section = f"""
        <div class="output-toggle" onclick="toggleOutput(this)">▼ Show / hide output</div>
        <pre class="cmd-output hidden">{e(output)}</pre>"""

        cmd_section = f'<div class="cmd-line">$ {e(cmd)}</div>' if cmd else ""

        step_cards.append(f"""
      <div class="step-card {status_label[1]}">
        <div class="step-header">
          <span class="step-num">Step {num}</span>
          <span class="step-status">{status_label[0]}</span>
        </div>
        <div class="thought">💭 {e(thought)}</div>
        {cmd_section}
        {output_section}
      </div>""")

    steps_html = "\n".join(step_cards)
    finished_at = dt.datetime.now()
    duration    = int((finished_at - started_at).total_seconds())
    run_count   = sum(1 for s in steps if s.get("status") == "run")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {e(target)}</title>
<style>
  :root {{
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --red:     #f85149;
    --yellow:  #d29922;
    --muted:   #8b949e;
    --text:    #e6edf3;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px; line-height: 1.6; padding: 2rem;
  }}
  .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 1.8rem; color: var(--accent); letter-spacing: 1px; }}
  .meta-row {{ display: flex; flex-wrap: wrap; gap: 1.5rem; margin-top: 0.75rem; }}
  .meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
  .meta-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; }}
  .meta-value {{ font-weight: 600; font-family: monospace; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat-box {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.5rem; min-width: 130px; text-align: center;
  }}
  .stat-num {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
  .stat-label {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
  .result-box {{
    border-radius: 8px; padding: 1.25rem 1.5rem; margin-bottom: 2rem;
    border: 1px solid; white-space: pre-wrap;
    font-family: monospace; font-size: 13px; line-height: 1.7;
  }}
  .result-exploit {{ background: rgba(248,81,73,0.08); border-color: var(--red); }}
  .result-info    {{ background: rgba(88,166,255,0.08); border-color: var(--accent); }}
  .result-title {{ font-size: 1rem; font-weight: 700; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; }}
  h2 {{ font-size: 1.1rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 1rem; padding-bottom: 0.4rem; border-bottom: 1px solid var(--border); }}
  .steps {{ display: flex; flex-direction: column; gap: 0.75rem; }}
  .step-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.25rem; border-left-width: 4px;
  }}
  .card-run     {{ border-left-color: var(--green); }}
  .card-skip    {{ border-left-color: var(--muted); opacity: 0.7; }}
  .card-blocked {{ border-left-color: var(--red);   opacity: 0.7; }}
  .card-done    {{ border-left-color: var(--accent); }}
  .step-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }}
  .step-num    {{ font-weight: 700; color: var(--accent); }}
  .step-status {{ font-size: 12px; color: var(--muted); }}
  .thought {{ color: var(--muted); font-style: italic; margin-bottom: 0.5rem; }}
  .cmd-line {{
    font-family: monospace; background: var(--bg); border-radius: 4px;
    padding: 0.4rem 0.7rem; color: var(--green); margin-bottom: 0.5rem; word-break: break-all;
  }}
  .output-toggle {{ font-size: 12px; color: var(--accent); cursor: pointer; user-select: none; margin-bottom: 4px; }}
  .output-toggle:hover {{ text-decoration: underline; }}
  .cmd-output {{
    background: var(--bg); border: 1px solid var(--border); border-radius: 4px;
    padding: 0.6rem 0.8rem; font-size: 12px; white-space: pre-wrap;
    word-break: break-all; max-height: 400px; overflow-y: auto; color: #cdd9e5;
  }}
  .hidden {{ display: none; }}
  .footer {{ margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; font-size: 12px; color: var(--muted); text-align: center; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Recon Reporter</h1>
  <div class="meta-row">
    <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{e(target)}</span></div>
    <div class="meta-item"><span class="meta-label">Started</span><span class="meta-value">{started_at:%Y-%m-%d %H:%M}</span></div>
    <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{duration // 60}m {duration % 60}s</span></div>
    <div class="meta-item"><span class="meta-label">Backend</span><span class="meta-value">{e(backend)}</span></div>
  </div>
</div>
<div class="stats">
  <div class="stat-box"><div class="stat-num">{len(steps)}</div><div class="stat-label">Total steps</div></div>
  <div class="stat-box"><div class="stat-num">{run_count}</div><div class="stat-label">Executed</div></div>
  <div class="stat-box"><div class="stat-num">{sum(1 for s in steps if s.get("status") == "skip")}</div><div class="stat-label">Skipped</div></div>
  <div class="stat-box"><div class="stat-num">{sum(1 for s in steps if s.get("status") == "blocked")}</div><div class="stat-label">Blocked</div></div>
</div>
<div class="result-box {result_class}">
  <div class="result-title">{result_icon} Result</div>{e(result_summary) if result_summary else "Session complete."}
</div>
<h2>Steps</h2>
<div class="steps">
{steps_html}
</div>
<div class="footer">
  Recon Reporter — use only on authorized targets (THM / HTB / personal lab).
</div>
<script>
  function toggleOutput(el) {{
    const pre = el.nextElementSibling;
    if (pre) pre.classList.toggle('hidden');
    el.textContent = pre && pre.classList.contains('hidden')
      ? '▼ Show / hide output' : '▲ Hide output';
  }}
</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML report: {out_path}")


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Human-approved autonomous recon agent")
    ap.add_argument("target", help="Target IP (authorized lab only)")
    ap.add_argument("-o", "--out", default="agent_transcript.md",
                    help="Session log file (default: agent_transcript.md)")
    args = ap.parse_args()

    if not confirm_authorized(args.target):
        print("[x] Aborted. Use only on authorized targets.")
        sys.exit(1)

    print(f"\n[*] Agent starting (backend: {BACKEND}). Press q to quit.\n")

    started_at      = dt.datetime.now()
    history_blocks: list[str] = [f"Target IP: {args.target}\nNo commands run yet."]
    transcript      = [
        f"# Agent Session — {args.target}",
        f"_{started_at:%Y-%m-%d %H:%M}_  backend=`{BACKEND}`\n",
    ]
    steps: list[dict] = []
    result_summary  = ""

    safe_ip  = args.target.replace(".", "_")
    html_out = f"recon_{safe_ip}_{started_at:%Y%m%d_%H%M}.html"

    for step in range(1, MAX_STEPS + 1):
        history = _compress_history(history_blocks) + f"\n[Step {step}/{MAX_STEPS}]"

        print(f"[AI] Step {step}: deciding next command...")
        try:
            decision = next_step(history)
        except Exception as e:
            print(f"[x] AI error: {e}")
            break

        thought = decision["thought"]
        cmd     = decision["command"]

        if decision["done"] or not cmd:
            print(f"\n[DONE] Agent finished:\n{thought}")
            transcript.append(f"## Result\n{thought}\n")
            result_summary = thought
            steps.append({"num": step, "thought": thought, "cmd": "", "output": "", "status": "done"})
            break

        print(f"\n  Thought: {thought}")
        print(f"  $ {cmd}")

        if DANGER.search(cmd):
            print("  [x] Destructive command — BLOCKED.")
            history_blocks.append(f"[BLOCKED] {cmd}")
            steps.append({"num": step, "thought": thought, "cmd": cmd, "output": "", "status": "blocked"})
            continue

        choice = input("  [Enter]=run  [e]=edit  [s]=skip  [q]=quit: ").strip().lower()
        if choice == "q":
            print("[*] Quitting.")
            break
        if choice == "s":
            history_blocks.append(f"[SKIPPED] {cmd}")
            transcript.append(f"### Step {step} (skipped)\n{thought}\n`{cmd}`\n")
            steps.append({"num": step, "thought": thought, "cmd": cmd, "output": "", "status": "skip"})
            continue
        if choice == "e":
            cmd = input("  New command: ").strip()
            if not cmd:
                continue
            if DANGER.search(cmd):
                print("  [x] Destructive — blocked.")
                continue

        timeout = _timeout_for(cmd)
        print(f"  Running... (max {timeout}s)")
        output = run_command(cmd)
        print("  ── output ──")
        print("  " + output.replace("\n", "\n  ")[:1500])
        print("  ────────────")

        exploit_msg = _detect_exploit_hit(cmd, output)
        if exploit_msg:
            output += (
                "\n[!!SEARCHSPLOIT HIT!!] Exploit found — agent stopping.\n"
                + exploit_msg
            )

        history_blocks.append(f"$ {cmd}\n{output}")
        transcript.append(f"### Step {step}\n{thought}\n\n```\n$ {cmd}\n{output}\n```\n")
        steps.append({"num": step, "thought": thought, "cmd": cmd, "output": output, "status": "run"})

        if exploit_msg:
            print(f"\n[DONE] Exploit found — stopping:\n{exploit_msg}")
            transcript.append(f"## Result\n{exploit_msg}\n")
            result_summary = exploit_msg
            with open(args.out, "w", encoding="utf-8") as f:
                f.write("\n".join(transcript))
            generate_html_report(args.target, BACKEND, started_at, steps, result_summary, html_out)
            print(f"[+] Session log: {args.out}")
            return

        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(transcript))
    else:
        result_summary = f"Reached {MAX_STEPS}-step limit."
        print(f"\n[*] {result_summary}")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(transcript))
    generate_html_report(args.target, BACKEND, started_at, steps, result_summary, html_out)
    print(f"[+] Session log: {args.out}")


if __name__ == "__main__":
    main()
