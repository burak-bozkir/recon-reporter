"""
recon_reporter.py — Static Nmap XML analysis with AI mentor guidance.

Usage:
    python recon_reporter.py scan.xml -o report.md

Workflow:
    Nmap XML (ports + NSE)  ->  parser (structured context)  ->  AI mentor  ->  report.md
"""

import argparse
import datetime as dt

from parser import parse_nmap_xml
from llm import guide_host, BACKEND


def build_guidance(xml_path: str) -> str:
    hosts = parse_nmap_xml(xml_path)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")

    out = []
    out.append("# Recon Report — Next Steps\n")
    out.append(
        f"- **Source:** `{xml_path}`  |  **Time:** {now}  |  **Backend:** `{BACKEND}`\n"
    )
    out.append(
        "> ⚠️  Use only on authorized targets (THM / HTB / personal lab). "
        "AI suggestions are starting points — review each command before running it.\n"
    )
    out.append("---\n")

    for host in hosts:
        title = host.hostname or host.ip
        out.append(f"## Target: {title} (`{host.ip}`)\n")

        if not host.open_services:
            out.append("_No open services found._\n")
            continue

        # Include raw context for transparency and learning
        out.append("<details><summary>Nmap context sent to AI</summary>\n")
        out.append("```\n" + host.context_block() + "\n```\n</details>\n")

        print(f"[AI] Generating guidance for {title}...")
        try:
            guidance = guide_host(host.context_block())
        except Exception as e:
            guidance = f"_Analysis failed: {e}_"
        out.append(guidance)
        out.append("\n---\n")

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="Generate AI mentor guidance from an Nmap XML scan."
    )
    ap.add_argument("xml", help="Nmap XML file (produced with nmap -sC -sV -oX)")
    ap.add_argument("-o", "--out", default="report.md", help="Output file (default: report.md)")
    args = ap.parse_args()

    text = build_guidance(args.xml)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"\n[+] Report written: {args.out}")


if __name__ == "__main__":
    main()
