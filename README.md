# Recon Reporter

An AI-assisted reconnaissance tool for authorized penetration testing labs (TryHackMe / HackTheBox / personal environments).

The tool combines deterministic Nmap parsing with an LLM mentor layer — the AI interprets findings and suggests next steps, but never fabricates CVEs and never runs exploits automatically.

```
nmap -sC -sV -oX scan.xml TARGET
           │
           ▼
     parser.py          ← deterministic: exact ports, services, NSE output
           │
           ▼
       llm.py           ← AI interprets, prioritizes, suggests commands
           │
      ┌────┴────┐
      ▼         ▼
recon_reporter  agent.py
  (static)      (agentic loop)
```

## Two modes

### 1. Static report — `recon_reporter.py`
Feed a completed Nmap XML scan and get a prioritized attack surface analysis in Markdown.

```bash
nmap -sC -sV -oX scan.xml 10.10.10.10
python recon_reporter.py scan.xml -o report.md
```

### 2. Agentic loop — `agent.py`
The AI decides the next recon command, you approve it, the tool runs it, and the output feeds back to the AI. Repeats until an exploit entry point is found — then hands off to you.

```bash
python agent.py 10.10.10.10
```

Every step requires your `[Enter]` approval. Destructive commands are blocked unconditionally even if approved. No exploit is executed automatically — the agent stops and tells you what to run.

## Setup

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # Windows
# cp .env.example .env   # Linux/macOS
```

Edit `.env` and set your backend:

```
LLM_BACKEND=haiku
ANTHROPIC_API_KEY=sk-ant-...
```

Test the connection:

```bash
python test_api.py
```

## Backend options

| `LLM_BACKEND` | Description | Cost |
|---|---|---|
| `stub` | No API — placeholder output for development | Free |
| `haiku` | Anthropic Claude Haiku via API | ~$0.001 / session |
| `ollama` | Local model via Ollama | Free (hardware) |

Get an API key at [console.anthropic.com](https://console.anthropic.com) → Settings → API Keys.
This is separate from a Claude Pro subscription.

## Project structure

```
recon-reporter/
├── agent.py            # Agentic recon loop (human-in-the-loop)
├── recon_reporter.py   # Static XML → Markdown report
├── llm.py              # Model-agnostic LLM layer (stub / haiku / ollama)
├── parser.py           # Nmap XML parser (deterministic)
├── test_api.py         # Verify API key and connection
├── sample_scan.xml     # Example scan — no setup required to test
├── requirements.txt
├── .env.example
└── .gitignore
```

## Security

- **Only use on authorized targets.** The tool asks for explicit authorization confirmation before each session.
- API keys go in `.env`, which is listed in `.gitignore` and never committed.
- The `DANGER` regex in `agent.py` blocks destructive commands (`rm -rf`, `dd`, `mkfs`, `curl | sh`, etc.) unconditionally, even if the user attempts to approve them.
