"""
test_api.py — Verify that your API key and connection work.

    python test_api.py

A green "SUCCESS" means you can switch to haiku mode in .env.
"""

import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

key = os.getenv("ANTHROPIC_API_KEY")
if not key:
    print("[X] ANTHROPIC_API_KEY not found.")
    print("    -> Open .env, paste your key, and save.")
    raise SystemExit(1)

print(f"[.] Key found (...{key[-4:]}). Testing API connection...")

try:
    from anthropic import Anthropic
    client = Anthropic()
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=20,
        messages=[{"role": "user", "content": "Reply with just 'OK'."}],
    )
    print("[+] SUCCESS! Model response:", msg.content[0].text.strip())
    print("    Set LLM_BACKEND=haiku in .env to use real analysis.")
except Exception as e:
    print("[X] FAILED:", type(e).__name__)
    print("   ", str(e)[:200])
    print("    -> Key may be invalid or account has no credits.")
    raise SystemExit(1)
