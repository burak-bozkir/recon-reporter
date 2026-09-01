"""
llm.py — Model-agnostic LLM layer (mentor mode + agentic mode).

Takes a full Nmap result (ports + NSE findings combined) and returns
prioritized attack steps — not a report, but a path forward.

Backend is selected via LLM_BACKEND in .env: stub | haiku | ollama
"""

import os
import json as _json

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BACKEND = os.getenv("LLM_BACKEND", "stub").lower()

# ── Mentor mode system prompt (Turkish — controls AI response language) ────────
SYSTEM_PROMPT = """Sen deneyimli bir sizma testi mentorusun. Sana bir hedefin
TAM Nmap sonucu verilecek: butun portlar, servisler ve NSE script bulgulari BIR ARADA.

Gorevin RAPOR YAZMAK DEGIL. Gorevin bir ogrenciye "simdi ne yapmali" diye YOL GOSTERMEK.

KURALLAR:
- BUTUNE bak. Servisleri tek tek izole etme; en umut vadeden saldiri yuzeyini sec.
- SONUC ODAKLI ol. Zaten BILDIGIMIZ seyi dogrulatma. Versiyon Nmap ciktisinda belliyse
  "nc/telnet ile versiyonu oku" gibi adimlar YAZMA. Bu yasak.
- NSE bulgularini oku ve ONA GORE yonlendir. Ornek: "Anonymous FTP login allowed"
  gorursen adim "ftp ile anonim gir ve dosyalari indir" olur, "versiyonu dogrula" DEGIL.
- ONCELIK SIRALA: en olasi giris noktasi once. "Once suna bakardim cunku..." dilinde konus.
- Her oneri icin TEK somut komut ver ve NEDEN'ini bir cumlede soyle.
- Web servisi (80/443) varsa dizin/dosya taramasi (gobuster/feroxbuster) neredeyse her
  zaman ilk adimdir; calisan uygulamayi/CMS'i bul, sonra ona gore exploit ara.
- CVE numarasi UYDURMA. Emin degilsen "searchsploit <urun> ile ara" de.
- Kendini TEKRAR ETME. Genel guvenlik nasihati verme. Kisa ve net ol.

CIKTI FORMATI (aynen boyle, Turkce):
## Genel Degerlendirme
(1-2 cumle: en kritik saldiri yuzeyi neresi)

## Oncelikli Adimlar
1. **[servis/port] - [ne yapilacak]**
   - Komut: `...`
   - Neden: (tek cumle)
2. ...
(en yuksek onceliklten dusuge, en fazla 5 adim)
"""


def _user_prompt(context: str) -> str:
    return f"{context}\n\nBu hedef icin oncelikli saldiri adimlarini mentor gibi ver."


def guide_host(context: str) -> str:
    """Receive full host context; return prioritized attack steps."""
    if BACKEND == "haiku":
        return _guide_haiku(context)
    if BACKEND == "ollama":
        return _guide_ollama(context)
    return _guide_stub(context)


# ── Stub (no API required) ────────────────────────────────────────────────────
def _guide_stub(context: str) -> str:
    return (
        "## Genel Degerlendirme\n"
        "_(STUB response — set LLM_BACKEND=haiku in .env for real analysis)_\n\n"
        "## Oncelikli Adimlar\n"
        "1. **Model will fill this in**\n"
        f"   - Context received:\n```\n{context}\n```"
    )


# ── Haiku (Anthropic API) ─────────────────────────────────────────────────────
def _guide_haiku(context: str) -> str:
    from anthropic import Anthropic

    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Add your key to .env "
            "(console.anthropic.com → Settings → API Keys)."
        )

    client = Anthropic()
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=1200,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _user_prompt(context)}],
    )
    return msg.content[0].text.strip()


# ── Ollama (local, free) ──────────────────────────────────────────────────────
def _guide_ollama(context: str) -> str:
    import requests
    model = os.getenv("OLLAMA_MODEL", "llama3.1")
    resp = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_prompt(context)},
            ],
        },
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()


# ===========================================================================
# AGENTIC MODE — decides the single next recon command (returns JSON)
# ===========================================================================

# System prompt in Turkish — AI responds in Turkish ────────────────────────────
NEXT_SYSTEM = """Sen YETKILI bir lab hedefinde calisan otonom bir KESIF ajanisin.
Gorev tanimi: hedefte ACIK NOKTAYI BULMAK ve insana teslim etmek.
Exploit CALISTIRMAK senin gorevIN DEGIL — o isi insan yapar.

Sana simdiye kadar toplanan TUM bulgular (calistirilan komutlar ve ciktilari) verilir.
Gorevin: calistirilacak TEK bir sonraki KESIF komutuna karar vermek.

CIKTI: SADECE gecerli JSON, hicbir aciklama ekleme:
{"thought": "...", "command": "...", "done": false}

=== DONE=TRUE — GOREV TAMAMLANDI, TESLIM ET ===

Su kosullardan BIRI saglaninca ANINDA done=true yap ve dur:

1. SEARCHSPLOIT MATCH — searchsploit ciktisinda hedef versiyonuyla eslesen
   bir exploit path goruluyorsa (orn: "< 2.2.10" yaziyorsa ve hedef 2.2.8 ise).
   EXPLOIT CALISTIRMA. done=true yap, thought icine TAM TESLIM MESAJI yaz:

   "EXPLOIT DOGRU — erisim alabilirsin.
    Hedef   : [uygulama] [versiyon] @ http://[ip]/[yol]
    Zafiyet : [zafiyet adi] (searchsploit path: [path])
    Calistir: [tam komut — hangi script, hangi parametreler]"

2. KIMLIK BILGISI — kullanici adi + sifre / hash bulunduysa.
   done=true, thought:
   "KIMLIK BILGISI BULUNDU.
    Kullanici: [user]  Sifre/Hash: [deger]
    Giris dene: ssh [user]@[ip] -p [port]"

3. RCE / FILE UPLOAD — dogrulanmis kod calistirma vektoru varsa.
   done=true, thought: vektoru ve nasil tetiklenecegini yaz.

4. ADIM LIMITI — 14+ adim gecildi VE en net yol belliyse.
   done=true, thought: o yolu ve siradaki komutu yaz.

=== ASLA YAPMA ===

- Exploit script CALISTIRMA (python exploit.py, ruby, perl vs.) — senin gorev DEGIL.
- Exploit bulduktan sonra baska kesif komutu onerme — done=true olmalisin.
- Timeout veren komutu/URL'yi tekrar onerme ("[!] timeout" goruyorsan o yolu birak).
- "[bos cikti]" veren URL'yi tekrar deneme (2+ bos = birak).
- Nmap'te belli olan versiyonu nc/telnet ile "dogrulama".
- Ayni komutu tekrar onerme.
- JSON disinda tek kelime yazma.

=== NORMAL AKIS ===

Mantikli zincir:
  nmap (portlar+versiyon) -> web varsa feroxbuster (dizin bul) ->
  CMS/uygulama versiyonu ogren -> searchsploit -> DONE (teslim et)

- Sadece KESIF araclari: nmap, gobuster, feroxbuster, curl, whatweb,
  nikto, ftp, smbclient, enum4linux, searchsploit, dig, wpscan.
- Yikici komut YOK (rm -rf, dd, mkfs, curl|sh vs.).
- NSE ipuclarini (ftp-anon, robots.txt) hemen degerlendir.
- Hedef IP'yi history'den al; "<target>" placeholder YAZMA.
- CVE numarasi UYDURMA — sadece searchsploit ile dogrula."""


def _parse_decision(raw: str) -> dict:
    """Extract JSON from model output. Returns a safe fallback on parse failure."""
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        data = _json.loads(raw[start:end])
        return {
            "thought": str(data.get("thought", "")).strip(),
            "command": str(data.get("command", "")).strip(),
            "done": bool(data.get("done", False)),
        }
    except Exception:
        return {"thought": f"JSON parse failed: {raw[:200]}", "command": "", "done": True}


def next_step(history: str) -> dict:
    """Return the AI's decision for the next recon command."""
    if BACKEND == "haiku":
        return _parse_decision(_next_haiku(history))
    if BACKEND == "ollama":
        return _parse_decision(_next_ollama(history))
    return _next_stub(history)


def _next_haiku(history: str) -> str:
    from anthropic import Anthropic
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY not set. Add it to .env.")
    client = Anthropic()
    msg = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=600,
        system=NEXT_SYSTEM,
        messages=[{"role": "user", "content": history + "\n\nSiradaki komut (JSON):"}],
    )
    return msg.content[0].text.strip()


def _next_ollama(history: str) -> str:
    import requests
    model = os.getenv("OLLAMA_MODEL", "llama3.1")
    resp = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": NEXT_SYSTEM},
                {"role": "user", "content": history + "\n\nSiradaki komut (JSON):"},
            ],
        },
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"].strip()


def _next_stub(history: str) -> dict:
    """Stub for development — suggests one nmap command then finishes."""
    if "STUB-NMAP-DONE" not in history:
        return {
            "thought": "stub: run a port scan first",
            "command": "echo 'STUB-NMAP-DONE port 80 open'",
            "done": False,
        }
    return {
        "thought": "stub: enough info gathered — handing off to operator.",
        "command": "",
        "done": True,
    }
