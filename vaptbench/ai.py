"""AI layer — local-first, hybrid-ready.

Default backend is local Ollama on the Windows host (reachable from WSL).
A single env switch routes a task to a cloud backend (Claude API) instead,
so client data stays local by default but you can opt in to better quality
for a specific task like report writing.

Config via env:
    VAPT_AI_BACKEND   = local | cloud        (default local)
    VAPT_OLLAMA_URL   = http://localhost:11434
    VAPT_OLLAMA_MODEL = qwen2.5-coder:14b
    VAPT_CLOUD_KEY    = <anthropic api key>  (only if backend=cloud)
    VAPT_CLOUD_MODEL  = claude-opus-4-8
"""
import os
import json
import urllib.request

LOCAL = "local"
CLOUD = "cloud"


def _cfg():
    return {
        "backend": os.environ.get("VAPT_AI_BACKEND", LOCAL),
        "ollama_url": os.environ.get("VAPT_OLLAMA_URL", "http://localhost:11434"),
        "ollama_model": os.environ.get("VAPT_OLLAMA_MODEL", "qwen2.5-coder:14b"),
        "cloud_key": os.environ.get("VAPT_CLOUD_KEY", ""),
        "cloud_model": os.environ.get("VAPT_CLOUD_MODEL", "claude-opus-4-8"),
    }


def available():
    """Return (ok, message) for the active backend without raising."""
    c = _cfg()
    if c["backend"] == CLOUD:
        return (bool(c["cloud_key"]), "cloud backend" if c["cloud_key"] else "no VAPT_CLOUD_KEY set")
    try:
        req = urllib.request.Request(c["ollama_url"] + "/api/tags")
        with urllib.request.urlopen(req, timeout=3) as r:
            return (r.status == 200, "ollama reachable")
    except Exception as e:
        return (False, f"ollama unreachable: {e}")


def ask(prompt, system="", force_backend=None):
    """Send a prompt to the active (or forced) backend. Returns text."""
    c = _cfg()
    backend = force_backend or c["backend"]
    if backend == CLOUD:
        return _ask_cloud(prompt, system, c)
    return _ask_ollama(prompt, system, c)


def _ask_ollama(prompt, system, c):
    payload = {
        "model": c["ollama_model"],
        "prompt": prompt,
        "system": system,
        "stream": False,
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        c["ollama_url"] + "/api/generate", data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read()).get("response", "")


def _ask_cloud(prompt, system, c):
    if not c["cloud_key"]:
        return "[cloud backend selected but VAPT_CLOUD_KEY is not set]"
    payload = {
        "model": c["cloud_model"],
        "max_tokens": 2048,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=data,
        headers={
            "Content-Type": "application/json",
            "x-api-key": c["cloud_key"],
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        body = json.loads(r.read())
        return "".join(b.get("text", "") for b in body.get("content", []))
