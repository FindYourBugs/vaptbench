"""AI layer — local-first, hybrid-ready.

Default backend is local Ollama on the Windows host (reachable from WSL).
A single env switch routes a task to a cloud backend (Claude API) instead,
so client data stays local by default but you can opt in to better quality
for a specific task like report writing.

Config via env:
    VAPT_AI_BACKEND   = local | cloud        (default local)
    VAPT_OLLAMA_URL   = http://localhost:11434
    VAPT_OLLAMA_MODEL = qwen3:14b
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
        "ollama_model": os.environ.get("VAPT_OLLAMA_MODEL", "qwen3:14b"),
        "cloud_key": os.environ.get("VAPT_CLOUD_KEY", ""),
        "cloud_model": os.environ.get("VAPT_CLOUD_MODEL", "claude-opus-4-8"),
    }


# Different jobs want different models: a reasoning model (e.g. deepseek-r1:14b)
# for planning + critique, a security-tuned one (e.g. whiterabbitneo) for
# payloads, a fluent one for report prose. Each falls back to the base model,
# so a single VAPT_OLLAMA_MODEL still works with nothing else set.
_ROLE_ENV = {
    "reasoner": "VAPT_MODEL_REASONER",
    "payload":  "VAPT_MODEL_PAYLOAD",
    "writer":   "VAPT_MODEL_WRITER",
}


def _model_for(role, c=None):
    c = c or _cfg()
    if role and _ROLE_ENV.get(role):
        return os.environ.get(_ROLE_ENV[role], "") or c["ollama_model"]
    return c["ollama_model"]


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


def ask(prompt, system="", force_backend=None, role=None):
    """Send a prompt to the active (or forced) backend. Returns text.

    `role` ('reasoner'|'payload'|'writer') picks a per-job model when set.
    """
    c = _cfg()
    backend = force_backend or c["backend"]
    if backend == CLOUD:
        return _ask_cloud(prompt, system, c)
    return _ask_ollama(prompt, system, c, model=_model_for(role, c))


def ask_json(prompt, system="", force_backend=None, retries=2, role=None):
    """Ask the model for a JSON object and return it parsed (dict).

    Local models drift from strict JSON, so we (a) ask Ollama for JSON mode,
    (b) extract the first {...} block, and (c) retry with a repair nudge.
    Returns {} if it never produces valid JSON — callers must handle that.
    """
    c = _cfg()
    backend = force_backend or c["backend"]
    model = _model_for(role, c)
    sys = (system + "\n\nReply with ONE JSON object only. No prose, no markdown fences.").strip()
    last = ""
    for attempt in range(retries + 1):
        p = prompt if attempt == 0 else (
            prompt + f"\n\nYour previous reply was not valid JSON:\n{last[:400]}\n"
            "Reply again with ONE valid JSON object only.")
        try:
            raw = (_ask_ollama(p, sys, c, as_json=True, model=model) if backend == LOCAL
                   else _ask_cloud(p, sys, c))
        except Exception as e:
            last = f"backend error: {e}"
            continue
        last = raw
        obj = _extract_json(raw)
        if obj is not None:
            return obj
    return {}


def _extract_json(text):
    """Pull the first balanced {...} object out of a model reply."""
    if not text:
        return None
    text = text.strip()
    # Strip a leading ```json fence if present.
    if text.startswith("```"):
        text = text.split("```", 2)[1].lstrip("json").strip() if "```" in text[3:] else text[3:]
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except Exception:
                    return None
    return None


def _ask_ollama(prompt, system, c, as_json=False, model=None):
    payload = {
        "model": model or c["ollama_model"],
        "prompt": prompt,
        "system": system,
        "stream": False,
    }
    if as_json:
        payload["format"] = "json"      # Ollama constrains output to valid JSON
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        c["ollama_url"] + "/api/generate", data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=180) as r:
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
