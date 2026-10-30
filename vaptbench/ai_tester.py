"""Phase 2 AI layer — payload crafting and finding write-ups.

Design rule: the AI never confirms a vulnerability. It only
  (a) proposes extra payloads to try — a payload "counts" only if it then trips
      a deterministic verifier (so AI widens coverage, verifiers keep truth), and
  (b) improves the prose of an already-confirmed finding.
Everything here is best-effort: if the model is offline or returns junk, the
engine carries on with its deterministic results.
"""
import re
from . import ai

MAX_PAYLOADS = 8


def _lines(text):
    out = []
    for ln in (text or "").splitlines():
        ln = ln.strip().strip("`").strip()
        ln = re.sub(r"^\d+[.)]\s*", "", ln)       # strip list numbering
        if ln and len(ln) < 300:
            out.append(ln)
    return out[:MAX_PAYLOADS]


def extra_payloads(vuln_class, skill_body, sample_value=""):
    """Ask the model for extra injection payloads for a class, grounded in the
    matching hunt-* skill. Returned payloads are only ever *tried* — a verifier
    still has to confirm the result."""
    ok, _ = ai.available()
    if not ok:
        return []
    system = ("You are a web pentest payload generator. Output ONLY raw payloads, "
              "one per line, no prose, no numbering, no code fences. Payloads must be "
              "non-destructive (read/prove only).")
    prompt = (f"Vulnerability class: {vuln_class}\n"
              f"Parameter current value: {sample_value!r}\n"
              f"Methodology excerpt:\n{(skill_body or '')[:3000]}\n\n"
              "Give up to 8 distinct payloads to test this parameter.")
    try:
        return _lines(ai.ask(prompt, system=system))
    except Exception:
        return []


def writeup(finding, skill_body=""):
    """Improve a confirmed finding's description/steps. Returns a dict of fields
    to update, or {} on any failure. Never invents evidence."""
    ok, _ = ai.available()
    if not ok:
        return {}
    system = ("You are writing a penetration-test finding. Be precise and factual. "
              "Do NOT invent impact beyond the evidence given. Return three labelled "
              "sections exactly: DESCRIPTION:, IMPACT:, REMEDIATION: — plain text.")
    prompt = (f"Title: {finding.get('title')}\n"
              f"Class: {finding.get('vuln_class')}  Severity: {finding.get('severity')}\n"
              f"Evidence (PoC response):\n{(finding.get('poc_response') or '')[:1500]}\n"
              f"Methodology excerpt:\n{(skill_body or '')[:1500]}\n\n"
              "Write the finding.")
    try:
        text = ai.ask(prompt, system=system)
    except Exception:
        return {}
    if not text or len(text) < 40:
        return {}
    # Fold the AI prose into description, keep the proven steps/PoC intact.
    return {"description": (finding.get("description", "") + "\n\n--- AI write-up ---\n" + text).strip()}
