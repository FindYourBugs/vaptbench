"""CSRF and session-token weaknesses.

Cross-site request forgery can't be *executed* headless (it needs a second
origin and a victim browser), so a missing-token signal is reported as
needs-review — honest, not asserted. The signal is strong when a state-changing
POST form carries no anti-CSRF token AND the session cookie isn't SameSite-
restricted (so a cross-site POST would ride the cookie).

Session-token weaknesses (short / low-entropy session identifiers) are likewise
reported as needs-review supporting evidence.
"""
import math
import re
from collections import Counter

_TOKEN_RE = re.compile(
    r"csrf|xsrf|_token\b|authenticity|nonce|verificationtoken|anti.?forgery", re.I)
_SESSION_RE = re.compile(r"(sess|sid|auth|token|jwt|login|phpsessid|jsessionid|asp\.net)", re.I)


def _f(title, cls, sev, desc, steps, req, resp):
    return dict(title=title, vuln_class=cls, severity=sev, confidence="needs-review",
                cvss="", description=desc, steps=steps, poc_request=req,
                poc_response=(resp or "")[:800])


def _samesite_restricted(set_cookie):
    low = (set_cookie or "").lower()
    return "samesite=strict" in low or "samesite=lax" in low


def check_csrf(form, set_cookie=""):
    """form: {action, inputs, method?}. set_cookie: the app's Set-Cookie line."""
    inputs = form.get("inputs") or {}
    if not inputs:
        return []
    if any(_TOKEN_RE.search(k) for k in inputs):
        return []                                   # token field present -> protected
    samesite = _samesite_restricted(set_cookie)
    sev = "low" if samesite else "medium"
    note = ("the session cookie is SameSite-restricted, which mitigates classic CSRF — verify no "
            "cross-site vector remains" if samesite else
            "the session cookie is NOT SameSite-restricted, so a cross-site POST would carry it")
    return [_f(
        f"Potential CSRF (no anti-CSRF token): POST {form.get('action')}",
        "hunt-csrf", sev,
        f"The state-changing POST form at {form.get('action')} (fields {list(inputs)}) carries no "
        f"anti-CSRF token field, and {note}. Execution can't be proven without a browser and a second "
        f"origin — confirm the request succeeds cross-site.",
        f"Build an off-site HTML form POSTing to {form.get('action')} with the same fields; submit it "
        f"while authenticated.",
        f"POST {form.get('action')}  fields={list(inputs)}", "")]


def _entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def check_session_token(set_cookie):
    """Flag a session identifier that is short or low-entropy (guessable)."""
    out = []
    for m in re.finditer(r"([A-Za-z0-9_.\-]+)=([A-Za-z0-9_.\-]+)", set_cookie or ""):
        name, val = m.group(1), m.group(2)
        if not _SESSION_RE.search(name):
            continue
        bits = _entropy(val) * len(val)
        if val.isdigit() or len(val) < 16 or bits < 48:
            out.append(_f(
                f"Weak session identifier '{name}'",
                "hunt-session", "medium",
                f"The session cookie '{name}' value is short/low-entropy "
                f"(len={len(val)}, ~{bits:.0f} bits, {'numeric' if val.isdigit() else 'alnum'}), "
                f"so session identifiers may be predictable or brute-forceable.",
                f"Collect several '{name}' values and assess predictability/entropy.",
                f"Set-Cookie: {name}={val[:12]}…", ""))
            break
    return out
