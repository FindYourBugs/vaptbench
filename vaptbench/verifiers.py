"""Deterministic Tier-1 verifiers.

Each verifier proves a bug with evidence — a reflected marker, a DB-error
signature, a Location canary, a cross-role status delta — never a guess. If a
check can't be proven deterministically it is NOT emitted here (AI-only
suspicions are handled separately and marked needs-review).

A verifier takes a `send` callable bound to the target's scope:
    send(method, url, headers="", body="", identity=None) -> result dict
      result = {ok, blocked, status, len, headers, text, identity, reason}
and returns a list of finding dicts.
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Unique, benign canaries.
XSS_MARK = "vaptx9z"
XSS_PAYLOAD = f'{XSS_MARK}"><svg/onload=alert(1)>'
REDIR_CANARY = "vaptbench-oob.canary"
SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysqli",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query", "psql:", "sqlite3.operationalerror", "ora-01756", "ora-00933",
    "sqlstate[", "odbc sql", "microsoft odbc", "native client", "syntax error at or near",
]
SEC_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy", "medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    "strict-transport-security": ("Missing HSTS (Strict-Transport-Security)", "low", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "x-content-type-options": ("Missing X-Content-Type-Options: nosniff", "low", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "referrer-policy": ("Missing Referrer-Policy", "info", ""),
    "permissions-policy": ("Missing Permissions-Policy", "info", ""),
}


def _poc(method, url, result, extra=""):
    req = f"{method} {url}\n{extra}".strip()
    hdrs = result.get("headers", {})
    head = f"HTTP {result.get('status')}  ({result.get('len')} bytes)\n"
    head += "\n".join(f"{k}: {v}" for k, v in list(hdrs.items())[:15])
    body = (result.get("text") or "")[:1500]
    return req, head + "\n\n" + body


def _params(url):
    p = urlparse(url)
    return p, parse_qs(p.query, keep_blank_values=True)


def _set_param(url, key, value):
    p, q = _params(url)
    q = {k: v[:] for k, v in q.items()}
    q[key] = [value]
    flat = urlencode([(k, vv) for k, vals in q.items() for vv in vals])
    return urlunparse(p._replace(query=flat))


# --- passive (one base response) ------------------------------------------
def check_headers(url, result):
    out = []
    h = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
    for key, (title, sev, cvss) in SEC_HEADERS.items():
        if key not in h:
            req, resp = _poc("GET", url, result)
            out.append(dict(title=title, vuln_class="hunt-misc", severity=sev,
                            cvss=cvss, confidence="confirmed",
                            description=f"Response for {url} does not set the {key} header.",
                            steps=f"GET {url} and observe the response headers.",
                            poc_request=req, poc_response=resp))
    return out


def check_clickjacking(url, result):
    h = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
    xfo = h.get("x-frame-options", "")
    csp = h.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        req, resp = _poc("GET", url, result)
        return [dict(title="Clickjacking: no framing protection",
                     vuln_class="hunt-clickjacking", severity="low",
                     cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                     confidence="confirmed",
                     description=f"{url} sets neither X-Frame-Options nor CSP frame-ancestors, so it can be framed.",
                     steps=f"Frame {url} in an attacker page; it renders.",
                     poc_request=req, poc_response=resp)]
    return []


def check_cookies(url, result):
    out = []
    raw = (result.get("headers") or {})
    setc = raw.get("Set-Cookie") or raw.get("set-cookie") or ""
    if not setc:
        return out
    low = setc.lower()
    missing = [f for f in ("httponly", "secure") if f not in low]
    if "samesite" not in low:
        missing.append("samesite")
    if missing:
        req, resp = _poc("GET", url, result)
        out.append(dict(title=f"Cookie missing flags: {', '.join(missing)}",
                        vuln_class="hunt-session", severity="low",
                        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        confidence="confirmed",
                        description=f"Set-Cookie on {url} is missing: {', '.join(missing)}.",
                        steps=f"GET {url}; inspect the Set-Cookie header.",
                        poc_request=req, poc_response=f"Set-Cookie: {setc}\n\n" + resp))
    return out


# --- active (send extra requests) -----------------------------------------
def check_cors(send, url):
    evil = f"https://{REDIR_CANARY}"
    r = send("GET", url, headers=f"Origin: {evil}")
    if not r.get("ok"):
        return []
    h = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == evil and acac:
        sev, desc = "high", "reflects an arbitrary Origin AND allows credentials"
    elif acao == evil:
        sev, desc = "medium", "reflects an arbitrary Origin"
    elif acao == "*" and acac:
        sev, desc = "medium", "wildcard ACAO with credentials"
    else:
        return []
    req, resp = _poc("GET", url, r, extra=f"Origin: {evil}")
    return [dict(title="CORS misconfiguration", vuln_class="hunt-cors", severity=sev,
                 cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                 confidence="confirmed",
                 description=f"{url} {desc} (ACAO={acao!r}, credentials={acac}).",
                 steps=f"Send GET {url} with 'Origin: {evil}'; observe the ACAO reflected.",
                 poc_request=req, poc_response=resp)]


def check_methods(send, url):
    r = send("OPTIONS", url)
    if not r.get("ok"):
        return []
    allow = ((r.get("headers") or {}).get("Allow")
             or (r.get("headers") or {}).get("allow") or "")
    dangerous = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")
                 if m in allow.upper()]
    if not dangerous:
        return []
    req, resp = _poc("OPTIONS", url, r)
    return [dict(title=f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                 vuln_class="hunt-misc", severity="low", cvss="",
                 confidence="confirmed",
                 description=f"OPTIONS {url} advertises: {allow}.",
                 steps=f"Send OPTIONS {url}; read the Allow header.",
                 poc_request=req, poc_response=resp)]


def check_open_redirect(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        payload = f"https://{REDIR_CANARY}/"
        test = _set_param(url, key, payload)
        r = send("GET", test)
        if not r.get("ok"):
            continue
        loc = ((r.get("headers") or {}).get("Location")
               or (r.get("headers") or {}).get("location") or "")
        if REDIR_CANARY in loc and r.get("status") in (301, 302, 303, 307, 308):
            req, resp = _poc("GET", test, r)
            out.append(dict(title=f"Open redirect via '{key}'",
                            vuln_class="hunt-open-redirect", severity="medium",
                            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                            confidence="confirmed",
                            description=f"Parameter '{key}' on {url} redirects to an attacker URL (Location: {loc}).",
                            steps=f"GET {test} → 3xx to {loc}.",
                            poc_request=req, poc_response=resp))
    return out


def check_reflected_xss(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        test = _set_param(url, key, XSS_PAYLOAD)
        r = send("GET", test)
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        if f'{XSS_MARK}"><svg' in body:
            req, resp = _poc("GET", test, r)
            out.append(dict(title=f"Reflected XSS via '{key}'",
                            vuln_class="hunt-xss", severity="high",
                            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            confidence="confirmed",
                            description=f"Parameter '{key}' reflects HTML metacharacters unencoded; the injected <svg/onload> survives in the response.",
                            steps=f"GET {test}; the payload reflects unencoded in the HTML.",
                            poc_request=req, poc_response=resp))
        elif XSS_MARK in body:
            out.append(dict(title=f"Input reflection via '{key}' (possible XSS)",
                            vuln_class="hunt-xss", severity="info",
                            cvss="", confidence="needs-review",
                            description=f"Parameter '{key}' is reflected but metacharacters appear encoded; verify context manually.",
                            steps=f"GET {test}; marker reflected (encoded).",
                            poc_request=f"GET {test}", poc_response=(body[:800])))
    return out


def check_error_sqli(send, url):
    _, q = _params(url)
    out = []
    for key in q:
        test = _set_param(url, key, (q[key][0] if q[key] else "1") + "'")
        r = send("GET", test)
        if not r.get("ok"):
            continue
        low = (r.get("text") or "").lower()
        hit = next((s for s in SQL_ERRORS if s in low), None)
        if hit:
            req, resp = _poc("GET", test, r)
            out.append(dict(title=f"SQL injection (error-based) via '{key}'",
                            vuln_class="hunt-sqli", severity="critical",
                            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            confidence="confirmed",
                            description=f"Appending a single quote to '{key}' triggers a database error ({hit!r}), proving the value reaches a SQL query unsanitised.",
                            steps=f"GET {test}; the response contains a SQL error.",
                            poc_request=req, poc_response=resp))
    return out


# Each path maps to a validator that must recognise the file's ACTUAL format.
# Weak substring signatures (e.g. "=" or "") match an SPA's index.html and
# produce false positives, so every validator below is format-specific and all
# reject HTML (checked separately before the validator runs).
SENSITIVE_FILES = {
    "/.git/HEAD":       lambda b: b.lstrip()[:5].startswith("ref:") and len(b) < 200,
    "/.git/config":     lambda b: "[core]" in b and "repositoryformatversion" in b.lower(),
    "/.env":            lambda b: bool(re.search(r'(?m)^[A-Z][A-Z0-9_]{2,}=', b)),
    "/.DS_Store":       lambda b: "Bud1" in b[:64],
    "/server-status":   lambda b: "Apache Server Status" in b,
    "/phpinfo.php":     lambda b: "phpinfo()" in b or "PHP Version" in b,
    "/.svn/entries":    lambda b: bool(re.match(r'^\s*\d+\s', b)) or b[:40].lower().startswith("<?xml"),
    "/.svn/wc.db":      lambda b: b[:15].startswith("SQLite format"),
    "/WEB-INF/web.xml": lambda b: "<web-app" in b.lower(),
    "/.aws/credentials": lambda b: "aws_access_key_id" in b.lower(),
    "/config.php~":     lambda b: "<?php" in b,
    "/.htpasswd":       lambda b: bool(re.search(r'(?m)^[^:\s]+:\$?[^\s:]{3,}', b)) and "<" not in b[:20],
}


def _header(result, name):
    for k, v in (result.get("headers") or {}).items():
        if k.lower() == name.lower():
            return v or ""
    return ""


def _is_html_page(result):
    """True if the response is an HTML page (e.g. an SPA app shell), not a raw file."""
    if "text/html" in _header(result, "content-type").lower():
        return True
    head = (result.get("text") or "")[:600].lower()
    return "<!doctype html" in head or "<html" in head


def check_exposed_files(send, base_url):
    out = []
    base = base_url.rstrip("/")

    # Learn the catch-all: many SPAs return 200 + index.html for ANY unknown
    # path (client-side routing). Capture that body so we can reject matches.
    probe = send("GET", base + "/vaptbench-nope-zzqx9k7w")
    catch_body = (probe.get("text") or "") if (probe.get("ok") and probe.get("status") == 200) else ""

    for path, valid in SENSITIVE_FILES.items():
        r = send("GET", base + path)
        if not r.get("ok") or r.get("status") != 200:
            continue
        body = r.get("text") or ""
        # 1) an HTML page is the app, not the file -> reject
        if _is_html_page(r):
            continue
        # 2) identical to the catch-all 200 body -> reject
        if catch_body and (body == catch_body or
                           abs(len(body) - len(catch_body)) < 32 and body[:300] == catch_body[:300]):
            continue
        # 3) must look like the real file format
        try:
            if not valid(body):
                continue
        except Exception:
            continue
        req, resp = _poc("GET", base + path, r)
        out.append(dict(title=f"Exposed sensitive file: {path}",
                        vuln_class="hunt-source-leak", severity="high",
                        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence="confirmed",
                        description=f"{base + path} is publicly accessible (HTTP 200) and its body matches the expected file format.",
                        steps=f"GET {base + path} → 200 with the actual file contents (not the SPA/app page).",
                        poc_request=req, poc_response=resp))
    return out
