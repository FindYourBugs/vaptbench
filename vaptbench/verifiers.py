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


SENSITIVE_PATHS = {
    "/.git/HEAD": "ref:", "/.env": "=", "/.DS_Store": "Bud1",
    "/server-status": "Apache Server Status", "/phpinfo.php": "phpinfo()",
    "/.svn/entries": "", "/WEB-INF/web.xml": "<web-app",
}


def check_exposed_files(send, base_url):
    out = []
    base = base_url.rstrip("/")
    for path, sig in SENSITIVE_PATHS.items():
        r = send("GET", base + path)
        if not r.get("ok") or r.get("status") != 200:
            continue
        body = r.get("text") or ""
        if sig and sig not in body:
            continue
        req, resp = _poc("GET", base + path, r)
        out.append(dict(title=f"Exposed sensitive file: {path}",
                        vuln_class="hunt-source-leak", severity="high",
                        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        confidence="confirmed",
                        description=f"{base + path} is publicly accessible (HTTP 200).",
                        steps=f"GET {base + path} → 200 with sensitive content.",
                        poc_request=req, poc_response=resp))
    return out
