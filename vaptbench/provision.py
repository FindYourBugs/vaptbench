"""Autonomous account provisioning — register and log in a throwaway account so
the authenticated and authorization phases run even when the client supplied NO
credentials (the "add a URL, click Start VAPT" promise).

Best-effort and scope-checked: it looks for a registration operation (an API
JSON body or a POST form whose path and fields look like sign-up), fills it with
a freshly generated throwaway identity, submits it, then logs in and captures the
session (cookies + any bearer token). Returns a session dict or None — never
raises into the engine. Disable with VAPT_AUTOSIGNUP=0.
"""
import json
import os
import re
import uuid
from urllib.parse import urlparse, urljoin

AUTOSIGNUP = os.environ.get("VAPT_AUTOSIGNUP", "1") != "0"

_REG_PATH = re.compile(r"(register|signup|sign-?up|/users\b|/account|join|create-?account)", re.I)
_LOGIN_PATH = re.compile(r"(login|sign-?in|/auth\b|/session|/token|authenticate)", re.I)
_EMAILF = re.compile(r"(e-?mail|user(name)?|login)", re.I)
_PASSF = re.compile(r"pass(word|wd)?", re.I)
_TOKEN_RE = re.compile(r'"(?:access_?token|token|jwt|id_?token|auth)"\s*:\s*"([^"]{16,})"', re.I)


def _creds():
    r = uuid.uuid4().hex[:10]
    return {"email": f"vaptuser_{r}@example.com",
            "password": f"Vapt!{r}Aa9", "username": f"vaptuser_{r}"}


def _fill(body, creds):
    """Set email/username/password-looking fields on a JSON body dict."""
    out = dict(body)
    for k in out:
        if not isinstance(out[k], str):
            continue
        if _PASSF.search(k):
            out[k] = creds["password"]
        elif re.search(r"e-?mail", k, re.I):
            out[k] = creds["email"]
        elif _EMAILF.search(k):
            out[k] = creds["username"]
    return out


def _session_from(resp):
    """Build a session blob from a response's Set-Cookie + any bearer token."""
    headers = resp.get("headers") or {}
    cookies = {}
    for part in (headers.get("Set-Cookie") or "").split(","):
        m = re.match(r"\s*([^=;]+)=([^;]+)", part)
        if m and "=" in part:
            cookies[m.group(1).strip()] = m.group(2).strip()
    hdrs = {}
    m = _TOKEN_RE.search(resp.get("text") or "")
    if m:
        hdrs["Authorization"] = f"Bearer {m.group(1)}"
    if cookies or hdrs:
        return json.dumps({"cookies": cookies, "headers": hdrs})
    return ""


def _reg_op(body_ops):
    for op in body_ops:
        if op.get("method") not in ("POST", "PUT"):
            continue
        if not _REG_PATH.search(urlparse(op["url"]).path):
            continue
        fields = op.get("fields") or []
        if any(_EMAILF.search(f) for f in fields) and any(_PASSF.search(f) for f in fields):
            return op
    return None


def auto_provision(send, base_url, body_ops, log=None):
    """Try to register + log in a throwaway account. Returns
    {"session_blob","username","password","how"} or None."""
    log = log or (lambda *a, **k: None)
    if not AUTOSIGNUP:
        return None
    creds = _creds()
    op = _reg_op(body_ops or [])
    if not op:
        return None
    reg_url = op["url"]
    log("info", "provision", f"auto-signup: registering throwaway account at {urlparse(reg_url).path}")
    body = _fill(op.get("body") or {}, creds)
    r = send("POST", reg_url, headers="Content-Type: application/json", body=json.dumps(body))
    if not (r and r.get("ok") and r.get("status") in (200, 201, 204, 302)):
        log("warn", "provision", f"auto-signup: registration not accepted (status {r.get('status')})")
        return None
    # session may be issued right at registration
    blob = _session_from(r)
    # otherwise, log in at a sibling/login endpoint
    if not blob:
        login_op = next((o for o in body_ops
                         if o.get("method") in ("POST", "PUT")
                         and _LOGIN_PATH.search(urlparse(o["url"]).path)), None)
        login_url = login_op["url"] if login_op else urljoin(base_url, "login")
        lbody = _fill((login_op.get("body") if login_op else None) or
                      {"email": "", "password": ""}, creds)
        rl = send("POST", login_url, headers="Content-Type: application/json", body=json.dumps(lbody))
        if rl and rl.get("ok"):
            blob = _session_from(rl)
    if not blob:
        log("warn", "provision", "auto-signup: registered but could not capture a session")
        return None
    log("hit", "provision", f"auto-signup: provisioned '{creds['email']}' and captured a session")
    return {"session_blob": blob, "username": creds["email"],
            "password": creds["password"], "how": urlparse(reg_url).path}
