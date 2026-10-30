"""Automated login per identity -> capture the session.

Form login varies per app, so each identity carries a login_config (JSON):
    {
      "username_field": "email",      # form field for the username
      "password_field": "password",
      "csrf_field": "csrf_token",     # hidden field to echo back (optional)
      "extra": {"remember": "1"},     # any extra form fields
      "success_contains": "Logout",   # string proving login worked (optional)
      "failure_contains": "Invalid"   # string proving it failed (optional)
    }

Result is stored on Identity.session_blob as {"cookies":{...}, "headers":{...}}
so the Repeater and access-matrix can replay requests as that role.
"""
import json
import re
import requests

from .scope import in_scope

DEFAULTS = {
    "username_field": "username",
    "password_field": "password",
    "csrf_field": "",
    "extra": {},
    "success_contains": "",
    "failure_contains": "",
}


def parse_curl(text):
    """Extract cookies + headers from a pasted cURL command or raw header block.

    Handles -H/--header '...', -b/--cookie '...', and plain 'Name: value' lines.
    Lets SPA/API logins be captured straight from the browser's DevTools
    ('Copy as cURL') with no automated login at all.
    """
    cookies, headers = {}, {}
    text = (text or "").replace("\\\n", " ").replace("^\n", " ")

    def _add_cookie_str(s):
        for part in s.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    # -H / --header '...'  and  -b / --cookie '...'
    for m in re.finditer(r"(-H|--header|-b|--cookie)\s+(['\"])(.*?)\2", text):
        flag, content = m.group(1), m.group(3)
        if flag in ("-b", "--cookie"):
            _add_cookie_str(content)
        elif ":" in content:
            name, value = content.split(":", 1)
            if name.strip().lower() == "cookie":
                _add_cookie_str(value)
            else:
                headers[name.strip()] = value.strip()

    # Fallback: raw header lines pasted without curl flags.
    if not cookies and not headers:
        for line in text.splitlines():
            if ":" in line and not line.strip().startswith("curl"):
                name, value = line.split(":", 1)
                if name.strip().lower() == "cookie":
                    _add_cookie_str(value)
                else:
                    headers[name.strip()] = value.strip()
    return cookies, headers


def _config(identity):
    cfg = dict(DEFAULTS)
    if identity.login_config:
        try:
            cfg.update(json.loads(identity.login_config))
        except (ValueError, TypeError):
            pass
    return cfg


def _parse_inputs(html):
    """Return a list of {name,type,value} for every <input> in the page."""
    inputs = []
    for tag in re.findall(r"<input\b[^>]*>", html or "", re.I):
        attrs = {}
        for k, dq, sq, uq in re.findall(
                r'([\w-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', tag):
            attrs[k.lower()] = dq or sq or uq
        if attrs.get("name"):
            inputs.append({"name": attrs["name"],
                           "type": (attrs.get("type") or "text").lower(),
                           "value": attrs.get("value", "")})
    return inputs


def _autodetect(html, cfg):
    """Fill in username/password/csrf field names from the login form when the
    config didn't specify them, so most forms work with zero configuration."""
    inputs = _parse_inputs(html)
    pw = next((i for i in inputs if i["type"] == "password"), None)
    if pw and cfg["password_field"] == DEFAULTS["password_field"]:
        cfg["password_field"] = pw["name"]
    if cfg["username_field"] == DEFAULTS["username_field"]:
        user = next((i for i in inputs if i["type"] in ("text", "email")
                     and re.search(r"user|email|login|name|id", i["name"], re.I)), None)
        if not user:
            user = next((i for i in inputs if i["type"] in ("text", "email")), None)
        if user:
            cfg["username_field"] = user["name"]
    if not cfg["csrf_field"]:
        csrf = next((i for i in inputs if i["type"] == "hidden"
                     and re.search(r"csrf|token|authenticity|nonce|_token", i["name"], re.I)), None)
        if csrf:
            cfg["csrf_field"] = csrf["name"]
    # Carry any other hidden fields through (some forms require them).
    cfg.setdefault("_hidden", {i["name"]: i["value"] for i in inputs
                               if i["type"] == "hidden" and i["name"] != cfg["csrf_field"]})
    return cfg


def _grab_csrf(html, field):
    """Pull a hidden CSRF token value out of the login page HTML."""
    if not field:
        return None
    m = re.search(
        r'<input[^>]*name=["\']%s["\'][^>]*value=["\']([^"\']*)["\']' % re.escape(field),
        html, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(
        r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']%s["\']' % re.escape(field),
        html, re.IGNORECASE)
    return m.group(1) if m else None


def _capture(sess, extra_headers=None):
    blob = {"cookies": sess.cookies.get_dict(), "headers": extra_headers or {}}
    return json.dumps(blob)


def login(identity, scope_rules):
    """Perform login for one identity. Returns (ok, message). Scope-guarded."""
    at = identity.auth_type

    # 'auto' = drive a headless browser (works on classic + JS/SPA apps).
    if at == "auto":
        from . import browser_login
        return browser_login.login(identity, scope_rules)

    # Token / basic / pasted-cookie: no network login needed.
    if at == "bearer":
        identity.session_blob = _capture(requests.Session(),
                                         {"Authorization": f"Bearer {identity.secret}"})
        return True, "bearer token stored"
    if at == "basic":
        import base64
        tok = base64.b64encode(f"{identity.username}:{identity.secret}".encode()).decode()
        identity.session_blob = _capture(requests.Session(), {"Authorization": f"Basic {tok}"})
        return True, "basic auth stored"
    if at == "cookie":
        # secret holds a raw Cookie header: "k1=v1; k2=v2"
        jar = {}
        for part in (identity.secret or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                jar[k.strip()] = v.strip()
        identity.session_blob = json.dumps({"cookies": jar, "headers": {}})
        return True, f"{len(jar)} cookie(s) stored"
    if at == "curl":
        # login_config holds a pasted cURL command / header block from DevTools.
        cookies, headers = parse_curl(identity.login_config or identity.secret or "")
        # Drop headers that must be recomputed per request or would break replay.
        _drop = {"host", "content-length", "accept-encoding", "connection",
                 "content-type", ":authority", ":method", ":path", ":scheme"}
        headers = {k: v for k, v in headers.items() if k.lower() not in _drop}
        if not cookies and not headers:
            return False, "no cookies/headers found in the pasted cURL/headers"
        identity.session_blob = json.dumps({"cookies": cookies, "headers": headers})
        bits = []
        if cookies:
            bits.append(f"{len(cookies)} cookie(s)")
        if any(h.lower() == "authorization" for h in headers):
            bits.append("auth token")
        if headers:
            bits.append(f"{len(headers)} header(s)")
        return True, "session captured: " + ", ".join(bits)

    # Form login.
    url = identity.login_url
    if not url:
        return False, "no login_url set for form login"
    ok, why = in_scope(url, scope_rules)
    if not ok:
        return False, f"login_url out of scope: {why}"

    cfg = _config(identity)
    sess = requests.Session()
    try:
        # Prime: fetch the login page for cookies + CSRF token, and auto-detect
        # the form field names so most forms work without any login_config.
        r0 = sess.get(url, timeout=20, verify=False)
        had_pw_field = any(i["type"] == "password" for i in _parse_inputs(r0.text))
        cfg = _autodetect(r0.text, cfg)
        token = _grab_csrf(r0.text, cfg["csrf_field"])
        pre_cookies = set(sess.cookies.keys())

        data = dict(cfg.get("_hidden") or {})          # carry hidden fields
        data[cfg["username_field"]] = identity.username
        data[cfg["password_field"]] = identity.secret
        if token is not None:
            data[cfg["csrf_field"]] = token
        data.update(cfg.get("extra") or {})

        r = sess.post(url, data=data, timeout=20, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return False, f"request error: {e}"

    # No password field in static HTML => JS/SPA login. Escalate to the
    # headless browser automatically if it's available.
    if not had_pw_field:
        from . import browser_login
        if browser_login.available():
            return browser_login.login(identity, scope_rules)
        return False, ("JavaScript/SPA login detected and the headless browser isn't "
                       "installed. Run scripts/setup_kali.sh to enable automatic login, "
                       "or use auth_type=curl with a session from the browser.")

    body = r.text
    gained = sorted(set(sess.cookies.keys()) - pre_cookies)
    redirected = bool(r.history) or r.url.rstrip("/") != url.rstrip("/")
    form_still = ('type="password"' in body.lower()) or ("type='password'" in body.lower())
    low = body.lower()
    fail_hit = (cfg["failure_contains"] and cfg["failure_contains"] in body) or \
               any(w in low for w in ("invalid", "incorrect", "try again",
                                      "failed", "wrong password", "denied"))

    # Decide success, most explicit signal first.
    if cfg["success_contains"]:
        good = cfg["success_contains"] in body
    elif gained and not form_still:
        good = True                       # got a session cookie, login form gone
    elif redirected and not form_still and not fail_hit:
        good = True                       # bounced off the login page cleanly
    else:
        good = False

    diag = (f"[HTTP {r.status_code}, redirected={redirected}, "
            f"new-cookies={gained or 'none'}, login-form-still-shown={form_still}, "
            f"fields used: user='{cfg['username_field']}' pw='{cfg['password_field']}'"
            f"{', failure-text seen' if fail_hit else ''}]")

    if not good:
        hint = ("login looks rejected (check creds/fields)" if form_still or fail_hit
                else "couldn't confirm; set success_contains to a logged-in-only string")
        return False, f"{hint} {diag}"

    identity.session_blob = _capture(sess)
    n = len(sess.cookies.get_dict())
    return True, f"logged in, {n} cookie(s) captured"
