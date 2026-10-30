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
        attrs = dict(re.findall(r'(\w+)\s*=\s*["\']([^"\']*)["\']', tag))
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
        cfg = _autodetect(r0.text, cfg)
        token = _grab_csrf(r0.text, cfg["csrf_field"])

        data = dict(cfg.get("_hidden") or {})          # carry hidden fields
        data[cfg["username_field"]] = identity.username
        data[cfg["password_field"]] = identity.secret
        if token is not None:
            data[cfg["csrf_field"]] = token
        data.update(cfg.get("extra") or {})

        r = sess.post(url, data=data, timeout=20, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return False, f"request error: {e}"

    # Decide success.
    body = r.text
    if cfg["failure_contains"] and cfg["failure_contains"] in body:
        return False, f"failure marker seen ({cfg['failure_contains']!r})"
    if cfg["success_contains"]:
        if cfg["success_contains"] not in body:
            return False, f"success marker not found ({cfg['success_contains']!r})"
        good = True
    else:
        # No marker given: treat gained cookies or a non-login redirect as success.
        good = bool(sess.cookies.get_dict()) or r.url != url

    if not good:
        return False, "no session cookie gained; set success_contains to confirm"

    identity.session_blob = _capture(sess)
    n = len(sess.cookies.get_dict())
    return True, f"logged in, {n} cookie(s) captured"
