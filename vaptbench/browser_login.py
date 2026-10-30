"""Headless-browser login — autonomous auth that works on JS/SPA apps.

A classic form login fails on SPAs because the form is rendered by JavaScript.
This drives a real headless Chromium (Playwright): load the login page, find the
username/password fields in the *rendered* DOM, type the creds, submit, and
capture the resulting cookies + any bearer token from localStorage. The
engine's requests-based tester then replays that session.

Playwright is optional: if it isn't installed the caller falls back to the
static form login / cURL paste, with a clear message.

login_config (JSON, all optional) can override the heuristics:
    {"username_selector": "#email", "password_selector": "#pw",
     "submit_selector": "button[type=submit]", "success_url_contains": "/dashboard",
     "wait_ms": 1500}
"""
import json

from .scope import in_scope

# CSS selectors tried in order to locate each field in the rendered DOM.
USER_SELECTORS = [
    "input[type=email]",
    "input[name*=email i]", "input[name*=user i]", "input[name*=login i]",
    "input[id*=email i]", "input[id*=user i]",
    "input[autocomplete=username]",
    "input[type=text]",
]
PASS_SELECTORS = ["input[type=password]", "input[name*=pass i]", "input[id*=pass i]"]
SUBMIT_SELECTORS = [
    "button[type=submit]", "input[type=submit]",
    "button:has-text('Log in')", "button:has-text('Login')",
    "button:has-text('Sign in')", "button:has-text('Sign In')",
    "button:has-text('Continue')",
]


def available():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _first(page, selectors, timeout=0):
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el and el.is_visible():
                return el, sel
        except Exception:
            continue
    return None, None


def login(identity, scope_rules):
    """Drive a headless browser to log in. Returns (ok, message)."""
    url = identity.login_url
    if not url:
        return False, "no login_url set"
    ok, why = in_scope(url, scope_rules)
    if not ok:
        return False, f"login_url out of scope: {why}"
    if not available():
        return False, ("headless browser not installed — run scripts/setup_kali.sh "
                       "(installs Playwright + Chromium)")

    cfg = {}
    if identity.login_config:
        try:
            cfg = json.loads(identity.login_config)
        except (ValueError, TypeError):
            cfg = {}

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)

            # Password field appearing = the JS login form is ready.
            pw_sel = cfg.get("password_selector")
            try:
                page.wait_for_selector(pw_sel or "input[type=password]", timeout=12000)
            except PWTimeout:
                browser.close()
                return False, "no password field appeared after JS render (wrong login URL, or MFA/redirect)"

            # Username
            if cfg.get("username_selector"):
                page.fill(cfg["username_selector"], identity.username or "")
            else:
                el, _ = _first(page, USER_SELECTORS)
                if not el:
                    browser.close()
                    return False, "could not locate a username field"
                el.fill(identity.username or "")

            # Password
            if pw_sel:
                page.fill(pw_sel, identity.secret or "")
            else:
                el, _ = _first(page, PASS_SELECTORS)
                el.fill(identity.secret or "")

            start_url = page.url
            # Submit
            if cfg.get("submit_selector"):
                page.click(cfg["submit_selector"])
            else:
                el, _ = _first(page, SUBMIT_SELECTORS)
                if el:
                    el.click()
                else:
                    page.keyboard.press("Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except PWTimeout:
                pass
            page.wait_for_timeout(int(cfg.get("wait_ms", 1200)))

            # Capture session
            cookies = {c["name"]: c["value"] for c in ctx.cookies()}
            headers = {}
            try:
                ls = page.evaluate("() => JSON.stringify(window.localStorage)")
                store = json.loads(ls) if ls else {}
            except Exception:
                store = {}
            # Promote a likely bearer token from localStorage to a header.
            token = _find_token(store)
            if token:
                headers["Authorization"] = f"Bearer {token}"

            still_has_pw = bool(page.query_selector("input[type=password]"))
            moved = page.url.rstrip("/") != start_url.rstrip("/")
            success_hint = cfg.get("success_url_contains")
            browser.close()

            if success_hint:
                good = success_hint in page.url
            else:
                good = bool(cookies or token) and (moved or not still_has_pw)

            if not good:
                return False, (f"login not confirmed [url-moved={moved}, "
                               f"cookies={len(cookies)}, token={'yes' if token else 'no'}, "
                               f"password-field-still-shown={still_has_pw}] — wrong creds, MFA, or set success_url_contains")

            identity.session_blob = json.dumps({"cookies": cookies, "headers": headers})
            bits = [f"{len(cookies)} cookie(s)"] + (["bearer token"] if token else [])
            return True, "browser login ok: " + ", ".join(bits)
    except Exception as e:
        return False, f"browser login error: {e}"


def _find_token(store):
    """Pull a JWT/access-token-looking value out of a localStorage dump."""
    best = None
    for k, v in (store or {}).items():
        if not isinstance(v, str):
            continue
        val = v.strip().strip('"')
        # Nested JSON (e.g. {"access_token": "..."}).
        if val.startswith("{"):
            try:
                inner = json.loads(val)
                for ik, iv in inner.items():
                    if isinstance(iv, str) and ("token" in ik.lower() or iv.startswith("eyJ")):
                        return iv
            except Exception:
                pass
        if val.startswith("eyJ") and val.count(".") == 2:    # looks like a JWT
            return val
        if ("token" in k.lower() or "auth" in k.lower()) and len(val) > 20:
            best = best or val
    return best
