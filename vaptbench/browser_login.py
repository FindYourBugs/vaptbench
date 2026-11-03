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
import os

from . import ai
from .scope import in_scope

# CSS selectors tried in order to locate each field in the rendered DOM.
USER_SELECTORS = [
    "input[type=email]",
    "input[name*=email i]", "input[name*=user i]", "input[name*=login i]",
    "input[id*=email i]", "input[id*=user i]",
    "input[autocomplete=username]", "input[type=username]",
    "input[type=text]",
]
PASS_SELECTORS = ["input[type=password]", "input[name*=pass i]", "input[id*=pass i]"]
SUBMIT_SELECTORS = [
    "button[type=submit]", "input[type=submit]",
    "button:has-text('Log in')", "button:has-text('Login')",
    "button:has-text('Sign in')", "button:has-text('Sign In')",
    "button:has-text('Continue')",
]

# ── AI-adaptive login ────────────────────────────────────────────────────────
# When the fixed-selector login below can't confirm, an agent drives the sign-in
# step-by-step from the *live* rendered page, so the tool can follow whatever
# flow an app actually presents (multi-step wizard, extra tenant field, SSO
# click-through, re-rendered steps) instead of assuming one shape. Credentials
# are referenced to the model by NAME ONLY — their values are substituted
# locally and never sent to the model. Disable with VAPT_AI_LOGIN=0.
_AI_LOGIN = os.environ.get("VAPT_AI_LOGIN", "1") != "0"
_AI_LOGIN_STEPS = int(os.environ.get("VAPT_AI_LOGIN_STEPS", "8") or 8)

_AI_LOGIN_SYSTEM = (
    "You are the login driver inside vaptbench, an authorised web-application VAPT tool. "
    "Your only job is to complete the sign-in on this page using the given credentials by "
    "choosing ONE next UI action at a time. You see the live, rendered page each step.\n"
    "Keep EVERY kind of login in mind — do not assume a plain username+password form:\n"
    "- single-step (username + password + submit on one screen)\n"
    "- identifier-first / two-step (enter email, Continue, THEN password on the next screen)\n"
    "- an extra field before credentials: company / tenant / workspace / domain / account id\n"
    "- an SSO or 'Continue with…' choice that must be clicked to reach the real form\n"
    "- a consent / 'trust this browser' / 'stay signed in' button needed to proceed\n"
    "- a step that re-renders fields which must be refilled\n"
    "You must ALSO recognise a step you cannot complete and STOP rather than guess:\n"
    "- a one-time passcode / OTP / email or SMS code / authenticator code\n"
    "- hardware or platform WebAuthn / passkey / fingerprint / security key\n"
    "- a device-trust / mutual-auth / client-certificate prompt\n"
    "- a CAPTCHA\n"
    "For any of those, return action 'blocked' with a precise blocked_reason. Never invent a code.\n\n"
    "Credentials are referenced by NAME ONLY (you never see their values): USERNAME, PASSWORD. "
    "To type one, set value_source to 'username' or 'password' and the tool fills the real value. "
    "Use value_source 'literal' only for non-secret text clearly required by the page (e.g. a "
    "tenant slug shown on screen). Never put a password or a guessed OTP in a literal.\n\n"
    "Refer to an element by its numeric 'ref' from the inputs/buttons lists. Reply with ONE JSON "
    "object and nothing else:\n"
    '{"thought":"...","action":"fill|click|press|done|blocked","ref":<number>,'
    '"value_source":"username|password|literal","value":"<only if literal>",'
    '"key":"Enter","blocked_reason":"<only if blocked>"}\n'
    "Choose 'done' only if the page already shows a signed-in state (no password field). "
    "The tool verifies a real session independently — do not fake success."
)

# Tags every visible input/button with a stable numeric ref and returns a
# compact description of the interactive surface (no field *values* — only a
# 'filled' flag — so credentials never leave the browser).
_SNAPSHOT_JS = r"""
() => {
  const vis = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  let n = 0;
  const tag = el => { el.setAttribute('data-vapt-id', ++n); return n; };
  const inputs = [...document.querySelectorAll('input,select,textarea')].filter(vis).map(el => ({
    ref: tag(el),
    type: (el.getAttribute('type') || el.tagName.toLowerCase()),
    name: el.getAttribute('name') || '',
    placeholder: el.getAttribute('placeholder') || '',
    aria: el.getAttribute('aria-label') || '',
    autocomplete: el.getAttribute('autocomplete') || '',
    filled: !!el.value
  }));
  const buttons = [...document.querySelectorAll('button,[role=button],input[type=submit],a[href]')]
    .filter(vis).map(el => ({
      ref: tag(el),
      text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 40),
      type: el.getAttribute('type') || el.tagName.toLowerCase()
    })).filter(b => b.text).slice(0, 30);
  const text = document.body ? document.body.innerText.replace(/\s+/g, ' ').trim().slice(0, 1200) : '';
  return JSON.stringify({ url: location.href, inputs, buttons, text });
}
"""


def available():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def error_hint(err):
    """Turn a giant Playwright launch dump into one short, actionable line."""
    s = str(err)
    low = s.lower()
    if "libnspr4" in low or "libnss3" in low or "error while loading shared libraries" in low \
            or "install-deps" in low or "host system is missing dependencies" in low:
        return ("headless browser is missing system libraries — run: "
                "sudo playwright install-deps chromium  "
                "(or: sudo apt install libnss3 libnspr4 libasound2t64)")
    if "executable doesn't exist" in low or ("looks like playwright" in low) \
            or ("chromium" in low and "install" in low and "run" in low):
        return "Chromium not installed for Playwright — run: playwright install chromium"
    return (s.splitlines()[0].strip() or s[:160])[:200]


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
            pw_sel = cfg.get("password_selector")

            def _fill_user():
                if cfg.get("username_selector"):
                    try:
                        page.fill(cfg["username_selector"], identity.username or "")
                        return True
                    except Exception:
                        return False
                el, _ = _first(page, USER_SELECTORS)
                if el:
                    try:
                        el.fill(identity.username or "")
                        return True
                    except Exception:
                        return False
                return False

            def _submit():
                if cfg.get("submit_selector"):
                    try:
                        page.click(cfg["submit_selector"]); return
                    except Exception:
                        pass
                el, _ = _first(page, SUBMIT_SELECTORS)
                if el:
                    try:
                        el.click(); return
                    except Exception:
                        pass
                page.keyboard.press("Enter")

            def _wait_pass(timeout):
                try:
                    page.wait_for_selector(pw_sel or "input[type=password]",
                                           state="visible", timeout=timeout)
                    return True
                except PWTimeout:
                    return False

            # Fill the username if it's on the first page.
            user_filled = _fill_user()

            # Single-step: the password field is present now (or renders shortly).
            # Two-step (username-first — Gin & Juice, Okta, Google, Microsoft …):
            # no password field yet, so submit the username to reveal step 2.
            two_step = False
            if not _wait_pass(5000):
                if not user_filled:
                    browser.close()
                    return False, ("no password field and no username field on the login "
                                   "page (wrong login URL, or MFA/redirect)")
                two_step = True
                _submit()
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except PWTimeout:
                    pass
                if not _wait_pass(12000):
                    browser.close()
                    return False, ("no password field appeared after submitting the username "
                                   "(two-step login not completed — wrong URL/creds, MFA, or redirect)")
                _fill_user()          # some step-2 pages re-show the username field

            # Password
            if pw_sel:
                page.fill(pw_sel, identity.secret or "")
            else:
                el, _ = _first(page, PASS_SELECTORS)
                if not el:
                    browser.close()
                    return False, "could not locate a password field"
                el.fill(identity.secret or "")

            start_url = page.url
            _submit()
            _settle(page, cfg)

            # Did the fixed-selector fill confirm on its own?
            success_hint = cfg.get("success_url_contains")
            cookies, headers, token, still_has_pw = _capture(ctx, page)
            if _confirmed(cookies, token, page.url, start_url, still_has_pw, success_hint):
                return _ok(identity, cookies, headers, token, two_step=two_step)

            # It didn't. A fixed selector list can't drive every login — a login
            # may be a multi-step wizard, need an extra tenant/company field, hide
            # the real form behind a "Continue"/SSO click, or re-render step 2.
            # Hand the live page to the agent, which looks at what's actually on
            # screen each step and decides the next action — and which stops with
            # a precise reason when it hits a wall it must not fake (OTP, hardware
            # WebAuthn, device-trust, CAPTCHA).
            if _AI_LOGIN and ai.available()[0]:
                return _adaptive_login(page, ctx, identity, cfg, start_url)

            moved = page.url.rstrip("/") != start_url.rstrip("/")
            return False, (f"login not confirmed [url-moved={moved}, "
                           f"cookies={len(cookies)}, token={'yes' if token else 'no'}, "
                           f"password-field-still-shown={still_has_pw}] — wrong creds, MFA, "
                           f"SSO/multi-step, or set success_url_contains "
                           f"(an Ollama/cloud model enables the AI-adaptive login)")
    except Exception as e:
        return False, f"browser login failed — {error_hint(e)}"


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


def _settle(page, cfg):
    """Wait for navigation/XHR to settle after an action."""
    from playwright.sync_api import TimeoutError as PWTimeout
    try:
        page.wait_for_load_state("networkidle", timeout=15000)
    except PWTimeout:
        pass
    try:
        page.wait_for_timeout(int(cfg.get("wait_ms", 1200)))
    except Exception:
        pass


def _capture(ctx, page):
    """Snapshot the current session: cookies, bearer token, password-field flag."""
    cookies = {c["name"]: c["value"] for c in ctx.cookies()}
    headers = {}
    try:
        ls = page.evaluate("() => JSON.stringify(window.localStorage)")
        store = json.loads(ls) if ls else {}
    except Exception:
        store = {}
    token = _find_token(store)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        still_has_pw = bool(page.query_selector("input[type=password]"))
    except Exception:
        still_has_pw = False
    return cookies, headers, token, still_has_pw


def _confirmed(cookies, token, cur_url, start_url, still_has_pw, success_hint):
    """Deterministic success test — a real session was captured. This is the only
    thing that marks a login confirmed, for the fixed AND the AI path alike; the
    model never gets to assert success."""
    if success_hint:
        return success_hint in (cur_url or "")
    moved = (cur_url or "").rstrip("/") != (start_url or "").rstrip("/")
    return bool(cookies or token) and (moved or not still_has_pw)


def _ok(identity, cookies, headers, token, two_step=False, via=""):
    identity.session_blob = json.dumps({"cookies": cookies, "headers": headers})
    bits = [f"{len(cookies)} cookie(s)"] + (["bearer token"] if token else [])
    tag = (" (two-step)" if two_step else "") + (f" ({via})" if via else "")
    return True, "browser login ok" + tag + ": " + ", ".join(bits)


def _adaptive_login(page, ctx, identity, cfg, start_url):
    """Agent-driven, one-action-at-a-time login from the live page.

    Returns (ok, message). A login counts as confirmed only when _confirmed()
    sees a real session — the model cannot declare success — and the loop stops
    with a precise, actionable reason when the model reports a step it must not
    fake (OTP / WebAuthn / device-trust / CAPTCHA).
    """
    success_hint = cfg.get("success_url_contains")
    history = []
    for step in range(_AI_LOGIN_STEPS):
        cookies, headers, token, still_has_pw = _capture(ctx, page)
        if _confirmed(cookies, token, page.url, start_url, still_has_pw, success_hint):
            return _ok(identity, cookies, headers, token, via="ai-adaptive")
        try:
            snap = page.evaluate(_SNAPSHOT_JS)
        except Exception as e:
            return False, f"login not confirmed — adaptive login could not read the page ({e})"

        prompt = ("Step %d of %d. Actions so far: %s.\nComplete the sign-in. Live page:\n%s"
                  % (step + 1, _AI_LOGIN_STEPS, "; ".join(history) or "none", snap))
        act = ai.ask_json(prompt, system=_AI_LOGIN_SYSTEM, role="reasoner") or {}
        a = str(act.get("action") or "").lower()

        if a == "blocked":
            why = str(act.get("blocked_reason") or "").strip() or "an interactive authentication step"
            return False, (
                "login blocked at a step the tool must not fake autonomously: " + why +
                ". Sign in manually in a browser, then hand vaptbench the resulting session "
                "(copy the bearer token from localStorage, or the cookie header) and re-run "
                "with --auth bearer or --auth cookie.")

        if a == "done":
            _settle(page, cfg)
            cookies, headers, token, still_has_pw = _capture(ctx, page)
            if _confirmed(cookies, token, page.url, start_url, still_has_pw, success_hint):
                return _ok(identity, cookies, headers, token, via="ai-adaptive")
            history.append("claimed done but no session yet")
            continue

        ref = act.get("ref")
        sel = ('[data-vapt-id="%s"]' % ref) if ref not in (None, "") else None
        try:
            if a == "fill" and sel:
                vs = str(act.get("value_source") or "").lower()
                val = (identity.username if vs == "username"
                       else identity.secret if vs == "password"
                       else str(act.get("value") or ""))
                page.fill(sel, val, timeout=5000)
                history.append("fill#%s=%s" % (ref, vs or "literal"))
            elif a == "click" and sel:
                page.click(sel, timeout=5000)
                history.append("click#%s" % ref)
            elif a == "press":
                page.keyboard.press(str(act.get("key") or "Enter"))
                history.append("press:%s" % (act.get("key") or "Enter"))
            else:
                history.append("skip(%s)" % (a or "empty"))
        except Exception:
            history.append("fail(%s#%s)" % (a, ref))
        _settle(page, cfg)

    cookies, headers, token, still_has_pw = _capture(ctx, page)
    if _confirmed(cookies, token, page.url, start_url, still_has_pw, success_hint):
        return _ok(identity, cookies, headers, token, via="ai-adaptive")
    return False, (
        f"login not confirmed after {_AI_LOGIN_STEPS} adaptive steps "
        f"[cookies={len(cookies)}, token={'yes' if token else 'no'}, "
        f"password-field-still-shown={still_has_pw}] — likely MFA/SSO/device-trust or a "
        f"login flow the tool can't drive; sign in manually and pass the session with "
        f"--auth bearer/cookie")
