"""SPA API discovery — the real attack surface of a JavaScript app.

A React/Vue/Angular/Next SPA ships a tiny HTML shell and does everything over
XHR/fetch to a backend API. The server HTML has no ``?param=`` links, so the
classic crawl + injection tests find nothing to bite — yet the app is talking to
``/api/v1/...`` the whole time. This module surfaces those endpoints two ways:

1. **Runtime capture (best)** — drive a headless Chromium (Playwright),
   authenticated with the identity's captured session, load the app, let it
   make its real network calls, and record every in-scope XHR/fetch request
   (method + URL + whether it carried a body). This is ground truth: these are
   endpoints the app actually uses.

2. **Static bundle harvest (fallback / supplement)** — no browser needed. Fetch
   the HTML shell + its JS bundles and grep out API hosts, versioned base paths,
   and resource-word route literals (minifiers store routes as string segments),
   then reconstruct candidate URLs. Mirrors the hunt-spa-api skill.

Everything is scope-checked. Discovered endpoints flow back into the engine's
endpoint list so the agent, injection suite, and access-control matrix can test
them. We only *discover* here — verifiers still decide what is a real finding.
"""
import json
import re
from urllib.parse import urljoin, urlparse

from .scope import in_scope

# Resource words that mark an interesting backend route in a minified bundle.
ROUTE_WORDS = re.compile(
    r"(login|logout|user|users|account|accounts|order|orders|billing|invoice|"
    r"payment|payments|deal|report|reports|token|otp|password|reset|admin|"
    r"profile|auth|upload|export|import|role|permission|dashboard|wallet|"
    r"finance|sales|customer|cart|checkout|address|notification|message|file|"
    r"document|search|setting|settings|config|api|graphql|session|member|team|"
    r"project|ticket|transaction|balance|subscription|webhook)", re.I)

# XHR/fetch resource types Playwright reports for API traffic.
_API_TYPES = {"xhr", "fetch", "websocket"}
_ASSET_EXT = re.compile(r"\.(?:js|css|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|map|mp4|woff)(?:\?|$)", re.I)


def available():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


# --------------------------------------------------------------------------
def _identity_session(identity):
    """(cookies dict, headers dict) from an identity's captured session_blob."""
    if not identity or not getattr(identity, "session_blob", None):
        return {}, {}
    try:
        blob = json.loads(identity.session_blob)
        return blob.get("cookies") or {}, blob.get("headers") or {}
    except (ValueError, TypeError):
        return {}, {}


def _is_api_url(url, scope_rules):
    if not url or not url.startswith("http"):
        return False
    if _ASSET_EXT.search(url):
        return False
    ok, _ = in_scope(url, scope_rules)
    return ok


def _origin_of(u):
    """scheme://netloc of a URL (its origin), no path."""
    pu = urlparse(u)
    return f"{pu.scheme}://{pu.netloc}"


def capture(base_url, scope_rules, identity=None, max_urls=80, log=None):
    """Runtime capture: load the SPA and record its real XHR/fetch calls.

    Returns a list of {"method","url","has_body"} dicts, in scope, deduped by
    (method, url-without-fragment). Non-fatal: returns [] on any failure.
    """
    def _l(msg):
        if log:
            log("info", "spa", msg)

    if not available():
        _l("headless browser not installed — skipping runtime API capture")
        return []

    cookies_d, headers_d = _identity_session(identity)
    seen = {}
    order = []

    def _record(method, url, has_body):
        url = url.split("#")[0]
        if not _is_api_url(url, scope_rules):
            return
        key = (method.upper(), url)
        if key in seen:
            return
        seen[key] = {"method": method.upper(), "url": url, "has_body": has_body}
        order.append(key)

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    host = urlparse(base_url).hostname or ""
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True)
            # Authenticate the browser with the identity's captured session.
            if cookies_d:
                ck = [{"name": n, "value": v, "domain": host, "path": "/"}
                      for n, v in cookies_d.items()]
                try:
                    ctx.add_cookies(ck)
                except Exception:
                    pass
            if headers_d:
                try:
                    ctx.set_extra_http_headers({k: str(v) for k, v in headers_d.items()})
                except Exception:
                    pass

            page = ctx.new_page()

            def on_request(req):
                try:
                    if req.resource_type in _API_TYPES:
                        _record(req.method, req.url, bool(req.post_data))
                except Exception:
                    pass
            page.on("request", on_request)

            try:
                page.goto(base_url, wait_until="networkidle", timeout=30000)
            except PWTimeout:
                pass
            # Let late XHRs (dashboards, lazy routes) fire, and nudge the app.
            page.wait_for_timeout(2000)
            try:
                page.mouse.wheel(0, 4000)
                page.wait_for_timeout(1200)
            except Exception:
                pass

            # Visit same-origin in-app links to trigger more route loads.
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)") or []
            except Exception:
                hrefs = []
            visited = 0
            for h in dict.fromkeys(hrefs):
                if visited >= 8 or len(order) >= max_urls:
                    break
                if urlparse(h).hostname != host:
                    continue
                if _ASSET_EXT.search(h or ""):
                    continue
                try:
                    page.goto(h, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(600)
                    visited += 1
                except Exception:
                    continue

            browser.close()
    except Exception as e:
        from .browser_login import error_hint
        _l(f"runtime API capture unavailable — {error_hint(e)}")
        return [seen[k] for k in order][:max_urls]

    results = [seen[k] for k in order][:max_urls]
    _l(f"runtime API capture: {len(results)} XHR/fetch endpoint(s)"
       + (" (authenticated)" if cookies_d or headers_d else " (unauthenticated)"))
    return results


# --------------------------------------------------------------------------
_JS_SRC_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']""", re.I)
_HOST_RE = None  # built per-call from the base host


def harvest_static(base_url, send, scope_rules, max_bundles=12, log=None):
    """Browserless fallback: grep the HTML shell + JS bundles for API routes.

    Uses the engine's scope-checked ``send`` so nothing goes out of scope.
    Returns the same {"method","url","has_body"} shape (method GET, has_body
    False — these are reconstructed candidates, not observed calls).
    """
    def _l(msg):
        if log:
            log("info", "spa", msg)

    base = send("GET", base_url)
    if not base.get("ok"):
        return []
    html = base.get("text") or ""
    host = (urlparse(base_url).hostname or "").lower()
    reg = ".".join(host.split(".")[-2:]) if host else ""
    reg_host = re.escape(reg) if reg else r"[a-z0-9.-]+"

    # Collect bundle URLs (CRA /static/js, Next /_next/static, generic .js).
    bundles = []
    for m in _JS_SRC_RE.findall(html):
        u = urljoin(base_url, m).split("#")[0]
        ok, _ = in_scope(u, scope_rules)
        if ok and u not in bundles:
            bundles.append(u)
    bundles = bundles[:max_bundles]

    # Any absolute origin on the SAME registrable domain is a candidate backend
    # (api./backend./console. … or a sibling host). An SPA's real attack surface
    # lives on these, so we must notice them even when they are not yet in scope.
    origin_re = re.compile(r"https?://([a-z0-9][a-z0-9.-]*\.%s)\b" % reg_host, re.I)
    # Quoted absolute API/app paths, e.g. "/api/...", "/login/api/user/2fa/...".
    path_re = re.compile(
        r"""["'`](/(?:api|login|logout|auth|oauth2|admin|backoffice|super-admin|"""
        r"""internal|account|users?|v[0-9]|graphql|register|webhook|billing|report|"""
        r"""export|upload|file|document|dashboard|settings?|compliance|device|"""
        r"""policy|signature|profile|token|otp|2fa|reset)[a-z0-9/_.:{}$-]*)["'`]""", re.I)
    versioned_re = re.compile(r"/api/v[0-9]+/?", re.I)
    literal_re = re.compile(r'"(/?[a-z0-9_-]+(?:/[a-z0-9_{}:.-]+){1,5})"', re.I)

    origins, app_paths, bases, segments = set(), set(), set(), set()
    corpus = [html]                       # the shell can carry paths/origins too
    for bu in bundles:
        r = send("GET", bu)
        if r.get("ok"):
            corpus.append(r.get("text") or "")
    for body in corpus:
        for h in origin_re.findall(body):
            origins.add(h.rstrip("/").lower())
        for p in path_re.findall(body):
            app_paths.add(p.split("#")[0])
        for b in versioned_re.findall(body):
            bases.add(b.rstrip("/"))
        for seg in literal_re.findall(body):
            if ROUTE_WORDS.search(seg) and 3 <= len(seg) <= 80 and " " not in seg:
                seg = "/" + seg.lstrip("/")
                (app_paths if versioned_re.match(seg) else segments).add(seg)

    # Backend hosts we found but can't legally touch yet — say so, loudly, with the
    # exact --scope to add, instead of a silent empty crawl.
    ext_hosts = sorted(h for h in origins
                       if h != host and not in_scope(f"https://{h}/", scope_rules)[0])
    if ext_hosts:
        _l("backend host(s) referenced but OUT OF SCOPE — the app's real API lives here; "
           "re-run with --scope " + " --scope ".join(ext_hosts) + " to test it")

    # Hosts we may build candidates on: the base, plus any in-scope sibling/API host.
    api_origins = [f"https://{h}" for h in sorted(origins)
                   if in_scope(f"https://{h}/", scope_rules)[0]]
    roots = [_origin_of(base_url)] + api_origins

    # Resolve version-less resource segments against any seen /api/vN base.
    paths = set(app_paths)
    for seg in list(segments)[:80]:
        if bases:
            for b in bases:
                paths.add("/" + (b.strip("/") + seg))
        else:
            paths.add(seg)

    candidates = set(api_origins)                  # the bare origins, worth probing
    for p in paths:
        if not p.startswith("/"):
            p = "/" + p
        for root in roots:
            candidates.add(root + p)

    out, seen = [], set()
    for u in candidates:
        u = u.split("#")[0]
        if not _is_api_url(u, scope_rules) or u in seen:
            continue
        seen.add(u)
        out.append({"method": "GET", "url": u, "has_body": False})
    _l(f"static bundle harvest: {len(bundles)} bundle(s), {len(origins)} host(s) -> "
       f"{len(out)} candidate API route(s)")
    return out


# --------------------------------------------------------------------------
def discover_api(base_url, send, scope_rules, identity=None, log=None):
    """Top-level: runtime capture (if a browser is available) + static harvest,
    merged and deduped by URL. Returns {"method","url","has_body"} dicts."""
    merged = {}

    def _merge(items):
        for it in items:
            key = it["url"]
            # Prefer a non-GET / body-carrying observation over a bare GET guess.
            if key not in merged or (it.get("has_body") and not merged[key].get("has_body")):
                merged[key] = it

    _merge(capture(base_url, scope_rules, identity=identity, log=log))
    try:
        _merge(harvest_static(base_url, send, scope_rules, log=log))
    except Exception as e:
        if log:
            log("warn", "spa", f"static harvest error: {e}")
    return list(merged.values())
