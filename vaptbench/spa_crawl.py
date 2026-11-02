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
        _l(f"runtime API capture error: {e}")
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
    host = urlparse(base_url).hostname or ""
    reg_host = re.escape(".".join(host.split(".")[-2:])) if host else r"[a-z0-9.-]+"

    # Collect bundle URLs (CRA /static/js, Next /_next/static, generic .js).
    bundles = []
    for m in _JS_SRC_RE.findall(html):
        u = urljoin(base_url, m).split("#")[0]
        ok, _ = in_scope(u, scope_rules)
        if ok and u not in bundles:
            bundles.append(u)
    bundles = bundles[:max_bundles]

    host_re = re.compile(r"https://[a-z0-9.-]*(?:api|console|backend|service|gateway)"
                         r"[a-z0-9.-]*\." + reg_host + r"[a-z0-9/_.-]*", re.I)
    base_path_re = re.compile(r"/api/v[0-9]+/[a-z0-9/_-]+", re.I)
    versioned_re = re.compile(r"/api/v[0-9]+/?", re.I)
    literal_re = re.compile(r'"(/?[a-z0-9_-]+(?:/[a-z0-9_{}:.-]+){1,5})"', re.I)

    api_hosts, full_paths, bases, segments = set(), set(), set(), set()
    for bu in bundles:
        r = send("GET", bu)
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        for h in host_re.findall(body):
            api_hosts.add(h.rstrip("/"))
        for p in base_path_re.findall(body):
            full_paths.add(p)
        for b in versioned_re.findall(body):
            bases.add(b.rstrip("/"))
        for seg in literal_re.findall(body):
            if ROUTE_WORDS.search(seg) and 3 <= len(seg) <= 80 and " " not in seg:
                seg = "/" + seg.lstrip("/")
                if versioned_re.match(seg):
                    full_paths.add(seg)      # already versioned = a full path
                else:
                    segments.add(seg)

    candidates = set()
    # 1) Full API hosts seen verbatim.
    candidates |= api_hosts
    # 2) Full /api/vN/... paths on the base host.
    for p in full_paths:
        candidates.add(urljoin(base_url, p))
    # 3) Version-less resource segments: prefix each known /api/vN base, or (if
    #    none seen) try them on the base host directly.
    for seg in list(segments)[:60]:
        if bases:
            for b in bases:
                candidates.add(urljoin(base_url, b + seg))
        else:
            candidates.add(urljoin(base_url, seg))

    out, seen = [], set()
    for u in candidates:
        u = u.split("#")[0]
        if not _is_api_url(u, scope_rules) or u in seen:
            continue
        seen.add(u)
        out.append({"method": "GET", "url": u, "has_body": False})
    _l(f"static bundle harvest: {len(bundles)} bundle(s) -> {len(out)} candidate API route(s)")
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
