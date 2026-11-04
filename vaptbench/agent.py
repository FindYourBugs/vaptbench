"""Agentic planner — the autonomous 'brain' on top of the deterministic engine.

The model (local qwen3:14b by default) does NOT get to assert bugs. It only
chooses the next ACTION from a fixed, safe set; the deterministic verifiers
decide what is real. So we get PentestGPT-agent-style autonomy while keeping
vaptbench's anti-hallucination guarantee: every finding is still proven.

Loop:
    observe (endpoints, findings so far, roles)  ->
    model picks one action (JSON)                ->
    execute it with the existing verifiers/tools ->
    feed the outcome back                         ->
    repeat until it calls finish() or the step budget runs out.

Engine builds a Ctx and calls run_agent(ctx). Each decision is streamed to the
live run feed so the operator sees the agent reasoning.
"""
import difflib
import json
import os
import re
from urllib.parse import urlparse

from . import verifiers as V
from . import verifiers2 as V2
from . import verifiers3 as V3
from . import ai as ai_mod
from .skills import list_web_playbooks

_ENV_STEPS = os.environ.get("VAPT_AGENT_STEPS", "")
MAX_STEPS = int(_ENV_STEPS) if _ENV_STEPS.isdigit() else 24   # fallback; run_agent scales it


def _budget(ctx):
    """Step budget: explicit env override, else scale with the surface size so
    big apps get enough steps and tiny ones don't spin. Capped to stay sane."""
    if _ENV_STEPS.isdigit():
        return int(_ENV_STEPS)
    return max(30, min(80, len(ctx.endpoints) + 2 * sum(
        1 for u in ctx.endpoints if urlparse(u).query)))

# The action vocabulary the model may choose from. Keeping it fixed and small
# is what keeps a 14B model reliable — it picks WHERE to look, not free shell.
ACTIONS = """\
Available actions (choose exactly one per turn):
- {"action":"probe","url":"<url>"}            inspect one endpoint (status, size, title, params, forms)
- {"action":"crawl","url":"<url>"}            discover more in-scope endpoints linked from this page
- {"action":"test","url":"<url>","classes":["xss","sqli","cors","methods","open_redirect","clickjacking"]}
                                              run deterministic Tier-1 checks for those classes
- {"action":"inject","url":"<url>"}           run Tier-2 injection suite (ssti, lfi, nosqli, time-sqli, cmd)
- {"action":"advanced","url":"<url>"}         SSRF (OOB-confirmed) + stored/DOM XSS
- {"action":"access_control","url":"<url>"}   replay across all roles to find IDOR / broken authz
- {"action":"request","method":"POST","url":"<url>","headers":{"K":"V"},"body":{...}|"raw","as":"anon|auth","expect":"what a response proves"}
                                              craft and SEND one real request, then READ the response yourself —
                                              use this to probe an API endpoint with the right method+body, to try a
                                              sensitive function with NO session ("as":"anon"), or to retry a failed
                                              attempt a different way. Non-destructive: DELETE is blocked by default.
- {"action":"finish","reason":"<why>"}        stop — ONLY when in-scope surface is exhausted, not just "no bugs yet"
When unsure, expand the surface (crawl/probe) rather than finish.
Always include a short "thought" field explaining the choice."""

TIER1 = {
    "cors": V.check_cors,
    "methods": V.check_methods,
    "open_redirect": V.check_open_redirect,
    "xss": V.check_reflected_xss,
    "sqli": V.check_error_sqli,
}


class Ctx:
    """Everything the agent needs, supplied by the engine (no circular import)."""
    def __init__(self, run, send, scope, endpoints, identities, seen,
                 add_finding, log, oob_host="127.0.0.1:8090"):
        self.run = run
        self.send = send
        self.scope = scope
        self.endpoints = list(endpoints)       # mutable: crawl can grow it
        self.identities = identities
        self.seen = seen
        self.add_finding = add_finding          # engine._add_finding bound to (run, seen)
        self.log = log                          # engine._log bound to run
        self.oob_host = oob_host
        self.primary = identities[0] if identities else None
        self.tested = set()                     # urls already tier-1 tested
        self.injected = set()
        self.advanced = set()                   # urls already advanced-tested
        self.accessed = set()                   # urls already authz-replayed


# --------------------------------------------------------------------------
def run_agent(ctx):
    """Drive the engagement with the model choosing each step. Falls back to
    a deterministic sweep if the AI is unavailable or keeps producing garbage."""
    ok, why = ai_mod.available()
    if not ok:
        ctx.log("warn", "agent", f"AI unavailable ({why}) — agent mode needs the model; skipping")
        return False

    budget = _budget(ctx)
    ctx.log("info", "agent", f"Agent mode: {ai_mod._cfg()['ollama_model']} planning up to {budget} steps")
    history = []
    bad_streak = 0
    waste_streak = 0

    for step in range(1, budget + 1):
        if getattr(ctx.run, "stop_requested", False):
            ctx.log("warn", "agent", "stop requested — halting agent")
            break

        decision = ai_mod.ask_json(_prompt(ctx, history), system=_SYSTEM, role="reasoner")
        action = (decision.get("action") or "").strip().lower()
        thought = " ".join((decision.get("thought") or "").split())[:280]

        if action not in ("probe", "crawl", "test", "inject", "advanced",
                           "access_control", "finish"):
            bad_streak += 1
            ctx.log("warn", "agent", f"step {step}: unusable decision ({decision}); nudging")
            history.append({"step": step, "action": "invalid", "result": "not a known action"})
            if bad_streak >= 3:
                ctx.log("warn", "agent", "model not cooperating — falling back to deterministic sweep")
                return False
            continue
        bad_streak = 0

        if thought:
            ctx.log("info", "agent", f"step {step}: {thought}")

        if action == "finish":
            ctx.log("info", "agent", f"step {step}: finish — {decision.get('reason','(done)')}")
            break

        # Repair a model-mangled host (a typo like viamo→viami) by snapping it to
        # the nearest known endpoint, and refuse to burn the budget re-poking a
        # host that is not a known in-scope endpoint — the model loops on these.
        url = decision.get("url", "")
        if action in ("probe", "crawl", "test", "inject", "advanced", "access_control", "request"):
            fixed = _repair_url(ctx, url)
            if fixed != url:
                ctx.log("info", "agent", f"step {step}: corrected url host -> {fixed}")
                url = fixed
                decision["url"] = url
            if url and not _in_scope_url(ctx, url):
                waste_streak += 1
                ctx.log("warn", "agent",
                        f"step {step}: {action} {url} -> not a known in-scope endpoint; "
                        f"choose one from the list")
                history.append({"step": step, "action": action, "url": url,
                                "result": "invalid: not a known in-scope endpoint"})
                if waste_streak >= 6:
                    ctx.log("warn", "agent",
                            "agent stuck on out-of-scope URLs — handing to deterministic phases")
                    break
                continue
        waste_streak = 0

        result = _dispatch(ctx, action, decision)
        ctx.log("test", "agent", f"step {step}: {action} {decision.get('url','')} -> {result}")
        history.append({"step": step, "action": action,
                        "url": decision.get("url", ""), "result": result})

    ctx.log("info", "agent", f"Agent finished after {len(history)} step(s)")
    return True


# --------------------------------------------------------------------------
_SYSTEM = (
    "You are an autonomous penetration tester on an AUTHORISED web-app VAPT. Work "
    "like a human attacker: first UNDERSTAND the application, then attack it.\n"
    "MAP FIRST, RELENTLESSLY — your findings are only as good as the surface you "
    "reach. Reach every page, parameter, route and API. Crawl to pull in linked "
    "pages and form fields; probe endpoints you have not inspected. Hunt the real "
    "surface: a backend API host, auth/2FA/password-reset flows, admin/backoffice "
    "areas, object IDs, file uploads, API docs (Swagger/OpenAPI/GraphQL). If the "
    "surface looks tiny for a real application, assume you are missing it and keep "
    "crawling/probing before you conclude anything.\n"
    "ATTACK ADAPTIVELY — pick the action most likely to expose a real, high-impact "
    "bug on the surface you have: test (Tier-1), inject (Tier-2 server-side "
    "injection), advanced (SSRF/stored-XSS), access_control (IDOR/BOLA/privilege "
    "escalation across roles). The verifiers already try many payload variants and "
    "WAF-evasions per call; your job is to aim them at the right endpoint and to "
    "FOLLOW LEADS — an id, a tenant, an admin route one result exposes becomes the "
    "next action. If an attack fails, try a different endpoint, parameter or angle "
    "rather than repeating it.\n"
    "USE YOUR HANDS — the 'request' action sends ONE real request you craft (method, "
    "headers, body) and returns the actual response for you to read. Reach for it to "
    "probe an API with the correct method and JSON body, to try a sensitive function "
    "with NO session (\"as\":\"anon\") to check whether auth is enforced, to reuse an id "
    "or token you saw, and to retry a failed attempt a different way. Read each "
    "response and let it shape the next request — that is how you actually exploit, "
    "not just scan. Stay non-destructive: prove a weakness, don't damage data.\n"
    "NEVER CLAIM A BUG YOURSELF — deterministic verifiers confirm findings. What you "
    "suspect but cannot prove is recorded for human review, never as confirmed, and "
    "you must not fabricate.\n"
    "DO NOT STOP EARLY — 'finish' only when the in-scope surface is genuinely "
    "exhausted: every known endpoint probed/tested, crawling yields nothing new, and "
    "no referenced backend host is left unexplored. 'No bugs found yet' is NOT a "
    "reason to finish. Don't re-test the same URL or inject static assets "
    "(.js/.css/images) — at most probe one once for leaked secrets."
)


def _prompt(ctx, history):
    eps = ctx.endpoints
    param_eps = [u for u in eps if urlparse(u).query]
    roles = [i.role for i in ctx.identities] or ["(unauthenticated only)"]
    found = _findings_summary(ctx)
    hist = history[-8:]
    lines = [
        f"TARGET endpoints in scope ({len(eps)} known, {len(param_eps)} with params):",
    ]
    for u in eps[:25]:
        tag = " [tested]" if u in ctx.tested else ""
        lines.append(f"  - {u}{tag}")
    lines.append(f"ROLES available: {', '.join(roles)}")
    lines.append(f"FINDINGS so far: {found or 'none yet'}")
    lines.append("RECENT ACTIONS:")
    for h in hist:
        lines.append(f"  step {h['step']}: {h['action']} {h.get('url','')} -> {h['result']}")
    lines.append("")
    lines.append(ACTIONS)
    lines.append('\nReturn JSON like: {"thought":"...","action":"inject","url":"https://..."}')
    return "\n".join(lines)


def _findings_summary(ctx):
    from .models import Finding
    rows = Finding.query.filter_by(run_id=ctx.run.id).all()
    if not rows:
        return ""
    return "; ".join(f"[{r.severity}] {r.vuln_class} ({r.confidence})" for r in rows[:12])


# --------------------------------------------------------------------------
def _dispatch(ctx, action, d):
    try:
        if action == "probe":
            return _probe(ctx, d.get("url", ""))
        if action == "crawl":
            return _crawl(ctx, d.get("url", ""))
        if action == "test":
            return _test(ctx, d.get("url", ""), d.get("classes") or list(TIER1))
        if action == "inject":
            return _inject(ctx, d.get("url", ""))
        if action == "advanced":
            return _advanced(ctx, d.get("url", ""))
        if action == "access_control":
            return _access(ctx, d.get("url", ""))
        if action == "request":
            return _request(ctx, d)
    except Exception as e:
        return f"error: {e}"
    return "no-op"


def _in_scope_url(ctx, url):
    return bool(url) and url.startswith("http") and any(
        urlparse(url).hostname == urlparse(e).hostname for e in ctx.endpoints)


def _known_hosts(ctx):
    out = []
    for e in ctx.endpoints:
        h = urlparse(e).hostname
        if h and h not in out:
            out.append(h)
    return out


def _repair_url(ctx, url):
    """Snap a model-mangled host (e.g. the typo 'viamo' for 'viami') to the
    nearest known in-scope endpoint host. Returns the corrected url, or the
    original when the host is already known or nothing is close enough."""
    if not url or not url.startswith("http"):
        return url
    host = urlparse(url).hostname or ""
    hosts = _known_hosts(ctx)
    if not host or host in hosts:
        return url
    match = difflib.get_close_matches(host, hosts, n=1, cutoff=0.8)
    if match and match[0] != host:
        pu = urlparse(url)
        netloc = match[0] + (f":{pu.port}" if pu.port else "")
        return pu._replace(netloc=netloc).geturl()
    return url


def _probe(ctx, url):
    if not url:
        return "no url"
    r = ctx.send("GET", url, identity=ctx.primary)
    if not r.get("ok"):
        return f"blocked/failed: {r.get('reason')}"
    body = r.get("text") or ""
    import re
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if m:
        title = m.group(1).strip()[:60]
    forms = len(re.findall(r"<form", body, re.I))
    params = list(dict.fromkeys(
        p.split("=")[0] for p in (urlparse(url).query.split("&") if urlparse(url).query else [])))
    return f"{r.get('status')} {r.get('len')}b title='{title}' forms={forms} params={params}"


def _crawl(ctx, url):
    """Add in-scope endpoints (links + FORM parameters) linked from url."""
    from .engine import _page_links
    target = url or (ctx.endpoints[0] if ctx.endpoints else "")
    r = ctx.send("GET", target, identity=ctx.primary)
    if not r.get("ok"):
        return f"failed: {r.get('reason')}"
    added = param_added = 0
    for u in _page_links(r.get("text") or "", target, target):
        if u not in ctx.endpoints:
            ctx.endpoints.append(u)
            added += 1
            if urlparse(u).query:
                param_added += 1
    extra = f", {param_added} with params" if param_added else ""
    return f"crawled, +{added} endpoint(s){extra} (total {len(ctx.endpoints)})"


def _test(ctx, url, classes):
    if not _in_scope_url(ctx, url):
        return "url not in scope / unknown"
    if url in ctx.tested:
        return "already Tier-1 tested this URL — pick a different endpoint"
    ctx.tested.add(url)
    hits = []
    # response-based check needs a GET first
    if "clickjacking" in classes:
        g = ctx.send("GET", url, identity=ctx.primary)
        if g.get("ok"):
            for f in V.check_clickjacking(url, g):
                ctx.add_finding(f); hits.append(f["vuln_class"])
    for name in classes:
        fn = TIER1.get(name)
        if not fn:
            continue
        for f in fn(ctx.send, url):
            ctx.add_finding(f); hits.append(f["vuln_class"])
    return f"tested {classes} -> " + (", ".join(sorted(set(hits))) if hits else "no findings")


def _inject(ctx, url):
    if not _in_scope_url(ctx, url):
        return "url not in scope / unknown"
    from .engine import is_static_asset
    if is_static_asset(url):
        return "skipped — static asset (JS/CSS/image) has no server-side injection surface"
    if url in ctx.injected:
        return "already injected this URL (no new surface) — pick a different endpoint"
    ctx.injected.add(url)
    hits = []
    for fn in (V2.check_ssti, V2.check_lfi, V2.check_nosqli,
               V2.check_time_sqli, V2.check_cmd_injection):
        try:
            for f in fn(ctx.send, url):
                ctx.add_finding(f); hits.append(f["vuln_class"])
        except Exception:
            pass
    return "injection -> " + (", ".join(sorted(set(hits))) if hits else "no findings")


def _advanced(ctx, url):
    if not _in_scope_url(ctx, url):
        return "url not in scope / unknown"
    from .engine import is_static_asset
    if is_static_asset(url):
        return "skipped — static asset (JS/CSS/image) is not an SSRF/stored-XSS surface"
    if url in ctx.advanced:
        return "already advanced-tested this URL — pick a different endpoint"
    ctx.advanced.add(url)
    import time
    import uuid
    from .models import OobHit

    def make_callback(tag):
        token = f"{tag}{uuid.uuid4().hex[:12]}"
        return token, f"http://{ctx.oob_host}/oob/{token}"

    def was_hit(token):
        for _ in range(6):
            if OobHit.query.filter_by(token=token).first():
                return True
            time.sleep(0.5)
        return False

    hits = []
    for f in V3.check_ssrf(ctx.send, url, make_callback, was_hit):
        ctx.add_finding(f); hits.append(f["vuln_class"])
    for f in V3.check_stored_xss(ctx.send, url, ctx.endpoints[:12]):
        ctx.add_finding(f); hits.append(f["vuln_class"])
    for f in V3.check_dom_xss(ctx.send, url):
        ctx.add_finding(f); hits.append(f["vuln_class"])
    return "advanced -> " + (", ".join(sorted(set(hits))) if hits else "no findings")


_SENS_PATH = re.compile(
    r"(admin|backoffice|super-?admin|internal|report|audit|user|account|customer|"
    r"compliance|setting|config|password|token|secret|2fa|mfa|otp|billing|invoice|"
    r"policy|device|directory|tenant|dashboard|export|profile)", re.I)
_SECRETISH = re.compile(
    r'"?(?:password|secret|token|api[_-]?key|private[_-]?key|totp|mfa[_-]?secret|'
    r'ssn|authenticator)"?\s*[:=]', re.I)
_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I)
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}


def _request(ctx, d):
    """Send ONE agent-crafted request and return a rich summary for the model to
    reason on. Non-destructive by default. If an ANONYMOUS request to a sensitive
    path returns substantial data with secret/PII markers, record a needs-review
    finding — never a fabricated 'confirmed'; a human validates the exposure."""
    url = _repair_url(ctx, d.get("url", ""))
    if not _in_scope_url(ctx, url):
        return "url not in scope / unknown"
    method = str(d.get("method", "GET")).upper()
    if method == "DELETE" and os.environ.get("VAPT_ALLOW_DESTRUCTIVE", "0") != "1":
        return "DELETE blocked (safe mode); set VAPT_ALLOW_DESTRUCTIVE=1 to allow"
    if method not in _SAFE_METHODS and method != "DELETE":
        return f"unsupported method {method}"

    raw_h = d.get("headers")
    if isinstance(raw_h, dict):
        hstr = "\n".join(f"{k}: {v}" for k, v in raw_h.items())
    else:
        hstr = str(raw_h or "")
    raw_b = d.get("body")
    if isinstance(raw_b, (dict, list)):
        body = json.dumps(raw_b)
        if "content-type" not in hstr.lower():
            hstr = (hstr + "\nContent-Type: application/json").strip()
    else:
        body = str(raw_b or "")

    # "as": anon (default for a missing-auth probe) | auth/session/<role>
    as_role = str(d.get("as", "anon")).lower()
    want_auth = as_role in ("auth", "session", "primary") or (
        ctx.primary is not None and as_role == (ctx.primary.role or "").lower())
    identity = ctx.primary if want_auth else None

    r = ctx.send(method, url, headers=hstr, body=body, identity=identity)
    if not r.get("ok"):
        return f"blocked/failed: {r.get('reason')}"
    status, blen, btext = r.get("status"), r.get("len") or 0, r.get("text") or ""
    emails = len(set(_EMAIL.findall(btext)))
    secretish = bool(_SECRETISH.search(btext))
    path = urlparse(url).path
    who = "authenticated" if identity else "anonymous"

    # Conservative, deterministic needs-review signal for the agentic exploit loop:
    # an ANONYMOUS request that got substantial data back from a sensitive path,
    # carrying secret/PII markers, is a real lead a human must verify.
    if (identity is None and status == 200 and blen >= 120
            and _SENS_PATH.search(path) and (secretish or emails >= 2)):
        marker = "secret/credential field" if secretish else f"{emails} email address(es)"
        ctx.add_finding({
            "title": f"Unauthenticated data/function exposure: {path}",
            "vuln_class": "hunt-auth", "severity": "high", "confidence": "needs-review",
            "cvss": "",
            "description": (f"{method} {url} with NO session returned HTTP {status} and "
                            f"{blen}B containing {marker}, on a sensitivity-suggesting path. "
                            f"This endpoint may expose data/functions without authentication. "
                            f"Needs human verification (is this data meant to be public?)."),
            "steps": f"{method} {url} with no Cookie/Authorization header; inspect the response.",
            "poc_request": f"{method} {url}  (no session)" + (f"\n\n{body}" if body else ""),
            "poc_response": btext[:600],
        })
        return (f"{who} {method} -> {status} {blen}B | emails={emails} secretish={secretish} "
                f"| ⚠ recorded needs-review (possible unauth exposure)")
    return (f"{who} {method} -> {status} {blen}B | emails={emails} secretish={secretish} "
            f"| snippet: {btext[:160].strip()!r}")


def _access(ctx, url):
    if not _in_scope_url(ctx, url):
        return "url not in scope / unknown"
    if url in ctx.accessed:
        return "already access-control replayed this URL — pick a different endpoint"
    ctx.accessed.add(url)
    from .engine import _access_control
    before = ctx.run.findings_count or 0
    _access_control(ctx.run, ctx.send, [url], ctx.identities, ctx.seen)
    gained = (ctx.run.findings_count or 0) - before
    return f"access-control replay -> {gained} new flag(s)"
