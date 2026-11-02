"""Autonomous VAPT engine (Phase 1).

Given a target, runs the whole methodology in a background thread:
  authenticate -> recon/map -> test (Tier-1 deterministic) -> access-control
  -> record findings. Correctness comes from verifiers.py; the engine is the
  orchestration + live feed. AI-crafted injection (Tier 2) plugs in later.

Phase 1 is fully deterministic and does NOT require the AI backend, so it runs
even while Ollama is being wired up.
"""
import os
import re
import time
import uuid
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse

from .models import db, Target, Identity, RequestLog, Run, RunLog, Finding, OobHit
from .http_client import send as http_send
from .auth import login as do_login
from .recon import run_tool
from . import verifiers as V
from . import verifiers2 as V2
from . import verifiers3 as V3
from . import ai_tester
from . import ai as ai_mod
from . import agent as agent_mod
from . import critic as critic_mod
from . import spa_crawl
from .skills import load_playbook

SPA_CRAWL = os.environ.get("VAPT_SPA_CRAWL", "1") != "0"  # discover XHR/fetch API surface

AGENT_MODE = os.environ.get("VAPT_AGENT", "1") != "0"   # LLM-driven when model is up
CRITIC_MODE = os.environ.get("VAPT_CRITIC", "1") != "0"  # skeptical review of findings
MAX_INJECT_ENDPOINTS = 15   # timing checks are request-heavy; cap them
MAX_ADV_ENDPOINTS = 8       # SSRF/stored are O(n^2)-ish; cap tighter
OOB_HOST = os.environ.get("VAPT_OOB_HOST", "127.0.0.1:8090")

MAX_ENDPOINTS = 40
LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\'#?\s][^"\']*)["\']', re.I)
ASSET_RE = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|mp4|webm)(?:$|\?)", re.I)


def is_static_asset(url):
    """Static resources (JS/CSS/images/fonts) are public by design — not an
    injection or access-control surface. Used to suppress false positives and
    stop the agent wasting steps on them."""
    return bool(ASSET_RE.search(url or ""))


# --------------------------------------------------------------------------
def start_run(app, target_id):
    """Create a Run and launch it in the background. Returns the Run id."""
    t = Target.query.get(target_id)
    run = Run(target_id=target_id, engagement_id=t.engagement_id,
              status="queued", phase="queued")
    db.session.add(run)
    db.session.commit()
    rid = run.id
    threading.Thread(target=_run, args=(app, rid), daemon=True).start()
    return rid


def request_stop(run_id):
    run = Run.query.get(run_id)
    if run and run.status == "running":
        run.stop_requested = True
        db.session.commit()
        return True
    return False


# --------------------------------------------------------------------------
def _log(run, level, phase, message):
    db.session.add(RunLog(run_id=run.id, level=level, phase=phase, message=message))
    run.phase = phase
    db.session.commit()


def _add_finding(run, seen, f):
    key = (f["vuln_class"], f["title"])
    if key in seen:
        return
    seen.add(key)
    fn = Finding(engagement_id=run.engagement_id, run_id=run.id,
                 title=f["title"], vuln_class=f["vuln_class"],
                 severity=f["severity"], cvss=f.get("cvss", ""),
                 confidence=f.get("confidence", "confirmed"),
                 status="confirmed" if f.get("confidence") == "confirmed" else "open",
                 description=f.get("description", ""), steps=f.get("steps", ""),
                 poc_request=f.get("poc_request", ""), poc_response=f.get("poc_response", ""))
    db.session.add(fn)
    run.findings_count = (run.findings_count or 0) + 1
    mark = "✓" if f.get("confidence") == "confirmed" else "?"
    _log(run, "hit", run.phase,
         f"{mark} [{f['severity'].upper()}] {f['title']} ({f.get('confidence')})")


def _same_origin(a, b):
    return urlparse(a).hostname == urlparse(b).hostname


def _page_links(html, page_url, base_url):
    """In-scope same-origin links + synthesised GET-form URLs from one page."""
    from . import forms as forms_mod
    out = set()
    for m in LINK_RE.findall(html or ""):
        u = urljoin(page_url, m)
        if u.startswith("http") and _same_origin(u, base_url):
            out.add(u.split("#")[0])
    for u in forms_mod.get_form_urls(html, page_url):   # form params = injectable surface
        if _same_origin(u, base_url):
            out.add(u)
    return out


def _discover(base_url, base_html, scope_rules, run, send=None, primary=None):
    """Build an endpoint list: links + FORM parameters in the base page, one
    level of authenticated crawl, katana, and known captured requests."""
    found = {base_url}
    found |= _page_links(base_html, base_url, base_url)

    # One level deeper, authenticated: the entry page (login, landing) rarely
    # links straight to the injectable pages — fetch the pages it does link to
    # (as the logged-in user) and harvest THEIR links + form parameters. This is
    # what gets us from login.php/index to /vulnerabilities/sqli/?id=... .
    if send is not None:
        frontier = [u for u in list(found) if u != base_url and not is_static_asset(u)][:15]
        for u in frontier:
            if run.stop_requested:
                break
            r = send("GET", u, identity=primary)
            body = r.get("text") or ""
            if r.get("ok") and ("<html" in body[:4000].lower() or "<form" in body.lower()):
                found |= _page_links(body, u, base_url)

    # Light katana crawl if available (depth 1); non-fatal if missing.
    res = run_tool("katana", base_url, scope_rules)
    if res.get("status") == "done":
        for u in res.get("urls", [])[:200]:
            if _same_origin(u, base_url):
                found.add(u.split("#")[0])
        _log(run, "info", "recon", f"katana crawl added endpoints (total {len(found)})")
    else:
        _log(run, "info", "recon", f"katana unavailable ({res.get('status')}); using in-page links")

    # Include anything already captured for this target.
    for r in RequestLog.query.filter_by(target_id=run.target_id).all():
        if _same_origin(r.url, base_url):
            found.add(r.url.split("#")[0])

    # Prefer parameterised URLs (more testable), then cap.
    ordered = sorted(found, key=lambda u: (0 if urlparse(u).query else 1, len(u)))
    return ordered[:MAX_ENDPOINTS]


def _spa_discover(run, send, t, endpoints, primary, scope):
    """Find the SPA's backend API (XHR/fetch + JS-bundle routes) and merge it in.

    API routes are the true attack surface on a JS app, so they are prioritised
    ahead of static page URLs and persisted as captured requests (for the
    Repeater / access-control matrix). Returns the merged, re-capped list.
    """
    _log(run, "info", "spa", "Discovering SPA backend API (XHR/fetch capture + JS bundle harvest)...")
    try:
        api = spa_crawl.discover_api(
            t.base_url, send, scope, identity=primary,
            log=lambda lvl, ph, msg: _log(run, lvl, ph, msg))
    except Exception as e:
        _log(run, "warn", "spa", f"SPA API discovery error: {e}")
        return endpoints
    if not api:
        _log(run, "info", "spa", "no SPA API endpoints discovered (static site, or app made no in-scope calls)")
        return endpoints

    existing = set(endpoints)
    api_urls, new = [], 0
    for it in api:
        url = it["url"]
        if url not in existing:
            new += 1
            # Persist so the Repeater / matrix can replay it.
            db.session.add(RequestLog(target_id=t.id, method=it.get("method", "GET"),
                                      url=url, resp_body=""))
        if url not in api_urls:
            api_urls.append(url)
    db.session.commit()

    withparam = sum(1 for u in api_urls if urlparse(u).query)
    _log(run, "info", "spa",
         f"SPA API: {len(api_urls)} endpoint(s) ({new} new, {withparam} with params) — "
         f"prioritised as attack surface")

    # API endpoints first (query'd ones ahead), then the original page URLs.
    api_sorted = sorted(api_urls, key=lambda u: (0 if urlparse(u).query else 1, len(u)))
    merged, out = set(), []
    for u in api_sorted + endpoints:
        if u not in merged:
            merged.add(u); out.append(u)
    return out[:MAX_ENDPOINTS]


def _run(app, run_id):
    with app.app_context():
        run = Run.query.get(run_id)
        run.status = "running"
        db.session.commit()
        try:
            t = Target.query.get(run.target_id)
            identities = Identity.query.filter_by(target_id=t.id).all()
            scope = t.scope_rules
            seen = set()

            def send(method, url, headers="", body="", identity=None):
                r = http_send(method, url, scope, headers=headers, body=body, identity=identity)
                run.requests_sent = (run.requests_sent or 0) + 1
                return r

            _log(run, "info", "start", f"Autonomous VAPT on {t.base_url} — {len(identities)} identity(ies)")

            # --- Phase 1: authenticate -------------------------------------
            _log(run, "info", "auth", "Logging in identities...")
            primary = None
            for ident in identities:
                ok, msg = do_login(ident, scope)
                ident.login_status = ("ok: " if ok else "fail: ") + msg
                db.session.commit()
                _log(run, "info" if ok else "warn", "auth", f"{ident.role}: {msg}")
                if ok and primary is None:
                    primary = ident

            # --- Phase 2: recon / map --------------------------------------
            _log(run, "info", "recon", "Mapping attack surface...")
            base = send("GET", t.base_url, identity=primary)
            if not base.get("ok"):
                _log(run, "error", "recon", f"base unreachable: {base.get('reason')}")
                run.status = "error"; run.finished = datetime.utcnow(); db.session.commit()
                return
            endpoints = _discover(t.base_url, base.get("text", ""), scope, run,
                                  send=send, primary=primary)
            withparam = sum(1 for u in endpoints if urlparse(u).query)
            _log(run, "info", "recon",
                 f"{len(endpoints)} endpoint(s) in scope to test ({withparam} with parameters)")

            # SPA API discovery: capture the real XHR/fetch backend routes that a
            # JS app talks to (invisible in server HTML). This is the actual
            # attack surface on React/Vue/Angular/Next targets.
            if SPA_CRAWL:
                endpoints = _spa_discover(run, send, t, endpoints, primary, scope)

            # Passive checks on the base response (phase back to recon so these
            # findings are attributed correctly, not to the SPA sub-phase).
            _log(run, "info", "recon",
                 "Passive checks on base response (security headers, cookie flags, "
                 "clickjacking, exposed files)...")
            for f in (V.check_headers(t.base_url, base) + V.check_cookies(t.base_url, base)
                      + V.check_clickjacking(t.base_url, base)):
                _add_finding(run, seen, f)
            for f in V.check_exposed_files(send, t.base_url):
                _add_finding(run, seen, f)

            # --- Phase 3: test & exploit -----------------------------------
            # Agent mode: the model drives order/depth across all tiers. If the
            # model is down or uncooperative it returns False and we fall back
            # to the fixed deterministic sweep below. Either way, verifiers are
            # the only thing that can record a finding.
            agent_drove = False
            if AGENT_MODE:
                ctx = agent_mod.Ctx(
                    run=run, send=send, scope=scope, endpoints=endpoints,
                    identities=identities, seen=seen,
                    add_finding=lambda f: _add_finding(run, seen, f),
                    log=lambda lvl, ph, msg: _log(run, lvl, ph, msg),
                    oob_host=OOB_HOST)
                agent_drove = agent_mod.run_agent(ctx)
                if agent_drove:
                    endpoints = ctx.endpoints        # keep anything the agent crawled
                    run.endpoints_tested = max(run.endpoints_tested or 0, len(ctx.tested))
                    db.session.commit()

            if agent_drove:
                _log(run, "info", "test", "Agent completed the test tiers; running baseline access-control + report")
            else:
                _deterministic_sweep(run, send, t, endpoints, identities, seen, primary)

            # --- Phase 4: access-control matrix ----------------------------
            if len(identities) >= 1 and not run.stop_requested:
                _log(run, "info", "access", "Replaying endpoints across roles (access control)...")
                _access_control(run, send, endpoints, identities, seen)

            # --- Phase 5: AI finding write-ups (best-effort) ---------------
            if not run.stop_requested:
                _writeup_phase(run)

            # --- Phase 5b: critic review (skeptical second opinion) --------
            if CRITIC_MODE and not run.stop_requested:
                _critic_phase(run)

            # --- Phase 6: chain correlated findings ------------------------
            if not run.stop_requested:
                _chain_phase(run, seen)

            run.status = "stopped" if run.stop_requested else "done"
            run.phase = "done"
            run.finished = datetime.utcnow()
            db.session.commit()
            _log(run, "info", "done",
                 f"Run {run.status}: {run.findings_count} finding(s), "
                 f"{run.endpoints_tested} endpoint(s), {run.requests_sent} request(s)")
        except Exception as e:
            run = Run.query.get(run_id)
            run.status = "error"; run.finished = datetime.utcnow()
            db.session.add(RunLog(run_id=run.id, level="error", phase="error", message=str(e)))
            db.session.commit()


def _deterministic_sweep(run, send, t, endpoints, identities, seen, primary=None):
    """The original fixed-script test tiers — fallback when the agent is off."""
    _log(run, "info", "test", "Testing endpoints (Tier-1 deterministic classes)...")
    for i, url in enumerate(endpoints, 1):
        if run.stop_requested:
            _log(run, "warn", "test", "stop requested — halting"); break
        run.endpoints_tested = i
        _log(run, "test", "test", f"[{i}/{len(endpoints)}] {url}")
        g = send("GET", url, identity=primary)
        if g.get("ok"):
            for f in V.check_clickjacking(url, g):
                _add_finding(run, seen, f)
        for fn in (V.check_cors, V.check_methods, V.check_open_redirect,
                   V.check_reflected_xss, V.check_error_sqli):
            try:
                for f in fn(send, url):
                    _add_finding(run, seen, f)
            except Exception as e:  # one check failing must not kill the run
                _log(run, "warn", "test", f"{fn.__name__} error on {url}: {e}")
        db.session.commit()

    # --- Tier-2 injection (deterministic + AI-assisted) ---
    if not run.stop_requested:
        _inject_phase(run, send, t, endpoints, identities, seen)

    # --- Tier-3 advanced (SSRF/OOB, stored XSS, DOM) ---
    if not run.stop_requested:
        _advanced_phase(run, send, t, endpoints, seen)


def _collect_tokens(identities):
    """Pull candidate JWT strings from identities' sessions/secrets."""
    import json as _json
    toks = []
    for i in identities:
        if i.secret:
            toks.append(i.secret)
        if i.session_blob:
            try:
                blob = _json.loads(i.session_blob)
                toks += list((blob.get("cookies") or {}).values())
                toks += [v for v in (blob.get("headers") or {}).values()]
            except Exception:
                pass
    return toks


def _inject_phase(run, send, t, endpoints, identities, seen):
    """Tier-2: time-based SQLi/cmd-injection, SSTI, LFI, NoSQLi, GraphQL, JWT."""
    ai_ok, _ = ai_mod.available()
    _log(run, "info", "inject",
         "Injection testing (Tier-2 deterministic%s)..." % (" + AI payloads" if ai_ok else ""))

    # Token-level + target-level checks (cheap, run once).
    for f in V2.check_jwt(_collect_tokens(identities)):
        _add_finding(run, seen, f)
    for f in V2.check_graphql(send, t.base_url, endpoints):
        _add_finding(run, seen, f)

    param_eps = [u for u in endpoints if urlparse(u).query][:MAX_INJECT_ENDPOINTS]
    skill_cache = {}
    for i, url in enumerate(param_eps, 1):
        if run.stop_requested:
            _log(run, "warn", "inject", "stop requested — halting"); break
        _log(run, "test", "inject", f"[{i}/{len(param_eps)}] injecting {url}")
        checks = (V2.check_ssti, V2.check_lfi, V2.check_nosqli,
                  V2.check_time_sqli, V2.check_cmd_injection)
        hit_classes = set()
        for fn in checks:
            try:
                for f in fn(send, url):
                    hit_classes.add(f["vuln_class"])
                    _add_finding(run, seen, f)
            except Exception as e:
                _log(run, "warn", "inject", f"{fn.__name__} error: {e}")

        # AI payload augmentation for signal-based classes it may have missed.
        if ai_ok:
            _ai_augment(run, send, url, seen, hit_classes, skill_cache)
        db.session.commit()


def _ai_augment(run, send, url, seen, hit_classes, skill_cache):
    """Try AI-suggested payloads; a result counts only if a deterministic
    signal still trips (so the AI widens coverage, verifiers keep truth)."""
    from .verifiers2 import _set_param, _params, PASSWD_RE
    _, q = _params(url)
    signals = {
        "hunt-ssti": lambda b: "vss5767" in b,                     # 73*79
        "hunt-lfi": lambda b: bool(PASSWD_RE.search(b)) or "[extensions]" in b.lower(),
    }
    for vclass, sig in signals.items():
        if vclass in hit_classes:
            continue
        if vclass not in skill_cache:
            pb = load_playbook(vclass)
            skill_cache[vclass] = pb["body"] if pb else ""
        payloads = ai_tester.extra_payloads(vclass, skill_cache[vclass])
        for key in list(q)[:2]:
            for p in payloads:
                r = send("GET", _set_param(url, key, p))
                if r.get("ok") and sig(r.get("text") or ""):
                    _add_finding(run, seen, dict(
                        title=f"{vclass.replace('hunt-','').upper()} via '{key}' (AI payload)",
                        vuln_class=vclass, severity="high", cvss="", confidence="confirmed",
                        description=f"An AI-suggested payload for {vclass} tripped the deterministic signal on '{key}'. Payload: {p}",
                        steps=f"GET {_set_param(url, key, p)}",
                        poc_request=f"GET {_set_param(url, key, p)}",
                        poc_response=(r.get("text") or "")[:800]))
                    break


def _advanced_phase(run, send, t, endpoints, seen):
    """SSRF (OOB-confirmed), stored XSS (two-step), DOM-XSS candidates."""
    _log(run, "info", "advanced", f"Advanced tests (SSRF via OOB host {OOB_HOST}, stored/DOM XSS)...")

    def make_callback(tag):
        token = f"{tag}{uuid.uuid4().hex[:12]}"
        return token, f"http://{OOB_HOST}/oob/{token}"

    def was_hit(token):
        for _ in range(6):                       # poll ~3s for a callback
            if OobHit.query.filter_by(token=token).first():
                return True
            time.sleep(0.5)
        return False

    param_eps = [u for u in endpoints if urlparse(u).query][:MAX_ADV_ENDPOINTS]
    for url in param_eps:
        if run.stop_requested:
            break
        try:
            for f in V3.check_ssrf(send, url, make_callback, was_hit):
                _add_finding(run, seen, f)
            for f in V3.check_stored_xss(send, url, endpoints[:MAX_ADV_ENDPOINTS]):
                _add_finding(run, seen, f)
        except Exception as e:
            _log(run, "warn", "advanced", f"error on {url}: {e}")
        db.session.commit()

    for url in endpoints[:MAX_ADV_ENDPOINTS]:
        if run.stop_requested:
            break
        try:
            for f in V3.check_dom_xss(send, url):
                _add_finding(run, seen, f)
        except Exception as e:
            _log(run, "warn", "advanced", f"dom error on {url}: {e}")
    db.session.commit()


# Rule-based escalation chains: any confirmed finding of a listed class makes
# the chain apply. The chain is surfaced as a high needs-review note that ties
# the member findings together and explains the realistic escalation.
CHAIN_RULES = [
    ({"hunt-ssti", "hunt-rce"}, "Injection → Remote Code Execution",
     "Template/command injection gives code execution on the server — full host compromise."),
    ({"hunt-jwt-crypto"}, "Forged JWT → account & privilege takeover",
     "The HS256 secret is crackable, so tokens can be forged for any user or role (admin ATO)."),
    ({"hunt-ssrf"}, "SSRF → internal services / cloud metadata",
     "The SSRF can target 169.254.169.254 or internal hosts to steal cloud credentials and pivot."),
    ({"hunt-sqli"}, "SQLi → database compromise / auth bypass",
     "The injection allows reading or altering the database and may bypass authentication."),
    ({"hunt-xss"}, "Stored/Reflected XSS → session & account takeover",
     "Script execution in victims' sessions enables cookie/session theft and account takeover."),
    ({"hunt-idor", "hunt-open-redirect"}, "Access-control + redirect → targeted exploitation",
     "Broken access control combined with an open redirect enables targeted data theft / phishing."),
]


def _chain_phase(run, seen):
    confirmed = Finding.query.filter_by(run_id=run.id, confidence="confirmed").all()
    present = {f.vuln_class for f in confirmed}
    if not present:
        return
    _log(run, "info", "chain", "Correlating findings into attack chains...")
    ai_ok = ai_mod.available()[0]
    for classes, title, narrative in CHAIN_RULES:
        members = [f for f in confirmed if f.vuln_class in classes]
        if not members:
            continue
        mtitles = "; ".join(f"[{m.severity}] {m.title}" for m in members)
        desc = narrative + "\n\nBased on confirmed findings: " + mtitles
        if ai_ok:
            try:
                nr = ai_mod.ask(
                    f"Confirmed findings: {mtitles}\nExplain, in 3-4 sentences, the realistic "
                    f"attack chain and business impact. Be factual, no invented details.",
                    system="You are a penetration tester summarising an exploit chain.",
                    role="reasoner")
                if nr and len(nr) > 40:
                    desc += "\n\n--- AI chain analysis ---\n" + nr
            except Exception:
                pass
        _add_finding(run, seen, dict(
            title="Attack chain: " + title, vuln_class="chain", severity="high",
            cvss="", confidence="needs-review", description=desc,
            steps="See the member findings referenced above.",
            poc_request="", poc_response=mtitles))


def _writeup_phase(run):
    """Improve confirmed findings' prose with the AI, grounded in the skill."""
    if not ai_mod.available()[0]:
        return
    _log(run, "info", "report", "AI writing up confirmed findings...")
    cache = {}
    for fn in Finding.query.filter_by(run_id=run.id, confidence="confirmed").all():
        if fn.vuln_class not in cache:
            pb = load_playbook(fn.vuln_class)
            cache[fn.vuln_class] = pb["body"] if pb else ""
        upd = ai_tester.writeup({
            "title": fn.title, "vuln_class": fn.vuln_class, "severity": fn.severity,
            "description": fn.description, "poc_response": fn.poc_response,
        }, cache[fn.vuln_class])
        if upd.get("description"):
            fn.description = upd["description"]
            db.session.commit()


def _critic_phase(run):
    """Skeptical second opinion on each finding via the reasoning model.

    Advisory only: appends an 'Analyst review' to the finding and, if the critic
    suspects a false positive, flags it for human verification. Never overturns
    a deterministically confirmed finding on its own.
    """
    if not ai_mod.available()[0]:
        return
    rmodel = ai_mod._model_for("reasoner")
    _log(run, "info", "critic", f"Critic reviewing findings ({rmodel})...")
    cache = {}
    for fn in Finding.query.filter_by(run_id=run.id).all():
        if fn.vuln_class == "chain":
            continue
        if fn.vuln_class not in cache:
            pb = load_playbook(fn.vuln_class)
            cache[fn.vuln_class] = pb["body"] if pb else ""
        try:
            rev = critic_mod.review({
                "title": fn.title, "vuln_class": fn.vuln_class, "severity": fn.severity,
                "description": fn.description, "poc_request": fn.poc_request,
                "poc_response": fn.poc_response,
            }, cache[fn.vuln_class])
        except Exception as e:
            _log(run, "warn", "critic", f"review error on {fn.title}: {e}")
            continue
        if not rev:
            continue
        note = critic_mod.format_note(rev)
        if note:
            fn.description = (fn.description or "") + "\n\n" + note
        if critic_mod.is_fp_suspect(rev):
            fn.description += "\n\n⚠ Critic flagged possible FALSE POSITIVE — verify before reporting."
            _log(run, "warn", "critic", f"⚠ possible FP: {fn.title} ({fn.severity})")
        else:
            _log(run, "info", "critic", f"reviewed: {fn.title} [{rev.get('verdict','')}]")
        db.session.commit()


def _access_control(run, send, endpoints, identities, seen):
    """Replay each endpoint as every role + unauthenticated, flag anomalies.

    Deterministic signal: an unauthenticated request getting 200 with a body
    comparable to an authenticated one on a non-root endpoint = possible broken
    access control. Marked needs-review (ownership can't be proven headless).

    Only runs when at least one role actually logged in — otherwise every role
    is effectively unauthenticated and the comparison is meaningless (which is
    what produced the bogus flags when SPA login failed).
    """
    authed = [i for i in identities if getattr(i, "session_blob", None)]
    if not authed:
        _log(run, "info", "access",
             "no authenticated role (logins failed or none supplied) — "
             "skipping access-control matrix (nothing to compare)")
        return
    roles = [(i.role, i) for i in authed] + [("unauth", None)]
    for url in endpoints[:20]:
        if run.stop_requested:
            break
        if urlparse(url).path in ("", "/") or is_static_asset(url):
            continue
        results = {}
        for role, ident in roles:
            r = send("GET", url, identity=ident)
            results[role] = (r.get("status"), r.get("len")) if r.get("ok") else (None, None)
        unauth = results.get("unauth")
        authed = [v for k, v in results.items() if k != "unauth" and v[0] == 200]
        if unauth and unauth[0] == 200 and authed:
            # unauth sees a 200 that an authed role also sees -> maybe no authz
            matrix = ", ".join(f"{k}={v[0]}/{v[1]}" for k, v in results.items())
            _add_finding(run, seen, dict(
                title=f"Possible broken access control: {urlparse(url).path}",
                vuln_class="hunt-idor", severity="medium", cvss="",
                confidence="needs-review",
                description=f"{url} returns 200 to an UNAUTHENTICATED request as well as to "
                            f"authenticated roles. Verify whether it should require auth / "
                            f"whether it exposes another user's data.\nMatrix: {matrix}",
                steps=f"GET {url} with and without a session; compare.",
                poc_request=f"GET {url}", poc_response=f"role matrix: {matrix}"))
