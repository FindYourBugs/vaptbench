"""VAPTBench CLI — run an autonomous web VAPT from the terminal.

Same engine as the web UI (agent mode + deterministic verifiers), no browser
needed. Streams the live feed to stdout and prints a findings summary; can also
write a Markdown report.

Examples:
  python -m vaptbench.cli https://shop.example.com/
  python -m vaptbench.cli https://shop.example.com/ \\
      --role userA:alice@example.com:Passw0rd --login-url https://shop.example.com/login \\
      --report report.md
  python -m vaptbench.cli https://target/ --no-agent      # deterministic only
"""
import os
import re
import sys
import time
import shutil
import textwrap
import argparse
import warnings
from datetime import datetime
from urllib.parse import urlparse

# Targets often have self-signed / proxied TLS; we verify=False deliberately.
# Silence the resulting per-request urllib3 warning so the feed stays readable.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ANSI colours (disabled if not a tty)
_TTY = sys.stdout.isatty()
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s

_WIDTH = min(shutil.get_terminal_size((100, 24)).columns, 108)

# Each engine phase -> the human-readable section it belongs to. Printing a
# banner when the section changes turns the flat feed into a readable, phase-wise
# narrative a tester can follow top to bottom.
SECTIONS = {
    "start":    "SETUP",
    "auth":     "PHASE 1 · AUTHENTICATION",
    "recon":    "PHASE 2 · RECON & MAPPING",
    "spa":      "PHASE 2b · SPA API DISCOVERY",
    "agent":    "PHASE 3 · AUTONOMOUS TESTING  (AI agent decides each step)",
    "test":     "PHASE 3 · TESTING",
    "inject":   "PHASE 3b · INJECTION  (Tier-2: SSTI / LFI / NoSQLi / time-SQLi / cmd)",
    "advanced": "PHASE 3c · ADVANCED  (SSRF via OOB, stored & DOM XSS)",
    "access":   "PHASE 4 · ACCESS CONTROL  (replay each endpoint across roles)",
    "report":   "PHASE 5 · REPORT WRITE-UP",
    "critic":   "PHASE 5b · CRITIC REVIEW  (skeptical second opinion)",
    "chain":    "PHASE 6 · ATTACK-CHAIN CORRELATION",
    "done":     "COMPLETE",
    "error":    "ERROR",
}
# Short coloured marker per log level (replaces the old right-aligned word).
MARK = {"info": ("·", "36"), "test": ("→", "34"), "hit": ("✓", "32"),
        "warn": ("!", "33"), "error": ("✗", "31")}


VERSION = "0.8"

_LOGO = r"""
__      __     _____ _______ ____                  _
\ \    / /\   |  __ \__   __|  _ \                | |
 \ \  / /  \  | |__) | | |  | |_) | ___ _ __   ___| |__
  \ \/ / /\ \ |  ___/  | |  |  _ < / _ \ '_ \ / __| '_ \
   \  / ____ \| |      | |  | |_) |  __/ | | | (__| | | |
    \/_/    \_\_|      |_|  |____/ \___|_| |_|\___|_| |_|
"""


def _logo():
    """Print the launch banner (logo + tagline), HexStrike/PentestGPT style."""
    print(_c("1;36", _LOGO.rstrip("\n")))
    print(_c("1;37", "  Autonomous Web Application VAPT")
          + _c("90", "   ·   local-first AI   ·   proven findings only"))
    print(_c("90", f"  v{VERSION}   engine: AI agent + deterministic verifiers + critic")
          + _c("1;33", "    ⚠ test only what you are authorised to test"))


def _banner(title):
    pad = max(4, _WIDTH - len(title) - 4)
    return "\n" + _c("1;36", "━━ " + title + " " + "━" * pad)


def _is_ip_target(s):
    """True if s is an IP address or CIDR (optionally scheme/port-decorated)."""
    import ipaddress
    s = (s or "").strip()
    s = s.split("://", 1)[-1].split("/")[0] if "://" in s else s
    bare = s.split("/")[0].split(":")[0]       # strip CIDR/port for the address test
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)   # CIDR like 10.0.0.0/24
        return True
    except ValueError:
        return False


def _norm_url(s):
    """Return a normalised http(s) URL, or '' if the text isn't a URL/host."""
    s = (s or "").strip()
    if not s:
        return ""
    if not re.match(r"^https?://", s, re.I):
        # bare host/domain -> assume https; anything else (prose) is rejected
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:/.*)?$", s, re.I):
            s = "https://" + s
        else:
            return ""
    return s if urlparse(s).hostname else ""


def _prompt_url(label, example, required):
    for _ in range(5):
        try:
            raw = input(_c("1;32", f"  {label}") + f" {example} > ").strip()
        except EOFError:
            return ""
        if not raw and not required:
            return ""
        u = _norm_url(raw)
        if u:
            return u
        print(_c("31", f"    ✗ that's not a URL — enter something like {example.strip('()')}"))
    return ""


def _interactive_setup(args):
    """Prompt for target + scope + optional login roles when none were given on
    the command line — a console flow for testers who don't want flags.
    Inputs are validated so a stray phrase can't become a bogus target/scope."""
    import getpass
    print(_banner("NEW ENGAGEMENT"))
    args.target = _prompt_url("Target URL", "(e.g. https://shop.example.com/)", required=True)
    if not args.target:
        return
    host = urlparse(args.target).hostname or ""
    sc = input(_c("1;32", "  Scope hosts") +
               f" (space-separated, blank = just {host}) > ").strip()
    if sc:
        # keep only things that look like a host/domain/IP/CIDR/wildcard
        good, bad = [], []
        for tok in sc.split():
            (good if re.match(r"^[*A-Za-z0-9.\-/:]+\.[A-Za-z0-9*]+", tok) else bad).append(tok)
        if bad:
            print(_c("33", f"    ! ignored (not hosts): {' '.join(bad)}"))
        args.scope = good
    # The target host is always in scope (you're testing it) so the base is reachable.
    if host and host not in args.scope:
        args.scope.append(host)

    lu = _prompt_url("Login URL", "(blank = unauthenticated scan)", required=False)
    if lu:
        args.login_url = lu
        print(_c("90", "  Add role credentials — one per app role. Blank role name to finish."))
        while True:
            role = input("    role name (e.g. admin) > ").strip()
            if not role:
                break
            user = input("    username / email   > ").strip()
            if not user:
                print(_c("33", "    ! no username — role skipped"))
                continue
            try:
                pw = getpass.getpass("    password (hidden)   > ")
            except Exception:
                pw = input("    password            > ")
            if not pw:
                print(_c("33", "    ! no password entered — login will likely fail"))
            args.role.append(f"{role}:{user}:{pw}")
            print(_c("32", f"    + role '{role}' added ({user})"))
    else:
        args.login_url = ""


def _print_wrapped(mark_code, mark, body, indent="  "):
    """Print one feed line, word-wrapped with a hanging indent (nothing is cut
    mid-word, long AI thoughts read as a tidy paragraph)."""
    cont = indent + "  "
    lines = textwrap.wrap(body, width=_WIDTH - len(cont),
                          break_long_words=False, break_on_hyphens=False) or [""]
    print(f"{indent}{_c(mark_code, mark)} {lines[0]}")
    for extra in lines[1:]:
        print(f"{cont}{extra}")


def _render(row):
    """Render a single RunLog row in a phase-aware, readable way."""
    lvl = row.level or "info"
    msg = row.message or ""
    mark, code = MARK.get(lvl, ("·", "0"))

    # Agent step lines: "step N: ..." -> grouped Step heading + indented result.
    if msg.startswith("step ") and ":" in msg:
        head, _, rest = msg.partition(":")
        n = head.replace("step", "Step").strip().title()  # "Step 7"
        rest = rest.strip()
        if lvl == "test":                                   # the action + outcome
            rest = rest.replace(" -> ", "   ⇒  ")
            _print_wrapped("34", "→", rest, indent="      ")
        else:                                               # the agent's reasoning
            _print_wrapped("1;35", "▸", f"{n}  {rest}", indent="  ")
        return

    # Finding hits: colour by whether they're proven or just flagged.
    if lvl == "hit":
        proven = "(confirmed)" in msg
        _print_wrapped("32" if proven else "33", "✓" if proven else "?",
                       msg.lstrip("✓? ").strip())
        return

    _print_wrapped(code, mark, msg)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vaptbench", description="Autonomous web application VAPT (CLI).")
    ap.add_argument("target", nargs="?", default="",
                    help="target base URL, e.g. https://shop.example.com/ "
                         "(omit for interactive setup)")
    ap.add_argument("--scope", action="append", default=[], metavar="RULE",
                    help="scope rule (repeatable); default = the target host")
    ap.add_argument("--role", action="append", default=[], metavar="ROLE:USER:PASS",
                    help="login role, repeatable. e.g. userA:alice@x.com:Pass123")
    ap.add_argument("--login-url", default="", help="login page URL (form/auto auth)")
    ap.add_argument("--auth", default="auto",
                    help="auth type: auto|form|bearer|cookie|basic (default auto)")
    ap.add_argument("--mode", default="auto", choices=["auto", "web", "network"],
                    help="auto (detect from target) | web | network (infra VAPT by IP/CIDR)")
    ap.add_argument("--ports", default="", metavar="SPEC",
                    help="network mode port spec: top1000 (default) | all | "
                         "a range/list like 1-65535 or 22,80,8443")
    ap.add_argument("--no-agent", action="store_true",
                    help="disable the LLM agent; run the deterministic sweep only")
    ap.add_argument("--model", default="", metavar="NAME",
                    help="base local model (Ollama), e.g. qwen3:14b (default) or a bigger one")
    ap.add_argument("--agent-model", default="", metavar="NAME",
                    help="model for the attacker-brain agent loop (reasoning-heavy); defaults "
                         "to --model. Point this at a capable model, e.g. qwen3:32b or a cloud model")
    ap.add_argument("--ai-backend", default="", choices=["", "local", "cloud"],
                    help="local (Ollama, default) or cloud (needs --cloud-key)")
    ap.add_argument("--cloud-key", default="", metavar="KEY",
                    help="API key for --ai-backend cloud (else env VAPT_CLOUD_KEY)")
    ap.add_argument("--cloud-model", default="", metavar="NAME",
                    help="cloud model id (default claude-opus-4-8)")
    ap.add_argument("--postman", default="", metavar="PATH",
                    help="Postman collection (v2.x JSON) to ingest as API surface; can be "
                         "run alone (target/scope/token are derived from the file)")
    ap.add_argument("--ci", action="store_true",
                    help="CI gate: exit non-zero if confirmed findings meet --fail-on "
                         "(2 = gated findings, 1 = run error, 0 = clean)")
    ap.add_argument("--fail-on", default="low",
                    choices=["critical", "high", "medium", "low", "none"],
                    help="severity threshold for --ci (default low = any confirmed finding)")
    ap.add_argument("--report", default="", metavar="PATH",
                    help="write a report; extension picks format: .pdf (branded, "
                         "needs Chromium) | .html | .md")
    ap.add_argument("--company", default="VAPTBench Security",
                    help="company name on the report cover/footer")
    ap.add_argument("--tester", default="", help="lead tester name on the report")
    ap.add_argument("--client", default="", help="client/organisation name")
    ap.add_argument("--logo", default="", help="path to a logo image for the cover")
    ap.add_argument("--db", default="", help="sqlite db path (default: throwaway temp db)")
    ap.add_argument("--authorization", default="CLI-authorized engagement",
                    help="authorization note recorded with the engagement")
    args = ap.parse_args(argv)

    _logo()

    # Postman: a collection can be scanned on its OWN — derive the target URL,
    # scope hosts and (if present) the auth token straight from the file, so the
    # user can run `vapt.py --postman collection.json` with nothing else.
    pm_auth_header = ""
    if args.postman:
        if not os.path.isfile(args.postman):
            ap.error(f"--postman file not found: {args.postman}")
        os.environ["VAPT_POSTMAN"] = os.path.abspath(args.postman)
        if not args.target:
            from vaptbench import discovery as _disc
            prof = _disc.postman_profile(os.path.abspath(args.postman))
            if prof.get("error"):
                ap.error(f"could not read the Postman file: {prof['error']}")
            if not prof.get("resolved"):
                ap.error(
                    "the Postman collection has no usable base URL in it — its host is a "
                    "variable (e.g. {{baseUrl}}) whose value lives in a separate environment "
                    "export you didn't provide. Pass the API base URL as the target:\n"
                    f"  python vapt.py https://api.your-host.com/ --postman {args.postman}")
            args.target = prof["base_url"]
            if not args.scope:
                args.scope = list(prof["hosts"])
            if not args.role and prof.get("auth_header"):
                pm_auth_header = prof["auth_header"]
            print(_c("90", f"  derived from Postman → target {prof['base_url']}   "
                           f"scope: {', '.join(prof['hosts'])}"
                           + ("   + embedded auth token" if pm_auth_header else
                              "   (no auth token in file)")))

    if not args.target:
        if sys.stdin.isatty():
            _interactive_setup(args)
        if not args.target:
            ap.error("a target URL is required (pass it as an argument, via --postman, "
                     "or run interactively)")

    # Decide web vs network. IP/CIDR targets => network; otherwise validate URL.
    net_mode = args.mode == "network" or (args.mode == "auto" and _is_ip_target(args.target))
    if net_mode:
        args.target = args.target.split("://", 1)[-1].rstrip("/")   # keep raw IP/CIDR[:port]
    else:
        norm = _norm_url(args.target)
        if not norm:
            ap.error(f"target must be a URL (got {args.target!r}); e.g. "
                     "https://shop.example.com/  — or an IP/CIDR with --mode network")
        args.target = norm

    if args.ports:
        os.environ["VAPT_NET_PORTS_SPEC"] = args.ports
    if args.no_agent:
        os.environ["VAPT_AGENT"] = "0"
    # Model selection: the agent (attacker brain) can run on a more capable model
    # than the verifiers' base model — point --agent-model at it.
    if args.model:
        os.environ["VAPT_OLLAMA_MODEL"] = args.model
    if args.agent_model:
        os.environ["VAPT_MODEL_REASONER"] = args.agent_model
    if args.ai_backend:
        os.environ["VAPT_AI_BACKEND"] = args.ai_backend
    if args.cloud_key:
        os.environ["VAPT_CLOUD_KEY"] = args.cloud_key
    if args.cloud_model:
        os.environ["VAPT_CLOUD_MODEL"] = args.cloud_model
    if args.db:
        os.environ["VAPT_DB"] = args.db
    elif "VAPT_DB" not in os.environ:
        import tempfile
        os.environ["VAPT_DB"] = os.path.join(tempfile.gettempdir(), "vaptbench-cli.db")

    from vaptbench import create_app
    from vaptbench.models import db, Engagement, Target, Identity
    from vaptbench import engine, ai as ai_mod
    if net_mode:
        from vaptbench import netengine

    app = create_app()
    with app.app_context():
        host = (urlparse(args.target).hostname or args.target) if not net_mode else args.target
        # The target host is always in scope so the base URL is reachable, even
        # when the user also supplied explicit scope rules.
        scope_list = list(args.scope)
        if host and host not in scope_list:
            scope_list.append(host)
        scope = "\n".join(scope_list)

        eng = Engagement(name=f"CLI {host}", authorization=args.authorization)
        db.session.add(eng); db.session.commit()
        t = Target(engagement_id=eng.id, base_url=args.target, scope_rules=scope)
        db.session.add(t); db.session.commit()
        for spec in args.role:
            parts = spec.split(":", 2)
            ident = Identity(
                target_id=t.id,
                role=parts[0] if parts and parts[0] else "user",
                username=parts[1] if len(parts) > 1 else "",
                secret=parts[2] if len(parts) > 2 else "",
                auth_type=args.auth,
                login_url=args.login_url or args.target)
            db.session.add(ident)
        # auth token lifted from the Postman collection (no --role given)
        if pm_auth_header and not args.role:
            db.session.add(Identity(
                target_id=t.id, role="api", username="", secret=pm_auth_header,
                auth_type="curl", login_url=args.target))
        db.session.commit()
        tid = t.id

        ai_ok, ai_why = ai_mod.available()
        if net_mode:
            mode = "NETWORK · nmap + service verifiers" + ("" if ai_ok else "  (AI offline)")
        elif args.no_agent:
            mode = "deterministic (agent disabled)"
        elif ai_ok:
            c = ai_mod._cfg()
            if c["backend"] == "cloud":
                agent_model = c["cloud_model"]
            else:
                agent_model = ai_mod._model_for("reasoner", c)
            base = c["ollama_model"]
            mode = f"AGENT · {agent_model}" + (f" (verifiers: {base})" if agent_model != base else "")
        else:
            mode = f"deterministic (AI offline: {ai_why})"

        print(_banner("ENGAGEMENT"))
        print(f"  {_c('90','target')}   {_c('1;37', args.target)}")
        print(f"  {_c('90','scope ')}   {scope.replace(chr(10), ', ')}")
        print(f"  {_c('90','roles ')}   {len(args.role)}")
        print(f"  {_c('90','mode  ')}   {_c('1;36', mode)}")
        print(f"  {_c('90','db    ')}   {os.environ['VAPT_DB']}")
        print(f"\n  {_c('90','legend')}   "
              f"{_c('1;35','▸')} agent reasoning   {_c('34','→')} action/result   "
              f"{_c('32','✓')} proven   {_c('33','?')} needs review")

        rid = (netengine.start_run(app, tid) if net_mode else engine.start_run(app, tid))
        try:
            _follow(app, rid)
        except KeyboardInterrupt:
            print(_c("33", "\n  ^C — requesting stop..."))
            engine.request_stop(rid)
            _follow(app, rid)

        _summary(app, rid)
        if args.report:
            meta = {"company": args.company, "tester": args.tester,
                    "client": args.client or host, "logo": args.logo,
                    "target": args.target, "scope": scope.replace(chr(10), ", ")}
            _write_report(app, rid, args.target, args.report, meta)
        if args.ci:
            return _ci_gate(app, rid, args.fail_on)
    return 0


def _ci_gate(app, rid, fail_on):
    """CI exit code: 1 if the run errored, 2 if any CONFIRMED finding is at or
    above the --fail-on severity, else 0. Only confirmed findings gate a build —
    needs-review findings never break CI (the whole point of proven-only)."""
    from vaptbench.models import Run, Finding
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with app.app_context():
        run = Run.query.get(rid)
        if not run or run.status == "error":
            print(_c("31", "\n  CI: run errored → exit 1"))
            return 1
        if fail_on == "none":
            print(_c("90", "\n  CI: --fail-on none → exit 0"))
            return 0
        thresh = order[fail_on]
        gating = [f for f in Finding.query.filter_by(run_id=rid, confidence="confirmed").all()
                  if order.get(f.severity, 4) <= thresh]
        if gating:
            worst = min(gating, key=lambda f: order.get(f.severity, 4))
            print(_c("31", f"\n  CI GATE FAILED → exit 2 — {len(gating)} confirmed finding(s) "
                           f"≥ {fail_on} (worst: {worst.severity.upper()} {worst.title})"))
            return 2
        print(_c("32", f"\n  CI GATE PASSED → exit 0 — no confirmed finding ≥ {fail_on}"))
        return 0


def _follow(app, rid):
    """Tail the RunLog for this run until it reaches a terminal state, printing a
    phase banner whenever the section changes so the feed reads phase-wise."""
    from vaptbench.models import Run, RunLog
    last = 0
    state = {"section": None}

    def emit(r):
        nonlocal last
        last = r.id
        sect = SECTIONS.get(r.phase, r.phase.upper() if r.phase else "")
        if sect and sect != state["section"]:
            state["section"] = sect
            print(_banner(sect))
        _render(r)

    while True:
        with app.app_context():
            rows = (RunLog.query.filter(RunLog.run_id == rid, RunLog.id > last)
                    .order_by(RunLog.id).all())
            for r in rows:
                emit(r)
            run = Run.query.get(rid)
            status = run.status if run else "error"
        if status in ("done", "error", "stopped"):
            # one final drain for log lines written right before the terminal commit
            with app.app_context():
                for r in (RunLog.query.filter(RunLog.run_id == rid, RunLog.id > last)
                          .order_by(RunLog.id).all()):
                    emit(r)
            return
        time.sleep(0.5)


def _summary(app, rid):
    from vaptbench.models import Run, Finding
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with app.app_context():
        run = Run.query.get(rid)
        findings = sorted(Finding.query.filter_by(run_id=rid).all(),
                          key=lambda f: order.get(f.severity, 5))
        print("\n" + _c("1", "  Findings"))
        if not findings:
            print("    none")
        for f in findings:
            sev = f.severity.upper()
            col = {"CRITICAL": "31", "HIGH": "31", "MEDIUM": "33",
                   "LOW": "36", "INFO": "90"}.get(sev, "0")
            conf = _c("32", "confirmed") if f.confidence == "confirmed" else _c("90", f.confidence)
            print(f"    {_c(col, f'[{sev}]'):<20} {f.title}  ({conf})")
        n_conf = sum(1 for f in findings if f.confidence == "confirmed")
        print("  " + "-" * 58)
        print(f"  {run.status.upper()} — {len(findings)} finding(s), "
              f"{n_conf} confirmed, {run.endpoints_tested} endpoint(s), "
              f"{run.requests_sent} request(s)")


def _write_report(app, rid, target, path, meta=None):
    from vaptbench.models import Run, Finding
    from vaptbench import report as report_mod
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with app.app_context():
        run = Run.query.get(rid)
        findings = sorted(Finding.query.filter_by(run_id=rid).all(),
                          key=lambda f: order.get(f.severity, 5))
        # .pdf / .html -> branded report module; .md -> the markdown below.
        if path.lower().endswith((".pdf", ".html", ".htm")):
            ok, msg = report_mod.write(run, findings, path, meta or {"target": target})
            if ok:
                print(_c("32", f"\n  report written: {msg}"))
            else:
                print(_c("33", f"\n  {msg}"))
            return
        lines = [
            f"# VAPT Report — {target}",
            "",
            f"- Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"- Status: {run.status}",
            f"- Endpoints tested: {run.endpoints_tested}",
            f"- Requests sent: {run.requests_sent}",
            f"- Findings: {len(findings)} "
            f"({sum(1 for f in findings if f.confidence == 'confirmed')} confirmed)",
            "",
            "## Summary",
            "",
            "| Severity | Title | Class | Status |",
            "|---|---|---|---|",
        ]
        for f in findings:
            lines.append(f"| {f.severity} | {f.title} | {f.vuln_class} | {f.confidence} |")
        lines.append("")
        lines.append("## Findings")
        for i, f in enumerate(findings, 1):
            lines += [
                "",
                f"### {i}. {f.title}",
                "",
                f"- **Severity:** {f.severity}",
                f"- **Class:** {f.vuln_class}",
                f"- **Confidence:** {f.confidence}" + (f"  \n- **CVSS:** {f.cvss}" if f.cvss else ""),
                "",
                (f.description or "").strip(),
            ]
            if f.steps:
                lines += ["", "**Steps to reproduce:**", "", "```", f.steps.strip(), "```"]
            if f.poc_request:
                lines += ["", "**Request:**", "", "```http", f.poc_request.strip(), "```"]
            if f.poc_response:
                lines += ["", "**Response (evidence):**", "", "```",
                          (f.poc_response or "")[:1500].strip(), "```"]
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(_c("32", f"\n  report written: {path}"))


if __name__ == "__main__":
    sys.exit(main())
