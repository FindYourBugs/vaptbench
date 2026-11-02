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
import sys
import time
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
LEVELCOL = {"info": "36", "test": "34", "hit": "32", "warn": "33", "error": "31"}


def _fmt(row):
    lvl = row.level or "info"
    tag = _c(LEVELCOL.get(lvl, "0"), f"{lvl:>5}")
    ph = _c("90", f"[{row.phase}]")
    return f"  {tag} {ph} {row.message}"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vaptbench", description="Autonomous web application VAPT (CLI).")
    ap.add_argument("target", help="target base URL, e.g. https://shop.example.com/")
    ap.add_argument("--scope", action="append", default=[], metavar="RULE",
                    help="scope rule (repeatable); default = the target host")
    ap.add_argument("--role", action="append", default=[], metavar="ROLE:USER:PASS",
                    help="login role, repeatable. e.g. userA:alice@x.com:Pass123")
    ap.add_argument("--login-url", default="", help="login page URL (form/auto auth)")
    ap.add_argument("--auth", default="auto",
                    help="auth type: auto|form|bearer|cookie|basic (default auto)")
    ap.add_argument("--no-agent", action="store_true",
                    help="disable the LLM agent; run the deterministic sweep only")
    ap.add_argument("--report", default="", metavar="PATH",
                    help="write a Markdown report to this path")
    ap.add_argument("--db", default="", help="sqlite db path (default: throwaway temp db)")
    ap.add_argument("--authorization", default="CLI-authorized engagement",
                    help="authorization note recorded with the engagement")
    args = ap.parse_args(argv)

    if args.no_agent:
        os.environ["VAPT_AGENT"] = "0"
    if args.db:
        os.environ["VAPT_DB"] = args.db
    elif "VAPT_DB" not in os.environ:
        import tempfile
        os.environ["VAPT_DB"] = os.path.join(tempfile.gettempdir(), "vaptbench-cli.db")

    from vaptbench import create_app
    from vaptbench.models import db, Engagement, Target, Identity
    from vaptbench import engine, ai as ai_mod

    app = create_app()
    with app.app_context():
        host = urlparse(args.target).hostname or args.target
        scope = "\n".join(args.scope) if args.scope else host

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
        db.session.commit()
        tid = t.id

        ai_ok, ai_why = ai_mod.available()
        if args.no_agent:
            mode = "deterministic (agent disabled)"
        elif ai_ok:
            mode = f"AGENT · {ai_mod._cfg()['ollama_model']}"
        else:
            mode = f"deterministic (AI offline: {ai_why})"

        print(_c("1", "\nVAPTBench — autonomous web VAPT"))
        print(f"  target : {args.target}")
        print(f"  scope  : {scope.replace(chr(10), ', ')}")
        print(f"  roles  : {len(args.role)}  |  mode: {mode}")
        print(f"  db     : {os.environ['VAPT_DB']}")
        print("  " + "-" * 58)

        rid = engine.start_run(app, tid)
        try:
            _follow(app, rid)
        except KeyboardInterrupt:
            print(_c("33", "\n  ^C — requesting stop..."))
            engine.request_stop(rid)
            _follow(app, rid)

        _summary(app, rid)
        if args.report:
            _write_report(app, rid, args.target, args.report)
            print(_c("32", f"\n  report written: {args.report}"))
    return 0


def _follow(app, rid):
    """Tail the RunLog for this run until it reaches a terminal state."""
    from vaptbench.models import Run, RunLog
    last = 0
    while True:
        with app.app_context():
            rows = (RunLog.query.filter(RunLog.run_id == rid, RunLog.id > last)
                    .order_by(RunLog.id).all())
            for r in rows:
                last = r.id
                print(_fmt(r))
            run = Run.query.get(rid)
            status = run.status if run else "error"
        if status in ("done", "error", "stopped"):
            # one final drain for log lines written right before the terminal commit
            with app.app_context():
                for r in (RunLog.query.filter(RunLog.run_id == rid, RunLog.id > last)
                          .order_by(RunLog.id).all()):
                    print(_fmt(r))
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


def _write_report(app, rid, target, path):
    from vaptbench.models import Run, Finding
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with app.app_context():
        run = Run.query.get(rid)
        findings = sorted(Finding.query.filter_by(run_id=rid).all(),
                          key=lambda f: order.get(f.severity, 5))
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


if __name__ == "__main__":
    sys.exit(main())
