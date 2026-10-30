"""The web workbench: playbooks, repeater, and the access-control matrix."""
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, current_app

from ..models import db, Target, Identity, RequestLog, ReconRun, Run, RunLog, Finding
from .. import engine


def _ensure_scope(t):
    """Blank scope would default-deny everything. The target's own host is
    implicitly authorised (the user entered it), so seed it automatically."""
    if not (t.scope_rules or "").strip():
        host = urlparse(t.base_url).hostname
        if host:
            t.scope_rules = host
            db.session.commit()
from ..skills import list_web_playbooks, load_playbook
from ..http_client import send, access_matrix
from ..scope import in_scope
from ..ai import ask, available as ai_available
from ..auth import login as do_login
from ..recon import available_tools, run_tool

bp = Blueprint("web_workbench", __name__)


@bp.route("/target/<int:tid>")
def workbench(tid):
    t = Target.query.get_or_404(tid)
    playbooks = list_web_playbooks()
    reqs = RequestLog.query.filter_by(target_id=tid).order_by(RequestLog.created.desc()).limit(50).all()
    runs = ReconRun.query.filter_by(target_id=tid).order_by(ReconRun.created.desc()).limit(20).all()
    ai_ok, _ = ai_available()
    return render_template("workbench.html", t=t, playbooks=playbooks,
                           reqs=reqs, runs=runs, tools=available_tools(), ai_ok=ai_ok)


@bp.route("/target/<int:tid>/start", methods=["POST"])
def start_vapt(tid):
    """Launch an autonomous VAPT run against this target."""
    t = Target.query.get_or_404(tid)
    _ensure_scope(t)
    app = current_app._get_current_object()
    rid = engine.start_run(app, tid)
    return redirect(url_for("web_workbench.run_view", rid=rid))


@bp.route("/run/<int:rid>")
def run_view(rid):
    run = Run.query.get_or_404(rid)
    return render_template("run.html", run=run, t=run.target)


@bp.route("/run/<int:rid>/feed")
def run_feed(rid):
    """Live feed polled by the run page: new logs + current findings + stats."""
    run = Run.query.get_or_404(rid)
    after = request.args.get("after", 0, type=int)
    logs = (RunLog.query.filter(RunLog.run_id == rid, RunLog.id > after)
            .order_by(RunLog.id).all())
    findings = Finding.query.filter_by(run_id=rid).order_by(Finding.id.desc()).all()
    return jsonify({
        "status": run.status, "phase": run.phase,
        "stats": {"endpoints": run.endpoints_tested, "requests": run.requests_sent,
                  "findings": run.findings_count},
        "logs": [{"id": l.id, "level": l.level, "phase": l.phase,
                  "message": l.message,
                  "ts": l.ts.strftime("%H:%M:%S") if l.ts else ""} for l in logs],
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity,
                      "vuln_class": f.vuln_class, "confidence": f.confidence}
                     for f in findings],
    })


@bp.route("/run/<int:rid>/stop", methods=["POST"])
def run_stop(rid):
    return jsonify({"stopped": engine.request_stop(rid)})


@bp.route("/identity/<int:iid>/login", methods=["POST"])
def identity_login(iid):
    """Automated login for one identity; captures its session."""
    ident = Identity.query.get_or_404(iid)
    t = Target.query.get(ident.target_id)
    _ensure_scope(t)
    ok, msg = do_login(ident, t.scope_rules)
    ident.login_status = ("ok: " if ok else "fail: ") + msg
    db.session.commit()
    return jsonify({"ok": ok, "message": msg, "role": ident.role})


@bp.route("/target/<int:tid>/login-all", methods=["POST"])
def login_all(tid):
    """Log in as every identity in one go."""
    t = Target.query.get_or_404(tid)
    _ensure_scope(t)
    results = []
    for ident in t.identities:
        ok, msg = do_login(ident, t.scope_rules)
        ident.login_status = ("ok: " if ok else "fail: ") + msg
        results.append({"role": ident.role, "ok": ok, "message": msg})
    db.session.commit()
    return jsonify({"results": results})


@bp.route("/target/<int:tid>/recon", methods=["POST"])
def recon(tid):
    """Run one recon tool against the target; store run; import any URLs."""
    t = Target.query.get_or_404(tid)
    tool = request.get_json(force=True).get("tool", "")
    res = run_tool(tool, t.base_url, t.scope_rules)

    imported = 0
    if res.get("urls"):
        existing = {r.url for r in RequestLog.query.filter_by(target_id=tid).all()}
        for u in res["urls"]:
            if u not in existing:
                db.session.add(RequestLog(target_id=tid, method="GET", url=u))
                existing.add(u)
                imported += 1

    run = ReconRun(target_id=tid, tool=tool, command=res.get("command", ""),
                   status=res["status"], output=res.get("output", ""),
                   url_count=imported)
    db.session.add(run)
    db.session.commit()
    return jsonify({"status": res["status"], "command": res.get("command", ""),
                    "output": res.get("output", ""), "imported": imported})


@bp.route("/playbook/<slug>")
def playbook(slug):
    pb = load_playbook(slug)
    if not pb:
        return jsonify({"error": "not found"}), 404
    return jsonify(pb)


@bp.route("/target/<int:tid>/scope-check")
def scope_check(tid):
    t = Target.query.get_or_404(tid)
    url = request.args.get("url", "")
    ok, why = in_scope(url, t.scope_rules)
    return jsonify({"in_scope": ok, "reason": why})


@bp.route("/target/<int:tid>/repeater", methods=["POST"])
def repeater(tid):
    """Send a request by hand, optionally as a chosen identity. Scope-guarded."""
    t = Target.query.get_or_404(tid)
    d = request.get_json(force=True)
    ident = Identity.query.get(d["identity_id"]) if d.get("identity_id") else None
    result = send(d.get("method", "GET"), d["url"], t.scope_rules,
                  headers=d.get("headers", ""), body=d.get("body", ""),
                  identity=ident)
    # Capture the request so it can be replayed across identities later.
    if result.get("ok"):
        log = RequestLog(target_id=tid, method=d.get("method", "GET"), url=d["url"],
                         req_headers=d.get("headers", ""), req_body=d.get("body", ""),
                         status=result.get("status"), resp_len=result.get("len"),
                         resp_body=result.get("text", "")[:20000])
        db.session.add(log)
        db.session.commit()
    return jsonify(result)


@bp.route("/request/<int:rid>/matrix")
def matrix(rid):
    """Replay one captured request under every identity for this target."""
    r = RequestLog.query.get_or_404(rid)
    t = Target.query.get(r.target_id)
    idents = Identity.query.filter_by(target_id=t.id).all()
    rows = access_matrix(r, idents, t.scope_rules)
    return jsonify({"request": {"method": r.method, "url": r.url}, "rows": rows})


@bp.route("/target/<int:tid>/ai-suggest", methods=["POST"])
def ai_suggest(tid):
    """Ask the local model for the next manual step, grounded in a playbook."""
    ok, msg = ai_available()
    if not ok:
        return jsonify({"error": msg}), 503
    d = request.get_json(force=True)
    pb = load_playbook(d["slug"]) if d.get("slug") else None
    ctx = pb["body"][:6000] if pb else ""
    system = ("You are a web application pentest assistant guiding a human operator. "
              "Suggest the next concrete MANUAL test step and an example request. "
              "The operator runs every action; never claim to have run anything.")
    prompt = (f"Target: {d.get('url','')}\n"
              f"Observation so far:\n{d.get('context','')}\n\n"
              f"Methodology playbook ({d.get('slug','')}):\n{ctx}\n\n"
              "What is the next manual step to test here?")
    return jsonify({"answer": ask(prompt, system=system)})
