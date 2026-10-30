"""Findings capture + report export."""
from flask import Blueprint, render_template, request, redirect, url_for, Response

from ..models import db, Engagement, Finding, RequestLog

bp = Blueprint("findings", __name__)

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@bp.route("/engagement/<int:eid>/finding/new", methods=["POST"])
def new_finding(eid):
    f = Finding(
        engagement_id=eid,
        title=request.form["title"],
        vuln_class=request.form.get("vuln_class", ""),
        severity=request.form.get("severity", "info"),
        cvss=request.form.get("cvss", ""),
        description=request.form.get("description", ""),
        steps=request.form.get("steps", ""),
    )
    # Attach a captured request/response as the PoC, if given.
    rid = request.form.get("request_id")
    if rid:
        r = RequestLog.query.get(int(rid))
        if r:
            f.poc_request = f"{r.method} {r.url}\n{r.req_headers}\n\n{r.req_body}"
            f.poc_response = f"HTTP {r.status} ({r.resp_len} bytes)\n\n{r.resp_body}"
    db.session.add(f)
    db.session.commit()
    return redirect(url_for("engagements.view_engagement", eid=eid))


@bp.route("/engagement/<int:eid>/report")
def report(eid):
    e = Engagement.query.get_or_404(eid)
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings = sorted(e.findings, key=lambda f: order.get(f.severity, 99))
    return render_template("report.html", e=e, findings=findings)


@bp.route("/engagement/<int:eid>/report.md")
def report_md(eid):
    e = Engagement.query.get_or_404(eid)
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings = sorted(e.findings, key=lambda f: order.get(f.severity, 99))
    out = [f"# VAPT Report — {e.name}", "", f"**Client:** {e.client}", ""]
    for f in findings:
        out += [f"## [{f.severity.upper()}] {f.title}", "",
                f"**Class:** {f.vuln_class}  **CVSS:** {f.cvss}", "",
                f.description, "", "### Steps to Reproduce", f.steps, "",
                "### PoC — Request", "```http", f.poc_request, "```",
                "### PoC — Response", "```http", f.poc_response, "```", ""]
    return Response("\n".join(out), mimetype="text/markdown")
