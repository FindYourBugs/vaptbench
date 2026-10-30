"""Engagements + targets + identities (the multi-role credential store)."""
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, redirect, url_for

from ..models import db, Engagement, Target, Identity
from ..ai import available as ai_available

bp = Blueprint("engagements", __name__)


@bp.route("/")
def dashboard():
    engagements = Engagement.query.order_by(Engagement.created.desc()).all()
    ai_ok, ai_msg = ai_available()
    return render_template("dashboard.html", engagements=engagements,
                           ai_ok=ai_ok, ai_msg=ai_msg)


@bp.route("/engagement/new", methods=["POST"])
def new_engagement():
    e = Engagement(
        name=request.form["name"],
        client=request.form.get("client", ""),
        authorization=request.form.get("authorization", ""),
    )
    db.session.add(e)
    db.session.commit()
    return redirect(url_for("engagements.view_engagement", eid=e.id))


@bp.route("/engagement/<int:eid>")
def view_engagement(eid):
    e = Engagement.query.get_or_404(eid)
    return render_template("engagement.html", e=e)


@bp.route("/engagement/<int:eid>/target/new", methods=["POST"])
def new_target(eid):
    base = request.form["base_url"].rstrip("/")
    scope = request.form.get("scope_rules", "").strip()
    if not scope:                     # default-deny would block everything; seed from host
        host = urlparse(base).hostname
        if host:
            scope = host
    t = Target(engagement_id=eid, base_url=base, scope_rules=scope)
    db.session.add(t)
    db.session.commit()
    return redirect(url_for("web_workbench.workbench", tid=t.id))


@bp.route("/target/<int:tid>/scope", methods=["POST"])
def update_scope(tid):
    t = Target.query.get_or_404(tid)
    t.scope_rules = request.form.get("scope_rules", "").strip()
    if "base_url" in request.form and request.form["base_url"].strip():
        t.base_url = request.form["base_url"].strip().rstrip("/")
    db.session.commit()
    return redirect(url_for("web_workbench.workbench", tid=tid))


@bp.route("/target/<int:tid>/identity/new", methods=["POST"])
def new_identity(tid):
    i = Identity(
        target_id=tid,
        role=request.form["role"],
        username=request.form.get("username", ""),
        secret=request.form.get("secret", ""),
        auth_type=request.form.get("auth_type", "form"),
        login_url=request.form.get("login_url", ""),
        login_config=request.form.get("login_config", ""),
    )
    db.session.add(i)
    db.session.commit()
    return redirect(url_for("web_workbench.workbench", tid=tid))


@bp.route("/identity/<int:iid>/delete", methods=["POST"])
def delete_identity(iid):
    i = Identity.query.get_or_404(iid)
    tid = i.target_id
    db.session.delete(i)
    db.session.commit()
    return redirect(url_for("web_workbench.workbench", tid=tid))
