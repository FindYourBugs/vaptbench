"""Data model for VAPTBench.

The core idea: an Engagement holds Targets. A Target holds many Identities
(one per application role), so access-control testing can replay one role's
request using another role's captured session. Findings carry the PoC
(request/response) and CVSS so they drop straight into the report.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Engagement(db.Model):
    __tablename__ = "engagements"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    client = db.Column(db.String(200))
    # Rules of engagement / authorization note — recorded so every run is
    # tied to a stated authorization.
    authorization = db.Column(db.Text)
    created = db.Column(db.DateTime, default=datetime.utcnow)

    targets = db.relationship("Target", backref="engagement", cascade="all, delete-orphan")
    findings = db.relationship("Finding", backref="engagement", cascade="all, delete-orphan")


class Target(db.Model):
    __tablename__ = "targets"
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey("engagements.id"))
    base_url = db.Column(db.String(500), nullable=False)
    # One scope rule per line; prefix with ! to exclude. Deny wins.
    scope_rules = db.Column(db.Text, default="")
    notes = db.Column(db.Text, default="")

    identities = db.relationship("Identity", backref="target", cascade="all, delete-orphan")
    requests = db.relationship("RequestLog", backref="target", cascade="all, delete-orphan")


class Identity(db.Model):
    """One application role: its credentials and captured session."""
    __tablename__ = "identities"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"))
    role = db.Column(db.String(120), nullable=False)        # e.g. "admin", "user A"
    username = db.Column(db.String(200))
    secret = db.Column(db.String(500))                      # password / token
    auth_type = db.Column(db.String(40), default="form")    # form | basic | bearer | cookie
    # Captured session after login: JSON {"cookies": {...}, "headers": {...}}
    session_blob = db.Column(db.Text, default="")
    login_url = db.Column(db.String(500))
    # Form-login tuning as JSON: field names, CSRF field, extra params, and a
    # success/failure string to confirm the login worked. Varies per app.
    login_config = db.Column(db.Text, default="")
    login_status = db.Column(db.String(200), default="")    # last login result


class RequestLog(db.Model):
    """A captured HTTP request available to the Repeater / access matrix."""
    __tablename__ = "requests"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"))
    method = db.Column(db.String(10), default="GET")
    url = db.Column(db.String(1000), nullable=False)
    req_headers = db.Column(db.Text, default="")
    req_body = db.Column(db.Text, default="")
    # Last response captured
    status = db.Column(db.Integer)
    resp_len = db.Column(db.Integer)
    resp_body = db.Column(db.Text, default="")
    created = db.Column(db.DateTime, default=datetime.utcnow)


class ReconRun(db.Model):
    """One run of an external recon tool against a target."""
    __tablename__ = "recon_runs"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"))
    tool = db.Column(db.String(60))
    command = db.Column(db.Text)
    status = db.Column(db.String(20), default="queued")  # queued|running|done|error|blocked
    output = db.Column(db.Text, default="")
    url_count = db.Column(db.Integer, default=0)
    created = db.Column(db.DateTime, default=datetime.utcnow)

    target = db.relationship("Target", backref="recon_runs")


class Run(db.Model):
    """One autonomous VAPT run against a target."""
    __tablename__ = "runs"
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"))
    engagement_id = db.Column(db.Integer, db.ForeignKey("engagements.id"))
    status = db.Column(db.String(20), default="queued")   # queued|running|done|error|stopped
    phase = db.Column(db.String(40), default="")
    stop_requested = db.Column(db.Boolean, default=False)
    endpoints_tested = db.Column(db.Integer, default=0)
    requests_sent = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    started = db.Column(db.DateTime, default=datetime.utcnow)
    finished = db.Column(db.DateTime)

    target = db.relationship("Target", backref="runs")
    logs = db.relationship("RunLog", backref="run", cascade="all, delete-orphan")


class RunLog(db.Model):
    """A line in the live run feed."""
    __tablename__ = "run_logs"
    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("runs.id"))
    ts = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(10), default="info")   # info|test|hit|warn|error
    phase = db.Column(db.String(40), default="")
    message = db.Column(db.Text, default="")


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    engagement_id = db.Column(db.Integer, db.ForeignKey("engagements.id"))
    run_id = db.Column(db.Integer, db.ForeignKey("runs.id"))
    title = db.Column(db.String(300), nullable=False)
    vuln_class = db.Column(db.String(80))       # maps to a hunt-* skill
    severity = db.Column(db.String(20), default="info")
    cvss = db.Column(db.String(60), default="")
    # confirmed = passed a deterministic verifier; needs-review = AI-only suspicion
    confidence = db.Column(db.String(20), default="confirmed")
    status = db.Column(db.String(20), default="open")   # open | confirmed | reported
    description = db.Column(db.Text, default="")
    steps = db.Column(db.Text, default="")      # reproduction steps
    poc_request = db.Column(db.Text, default="")
    poc_response = db.Column(db.Text, default="")
    created = db.Column(db.DateTime, default=datetime.utcnow)
