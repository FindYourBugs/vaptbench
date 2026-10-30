"""VAPTBench — a web-application pentest workbench (not just a scanner).

App factory. Local-first AI, hybrid cloud option. Playbooks come from your
hunt-* skills. SQLite store by default.
"""
import os
from flask import Flask
from sqlalchemy import inspect, text

from .models import db


def _auto_migrate():
    """Add any model columns missing from existing tables (SQLite ADD COLUMN).

    create_all() creates new tables but never alters existing ones, so as the
    schema grows this back-fills new columns instead of forcing a DB wipe.
    """
    insp = inspect(db.engine)
    for table in db.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            coltype = col.type.compile(db.engine.dialect)
            try:
                db.session.execute(
                    text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}'))
                db.session.commit()
            except Exception:
                db.session.rollback()


def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config["SECRET_KEY"] = os.environ.get("VAPT_SECRET", "dev-change-me")
    db_path = os.environ.get("VAPT_DB", os.path.join(os.getcwd(), "vaptbench.db"))
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    from .blueprints.engagements import bp as eng_bp
    from .blueprints.web_workbench import bp as web_bp
    from .blueprints.findings import bp as find_bp
    from .blueprints.oob import bp as oob_bp
    app.register_blueprint(eng_bp)
    app.register_blueprint(web_bp)
    app.register_blueprint(find_bp)
    app.register_blueprint(oob_bp)

    with app.app_context():
        db.create_all()
        _auto_migrate()

    return app
