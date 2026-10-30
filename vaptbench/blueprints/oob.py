"""Built-in OOB (out-of-band) collaborator.

When the engine tests SSRF / blind injection it plants a URL pointing at
  http://<VAPT_OOB_HOST>/oob/<token>
If the *target server* fetches it, this route records the hit — hard proof the
target made the request. VAPT_OOB_HOST must be an address the target can reach
(for local labs 127.0.0.1:8090 is fine; for internet targets set it to a public
host that forwards here).
"""
from flask import Blueprint, request

from ..models import db, OobHit

bp = Blueprint("oob", __name__)


@bp.route("/oob/<token>", methods=["GET", "POST", "PUT", "HEAD"])
def oob(token):
    hit = OobHit(token=token[:64],
                 source_ip=request.headers.get("X-Forwarded-For", request.remote_addr),
                 method=request.method, path=request.full_path[:500])
    db.session.add(hit)
    db.session.commit()
    return "1", 200
