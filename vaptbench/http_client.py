"""HTTP engine for the Repeater and access-control matrix.

Every outbound request passes the scope guard first. Sending a captured
request under a *different* identity's session is the core access-control
test: same request, swapped session -> compare responses.
"""
import json
import requests

from .scope import in_scope


def _apply_identity(sess, identity):
    """Load a stored identity session (cookies/headers) into a requests.Session."""
    if not identity or not identity.session_blob:
        return
    try:
        blob = json.loads(identity.session_blob)
    except (ValueError, TypeError):
        return
    for k, v in (blob.get("cookies") or {}).items():
        sess.cookies.set(k, v)
    sess.headers.update(blob.get("headers") or {})
    if identity.auth_type == "bearer" and identity.secret:
        sess.headers["Authorization"] = f"Bearer {identity.secret}"


def send(method, url, scope_rules, headers=None, body=None, identity=None, timeout=20):
    """Send one request. Returns dict with ok/blocked/status/len/text."""
    ok, why = in_scope(url, scope_rules)
    if not ok:
        return {"ok": False, "blocked": True, "reason": why}

    sess = requests.Session()
    _apply_identity(sess, identity)
    hdrs = {}
    for line in (headers or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip()] = v.strip()
    try:
        resp = sess.request(
            method.upper(), url, headers=hdrs or None,
            data=body if body else None, timeout=timeout,
            allow_redirects=False, verify=False,
        )
    except requests.RequestException as e:
        return {"ok": False, "blocked": False, "reason": str(e)}

    text = resp.text
    return {
        "ok": True, "blocked": False,
        "status": resp.status_code,
        "len": len(text),
        "headers": dict(resp.headers),
        "text": text[:20000],
        "identity": identity.role if identity else "(none)",
    }


def access_matrix(req_log, identities, scope_rules):
    """Replay one captured request under every identity. The crux of IDOR /
    privilege-escalation testing: look for the same 200/length across roles
    that should NOT all have access."""
    rows = []
    for ident in identities:
        r = send(req_log.method, req_log.url, scope_rules,
                 headers=req_log.req_headers, body=req_log.req_body, identity=ident)
        rows.append({
            "role": ident.role,
            "status": r.get("status"),
            "len": r.get("len"),
            "blocked": r.get("blocked"),
            "reason": r.get("reason", ""),
        })
    return rows
