"""Mass assignment / auto-binding — the API binds request-body fields straight
onto a model, so injecting a privileged field (role, isAdmin, verified, balance…)
that the client was never meant to set is accepted and persisted.

Deterministic, zero-FP: a privileged field NOT present in the documented body is
injected; it's confirmed only when the response echoes that exact field with the
injected value while the unmodified baseline response did not — proof the server
accepted and bound the extra field.
"""
import copy
import json
import re

_JSON_HDR = "Content-Type: application/json"

# (field, value, response-regex). The regex matches the field echoed back with
# our injected value (JSON-ish), case-insensitive.
_PRIV = [
    ("role", "admin"), ("isAdmin", True), ("is_admin", True), ("admin", True),
    ("isAdministrator", True), ("verified", True), ("emailVerified", True),
    ("active", True), ("enabled", True), ("accountType", "admin"),
    ("account_type", "admin"), ("privilege", "admin"), ("userRole", "admin"),
    ("group", "admin"), ("premium", True), ("approved", True),
]


def _echoes(body, field, val):
    valpat = "true" if val is True else re.escape(str(val))
    return re.search(r'"%s"\s*:\s*"?%s"?' % (re.escape(field), valpat), body, re.I)


def _send(send, op, body):
    return send(op["method"], op["url"], headers=_JSON_HDR, body=json.dumps(body))


def check_mass_assignment(send, op):
    if not isinstance(op.get("body"), dict):
        return []
    out = []
    base = _send(send, op, op["body"])
    base_body = (base.get("text") or "") if base.get("ok") else ""
    for field, val in _PRIV:
        if field in op["body"]:
            continue
        body = copy.deepcopy(op["body"])
        body[field] = val
        r = _send(send, op, body)
        if not r.get("ok"):
            continue
        resp = r.get("text") or ""
        # accepted iff our privileged field is echoed with our value AND the
        # untouched baseline did not already carry it (rules out static output).
        if _echoes(resp, field, val) and not _echoes(base_body, field, val):
            out.append(dict(
                title=f"Mass assignment via '{field}' on {op['method']} {op['url']}",
                vuln_class="hunt-mass-assign", severity="high", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                description=f"The {op['method']} body is auto-bound to the model: injecting the "
                            f"undocumented privileged field '{field}'={val!r} was accepted and reflected "
                            f"back in the response object, while the unmodified request did not carry it. "
                            f"A client can set server-controlled attributes (privilege, verification, "
                            f"balance) it should never control.",
                steps=f"{op['method']} {op['url']} with the JSON body plus \"{field}\": {json.dumps(val)}; "
                      f"the response echoes the field as set.",
                poc_request=f"{op['method']} {op['url']}\n{_JSON_HDR}\n\n{json.dumps(body)}",
                poc_response=resp[:800]))
            break
    return out
