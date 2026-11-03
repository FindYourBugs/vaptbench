"""JSON request-body injection verifiers (for OpenAPI/Swagger-documented APIs).

Documented API operations take their input in a JSON body, not query strings or
form fields — so neither the GET-param verifiers nor the POST-form verifiers
reach them. This module injects into each string field of a synthesised JSON body
(built from the OpenAPI schema) and applies the SAME deterministic proof standard:

- error-based SQLi -> a database error surfaces
- SSTI             -> an arithmetic marker is evaluated (49*49 -> 2401) while the
                      literal expression is absent (so it was executed, not echoed)
- reflected XSS    -> the <svg/onload> breakout survives unencoded in the response

Only verifier-proven results are returned; nothing is asserted on reflection
alone. The body is replayed with one field mutated at a time, under the operation's
documented method (POST/PUT/PATCH).
"""
import copy
import json
import re

from .verifiers import SQL_ERRORS, XSS_MARK, XSS_PAYLOAD

_PATH_TOK = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _parse_path(path):
    """'user.name' -> ['user','name'];  'items[0].sku' -> ['items',0,'sku']."""
    toks = []
    for m in _PATH_TOK.finditer(path):
        toks.append(m.group(1) if m.group(1) is not None else int(m.group(2)))
    return toks or [path]


def _set_by_path(body, path, value):
    """Set a (possibly nested/indexed) field in a deep-copied body. A plain
    top-level key round-trips exactly as before."""
    toks = _parse_path(path)
    node = body
    for t in toks[:-1]:
        node = node[t]
    node[toks[-1]] = value
    return body

_JSON_HDR = "Content-Type: application/json"
# SSTI: unique marker * square, evaluated only if the template engine runs it
_SSTI_A, _SSTI_B = 49, 49
_SSTI_PAYLOAD = "{{%d*%d}}" % (_SSTI_A, _SSTI_B)
_SSTI_ALT = "${%d*%d}" % (_SSTI_A, _SSTI_B)
_SSTI_RESULT = str(_SSTI_A * _SSTI_B)       # "2401"


def _send(send, op, field, value):
    body = _set_by_path(copy.deepcopy(op["body"]), field, value)
    return send(op["method"], op["url"], headers=_JSON_HDR, body=json.dumps(body))


def _poc(op, field, value):
    body = _set_by_path(copy.deepcopy(op["body"]), field, value)
    return f"{op['method']} {op['url']}\n{_JSON_HDR}\n\n{json.dumps(body)}"


def check_json_sqli(send, op):
    out = []
    for field in op["fields"]:
        r = _send(send, op, field, "1'")
        if not r.get("ok"):
            continue
        low = (r.get("text") or "").lower()
        hit = next((s for s in SQL_ERRORS if s in low), None)
        if hit:
            out.append(dict(
                title=f"SQL injection (error-based) via JSON body '{field}'",
                vuln_class="hunt-sqli", severity="critical", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description=f"JSON field '{field}' of {op['method']} {op['url']} triggers a database "
                            f"error ({hit!r}) when a single quote is injected — the value reaches a "
                            f"SQL query unsanitised.",
                steps=f"{op['method']} {op['url']} with JSON body field '{field}' = \"1'\"",
                poc_request=_poc(op, field, "1'"),
                poc_response=(r.get("text") or "")[:800]))
    return out


def check_json_ssti(send, op):
    out = []
    for field in op["fields"]:
        for payload in (_SSTI_PAYLOAD, _SSTI_ALT):
            r = _send(send, op, field, payload)
            if not r.get("ok"):
                continue
            body = r.get("text") or ""
            # executed if the PRODUCT appears and the literal expression does not
            if _SSTI_RESULT in body and payload not in body:
                out.append(dict(
                    title=f"Server-side template injection via JSON body '{field}'",
                    vuln_class="hunt-ssti", severity="critical", confidence="confirmed",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=f"JSON field '{field}' of {op['method']} {op['url']} is evaluated as a "
                                f"server-side template: '{payload}' rendered to {_SSTI_RESULT}. Template "
                                f"injection commonly escalates to remote code execution.",
                    steps=f"{op['method']} {op['url']} with JSON body field '{field}' = '{payload}' "
                          f"(response contains {_SSTI_RESULT})",
                    poc_request=_poc(op, field, payload),
                    poc_response=(body[:800])))
                break
    return out


def check_json_xss(send, op):
    out = []
    for field in op["fields"]:
        r = _send(send, op, field, XSS_PAYLOAD)
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        ctype = (r.get("headers") or {}).get("Content-Type", "")
        # only meaningful if the response is served as HTML (JSON-echoed is inert)
        if "html" in ctype.lower() and f'{XSS_MARK}"><svg' in body:
            out.append(dict(
                title=f"Reflected XSS via JSON body '{field}'",
                vuln_class="hunt-xss", severity="high", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                description=f"JSON field '{field}' of {op['method']} {op['url']} is reflected unencoded "
                            f"into an HTML response; the injected <svg/onload> survives.",
                steps=f"{op['method']} {op['url']} with JSON body field '{field}' = XSS payload",
                poc_request=_poc(op, field, XSS_PAYLOAD),
                poc_response=(body[:800])))
    return out


def check_json_body(send, op):
    out = []
    for fn in (check_json_sqli, check_json_ssti, check_json_xss):
        try:
            out += fn(send, op)
        except Exception:
            pass
    return out
