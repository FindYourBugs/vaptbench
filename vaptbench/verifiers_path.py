"""Path-segment injection verifiers — reach identifiers carried in the URL path.

REST APIs put the object reference in the path (/users/123, /order/4f2a…,
/api/v1/item/42), not in a query string, form field or JSON body — so the
GET-param, POST-form and JSON-body verifiers never touch it. This module injects
into each id-like path segment and confirms ONLY on a deterministic signal,
keeping the zero-false-positive standard:

- error-based SQLi -> a database error surfaces when a quote is appended
- reflected XSS    -> the <svg/onload> breakout survives unencoded in an HTML
                      response

Nothing is asserted on reflection or status alone.
"""
import re
from urllib.parse import urlsplit, urlunsplit, quote

from .verifiers import SQL_ERRORS, XSS_MARK, XSS_PAYLOAD

# A segment worth fuzzing: a numeric id, a hex/ObjectId/UUID-ish token, or the
# literal "1" we substitute for an OpenAPI {id}. We skip file-looking segments
# (something.ext) and ordinary words so we don't rewrite static routes.
_ID_SEG = re.compile(r"^(\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,})$")


def candidate_indices(path):
    """Indices of path segments that look like an injectable identifier."""
    segs = path.split("/")
    return [i for i, s in enumerate(segs) if s and _ID_SEG.match(s)]


def _with_segment(url, idx, value):
    parts = urlsplit(url)
    segs = parts.path.split("/")
    segs[idx] = quote(str(value), safe="")
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segs), parts.query, ""))


def check_path_params(send, url):
    """Inject into each id-like path segment of `url`; return confirmed findings."""
    out = []
    parts = urlsplit(url)
    segs = parts.path.split("/")
    for idx in candidate_indices(parts.path):
        orig = segs[idx]

        # --- error-based SQLi: append a single quote to the identifier ---------
        u = _with_segment(url, idx, orig + "'")
        r = send("GET", u)
        if r.get("ok"):
            low = (r.get("text") or "").lower()
            hit = next((s for s in SQL_ERRORS if s in low), None)
            if hit:
                out.append(dict(
                    title=f"SQL injection (error-based) via path segment '{orig}'",
                    vuln_class="hunt-sqli", severity="critical", confidence="confirmed",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=f"The path segment '{orig}' of {parts.path} reaches a SQL query "
                                f"unsanitised: appending a single quote triggers a database error "
                                f"({hit!r}).",
                    steps=f"GET {u}",
                    poc_request=f"GET {u}",
                    poc_response=(r.get("text") or "")[:800]))

        # --- reflected XSS: payload survives unencoded in an HTML response ------
        u = _with_segment(url, idx, XSS_PAYLOAD)
        r = send("GET", u)
        if r.get("ok"):
            body = r.get("text") or ""
            ctype = (r.get("headers") or {}).get("Content-Type", "")
            if "html" in ctype.lower() and f'{XSS_MARK}"><svg' in body:
                out.append(dict(
                    title=f"Reflected XSS via path segment (position {idx})",
                    vuln_class="hunt-xss", severity="high", confidence="confirmed",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    description=f"A path segment of {parts.path} is reflected unencoded into an HTML "
                                f"response; the injected <svg/onload> breakout survives.",
                    steps=f"GET {u}",
                    poc_request=f"GET {u}",
                    poc_response=(body[:800])))
    return out
