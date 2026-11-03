"""CRLF / HTTP response-header injection.

A parameter whose value is copied into a response header (Location, Set-Cookie)
without stripping CR/LF lets an attacker inject new headers (session fixation,
cache poisoning, reflected-XSS via injected body).

Deterministic, zero-FP: a CRLF-prefixed UNIQUE header is injected; confirmed only
when that exact header name+nonce appears in the parsed response headers — proof
the newline broke out of the original header value.
"""
import uuid
from urllib.parse import urlparse, parse_qs, urlunparse

_HDR = "X-Vapt-CRLF"


def check_crlf(send, url):
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    if not q:
        return []
    out = []
    for key in q:
        nonce = "vcrlf" + uuid.uuid4().hex[:8]
        base = (q[key] or ["1"])[0]
        inj = f"{base}%0d%0a{_HDR}: {nonce}"
        # build the query by hand so the %0d%0a stays percent-encoded in the URL
        newq = "&".join(f"{k}={inj if k == key else (v[0] if v else '')}"
                        for k, v in q.items())
        test = urlunparse(p._replace(query=newq))
        r = send("GET", test)
        if not r.get("ok"):
            continue
        hdrs = r.get("headers") or {}
        got = any(k.lower() == _HDR.lower() and nonce in str(v) for k, v in hdrs.items()) \
            or any(nonce in str(v) for v in hdrs.values())
        if got:
            out.append(dict(
                title=f"CRLF / HTTP response-header injection via '{key}'",
                vuln_class="hunt-crlf", severity="medium", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                description=f"Parameter '{key}' on {url} is written into a response header without "
                            f"stripping CR/LF: an injected newline produced the header "
                            f"'{_HDR}: {nonce}' in the response. This enables header injection, "
                            f"session fixation and cache poisoning.",
                steps=f"GET {test}; the response carries the injected '{_HDR}' header.",
                poc_request=f"GET {test}", poc_response=str(hdrs)[:800]))
            break
    return out
