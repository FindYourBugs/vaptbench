"""OAuth / OIDC redirect_uri validation.

An authorization endpoint that redirects to an attacker-supplied redirect_uri
leaks the authorization code / token to the attacker (account takeover).

Deterministic, zero-FP: on an authorize endpoint carrying a redirect_uri-style
param, the value is swapped for an attacker origin; confirmed only when the
response's Location header actually redirects to that attacker origin.
"""
import re
import uuid
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

_AUTHZ_PATH = re.compile(r"/(?:oauth|authorize|authorization|connect|openid|sso|auth)(?:/|$)", re.I)
_REDIR_PARAM = re.compile(r"^(redirect_uri|redirecturl|redirect|callback|return_to|"
                          r"returnurl|next|continue|reply_url|post_login)$", re.I)


def check_oauth_redirect(send, url):
    p = urlparse(url)
    if not _AUTHZ_PATH.search(p.path):
        return []
    q = parse_qsl(p.query, keep_blank_values=True)
    redir_keys = [k for k, _ in q if _REDIR_PARAM.search(k)]
    if not redir_keys:
        return []
    evil = f"https://vauth{uuid.uuid4().hex[:8]}.attacker-example.net/cb"
    out = []
    for key in redir_keys:
        newq = urlencode([(k, evil if k == key else v) for k, v in q])
        test = urlunparse(p._replace(query=newq))
        r = send("GET", test)
        if not r.get("ok"):
            continue
        loc = (r.get("headers") or {}).get("Location", "")
        if loc.startswith(evil) or urlparse(loc).netloc == urlparse(evil).netloc:
            out.append(dict(
                title=f"OAuth open redirect_uri via '{key}'",
                vuln_class="hunt-oauth", severity="high", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                description=f"The authorization endpoint {p.path} accepts an unvalidated '{key}' and "
                            f"redirected to the attacker origin {evil!r}. An attacker can harvest the "
                            f"authorization code / access token and take over accounts.",
                steps=f"GET {test}; the response Location points at the attacker origin.",
                poc_request=f"GET {test}", poc_response=f"Location: {loc}"))
            break
    return out
