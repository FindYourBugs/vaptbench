"""Host-header injection — the server trusts a client-supplied Host (or
X-Forwarded-Host) header and reflects it into the response, enabling password-
reset poisoning, cache poisoning and routing abuse.

Deterministic, zero-FP: a UNIQUE random marker domain is sent in the header and
confirmed only when that exact marker appears in the response body or a Location
header — proof the application used the attacker-controlled host value.
"""
import uuid


def _f(title, desc, steps, req, resp, sev="medium", conf="confirmed"):
    return dict(title=title, vuln_class="hunt-host-header", severity=sev,
                confidence=conf, cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                description=desc, steps=steps, poc_request=req,
                poc_response=(resp or "")[:800])


_HEADERS = ["Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
            "X-HTTP-Host-Override", "Forwarded"]


def check_host_header(send, url):
    out = []
    marker = "vhh" + uuid.uuid4().hex[:8] + ".attacker-example.net"
    for name in _HEADERS:
        val = f"host={marker}" if name == "Forwarded" else marker
        r = send("GET", url, headers=f"{name}: {val}")
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        loc = (r.get("headers") or {}).get("Location", "")
        where = "Location header" if marker in loc else ("response body" if marker in body else None)
        if where:
            out.append(_f(
                f"Host-header injection via '{name}'",
                f"{url} reflects a client-controlled '{name}' header into its {where}: the injected "
                f"marker host {marker!r} appeared verbatim. An attacker can forge absolute URLs the "
                f"app generates (password-reset links, redirects) or poison shared caches.",
                f"GET {url} with '{name}: {val}'; the marker host is reflected in the {where}.",
                f"GET {url}\n{name}: {val}",
                loc if marker in loc else body))
            break
    return out
