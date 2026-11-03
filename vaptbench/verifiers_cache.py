"""Web cache poisoning.

An unkeyed input (e.g. X-Forwarded-Host / X-Forwarded-Scheme) is reflected into a
response that is cacheable — so an attacker's value gets served to other users
from the cache.

Deterministic: a UNIQUE marker sent in an unkeyed header is reflected in the body
AND the response is cacheable (Cache-Control public/max-age>0, or an Age/X-Cache
header is present). Confirmed only when both hold.
"""
import re
import uuid

_UNKEYED = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
            "X-Host", "X-Forwarded-Server"]


def _cacheable(headers):
    cc = (headers.get("Cache-Control") or "").lower()
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return False
    if "public" in cc:
        return True
    m = re.search(r"max-age=(\d+)", cc)
    if m and int(m.group(1)) > 0:
        return True
    return bool(headers.get("Age") or headers.get("X-Cache") or headers.get("X-Cache-Hits"))


def check_cache_poisoning(send, url):
    marker = "vcp" + uuid.uuid4().hex[:8] + ".cache-example.net"
    for name in _UNKEYED:
        r = send("GET", url, headers=f"{name}: {marker}")
        if not r.get("ok"):
            continue
        headers = r.get("headers") or {}
        if marker in (r.get("text") or "") and _cacheable(headers):
            return [dict(
                title=f"Web cache poisoning via unkeyed '{name}'",
                vuln_class="hunt-cache", severity="high", confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L",
                description=f"{url} reflects the unkeyed request header '{name}' into a CACHEABLE "
                            f"response (marker {marker!r} reflected; cache headers "
                            f"{ {k: headers.get(k) for k in ('Cache-Control','Age','X-Cache') if headers.get(k)} }). "
                            f"An attacker can poison the shared cache so other users receive the "
                            f"attacker-controlled content.",
                steps=f"GET {url} with '{name}: {marker}'; the marker is reflected and the response is "
                      f"cacheable — repeat to poison the cache key.",
                poc_request=f"GET {url}\n{name}: {marker}",
                poc_response=(r.get("text") or "")[:800])]
    return []
