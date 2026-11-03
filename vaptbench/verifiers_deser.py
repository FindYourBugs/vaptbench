"""Insecure deserialization (detection).

Sends recognisable serialized-object markers and looks for deserialization error
signatures that reveal the server feeds untrusted input to a native deserializer
(Java ObjectInputStream, PHP unserialize, Python pickle, Ruby/YAML). Remote code
execution via a real gadget chain is NOT attempted (unsafe), so this is reported
as needs-review — a strong lead for manual exploitation.
"""
import re

# marker payloads: base64 Java stream header, PHP object, python pickle, ruby/yaml
_PAYLOADS = [
    "rO0ABXQABHRlc3Q=",                       # base64 of a java serialized stream header
    'O:8:"stdClass":0:{}',                    # PHP serialized object
    "gASVCgAAAAAAAACMBHRlc3SULg==",          # base64 python pickle
    "--- !ruby/object:OpenStruct {}",         # ruby/yaml
    "!!python/object/apply:os.system []",     # python yaml tag
]
_ERR = re.compile(
    r"java\.io\.|objectinputstream|readobject|invalidclassexception|classnotfound|"
    r"unserialize\(\)|__wakeup|allowed_classes|_pickle|cpickle|unpickl|"
    r"yaml\.load|psych::|marshal\.load|deserializ", re.I)

_SINK_PARAMS = re.compile(r"(data|obj|object|payload|state|session|token|ViewState|"
                          r"serialized|blob|cache|node|item|cart|user|auth)", re.I)


def check_deserialization(send, url):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    cands = [k for k in q if _SINK_PARAMS.search(k)] or list(q)[:2]
    out = []
    for key in cands:
        for pay in _PAYLOADS:
            newq = urlencode([(k, pay if k == key else (v[0] if v else ""))
                              for k, v in q.items()])
            r = send("GET", urlunparse(p._replace(query=newq)))
            if not r.get("ok"):
                continue
            m = _ERR.search(r.get("text") or "")
            if m:
                out.append(dict(
                    title=f"Possible insecure deserialization via '{key}'",
                    vuln_class="hunt-deser", severity="high", confidence="needs-review",
                    cvss="",
                    description=f"Parameter '{key}' on {url} returned a deserialization error "
                                f"({m.group(0)!r}) when fed a serialized-object marker — the value is "
                                f"passed to a native deserializer. A crafted gadget chain may achieve "
                                f"RCE; verify manually (not auto-exploited for safety).",
                    steps=f"Send a serialized object in '{key}'; the server attempts to deserialize it.",
                    poc_request=f"GET {urlunparse(p._replace(query=newq))}",
                    poc_response=(r.get("text") or "")[:800]))
                return out
    return out
