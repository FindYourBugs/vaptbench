"""Authorization & authentication testing — IDOR / BOLA, privilege escalation
(BFLA), missing authentication, and a matrix of access-control bypass variants.

The Phase-4 unauth-vs-auth check catches the *missing-authorization* class. This
module adds the tests that actually PROVE broken access control using the real,
user-supplied roles, with deterministic confirmation and a strict zero-false-
positive bar — a variant must return the **same protected content** before a
finding is recorded, never a bare 200.

Classes covered (each `confirmed` only when provable):

  1. Horizontal IDOR / BOLA  — an object-reference endpoint that is gated against
     the anonymous user still serves user A's object to a *different* authenticated
     user B. Signal: unauth DENIED, yet A and B both get the same substantial
     object body for A's identifier.
  2. Vertical privilege escalation / BFLA — an endpoint the app itself denies to
     one role (proving a control exists) is reached by that same role through a
     bypass variant that returns the authorised content.
  3. Missing authentication — a substantial, non-public, authenticated resource is
     served identically to a request with no session at all.
  4. Authentication bypass — the anonymous user reaches an authenticated-only
     resource via a header/param/path/verb variant (returning the authed content).
  5. Enumerable object references — sequential numeric identifiers return distinct
     objects to the same user (needs-review supporting evidence when only one role
     is available to prove cross-user access).

Variants tried (only against an endpoint that demonstrably enforces a control):
  - parameter injection: &admin=true, &role=admin, &is_admin=1, &debug=true …
  - header spoofing: X-Original-URL / X-Rewrite-URL, X-Forwarded-For/-Host,
    X-Originating-IP, X-Custom-IP-Authorization …
  - path mangling: trailing slash, //, /./, /%2e/, ..;/, .json suffix
  - verb tampering: POST/HEAD/OPTIONS, X-HTTP-Method-Override

Disable with VAPT_AUTHZ=0.
"""
import difflib
import os
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

AUTHZ = os.environ.get("VAPT_AUTHZ", "1") != "0"
_MAX_ENDPOINTS = int(os.environ.get("VAPT_AUTHZ_MAX", "25"))
_MINLEN = 150                       # a "substantial" body (below this = error/stub)

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{12,64}$")
_ID_HINT = re.compile(
    r"(?:^|[_-])(id|uid|uuid|guid|user|userid|account|acct|order|doc|document|"
    r"file|fileid|pid|num|no|key|ref|invoice|customer|member|profile|ticket|msg|"
    r"message|group|team|org|project|item|record|row|cart|address|payment)s?$", re.I)
_LOGIN = re.compile(
    r"""type=["']password["']|name=["'](?:pwd|pass|password|login|username)["']|"""
    r"""please\s+log\s*in|sign\s*in\s+to|login\s*required|unauthor|forbidden|"""
    r"""access\s+denied|not\s+authori[sz]ed""", re.I)
_PUBLIC = re.compile(
    r"/(?:login|logout|signin|sign-in|signup|register|home|index|about|contact|"
    r"faq|help|terms|privacy|robots\.txt|favicon|static|assets|public|css|js|img|"
    r"images|fonts)(?:/|$|\.)", re.I)
# resources that are plausibly private — only these count for "missing auth" when
# a page is served identically to everyone (a public page served to all is not a
# finding, a /dashboard or /api object served to anonymous is).
_SENSITIVE = re.compile(
    r"/(?:dashboard|account|accounts|profile|settings|admin|administrator|user|"
    r"users|order|orders|invoice|invoices|billing|payment|payments|api|me|my|"
    r"private|internal|config|report|reports|document|documents|message|messages|"
    r"inbox|notification|notifications|cart|checkout|address|addresses|wallet|"
    r"subscription|export|download|manage|owner|member|customer)s?(?:/|$|\?)", re.I)

_BYPASS_PARAMS = [("admin", "true"), ("is_admin", "1"), ("role", "admin"),
                  ("isAdmin", "true"), ("debug", "true"), ("access", "1"),
                  ("authorized", "true")]
_BYPASS_VERBS = ["POST", "HEAD", "PUT"]


def _body(r):
    return r.get("text") or ""


def _authorized(r):
    """A real, served, protected-looking 200 body (not a login/error/stub)."""
    if not (r and r.get("ok") and r.get("status") == 200):
        return False
    b = _body(r)
    return len(b) >= _MINLEN and not _LOGIN.search(b[:1500])


def _denied(r):
    """The request was refused / not served the protected content."""
    if not r or not r.get("ok"):
        return True
    st = r.get("status")
    if st in (401, 403) or (st and st >= 400):
        return True
    if st in (301, 302, 303, 307, 308):
        return True
    b = _body(r)
    if len(b) < _MINLEN or _LOGIN.search(b[:1500]):
        return True
    return False


def _norm(s):
    return re.sub(r"\s+", " ", (s or "")).strip()[:4000]


def _same_content(a, b):
    """Two responses show the same object/page (near-identical body)."""
    na, nb = _norm(a), _norm(b)
    if not na or not nb:
        return False
    lr = len(nb) / max(len(na), 1)
    if not (0.9 <= lr <= 1.11):
        return False
    return difflib.SequenceMatcher(None, na, nb).quick_ratio() >= 0.9


# ----------------------------------------------------------- identifier detection
def _idish(v):
    return bool(v) and (v.isdigit() or _UUID.match(v) or _HEX.match(v))


def _path_ids(url):
    """[(seg_index, value)] for id-looking path segments."""
    segs = urlparse(url).path.split("/")
    return [(i, s) for i, s in enumerate(segs) if _idish(s)]


def _query_ids(url):
    """[(key, value)] for id-looking query params (id-ish name or id-ish value)."""
    out = []
    for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if _idish(v) or _ID_HINT.search(k):
            out.append((k, v))
    return out


def _has_object_id(url):
    return bool(_path_ids(url) or _query_ids(url))


def _set_path_seg(url, idx, value):
    p = urlparse(url)
    segs = p.path.split("/")
    if idx >= len(segs):
        return url
    segs[idx] = str(value)
    return urlunparse(p._replace(path="/".join(segs)))


def _neighbors(value):
    if str(value).isdigit():
        n = int(value)
        return [str(n + 1), str(n - 1)] if n > 1 else [str(n + 1), str(n + 2)]
    return []


# ----------------------------------------------------------- bypass variants
def _path_variants(url):
    p = urlparse(url)
    path = p.path or "/"
    cands = []
    if not path.endswith("/"):
        cands.append(p._replace(path=path + "/"))
    cands.append(p._replace(path=path + "/."))
    cands.append(p._replace(path="/" + path.lstrip("/")))          # //path
    cands.append(p._replace(path=re.sub(r"/([^/]+)$", r"/%2e/\1", path)))
    cands.append(p._replace(path=path + ".json"))
    cands.append(p._replace(path=path + "/..;/"))
    return [urlunparse(c) for c in cands]


def _try_bypass(send, url, identity, target_body):
    """Return (label, response) for the first variant that turns a denial into the
    protected content (matching target_body), else None. `identity` is the actor
    we are trying to elevate (a lower role, or None for anonymous)."""
    path = urlparse(url).path or "/"

    def hit(r):
        return _authorized(r) and _same_content(_body(r), target_body)

    # 1) parameter injection
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    for k, v in _BYPASS_PARAMS:
        u2 = urlunparse(p._replace(query=urlencode(q + [(k, v)])))
        r = send("GET", u2, identity=identity)
        if hit(r):
            return (f"parameter injection ({k}={v})", r)
    # 2) header spoofing
    for hdr in (f"X-Original-URL: {path}", f"X-Rewrite-URL: {path}",
                "X-Forwarded-For: 127.0.0.1", "X-Forwarded-Host: localhost",
                "X-Originating-IP: 127.0.0.1", "X-Remote-Addr: 127.0.0.1",
                "X-Custom-IP-Authorization: 127.0.0.1", "X-Real-IP: 127.0.0.1"):
        r = send("GET", url, headers=hdr, identity=identity)
        if hit(r):
            return (f"header spoofing ({hdr.split(':')[0]})", r)
    # 3) path mangling
    for u2 in _path_variants(url):
        r = send("GET", u2, identity=identity)
        if hit(r):
            return (f"path mangling ({urlparse(u2).path})", r)
    # 4) verb tampering
    for verb in _BYPASS_VERBS:
        r = send(verb, url, identity=identity)
        if hit(r):
            return (f"HTTP method change ({verb})", r)
    r = send("POST", url, headers="X-HTTP-Method-Override: GET", identity=identity)
    if hit(r):
        return ("verb tampering (X-HTTP-Method-Override)", r)
    return None


# ----------------------------------------------------------- findings
def _f(title, cls, sev, desc, steps, req, resp, conf="confirmed", cvss=""):
    return dict(title=title, vuln_class=cls, severity=sev, confidence=conf,
                cvss=cvss, description=desc, steps=steps, poc_request=req,
                poc_response=(resp or "")[:800])


def _role(ident):
    return getattr(ident, "role", None) or "user"


def run_authz(send, endpoints, identities, log=None):
    """Full authorization/authentication suite. `send(method,url,headers='',
    body='',identity=None)` is the engine closure. `identities` are authenticated
    Identity objects. Returns a list of finding dicts."""
    log = log or (lambda *a: None)
    if not AUTHZ:
        return []
    authed = [i for i in identities if getattr(i, "session_blob", None)]
    findings, emitted = [], set()

    # prioritise object-reference endpoints, then parameterised ones
    def _rank(u):
        return (0 if _has_object_id(u) else 1, len(u))
    cands = [u for u in sorted(set(endpoints), key=_rank)
             if urlparse(u).path not in ("", "/") and not _PUBLIC.search(urlparse(u).path)]
    cands = cands[:_MAX_ENDPOINTS]

    for url in cands:
        path = urlparse(url).path
        # access vector: each authed role + anonymous
        resp = {}
        for ident in authed:
            resp[_role(ident)] = send("GET", url, identity=ident)
        anon = send("GET", url, identity=None)

        authorized_roles = [r for r, rr in resp.items() if _authorized(rr)]
        denied_roles = [r for r, rr in resp.items() if _denied(rr)]
        anon_ok = _authorized(anon)
        has_id = _has_object_id(url)

        # ---- (3/4) authentication -------------------------------------------
        # a page served identically to everyone is only a finding when it is
        # plausibly private (a sensitive path or an object reference) — a public
        # page shown to all is not "missing authentication".
        if authorized_roles and anon_ok and (_SENSITIVE.search(path) or has_id):
            ref = _body(resp[authorized_roles[0]])
            if _same_content(_body(anon), ref):
                key = ("auth", path)
                if key not in emitted:
                    emitted.add(key)
                    findings.append(_f(
                        f"Missing authentication: {path}",
                        "hunt-auth", "high",
                        f"{url} returns the same substantial content ({len(_body(anon))}B) to an "
                        f"UNAUTHENTICATED request as to the '{authorized_roles[0]}' session, and the "
                        f"anonymous response is not a login page — the endpoint enforces no "
                        f"authentication.",
                        f"GET {url} with a valid session, then with no Cookie/Authorization header; "
                        f"compare bodies.",
                        f"GET {url}   (no session)", _body(anon),
                        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"))
                    log("hit", "authz", f"★ missing authentication on {path}")

        # anonymous denied but an authed role is authorised -> try to bypass auth
        if authorized_roles and _denied(anon) and not anon_ok:
            ref = _body(resp[authorized_roles[0]])
            got = _try_bypass(send, url, None, ref)
            if got:
                label, r = got
                key = ("authbypass", path)
                if key not in emitted:
                    emitted.add(key)
                    findings.append(_f(
                        f"Authentication bypass via {label}: {path}",
                        "hunt-auth-bypass", "high",
                        f"{url} requires authentication (anonymous request denied), but an "
                        f"anonymous request using **{label}** returned the protected content "
                        f"verbatim — the access control is bypassable.",
                        f"GET {url} anonymously with the {label} variant; response matches the "
                        f"authenticated body.",
                        f"GET {url}   (anonymous + {label})", _body(r),
                        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"))
                    log("hit", "authz", f"★ auth bypass ({label}) on {path}")

        # ---- (1) horizontal IDOR / BOLA -------------------------------------
        # object endpoint, gated against anon, served to >=2 distinct users as the
        # same object => a different user reads user A's object.
        if has_id and len(authorized_roles) >= 2 and _denied(anon):
            ra = resp[authorized_roles[0]]
            rb = resp[authorized_roles[1]]
            if _same_content(_body(ra), _body(rb)):
                key = ("idor", path)
                if key not in emitted:
                    emitted.add(key)
                    enum = ""
                    for _idx, val in _path_ids(url)[:1] + []:
                        for nb in _neighbors(val):
                            rn = send("GET", _set_path_seg(url, _idx, nb),
                                      identity=authed[0])
                            if _authorized(rn) and not _same_content(_body(rn), _body(ra)):
                                enum = " Identifiers are also enumerable (an adjacent ID returned a " \
                                       "different object), so other users' records can be walked."
                                break
                        if enum:
                            break
                    findings.append(_f(
                        f"IDOR / broken object-level authorization: {path}",
                        "hunt-idor", "high",
                        f"The object-reference endpoint {url} is access-controlled (an anonymous "
                        f"request is denied), yet two different authenticated users "
                        f"('{authorized_roles[0]}' and '{authorized_roles[1]}') both receive the "
                        f"same object ({len(_body(ra))}B, {_norm(_body(ra))[:60]!r}…) — the "
                        f"endpoint does not enforce per-object ownership, so one user can read "
                        f"another's data by referencing their identifier.{enum}",
                        f"As user '{authorized_roles[0]}', GET {url}; replay the identical request "
                        f"as user '{authorized_roles[1]}' — the same object is returned.",
                        f"GET {url}   (as {authorized_roles[1]}, object owned by {authorized_roles[0]})",
                        _body(rb),
                        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"))
                    log("hit", "authz", f"★ IDOR/BOLA on {path}")

        # ---- (2) vertical privilege escalation / BFLA -----------------------
        # app denies the endpoint to some role (control proven) but that role can
        # reach the authorised content via a bypass variant.
        if authorized_roles and denied_roles:
            ref = _body(resp[authorized_roles[0]])
            for drole in denied_roles:
                dident = next((i for i in authed if _role(i) == drole), None)
                if dident is None:
                    continue
                got = _try_bypass(send, url, dident, ref)
                if got:
                    label, r = got
                    key = ("privesc", path, drole)
                    if key not in emitted:
                        emitted.add(key)
                        findings.append(_f(
                            f"Privilege escalation ({drole} → {authorized_roles[0]}) via {label}: {path}",
                            "hunt-authz", "high",
                            f"{url} is denied to the '{drole}' role (the application enforces an "
                            f"authorization control) but is served to '{authorized_roles[0]}'. Using "
                            f"**{label}**, the '{drole}' session obtained the privileged content — a "
                            f"broken function-level authorization / privilege-escalation flaw.",
                            f"As '{drole}', GET {url} with the {label} variant; the response matches "
                            f"the '{authorized_roles[0]}' (privileged) body.",
                            f"GET {url}   (as {drole} + {label})", _body(r),
                            cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"))
                        log("hit", "authz", f"★ privilege escalation {drole}->{authorized_roles[0]} ({label}) on {path}")
                    break

        # ---- (5) enumerable references (only one role to prove with) --------
        if has_id and _path_ids(url) and len(authed) < 2 and authorized_roles:
            idx, val = _path_ids(url)[0]
            if str(val).isdigit():
                distinct = 0
                base_body = _body(resp[authorized_roles[0]])
                for nb in _neighbors(val):
                    rn = send("GET", _set_path_seg(url, idx, nb), identity=authed[0])
                    if _authorized(rn) and not _same_content(_body(rn), base_body):
                        distinct += 1
                if distinct >= 1:
                    key = ("enum", path)
                    if key not in emitted:
                        emitted.add(key)
                        findings.append(_f(
                            f"Enumerable object references: {path}",
                            "hunt-idor", "medium",
                            f"{url} exposes a sequential numeric identifier; adjacent IDs return "
                            f"different valid objects. With a second user account this should be "
                            f"confirmed as IDOR — provide another role to prove cross-user access.",
                            f"GET {url} then increment/decrement the identifier.",
                            f"GET {_set_path_seg(url, idx, _neighbors(val)[0])}", "",
                            conf="needs-review"))
                        log("hit", "authz", f"? enumerable references on {path}")

    return findings
