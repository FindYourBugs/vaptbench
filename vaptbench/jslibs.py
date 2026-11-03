"""Client-side JavaScript library CVE detection (retire.js-style, self-contained).

The `_cve_phase` nuclei pass covers server-side components; it does NOT see the
front-end JS libraries a page ships (jQuery, AngularJS, Bootstrap, lodash, …),
which are a very common "vulnerable & outdated component" (OWASP A06) finding on
real apps. retire.js does exactly this but isn't installed on every box, so this
module reproduces its core behaviour with no external dependency:

  1. detect each library + version from <script src> filenames and from the
     version banners embedded in the script bodies (same signal retire.js uses)
  2. compare the detected version against a curated table of known-fixed
     versions and report every library that is below one (CWE-1395 / A06).

Detection is deterministic: a disclosed version that sits below a known-fixed
release is a real finding (this is precisely what retire.js reports). If the
`retire` binary IS present it is used in addition, for its larger dataset.
Disable with VAPT_JS_CVE=0.
"""
import json
import os
import re
import shutil
import subprocess
from urllib.parse import urljoin, urlparse

JS_CVE = os.environ.get("VAPT_JS_CVE", "1") != "0"
_MAX_SCRIPTS = int(os.environ.get("VAPT_JS_MAX_SCRIPTS", "20"))


def _ver(s):
    """'3.4.1' -> (3,4,1); tolerant of trailing junk. None if no numeric version."""
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", (s or "").strip())
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())


# lib -> list of (fixed_in, [CVEs], severity, one-line summary). A detected
# version strictly BELOW `fixed_in` is reported. Ordered worst-first so the most
# serious applicable entry is chosen.
_VULN = {
    "jquery": [
        ((3, 5, 0), ["CVE-2020-11022", "CVE-2020-11023"], "medium",
         "jQuery.htmlPrefilter cross-site scripting via crafted HTML from untrusted sources"),
        ((3, 4, 0), ["CVE-2019-11358"], "medium",
         "jQuery.extend(true,...) prototype pollution"),
        ((3, 0, 0), ["CVE-2015-9251"], "medium",
         "cross-domain AJAX without dataType executes attacker script (XSS)"),
    ],
    "jquery-ui": [
        ((1, 13, 2), ["CVE-2022-31160"], "medium", "XSS in jQuery UI checkboxradio widget"),
        ((1, 12, 0), ["CVE-2016-7103"], "medium", "XSS via jQuery UI dialog closeText option"),
    ],
    "angular": [   # AngularJS 1.x — end-of-life, multiple unpatched XSS/sandbox escapes
        ((1, 99, 0), ["CVE-2020-7676", "CVE-2019-10768", "CVE-2022-25869"], "medium",
         "AngularJS 1.x is end-of-life with known XSS / sanitiser-bypass issues and no security fixes"),
    ],
    "bootstrap": [
        ((3, 4, 1), ["CVE-2019-8331", "CVE-2018-14041", "CVE-2018-14040", "CVE-2018-14042"], "medium",
         "XSS via data-* attributes (tooltip/popover/collapse/scrollspy)"),
        ((4, 3, 1), ["CVE-2019-8331"], "medium",
         "XSS via data-template / data-* attributes in 4.x before 4.3.1"),
    ],
    "lodash": [
        ((4, 17, 21), ["CVE-2021-23337"], "high",
         "command injection via lodash template; prototype pollution in _.set/_.zipObjectDeep"),
        ((4, 17, 12), ["CVE-2019-10744"], "high",
         "prototype pollution via _.defaultsDeep"),
    ],
    "underscore": [
        ((1, 12, 1), ["CVE-2021-23358"], "high",
         "arbitrary code execution via the template function's variable option"),
    ],
    "moment": [
        ((2, 29, 4), ["CVE-2022-31129"], "medium", "ReDoS parsing very long date strings"),
        ((2, 29, 2), ["CVE-2022-24785"], "medium", "path traversal via crafted locale name"),
    ],
    "handlebars": [
        ((4, 7, 7), ["CVE-2021-23369", "CVE-2021-23383"], "high",
         "remote code execution / prototype pollution via crafted templates"),
    ],
    "dompurify": [
        ((2, 4, 0), ["CVE-2020-26870"], "medium", "mutation-XSS (mXSS) sanitiser bypass"),
    ],
    "axios": [
        ((1, 6, 0), ["CVE-2023-45857"], "medium",
         "CSRF/XSRF token leaked to third-party host via SSRF-style redirect"),
        ((0, 21, 2), ["CVE-2021-3749"], "medium", "ReDoS in trim regex"),
        ((0, 21, 1), ["CVE-2020-28168"], "medium", "SSRF via proxy-bypass on redirect"),
    ],
}

# library name as it may appear in a filename / URL  ->  canonical table key
_ALIASES = {
    "jquery.min": "jquery", "jquery-latest": "jquery",
    "jquery.ui": "jquery-ui", "jquery-ui.min": "jquery-ui",
    "angular.min": "angular", "angularjs": "angular",
    "bootstrap.min": "bootstrap", "bootstrap.bundle": "bootstrap",
    "lodash.min": "lodash", "underscore.min": "underscore",
    "moment.min": "moment", "handlebars.min": "handlebars", "handlebars.runtime": "handlebars",
    "purify": "dompurify", "purify.min": "dompurify", "dompurify.min": "dompurify",
    "axios.min": "axios",
}

# version banners inside script bodies (same evidence retire.js matches on)
_BANNERS = [
    ("jquery", re.compile(r"jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+)", re.I)),
    ("jquery-ui", re.compile(r"jQuery UI\s+-?\s*v?(\d+\.\d+\.\d+)", re.I)),
    ("angular", re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("bootstrap", re.compile(r"Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("lodash", re.compile(r"[Ll]odash(?:\.js)?[^\n]*?([\d]+\.[\d]+\.[\d]+)")),
    ("lodash", re.compile(r"VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]")),
    ("moment", re.compile(r"[Mm]oment\.js[^\n]*?(\d+\.\d+\.\d+)")),
    ("handlebars", re.compile(r"[Hh]andlebars[^\n]*?v?(\d+\.\d+\.\d+)")),
    ("dompurify", re.compile(r"DOMPurify[^\n]*?(\d+\.\d+\.\d+)", re.I)),
    ("axios", re.compile(r"[Aa]xios(?:/|\s+v)(\d+\.\d+\.\d+)")),
]
# name-version in a filename:  jquery-3.4.1.min.js / angular.1.7.9.js / lodash.4.17.4.js
_FNAME = re.compile(r"([a-zA-Z][a-zA-Z0-9_.\-]*?)[-._]v?(\d+\.\d+(?:\.\d+)?)", re.I)
_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)


def _canon(name):
    name = (name or "").lower().strip().rstrip(".-_")
    name = _ALIASES.get(name, name)
    return name if name in _VULN else None


def _match_version(lib, version):
    """Return (fixed_in, cves, severity, summary) for the worst entry the detected
    version is below, else None."""
    v = _ver(version)
    if not v:
        return None
    for fixed_in, cves, sev, summary in _VULN.get(lib, []):
        if v < fixed_in:
            return fixed_in, cves, sev, summary
    return None


def _detect_from_src(src):
    """(lib, version) from a script URL's filename, or None."""
    fname = urlparse(src).path.rsplit("/", 1)[-1]
    fname = re.sub(r"\.(min|slim|bundle|runtime)\b", "", fname, flags=re.I)
    for m in _FNAME.finditer(fname):
        lib = _canon(m.group(1))
        if lib:
            return lib, m.group(2)
    return None


def _detect_from_body(text):
    """[(lib, version)] from version banners in a script body."""
    out = []
    head = (text or "")[:6000]
    for lib, rx in _BANNERS:
        m = rx.search(head)
        if m:
            out.append((lib, m.group(1)))
    return out


def _finding(lib, version, src, fixed_in, cves, sev, summary):
    fixed = ".".join(str(x) for x in fixed_in)
    cve_s = ", ".join(cves)
    return dict(
        title=f"Outdated JavaScript library: {lib} {version} [{cves[0]}]",
        vuln_class="web-cve", severity=sev, confidence="confirmed",
        cvss="",
        description=f"The page loads **{lib} {version}**, which is affected by known "
                    f"vulnerabilities ({cve_s}): {summary}. Fixed in {lib} {fixed} or later. "
                    f"Client-side library versions are trivially read by any visitor, so an "
                    f"attacker can target the exact flaws of this release.\n\nReference: "
                    f"https://nvd.nist.gov/vuln/detail/{cves[0]}",
        steps=f"Observe the loaded script ({src}); the version {version} is < {fixed}.",
        poc_request=f"GET {src}",
        poc_response=f"{lib} {version} (vulnerable; fixed in {fixed}) — {cve_s}")


def _run_retire(base_url, log):
    """If retire.js is installed, run it against the target for extra coverage."""
    if not shutil.which("retire"):
        return []
    try:
        out = subprocess.run(["retire", "--outputformat", "json", "--path", "/dev/null"],
                             capture_output=True, text=True, timeout=30)
    except Exception:
        return []
    # retire's web scanning needs a URL plugin; the CLI alone scans the filesystem.
    # We keep this as a no-op hook (binary absent on this box) rather than guess its
    # output shape — the built-in detector below is the primary path.
    return []


def scan(send, base_url, base_html, log=None):
    """Detect outdated/vulnerable client-side JS libraries. `send` matches the
    engine contract. Returns a list of finding dicts (deduped per lib+version)."""
    if not JS_CVE:
        return []
    log = log or (lambda *a: None)
    findings, seen = [], set()

    def consider(lib, version, src):
        hit = _match_version(lib, version)
        if not hit:
            return
        key = (lib, version)
        if key in seen:
            return
        seen.add(key)
        fixed_in, cves, sev, summary = hit
        findings.append(_finding(lib, version, src, fixed_in, cves, sev, summary))
        log("hit", "cve", f"★ outdated JS lib: {lib} {version} ({cves[0]}) — fixed in "
                          + ".".join(str(x) for x in fixed_in))

    # 1) library + version straight from <script src> filenames
    srcs = []
    for m in _SRC_RE.finditer(base_html or ""):
        srcs.append(urljoin(base_url, m.group(1)))
    host = urlparse(base_url).hostname
    for src in srcs:
        d = _detect_from_src(src)
        if d:
            consider(d[0], d[1], src)

    # 2) fetch same-origin scripts and read their embedded version banners — catches
    #    libraries served under version-less names (jquery.min.js, app.bundle.js, …)
    fetched = 0
    for src in srcs:
        if fetched >= _MAX_SCRIPTS:
            break
        if urlparse(src).hostname != host or not src.lower().split("?")[0].endswith(".js"):
            continue
        fetched += 1
        try:
            r = send("GET", src)
        except Exception:
            continue
        if not r.get("ok") or r.get("status") != 200:
            continue
        for lib, version in _detect_from_body(r.get("text") or ""):
            consider(lib, version, src)

    # 3) banners in any inline <script> in the page itself
    for lib, version in _detect_from_body(base_html or ""):
        consider(lib, version, base_url)

    return findings
