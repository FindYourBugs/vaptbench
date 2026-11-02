"""Client-ready VAPT report generator.

Renders a branded, professional report (cover, document control, executive
summary with severity donut + category bar, risk methodology, per-finding
detail with CVSS/CWE/OWASP mapping, PoC evidence, remediation, analyst review,
OWASP coverage appendix, sign-off) as styled HTML, then prints it to PDF via
the headless Chromium we already depend on (Playwright).

Dispatch by extension: .pdf (needs Chromium), .html (always), .md (simple).
Branding is configurable via `meta` (company, logo, tester, client, …) so a
team can drop in their own letterhead.
"""
import base64
import html as _html
import os
from datetime import datetime
from urllib.parse import urlparse

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#c0152f", "high": "#e8601c", "medium": "#c99700",
             "low": "#2e7d32", "info": "#5a6b7b"}
BRAND = "#0b2f5e"      # deep navy, like the SysTools template

# vuln_class -> (CWE, OWASP Top 10 2021, report category)
CLASS_MAP = {
    "hunt-sqli":       ("CWE-89",   "A03:2021 – Injection",                 "Injection"),
    "hunt-nosqli":     ("CWE-943",  "A03:2021 – Injection",                 "Injection"),
    "hunt-xss":        ("CWE-79",   "A03:2021 – Injection",                 "Input Handling / XSS"),
    "hunt-html-injection": ("CWE-79", "A03:2021 – Injection",              "Input Handling / XSS"),
    "hunt-lfi":        ("CWE-22",   "A01:2021 – Broken Access Control",     "Injection / File Access"),
    "hunt-rce":        ("CWE-94",   "A03:2021 – Injection",                 "Injection / RCE"),
    "hunt-ssti":       ("CWE-1336", "A03:2021 – Injection",                 "Injection / RCE"),
    "hunt-cmd":        ("CWE-78",   "A03:2021 – Injection",                 "Injection / RCE"),
    "hunt-idor":       ("CWE-639",  "A01:2021 – Broken Access Control",     "Authorization & Access Control"),
    "hunt-ssrf":       ("CWE-918",  "A10:2021 – SSRF",                      "Server-Side Request Forgery"),
    "hunt-cors":       ("CWE-942",  "A05:2021 – Security Misconfiguration", "Security Misconfiguration"),
    "hunt-clickjacking": ("CWE-1021", "A05:2021 – Security Misconfiguration", "Security Misconfiguration"),
    "hunt-open-redirect": ("CWE-601", "A01:2021 – Broken Access Control",   "Open Redirect"),
    "hunt-jwt-crypto": ("CWE-347",  "A02:2021 – Cryptographic Failures",    "Authentication"),
    "hunt-auth-bypass": ("CWE-287", "A07:2021 – Auth Failures",            "Authentication"),
    "hunt-graphql":    ("CWE-16",   "A05:2021 – Security Misconfiguration", "Security Misconfiguration"),
    "hunt-misc":       ("CWE-693",  "A05:2021 – Security Misconfiguration", "Security Misconfiguration"),
    "chain":           ("-",        "-",                                    "Attack Chain"),
    # network / infrastructure classes
    "net-service":     ("-",        "-",                                    "Network Exposure"),
    "net-tls":         ("CWE-326",  "A02:2021 – Cryptographic Failures",    "TLS / Transport Security"),
    "net-ftp":         ("CWE-287",  "A07:2021 – Auth Failures",            "Network Service — FTP"),
    "net-telnet":      ("CWE-319",  "A02:2021 – Cryptographic Failures",    "Cleartext Protocol"),
    "net-smtp":        ("CWE-269",  "A05:2021 – Security Misconfiguration", "Network Service — SMTP"),
    "net-dns":         ("CWE-200",  "A05:2021 – Security Misconfiguration", "Network Service — DNS"),
    "net-smb":         ("CWE-287",  "A05:2021 – Security Misconfiguration", "Network Service — SMB"),
    "net-snmp":        ("CWE-1392", "A05:2021 – Security Misconfiguration", "Network Service — SNMP"),
    "net-redis":       ("CWE-306",  "A05:2021 – Security Misconfiguration", "Unauthenticated Datastore"),
    "net-mongodb":     ("CWE-306",  "A05:2021 – Security Misconfiguration", "Unauthenticated Datastore"),
    "net-memcached":   ("CWE-306",  "A05:2021 – Security Misconfiguration", "Unauthenticated Datastore"),
    "net-elastic":     ("CWE-306",  "A05:2021 – Security Misconfiguration", "Unauthenticated Datastore"),
    "net-nuclei":      ("-",        "-",                                    "Network Vulnerability"),
}
SLA = {"critical": "Within 7 days (emergency)", "high": "Within 15 days",
       "medium": "Within 30 days", "low": "Within 60 days", "info": "Next release cycle"}


def _e(s):
    return _html.escape(str(s or ""))


def _cls(vc):
    return CLASS_MAP.get(vc, ("-", "-", "Other"))


# -------------------------------------------------------------------------- HTML
def _donut(counts):
    total = sum(counts.values()) or 1
    r, cx, cy, circ = 54, 90, 90, 2 * 3.14159 * 54
    segs, off = [], 0.0
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        frac = n / total
        segs.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                    f'stroke="{SEV_COLOR[sev]}" stroke-width="26" '
                    f'stroke-dasharray="{frac*circ:.2f} {circ:.2f}" '
                    f'stroke-dashoffset="{-off*circ:.2f}" transform="rotate(-90 {cx} {cy})"/>')
        off += frac
    legend = "".join(
        f'<div class="lg"><span class="sw" style="background:{SEV_COLOR[s]}"></span>'
        f'{s.capitalize()} ({counts.get(s,0)})</div>' for s in SEV_ORDER if counts.get(s, 0))
    return (f'<div class="donutwrap"><svg width="180" height="180" viewBox="0 0 180 180">'
            f'{"".join(segs)}<text x="90" y="86" text-anchor="middle" class="dn">{total}</text>'
            f'<text x="90" y="104" text-anchor="middle" class="dl">Total</text></svg>'
            f'<div class="legend">{legend}</div></div>')


def _catbar(findings):
    cats = {}
    for f in findings:
        cats[_cls(f.vuln_class)[2]] = cats.get(_cls(f.vuln_class)[2], 0) + 1
    if not cats:
        return ""
    mx = max(cats.values())
    rows = "".join(
        f'<div class="barrow"><div class="barlbl">{_e(k)}</div>'
        f'<div class="bartrack"><div class="bar" style="width:{int(v/mx*100)}%"></div></div>'
        f'<div class="barnum">{v}</div></div>'
        for k, v in sorted(cats.items(), key=lambda x: -x[1]))
    return f'<div class="catbar">{rows}</div>'


def _sections_from_desc(desc):
    """Split a stored description into (body, remediation, analyst_review).
    Handles the AI write-up labels (DESCRIPTION/IMPACT/REMEDIATION, incl. typos)
    and the appended '--- Analyst review ---' critic block."""
    desc = desc or ""
    review = ""
    if "--- Analyst review" in desc:
        desc, review = desc.split("--- Analyst review", 1)
        review = review.split("---", 1)[-1].strip() if review.startswith(" ") else review
        review = review.lstrip(" (AIcrit,advisory)-\n")
    # strip the "--- AI write-up ---" marker if present
    desc = desc.replace("--- AI write-up ---", "").strip()
    remediation = ""
    low = desc.upper()
    for key in ("REMEDIATION:", "REMEDATION:", "REMEDIATION "):
        i = low.find(key)
        if i != -1:
            remediation = desc[i + len(key):].strip()
            desc = desc[:i].strip()
            break
    return desc, remediation, review.strip()


def _finding_html(i, f):
    sev = (f.severity or "info").lower()
    cwe, owasp, _cat = _cls(f.vuln_class)
    loc = urlparse(f.poc_request.split()[-1]) if f.poc_request else None
    host = loc.hostname if loc else ""
    path = (loc.path + ("?" + loc.query if loc and loc.query else "")) if loc else ""
    param = ""
    if "via '" in (f.title or ""):
        param = f.title.split("via '", 1)[1].split("'")[0]
    body, remediation, review = _sections_from_desc(f.description)
    conf = "Confirmed (verifier-proven)" if f.confidence == "confirmed" else "Needs review (flagged)"
    parts = [
        f'<div class="finding">',
        f'<div class="fhead" style="background:{SEV_COLOR[sev]}">'
        f'<span class="fid">F-{i:03d}</span>&nbsp;&nbsp;{_e(f.title)}</div>',
        '<table class="meta">',
        f'<tr><th>Severity</th><td><b style="color:{SEV_COLOR[sev]}">{sev.upper()}</b>'
        + (f' &nbsp;—&nbsp; CVSS {_e(f.cvss.split("/")[0]) if f.cvss else "—"}' if f.cvss else "")
        + f' &nbsp;·&nbsp; {conf}</td></tr>',
        f'<tr><th>Classification (CWE)</th><td>{_e(cwe)}</td></tr>',
        f'<tr><th>OWASP Top 10</th><td>{_e(owasp)}</td></tr>',
        f'<tr><th>Location</th><td>{_e(host)}</td></tr>',
        f'<tr><th>Path / Endpoint</th><td>{_e(path)}</td></tr>',
    ]
    if param:
        parts.append(f'<tr><th>Parameter</th><td>{_e(param)}</td></tr>')
    if f.cvss and "/" in f.cvss:
        parts.append(f'<tr><th>CVSS Vector</th><td><code>{_e(f.cvss)}</code></td></tr>')
    parts.append('</table>')
    if body:
        parts.append(f'<h4>Description</h4><p>{_e(body).replace(chr(10), "<br>")}</p>')
    if f.steps:
        parts.append(f'<h4>Proof of Concept &amp; Steps to Reproduce</h4><pre>{_e(f.steps)}</pre>')
    if f.poc_request:
        parts.append(f'<h4>Request</h4><pre>{_e(f.poc_request)}</pre>')
    if f.poc_response:
        parts.append(f'<h4>Response (evidence)</h4><pre>{_e(f.poc_response[:2000])}</pre>')
    if remediation:
        parts.append(f'<h4>Remediation</h4><p>{_e(remediation).replace(chr(10), "<br>")}</p>')
    if review:
        parts.append(f'<div class="review"><b>Analyst review (AI critic, advisory)</b><br>'
                     f'{_e(review).replace(chr(10), "<br>")}</div>')
    parts.append('</div>')
    return "\n".join(parts)


def build_html(run, findings, meta):
    counts = {s: sum(1 for f in findings if (f.severity or "info").lower() == s) for s in SEV_ORDER}
    total = len(findings)
    confirmed = sum(1 for f in findings if f.confidence == "confirmed")
    top = next((s for s in SEV_ORDER if counts[s]), "info")
    logo = ""
    if meta.get("logo") and os.path.exists(meta["logo"]):
        try:
            ext = os.path.splitext(meta["logo"])[1].lstrip(".") or "png"
            b64 = base64.b64encode(open(meta["logo"], "rb").read()).decode()
            logo = f'<img class="logo" src="data:image/{ext};base64,{b64}">'
        except Exception:
            logo = ""
    if not logo:
        logo = f'<div class="wordmark">{_e(meta.get("company","VAPTBench"))}</div>'

    rows = "".join(
        f'<tr><td><span class="dot" style="background:{SEV_COLOR[s]}"></span>{s.capitalize()}</td>'
        f'<td style="text-align:center">{counts[s]}</td></tr>' for s in SEV_ORDER)
    findings_sorted = sorted(findings, key=lambda f: SEV_ORDER.index((f.severity or "info").lower()))
    detail = "\n".join(_finding_html(i, f) for i, f in enumerate(findings_sorted, 1))
    summary_rows = "".join(
        f'<tr><td>F-{i:03d}</td><td>{_e(f.title)}</td>'
        f'<td><b style="color:{SEV_COLOR[(f.severity or "info").lower()]}">{(f.severity or "info").upper()}</b></td>'
        f'<td>{_e(f.confidence)}</td></tr>'
        for i, f in enumerate(findings_sorted, 1))

    return _TEMPLATE.format(
        brand=BRAND, logo=logo,
        company=_e(meta.get("company", "VAPTBench")),
        tester=_e(meta.get("tester", "")),
        client=_e(meta.get("client", "")),
        target=_e(meta.get("target", "")),
        scope=_e(meta.get("scope", "")),
        classification=_e(meta.get("classification", "CONFIDENTIAL — For intended recipient only")),
        version=_e(meta.get("version", "1.0")),
        date=datetime.utcnow().strftime("%d %B %Y"),
        total=total, confirmed=confirmed, top=top.upper(), top_color=SEV_COLOR[top],
        donut=_donut(counts), catbar=_catbar(findings),
        count_rows=rows, summary_rows=summary_rows or '<tr><td colspan="4">No findings.</td></tr>',
        detail=detail or "<p>No findings were recorded.</p>",
        n_req=run.requests_sent or 0, n_ep=run.endpoints_tested or 0)


# --------------------------------------------------------------------------- PDF
def _footer(meta):
    return (f'<div style="font-size:8px;color:#888;width:100%;padding:0 14mm;'
            f'display:flex;justify-content:space-between">'
            f'<span>CONFIDENTIAL — {_e(meta.get("company","VAPTBench"))}</span>'
            f'<span>VAPT {_e(meta.get("version","1.0"))}</span>'
            f'<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>')


def write_pdf(html, path, meta):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        pg = b.new_context().new_page()
        pg.set_content(html, wait_until="networkidle")
        pg.pdf(path=path, format="A4", print_background=True,
               display_header_footer=True, header_template="<span></span>",
               footer_template=_footer(meta),
               margin={"top": "16mm", "bottom": "16mm", "left": "0mm", "right": "0mm"})
        b.close()


def write(run, findings, path, meta):
    """Write a report by extension. Returns (ok, message)."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        try:
            import playwright  # noqa: F401
        except ImportError:
            alt = path[:-4] + ".html"
            open(alt, "w").write(build_html(run, findings, meta))
            return False, f"Playwright not installed — wrote HTML instead: {alt}"
        try:
            write_pdf(build_html(run, findings, meta), path, meta)
            return True, path
        except Exception as e:
            from .browser_login import error_hint
            alt = path[:-4] + ".html"
            open(alt, "w").write(build_html(run, findings, meta))
            return False, f"PDF render failed ({error_hint(e)}) — wrote HTML instead: {alt}"
    if ext in (".html", ".htm"):
        open(path, "w").write(build_html(run, findings, meta))
        return True, path
    # .md / fallback handled by the caller's markdown writer
    return None, "markdown"


_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4; }}
* {{ box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; color:#1b2733; font-size:11.5px;
       line-height:1.5; margin:0; }}
.page {{ padding: 0 14mm; }}
.cover {{ height: 247mm; padding: 28mm 18mm 0; text-align:center; page-break-after:always; }}
.logo {{ max-height: 70px; margin: 0 auto 8px; }}
.wordmark {{ font-size:34px; font-weight:800; color:{brand}; letter-spacing:.5px; }}
.rule {{ height:3px; background:{brand}; margin:16px 0 36px; }}
h1.title {{ color:{brand}; font-size:30px; line-height:1.25; margin:40px 0 10px; }}
.sub {{ color:{brand}; font-size:15px; font-weight:600; }}
.sub2 {{ color:#5a6b7b; font-size:12px; margin-bottom:28px; }}
table.cover-meta {{ width:100%; border-collapse:collapse; margin-top:10px; }}
table.cover-meta th {{ background:{brand}; color:#fff; text-align:center; width:34%;
       padding:8px 10px; border:1px solid #fff; font-size:11px; }}
table.cover-meta td {{ border:1px solid #d7dde5; padding:8px 12px; text-align:left; }}
h2 {{ color:{brand}; font-size:17px; border-bottom:2px solid {brand};
      padding-bottom:5px; margin:26px 0 12px; page-break-after:avoid; }}
h3 {{ color:{brand}; font-size:13.5px; margin:16px 0 6px; }}
h4 {{ color:{brand}; font-size:12px; margin:12px 0 4px; }}
table.data {{ width:100%; border-collapse:collapse; margin:8px 0; }}
table.data th {{ background:{brand}; color:#fff; text-align:left; padding:6px 9px; font-size:11px; }}
table.data td {{ border:1px solid #d7dde5; padding:6px 9px; }}
.dot {{ display:inline-block; width:9px; height:12px; margin-right:7px; vertical-align:-1px; }}
.riskbox {{ display:flex; margin:10px 0 4px; border:1px solid #d7dde5; }}
.riskbox .lvl {{ width:34%; color:#fff; font-size:22px; font-weight:800;
      display:flex; align-items:center; justify-content:center; padding:18px; }}
.riskbox .txt {{ flex:1; padding:14px 16px; }}
.donutwrap {{ display:flex; align-items:center; gap:26px; margin:10px 0; }}
.dn {{ font-size:26px; font-weight:800; fill:{brand}; }}
.dl {{ font-size:9px; fill:#5a6b7b; }}
.legend .lg {{ font-size:11px; margin:3px 0; }}
.sw {{ display:inline-block; width:11px; height:11px; border-radius:2px; margin-right:7px; }}
.catbar {{ margin:8px 0; }}
.barrow {{ display:flex; align-items:center; margin:4px 0; font-size:10.5px; }}
.barlbl {{ width:42%; }}
.bartrack {{ flex:1; background:#eef1f5; height:12px; border-radius:2px; }}
.bar {{ height:12px; background:{brand}; border-radius:2px; }}
.barnum {{ width:26px; text-align:right; }}
.finding {{ page-break-inside:avoid; margin:20px 0; }}
.fhead {{ color:#fff; font-weight:700; font-size:13px; padding:9px 12px; }}
.fhead .fid {{ font-weight:800; }}
table.meta {{ width:100%; border-collapse:collapse; margin:0 0 8px; }}
table.meta th {{ background:#eef1f5; color:#1b2733; text-align:left; width:26%;
      padding:6px 9px; border:1px solid #d7dde5; font-weight:600; }}
table.meta td {{ border:1px solid #d7dde5; padding:6px 9px; }}
pre {{ background:#f6f8fa; border:1px solid #e1e6ec; border-radius:4px; padding:9px 11px;
      font-family:'Consolas',monospace; font-size:9.5px; white-space:pre-wrap;
      word-break:break-word; overflow-wrap:anywhere; }}
.review {{ background:#fff8e6; border-left:3px solid #d9a300; padding:9px 12px;
      font-size:10.5px; margin:8px 0; }}
.section {{ page-break-before:always; }}
p {{ margin:6px 0; }}
</style></head><body>

<div class="cover">
  {logo}
  <div class="rule"></div>
  <h1 class="title">VULNERABILITY ASSESSMENT &amp;<br>PENETRATION TESTING REPORT</h1>
  <div class="sub">Web Application Security Assessment</div>
  <div class="sub2">{target}</div>
  <div class="rule"></div>
  <table class="cover-meta">
    <tr><th>Target</th><td>{target}</td></tr>
    <tr><th>Asset Type</th><td>Web Application</td></tr>
    <tr><th>Scope</th><td>{scope}</td></tr>
    <tr><th>Assessment Date</th><td>{date}</td></tr>
    <tr><th>Report Version</th><td>{version}</td></tr>
    <tr><th>Prepared By</th><td>{company}</td></tr>
    <tr><th>Lead Tester</th><td>{tester}</td></tr>
    <tr><th>Classification</th><td>{classification}</td></tr>
  </table>
</div>

<div class="page">
  <h2>1. Executive Summary</h2>
  <p>{company} performed an automated, autonomous Vulnerability Assessment and
  Penetration Test of <b>{target}</b>. The assessment identified <b>{total}</b>
  finding(s) ({confirmed} deterministically confirmed). Every confirmed finding
  was reproduced against the live target by a deterministic verifier — not
  inferred — with the raw HTTP evidence captured for each.</p>

  <h3>Overall Risk Rating</h3>
  <div class="riskbox">
    <div class="lvl" style="background:{top_color}">{top}</div>
    <div class="txt">The highest-severity confirmed exposure on this target is
      <b>{top}</b>. Remediation should proceed in severity order, prioritising
      Critical and High findings within their recommended SLAs before release.</div>
  </div>

  <h3>Findings at a Glance</h3>
  {donut}
  {catbar}

  <h2>2. Risk Summary</h2>
  <table class="data"><tr><th>Severity</th><th style="text-align:center">Count</th></tr>
  {count_rows}
  <tr><td><b>Total</b></td><td style="text-align:center"><b>{total}</b></td></tr></table>
  <p style="color:#5a6b7b">Engagement stats: {n_ep} endpoint(s) tested, {n_req} request(s) sent.</p>

  <h2>3. Risk Rating Methodology</h2>
  <table class="data">
    <tr><th>Severity</th><th>CVSS v3.1</th><th>Business Meaning</th><th>Recommended SLA</th></tr>
    <tr><td><b style="color:#c0152f">Critical</b></td><td>9.0 – 10.0</td><td>Direct, trivially-exploitable compromise. Fix immediately.</td><td>Within 7 days</td></tr>
    <tr><td><b style="color:#e8601c">High</b></td><td>7.0 – 8.9</td><td>Serious weakness with a clear exploitation path.</td><td>Within 15 days</td></tr>
    <tr><td><b style="color:#c99700">Medium</b></td><td>4.0 – 6.9</td><td>Exploitable under specific conditions, or a chain contributor.</td><td>Within 30 days</td></tr>
    <tr><td><b style="color:#2e7d32">Low</b></td><td>0.1 – 3.9</td><td>Limited direct impact; defence-in-depth gap.</td><td>Within 60 days</td></tr>
    <tr><td><b style="color:#5a6b7b">Informational</b></td><td>0.0</td><td>No direct exploit path; recorded for context.</td><td>Next release</td></tr>
  </table>

  <h2>4. Findings Summary</h2>
  <table class="data"><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th></tr>
  {summary_rows}</table>
</div>

<div class="page section">
  <h2>5. Detailed Findings</h2>
  <p>Each finding is presented with a severity header, a metadata block
  (CVSS/CWE/OWASP, location, parameter), a technical description, proof-of-concept
  evidence, remediation, and — where available — an advisory analyst review.</p>
  {detail}
</div>

<div class="page section">
  <h2>Sign-off</h2>
  <p>This report was produced by {company}. Testing was conducted under written
  authorisation, in a controlled, non-destructive manner, limited to the agreed
  scope. Security is not static; changes after the assessment date may introduce
  new weaknesses not covered here.</p>
  <p style="margin-top:30px">Lead Tester: <b>{tester}</b><br>Date: {date}<br>
  Classification: {classification}</p>
</div>

</body></html>"""
