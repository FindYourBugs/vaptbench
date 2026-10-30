"""Recon runners — drive the standard tools, scope-checked, parse results.

Each tool is a registry entry that builds an argv list (no shell) from the
target. Output is captured; discovered URLs are extracted so they can be
imported as captured requests for the Repeater / access-control matrix.

Tools are optional: if the binary isn't on PATH the runner reports that
cleanly instead of failing.
"""
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse

from .scope import in_scope

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
DEFAULT_WORDLIST = os.environ.get(
    "VAPT_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt")


def _host(url):
    return urlparse(url).hostname or url


# name -> (binary, argv-builder, produces_urls, timeout_s, note)
REGISTRY = {
    "httpx": {
        "bin": "httpx",
        "args": lambda u: ["httpx", "-silent", "-td", "-title", "-sc", "-u", u],
        "urls": False, "timeout": 60,
        "note": "probe: status, title, tech detection",
    },
    "whatweb": {
        "bin": "whatweb",
        "args": lambda u: ["whatweb", "--color=never", u],
        "urls": False, "timeout": 60,
        "note": "technology fingerprint",
    },
    "katana": {
        "bin": "katana",
        "args": lambda u: ["katana", "-silent", "-d", "2", "-jc", "-u", u],
        "urls": True, "timeout": 180,
        "note": "crawl (depth 2, incl. JS endpoints)",
    },
    "gau": {
        "bin": "gau",
        "args": lambda u: ["gau", "--subs", _host(u)],
        "urls": True, "timeout": 120,
        "note": "historical URLs (wayback/otx/commoncrawl)",
    },
    "waybackurls": {
        "bin": "waybackurls",
        "args": lambda u: ["waybackurls", _host(u)],
        "urls": True, "timeout": 120,
        "note": "historical URLs (wayback)",
    },
    "ffuf": {
        "bin": "ffuf",
        "args": lambda u: ["ffuf", "-u", u.rstrip("/") + "/FUZZ",
                           "-w", DEFAULT_WORDLIST,
                           "-mc", "200,204,301,302,307,401,403", "-s"],
        "urls": False, "timeout": 300,
        "note": "content discovery (needs wordlist)",
    },
    "nuclei": {
        "bin": "nuclei",
        "args": lambda u: ["nuclei", "-silent", "-u", u],
        "urls": False, "timeout": 600,
        "note": "templated checks (your nuclei templates)",
    },
}


def available_tools():
    """Return [{name, installed, note}] for the registry."""
    out = []
    for name, spec in REGISTRY.items():
        out.append({
            "name": name,
            "installed": shutil.which(spec["bin"]) is not None,
            "note": spec["note"],
        })
    return out


def run_tool(name, base_url, scope_rules):
    """Run one tool against base_url (scope-checked). Returns a result dict."""
    spec = REGISTRY.get(name)
    if not spec:
        return {"status": "error", "output": f"unknown tool: {name}", "command": "", "urls": []}

    ok, why = in_scope(base_url, scope_rules)
    if not ok:
        return {"status": "blocked", "output": f"target out of scope: {why}",
                "command": "", "urls": []}

    if shutil.which(spec["bin"]) is None:
        return {"status": "error", "output": f"{spec['bin']} not installed (PATH)",
                "command": "", "urls": []}

    if name == "ffuf" and not os.path.exists(DEFAULT_WORDLIST):
        return {"status": "error", "command": "",
                "output": f"wordlist not found: {DEFAULT_WORDLIST} (set VAPT_WORDLIST)",
                "urls": []}

    argv = spec["args"](base_url)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=spec["timeout"])
        output = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return {"status": "error", "command": " ".join(argv),
                "output": f"timed out after {spec['timeout']}s", "urls": []}
    except OSError as e:
        return {"status": "error", "command": " ".join(argv),
                "output": str(e), "urls": []}

    urls = []
    if spec["urls"]:
        seen = set()
        for m in URL_RE.findall(output):
            if m not in seen:
                seen.add(m)
                urls.append(m)
        urls = urls[:500]  # cap

    return {"status": "done", "command": " ".join(argv),
            "output": output[:40000], "urls": urls}
