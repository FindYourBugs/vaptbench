"""HTML form & parameter discovery.

Classic apps (DVWA, most PHP/Java/Rails apps) expose their injectable surface
through FORMS, not through parameterised links. The SQLi page is
``/vulnerabilities/sqli/`` with a ``<form>`` whose ``id`` input becomes
``?id=1&Submit=Submit`` only when submitted — a plain link crawl never sees that
parameter, so the injection verifiers have nothing to bite.

This module parses forms out of a page and synthesises testable requests:
- GET forms  -> a URL with the inputs as query params (feeds the GET-based
  Tier-1/Tier-2 injection verifiers directly).
- POST forms -> a (method, action, params) record the engine can replay.

Stdlib html.parser only (no bs4 dependency).
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlencode, urlparse

# A benign default value per input so the param exists and round-trips; the
# verifiers overwrite it with their payloads.
_DEFAULTS = {
    "email": "test@example.com", "number": "1", "tel": "1234567890",
    "url": "https://example.com/", "date": "2024-01-01", "search": "test",
}
_SUBMIT_TYPES = {"submit", "button", "image", "reset"}
_SKIP_TYPES = {"file"}   # file uploads need multipart; handled elsewhere


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self._cur = {"method": (a.get("method") or "get").lower(),
                         "action": a.get("action", ""), "inputs": {},
                         "enctype": (a.get("enctype") or "").lower(),
                         "file_field": None}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if not name:
                return
            itype = (a.get("type") or "").lower()
            if itype in _SKIP_TYPES:
                # remember the file field so the upload tester can target it
                self._cur["file_field"] = name
                return
            if itype in _SUBMIT_TYPES:
                # keep a submit button's name=value — DVWA needs &Submit=Submit
                self._cur["inputs"].setdefault(name, a.get("value") or "Submit")
            else:
                self._cur["inputs"][name] = a.get("value") or _DEFAULTS.get(itype, "1")

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def extract_forms(html, page_url):
    """Return [{method, action(absolute url), inputs{name:default}}] for a page."""
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    out = []
    for f in p.forms:
        action = urljoin(page_url, f["action"]) if f["action"] else page_url
        if not action.startswith("http"):
            continue
        out.append({"method": f["method"], "action": action.split("#")[0],
                    "inputs": f["inputs"], "enctype": f.get("enctype", ""),
                    "file_field": f.get("file_field")})
    return out


def get_form_urls(html, page_url):
    """Synthesise testable GET URLs from GET forms that carry inputs, so the
    injection verifiers have real parameters to inject into."""
    urls = []
    for f in extract_forms(html, page_url):
        if f["method"] != "get" or not f["inputs"]:
            continue
        sep = "&" if urlparse(f["action"]).query else "?"
        urls.append(f["action"] + sep + urlencode(f["inputs"]))
    return urls


def post_forms(html, page_url):
    """POST forms as (action, params) records for the engine to replay later."""
    return [{"action": f["action"], "inputs": f["inputs"]}
            for f in extract_forms(html, page_url)
            if f["method"] == "post" and f["inputs"]]


def upload_forms(html, page_url):
    """Multipart file-upload forms: those with a file input (or multipart enctype)
    — the surface the file-upload bypass tester targets."""
    out = []
    for f in extract_forms(html, page_url):
        if f.get("file_field") or "multipart" in (f.get("enctype") or ""):
            out.append({"action": f["action"], "file_field": f.get("file_field"),
                        "inputs": f["inputs"]})
    return out
