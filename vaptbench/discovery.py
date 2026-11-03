"""Deep attack-surface discovery — close the coverage gaps beyond the base crawl.

Three best-effort, scope-checked sources, each degrading gracefully to nothing
(a missing tool, unreachable spec, or parse error yields no URLs, never a crash):

  1. sitemap / robots ingestion            -> pages the in-page crawl never linked to
  2. OpenAPI / Swagger + GraphQL ingestion  -> the documented API contract, expanded
                                               into concrete, testable endpoint URLs
  3. hidden-parameter mining (arjun)        -> parameters that exist server-side but
                                               appear in no form or link

`expand_surface` returns (new_urls, post_methods, notes):
  - new_urls      : set[str] of in-scope endpoint URLs to merge into the run
  - post_methods  : list[(METHOD, url)] non-GET operations worth replaying
  - notes         : list[(kind, url, detail)] for logging / exposure findings
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urljoin, urlparse, urlencode

from .scope import in_scope

try:
    import yaml
except Exception:                      # PyYAML optional; JSON specs still work
    yaml = None

API_INGEST = os.environ.get("VAPT_API_INGEST", "1") != "0"
PARAM_MINING = os.environ.get("VAPT_PARAM_MINING", "1") != "0"
_MINE_MAX = int(os.environ.get("VAPT_PARAM_MINE_MAX", "6"))     # endpoints to arjun
_MINE_TIMEOUT = int(os.environ.get("VAPT_PARAM_MINE_TIMEOUT", "120"))


def _ok200(r):
    return r.get("status") == 200 and (r.get("text") or "")


def _in(url, scope):
    try:
        ok, _ = in_scope(url, scope)
        return ok
    except Exception:
        return False


# --------------------------------------------------------------- sitemap/robots
_SITEMAP_SEEDS = ["robots.txt", "sitemap.xml", "sitemap_index.xml"]


def ingest_sitemaps(base_url, send, scope, log):
    found, seen_sm, nested = set(), set(), 0
    queue = [urljoin(base_url, p) for p in _SITEMAP_SEEDS]
    while queue:
        u = queue.pop(0)
        if u in seen_sm:
            continue
        seen_sm.add(u)
        if not _in(u, scope):
            continue
        r = send("GET", u)
        if not _ok200(r):
            continue
        body = r["text"]
        if u.rstrip("/").endswith("robots.txt"):
            for kind, val in re.findall(r"(?im)^\s*(allow|disallow|sitemap)\s*:\s*(\S+)", body):
                val = val.strip()
                if val in ("", "/", "*"):
                    continue
                tgt = val if val.startswith("http") else urljoin(base_url, val)
                if kind.lower() == "sitemap":
                    if nested < 15:
                        queue.append(tgt)
                        nested += 1
                elif _in(tgt, scope) and "*" not in tgt:
                    found.add(tgt.split("#")[0])
        else:                           # <urlset> / <sitemapindex>
            for loc in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", body, re.I):
                loc = loc.strip()
                if loc.endswith(".xml") and loc not in seen_sm and nested < 15:
                    queue.append(loc)
                    nested += 1
                elif _in(loc, scope):
                    found.add(loc.split("#")[0])
    if found:
        log("info", "discover", f"sitemap/robots: +{len(found)} URL(s)")
    return found


# --------------------------------------------------------------- OpenAPI/Swagger
_OPENAPI_PATHS = ["openapi.json", "swagger.json", "v3/api-docs", "api-docs",
                  "v2/swagger.json", "api/swagger.json", "swagger/v1/swagger.json",
                  "api/openapi.json", "openapi.yaml", "swagger.yaml", "api/docs.json"]


def _load_spec(body):
    body = (body or "").strip()
    try:
        return json.loads(body)
    except Exception:
        pass
    if yaml:
        try:
            d = yaml.safe_load(body)
            return d if isinstance(d, dict) else None
        except Exception:
            return None
    return None


def _spec_base(spec, base_url):
    """Resolve the API base URL from an OpenAPI 3 (servers[]) or Swagger 2
    (host + basePath) document, relative to the target when the spec is relative."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        u = (servers[0] or {}).get("url", "") if isinstance(servers[0], dict) else ""
        if u.startswith("http"):
            return u.rstrip("/") + "/"
        if u.startswith("/"):
            return urljoin(base_url, u).rstrip("/") + "/"
    host, bp = spec.get("host"), (spec.get("basePath") or "")
    if host:
        schemes = spec.get("schemes") or ["https"]
        scheme = "https" if "https" in schemes else schemes[0]
        return f"{scheme}://{host}{bp}".rstrip("/") + "/"
    if bp:
        return urljoin(base_url, bp.rstrip("/") + "/")
    return base_url if base_url.endswith("/") else base_url + "/"


def ingest_openapi(base_url, send, scope, log):
    """Return (urls, post_methods, note) from the first reachable OpenAPI/Swagger doc."""
    for p in _OPENAPI_PATHS:
        u = urljoin(base_url if base_url.endswith("/") else base_url + "/", p)
        if not _in(u, scope):
            continue
        r = send("GET", u)
        if not _ok200(r):
            continue
        spec = _load_spec(r["text"])
        if not spec or not isinstance(spec.get("paths"), dict):
            continue
        sbase = _spec_base(spec, base_url)
        urls, post_methods = set(), []
        for path, item in spec["paths"].items():
            if not isinstance(item, dict):
                continue
            concrete = re.sub(r"\{[^}]+\}", "1", str(path)).lstrip("/")
            full = urljoin(sbase, concrete)
            if not _in(full, scope):
                continue
            qp = {}
            for meth, op in item.items():
                if meth.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                for prm in (op.get("parameters") if isinstance(op, dict) else None) or []:
                    if isinstance(prm, dict) and prm.get("in") == "query":
                        qp[prm.get("name", "q")] = "1"
                if meth.lower() in ("post", "put", "patch", "delete"):
                    post_methods.append((meth.upper(), full))
            urls.add(full + ("?" + urlencode(qp) if qp else ""))
        if urls:
            log("hit", "discover", f"OpenAPI/Swagger at /{p}: +{len(urls)} documented route(s)")
            return urls, post_methods, ("openapi", u, f"{len(urls)} documented route(s)")
    return set(), [], None


# --------------------------------------------------------------- GraphQL
_GQL_PATHS = ["graphql", "api/graphql", "graphql/v1", "v1/graphql", "query", "gql"]
_GQL_INTROSPECT = json.dumps(
    {"query": "{__schema{queryType{name} mutationType{name} types{name kind}}}"})


def ingest_graphql(base_url, send, scope, log):
    for p in _GQL_PATHS:
        u = urljoin(base_url if base_url.endswith("/") else base_url + "/", p)
        if not _in(u, scope):
            continue
        r = send("POST", u, headers="Content-Type: application/json", body=_GQL_INTROSPECT)
        body = r.get("text") or ""
        if r.get("status") in (200, 400) and '"__schema"' in body:
            log("hit", "discover", f"GraphQL introspection enabled at /{p}")
            return {u}, ("graphql", u, "introspection enabled (full schema exposed)")
    return set(), None


# --------------------------------------------------------------- param mining
def _run_arjun(url, method="GET"):
    """Run arjun on one URL, return list of discovered parameter names."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    params = []
    try:
        subprocess.run(["arjun", "-u", url, "-oJ", path, "-t", "10", "-T", "6",
                        "-q", "-m", method],
                       capture_output=True, text=True, timeout=_MINE_TIMEOUT)
        with open(path) as f:
            data = json.load(f)
        # arjun writes {url: {"params":[...], "method":...}} or {url: [...]}
        for _k, v in (data.items() if isinstance(data, dict) else []):
            if isinstance(v, dict):
                params += v.get("params") or v.get("found") or list(v.get("params", []))
            elif isinstance(v, list):
                params += v
    except Exception:
        pass
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass
    # de-dupe, keep names only
    seen, out = set(), []
    for p in params:
        if isinstance(p, str) and p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def mine_params(endpoints, scope, log):
    """Discover hidden parameters on the parameter-less endpoints via arjun,
    returning synthesised ?p=1 URLs ready for the injection tiers."""
    if not (PARAM_MINING and shutil.which("arjun")):
        return set()
    cand = [u for u in endpoints if not urlparse(u).query][:_MINE_MAX]
    found = set()
    for u in cand:
        if not _in(u, scope):
            continue
        names = _run_arjun(u)
        if names:
            synth = u + ("&" if urlparse(u).query else "?") + urlencode({p: "1" for p in names})
            found.add(synth)
            log("hit", "discover",
                f"arjun: {u} -> hidden param(s): {', '.join(names[:8])}"
                + (" …" if len(names) > 8 else ""))
    if found:
        log("info", "discover", f"param mining: +{len(found)} endpoint(s) with hidden params")
    return found


# --------------------------------------------------------------- orchestration
def expand_surface(base_url, send, scope, endpoints, log, param_mining=True):
    """Run all deep-discovery sources. Returns (new_urls, post_methods, notes)."""
    new_urls, post_methods, notes = set(), [], []

    try:
        new_urls |= ingest_sitemaps(base_url, send, scope, log)
    except Exception as e:
        log("warn", "discover", f"sitemap ingest error: {e}")

    if API_INGEST:
        try:
            u, pm, note = ingest_openapi(base_url, send, scope, log)
            new_urls |= u
            post_methods += pm
            if note:
                notes.append(note)
        except Exception as e:
            log("warn", "discover", f"openapi ingest error: {e}")
        try:
            u, note = ingest_graphql(base_url, send, scope, log)
            new_urls |= u
            if note:
                notes.append(note)
        except Exception as e:
            log("warn", "discover", f"graphql ingest error: {e}")

    if param_mining:
        try:
            # mine the richer set: original endpoints + newly discovered pages
            mine_set = list(dict.fromkeys(list(endpoints) + list(new_urls)))
            new_urls |= mine_params(mine_set, scope, log)
        except Exception as e:
            log("warn", "discover", f"param mining error: {e}")

    return new_urls, post_methods, notes
