"""Deep attack-surface discovery — close the coverage gaps beyond the base crawl.

Three best-effort, scope-checked sources, each degrading gracefully to nothing
(a missing tool, unreachable spec, or parse error yields no URLs, never a crash):

  1. sitemap / robots ingestion            -> pages the in-page crawl never linked to
  2. OpenAPI / Swagger + GraphQL ingestion  -> the documented API contract, expanded
                                               into concrete, testable endpoint URLs
  3. hidden-parameter mining (arjun)        -> parameters that exist server-side but
                                               appear in no form or link

`expand_surface` returns (new_urls, post_methods, body_ops, notes):
  - new_urls      : set[str] of in-scope endpoint URLs to merge into the run
  - post_methods  : list[(METHOD, url)] non-GET operations worth replaying
  - body_ops      : list[dict] documented ops with a synthesised JSON body to fuzz
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
MINE_POST = os.environ.get("VAPT_PARAM_MINE_POST", "1") != "0"   # also mine JSON-body params
_MINE_MAX = int(os.environ.get("VAPT_PARAM_MINE_MAX", "6"))     # endpoints to arjun
_MINE_TIMEOUT = int(os.environ.get("VAPT_PARAM_MINE_TIMEOUT", "120"))
_MAX_BODY_FIELDS = int(os.environ.get("VAPT_MAX_BODY_FIELDS", "40"))  # injectable leaves / body


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


def _resolve_ref(spec, ref):
    """Resolve a local JSON pointer ('#/components/schemas/X' or '#/definitions/X')."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _example(schema, spec, seen=None, depth=0):
    """Build a concrete example value from a JSON schema (OpenAPI 3 / Swagger 2),
    resolving $ref. Strings default to '1' so they round-trip as injectable values."""
    if not isinstance(schema, dict) or depth > 6:
        return "1"
    if "$ref" in schema:
        seen = seen or set()
        ref = schema["$ref"]
        if ref in seen:                        # guard against recursive schemas
            return {}
        seen = seen | {ref}
        return _example(_resolve_ref(spec, ref) or {}, spec, seen, depth + 1)
    if "example" in schema and not isinstance(schema["example"], (dict, list)):
        return schema["example"]
    if schema.get("enum"):
        return schema["enum"][0]
    for comb in ("allOf", "oneOf", "anyOf"):
        if isinstance(schema.get(comb), list) and schema[comb]:
            merged = {}
            for sub in (schema[comb] if comb == "allOf" else schema[comb][:1]):
                v = _example(sub, spec, seen, depth + 1)
                if isinstance(v, dict):
                    merged.update(v)
            if merged or comb != "allOf":
                return merged or _example(schema[comb][0], spec, seen, depth + 1)
    t = schema.get("type")
    if t == "object" or (t is None and "properties" in schema):
        out = {}
        for name, sub in (schema.get("properties") or {}).items():
            out[name] = _example(sub, spec, seen, depth + 1)
        return out
    if t == "array":
        return [_example(schema.get("items") or {}, spec, seen, depth + 1)]
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    return "1"                                 # string / unknown -> injectable token


def _field_paths(value, prefix=""):
    """Every string-valued leaf in a synthesised JSON body, as a dotted/bracket
    path — at ANY nesting depth, inside arrays included:

        {"email": "1"}                       -> ["email"]
        {"user": {"name": "1"}}               -> ["user.name"]
        {"items": [{"sku": "1"}]}             -> ["items[0].sku"]
        {"roles": ["1"]}                      -> ["roles[0]"]

    These are the injectable fields the JSON-body fuzzer mutates one at a time.
    Top-level-only coverage used to miss every nested object/array field."""
    out = []
    if isinstance(value, dict):
        for k, v in value.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            out += _field_paths(v, p)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out += _field_paths(v, f"{prefix}[{i}]")
    elif isinstance(value, str) and prefix:
        out.append(prefix)
    return out[:_MAX_BODY_FIELDS]


def _body_op(spec, method, url, op):
    """If the operation documents a JSON request body, synthesise a concrete body
    and list its injectable (string-valued) fields at every nesting depth."""
    schema = None
    # OpenAPI 3: requestBody.content["application/json"].schema
    rb = op.get("requestBody") if isinstance(op, dict) else None
    if isinstance(rb, dict):
        if "$ref" in rb:
            rb = _resolve_ref(spec, rb["$ref"]) or rb
        content = (rb.get("content") or {}) if isinstance(rb, dict) else {}
        for ct in ("application/json", "application/*+json", "*/*"):
            if ct in content and isinstance(content[ct], dict):
                schema = content[ct].get("schema")
                break
    # Swagger 2: a parameter with in == "body"
    if schema is None:
        for prm in (op.get("parameters") if isinstance(op, dict) else None) or []:
            if isinstance(prm, dict) and prm.get("in") == "body":
                schema = prm.get("schema")
                break
    if schema is None:
        return None
    body = _example(schema, spec)
    if not isinstance(body, dict) or not body:
        return None
    fields = _field_paths(body)
    if not fields:
        return None
    return {"method": method.upper(), "url": url, "content_type": "application/json",
            "body": body, "fields": fields}


def ingest_openapi(base_url, send, scope, log, extra_bases=()):
    """Return (urls, post_methods, body_ops, note) from the first reachable
    OpenAPI/Swagger doc. body_ops carry synthesised JSON bodies for fuzzing.

    Probes the target AND any ``extra_bases`` (e.g. the SPA's backend API host,
    where the spec usually lives), so a public /v3/api-docs on a sibling host is
    ingested too — that single doc is often the whole attack surface."""
    bases, seen_b = [], set()
    for b in [base_url] + list(extra_bases or ()):
        b = b if b.endswith("/") else b + "/"
        if b not in seen_b:
            seen_b.add(b); bases.append(b)
    for root, p in [(b, p) for b in bases for p in _OPENAPI_PATHS]:
        u = urljoin(root, p)
        if not _in(u, scope):
            continue
        r = send("GET", u)
        if not _ok200(r):
            continue
        spec = _load_spec(r["text"])
        if not spec or not isinstance(spec.get("paths"), dict):
            continue
        sbase = _spec_base(spec, root)
        urls, post_methods, body_ops = set(), [], []
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
                    bop = _body_op(spec, meth, full, op)
                    if bop:
                        body_ops.append(bop)
            urls.add(full + ("?" + urlencode(qp) if qp else ""))
        if urls:
            extra = f", {len(body_ops)} with JSON body" if body_ops else ""
            log("hit", "discover",
                f"OpenAPI/Swagger at /{p}: +{len(urls)} documented route(s){extra}")
            return urls, post_methods, body_ops, ("openapi", u, f"{len(urls)} documented route(s)")
    return set(), [], [], None


# --------------------------------------------------------------- Postman
_VAR_RE = re.compile(r"\{\{([^}]+)\}\}")
_BASE_VARS = re.compile(
    r"(?i)^(base[_-]?url|api[_-]?url|url|host|hostname|server|endpoint|gateway|origin)$")


def _subst_vars(s, variables):
    """Replace {{var}} tokens from a Postman variable map; leave unknown ones."""
    if not isinstance(s, str):
        return s
    return _VAR_RE.sub(lambda m: str(variables.get(m.group(1).strip(), m.group(0))), s)


def _collect_vars(coll):
    """Collection-level + environment variables -> {name: value}."""
    out = {}
    for v in (coll.get("variable") or []):
        if isinstance(v, dict) and v.get("key"):
            out[v["key"]] = v.get("value", "")
    return out


def _pm_url(url, variables, base_url):
    """Resolve a Postman request URL (string or object) to an absolute URL."""
    if isinstance(url, dict):
        raw = url.get("raw")
        if not raw:
            host = url.get("host")
            host = ".".join(host) if isinstance(host, list) else (host or "")
            path = url.get("path")
            path = "/".join(str(p) for p in path) if isinstance(path, list) else (path or "")
            raw = f"{host}/{path}"
    else:
        raw = url
    raw = _subst_vars(raw or "", variables)
    if not raw:
        return ""
    # A leading base-URL variable (e.g. {{baseUrl}}/users) that no collection
    # variable resolved — the environment file that held it wasn't provided, so
    # fall back to the target URL the user passed.
    if raw.startswith("{{"):
        raw = _VAR_RE.sub("", raw, count=1).lstrip("/")
    if "{{" in raw:                    # unresolved variable mid-URL — can't test safely
        return ""
    if not raw.startswith("http"):
        base = base_url if base_url.endswith("/") else base_url + "/"
        raw = urljoin(base, raw.lstrip("/"))
    return raw.split("#")[0] if raw.startswith("http") else ""


def _pm_body_op(method, url, body, variables):
    """A JSON request body -> a body_op for the JSON fuzzer (string fields only)."""
    if not isinstance(body, dict) or body.get("mode") != "raw":
        return None
    raw = _subst_vars(body.get("raw") or "", variables)
    try:
        doc = json.loads(raw)
    except Exception:
        return None
    if not isinstance(doc, dict) or not doc:
        return None
    fields = _field_paths(doc)
    if not fields:
        return None
    return {"method": method.upper(), "url": url, "content_type": "application/json",
            "body": doc, "fields": fields}


def _pm_abs(url, variables):
    """Resolve a Postman URL to an ABSOLUTE http(s) URL using only the collection's
    own variables (no target fallback). Returns '' when the host can't be known."""
    if isinstance(url, dict):
        raw = url.get("raw")
        if not raw:
            host = url.get("host")
            host = ".".join(host) if isinstance(host, list) else (host or "")
            path = url.get("path")
            path = "/".join(str(p) for p in path) if isinstance(path, list) else (path or "")
            raw = f"{host}/{path}"
    else:
        raw = url
    raw = _subst_vars(raw or "", variables)
    if "{{" in raw or not raw.startswith("http"):
        return ""
    return raw.split("#")[0]


def _one_auth(auth, variables):
    """A Postman auth block -> a request header string ('Name: value'), or ''."""
    if not isinstance(auth, dict):
        return ""
    t = (auth.get("type") or "").lower()

    def val(listname, field):
        for x in auth.get(listname) or []:
            if isinstance(x, dict) and x.get("key") == field:
                return _subst_vars(str(x.get("value", "")), variables)
        return ""

    if t == "bearer":
        tok = val("bearer", "token")
        if tok and "{{" not in tok:
            return f"Authorization: Bearer {tok}"
    elif t == "apikey":
        name = val("apikey", "key") or "X-API-Key"
        v = val("apikey", "value")
        where = (val("apikey", "in") or "header").lower()
        if v and "{{" not in v and where == "header":
            return f"{name}: {v}"
    elif t == "basic":
        import base64
        u, p = val("basic", "username"), val("basic", "password")
        if u and "{{" not in u and "{{" not in p:
            tok = base64.b64encode(f"{u}:{p}".encode()).decode()
            return f"Authorization: Basic {tok}"
    return ""


def _pm_auth_header(coll, variables):
    """Find an auth token in the collection: collection-level auth first, then the
    first request-level auth block or Authorization header. Returns '' if none."""
    h = _one_auth(coll.get("auth"), variables)
    if h:
        return h
    found = [""]

    def walk(items):
        for it in items or []:
            if found[0] or not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            h = _one_auth(req.get("auth"), variables)
            if h:
                found[0] = h
                return
            for hd in req.get("header") or []:
                if isinstance(hd, dict) and (hd.get("key", "").lower() == "authorization"):
                    v = _subst_vars(str(hd.get("value", "")), variables)
                    if v and "{{" not in v:
                        found[0] = v if v.lower().startswith("authorization") else f"Authorization: {v}"
                        return

    walk(coll.get("item"))
    return found[0]


def postman_profile(path):
    """Derive what's needed to scan a Postman collection on its own:
    {base_url, hosts, auth_header, resolved, error}. `resolved` is False when the
    collection references its host only through an undefined variable — then the
    caller must ask the user for the target URL."""
    try:
        with open(path) as f:
            coll = json.load(f)
    except Exception as e:
        return {"base_url": "", "hosts": [], "auth_header": "", "resolved": False,
                "error": str(e)}
    variables = _collect_vars(coll)
    base = ""
    for name, v in variables.items():
        if _BASE_VARS.match(name or "") and str(v).startswith("http"):
            base = str(v).rstrip("/") + "/"
            break
    hosts, first = set(), [None]

    def walk(items):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            a = _pm_abs(req.get("url"), variables)
            if a:
                hosts.add(urlparse(a).netloc)
                if first[0] is None:
                    first[0] = a

    walk(coll.get("item"))
    if not base and first[0]:
        pu = urlparse(first[0])
        base = f"{pu.scheme}://{pu.netloc}/"
    if base:
        hosts.add(urlparse(base).netloc)
    return {"base_url": base, "hosts": sorted(h for h in hosts if h),
            "auth_header": _pm_auth_header(coll, variables),
            "resolved": bool(base), "error": ""}


def ingest_postman(path, base_url, scope, log):
    """Parse a Postman v2.x collection file into (urls, post_methods, body_ops).
    Clients often hand over a Postman export instead of an OpenAPI spec; this
    turns it into the same testable surface. Scope-checked; JSON request bodies
    feed the JSON-body fuzzer."""
    try:
        with open(path) as f:
            coll = json.load(f)
    except Exception as e:
        log("warn", "discover", f"postman: cannot read {path}: {e}")
        return set(), [], []
    variables = _collect_vars(coll)
    urls, post_methods, body_ops = set(), [], []

    def walk(items):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):      # folder -> recurse
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = (req.get("method") or "GET").upper()
            full = _pm_url(req.get("url"), variables, base_url)
            if not full or not _in(full, scope):
                continue
            urls.add(full)
            if method != "GET":
                post_methods.append((method, full))
                bop = _pm_body_op(method, full, req.get("body"), variables)
                if bop:
                    body_ops.append(bop)

    walk(coll.get("item"))
    if urls:
        extra = f", {len(body_ops)} with JSON body" if body_ops else ""
        log("hit", "discover",
            f"Postman collection: +{len(urls)} request(s){extra}")
    return urls, post_methods, body_ops


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
    """Discover hidden parameters on the parameter-less endpoints via arjun.
    Returns (urls, body_ops):
      - urls     : synthesised ?p=1 GET URLs for the query-param injection tiers
      - body_ops : JSON-body operations (POST) for the JSON-body fuzzer, from
                   params the server only accepts in a request body — surface
                   that GET mining never reveals."""
    if not (PARAM_MINING and shutil.which("arjun")):
        return set(), []
    cand = [u for u in endpoints if not urlparse(u).query][:_MINE_MAX]
    found, body_ops = set(), []
    for u in cand:
        if not _in(u, scope):
            continue
        names = _run_arjun(u, "GET")
        if names:
            synth = u + ("&" if urlparse(u).query else "?") + urlencode({p: "1" for p in names})
            found.add(synth)
            log("hit", "discover",
                f"arjun GET: {u} -> hidden param(s): {', '.join(names[:8])}"
                + (" …" if len(names) > 8 else ""))
        if MINE_POST:
            jnames = _run_arjun(u, "JSON")
            # only net-new params (a param found for GET is already covered)
            jnames = [p for p in jnames if p not in (names or [])]
            if jnames:
                body = {p: "1" for p in jnames}
                body_ops.append({"method": "POST", "url": u,
                                 "content_type": "application/json",
                                 "body": body, "fields": _field_paths(body)})
                log("hit", "discover",
                    f"arjun JSON-body: {u} -> hidden field(s): {', '.join(jnames[:8])}"
                    + (" …" if len(jnames) > 8 else ""))
    if found or body_ops:
        log("info", "discover",
            f"param mining: +{len(found)} query endpoint(s), +{len(body_ops)} JSON-body op(s)")
    return found, body_ops


# --------------------------------------------------------------- orchestration
def expand_surface(base_url, send, scope, endpoints, log, param_mining=True):
    """Run all deep-discovery sources.
    Returns (new_urls, post_methods, body_ops, notes)."""
    new_urls, post_methods, body_ops, notes = set(), [], [], []

    try:
        new_urls |= ingest_sitemaps(base_url, send, scope, log)
    except Exception as e:
        log("warn", "discover", f"sitemap ingest error: {e}")

    # Backend API hosts that discovery already pulled into the endpoint list
    # (e.g. the SPA's api.* host) — probe them for an OpenAPI/Swagger doc too.
    base_netloc = urlparse(base_url).netloc
    extra_bases = []
    for u in endpoints:
        pu = urlparse(u)
        if pu.scheme in ("http", "https") and pu.netloc and pu.netloc != base_netloc:
            origin = f"{pu.scheme}://{pu.netloc}/"
            if origin not in extra_bases and _in(origin, scope):
                extra_bases.append(origin)

    if API_INGEST:
        try:
            u, pm, bops, note = ingest_openapi(base_url, send, scope, log, extra_bases=extra_bases)
            new_urls |= u
            post_methods += pm
            body_ops += bops
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

        pm_path = os.environ.get("VAPT_POSTMAN", "")
        if pm_path and os.path.isfile(pm_path):
            try:
                u, pm, bops = ingest_postman(pm_path, base_url, scope, log)
                new_urls |= u
                post_methods += pm
                body_ops += bops
            except Exception as e:
                log("warn", "discover", f"postman ingest error: {e}")

    if param_mining:
        try:
            # mine the richer set: original endpoints + newly discovered pages
            mine_set = list(dict.fromkeys(list(endpoints) + list(new_urls)))
            mined_urls, mined_bops = mine_params(mine_set, scope, log)
            new_urls |= mined_urls
            body_ops += mined_bops
        except Exception as e:
            log("warn", "discover", f"param mining error: {e}")

    return new_urls, post_methods, body_ops, notes
