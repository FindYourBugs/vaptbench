# VAPTBench

A web-application **pentest workbench** — not just a scanner. It follows the
manual VAPT methodology: recon, multi-role auth, manual testing driven by your
`hunt-*` skill playbooks, hands-on exploitation via a repeater + access-control
matrix, PoC capture, and report export.

## Why it's not a scanner
- **Multi-role identities** per target — log in as each role, then replay one
  role's request under another role's session. That's the core IDOR /
  privilege-escalation test.
- **Repeater** — craft and send requests by hand; you pull the trigger.
- **Access-control matrix** — one captured request replayed across every role,
  side by side, to spot authz flaws.
- **Playbooks** — your `hunt-*` skills loaded read-only as methodology.
- **AI assist** — local model (Ollama) suggests the next *manual* step; it never
  acts for you.
- **Scope guard** — deny-wins, default-deny; every outbound request is checked.

## Run
```bash
pip install -r requirements.txt
python app.py          # web UI  -> http://127.0.0.1:8090
```

### CLI (headless, no browser)
Drive the same autonomous engine from the terminal. Launches with a banner +
console header; run it with **no target** for an interactive setup that prompts
for the URL, scope, and login roles (password masked):
```bash
python vapt.py                        # interactive: prompts target/scope/roles
python vapt.py https://shop.example.com/
python vapt.py https://shop.example.com/ \
    --role userA:alice@example.com:Passw0rd \
    --login-url https://shop.example.com/login \
    --report report.md
python vapt.py https://target/ --no-agent        # deterministic only
```
It streams the live feed, prints a findings summary, and (with `--report`) writes
a report. `--role ROLE:USER:PASS` repeatable; `--auth auto|form|bearer|cookie|
basic`; `--scope RULE` repeatable (defaults to the target host). Uses a throwaway
temp DB unless you pass `--db`.

### Reports (format by extension)
```bash
python vapt.py https://target/ --report out.pdf \
    --company "SysTools Group" --tester "Shrikant Shinde" --logo logo.png
```
- **`.pdf`** — branded, client-ready report (cover, exec summary with severity
  donut + category bar, CVSS/CWE/OWASP mapping per finding, PoC evidence,
  remediation, analyst review, sign-off). Rendered via headless Chromium
  (Playwright); falls back to `.html` with a message if Chromium is unavailable.
- **`.html`** — same report, no browser needed.
- **`.md`** — the plain Markdown report.

Branding flags: `--company`, `--tester`, `--client`, `--logo`.

## Network / infrastructure VAPT (by IP or CIDR)
Give it an IP or range and it runs a full network assessment — not just a port
scan:
```bash
python vapt.py 10.0.0.5 --mode network --report infra.pdf
python vapt.py 192.168.1.0/24 --mode network        # whole subnet (live-host discovery first)
python vapt.py 10.0.0.5 --mode network --ports all  # full 1-65535 on one host
python vapt.py 10.0.0.5                              # IP auto-detected -> network mode
```
Phases: **discovery + service/version scan** (nmap, with a built-in connect-scan
fallback) → **per-service verification** (proof-only) → **nuclei** network/ssl
templates → AI write-up + critic → the same branded report.

Service verifiers (each emits a finding only when **proven**, never on mere
detection). **Wave 1** — weak TLS protocols / expired / self-signed certs,
anonymous FTP, Telnet (cleartext), SMTP open-relay & VRFY user-enum, DNS version
disclosure, SMB null-session share enumeration, SNMP default community, and
unauthenticated Redis / MongoDB / Memcached / Elasticsearch. **Wave 2** — weak
SSH algorithms (KEXINIT parse: SHA-1 KEX, ssh-rsa/dss host keys, CBC ciphers,
SHA-1/MD5 MACs), **MySQL / PostgreSQL / MSSQL default-credential login** (proven
with a read-only `SELECT version()`), LDAP anonymous bind, NFS export
enumeration, VNC with no authentication, and **RDP not enforcing NLA**
(standard-RDP / TLS-only, BlueKeep-class pre-auth surface).

Missing tools degrade gracefully. Scope accepts IP/CIDR rules (deny-wins,
default-deny) — authorised targets only. `VAPT_NET_PORTS` sets the nmap top-ports
count; `VAPT_NUCLEI=0` disables nuclei (info-level nuclei *detection* templates
are logged to the live feed but kept out of the report so real findings aren't
buried). `VAPT_NET_CREDS=0` disables all default-credential login attempts
(algorithm/version checks still run).

## AI brain (local-first, hybrid-ready)
```bash
# local (default) — on the Windows host, reachable from WSL:
#   ollama pull qwen3:14b
export VAPT_OLLAMA_URL=http://localhost:11434
export VAPT_OLLAMA_MODEL=qwen3:14b          # base model (used for any unset role)

# hybrid — route a task to the cloud when you choose:
export VAPT_AI_BACKEND=cloud
export VAPT_CLOUD_KEY=sk-ant-...
export VAPT_CLOUD_MODEL=claude-opus-4-8
```

### Per-job models (any Ollama model works by name)
Different jobs want different brains. Each falls back to `VAPT_OLLAMA_MODEL`:
```bash
ollama pull deepseek-r1:14b        # strong reasoner
ollama pull whiterabbitneo         # offensive-security tuned
export VAPT_MODEL_REASONER=deepseek-r1:14b   # planning + critic (judgment)
export VAPT_MODEL_PAYLOAD=whiterabbitneo     # payload crafting
export VAPT_MODEL_WRITER=qwen3:14b           # report prose
```

### Exploitation depth (read-only proof)
After a verifier **confirms** a SQLi / command-injection / LFI, vaptbench safely
extracts proof for the report — turning "the vuln exists" into "here is the data":
- **SQLi** → DB engine, version, current user, current database (error-based,
  auto-detects MySQL/Postgres/MSSQL)
- **command injection** → output of read-only commands (`id`, `whoami`,
  `hostname`, `uname -a`)
- **LFI** → contents of standard system files (`/etc/passwd`, `/etc/hosts`)

Read-only and non-destructive — no writes, deletes, or dumping of arbitrary user
tables; only enough to make the finding undeniable. Authorised targets only.
Toggle with `VAPT_EXPLOIT=0`.

### Critic pass (skeptical second opinion)
After findings are gathered, a reasoning model reviews each one — real impact,
false-positive risk, a better exploitation path, whether remediation is truly
needed — and attaches an **Analyst review** to the finding, flagging likely
false positives for human check. It is **advisory**: it never overturns
deterministic proof and never invents a bug. Toggle with `VAPT_CRITIC=0`.

## Skills location
Defaults to `~/.claude/skills`. Override with `VAPT_SKILLS_DIR`.

## Autonomous login (client-grade)
Pick **username + password** (auth_type `auto`): a headless Chromium logs in
for you, including on **JavaScript / SPA apps** where there's no server-side
form — it renders the page, finds the fields, submits, and captures the
cookies + bearer token. Just set the login page URL + creds. Installed by
`scripts/setup_kali.sh` (Playwright + Chromium). Falls back to the methods
below if the browser isn't available.

## Automated login (other methods)
Per identity, `login`/`Log in as all roles` captures the session into the
identity so the Repeater and matrix replay as that role:
- **bearer** — `secret` = token → `Authorization: Bearer ...`
- **basic** — username/secret → `Authorization: Basic ...`
- **cookie** — `secret` = `"k1=v1; k2=v2"`
- **form** — set `login_url` + `login_config` JSON:
  `{"username_field","password_field","csrf_field","extra","success_contains","failure_contains"}`
  (primes the page for cookies+CSRF, posts creds, confirms via marker/cookie)

## Recon runners
Scope-checked external tools, output captured; crawl/history tools auto-import
discovered URLs as captured requests for the matrix: `httpx`, `whatweb`,
`katana`, `gau`, `waybackurls`, `ffuf` (set `VAPT_WORDLIST`), `nuclei`.
Missing binaries are reported cleanly, not fatal.

## SPA API discovery (the real attack surface on JS apps)
A React/Vue/Angular/Next app ships a tiny HTML shell and does everything over
XHR/fetch to a backend API — so the server HTML has no `?param=` links and the
classic crawl finds nothing to test. The engine now surfaces the backend API two
ways before testing (Phase 2 recon):
- **Runtime capture** — a headless Chromium (authenticated with the role's
  captured session) loads the app, lets it make its real network calls, clicks
  through in-app links, and records every in-scope **XHR/fetch** endpoint. This
  is ground truth: endpoints the app actually uses.
- **Static bundle harvest** (browserless fallback) — fetches the HTML shell + JS
  bundles and greps out API hosts, `/api/vN/` base paths, and resource-word
  route literals (minifiers store routes as string segments), reconstructing
  candidate URLs. Mirrors the `hunt-spa-api` play.

Discovered API routes are **prioritised** ahead of static page URLs, persisted as
captured requests (Repeater / access-control matrix can replay them), and fed to
the agent + injection + authz matrix — which is exactly where broken-access /
missing-auth on an API route group shows up. Toggle with `VAPT_SPA_CRAWL=0`.
Runtime capture needs Playwright (installed by `scripts/setup_kali.sh`); without
it the static harvest still runs.

## Deep discovery (reach the whole attack surface)
Beyond the in-page crawl + SPA API capture, the engine runs three more
discovery sources before testing so pages, parameters and API routes aren't
missed (Phase 2b, `discovery.py`):
- **Sitemap / robots ingestion** — parses `robots.txt` (Allow/Disallow/Sitemap)
  and `sitemap.xml` (incl. nested sitemap indexes) for pages nothing linked to.
- **OpenAPI / Swagger ingestion** — fetches the common spec locations
  (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …), resolves the server
  base, and expands **every documented route** into a concrete, testable URL
  (path params filled, query params attached). Non-GET operations are captured
  for the matrix. A publicly reachable spec is also recorded as a finding.
- **GraphQL introspection** — probes the common GraphQL paths; if introspection
  answers, the endpoint enters the test surface (and the deterministic
  introspection verifier flags it).
- **Hidden-parameter mining** — runs **arjun** on parameter-less endpoints to
  find params that exist server-side but appear in no form or link, then
  synthesises `?p=1` URLs for the injection tiers.

Toggle with `VAPT_DEEP_DISCOVERY=0` (whole phase), `VAPT_API_INGEST=0`
(OpenAPI/GraphQL), `VAPT_PARAM_MINING=0` (arjun). `VAPT_MAX_ENDPOINTS` caps the
merged surface (default 60); `VAPT_PARAM_MINE_MAX` caps how many endpoints arjun
runs on (default 6).

## Control-bypass / payload-variation engine
A single baseline payload misses anything behind partial sanitisation or a WAF.
After the baseline tiers, a **variation pass** (`bypass.py`, Phase 3e) rotates a
matrix of filter-bypass payloads per parameter and confirms a hit **only via a
deterministic signal** — proving the control is *bypassable*, not merely that
input is reflected. It records **which variation** defeated the control. It only
tries `(class, parameter)` pairs the baseline verifiers did **not** already
confirm, so it adds net-new proof without duplicating findings.

Classes & signals:
- **SQLi** — quote/paren/comment + inline-comment/newline WAF bypasses; signal =
  a new SQL error the payload provoked.
- **XSS** — self-contained element injections (`<svg>`, `<img onerror>`,
  `<body onload>`, `<details ontoggle>`, mixed-case, `<iframe>`, `<marquee>`,
  `<video><source>`); signal = the executable construct survives **unencoded**
  (context-independent, so no false positives from reflected-but-inert text).
- **OS command injection** — output signature (`id`) + bypass-style timing
  (`${IFS}`, brace expansion, quoted break-out, newline); signal = `uid=…` output
  or a reproducible, double-checked delay.
- **SSTI** — multi-engine arithmetic (Jinja2/Twig, ERB, Freemarker/Mako, Smarty,
  Velocity, Razor, Thymeleaf); signal = the computed product next to our marker,
  without the literal expression.
- **LFI / path traversal** — traversal depths, `....//`, URL/double-URL encoding,
  `php://filter` (base64), `/proc/self/environ`, `file://`, `.env`, Windows;
  signal = a file signature (`root:…:0:0`, `win.ini`, base64 passwd, `.env`).
- **SSRF** — scheme/parser bypasses (gopher, dict, `//`, `@`-trick, uppercase
  scheme, trailing-dot host); signal = a real OOB callback.

Toggle with `VAPT_BYPASS=0`; `VAPT_BYPASS_TIMING=0` drops the slow cmd-timing
variants; `VAPT_BYPASS_MAX` caps endpoints (default 10).

## Autonomous engine (Start VAPT)
Click **Start VAPT** on a target and the engine runs the whole web VAPT in the
background — authenticate every role → recon/map → test & verify → access
control → findings — with a **live feed** you watch (`/run/<id>`). The test
tiers are fully deterministic (work even with the AI offline); correctness comes
from `verifiers.py`, which only emits a finding when it can *prove* it.

### Agent mode (the autonomous brain)
When the local model is up, an **agentic planner** (`agent.py`) drives the run:
the model observes the mapped surface + findings so far and chooses the next
**action** from a fixed, safe set (`probe`, `crawl`, `test`, `inject`,
`advanced`, `access_control`, `finish`). Every decision streams to the live feed
so you watch it reason. Crucially, **the model never asserts a bug** — it only
decides *where* to look; the deterministic verifiers decide *what is real*. So
you get PentestGPT-agent-style autonomy with no hallucinated findings. If the
model is offline or uncooperative the engine falls back to the fixed
deterministic sweep automatically. Toggle with `VAPT_AGENT=0`; step budget via
`VAPT_AGENT_STEPS` (default 24).

**Tier-1 classes verified now:** missing security headers, cookie flags,
clickjacking, CORS misconfig, dangerous HTTP methods, open redirect, reflected
XSS (unencoded breakout), error-based SQLi, exposed sensitive files. Plus a
cross-role **access-control matrix** flagging possible broken access / IDOR as
needs-review. Every finding is `confirmed` (passed a verifier) or `needs-review`
(flagged, not proven) — never a blind AI guess.

**Tier-2 classes verified now (Phase 2):** blind/time-based SQLi (measured,
double-checked delay), OS command injection (timing), SSTI (computed arithmetic
reflected), LFI/path traversal (/etc/passwd + win.ini signature), NoSQLi (engine
error), GraphQL introspection, and JWT weak-secret (HS256 cracked locally).

**AI layer:** when the model is online it (a) suggests extra payloads — which
only count if they still trip a deterministic signal — and (b) writes up each
confirmed finding, grounded in the matching `hunt-*` skill. The AI never
confirms a bug on its own.

**Tier-3 / advanced (Phase 3):** SSRF proven via a built-in **OOB collaborator**
(the target actually calls back to `/oob/<token>` — set `VAPT_OOB_HOST` to an
address the target can reach), **stored XSS** proven two-step (payload surfaces
unencoded on a *different* page), DOM-XSS candidates (source→sink, needs-review),
and **attack-chain correlation** that ties confirmed findings into realistic
escalation paths (SSRF→metadata, forged-JWT→ATO, injection→RCE, XSS→session
theft), narrated by the AI when online.

Next: the network / AD / API / red-team modules.

## OOB listener
Built in. The target's callbacks hit `/oob/<token>` on this app. For internet
targets, set `VAPT_OOB_HOST` to a public host that forwards here; for local labs
the default `127.0.0.1:8090` works.

## Status
v0.5. Working: engagements/targets, multi-role store, scope guard, automated
login, recon runners, **autonomous engine + Start VAPT + live run feed**,
Tier-1 verifiers, access-control matrix, repeater, playbook loader, AI-suggest,
findings + report export.

## Authorization
Only run against targets you are authorized to test. Each engagement records an
authorization note; the scope guard blocks anything outside the defined scope.
