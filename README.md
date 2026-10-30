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
python app.py          # http://127.0.0.1:8090
```

## AI brain (local-first, hybrid-ready)
```bash
# local (default) — on the Windows host, reachable from WSL:
#   ollama pull qwen2.5-coder:14b
export VAPT_OLLAMA_URL=http://localhost:11434
export VAPT_OLLAMA_MODEL=qwen2.5-coder:14b

# hybrid — route a task to the cloud when you choose:
export VAPT_AI_BACKEND=cloud
export VAPT_CLOUD_KEY=sk-ant-...
export VAPT_CLOUD_MODEL=claude-opus-4-8
```

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

## Autonomous engine (Start VAPT)
Click **Start VAPT** on a target and the engine runs the whole web VAPT in the
background — authenticate every role → recon/map → test & verify → access
control → findings — with a **live feed** you watch (`/run/<id>`). Phase 1 is
fully deterministic (works even with the AI offline); correctness comes from
`verifiers.py`, which only emits a finding when it can *prove* it.

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
