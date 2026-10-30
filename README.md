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

## Automated login
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

## Status
v0.2. Working: engagements/targets, multi-role store, scope guard, **automated
login (bearer/basic/cookie/form)**, **recon runners (7 tools)**, repeater,
access-matrix, playbook loader, AI-suggest, findings + report export.
Next: per-playbook checklist UI with progress, PoC screenshots, background
long-running recon, then network/AD/API/red-team modules.

## Authorization
Only run against targets you are authorized to test. Each engagement records an
authorization note; the scope guard blocks anything outside the defined scope.
