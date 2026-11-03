# vaptbench test catalog & coverage board

The definitive map of **what vaptbench tests**, the **engine** that tests it, how it's
**confirmed** (deterministic, zero-false-positive), and **status**. We work this board
top-down instead of ad-hoc. `🟢` shipped · `🟡` partial · `🔴` not yet · `⚪` n/a.

## Engines (detection mechanisms)
| Engine | Module | Surface | Confirms via |
|---|---|---|---|
| E1 Passive | `verifiers.py` | base response | header/cookie/file signatures |
| E2 Query-param injection | `verifiers.py`,`verifiers2.py` | `?p=` | error / timing / computed marker / command output |
| E3 POST-form injection | `verifiers_post.py` | form fields | same oracles |
| E4 JSON-body fuzz | `verifiers_json.py` | API bodies (nested/array) | same oracles |
| E5 Path-segment injection | `verifiers_path.py` | `/users/123` | error / reflection |
| E6 Bypass/variation | `bypass.py` | all param surfaces | which WAF-evasion payload trips the signal |
| E7 OOB collaborator | `blueprints/oob.py` | blind classes | real callback / in-band marker reflection |
| E8 Authorization | `authz.py` | cross-role replay | same protected body / owner-mismatch / seed-ref |
| E9 File-upload | `upload.py` | multipart | stored file executes |
| E10 CVE | `jslibs.py` + nuclei | JS libs, templates | version<fixed / template match |
| E11 Exploitation | `exploit.py` | confirmed sqli/cmd/lfi | read-only data extraction |
| E12 Network | `net_verifiers.py` | open services | protocol-level proof |
| E13 Chain correlation | `_chain_phase` | confirmed findings | rule match |

## Vulnerability coverage
| Vulnerability | Engine | Status | Note |
|---|---|---|---|
| SQLi (error / blind-time) | E2,E3,E4,E5,E6 | 🟢 | |
| NoSQL injection | E2 | 🟢 | |
| OS command execution/injection | E2,E3,E6 | 🟢 | **output oracle** (direct-exec + separator breakout) |
| SSTI | E2,E4,E6 | 🟢 | |
| LFI / path traversal | E2,E6 | 🟢 | passwd/hosts/environ/win.ini/php-filter signatures |
| Reflected / Stored / DOM XSS | E2,E3,E4,E5,E6 | 🟢 | DOM = needs-review |
| SSRF | E7,E6 | 🟢 | OOB callback **or** in-band marker reflection |
| Open redirect | E2 | 🟢 | |
| CORS / headers / cookies / methods / exposed files | E1 | 🟢 | |
| IDOR/BOLA · privesc/BFLA · missing-auth · authn-bypass | E8 | 🟢 | + single-account + **unauth seed-ref BOLA** |
| Mass assignment / auto-binding | E4 | 🟢 | privileged field accepted & echoed |
| Host-header injection | E1 | 🟢 | unique marker reflected in body/Location |
| CSRF (missing token) | `verifiers_csrf.py` | 🟡 | needs-review (no browser to prove cross-site) |
| Session-token weakness | `verifiers_csrf.py` | 🟡 | needs-review (short/low-entropy id) |
| JWT weak-secret | E2 | 🟡 | secret only (no alg-confusion/kid/jku) |
| Vulnerable components (JS libs, nuclei CVEs) | E10 | 🟢 | curated JS table + nuclei templates |
| File-upload RCE | E9 | 🟢 | |
| GraphQL introspection | discovery | 🟢 | no field-authz/batching |
| TLS / network services / default DB creds | E12 | 🟢 | |
| XXE | `verifiers_xxe.py` | 🟢 | file read / OOB / in-band marker |
| CRLF / response splitting | `verifiers_crlf.py` | 🟢 | injected header surfaces in response |
| Web cache poisoning | `verifiers_cache.py` | 🟢 | unkeyed input reflected + cacheable |
| Insecure deserialization | `verifiers_deser.py` | 🟡 | needs-review (error sig; RCE not auto-exploited) |
| OAuth / OIDC redirect_uri | `verifiers_oauth.py` | 🟢 | redirects to attacker origin |
| Login rate-limit / lockout | `verifiers_authn.py` | 🟡 | needs-review (bogus-user probe) |

## Backlog (worked in sprints)
**Sprint 1 — recall gaps (DONE):** cmd-exec output oracle ✅ · LFI content canary ✅ · in-band SSRF ✅ · unauth seed-ref BOLA ✅

**Sprint 2 — high-frequency classes (DONE):** CSRF ✅ (needs-review) · mass-assignment ✅ · host-header injection ✅ · session-token weakness ✅ (fixation/rotation still 🔴)

**Sprint 3 — deeper classes (DONE):** XXE ✅ · CRLF/response-splitting ✅ · brute-force/lockout ✅ (needs-review) · auto-signup provisioning 🔴

**Sprint 4 — advanced (mostly DONE):** insecure deserialization ✅ (needs-review) · OAuth redirect_uri ✅ · cache poisoning ✅ · race conditions 🔴 (manual — unsafe to auto-probe state changes) · SAML flow 🔴

**Surface still thin:** nested/array **query** params (`filter[role]=`) 🔴 · headers & cookies as injection points 🔴 · JWT alg-confusion/kid/jku 🔴 · auto-signup provisioning 🔴

Every backlog item ships with a concrete deterministic oracle — the zero-false-positive
standard is non-negotiable (a finding is `confirmed` only when provably true).
