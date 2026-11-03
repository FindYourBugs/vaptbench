"""Authentication hardening — login rate-limiting / account-lockout.

Sends several failed logins for a NON-EXISTENT user (never the real supplied
account, so a legitimate user is not locked out) and checks whether the endpoint
throttles. Reported as needs-review: absence of a 429 / lockout / CAPTCHA within
the probe window is a strong signal, not a proof the policy is wholly missing.
"""
import uuid
from urllib.parse import urlencode

from . import forms as forms_mod

_ATTEMPTS = 6
_THROTTLE = ("too many", "rate limit", "locked", "lockout", "captcha", "slow down",
             "try again later", "temporarily disabled", "retry-after")


def _login_fields(send, login_url):
    """Return (pw_field, user_field, extra_defaults) from the login form, or None."""
    r = send("GET", login_url)
    if not r.get("ok"):
        return None
    for f in forms_mod.extract_forms(r.get("text") or "", login_url):
        inputs = f.get("inputs") or {}
        pw = next((k for k in inputs if "pass" in k.lower()), None)
        if not pw:
            continue
        user = next((k for k in inputs
                     if any(t in k.lower() for t in ("user", "email", "login", "name"))), None)
        extra = {k: v for k, v in inputs.items() if k not in (pw, user)}
        return pw, user, extra
    return None


def check_login_rate_limit(send, login_url):
    fields = _login_fields(send, login_url)
    if not fields:
        return []
    pw, user, extra = fields
    bogus = f"vaptprobe_{uuid.uuid4().hex[:8]}@example.invalid"
    statuses = []
    for i in range(_ATTEMPTS):
        body = dict(extra)
        if user:
            body[user] = bogus
        body[pw] = f"WrongPass_{i}_{uuid.uuid4().hex[:6]}"
        r = send("POST", login_url,
                 headers="Content-Type: application/x-www-form-urlencoded",
                 body=urlencode(body))
        if not r.get("ok"):
            return []
        st = r.get("status")
        low = (r.get("text") or "").lower()
        if st == 429 or any(t in low for t in _THROTTLE) or (r.get("headers") or {}).get("Retry-After"):
            return []                              # throttling observed -> protected
        statuses.append(st)
    return [dict(
        title="No rate limiting / account lockout on login",
        vuln_class="hunt-brute-force", severity="medium", confidence="needs-review",
        cvss="",
        description=f"{_ATTEMPTS} consecutive failed logins to {login_url} were all accepted "
                    f"(statuses {statuses}) with no 429, Retry-After, lockout or CAPTCHA — the "
                    f"endpoint does not throttle authentication, enabling credential brute-force / "
                    f"password spraying. (Probed with a non-existent account to avoid locking a real "
                    f"user; confirm the policy manually.)",
        steps=f"POST {_ATTEMPTS} bad-password logins to {login_url}; none are throttled.",
        poc_request=f"POST {login_url} x{_ATTEMPTS} (bad credentials)",
        poc_response=f"statuses: {statuses}")]
