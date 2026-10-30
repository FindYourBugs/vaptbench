"""Skill loader — treats your hunt-* skills as read-only playbooks.

The tool reads each skill's SKILL.md (frontmatter + body) and exposes it as a
playbook the workbench can walk you through and the AI can read for context.
It never writes to the skills. Point VAPT_SKILLS_DIR at your skills folder;
defaults to ~/.claude/skills.
"""
import os
import re
import glob

# Web-application-relevant skills, shown first in the web workbench.
WEB_SKILLS = {
    "hunt-idor", "hunt-xss", "hunt-sqli", "hunt-ssrf", "hunt-auth-bypass",
    "hunt-csrf", "hunt-cors", "hunt-oauth", "hunt-saml", "hunt-jwt-crypto",
    "hunt-session", "hunt-file-upload", "hunt-ssti", "hunt-lfi", "hunt-rce",
    "hunt-xxe", "hunt-open-redirect", "hunt-host-header", "hunt-race-condition",
    "hunt-business-logic", "hunt-graphql", "hunt-nosqli", "hunt-deserialization",
    "hunt-cache-poison", "hunt-http-smuggling", "hunt-dom", "hunt-mfa-bypass",
    "hunt-forgot-password", "hunt-clickjacking", "hunt-html-injection",
    "hunt-websocket", "hunt-source-leak", "hunt-api-misconfig", "hunt-spa-api",
    "hunt-shadow-api", "hunt-llm-ai",
}


def skills_dir():
    return os.environ.get(
        "VAPT_SKILLS_DIR", os.path.expanduser("~/.claude/skills")
    )


def _read_frontmatter(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None, ""
    name = os.path.basename(os.path.dirname(path))
    desc = ""
    m = re.search(r"^---\s*(.*?)\s*---", text, re.DOTALL)
    if m:
        fm = m.group(1)
        dn = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
        dd = re.search(r"^description:\s*(.+)$", fm, re.MULTILINE)
        if dn:
            name = dn.group(1).strip()
        if dd:
            desc = dd.group(1).strip()
    return name, desc, text


def list_web_playbooks():
    """Return [{slug, name, description}] for web-relevant skills present."""
    out = []
    base = skills_dir()
    for slug in sorted(WEB_SKILLS):
        p = os.path.join(base, slug, "SKILL.md")
        if os.path.exists(p):
            name, desc, _ = _read_frontmatter(p)
            out.append({"slug": slug, "name": name, "description": desc[:300]})
    return out


def load_playbook(slug):
    """Return the full skill body for a given slug, or None."""
    p = os.path.join(skills_dir(), slug, "SKILL.md")
    if not os.path.exists(p):
        return None
    name, desc, text = _read_frontmatter(p)
    return {"slug": slug, "name": name, "description": desc, "body": text}
