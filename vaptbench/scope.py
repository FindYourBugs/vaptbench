"""Deny-wins scope guard. Nothing gets touched unless it matches an allow
rule and matches no deny rule. Default-deny: empty ruleset blocks everything.

Rules, one per line:
    example.com            allow host (and subdomains)
    https://example.com/*  allow URL glob
    !admin.example.com     deny (wins over any allow)
"""
import fnmatch
from urllib.parse import urlparse


def _host(url_or_host):
    if "://" in url_or_host:
        return (urlparse(url_or_host).hostname or "").lower()
    return url_or_host.split("/")[0].lower()


def parse_rules(text):
    allows, denies = [], []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            denies.append(line[1:].strip())
        else:
            allows.append(line)
    return allows, denies


def _matches(rule, url):
    host = _host(url)
    rhost = _host(rule)
    # A rule containing a glob is matched strictly (lets you scope precise paths
    # or write path-level deny rules like !https://x.com/admin/*).
    if "*" in rule:
        return fnmatch.fnmatch(url, rule) or fnmatch.fnmatch(host, rule)
    # Otherwise a plain host OR a full URL authorises the whole host (and its
    # subdomains) — so "shop.x.com", "https://shop.x.com", and
    # "https://shop.x.com/login" all mean the same thing: the shop.x.com site.
    return bool(rhost) and (host == rhost or host.endswith("." + rhost))


def in_scope(url, rules_text):
    allows, denies = parse_rules(rules_text)
    if any(_matches(d, url) for d in denies):
        return False, "blocked by deny rule"
    if any(_matches(a, url) for a in allows):
        return True, "in scope"
    return False, "no matching allow rule (default-deny)"
