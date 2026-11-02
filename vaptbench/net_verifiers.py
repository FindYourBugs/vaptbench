"""Network service verifiers — deterministic, proof-only (wave 1).

Each check takes a discovered service and returns finding dict(s) ONLY when it can
prove the issue (same contract as the web verifiers). Everything is best-effort:
a missing tool, closed port, or timeout yields no finding, never a crash.

Covered now: TLS/SSL weaknesses, anonymous FTP, Telnet (cleartext), SNMP default
community, SMB null session + signing, unauthenticated Redis / MongoDB /
Memcached / Elasticsearch, SMTP open-relay & user enumeration, DNS version.bind.
"""
import shutil
import socket
import ssl
import subprocess
from datetime import datetime

_T = 4   # socket timeout seconds


def _fy(**k):
    k.setdefault("cvss", "")
    k.setdefault("confidence", "confirmed")
    return k


def _run(cmd, timeout=25):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


# --------------------------------------------------------------------- TLS/SSL
def check_tls(host, port):
    out = []
    weak = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1),
                      ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((host, port), timeout=_T) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    weak.append(name)
        except Exception:
            pass
    if weak:
        out.append(_fy(
            title=f"Weak TLS protocol(s) enabled on {port}/tcp: {', '.join(weak)}",
            vuln_class="net-tls", severity="medium",
            cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=f"The service on {host}:{port} negotiates deprecated TLS protocol "
                        f"version(s) {', '.join(weak)}, which are vulnerable to known downgrade/"
                        f"padding attacks (BEAST/POODLE-class) and fail modern compliance (PCI/NIST).",
            steps=f"openssl s_client -connect {host}:{port} -tls1 (and -tls1_1) completes a handshake.",
            poc_request=f"TLS handshake to {host}:{port} forcing {', '.join(weak)}",
            poc_response=f"Handshake succeeded with: {', '.join(weak)}"))

    # certificate inspection (no verification; we read it)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_T) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                der = ss.getpeercert(binary_form=True)
        if cert:
            na = cert.get("notAfter")
            if na:
                exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                if exp < datetime.utcnow():
                    out.append(_fy(
                        title=f"Expired TLS certificate on {port}/tcp",
                        vuln_class="net-tls", severity="low",
                        description=f"The certificate presented by {host}:{port} expired on {na}.",
                        steps=f"Inspect the cert: openssl s_client -connect {host}:{port}",
                        poc_request=f"TLS to {host}:{port}", poc_response=f"notAfter={na}"))
            subj = dict(x[0] for x in cert.get("subject", []))
            iss = dict(x[0] for x in cert.get("issuer", []))
            if subj and subj == iss:
                out.append(_fy(
                    title=f"Self-signed TLS certificate on {port}/tcp",
                    vuln_class="net-tls", severity="low",
                    description=f"The certificate on {host}:{port} is self-signed "
                                f"(issuer == subject: {subj.get('commonName','?')}).",
                    steps=f"openssl s_client -connect {host}:{port} shows issuer==subject.",
                    poc_request=f"TLS to {host}:{port}",
                    poc_response=f"subject={subj}; issuer={iss}"))
    except Exception:
        pass
    return out


# --------------------------------------------------------------------- FTP
def check_ftp(host, port):
    import ftplib
    out = []
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=_T)
        banner = ftp.getwelcome() or ""
        ftp.login("anonymous", "anon@test.com")       # anonymous
        listing = []
        try:
            ftp.retrlines("LIST", listing.append)
        except Exception:
            pass
        ftp.quit()
        out.append(_fy(
            title=f"Anonymous FTP login allowed on {port}/tcp",
            vuln_class="net-ftp", severity="high",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=f"The FTP service on {host}:{port} accepts anonymous login and serves "
                        f"a directory listing without credentials. Banner: {banner.strip()}",
            steps=f"ftp {host} {port}; login anonymous / any-password; LIST.",
            poc_request=f"USER anonymous / PASS anon@test.com to {host}:{port}",
            poc_response=(banner + "\n" + "\n".join(listing[:20]))[:800]))
    except Exception:
        pass
    return out


# --------------------------------------------------------------------- Telnet
def check_telnet(host, port):
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            banner = s.recv(256)
    except Exception:
        return []
    return [_fy(
        title=f"Telnet (cleartext administration) exposed on {port}/tcp",
        vuln_class="net-telnet", severity="medium",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description=f"{host}:{port} runs Telnet, which transmits credentials and sessions in "
                    f"cleartext — trivially captured by anyone on the network path.",
        steps=f"telnet {host} {port} connects; traffic is unencrypted.",
        poc_request=f"TCP connect {host}:{port}",
        poc_response=repr(banner[:120]))]


# --------------------------------------------------------------------- SNMP
def check_snmp(host, port=161):
    if not shutil.which("snmpwalk"):
        return []
    out = []
    for comm in ("public", "private"):
        res = _run(["snmpwalk", "-v2c", "-c", comm, "-t", "2", "-r", "1",
                    f"{host}:{port}", "1.3.6.1.2.1.1.1.0"], timeout=10)
        if "STRING:" in res or "Hex-STRING" in res:
            out.append(_fy(
                title=f"SNMP default community '{comm}' on {port}/udp",
                vuln_class="net-snmp", severity="high",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description=f"{host}:{port} responds to the default SNMP community string "
                            f"'{comm}', disclosing system/network information (and, with write "
                            f"access, enabling configuration changes).",
                steps=f"snmpwalk -v2c -c {comm} {host} system",
                poc_request=f"snmpwalk -v2c -c {comm} {host}:{port} 1.3.6.1.2.1.1.1.0",
                poc_response=res.strip()[:600]))
            break
    return out


# --------------------------------------------------------------------- SMB
def check_smb(host, port=445):
    if not shutil.which("smbclient"):
        return []
    out = []
    res = _run(["smbclient", "-N", "-L", f"//{host}/", "-p", str(port)], timeout=20)
    if "Sharename" in res or "Disk" in res:
        shares = [ln.strip() for ln in res.splitlines()
                  if ln.strip() and ("Disk" in ln or "IPC" in ln)][:15]
        out.append(_fy(
            title=f"SMB null session allowed on {port}/tcp (share enumeration)",
            vuln_class="net-smb", severity="high",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=f"{host}:{port} permits an unauthenticated (null) session that lists "
                        f"SMB shares without credentials — an information-disclosure and often a "
                        f"foothold for further access.",
            steps=f"smbclient -N -L //{host}/",
            poc_request=f"smbclient -N -L //{host}/ -p {port}",
            poc_response="\n".join(shares)[:600] or res[:600]))
    return out


# --------------------------------------------------------------------- Redis
def check_redis(host, port=6379):
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(b"*1\r\n$4\r\nPING\r\n")
            if b"PONG" not in s.recv(128):
                return []
            s.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
            info = s.recv(2048).decode(errors="replace")
    except Exception:
        return []
    return [_fy(
        title=f"Unauthenticated Redis exposed on {port}/tcp",
        vuln_class="net-redis", severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description=f"Redis on {host}:{port} answers commands without authentication. An attacker "
                    f"can read/modify all data and often achieve RCE (e.g. writing an SSH key or "
                    f"module via CONFIG SET).",
        steps=f"redis-cli -h {host} -p {port} PING -> PONG; INFO returns server data.",
        poc_request=f"PING / INFO server to {host}:{port} (no AUTH)",
        poc_response=info[:600])]


# --------------------------------------------------------------------- Memcached
def check_memcached(host, port=11211):
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(b"stats\r\n")
            data = s.recv(2048).decode(errors="replace")
    except Exception:
        return []
    if "STAT " not in data:
        return []
    return [_fy(
        title=f"Unauthenticated Memcached exposed on {port}/tcp",
        vuln_class="net-memcached", severity="high",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        description=f"Memcached on {host}:{port} answers without auth, exposing cached data and "
                    f"enabling UDP reflection/amplification abuse.",
        steps=f"echo stats | nc {host} {port}",
        poc_request=f"stats -> {host}:{port}", poc_response=data[:500])]


# --------------------------------------------------------------------- Elasticsearch
def check_elasticsearch(host, port=9200):
    import urllib.request
    for scheme in ("http", "https"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}:{port}/")
            with urllib.request.urlopen(req, timeout=_T, context=ctx) as r:
                body = r.read(2048).decode(errors="replace")
            if '"cluster_name"' in body or '"lucene_version"' in body:
                return [_fy(
                    title=f"Unauthenticated Elasticsearch exposed on {port}/tcp",
                    vuln_class="net-elastic", severity="high",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    description=f"Elasticsearch on {host}:{port} serves cluster info and indices "
                                f"without authentication — full read (often write) of stored data.",
                    steps=f"curl {scheme}://{host}:{port}/ and /_cat/indices",
                    poc_request=f"GET {scheme}://{host}:{port}/",
                    poc_response=body[:600])]
        except Exception:
            continue
    return []


# --------------------------------------------------------------------- MongoDB
def check_mongodb(host, port=27017):
    # minimal OP_QUERY ismaster (legacy opcode 2004) to admin.$cmd
    import struct
    doc = b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"   # {ismaster:1}
    body = (struct.pack("<i", 0) + b"admin.$cmd\x00" +
            struct.pack("<ii", 0, -1) + doc)
    msg = struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(msg)
            resp = s.recv(2048)
    except Exception:
        return []
    if b"ismaster" not in resp and b"maxWireVersion" not in resp and b"ok" not in resp:
        return []
    return [_fy(
        title=f"Unauthenticated MongoDB exposed on {port}/tcp",
        vuln_class="net-mongodb", severity="critical",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description=f"MongoDB on {host}:{port} answers the 'ismaster' command without "
                    f"authentication — databases are readable/writable by anyone who can reach it.",
        steps=f"mongosh mongodb://{host}:{port} connects without credentials.",
        poc_request=f"OP_QUERY ismaster to {host}:{port}",
        poc_response=repr(resp[:200]))]


# --------------------------------------------------------------------- SMTP
def check_smtp(host, port=25):
    out = []
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            banner = s.recv(512).decode(errors="replace")
            s.sendall(b"EHLO vaptbench.test\r\n")
            s.recv(1024)
            # user enumeration via VRFY
            s.sendall(b"VRFY root\r\n")
            vrfy = s.recv(256).decode(errors="replace")
            if vrfy[:3] in ("250", "252"):
                out.append(_fy(
                    title=f"SMTP user enumeration via VRFY on {port}/tcp",
                    vuln_class="net-smtp", severity="low",
                    description=f"{host}:{port} answers VRFY, allowing valid local usernames to "
                                f"be enumerated.",
                    steps=f"VRFY root -> {vrfy.strip()}",
                    poc_request=f"VRFY root to {host}:{port}", poc_response=vrfy.strip()))
            # open relay test (foreign sender + foreign recipient, no DATA sent)
            s.sendall(b"MAIL FROM:<test@evil.example>\r\n")
            mf = s.recv(256).decode(errors="replace")
            s.sendall(b"RCPT TO:<victim@external.example>\r\n")
            rc = s.recv(256).decode(errors="replace")
            if mf[:3] == "250" and rc[:3] == "250":
                out.append(_fy(
                    title=f"SMTP open relay on {port}/tcp",
                    vuln_class="net-smtp", severity="high",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    description=f"{host}:{port} accepts a foreign sender AND foreign recipient — "
                                f"an open mail relay abusable for spam/phishing (no message was sent).",
                    steps="MAIL FROM:<test@evil.example>; RCPT TO:<victim@external.example> both 250.",
                    poc_request=f"MAIL FROM/RCPT TO to {host}:{port}",
                    poc_response=f"MAIL: {mf.strip()} | RCPT: {rc.strip()}"))
            try:
                s.sendall(b"QUIT\r\n")
            except Exception:
                pass
    except Exception:
        return out
    return out


# --------------------------------------------------------------------- DNS
def check_dns(host, port=53):
    if not shutil.which("dig"):
        return []
    res = _run(["dig", f"@{host}", "version.bind", "chaos", "txt", "+short",
                "+time=2", "+tries=1"], timeout=8)
    ver = res.strip().strip('"')
    if ver and "connection timed out" not in res and ";;" not in ver:
        return [_fy(
            title=f"DNS version disclosure on {port}/udp",
            vuln_class="net-dns", severity="info",
            description=f"The DNS server {host} discloses its version via a CHAOS TXT query: {ver}",
            steps=f"dig @{host} version.bind chaos txt",
            poc_request=f"dig @{host} version.bind chaos txt",
            poc_response=ver[:200])]
    return []


# -------------------------------------------------------- dispatch by service
def verifiers_for(svc):
    """Return the checks relevant to a discovered service."""
    name = (svc.get("name") or "").lower()
    port = svc.get("port")
    tunnel = (svc.get("tunnel") or "").lower()
    checks = []
    if name in ("ftp", "ftp-data") or port == 21:
        checks.append(("ftp", lambda h: check_ftp(h, port)))
    if name == "telnet" or port == 23:
        checks.append(("telnet", lambda h: check_telnet(h, port)))
    if name == "smtp" or port in (25, 587, 465):
        checks.append(("smtp", lambda h: check_smtp(h, port)))
    if "domain" in name or port == 53:
        checks.append(("dns", lambda h: check_dns(h, port)))
    if name in ("microsoft-ds", "netbios-ssn") or port in (445, 139):
        checks.append(("smb", lambda h: check_smb(h, port)))
    if "snmp" in name or port == 161:
        checks.append(("snmp", lambda h: check_snmp(h, port)))
    if name == "redis" or port == 6379:
        checks.append(("redis", lambda h: check_redis(h, port)))
    if name == "memcached" or port == 11211:
        checks.append(("memcached", lambda h: check_memcached(h, port)))
    if "elasticsearch" in name or port == 9200:
        checks.append(("elasticsearch", lambda h: check_elasticsearch(h, port)))
    if name == "mongodb" or port == 27017:
        checks.append(("mongodb", lambda h: check_mongodb(h, port)))
    # TLS checks on any TLS-wrapped service
    if tunnel == "ssl" or name in ("https", "ssl", "ldapssl", "imaps", "pop3s",
                                    "https-alt") or port in (443, 993, 995, 636, 8443, 465):
        checks.append(("tls", lambda h: check_tls(h, port)))
    return checks
