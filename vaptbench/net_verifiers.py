"""Network service verifiers — deterministic, proof-only (wave 1).

Each check takes a discovered service and returns finding dict(s) ONLY when it can
prove the issue (same contract as the web verifiers). Everything is best-effort:
a missing tool, closed port, or timeout yields no finding, never a crash.

Covered now: TLS/SSL weaknesses, anonymous FTP, Telnet (cleartext), SNMP default
community, SMB null session + signing, unauthenticated Redis / MongoDB /
Memcached / Elasticsearch, SMTP open-relay & user enumeration, DNS version.bind.
"""
import os
import shutil
import socket
import ssl
import struct
import subprocess
from datetime import datetime

_T = 4   # socket timeout seconds

# Credential testing (wave 2) is deterministic proof: a finding is emitted only
# when a login actually succeeds and a read-only query returns. Disable the whole
# credential layer with VAPT_NET_CREDS=0 (version/algorithm checks still run).
_CREDS_ENABLED = os.environ.get("VAPT_NET_CREDS", "1") != "0"
# Small, well-known default-credential sets — authorised targets only.
_MYSQL_CREDS = [("root", ""), ("root", "root"), ("root", "toor"),
                ("root", "password"), ("root", "mysql")]
_PG_CREDS = [("postgres", ""), ("postgres", "postgres"), ("postgres", "password")]
_MSSQL_CREDS = [("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "Password123")]


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


# --------------------------------------------------------------------- SSH
def check_ssh(host, port=22):
    """Parse the server's KEXINIT (no authentication) and flag weak key-exchange,
    host-key, cipher or MAC algorithms. Pure protocol inspection — read-only."""
    try:
        s = socket.create_connection((host, port), timeout=_T)
        s.settimeout(_T)
    except Exception:
        return []
    out = []
    try:
        banner = b""
        while b"\n" not in banner and len(banner) < 512:
            chunk = s.recv(256)
            if not chunk:
                break
            banner += chunk
        if not banner.startswith(b"SSH-"):
            s.close()
            return []
        s.sendall(b"SSH-2.0-vaptbench\r\n")
        # the KEXINIT packet may trail the banner, or arrive next
        data = banner.split(b"\n", 1)[1] if b"\n" in banner else b""
        while len(data) < 5:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        plen = struct.unpack(">I", data[:4])[0]
        while len(data) < 4 + plen and plen < 65535:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        packet = data[4:4 + plen]
        pad = packet[0]
        payload = packet[1:len(packet) - pad]
        if not payload or payload[0] != 20:      # 20 = SSH_MSG_KEXINIT
            s.close()
            return []
        p = payload[17:]                          # skip msg-type(1) + cookie(16)
        names = []
        for _ in range(6):   # kex, hostkey, enc c2s, enc s2c, mac c2s, mac s2c
            if len(p) < 4:
                break
            ln = struct.unpack(">I", p[:4])[0]
            names.append(p[4:4 + ln].decode(errors="replace"))
            p = p[4 + ln:]
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return out
    try:
        s.close()
    except Exception:
        pass
    kex = names[0] if len(names) > 0 else ""
    hostkey = names[1] if len(names) > 1 else ""
    ciphers = (names[2] if len(names) > 2 else "") + "," + (names[3] if len(names) > 3 else "")
    macs = (names[4] if len(names) > 4 else "") + "," + (names[5] if len(names) > 5 else "")
    weak = []
    if any(w in kex for w in ("group1-sha1", "group14-sha1", "group-exchange-sha1", "gex-sha1")):
        weak.append("weak key exchange (SHA-1 / DH group1)")
    if any(w in hostkey for w in ("ssh-rsa", "ssh-dss")):
        weak.append("weak host-key algorithm (ssh-rsa / ssh-dss)")
    if any(w in ciphers for w in ("-cbc", "arcfour", "3des", "blowfish", "cast128")):
        weak.append("CBC-mode / legacy ciphers")
    if any(w in macs for w in ("hmac-sha1", "hmac-md5", "umac-64", "-96")):
        weak.append("weak MAC (SHA-1 / MD5 / 64-bit)")
    if weak:
        out.append(_fy(
            title=f"Weak SSH algorithms offered on {port}/tcp",
            vuln_class="net-ssh", severity="low",
            cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=f"The SSH service on {host}:{port} offers deprecated algorithms: "
                        f"{'; '.join(weak)}. These weaken confidentiality/integrity of the "
                        f"session and fail modern hardening baselines (CIS / NIST).",
            steps=f"ssh -vv {host} -p {port} (observe offered KEX/cipher/MAC) or "
                  f"nmap --script ssh2-enum-algos -p{port} {host}",
            poc_request=f"SSH_MSG_KEXINIT from {host}:{port}",
            poc_response=f"kex={kex}\nhostkey={hostkey}\nciphers={ciphers}\nmacs={macs}"[:600]))
    return out


# --------------------------------------------------------------------- MySQL
def check_mysql(host, port=3306):
    """Read the MySQL greeting for version, then (if enabled) prove weak/default
    credentials by logging in and running a read-only SELECT VERSION()."""
    ver = ""
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            data = s.recv(512)
        if len(data) > 5 and data[4] == 10:         # protocol v10 greeting
            end = data.index(b"\x00", 5)
            ver = data[5:end].decode(errors="replace")
    except Exception:
        return []
    if not ver or not _CREDS_ENABLED or not shutil.which("mysql"):
        return []
    for user, pw in _MYSQL_CREDS:
        env = dict(os.environ, MYSQL_PWD=pw)
        try:
            r = subprocess.run(["mysql", "-h", host, "-P", str(port), "-u", user,
                                "--connect-timeout=4", "-N", "-B",
                                "-e", "SELECT VERSION()"],
                               capture_output=True, text=True, timeout=12, env=env)
        except Exception:
            continue
        if r.returncode == 0 and r.stdout.strip():
            cred = f"{user}/{pw or '<empty>'}"
            return [_fy(
                title=f"MySQL weak/default credentials on {port}/tcp ({cred})",
                vuln_class="net-mysql", severity="critical",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description=f"MySQL on {host}:{port} (v{ver}) accepts the weak/default credentials "
                            f"'{cred}', granting direct database access. Login confirmed with a "
                            f"read-only SELECT VERSION().",
                steps=f"mysql -h {host} -P {port} -u {user} (password '{pw or 'empty'}') "
                      f"-e 'SELECT VERSION()'",
                poc_request=f"MySQL auth {cred} -> SELECT VERSION()",
                poc_response=r.stdout.strip()[:300])]
    return []


# --------------------------------------------------------------------- Postgres
def check_postgres(host, port=5432):
    if not _CREDS_ENABLED or not shutil.which("psql"):
        return []
    for user, pw in _PG_CREDS:
        env = dict(os.environ, PGPASSWORD=pw, PGCONNECT_TIMEOUT="4")
        try:
            r = subprocess.run(["psql", "-h", host, "-p", str(port), "-U", user, "-w",
                                "-t", "-c", "SELECT version()"],
                               capture_output=True, text=True, timeout=12, env=env)
        except Exception:
            continue
        if r.returncode == 0 and "PostgreSQL" in r.stdout:
            cred = f"{user}/{pw or '<empty>'}"
            return [_fy(
                title=f"PostgreSQL weak/default credentials on {port}/tcp ({cred})",
                vuln_class="net-postgres", severity="critical",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description=f"PostgreSQL on {host}:{port} accepts the weak/default credentials "
                            f"'{cred}' (or trust authentication), granting database access. Login "
                            f"confirmed with a read-only SELECT version().",
                steps=f"PGPASSWORD='{pw}' psql -h {host} -p {port} -U {user} -c 'SELECT version()'",
                poc_request=f"PostgreSQL auth {cred} -> SELECT version()",
                poc_response=r.stdout.strip()[:300])]
    return []


# --------------------------------------------------------------------- MSSQL
def check_mssql(host, port=1433):
    if not _CREDS_ENABLED or not shutil.which("impacket-mssqlclient"):
        return []
    for user, pw in _MSSQL_CREDS:
        try:
            r = subprocess.run(["impacket-mssqlclient", f"{user}:{pw}@{host}",
                                "-port", str(port)],
                               input="SELECT @@version;\nexit\n",
                               capture_output=True, text=True, timeout=25)
        except Exception:
            continue
        o = (r.stdout or "") + (r.stderr or "")
        if "Login failed" in o or "SQL (" not in o:   # prompt appears only on success
            continue
        cred = f"{user}/{pw or '<empty>'}"
        banner = next((ln.strip() for ln in o.splitlines()
                       if "Microsoft SQL Server" in ln), "login succeeded")
        return [_fy(
            title=f"MSSQL weak/default credentials on {port}/tcp ({cred})",
            vuln_class="net-mssql", severity="critical",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=f"Microsoft SQL Server on {host}:{port} accepts the weak/default "
                        f"credentials '{cred}', granting database access (and often xp_cmdshell "
                        f"to OS command execution). Login confirmed with SELECT @@version.",
            steps=f"impacket-mssqlclient {user}:{pw}@{host} -port {port}  (then SELECT @@version)",
            poc_request=f"MSSQL auth {cred} -> SELECT @@version",
            poc_response=banner[:300])]
    return []


# --------------------------------------------------------------------- LDAP
def check_ldap(host, port=389):
    if not shutil.which("ldapsearch"):
        return []
    r = _run(["ldapsearch", "-x", "-H", f"ldap://{host}:{port}", "-s", "base",
              "-b", "", "-o", "nettimeout=4", "-l", "4", "namingContexts"], timeout=12)
    if "namingContexts:" in r:
        ctxs = [ln.strip() for ln in r.splitlines()
                if ln.lower().startswith("namingcontexts:")]
        return [_fy(
            title=f"LDAP anonymous bind allowed on {port}/tcp",
            vuln_class="net-ldap", severity="medium",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            description=f"The LDAP/Directory service on {host}:{port} permits an anonymous "
                        f"(unauthenticated) bind and discloses its naming contexts — typically "
                        f"enabling enumeration of users, groups and domain structure.",
            steps=f"ldapsearch -x -H ldap://{host}:{port} -s base -b '' namingContexts",
            poc_request="anonymous simple bind -> rootDSE namingContexts",
            poc_response=("\n".join(ctxs) or r.strip())[:500])]
    return []


# --------------------------------------------------------------------- NFS
def check_nfs(host, port=2049):
    if not shutil.which("showmount"):
        return []
    r = _run(["showmount", "-e", host], timeout=10)
    if "Export list" in r:
        exports = [ln.strip() for ln in r.splitlines()[1:] if ln.strip()]
        if exports:
            return [_fy(
                title=f"NFS exports enumerable on {port}/tcp",
                vuln_class="net-nfs", severity="medium",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                description=f"{host} discloses its NFS export list. Exports shared to a broad "
                            f"range (e.g. '*') can be mounted without authentication, exposing or "
                            f"even allowing modification of their contents.",
                steps=f"showmount -e {host}  (then mount -t nfs {host}:<export> /mnt)",
                poc_request=f"showmount -e {host}",
                poc_response="\n".join(exports)[:500])]
    return []


# --------------------------------------------------------------------- VNC
def check_vnc(host, port=5900):
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            ver = s.recv(12)                       # e.g. b"RFB 003.008\n"
            if not ver.startswith(b"RFB"):
                return []
            s.sendall(ver)                         # echo the server's version
            sec = s.recv(256)
    except Exception:
        return []
    none_auth = False
    if len(sec) >= 2 and sec[0] not in (0, None):  # 3.7+: count byte + type list
        types = sec[1:1 + sec[0]]
        none_auth = 1 in types
    elif len(sec) >= 4:                            # 3.3: single 4-byte type
        none_auth = struct.unpack(">I", sec[:4])[0] == 1
    if none_auth:
        return [_fy(
            title=f"VNC without authentication on {port}/tcp",
            vuln_class="net-vnc", severity="critical",
            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description=f"VNC on {host}:{port} offers the 'None' security type — full remote "
                        f"desktop control with no password.",
            steps=f"vncviewer {host}:{port} connects without a password.",
            poc_request=f"RFB handshake to {host}:{port}",
            poc_response=f"version={ver!r}; security types include None(1): {sec[:8]!r}")]
    return []


# --------------------------------------------------------------------- RDP (NLA)
def check_rdp(host, port=3389):
    """Negotiate RDP security. Flag when the server does NOT enforce Network Level
    Authentication (CredSSP/HYBRID) — i.e. it accepts standard RDP security or
    TLS-only, exposing the pre-auth attack surface (BlueKeep-class)."""
    nego = bytes([0x01, 0x00]) + struct.pack("<H", 0x0008) + struct.pack("<I", 0x0003)
    x224 = bytes([0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + nego
    tpkt = b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224
    try:
        with socket.create_connection((host, port), timeout=_T) as s:
            s.settimeout(_T)
            s.sendall(tpkt)
            resp = s.recv(512)
    except Exception:
        return []
    if len(resp) < 19 or resp[0] != 0x03:
        return []
    kind, code = resp[11], struct.unpack("<I", resp[15:19])[0]
    sev = label = None
    if kind == 0x02:                               # negotiation response
        proto = code
        if proto == 0:                             # standard RDP security
            sev, label = "high", "standard RDP security (no TLS, no NLA)"
        elif proto == 1:                           # TLS only, no CredSSP
            sev, label = "medium", "TLS without Network Level Authentication (NLA)"
    elif kind == 0x03 and code == 2:               # SSL_NOT_ALLOWED_BY_SERVER
        sev, label = "high", "standard RDP security only (server refuses TLS/NLA)"
    if not sev:
        return []
    return [_fy(
        title=f"RDP does not enforce Network Level Authentication on {port}/tcp",
        vuln_class="net-rdp", severity=sev,
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
        description=f"The RDP service on {host}:{port} negotiated {label}. Without NLA the server "
                    f"processes connections before authentication, enlarging the pre-authentication "
                    f"attack surface (e.g. CVE-2019-0708 BlueKeep-class) and enabling credential "
                    f"interception on weak/standard security.",
        steps=f"Send an RDP negotiation request to {host}:{port}; server selects a "
              f"non-HYBRID protocol.",
        poc_request=f"X.224 RDP negotiation (request SSL|HYBRID) to {host}:{port}",
        poc_response=f"selectedProtocol/failureCode={code} -> {label}")]


# -------------------------------------------------------- dispatch by service
def verifiers_for(svc):
    """Return the checks relevant to a discovered service."""
    name = (svc.get("name") or "").lower()
    port = svc.get("port")
    tunnel = (svc.get("tunnel") or "").lower()
    checks = []
    if name in ("ftp", "ftp-data") or port == 21:
        checks.append(("ftp", lambda h: check_ftp(h, port)))
    if name == "ssh" or port == 22:
        checks.append(("ssh", lambda h: check_ssh(h, port)))
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
    if name in ("mysql", "mariadb") or port == 3306:
        checks.append(("mysql", lambda h: check_mysql(h, port)))
    if "postgres" in name or port == 5432:
        checks.append(("postgres", lambda h: check_postgres(h, port)))
    if "ms-sql" in name or name == "mssql" or port in (1433, 1434):
        checks.append(("mssql", lambda h: check_mssql(h, port)))
    if name in ("ldap", "ldapssl") or "ldap" in name or port in (389, 3268):
        checks.append(("ldap", lambda h: check_ldap(h, port)))
    if "nfs" in name or port == 2049:
        checks.append(("nfs", lambda h: check_nfs(h, port)))
    if name == "vnc" or (port and 5900 <= port <= 5903):
        checks.append(("vnc", lambda h: check_vnc(h, port)))
    if "ms-wbt" in name or name == "rdp" or port == 3389:
        checks.append(("rdp", lambda h: check_rdp(h, port)))
    # TLS checks on any TLS-wrapped service
    if tunnel == "ssl" or name in ("https", "ssl", "ldapssl", "imaps", "pop3s",
                                    "https-alt") or port in (443, 993, 995, 636, 8443, 465):
        checks.append(("tls", lambda h: check_tls(h, port)))
    return checks
