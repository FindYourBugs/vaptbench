"""Network discovery & service detection (the recon layer of network VAPT).

Drives nmap for host discovery + TCP service/version detection, parses its XML,
and returns a structured map of hosts -> open services. A light pure-Python TCP
connect-scan fallback runs if nmap is unavailable, so the module still works.

Everything is scope-checked by the caller before a host is touched.
"""
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

# Common UDP services worth a quick look (nmap -sU needs root; best-effort).
UDP_PORTS = "53,67,123,161,500"
# Fallback connect-scan port set (when nmap is missing).
FALLBACK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
                  636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
                  6379, 8080, 8443, 9200, 11211, 27017]


def available():
    return shutil.which("nmap") is not None


def scan_host(host, top_ports=1000, udp=False, timeout=600, log=None):
    """Return {'host', 'up', 'services':[{port,proto,state,name,product,version,
    extrainfo}]}. Uses nmap -sT -sV; falls back to a socket connect-scan."""
    def _l(msg):
        if log:
            log(msg)

    if available():
        return _nmap(host, top_ports, udp, timeout, _l)
    _l("nmap not installed — using built-in TCP connect-scan (no version detection)")
    return _fallback(host)


def _nmap(host, top_ports, udp, timeout, _l):
    cmd = ["nmap", "-sT", "-sV", "-Pn", "--open", "-T4",
           "--top-ports", str(top_ports), "-oX", "-", host]
    if udp:
        # best-effort UDP (will no-op without root); keep it small & fast
        cmd = ["nmap", "-sT", "-sU", "-sV", "-Pn", "--open", "-T4",
               "--top-ports", str(top_ports), "-p", f"U:{UDP_PORTS},T:1-{top_ports}",
               "-oX", "-", host]
    _l(f"nmap {' '.join(cmd[1:])}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _l("nmap timed out")
        return {"host": host, "up": False, "services": []}
    except Exception as e:
        _l(f"nmap error: {e}")
        return {"host": host, "up": False, "services": []}
    return _parse_nmap_xml(out.stdout, host)


def _parse_nmap_xml(xml_text, host):
    services, up = [], False
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"host": host, "up": False, "services": []}
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") == "up":
            up = True
        # prefer the resolved address as the host label
        addr = h.find("address")
        hlabel = addr.get("addr") if addr is not None else host
        for p in h.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            services.append({
                "host": hlabel,
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "state": "open",
                "name": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
                "tunnel": (svc.get("tunnel") if svc is not None else "") or "",
            })
    return {"host": host, "up": up or bool(services), "services": services}


def _fallback(host):
    services = []
    for port in FALLBACK_PORTS:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                services.append({"host": host, "port": port, "proto": "tcp",
                                 "state": "open", "name": _guess(port),
                                 "product": "", "version": "", "extrainfo": "",
                                 "tunnel": "ssl" if port in (443, 993, 995, 8443, 636) else ""})
        except (OSError, socket.timeout):
            continue
    return {"host": host, "up": bool(services), "services": services}


_WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap",
    443: "https", 445: "microsoft-ds", 636: "ldapssl", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}


def _guess(port):
    return _WELL_KNOWN.get(port, "unknown")
