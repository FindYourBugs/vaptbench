"""Autonomous network / infrastructure VAPT engine.

Given an IP or CIDR, runs the whole network methodology in a background thread:
  discovery -> port/service/version scan -> per-service verification (proof-only)
  -> nuclei network templates -> AI write-up + critic -> findings + report.

Reuses the web engine's finding store, logging, AI write-up and critic so a
network run produces the same live feed and the same branded report.
"""
import os
import shutil
import subprocess
import threading
from datetime import datetime

from .models import db, Target, Run, RunLog, Finding
from .scope import in_scope
from . import netscan
from . import net_verifiers as NV
from . import engine as web_engine   # reuse _add_finding / _log / writeup / critic

NUCLEI = os.environ.get("VAPT_NUCLEI", "1") != "0" and shutil.which("nuclei")
CRITIC_MODE = web_engine.CRITIC_MODE
PORTS_SPEC = os.environ.get("VAPT_NET_PORTS_SPEC", "") or \
    ("top" + os.environ.get("VAPT_NET_PORTS", "1000"))


def start_run(app, target_id):
    t = Target.query.get(target_id)
    run = Run(target_id=target_id, engagement_id=t.engagement_id,
              status="queued", phase="queued")
    db.session.add(run)
    db.session.commit()
    rid = run.id
    threading.Thread(target=_run, args=(app, rid), daemon=True).start()
    return rid


def _run(app, run_id):
    with app.app_context():
        run = Run.query.get(run_id)
        run.status = "running"
        db.session.commit()
        _log = web_engine._log
        _add = web_engine._add_finding
        try:
            t = Target.query.get(run.target_id)
            scope = t.scope_rules
            target = (t.base_url or "").strip()
            seen = set()
            _log(run, "info", "start", f"Autonomous NETWORK VAPT on {target}")

            # --- Phase 1: discovery + service/version scan -----------------
            _log(run, "info", "recon", f"Scanning {target} (ports: {PORTS_SPEC}, service detection)...")
            if not netscan.available():
                _log(run, "warn", "recon", "nmap not installed — using built-in connect-scan (no versions)")
            # single-host reachability probe (CIDR scans skip this)
            single = "/" not in target
            if single and not netscan.reachable(target):
                _log(run, "warn", "recon",
                     f"{target} did not respond on common ports — host may be down, firewalled, "
                     f"or unreachable from this machine. In WSL, LAN IPs aren't always directly "
                     f"routable: verify with `ping {target}` / `nc -vz {target} <port>` from this "
                     f"shell. Scanning anyway (-Pn)...")
            result = netscan.scan_host(target, ports=PORTS_SPEC,
                                       log=lambda m: _log(run, "info", "recon", m))
            services = result.get("services", [])
            # group by host, scope-check each host
            by_host = {}
            for svc in services:
                h = svc.get("host") or target
                ok, _why = in_scope(h, scope)
                if not ok:
                    continue
                by_host.setdefault(h, []).append(svc)
            if not by_host:
                if single and not netscan.reachable(target):
                    _log(run, "warn", "recon",
                         "no services — host appears DOWN/unreachable from here (see note above). "
                         "Run from a host on the same network segment, or check routing/firewall.")
                else:
                    _log(run, "warn", "recon",
                         "host is UP but no open ports in the scanned range — try a wider scan: "
                         "--ports all  (full 1-65535), or --ports 8000-9000 for a custom range.")
            total_svc = sum(len(v) for v in by_host.values())
            _log(run, "info", "recon",
                 f"{len(by_host)} host(s) up, {total_svc} open in-scope service(s)")
            run.endpoints_tested = total_svc
            db.session.commit()

            # --- Phase 2: per-host surface summary + verification ----------
            for host, svcs in by_host.items():
                if run.stop_requested:
                    break
                portlist = ", ".join(f"{s['port']}/{s['proto']} {s['name']}"
                                     + (f" ({s['product']} {s['version']})".rstrip() if s['product'] else "")
                                     for s in sorted(svcs, key=lambda x: x["port"]))
                _log(run, "info", "recon", f"{host}: {portlist}")
                _add(run, seen, dict(
                    title=f"Open network services on {host}",
                    vuln_class="net-service", severity="info", confidence="confirmed",
                    description=f"Host {host} exposes {len(svcs)} service(s):\n{portlist}",
                    steps=f"nmap -sV {host}", poc_request=f"nmap -sV {host}",
                    poc_response=portlist))

                _log(run, "info", "test", f"Verifying services on {host}...")
                for svc in svcs:
                    if run.stop_requested:
                        break
                    run.requests_sent = (run.requests_sent or 0) + 1
                    for label, fn in NV.verifiers_for(svc):
                        try:
                            for f in fn(host):
                                _add(run, seen, f)
                        except Exception as e:
                            _log(run, "warn", "test", f"{label} check error on {host}:{svc['port']}: {e}")
                    db.session.commit()

                # --- Phase 3: nuclei network/version templates -------------
                if NUCLEI and not run.stop_requested:
                    _nuclei_host(run, host, svcs, seen)

            # --- Phase 4: AI write-up + critic (reused) --------------------
            if not run.stop_requested:
                web_engine._writeup_phase(run)
            if CRITIC_MODE and not run.stop_requested:
                web_engine._critic_phase(run)

            run.status = "stopped" if run.stop_requested else "done"
            run.phase = "done"
            run.finished = datetime.utcnow()
            db.session.commit()
            _log(run, "info", "done",
                 f"Run {run.status}: {run.findings_count} finding(s) across "
                 f"{len(by_host)} host(s), {total_svc} service(s)")
        except Exception as e:
            run = Run.query.get(run_id)
            run.status = "error"; run.finished = datetime.utcnow()
            db.session.add(RunLog(run_id=run.id, level="error", phase="error", message=str(e)))
            db.session.commit()


def _nuclei_host(run, host, svcs, seen):
    """Run nuclei network/ssl templates against the host's open ports."""
    web_engine._log(run, "info", "nuclei", f"nuclei network/ssl templates on {host}...")
    targets = [f"{host}:{s['port']}" for s in svcs]
    cmd = ["nuclei", "-silent", "-jsonl", "-tags", "network,ssl,default-login,exposure",
           "-timeout", "5", "-rl", "50"]
    for tg in targets:
        cmd += ["-target", tg]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        web_engine._log(run, "warn", "nuclei", f"nuclei error: {e}")
        return
    import json as _json
    for line in (out.stdout or "").splitlines():
        try:
            j = _json.loads(line)
        except ValueError:
            continue
        info = j.get("info", {})
        sev = (info.get("severity") or "info").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        web_engine._add_finding(run, seen, dict(
            title=f"{info.get('name', j.get('template-id','nuclei finding'))} ({j.get('matched-at','')})",
            vuln_class="net-nuclei", severity=sev, confidence="confirmed",
            description=(info.get("description") or info.get("name") or "nuclei match").strip(),
            steps=f"nuclei -id {j.get('template-id','')} -target {j.get('matched-at','')}",
            poc_request=j.get("matched-at", ""),
            poc_response=_json.dumps(j.get("extracted-results", []))[:400] or j.get("template-id", "")))
