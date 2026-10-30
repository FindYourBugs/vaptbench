#!/usr/bin/env bash
# VAPTBench — Kali-WSL one-shot setup.
# Installs the tools the workbench drives + the roadmap tooling, sets up the
# Python venv, and bakes in the Ollama defaults. Safe to re-run (idempotent).
#
# Usage:
#   bash scripts/setup_kali.sh            # install everything (default)
#   bash scripts/setup_kali.sh web        # just core + web recon
#   GROUPS="web crack" bash scripts/setup_kali.sh   # pick groups
#
# Groups: web network ad crack  (core is always installed)
set -uo pipefail

GROUPS="${GROUPS:-${*:-all}}"
[ "$GROUPS" = "all" ] && GROUPS="web network ad crack"

c_y='\033[1;33m'; c_g='\033[1;32m'; c_r='\033[1;31m'; c_0='\033[0m'
say(){ printf "\n${c_y}==> %s${c_0}\n" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

want(){ case " $GROUPS " in *" $1 "*) return 0;; *) return 1;; esac; }

# ---- apt packages ---------------------------------------------------------
APT_CORE="python3 python3-venv python3-pip git curl wget jq golang-go"
APT_WEB="nmap nuclei ffuf whatweb seclists wordlists sqlmap nikto wafw00f dirsearch feroxbuster gobuster wfuzz amass"
APT_NET="masscan dnsutils netcat-traditional arp-scan"
APT_AD="netexec impacket-scripts enum4linux-ng smbmap responder ldap-utils krb5-user"
APT_CRACK="hashcat john hydra"

install_apt(){ sudo apt-get install -y --no-install-recommends $* || true; }

say "apt update"
sudo apt-get update -y

say "core packages"
install_apt $APT_CORE

want web     && { say "web recon packages";   install_apt $APT_WEB; }
want network && { say "network packages";      install_apt $APT_NET; }
want ad      && { say "active directory packages"; install_apt $APT_AD; }
want crack   && { say "cracking packages";     install_apt $APT_CRACK; }

# ---- Go-based tools (latest, reliable) ------------------------------------
# httpx/gau/waybackurls/subfinder are cleaner via `go install`. Put go/bin
# FIRST on PATH so the projectdiscovery `httpx` wins over the python one.
export GOBIN="$HOME/go/bin"; mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"

if want web; then
  say "go tools (httpx, katana, gau, waybackurls, subfinder, qsreplace, anew, uro)"
  GO_TOOLS=(
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/s0md3v/uro@latest"
  )
  for t in "${GO_TOOLS[@]}"; do
    bin="$(basename "${t%@*}")"
    if have "$bin"; then printf "   %s already present\n" "$bin"
    else printf "   installing %s...\n" "$bin"; go install "$t" 2>/dev/null || printf "   ${c_r}%s failed${c_0}\n" "$bin"; fi
  done
fi

# ---- shell PATH + env defaults -------------------------------------------
RC="$HOME/.zshrc"; [ -f "$RC" ] || RC="$HOME/.bashrc"
say "updating $RC (PATH + VAPTBench defaults)"
grep -q 'go/bin' "$RC" 2>/dev/null || echo 'export PATH="$HOME/go/bin:$PATH"' >> "$RC"
grep -q 'VAPT_OLLAMA_MODEL' "$RC" 2>/dev/null || echo 'export VAPT_OLLAMA_MODEL=qwen3:14b' >> "$RC"
grep -q 'VAPT_WORDLIST' "$RC" 2>/dev/null || echo 'export VAPT_WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt' >> "$RC"

# ---- Python venv for the app ---------------------------------------------
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
say "python venv + requirements ($APP_DIR)"
cd "$APP_DIR"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt && printf "   ${c_g}python deps installed${c_0}\n"

# Headless browser for autonomous login on JS/SPA apps (Playwright + Chromium).
say "installing headless browser (Chromium via Playwright)"
sudo ./.venv/bin/python -m playwright install-deps chromium || \
  printf "   ${c_r}playwright system deps failed (install manually if browser login errors)${c_0}\n"
./.venv/bin/python -m playwright install chromium && printf "   ${c_g}chromium installed${c_0}\n"

# ---- verification table ---------------------------------------------------
say "verification"
CHECK="python3 nmap nuclei ffuf katana whatweb httpx gau waybackurls subfinder \
sqlmap nikto gobuster feroxbuster masscan netexec smbmap hashcat john hydra ollama"
printf "   %-16s %s\n" "TOOL" "STATUS"
printf "   %-16s %s\n" "----" "------"
for t in $CHECK; do
  if have "$t"; then printf "   %-16s ${c_g}ok${c_0}\n" "$t"
  else printf "   %-16s ${c_r}missing${c_0}\n" "$t"; fi
done

say "done"
echo "Open a NEW Kali shell (to load PATH/env), then:"
echo "    cd $APP_DIR && source .venv/bin/activate && python app.py"
echo "Note: 'ollama' missing here is normal — it runs on Windows, reached over the network."
