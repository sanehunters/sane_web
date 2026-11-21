#!/usr/bin/env bash
# Install the free tools the cards can use. Nothing here is required: every card has a curl or Python path, and
# `scripts/sane doctor` shows what is present. Run it once per machine.
#
#   scripts/install-tools.sh            install what can be installed without root, print the rest
#   scripts/install-tools.sh --apt      also run the apt line with sudo
#
# Everything is fetched from the projects' own repositories and package registries.
set -u
APT=0; [ "${1:-}" = "--apt" ] && APT=1
have(){ command -v "$1" >/dev/null 2>&1 || [ -x "$HOME/go/bin/$1" ]; }
say(){ printf '\n== %s\n' "$1"; }

APT_PKGS="curl dnsutils jq git nmap sqlmap golang-go pipx python3-pip whois"
say "system packages"
if [ $APT -eq 1 ]; then
  sudo apt-get update -y && sudo apt-get install -y $APT_PKGS
else
  echo "run yourself if any are missing:  sudo apt-get install -y $APT_PKGS"
fi

say "Go tools (ProjectDiscovery and others)"
if have go; then
  export PATH="$PATH:$HOME/go/bin"
  while read -r name pkg; do
    [ -z "$name" ] && continue
    if have "$name"; then echo "ok       $name"; else echo "install  $name"; go install "$pkg" 2>&1 | tail -2; fi
  done <<'EOF'
subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
katana github.com/projectdiscovery/katana/cmd/katana@latest
nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest
interactsh-client github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
ffuf github.com/ffuf/ffuf/v2@latest
gau github.com/lc/gau/v2/cmd/gau@latest
waybackurls github.com/tomnomnom/waybackurls@latest
dalfox github.com/hahwul/dalfox/v2@latest
EOF
  grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null || echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
  echo "added ~/go/bin to PATH in ~/.bashrc (open a new shell)"
else
  echo "Go is not installed: sudo apt-get install -y golang-go, then run this again"
fi

say "nuclei templates (used only for matched CVE ids, never as a whole-set scan)"
if have nuclei; then nuclei -update-templates -silent 2>&1 | tail -1; ls -d "$HOME/nuclei-templates" 2>/dev/null || echo "templates directory not found yet"; else echo "skipped: nuclei not installed"; fi

say "Python tools"
if have pipx; then
  for p in arjun; do have "$p" && echo "ok       $p" || pipx install "$p" 2>&1 | tail -1; done
else
  echo "pipx not installed: sudo apt-get install -y pipx"
fi
python3 -c "import h2" 2>/dev/null && echo "ok       python h2 (single-packet race harness)" || echo "optional: pip install --user h2 httpx[http2] websockets   (race and websocket cards)"

say "scriptable browser (proof of client-side findings, screenshots)"
if have npx; then
  echo "run once:  npx --yes playwright install chromium"
else
  echo "Node.js not found: install it, then  npx --yes playwright install chromium"
fi

say "keys (optional, all free)"
echo "HackerOne API (scope import):   export H1_USERNAME=<user> H1_TOKEN=<token>      https://hackerone.com/settings/api_token/edit"
echo "HexBrain (report library MCP):  export HEXBRAIN_API_KEY=<key>                   https://hexbrainai.com/account"
echo "NVD (faster CVE lookup):        export NVD_API_KEY=<key>                        https://nvd.nist.gov/developers/request-an-api-key"

say "result"
python3 "$(dirname "$0")/sane" doctor
