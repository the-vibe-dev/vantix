#!/usr/bin/env bash
# bugbounty-install.sh — Bug bounty toolchain installer and tracker
#
# Installs and tracks the full bug bounty tool suite.
# Safe to re-run: skips tools that are already installed.
#
# Usage:
#   bugbounty-install.sh               # install everything missing
#   bugbounty-install.sh --check       # list installed/missing tools, no install
#   bugbounty-install.sh --tool TOOL   # install/check a single tool
#   bugbounty-install.sh --apt-only    # only apt installs
#   bugbounty-install.sh --go-only     # only Go-based tools
#   bugbounty-install.sh --pip-only    # only pip/pipx tools
#   bugbounty-install.sh --git-only    # only git clone + build tools

set -euo pipefail

CTF_ROOT="${CTF_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BB_DIR="$CTF_ROOT/agent_ops/bugbounty"
TRACK_FILE="$BB_DIR/tools_installed.yaml"
GO_BIN="${HOME}/go/bin"
LOCAL_BIN="${HOME}/.local/bin"
CHECK_ONLY=false
SINGLE_TOOL=""
APT_ONLY=false
GO_ONLY=false
PIP_ONLY=false
GIT_ONLY=false

mkdir -p "$BB_DIR" "$LOCAL_BIN"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)    CHECK_ONLY=true; shift ;;
    --tool)     SINGLE_TOOL="$2"; shift 2 ;;
    --apt-only) APT_ONLY=true; shift ;;
    --go-only)  GO_ONLY=true; shift ;;
    --pip-only) PIP_ONLY=true; shift ;;
    --git-only) GIT_ONLY=true; shift ;;
    -h|--help) grep '^#' "$0" | head -15 | sed 's/^# \?//'; exit 0 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
done

# ── Tracking helpers ──────────────────────────────────────────────────────────
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

track_tool() {
  local name="$1" method="$2" binary="$3"
  local version
  version=$("$binary" --version 2>/dev/null | head -1 || \
            "$binary" version 2>/dev/null | head -1 || \
            echo "installed")
  version="${version//[$'\r\n']/}"
  # Update or append to YAML tracking file
  if grep -q "^  $name:" "$TRACK_FILE" 2>/dev/null; then
    sed -i "s|^  ${name}:.*|  ${name}: { method: ${method}, binary: ${binary}, version: \"${version}\", ts: \"$(ts)\" }|" "$TRACK_FILE"
  else
    echo "  ${name}: { method: ${method}, binary: ${binary}, version: \"${version}\", ts: \"$(ts)\" }" >> "$TRACK_FILE"
  fi
}

tool_present() {
  local name="$1"
  command -v "$name" &>/dev/null || [[ -x "$GO_BIN/$name" ]] || [[ -x "$LOCAL_BIN/$name" ]]
}

check_or_install() {
  local name="$1" method="$2" binary="${3:-$1}"
  if tool_present "$binary"; then
    echo "  [OK] $name"
  else
    echo "  [MISSING] $name (method: $method)"
  fi
}

# ── Initialize tracking file ──────────────────────────────────────────────────
[[ -f "$TRACK_FILE" ]] || cat > "$TRACK_FILE" <<'YAML'
# Bug bounty tool inventory
# Auto-managed by bugbounty-install.sh
tools:
YAML

echo "[*] Bug bounty toolchain $(${CHECK_ONLY} && echo check || echo install)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# APT tools
# ─────────────────────────────────────────────────────────────────────────────
APT_TOOLS=(
  nmap        # port scanning + service detection
  curl        # HTTP requests + PoC testing
  wget        # file downloads
  jq          # JSON processing for API responses
  sqlmap      # SQL injection testing
  ffuf        # fast web fuzzer (subdomain + param + path)
  wfuzz       # web fuzzer alternative
  nikto       # web server scanner
  whatweb     # web tech fingerprinting
  dnsutils    # dig/nslookup for DNS recon
  whois       # domain registration info
  git         # git clone for tool installs
  python3-pip # pip package installer
  pipx        # isolated pip tool installs
  golang-go   # Go runtime for Go-based tools
  amass       # subdomain enumeration (apt version)
  subfinder   # fast subdomain discovery
  httpx-toolkit # HTTP probe tool (apt name varies)
  chromium    # headless browser for JS-heavy apps
  nodejs      # JS runtime for some tools
  npm         # Node package manager
  ruby        # Ruby runtime for some tools
  libssl-dev  # SSL libs needed by some tools
  python3-requests  # Python HTTP library
)

if ! $CHECK_ONLY && ! $GO_ONLY && ! $PIP_ONLY && ! $GIT_ONLY; then
  echo "=== APT tools ==="
  MISSING_APT=()
  for tool in "${APT_TOOLS[@]}"; do
    pkg_name="${tool%%#*}"  # strip comments
    pkg_name="${pkg_name// /}"
    if ! dpkg -s "$pkg_name" &>/dev/null 2>&1; then
      MISSING_APT+=("$pkg_name")
    fi
  done
  if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
    echo "[*] Installing: ${MISSING_APT[*]}"
    sudo apt-get install -y "${MISSING_APT[@]}" 2>&1 | grep -E '(Setting up|already installed|E:|error)' || true
  else
    echo "[OK] All apt tools present"
  fi
elif $CHECK_ONLY || $APT_ONLY; then
  echo "=== APT tools ==="
  for tool in "${APT_TOOLS[@]}"; do
    pkg_name="${tool%%#*}"; pkg_name="${pkg_name// /}"
    if dpkg -s "$pkg_name" &>/dev/null 2>&1; then
      echo "  [OK] $pkg_name"
    else
      echo "  [MISSING] $pkg_name"
    fi
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
# Go-based tools (go install)
# ─────────────────────────────────────────────────────────────────────────────
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest:subfinder"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest:httpx"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest:dnsx"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest:nuclei"
  "github.com/projectdiscovery/katana/cmd/katana@latest:katana"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest:naabu"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest:interactsh-client"
  "github.com/hahwul/dalfox/v2@latest:dalfox"
  "github.com/lc/gau/v2/cmd/gau@latest:gau"
  "github.com/tomnomnom/waybackurls@latest:waybackurls"
  "github.com/tomnomnom/anew@latest:anew"
  "github.com/tomnomnom/gf@latest:gf"
  "github.com/tomnomnom/qsreplace@latest:qsreplace"
  "github.com/ffuf/ffuf/v2@latest:ffuf"
  "github.com/s0md3v/uro@latest:uro"
  "github.com/jaeles-project/gospider@latest:gospider"
)

if ! $CHECK_ONLY && ! $APT_ONLY && ! $PIP_ONLY && ! $GIT_ONLY && command -v go &>/dev/null; then
  echo ""
  echo "=== Go tools ==="
  export GOPATH="${HOME}/go"
  export PATH="$PATH:$GO_BIN"
  for entry in "${GO_TOOLS[@]}"; do
    pkg="${entry%%:*}"; bin="${entry##*:}"
    if tool_present "$bin"; then
      echo "  [OK] $bin"
    else
      echo "  [*] Installing $bin..."
      go install "$pkg" 2>/dev/null && track_tool "$bin" "go" "$GO_BIN/$bin" || echo "  [FAIL] $bin"
    fi
  done
elif $CHECK_ONLY; then
  echo ""
  echo "=== Go tools ==="
  for entry in "${GO_TOOLS[@]}"; do
    bin="${entry##*:}"
    check_or_install "$bin" "go" "$bin"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
# pip / pipx tools
# ─────────────────────────────────────────────────────────────────────────────
PIP_TOOLS=(
  "arjun:arjun"           # HTTP parameter discovery
  "xsstrike:xsstrike"     # XSS scanner
  "trufflehog:trufflehog" # secret/credential scanner
  "waymore:waymore"       # URL collection (Wayback + other)
  "uro:uro"               # URL deduplication
  "socialhunter:socialhunter"  # broken social media link finder
  "pycorscan:pycorscan"   # CORS misconfiguration scanner
)

if ! $CHECK_ONLY && ! $APT_ONLY && ! $GO_ONLY && ! $GIT_ONLY; then
  echo ""
  echo "=== pip/pipx tools ==="
  if command -v pipx &>/dev/null; then
    for entry in "${PIP_TOOLS[@]}"; do
      pkg="${entry%%:*}"; bin="${entry##*:}"
      if tool_present "$bin"; then
        echo "  [OK] $bin"
      else
        echo "  [*] Installing $pkg via pipx..."
        pipx install "$pkg" 2>/dev/null && track_tool "$bin" "pipx" "$(command -v "$bin" || echo pipx)" || echo "  [FAIL] $pkg"
      fi
    done
  elif command -v pip3 &>/dev/null; then
    for entry in "${PIP_TOOLS[@]}"; do
      pkg="${entry%%:*}"; bin="${entry##*:}"
      if tool_present "$bin"; then
        echo "  [OK] $bin"
      else
        echo "  [*] Installing $pkg via pip3..."
        pip3 install --user "$pkg" 2>/dev/null && track_tool "$bin" "pip" "$LOCAL_BIN/$bin" || echo "  [FAIL] $pkg"
      fi
    done
  fi
elif $CHECK_ONLY; then
  echo ""
  echo "=== pip/pipx tools ==="
  for entry in "${PIP_TOOLS[@]}"; do
    bin="${entry##*:}"
    check_or_install "$bin" "pip/pipx" "$bin"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
# git clone tools
# ─────────────────────────────────────────────────────────────────────────────
GIT_DIR="${HOME}/tools/bugbounty"
mkdir -p "$GIT_DIR"

git_install() {
  local name="$1" repo="$2" setup_cmd="${3:-}"
  local dst="$GIT_DIR/$name"
  if [[ -d "$dst/.git" ]]; then
    if $CHECK_ONLY; then echo "  [OK] $name (git: $dst)"; fi
    return 0
  fi
  if $CHECK_ONLY; then echo "  [MISSING] $name (git: $repo)"; return 0; fi
  echo "  [*] Cloning $name..."
  git clone --depth 1 "$repo" "$dst" 2>/dev/null || { echo "  [FAIL] clone $repo"; return 1; }
  if [[ -n "$setup_cmd" ]]; then
    (cd "$dst" && eval "$setup_cmd" 2>/dev/null) || true
  fi
  # Try to link to LOCAL_BIN if there's a main script
  for candidate in "$dst/$name" "$dst/main.py" "$dst/${name}.py" "$dst/src/$name"; do
    if [[ -f "$candidate" ]]; then
      chmod +x "$candidate" 2>/dev/null || true
      ln -sf "$candidate" "$LOCAL_BIN/$name" 2>/dev/null || true
      break
    fi
  done
  track_tool "$name" "git" "$dst"
  echo "  [OK] $name installed to $dst"
}

GIT_TOOLS=(
  "LinkFinder:https://github.com/GerbenJavado/LinkFinder.git:pip3 install -r requirements.txt"
  "SecretFinder:https://github.com/m4ll0k/SecretFinder.git:pip3 install -r requirements.txt"
  "JSFinder:https://github.com/Threezh1/JSFinder.git:"
  "getJS:https://github.com/003random/getJS.git:"
  "CORStest:https://github.com/RUB-NDS/CORStest.git:"
  "SubOver:https://github.com/Ice3man543/SubOver.git:"
  "GitTools:https://github.com/internetwache/GitTools.git:"
  "ghauri:https://github.com/r0oth3x49/ghauri.git:pip3 install -r requirements.txt"
  "XSStrike:https://github.com/s0md3v/XSStrike.git:pip3 install -r requirements.txt"
  "jwt_tool:https://github.com/ticarpi/jwt_tool.git:pip3 install -r requirements.txt"
  "param-miner:https://github.com/PortSwigger/param-miner.git:"
  "403bypass:https://github.com/iamj0ker/bypass-403.git:"
)

if ! $CHECK_ONLY && ! $APT_ONLY && ! $GO_ONLY && ! $PIP_ONLY || $GIT_ONLY || $CHECK_ONLY; then
  echo ""
  echo "=== git clone tools ==="
  for entry in "${GIT_TOOLS[@]}"; do
    IFS=':' read -r name repo setup <<< "$entry"
    git_install "$name" "$repo" "$setup"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
# Nuclei templates
# ─────────────────────────────────────────────────────────────────────────────
if ! $CHECK_ONLY && command -v nuclei &>/dev/null; then
  echo ""
  echo "=== Nuclei templates ==="
  if [[ ! -d "${HOME}/nuclei-templates" ]]; then
    echo "  [*] Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || true
    echo "  [OK] Templates updated"
  else
    echo "  [OK] Templates present"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
if $CHECK_ONLY; then
  echo "[*] Check complete. Install missing tools with: bugbounty-install.sh"
else
  echo "[+] Installation complete. Tracking: $TRACK_FILE"
fi

# Update PATH hint
if [[ ":$PATH:" != *":$GO_BIN:"* ]] || [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
  echo "[!] Add to ~/.bashrc or ~/.zshrc:"
  echo "    export PATH=\"\$PATH:$GO_BIN:$LOCAL_BIN\""
fi
