#!/bin/bash
#
# Router_analysis - Automated Router Firmware Security Analysis
# One-click Setup for Kali / Debian / Ubuntu
#
# Usage: chmod +x setup.sh && ./setup.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }
step()  { echo -e "\n${CYAN}=== $1 ===${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
step "Checking prerequisites"

if [ "$(id -u)" -eq 0 ]; then
    warn "Running as root; regular user recommended"
    SUDO=""
else
    SUDO="sudo"
fi

if ! command -v python3 &>/dev/null; then
    err "python3 not found, installing..."
    $SUDO apt update && $SUDO apt install -y python3 python3-pip python3-venv
fi

PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)

if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 11 ]; }; then
    err "Python >= 3.11 required, got $PYVER"
    exit 1
fi
info "Python $PYVER OK"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------
step "Installing system dependencies"

PKGS=(
    binwalk
    file
    python3-dev
    libffi-dev
    libssl-dev
    git
    curl
    wget
)

MISSING=()
for pkg in "${PKGS[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null 2>&1; then
        MISSING+=("$pkg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    info "Installing: ${MISSING[*]}"
    $SUDO apt update
    $SUDO apt install -y "${MISSING[@]}"
else
    info "System packages OK"
fi

# ---------------------------------------------------------------------------
# binwalk (latest from GitHub — apt version is often outdated)
# ---------------------------------------------------------------------------
step "Installing binwalk"

if command -v binwalk &>/dev/null; then
    info "binwalk already installed: $(binwalk --version 2>/dev/null | head -1)"
else
    info "Installing binwalk from GitHub..."
    $SUDO python3 -m pip install --break-system-packages git+https://github.com/ReFirmLabs/binwalk.git \
        || warn "binwalk install failed; firmware extraction will not work"
fi

# ---------------------------------------------------------------------------
# Magika
# ---------------------------------------------------------------------------
step "Installing Magika (file type identification)"

if python3 -c "import magika" &>/dev/null; then
    info "Magika already installed"
else
    info "Installing magika..."
    $SUDO python3 -m pip install --break-system-packages magika || warn "magika install failed; file identification will use fallback"
fi

# ---------------------------------------------------------------------------
# Install router-analysis (editable)
# ---------------------------------------------------------------------------
step "Installing router-analysis"

PIP_ARGS="--break-system-packages"
python3 -m pip install --help 2>/dev/null | grep -q "break-system-packages" || PIP_ARGS=""

$SUDO python3 -m pip install $PIP_ARGS -e "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Optional: Ghidra (static disassembly)
# ---------------------------------------------------------------------------
step "Installing optional tools"

# Ghidra
if [ -f "$HOME/ghidra/support/analyzeHeadless" ]; then
    info "Ghidra already found: $HOME/ghidra"
elif command -v analyzeHeadless &>/dev/null; then
    info "Ghidra already in PATH"
else
    warn "Ghidra not found — static disassembly will be skipped"
    warn "  Install from: https://github.com/NationalSecurityAgency/ghidra"
    warn "  Or: git clone https://github.com/NationalSecurityAgency/ghidra.git"
fi

# radare2
if command -v r2 &>/dev/null; then
    info "radare2 already installed"
else
    info "Installing radare2..."
    git clone --depth=1 https://github.com/radareorg/radare2.git /tmp/radare2-build 2>/dev/null && \
        /tmp/radare2-build/sys/install.sh && \
        rm -rf /tmp/radare2-build || \
        warn "radare2 install failed; use --tool ghidra instead"
fi

# r2pipe (Python bindings for radare2)
if python3 -c "import r2pipe" &>/dev/null; then
    info "r2pipe already installed"
else
    $SUDO python3 -m pip install $PIP_ARGS r2pipe || warn "r2pipe install failed"
fi

# angr
if python3 -c "import angr" &>/dev/null; then
    info "angr already installed"
else
    info "Installing angr (may take a few minutes)..."
    $SUDO python3 -m pip install $PIP_ARGS angr || warn "angr install failed; use --tool ghidra instead"
fi

# checksec (from pwntools)
if python3 -c "import pwn" &>/dev/null; then
    info "pwntools already installed"
else
    $SUDO python3 -m pip install $PIP_ARGS pwntools || err "pwntools install failed"
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
step "Verifying installation"

PASS=0
FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" &>/dev/null 2>&1; then
        info "$name OK"
        PASS=$((PASS + 1))
    else
        warn "$name not ready"
        FAIL=$((FAIL + 1))
    fi
}

check "python3"      "python3 --version"
check "binwalk"      "command -v binwalk"
check "magika"       "python3 -c 'import magika'"
check "pwntools"     "python3 -c 'import pwn'"
check "angr"         "python3 -c 'import angr'"
check "r2pipe"       "python3 -c 'import r2pipe'"
check "radare2"       "command -v r2"
check "ghidra"       "command -v analyzeHeadless || [ -f '$HOME/ghidra/support/analyzeHeadless' ]"
check "router-analysis" "python3 -m autopwn --version"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}  Router_analysis setup complete${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "  Passed: ${GREEN}${PASS}${NC}  Not ready: ${YELLOW}${FAIL}${NC}"
echo ""
echo -e "  Usage:"
echo -e "    ${CYAN}router-analysis ./firmware.bin${NC}                       Analyze firmware"
echo -e "    ${CYAN}router-analysis ./firmware.bin -o ./output${NC}            Output to dir"
echo -e "    ${CYAN}router-analysis ./firmware.bin -t ghidra${NC}              Use Ghidra"
echo -e "    ${CYAN}router-analysis ./firmware.bin -t angr${NC}                Use angr"
echo -e "    ${CYAN}router-analysis ./firmware.bin --no-disassembly${NC}       CVE scan only"
echo -e "    ${CYAN}router-analysis ./firmware.bin --json-report out.json${NC}  JSON output"
echo ""

if [ $FAIL -gt 0 ]; then
    warn "Some optional tools are not ready; core scanning will still work"
fi
