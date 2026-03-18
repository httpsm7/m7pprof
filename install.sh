#!/bin/bash
# ══════════════════════════════════════════════════════════
#   m7pprof - One-Command Installer
#   Author: Sharlix | Milkyway Intelligence
# ══════════════════════════════════════════════════════════

set -e

CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PATH="/usr/local/bin/m7pprof"

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     m7pprof Installer v1.0.0             ║"
echo "  ║     Milkyway Intelligence by Sharlix     ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# Check python3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] python3 not found. Please install Python 3.7+${RESET}"
    exit 1
fi

PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
PY_VER="${PY_MAJOR}.${PY_MINOR}"

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 7 ]; }; then
    echo -e "${RED}[-] Python 3.7+ required. Found: $PY_VER${RESET}"
    exit 1
fi

echo -e "${GREEN}[+] Python $PY_VER: OK${RESET}"
echo -e "${GREEN}[+] Zero external dependencies required (pure Python stdlib)${RESET}"

# Verify stdlib modules
echo -e "${YELLOW}[*] Verifying stdlib modules...${RESET}"
python3 -c "
import asyncio, ssl, urllib.request, urllib.parse, urllib.error
import gzip, base64, re, json, math, struct, os, sys
import concurrent.futures, socket, threading
print('All stdlib modules: OK')
"

# Create results dir
mkdir -p "${TOOL_DIR}/results"
echo -e "${GREEN}[+] Results directory ready${RESET}"

# Make executable
chmod +x "${TOOL_DIR}/m7pprof.py"

# Create global launcher
echo -e "${YELLOW}[*] Installing global command 'm7pprof'...${RESET}"
LAUNCHER_CONTENT="#!/bin/bash
cd \"${TOOL_DIR}\"
exec python3 \"${TOOL_DIR}/m7pprof.py\" \"\$@\"
"

GLOBAL_INSTALLED=false
if echo "$LAUNCHER_CONTENT" > /tmp/m7pprof_launcher 2>/dev/null; then
    if cp /tmp/m7pprof_launcher "${INSTALL_PATH}" 2>/dev/null && chmod +x "${INSTALL_PATH}" 2>/dev/null; then
        GLOBAL_INSTALLED=true
        echo -e "${GREEN}[+] Global command installed: ${INSTALL_PATH}${RESET}"
    else
        # Try with sudo
        if sudo cp /tmp/m7pprof_launcher "${INSTALL_PATH}" 2>/dev/null && sudo chmod +x "${INSTALL_PATH}" 2>/dev/null; then
            GLOBAL_INSTALLED=true
            echo -e "${GREEN}[+] Global command installed (sudo): ${INSTALL_PATH}${RESET}"
        else
            echo -e "${YELLOW}[!] Could not install globally. Use: python3 m7pprof.py${RESET}"
        fi
    fi
fi

# Quick self-test
echo -e "${YELLOW}[*] Running self-test...${RESET}"
cd "${TOOL_DIR}"
python3 -c "
import sys
sys.path.insert(0, '.')
from core.banner import print_banner
from utils.config import Config
from utils.logger import Logger
from engines.decode import AutoDecodeEngine
from engines.extractor import ExtractionEngine

c = Config()
l = Logger(no_color=True)
d = AutoDecodeEngine(c, l)
e = ExtractionEngine(c, l)
print('Self-test: PASSED')
"

echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✓ Installation Complete!${RESET}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "${BOLD}Usage:${RESET}"
if [ "$GLOBAL_INSTALLED" = true ]; then
    echo -e "  ${GREEN}m7pprof -u http://target.com:6060${RESET}"
    echo -e "  ${GREEN}m7pprof -u http://target.com:6060 --full-chain${RESET}"
    echo -e "  ${GREEN}m7pprof -u http://target.com:6060 --burst --threads 20${RESET}"
    echo -e "  ${GREEN}m7pprof -u http://target.com:6060 --proxy http://127.0.0.1:8080${RESET}"
    echo -e "  ${GREEN}m7pprof -l targets.txt --full-chain --json${RESET}"
else
    echo -e "  ${GREEN}python3 m7pprof.py -u http://target.com:6060${RESET}"
    echo -e "  ${GREEN}python3 m7pprof.py -u http://target.com:6060 --full-chain${RESET}"
    echo -e "  ${GREEN}python3 m7pprof.py -u http://target.com:6060 --proxy http://127.0.0.1:8080${RESET}"
fi
echo ""
echo -e "  ${YELLOW}Run with --help to see all options${RESET}"
echo ""
