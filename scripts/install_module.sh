#!/bin/bash
# install_module.sh -- Build, package and install FART-LOS21 module
set -e

ADB_HOST="${ADB_HOST:-192.168.238.1}"
ADB_PORT="${ADB_PORT:-5037}"

adb_cmd() { adb -H "$ADB_HOST" -P "$ADB_PORT" "$@"; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}FART-LOS21 Module Installer${NC}"

# 1. Build
echo -e "\n${YELLOW}[1/4] Building...${NC}"
cd "$PROJECT_DIR/native"
make clean 2>/dev/null
make -j4
cd - > /dev/null

# 2. Package
echo -e "\n${YELLOW}[2/4] Packaging...${NC}"
cd "$PROJECT_DIR" && scripts/package_module.sh

# 3. Push
echo -e "\n${YELLOW}[3/4] Pushing to device...${NC}"
adb_cmd devices | grep -q "device$" || { echo "Device not connected"; exit 1; }
adb_cmd push "$PROJECT_DIR/fart-los21-module.zip" /data/local/tmp/

# 4. Install via kp
echo -e "\n${YELLOW}[4/4] Installing...${NC}"
adb_cmd shell "kp -c 'apd module install /data/local/tmp/fart-los21-module.zip 2>&1'"

echo -e "\n${GREEN}Done. Reboot to activate.${NC}"
echo -e "  Tool: ${YELLOW}$0 --reboot${NC}"
echo -e "  Or:   ${YELLOW}adb -H $ADB_HOST -P $ADB_PORT reboot${NC}"

if [ "$1" = "--reboot" ]; then
    adb_cmd reboot
fi
