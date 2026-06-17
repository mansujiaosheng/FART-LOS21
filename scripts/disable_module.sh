#!/bin/bash
# disable_module.sh -- Disable/uninstall FART-LOS21 module
ADB_HOST="${ADB_HOST:-192.168.238.1}"
ADB_PORT="${ADB_PORT:-5037}"
adb_cmd() { adb -H "$ADB_HOST" -P "$ADB_PORT" "$@"; }

ACTION="${1:---disable}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

adb_cmd devices | grep -q "device$" || { echo -e "${RED}Device not connected${NC}"; exit 1; }

exists=$(adb_cmd shell "kp -c '[ -d /data/adb/modules/fart-los21 ] && echo 1 || echo 0'" 2>/dev/null)

if [ "$exists" != "1" ]; then
    echo "Module not installed"
    exit 0
fi

if [ "$ACTION" = "--uninstall" ]; then
    echo -e "${RED}Uninstalling...${NC}"
    adb_cmd shell "kp -c 'rm -rf /data/adb/modules/fart-los21'"
    echo -e "${GREEN}Removed. Reboot needed.${NC}"
elif [ "$ACTION" = "--disable" ]; then
    echo -e "${YELLOW}Disabling...${NC}"
    adb_cmd shell "kp -c 'touch /data/adb/modules/fart-los21/disable'"
    echo -e "${GREEN}Disabled. Reboot needed.${NC}"
else
    echo "Usage: $0 [--disable|--uninstall]"
fi
