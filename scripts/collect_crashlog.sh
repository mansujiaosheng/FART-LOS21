#!/bin/bash
#
# collect_crashlog.sh - Collect crash logs, tombstones, and module logs
#
# Usage: ./collect_crashlog.sh [output_dir]
#

ADB_HOST="${ADB_HOST:-192.168.238.1}"
ADB_PORT="${ADB_PORT:-5037}"

adb_cmd() {
    adb -H "$ADB_HOST" -P "$ADB_PORT" "$@"
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${1:-$PROJECT_DIR/crashlogs_$(date +%Y%m%d_%H%M%S)}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}Collecting crash logs...${NC}"

adb_cmd devices | grep -q "device$" || {
    echo -e "${RED}❌ Device not connected${NC}"
    exit 1
}

mkdir -p "$OUTPUT_DIR"

# 1. FART module log
echo -n "  Module log..."
adb_cmd shell su -c 'cat /data/local/tmp/fart/module.log 2>/dev/null' > "$OUTPUT_DIR/module.log" 2>/dev/null
echo " done"

# 2. Crash logcat
echo -n "  Crash logcat..."
adb_cmd logcat -b crash -d 2>/dev/null > "$OUTPUT_DIR/logcat_crash.txt"
echo " done"

# 3. FART log filter
echo -n "  FART log filter..."
adb_cmd logcat -d | grep -i "FART_LOS21" > "$OUTPUT_DIR/logcat_fart.txt" 2>/dev/null
echo " done"

# 4. Main logcat (last 1000 lines)
echo -n "  Main logcat (last 500 lines)..."
adb_cmd logcat -d -t 500 2>/dev/null > "$OUTPUT_DIR/logcat_main.txt"
echo " done"

# 5. Tombstones
echo -n "  Tombstones..."
mkdir -p "$OUTPUT_DIR/tombstones"
TOMBSTONES=$(adb_cmd shell su -c 'ls -t /data/tombstones/* 2>/dev/null | head -5')
for ts in $TOMBSTONES; do
    ts_name=$(basename "$ts")
    adb_cmd pull "$ts" "$OUTPUT_DIR/tombstones/$ts_name" 2>/dev/null
done
echo " done"

# 6. /proc/maps of target process (if specified)
if [ -n "$2" ]; then
    echo -n "  Process maps for $2..."
    adb_cmd shell su -c "cat /proc/\$(pidof $2)/maps 2>/dev/null" > "$OUTPUT_DIR/maps_$2.txt" 2>/dev/null
    echo " done"
fi

# Summary
echo ""
echo -e "${GREEN}✅ Crash logs collected to: $OUTPUT_DIR${NC}"
echo ""
echo "Files:"
ls -lh "$OUTPUT_DIR/" 2>/dev/null | grep -v tombstones
if [ -d "$OUTPUT_DIR/tombstones" ]; then
    echo "Tombstones:"
    ls -lh "$OUTPUT_DIR/tombstones/" 2>/dev/null
fi
