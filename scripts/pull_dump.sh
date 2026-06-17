#!/bin/bash
#
# pull_dump.sh - Pull FART dump results from device
#
# Usage: ./pull_dump.sh [output_dir]
#

ADB_HOST="${ADB_HOST:-192.168.238.1}"
ADB_PORT="${ADB_PORT:-5037}"

adb_cmd() {
    adb -H "$ADB_HOST" -P "$ADB_PORT" "$@"
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${1:-$PROJECT_DIR/fart_dump}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${YELLOW}Pulling FART dump from device...${NC}"
echo ""

adb_cmd devices | grep -q "device$" || {
    echo -e "${RED}❌ Device not connected${NC}"
    exit 1
}

# Check dump directory
DUMP_FILES=$(adb_cmd shell su -c 'find /data/local/tmp/fart -type f -maxdepth 4 -ls 2>/dev/null | head -100')

if [ -z "$DUMP_FILES" ]; then
    echo -e "${YELLOW}No dump files found on device${NC}"
    echo "Checked: /data/local/tmp/fart/"
    exit 0
fi

echo "Files on device:"
echo "$DUMP_FILES"
echo ""

mkdir -p "$OUTPUT_DIR"
adb_cmd pull /data/local/tmp/fart "$OUTPUT_DIR" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Dump pulled to: $OUTPUT_DIR${NC}"
    echo ""
    
    # Show dex files
    echo "Dex files:"
    find "$OUTPUT_DIR" -name '*.dex' -ls 2>/dev/null | head -20
    
    echo ""
    echo "Dex count: $(find "$OUTPUT_DIR" -name '*.dex' 2>/dev/null | wc -l)"
    echo "Total size: $(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)"
else
    echo -e "${RED}❌ Pull failed${NC}"
    exit 1
fi
