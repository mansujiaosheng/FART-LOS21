#!/system/bin/sh
# fartctl - FART-LOS21 Module Control Program
# Manage FART module config and run dex_scanner from your phone
# Usage: fartctl [command] [args]
#        fartctl (interactive mode)

CONFIG_PATH="/data/local/tmp/fart/config.json"
MODULE_DIR="/data/adb/modules/fart-los21"
DEX_SCANNER="/data/local/tmp/dex_scanner"
DEFAULT_DUMP_DIR="/data/local/tmp/fart_dump"

# Colors (if terminal supports)
R='\033[0;31m'
G='\033[0;32m'
Y='\033[0;33m'
B='\033[0;34m'
C='\033[0;36m'
N='\033[0m'

# ---- JSON helpers (no jq dependency, Android sed compatible) ----
# Android toybox sed: no \s (use [[:space:]]), no \| in basic regex (use -E)
# Use sed -E for extended regex where alternation (|) is needed

json_get_bool() {
    local key="$1" file="$2"
    sed -En "s/.*\"${key}\":[[:space:]]*(true|false).*/\1/p" "$file" | head -1
}

json_get_num() {
    local key="$1" file="$2"
    sed -En "s/.*\"${key}\":[[:space:]]*([0-9]+).*/\1/p" "$file" | head -1
}

json_get_str() {
    local key="$1" file="$2"
    sed -En "s/.*\"${key}\":[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | head -1
}

json_get_array() {
    local key="$1" file="$2"
    sed -En "s/.*\"${key}\":[[:space:]]*\[([^]]*)\].*/\1/p" "$file" | head -1 | \
        sed 's/"//g; s/,/ /g' | tr -s ' '
}

json_set_bool() {
    local key="$1" val="$2" file="$3"
    local old
    old=$(json_get_bool "$key" "$file")
    [ "$old" = "$val" ] && return
    sed -i "s/\"${key}\":[[:space:]]*${old}/\"${key}\":${val}/" "$file"
}

json_set_num() {
    local key="$1" val="$2" file="$3"
    local old
    old=$(json_get_num "$key" "$file")
    [ "$old" = "$val" ] && return
    sed -i "s/\"${key}\":[[:space:]]*${old}/\"${key}\":${val}/" "$file"
}

json_set_str() {
    local key="$1" val="$2" file="$3"
    local old
    old=$(json_get_str "$key" "$file")
    [ "$old" = "$val" ] && return
    sed -i "s/\"${key}\":[[:space:]]*\"${old}\"/\"${key}\":\"${val}\"/" "$file"
}

json_set_packages() {
    local pkgs="$1" file="$2"
    local arr="["
    local first=1
    for p in $pkgs; do
        [ $first -eq 0 ] && arr="${arr},"
        arr="${arr}\"${p}\""
        first=0
    done
    arr="${arr}]"
    sed -i "s/\"packages\":[[:space:]]*\[[^]]*\]/\"packages\":${arr}/" "$file"
}

# ---- Config sync ----
sync_config() {
    # The module's service.sh copies from module dir to /data/local/tmp/fart/
    # So we also update the module dir copy
    if [ -f "${MODULE_DIR}/config.json" ]; then
        cp "$CONFIG_PATH" "${MODULE_DIR}/config.json"
    fi
}

# ---- Display functions ----
show_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "${R}Config not found: $CONFIG_PATH${N}"
        return 1
    fi
    echo "${B}===== FART-LOS21 Current Config =====${N}"
    echo "${C}Config file:${N} $CONFIG_PATH"
    echo ""

    local enable=$(json_get_bool enable "$CONFIG_PATH")
    local pkgs=$(json_get_array packages "$CONFIG_PATH")
    local dump_dir=$(json_get_str dump_dir "$CONFIG_PATH")
    local dump_dex=$(json_get_bool dump_dex "$CONFIG_PATH")
    local art_hook=$(json_get_bool enable_artmethod_hook "$CONFIG_PATH")
    local delay=$(json_get_num dump_dex_delay_ms "$CONFIG_PATH")

    echo "  enable:            ${G}${enable}${N}"
    echo "  packages:          ${Y}${pkgs}${N}"
    echo "  dump_dir:          ${Y}${dump_dir}${N}"
    echo "  dump_dex:          ${G}${dump_dex}${N}"
    echo "  enable_artmethod:  ${G}${art_hook}${N}"
    echo "  dump_dex_delay_ms: ${Y}${delay}${N}"

    echo ""
    if [ "$dump_dex" = "false" ] && [ "$delay" != "0" ]; then
        echo "${G}Mode: NOHOOK (safe for packer detection bypass)${N}"
    elif [ "$dump_dex" = "true" ]; then
        echo "${Y}Mode: DEX DUMP (hook-based, may trigger packer detection)${N}"
    else
        echo "${R}Mode: DISABLED${N}"
    fi
}

show_status() {
    echo "${B}===== FART-LOS21 Status =====${N}"

    # Check module
    if [ -d "$MODULE_DIR" ]; then
        echo "${G}Module installed:${N} $MODULE_DIR"
        if [ -f "${MODULE_DIR}/disable" ]; then
            echo "${R}  Status: DISABLED (disable file exists)${N}"
        else
            echo "${G}  Status: ENABLED${N}"
        fi
    else
        echo "${R}Module NOT found at $MODULE_DIR${N}"
    fi

    # Check SO files
    echo ""
    echo "SO files:"
    for f in "${MODULE_DIR}/lib64/libfart-hook.so" "${MODULE_DIR}/zygisk/arm64-v8a.so" \
             "/data/local/tmp/fart/libfart-hook.so"; do
        if [ -f "$f" ]; then
            local sz=$(ls -l "$f" 2>/dev/null | awk '{print $5}')
            echo "  ${G}[OK]${N} $f (${sz} bytes)"
        else
            echo "  ${R}[MISSING]${N} $f"
        fi
    done

    # Check dex_scanner
    echo ""
    if [ -x "$DEX_SCANNER" ]; then
        echo "${G}dex_scanner:${N} $DEX_SCANNER (ready)"
    else
        echo "${R}dex_scanner:${N} not found at $DEX_SCANNER"
    fi

    # Show recent dumps
    echo ""
    echo "Recent DEX dumps:"
    local dump_dir=$(json_get_str dump_dir "$CONFIG_PATH")
    dump_dir=${dump_dir:-$DEFAULT_DUMP_DIR}
    if [ -d "$dump_dir" ]; then
        local count=$(ls "$dump_dir"/*.dex 2>/dev/null | wc -l)
        echo "  ${dump_dir}: ${count} DEX files"
        ls -lt "$dump_dir"/*.dex 2>/dev/null | head -5 | while read line; do
            echo "    $line"
        done
    else
        echo "  ${dump_dir}: (empty or not exists)"
    fi
}

# ---- Package management ----
list_packages() {
    echo "${B}===== Target Packages =====${N}"
    local pkgs=$(json_get_array packages "$CONFIG_PATH")
    if [ -z "$pkgs" ]; then
        echo "${R}No packages configured${N}"
        return
    fi
    local i=1
    for p in $pkgs; do
        echo "  ${i}. ${Y}${p}${N}"
        # Check if running
        local pid=$(pidof "$p" 2>/dev/null || echo "")
        if [ -n "$pid" ]; then
            echo "     ${G}RUNNING (PID: $pid)${N}"
        else
            echo "     not running"
        fi
        i=$((i + 1))
    done
}

add_package() {
    local pkg="$1"
    [ -z "$pkg" ] && { echo "${R}Usage: fartctl add <package_name>${N}"; return 1; }
    local pkgs=$(json_get_array packages "$CONFIG_PATH")
    # Check duplicate
    for p in $pkgs; do
        [ "$p" = "$pkg" ] && { echo "${Y}Already in list: $pkg${N}"; return 0; }
    done
    pkgs="${pkgs} ${pkg}"
    json_set_packages "$pkgs" "$CONFIG_PATH"
    sync_config
    echo "${G}Added: $pkg${N}"
    show_config
}

remove_package() {
    local pkg="$1"
    [ -z "$pkg" ] && { echo "${R}Usage: fartctl remove <package_name>${N}"; return 1; }
    local pkgs=$(json_get_array packages "$CONFIG_PATH")
    local new_pkgs=""
    local found=0
    for p in $pkgs; do
        if [ "$p" = "$pkg" ]; then
            found=1
        else
            new_pkgs="${new_pkgs} ${p}"
        fi
    done
    [ $found -eq 0 ] && { echo "${Y}Not found: $pkg${N}"; return 0; }
    json_set_packages "$new_pkgs" "$CONFIG_PATH"
    sync_config
    echo "${G}Removed: $pkg${N}"
    show_config
}

# ---- Mode switching ----
set_nohook() {
    json_set_bool dump_dex false "$CONFIG_PATH"
    json_set_bool enable_artmethod_hook false "$CONFIG_PATH"
    json_set_num dump_dex_delay_ms 500 "$CONFIG_PATH"
    sync_config
    echo "${G}Switched to NOHOOK mode (safe for packer bypass)${N}"
    show_config
}

set_hook() {
    json_set_bool dump_dex true "$CONFIG_PATH"
    json_set_num dump_dex_delay_ms 0 "$CONFIG_PATH"
    sync_config
    echo "${Y}Switched to HOOK mode (dump_dex=true, may trigger packer detection)${N}"
    show_config
}

set_enable() {
    json_set_bool enable true "$CONFIG_PATH"
    sync_config
    echo "${G}FART module ENABLED${N}"
}

set_disable() {
    json_set_bool enable false "$CONFIG_PATH"
    sync_config
    echo "${R}FART module DISABLED${N}"
}

set_dumpdir() {
    local dir="$1"
    [ -z "$dir" ] && { echo "${R}Usage: fartctl dumpdir <path>${N}"; return 1; }
    json_set_str dump_dir "$dir" "$CONFIG_PATH"
    sync_config
    mkdir -p "$dir"
    echo "${G}Dump directory set to: $dir${N}"
}

# ---- DEX Scanner ----
scan_dex() {
    local pkg="$1"
    if [ -z "$pkg" ]; then
        # Try first configured package
        pkg=$(json_get_array packages "$CONFIG_PATH" | awk '{print $1}')
    fi
    [ -z "$pkg" ] && { echo "${R}No package specified. Usage: fartctl scan <package>${N}"; return 1; }

    if [ ! -x "$DEX_SCANNER" ]; then
        echo "${R}dex_scanner not found at $DEX_SCANNER${N}"
        echo "Push it with: adb push dex_scanner /data/local/tmp/dex_scanner"
        return 1
    fi

    local pid=$(pidof "$pkg" 2>/dev/null || echo "")
    if [ -z "$pid" ]; then
        echo "${R}App $pkg is not running!${N}"
        echo "Launch the app first, then run this command."
        return 1
    fi

    local dump_dir=$(json_get_str dump_dir "$CONFIG_PATH")
    dump_dir=${dump_dir:-$DEFAULT_DUMP_DIR}

    echo "${B}===== Running dex_scanner =====${N}"
    echo "  Package: ${Y}${pkg}${N}"
    echo "  PID:     ${Y}${pid}${N}"
    echo "  Output:  ${Y}${dump_dir}${N}"
    echo ""

    $DEX_SCANNER "$pid" "$dump_dir"

    echo ""
    echo "${G}Scan complete. DEX files saved to: $dump_dir${N}"
    local count=$(ls "$dump_dir"/*.dex 2>/dev/null | wc -l)
    echo "Total DEX files: $count"
}

# ---- Quick dump: launch app and scan ----
quick_dump() {
    local pkg="$1"
    if [ -z "$pkg" ]; then
        pkg=$(json_get_array packages "$CONFIG_PATH" | awk '{print $1}')
    fi
    [ -z "$pkg" ] && { echo "${R}No package specified. Usage: fartctl dump <package>${N}"; return 1; }

    echo "${B}===== Quick Dump: $pkg =====${N}"

    # Set nohook mode if not already
    local dump_dex=$(json_get_bool dump_dex "$CONFIG_PATH")
    local delay=$(json_get_num dump_dex_delay_ms "$CONFIG_PATH")
    if [ "$dump_dex" != "false" ] || [ "$delay" = "0" ]; then
        echo "${Y}Switching to nohook mode for safe dump...${N}"
        set_nohook
    fi

    # Add package if not in list
    local pkgs=$(json_get_array packages "$CONFIG_PATH")
    local found=0
    for p in $pkgs; do
        [ "$p" = "$pkg" ] && found=1
    done
    [ $found -eq 0 ] && add_package "$pkg"

    # Force stop and relaunch
    echo "${Y}Force stopping $pkg...${N}"
    am force-stop "$pkg"
    sleep 1

    echo "${Y}Launching $pkg...${N}"
    monkey -p "$pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || \
        am start -n "$pkg/$(cmd package resolve-activity -c android.intent.category.LAUNCHER $pkg 2>/dev/null | grep -o '^[^/]*' | head -1)" 2>/dev/null

    echo "${Y}Waiting for app to load (8 seconds)...${N}"
    sleep 8

    # Scan
    scan_dex "$pkg"
}

# ---- Pull dumps to PC ----
pull_dumps() {
    local out_dir="$1"
    local dump_dir=$(json_get_str dump_dir "$CONFIG_PATH")
    dump_dir=${dump_dir:-$DEFAULT_DUMP_DIR}

    if [ -z "$out_dir" ]; then
        echo "${Y}Usage: fartctl pull <local_dir>${N}"
        echo "  Pulls DEX files from device to local machine via adb"
        echo "  Example: fartctl pull ./dump_output"
        return 1
    fi

    # This only works if running from adb host side
    echo "${Y}Note: Use 'adb pull $dump_dir/ $out_dir/' from your PC instead${N}"
    echo "  Or copy files manually from: $dump_dir"
}

# ---- Fix DEX checksums ----
fix_dex() {
    local dump_dir=$(json_get_str dump_dir "$CONFIG_PATH")
    dump_dir=${dump_dir:-$DEFAULT_DUMP_DIR}

    if [ ! -d "$dump_dir" ]; then
        echo "${R}Dump directory not found: $dump_dir${N}"
        return 1
    fi

    local count=0
    local fixed=0
    for dex in "$dump_dir"/*.dex; do
        [ ! -f "$dex" ] && continue
        count=$((count + 1))
        # dex_scanner already fixes checksums, but if using other tools:
        if command -v python3 >/dev/null 2>&1; then
            python3 /data/local/tmp/fix_dex_checksum.py "$dex" 2>/dev/null
            fixed=$((fixed + 1))
        else
            echo "${Y}python3 not available, skipping fix for $(basename $dex)${N}"
        fi
    done

    if [ $count -eq 0 ]; then
        echo "${Y}No DEX files found in $dump_dir${N}"
    else
        echo "Checked $count DEX files, fixed $fixed"
    fi
}

# ---- Running apps list ----
list_running() {
    echo "${B}===== Running Apps (with packer detection) =====${N}"
    ps -A -o PID,NAME 2>/dev/null | grep -v "^PID" | while read pid name; do
        # Check if it's a user app (has /data/data)
        local pkg_dir="/data/data/$name"
        [ -d "$pkg_dir" ] || continue
        # Check if it has SO files (likely packed)
        local has_so=$(grep -c "\.so$" "/proc/$pid/maps" 2>/dev/null || echo "0")
        local has_dex=$(grep -c "dex" "/proc/$pid/maps" 2>/dev/null || echo "0")
        if [ "$has_so" -gt 0 ] || [ "$has_dex" -gt 0 ]; then
            printf "  %-8s %-40s SO:%-3s DEX:%-3s\n" "$pid" "$name" "$has_so" "$has_dex"
        fi
    done
}

# ---- Interactive menu ----
interactive() {
    while true; do
        echo ""
        echo "${B}===== FART-LOS21 Controller =====${N}"
        echo "  1) Show config"
        echo "  2) Show status"
        echo "  3) List target packages"
        echo "  4) Add target package"
        echo "  5) Remove target package"
        echo "  6) Set NOHOOK mode (safe)"
        echo "  7) Set HOOK mode (dump_dex)"
        echo "  8) Enable FART module"
        echo "  9) Disable FART module"
        echo "  s) Scan DEX (running app)"
        echo "  d) Quick dump (restart + scan)"
        echo "  l) List running apps"
        echo "  f) Fix DEX checksums"
        echo "  q) Quit"
        echo ""
        printf "  Choice: "
        read choice

        case "$choice" in
            1) show_config ;;
            2) show_status ;;
            3) list_packages ;;
            4)
                printf "  Package name: "
                read pkg
                add_package "$pkg"
                ;;
            5)
                printf "  Package name: "
                read pkg
                remove_package "$pkg"
                ;;
            6) set_nohook ;;
            7) set_hook ;;
            8) set_enable ;;
            9) set_disable ;;
            s)
                printf "  Package (empty=first configured): "
                read pkg
                scan_dex "$pkg"
                ;;
            d)
                printf "  Package (empty=first configured): "
                read pkg
                quick_dump "$pkg"
                ;;
            l) list_running ;;
            f) fix_dex ;;
            q) echo "Bye!"; exit 0 ;;
            *) echo "${R}Invalid choice${N}" ;;
        esac
    done
}

# ---- Main ----
case "${1:-}" in
    config|show|info)
        show_config
        ;;
    status)
        show_status
        ;;
    list|ls|packages)
        list_packages
        ;;
    add)
        add_package "$2"
        ;;
    remove|rm|del)
        remove_package "$2"
        ;;
    nohook|safe)
        set_nohook
        ;;
    hook|full)
        set_hook
        ;;
    enable|on)
        set_enable
        ;;
    disable|off)
        set_disable
        ;;
    dumpdir)
        set_dumpdir "$2"
        ;;
    scan)
        scan_dex "$2"
        ;;
    dump|quick)
        quick_dump "$2"
        ;;
    pull)
        pull_dumps "$2"
        ;;
    fix)
        fix_dex
        ;;
    running|apps)
        list_running
        ;;
    help|--help|-h|"")
        if [ -z "${1:-}" ]; then
            interactive
        fi
        echo "${B}FART-LOS21 Controller (fartctl)${N}"
        echo ""
        echo "Usage: fartctl <command> [args]"
        echo ""
        echo "Commands:"
        echo "  config              Show current config"
        echo "  status              Show module status and SO files"
        echo "  list                List target packages"
        echo "  add <pkg>           Add target package"
        echo "  remove <pkg>        Remove target package"
        echo "  nohook              Switch to NOHOOK mode (safe for packer bypass)"
        echo "  hook                Switch to HOOK mode (dump_dex=true)"
        echo "  enable              Enable FART module"
        echo "  disable             Disable FART module"
        echo "  dumpdir <path>      Set dump output directory"
        echo "  scan [pkg]          Scan DEX of running app with dex_scanner"
        echo "  dump [pkg]          Quick dump: restart app + scan DEX"
        echo "  fix                 Fix DEX checksums in dump dir"
        echo "  running             List running apps with SO/DEX in memory"
        echo "  help                Show this help"
        echo ""
        echo "Run without arguments for interactive mode."
        ;;
    *)
        echo "${R}Unknown command: $1${N}"
        echo "Run 'fartctl help' for usage."
        ;;
esac
