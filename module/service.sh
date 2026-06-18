#!/system/bin/sh
#
# FART-LOS21 service.sh - Config bridge + heartbeat
#

MODPATH="${0%/*}"
CTRL_DIR="/data/data/com.fartlos21.controller/files"
FART_DIR="/data/local/tmp/fart"

mkdir -p "$FART_DIR" "$CTRL_DIR"

# Wait for system to settle
sleep 15

# Heartbeat + config polling loop
echo "[FART_LOS21] service.sh started at $(date)" >> "$FART_DIR/module.log"

while true; do
    # Write heartbeat so app can detect module is alive
    echo "alive" > "$CTRL_DIR/.module_heartbeat"
    chmod 777 "$CTRL_DIR/.module_heartbeat"

    # Write stats for the app
    dex_count=$(ls /data/local/tmp/fart_dump/*.dex 2>/dev/null | wc -l)
    code_count=$(ls /data/local/tmp/fart_dump/methods/*.code 2>/dev/null | wc -l)
    {
        echo "dex:$dex_count"
        echo "code:$code_count"
    } > "$CTRL_DIR/.stats"
    chmod 777 "$CTRL_DIR/.stats"

    # Poll for config written by the app
    if [ -f "$CTRL_DIR/config.json" ]; then
        cp "$CTRL_DIR/config.json" "$MODPATH/config/config.json" 2>/dev/null
        chmod 644 "$MODPATH/config/config.json" 2>/dev/null
        rm "$CTRL_DIR/config.json"
        echo "[FART_LOS21] Config updated from app at $(date)" >> "$FART_DIR/module.log"
    fi

    # Poll for export trigger
    if [ -f "$CTRL_DIR/.export_trigger" ]; then
        pkg=$(cat "$CTRL_DIR/.export_trigger")
        dir="/sdcard/FART-LOS21/$pkg/"
        mkdir -p "$dir/methods"
        cp /data/local/tmp/fart_dump/*.dex "$dir/" 2>/dev/null
        cp /data/local/tmp/fart_dump/methods/* "$dir/methods/" 2>/dev/null
        chmod -R 644 "$dir"* 2>/dev/null
        rm "$CTRL_DIR/.export_trigger"
        echo "[FART_LOS21] Exported to $dir at $(date)" >> "$FART_DIR/module.log"
    fi

    sleep 2
done
