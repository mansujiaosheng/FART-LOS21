#!/system/bin/sh
#
# FART-LOS21 service.sh - Config bridge + heartbeat
#

MODPATH="${0%/*}"
CTRL_DIR="/data/data/com.fartlos21.controller/files"
FART_DIR="/data/local/tmp/fart"

mkdir -p "$FART_DIR" "$CTRL_DIR" /data/local/tmp/fart_dump /data/local/tmp/fart_dump/methods
cp "$MODPATH/lib64/libfart-hook.so" "$FART_DIR/libfart-hook.so" 2>/dev/null
chmod 755 "$FART_DIR/libfart-hook.so" 2>/dev/null

# Wait for system to settle
sleep 15

# Heartbeat + config polling loop
echo "[FART_LOS21] service.sh started at $(date)" >> "$FART_DIR/module.log"

while true; do
    # Write heartbeat so app can detect module is alive
    echo "alive" > "$CTRL_DIR/.module_heartbeat"
    chmod 777 "$CTRL_DIR/.module_heartbeat"
    cp "$MODPATH/lib64/libfart-hook.so" "$FART_DIR/libfart-hook.so" 2>/dev/null
    chmod 755 "$FART_DIR/libfart-hook.so" 2>/dev/null

    # Write stats for the app
    dex_count=$(ls /data/local/tmp/fart_dump/*.dex 2>/dev/null | wc -l)
    code_count=$(ls /data/local/tmp/fart_dump/methods/*.code 2>/dev/null | wc -l)
    {
        echo "dex:$dex_count"
        echo "code:$code_count"
    } > "$CTRL_DIR/.stats"
    chmod 777 "$CTRL_DIR/.stats"

    if [ -f "$FART_DIR/status" ]; then
        cp "$FART_DIR/status" "$CTRL_DIR/.dump_status" 2>/dev/null
        chmod 777 "$CTRL_DIR/.dump_status" 2>/dev/null
    fi

    if [ -f "$FART_DIR/status" ] && grep -q "已完成 DEX 去重导出" "$FART_DIR/status" 2>/dev/null; then
        if [ -f "$CTRL_DIR/.auto_export" ]; then
            auto=$(cat "$CTRL_DIR/.auto_export" | tr -d '\r\n')
            auto_pkg="${auto%%|*}"
            auto_base="${auto#*|}"
            if [ "$auto_base" = "$auto" ] || [ -z "$auto_base" ]; then
                auto_base="/sdcard/FART-LOS21"
            fi
            auto_base="${auto_base%/}"
            current_count=$(ls /data/local/tmp/fart_dump/*.dex 2>/dev/null | wc -l)
            stable_count=""
            [ -f "$FART_DIR/last_dump_count" ] && stable_count=$(cat "$FART_DIR/last_dump_count")
            echo "$current_count" > "$FART_DIR/last_dump_count"
            auto_key="$auto_pkg|$auto_base|$current_count|$(cat "$FART_DIR/status")"
            last_key=""
            [ -f "$FART_DIR/last_auto_export" ] && last_key=$(cat "$FART_DIR/last_auto_export")
            if [ "$current_count" -gt 0 ] && [ "$stable_count" = "$current_count" ] && [ "$auto_key" != "$last_key" ]; then
                echo "$auto_pkg|$auto_base" > "$CTRL_DIR/.export_trigger"
                echo "$auto_key" > "$FART_DIR/last_auto_export"
            fi
        fi
    fi

    # Poll for config written by the app
    if [ -f "$CTRL_DIR/config.json" ]; then
        if grep -q '"enable"[[:space:]]*:[[:space:]]*true' "$CTRL_DIR/config.json" 2>/dev/null; then
            rm -f /data/local/tmp/fart_dump/*.dex 2>/dev/null
            rm -f /data/local/tmp/fart_dump/methods/* 2>/dev/null
            echo "已允许脱壳，等待目标应用启动" > "$FART_DIR/status"
            rm -f "$FART_DIR/last_auto_export" 2>/dev/null
            rm -f "$FART_DIR/last_dump_count" 2>/dev/null
        else
            echo "已关闭脱壳，目标应用将正常启动" > "$FART_DIR/status"
            rm -f "$CTRL_DIR/.auto_export" 2>/dev/null
        fi
        cp "$CTRL_DIR/config.json" "$MODPATH/config/config.json" 2>/dev/null
        chmod 644 "$MODPATH/config/config.json" 2>/dev/null
        cp "$CTRL_DIR/config.json" "$FART_DIR/config.json" 2>/dev/null
        chmod 644 "$FART_DIR/config.json" 2>/dev/null
        rm "$CTRL_DIR/config.json"
        echo "[FART_LOS21] Config updated from app at $(date)" >> "$FART_DIR/module.log"
    fi

    # Poll for launch trigger (force-stop so next launch gets a fresh zygote fork)
    if [ -f "$CTRL_DIR/.launch_trigger" ]; then
        pkg=$(cat "$CTRL_DIR/.launch_trigger" | tr -d '\r\n')
        if [ -n "$pkg" ]; then
            am force-stop "$pkg" 2>/dev/null
            echo "[FART_LOS21] Force-stopped $pkg at $(date)" >> "$FART_DIR/module.log"
        fi
        rm "$CTRL_DIR/.launch_trigger"
    fi

    # Poll for export trigger
    if [ -f "$CTRL_DIR/.export_trigger" ]; then
        trigger=$(cat "$CTRL_DIR/.export_trigger" | tr -d '\r\n')
        pkg="${trigger%%|*}"
        base_dir="${trigger#*|}"
        if [ "$base_dir" = "$trigger" ] || [ -z "$base_dir" ]; then
            base_dir="/sdcard/FART-LOS21"
        fi
        base_dir="${base_dir%/}"
        dir="$base_dir/$pkg/"
        dex_count=$(ls /data/local/tmp/fart_dump/*.dex 2>/dev/null | wc -l)
        code_count=$(ls /data/local/tmp/fart_dump/methods/*.code 2>/dev/null | wc -l)

        if [ -z "$pkg" ]; then
            echo "ERR|未选择目标应用|0|0|" > "$CTRL_DIR/.export_status"
            echo "报错：未选择目标应用" > "$FART_DIR/status"
        elif [ "$dex_count" -eq 0 ] && [ "$code_count" -eq 0 ]; then
            echo "ERR|未发现 dump 文件，请确认目标应用已启动并触发脱壳|0|0|" > "$CTRL_DIR/.export_status"
            echo "报错：未发现 dump 文件，请确认目标应用已启动并触发脱壳" > "$FART_DIR/status"
        else
            mkdir -p "$dir/methods"
            seen="$FART_DIR/export_seen_hashes"
            : > "$seen"
            for dex in /data/local/tmp/fart_dump/*.dex; do
                [ -f "$dex" ] || continue
                h=$(sha256sum "$dex" 2>/dev/null | awk '{print $1}')
                [ -z "$h" ] && h=$(cksum "$dex" 2>/dev/null | awk '{print $1 "_" $2}')
                [ -z "$h" ] && h=$(basename "$dex")
                if grep -q "^$h$" "$seen" 2>/dev/null; then
                    continue
                fi
                echo "$h" >> "$seen"
                cp "$dex" "$dir/dex_${h}.dex" 2>/dev/null
            done
            cp /data/local/tmp/fart_dump/methods/* "$dir/methods/" 2>/dev/null
            chmod -R 644 "$dir"* 2>/dev/null
            out_dex=$(ls "$dir"/*.dex 2>/dev/null | wc -l)
            out_code=$(ls "$dir"/methods/*.code 2>/dev/null | wc -l)
            if [ "$out_dex" -eq 0 ] && [ "$out_code" -eq 0 ]; then
                echo "ERR|复制失败，请检查 /sdcard/FART-LOS21 权限|0|0|$dir" > "$CTRL_DIR/.export_status"
                echo "报错：复制失败，请检查导出目录权限 $dir" > "$FART_DIR/status"
            else
                echo "OK|导出完成|$out_dex|$out_code|$dir" > "$CTRL_DIR/.export_status"
                echo "已自动导出完成 Dex:$out_dex CodeItem:$out_code $dir" > "$FART_DIR/status"
            fi
        fi
        chmod 777 "$CTRL_DIR/.export_status"
        rm "$CTRL_DIR/.export_trigger"
        echo "[FART_LOS21] Exported to $dir at $(date)" >> "$FART_DIR/module.log"
    fi

    if [ -f "$CTRL_DIR/.log_export_trigger" ]; then
        log_base=$(cat "$CTRL_DIR/.log_export_trigger" | tr -d '\r\n')
        [ -z "$log_base" ] && log_base="/sdcard/FART-LOS21"
        log_base="${log_base%/}"
        log_dir="$log_base/logs"
        mkdir -p "$log_dir"
        ts=$(date +%Y%m%d_%H%M%S)
        out="$log_dir/fart_log_$ts.txt"
        {
            echo "=== FART-LOS21 LOG $ts ==="
            echo
            echo "--- status ---"
            cat "$FART_DIR/status" 2>/dev/null
            echo
            echo "--- controller stats ---"
            cat "$CTRL_DIR/.stats" 2>/dev/null
            echo
            echo "--- temp dump dir ---"
            ls -la /data/local/tmp/fart_dump 2>/dev/null
            ls -la /data/local/tmp/fart_dump/methods 2>/dev/null
            echo
            echo "--- export status ---"
            cat "$CTRL_DIR/.export_status" 2>/dev/null
            echo
            echo "--- auto export ---"
            cat "$CTRL_DIR/.auto_export" 2>/dev/null
            echo
            echo "--- config /data/local/tmp/fart/config.json ---"
            cat "$FART_DIR/config.json" 2>/dev/null
            echo
            echo "--- module config ---"
            cat "$MODPATH/config/config.json" 2>/dev/null
            echo
            echo "--- module.log ---"
            tail -200 "$FART_DIR/module.log" 2>/dev/null
            echo
            echo "--- logcat FART/FART_CTRL tail ---"
            logcat -d -t 300 2>/dev/null | grep -E "FART_LOS21|FART_CTRL|fartlos21" 2>/dev/null
        } > "$out"
        chmod 644 "$out" 2>/dev/null
        echo "OK|日志已导出 $out" > "$CTRL_DIR/.log_export_status"
        chmod 777 "$CTRL_DIR/.log_export_status" 2>/dev/null
        rm "$CTRL_DIR/.log_export_trigger"
    fi

    sleep 2
done
