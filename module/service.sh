#!/system/bin/sh
#
# FART-LOS21 service.sh - Start injector daemon on boot
# Also sets up LD_PRELOAD for zygote if possible
#

MODPATH="${0%/*}"
FART_DIR="/data/local/tmp/fart"
INJECTOR="$FART_DIR/fart-injector"
HOOK_LIB="$FART_DIR/libfart-hook.so"

mkdir -p "$FART_DIR"

# Wait for system to settle
sleep 15

# Start injector daemon
if [ -f "$INJECTOR" ] && [ -f "$HOOK_LIB" ]; then
    chmod 755 "$INJECTOR"
    chmod 644 "$HOOK_LIB"
    
    # Kill any previous instance
    killall fart-injector 2>/dev/null
    
    # Start injector
    nohup "$INJECTOR" &> "$FART_DIR/injector.log" &
    
    echo "[FART_LOS21] Injector started at $(date)" >> "$FART_DIR/module.log"
else
    echo "[FART_LOS21] Injector or hook lib missing" >> "$FART_DIR/module.log"
fi
