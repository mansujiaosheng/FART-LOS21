#!/system/bin/sh
#
# FART-LOS21 customize.sh -- APatch/Zygisk module install script
#

MODPATH="${0%/*}"

# 仅 arm64
if [ "$(getprop ro.product.cpu.abi)" != "arm64-v8a" ]; then
  abort "FART-LOS21: only arm64 supported"
fi

# 创建 module 内部目录
mkdir -p "$MODPATH/zygisk"
mkdir -p "$MODPATH/lib64"
mkdir -p "$MODPATH/config"

# 设置权限
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0644
set_perm "$MODPATH/lib64/libfart-hook.so" 0 0 0644

# 确保 dump 目录存在
mkdir -p /data/local/tmp/fart

# 复制默认配置到运行时位置
if [ ! -f /data/local/tmp/fart/config.json ]; then
    cp "$MODPATH/config/config.json" /data/local/tmp/fart/config.json 2>/dev/null
fi

ui_print "✅ FART-LOS21 v1.0"
ui_print "  zygisk/arm64-v8a.so  -- loader"
ui_print "  lib64/libfart-hook.so -- hook core"
ui_print "  config/config.json   -- runtime config"
