#!/bin/bash
#
# package_module.sh -- Package FART-LOS21 module for APatch/ZygiskNext
#
# Module structure:
#   module.prop
#   customize.sh
#   service.sh
#   config/config.json
#   zygisk/arm64-v8a.so          ← Zygisk loader entry
#   lib64/libfart-hook.so        ← Hook core library
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MODULE_DIR="$PROJECT_DIR/module"
NATIVE_DIR="$PROJECT_DIR/native"
OUT_DIR="$NATIVE_DIR/out"
TEMP_DIR=$(mktemp -d)

echo "📦 Packaging FART-LOS21 module..."

mkdir -p "$TEMP_DIR/zygisk"
mkdir -p "$TEMP_DIR/lib64"
mkdir -p "$TEMP_DIR/config"

# module.prop
cat > "$TEMP_DIR/module.prop" << 'PROP'
id=fart-los21
name=FART-LOS21
version=v1.0.0
versionCode=1
author=fart-los21
description=FART-lite: ART DexFile dumper for LineageOS 21 / Android 14 (arm64, ZygiskNext)
PROP

# Module scripts
cp "$MODULE_DIR/customize.sh" "$TEMP_DIR/"
cp "$MODULE_DIR/service.sh" "$TEMP_DIR/" 2>/dev/null || echo "#!/system/bin/sh" > "$TEMP_DIR/service.sh"
cp "$MODULE_DIR/sepolicy.rule" "$TEMP_DIR/" 2>/dev/null || true

# Config
cp "$PROJECT_DIR/config/config.json" "$TEMP_DIR/config/"

# Binaries
cp "$OUT_DIR/zygisk/arm64-v8a.so" "$TEMP_DIR/zygisk/"
cp "$OUT_DIR/lib64/libfart-hook.so" "$TEMP_DIR/lib64/"

# Create zip
ZIP_FILE="$PROJECT_DIR/fart-los21-module.zip"
cd "$TEMP_DIR"
zip -r "$ZIP_FILE" . > /dev/null
cd - > /dev/null
rm -rf "$TEMP_DIR"

echo "✅ Module zip: $ZIP_FILE ($(ls -lh "$ZIP_FILE" | awk '{print $5}'))"
unzip -l "$ZIP_FILE" 2>/dev/null | grep -v "^Archive\|^$"
