#!/bin/bash
set -e
SD="$(cd "$(dirname "$0")" && pwd)"
BD="$SD/build"
AJ="/lina_android/lineage/packages/apps/Seedvault/libs/aosp/android.jar"
DX="/lina_android/lineage/prebuilts/build-tools/common/bin/dx"
PKG="com.fartlos21.controller"

echo "=== FART\u63a7\u5236\u5668 Build ==="
rm -rf "$BD"
mkdir -p "$BD/classes"

# Generate binary AndroidManifest.xml via build_simple.py
echo "  binary AXML..."
python3 "$SD/build_simple.py" "$BD"

# Compile Java
echo "  javac..."
javac -source 8 -target 8 -cp "$AJ" -d "$BD/classes" \
  "$SD/app/src/main/java/com/fartlos21/controller/"*.java 2>&1 | grep -v warning

# DEX
echo "  dx..."
cd "$BD/classes" && "$DX" --dex --min-sdk-version 34 --output="$BD/classes.dex" \
  com/fartlos21/controller/*.class 2>&1

# Package APK
echo "  apk..."
cd "$BD"
# Use the binary manifest (either from aapt2 or generated)
if [ ! -f "$BD/AndroidManifest.xml" ]; then
    echo "Generating binary AXML..."
    python3 "$SD/build_simple.py" "$BD"
fi

python3 -c "
import zipfile, os
bd = '$BD'
axml_path = os.path.join(bd, 'AndroidManifest.xml')
dex_path = os.path.join(bd, 'classes.dex')
if not os.path.exists(axml_path):
    print('ERROR: no AXML')
    exit(1)
with zipfile.ZipFile(os.path.join(bd, 'unsigned.apk'), 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.write(axml_path, 'AndroidManifest.xml')
    zf.write(dex_path, 'classes.dex')
print('APK packaged')
"

# Sign
[ -f "$BD/debug.keystore" ] || keytool -genkey -v -keystore "$BD/debug.keystore" -storepass android -alias a -keypass android -keyalg RSA -dname "CN=A" -validity 10000 2>/dev/null
echo "  sign..."
java -jar /lina_android/lineage/tools/apksig/build/apksigner.jar sign \
  --min-sdk-version 34 --ks "$BD/debug.keystore" --ks-pass pass:android \
  --ks-key-alias a --out "$BD/FARTController.apk" "$BD/unsigned.apk" 2>&1
rm -f "$BD/unsigned.apk"
echo "=== OK ==="
ls -lh "$BD/FARTController.apk"
