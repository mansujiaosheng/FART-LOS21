#!/usr/bin/env python3
"""
check_art_symbols.py - Analyze device libart.so for FART hook points.

Usage:
    uv run python check_art_symbols.py [--libart /path/to/libart.so]
"""

import subprocess
import sys
import os
import re
import json
from pathlib import Path

# ADB settings
ADB_HOST = os.environ.get("ADB_HOST", "192.168.238.1")
ADB_PORT = os.environ.get("ADB_PORT", "5037")

PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LIBART = PROJECT_DIR / "libart_device.so"


def adb_cmd(*args):
    cmd = ["adb", "-H", ADB_HOST, "-P", ADB_PORT] + list(args)
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(errors="replace")


def readelf_symbols(elf_path, dynamic_only=False):
    """Read all symbols from an ELF file using readelf."""
    cmd = ["readelf", "-Ws" if not dynamic_only else "-Ws", str(elf_path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Try with just -s
        cmd = ["readelf", "-s" if not dynamic_only else "-Ws", str(elf_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)

    symbols = []
    for line in result.stdout.split("\n"):
        m = re.match(
            r"\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\d+)\s+(.+)",
            line,
        )
        if m:
            symbols.append(
                {
                    "num": int(m.group(1)),
                    "value": int(m.group(2), 16) if m.group(2) != "0000000000000000" else 0,
                    "size": int(m.group(3)),
                    "type": m.group(4),
                    "bind": m.group(5),
                    "vis": m.group(6),
                    "ndx": m.group(7),
                    "name": m.group(8).split("@")[0],  # remove version suffix
                }
            )
    return symbols


def check_device_libart():
    """Pull libart from device and analyze."""
    print("=" * 60)
    print("  FART-LOS21 ART Symbol Analysis")
    print("=" * 60)

    # Check device connection
    try:
        output = adb_cmd("devices")
        if "device" not in output:
            print("❌ Device not connected. Aborting.")
            return
        print("✅ Device connected")
    except Exception as e:
        print(f"❌ ADB error: {e}")
        return

    # Check libart on device
    try:
        ls_output = adb_cmd("shell", "kp", "-c", "ls -l /apex/com.android.art/lib64/libart.so")
        print(f"📁 Device libart: {ls_output.strip()}")
    except Exception as e:
        print(f"❌ Cannot access libart: {e}")
        return

    # Pull if not already present
    if not DEFAULT_LIBART.exists():
        print("📥 Pulling libart.so from device...")
        try:
            subprocess.run(
                ["adb", "-H", ADB_HOST, "-P", ADB_PORT, "pull",
                 "/apex/com.android.art/lib64/libart.so", str(DEFAULT_LIBART)],
                check=True, capture_output=True
            )
            print(f"✅ Pulled to {DEFAULT_LIBART}")
        except Exception as e:
            print(f"❌ Pull failed: {e}")
            return

    # Analyze symbols
    print(f"\n{'─' * 60}")
    print("  Dynamic Symbol Analysis (.dynsym)")
    print(f"{'─' * 60}")
    syms = readelf_symbols(DEFAULT_LIBART, dynamic_only=True)

    # Filter interesting ART symbols
    interesting_keywords = [
        "ClassLinker", "ArtMethod", "DexFile", "DefineClass",
        "InsertClass", "FindClass", "OpenCommon", "DexFileLoader",
        "Invoke", "interpreter", "Execute",
    ]

    print("\n🔍 Exported symbols matching FART targets:")
    print(f"{'Offset':>12}  {'Size':>6}  {'Name'}")
    print(f"{'─'*12}  {'─'*6}  {'─'*50}")

    useful_symbols = []
    for sym in syms:
        for kw in interesting_keywords:
            if kw.lower() in sym["name"].lower() and sym["value"] > 0:
                useful_symbols.append(sym)
                print(f"  0x{sym['value']:08x}  {sym['size']:>6}  {sym['name']}")
                break

    # Try to demangle
    print(f"\n{'─' * 60}")
    print("  Demangled key symbols")
    print(f"{'─' * 60}")
    for sym in useful_symbols[:20]:
        try:
            demangled = subprocess.run(
                ["c++filt", sym["name"]], capture_output=True, text=True
            ).stdout.strip()
            print(f"  {demangled}")
        except Exception:
            pass

    # Summary
    print(f"\n{'─' * 60}")
    print("  Summary")
    print(f"{'─' * 60}")
    print(f"  Total dynamic symbols: {len(syms)}")
    print(f"  Useful ART symbols:    {len(useful_symbols)}")
    print()

    # Check for the key hook targets
    key_targets = {
        "DefineClass": "ClassLinker::DefineClass",
        "ArtMethod::Invoke": "ArtMethod::Invoke",
        "FindClassInBaseDexClassLoader": "FindClassInBaseDexClassLoader",
        "InsertClass": "InsertClass",
    }

    print("  Key hook target status:")
    for demangled, desc in key_targets.items():
        found = any(demangled.lower() in s["name"].lower() for s in useful_symbols)
        status = "✅ Exported" if found else "❌ NOT exported (need inline hook)"
        print(f"    {desc:45s} {status}")

    print()
    print("  Recommended hooks (exported, useful for first version):")
    print("    - ClassLinker::FindClassInBaseDexClassLoader")
    print("    - ClassLinker::InsertClass (after class is defined, has mirror::Class*)")
    print()

    # Save analysis
    output = PROJECT_DIR / "art_symbol_analysis.json"
    data = {
        "libart_path": str(DEFAULT_LIBART),
        "libart_size": DEFAULT_LIBART.stat().st_size,
        "total_dynamic_symbols": len(syms),
        "useful_symbols": [
            {"offset": f"0x{s['value']:x}", "size": s["size"], "name": s["name"]}
            for s in useful_symbols
        ],
    }
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  📄 Analysis saved to: {output}")


if __name__ == "__main__":
    check_device_libart()
