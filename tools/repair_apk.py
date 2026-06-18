#!/usr/bin/env python3
"""
repair_apk.py — FART-LOS21 APK-level DEX repair tool

Extracts carrier DEX files from an APK, matches them with dumped DEX
files from a FART session, and repairs all method bodies.

Usage:
    python3 tools/repair_apk.py \\
        --apk target.apk \\
        --dump-dir fart_dump/session/ \\
        --out repaired_apk/
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools.repair_dex import DexFile, repair


def compute_dex_key(data):
    """Compute dex_key from DEX data: sha256(first 4KB)[:16] + hex(dex_size)."""
    if len(data) < 4096:
        prefix = data
    else:
        prefix = data[:4096]
    h = hashlib.sha256(prefix).hexdigest()[:16]
    size_hex = f"{len(data):08x}"[-8:]
    return h + size_hex


def extract_apk_dexes(apk_path, out_dir):
    """Extract all classes*.dex from an APK.
    Returns list of (filename, filepath, dex_key).
    """
    dexes = []
    with zipfile.ZipFile(apk_path, 'r') as zf:
        for name in zf.namelist():
            if not name.endswith('.dex'):
                continue
            if not name.startswith('classes') and name != 'classes.dex':
                continue
            print(f"  Extracting: {name}")
            data = zf.read(name)
            fpath = os.path.join(out_dir, name)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, 'wb') as f:
                f.write(data)
            dk = compute_dex_key(data)
            dexes.append((name, fpath, dk, data))
    return dexes


def find_dump_dexes(dump_dir):
    """Scan dump directory for dumped DEX files.
    Returns dict of dex_key -> filepath.
    """
    dumped = {}
    # Check all subdirectories recursively
    for root, dirs, files in os.walk(dump_dir):
        for fname in files:
            if not fname.endswith('.dex'):
                continue
            if fname.startswith('dex_'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read()
                    if data[:4] != b'dex\n':
                        continue
                    dk = compute_dex_key(data)
                    # Keep the largest dumped DEX for each key (best-effort)
                    if dk not in dumped or len(data) > len(open(dumped[dk], 'rb').read()):
                        dumped[dk] = fpath
                except Exception:
                    continue
    return dumped


def find_code_dir(dump_dir):
    """Find the methods/ directory in the dump."""
    for root, dirs, files in os.walk(dump_dir):
        if 'method_index.csv' in files:
            return root
    return None


def main():
    parser = argparse.ArgumentParser(description='FART-LOS21 APK-level DEX Repair')
    parser.add_argument('--apk', required=True, help='Target APK file')
    parser.add_argument('--dump-dir', required=True, help='FART dump directory')
    parser.add_argument('--out', required=True, help='Output directory for repaired APK')
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    # Step 1: Extract carrier DEXes from APK
    print("[*] Extracting carrier DEXes from APK...")
    with tempfile.TemporaryDirectory() as tmpdir:
        carrier_dexes = extract_apk_dexes(args.apk, tmpdir)
        print(f"[*] Found {len(carrier_dexes)} carrier DEX files")

        # Step 2: Find dumped DEX files
        print(f"[*] Scanning dump directory: {args.dump_dir}")
        dumped_dexes = find_dump_dexes(args.dump_dir)
        print(f"[*] Found {len(dumped_dexes)} dumped DEX files")

        # Step 3: Find code directory
        code_dir = find_code_dir(args.dump_dir)
        if code_dir:
            csv_path = os.path.join(code_dir, 'method_index.csv')
            print(f"[*] Code directory: {code_dir}")
            print(f"[*] CSV file: {csv_path}")
        else:
            csv_path = ''
            code_dir = args.dump_dir
            print(f"[!] No method_index.csv found, scanning .code files directly")

        # Step 4: Match carriers to dumped dexes by size
        print(f"\n[*] Matching carrier DEXes to dumped DEXes...")
        report = {
            'apk': args.apk,
            'dump_dir': args.dump_dir,
            'output_dir': args.out,
            'carrier_count': len(carrier_dexes),
            'dumped_count': len(dumped_dexes),
            'repaired_dexes': [],
            'errors': [],
        }

        for cname, cpath, ckey, cdata in carrier_dexes:
            carrier_size = len(cdata)
            best_match = None
            best_score = 0

            for dk, dp in dumped_dexes.items():
                with open(dp, 'rb') as f:
                    ddata = f.read()
                # Score: how well does this dump match the carrier?
                # Check method_ids count (should be close)
                if len(ddata) < 112:
                    continue
                d_mids = struct.unpack_from('<I', ddata, 0x58)[0]
                c_mids = struct.unpack_from('<I', cdata, 0x58)[0]
                # Also check class_defs count
                d_cds = struct.unpack_from('<I', ddata, 0x60)[0]
                c_cds = struct.unpack_from('<I', cdata, 0x60)[0]

                # Score based on matching metadata
                score = 0
                if d_mids == c_mids:
                    score += 50
                elif abs(d_mids - c_mids) < 100:
                    score += 30
                if d_cds == c_cds:
                    score += 50
                elif abs(d_cds - c_cds) < 100:
                    score += 30

                if score > best_score:
                    best_score = score
                    best_match = (cname, dp, ddata)

            if best_match and best_score > 20:
                cname, dp, ddata = best_match
                out_name = cname.replace('.dex', '_repaired.dex')
                out_path = os.path.join(args.out, out_name)

                print(f"\n  [+] {cname}")
                print(f"      carrier: {carrier_size} bytes, {struct.unpack_from('<I', cdata, 0x58)[0]} methods")
                print(f"      dumped:  {len(ddata)} bytes, {struct.unpack_from('<I', ddata, 0x58)[0]} methods")
                print(f"      match score: {best_score}")

                try:
                    repair(dp, code_dir, csv_path, out_path, cpath)
                    report['repaired_dexes'].append({
                        'dex': cname,
                        'carrier_size': carrier_size,
                        'dumped_size': len(ddata),
                        'output': out_name,
                        'status': 'repaired',
                    })
                except Exception as e:
                    print(f"  [!] Repair failed for {cname}: {e}")
                    report['errors'].append(f"{cname}: {e}")
                    # Fallback: copy carrier as-is
                    shutil.copy(cpath, out_path)
            else:
                print(f"\n  [-] {cname}: no matching dump found (best score={best_score})")
                # Copy carrier as-is (no repair needed)
                out_path = os.path.join(args.out, cname)
                shutil.copy(cpath, out_path)
                report['repaired_dexes'].append({
                    'dex': cname,
                    'status': 'unchanged (no matching dump)',
                })

    # Step 5: Generate report
    report_path = os.path.join(args.out, 'repair_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Report saved to: {report_path}")
    print(f"[*] Done. {len([x for x in report['repaired_dexes'] if x['status'] == 'repaired'])} DEX files repaired.")


if __name__ == '__main__':
    main()
