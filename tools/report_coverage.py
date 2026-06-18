#!/usr/bin/env python3
"""
report_coverage.py — FART-LOS21 Coverage Report Tool

Analyzes DEX methods vs captured code_items to identify coverage gaps.

Usage:
    python3 tools/report_coverage.py \\
        --dex original.dex \\
        --csv method_index.csv \\
        --code-dir fart_dump/ \\
        --out coverage.json

Output:
    coverage.json — Full coverage report with missing methods by class/package
"""

import argparse
import json
import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tools.repair_dex import DexFile, read_uleb128, load_code_records, scan_code_files

DEX_MAGIC = b'dex\n035\x00'


def analyze(dex_path, csv_path, code_dir, out_path):
    print(f"[*] Loading DEX: {dex_path}")
    with open(dex_path, 'rb') as f:
        dex = DexFile(f.read())

    print(f"[*] Loading code records...")
    if csv_path and os.path.exists(csv_path):
        records = load_code_records(csv_path, code_dir)
    else:
        csv_in_dir = os.path.join(code_dir, 'method_index.csv')
        if os.path.exists(csv_in_dir):
            records = load_code_records(csv_in_dir, code_dir)
        else:
            records = {}
            # Key by (dex_key, method_idx) but scan_code_files returns (='', midx)
            scanned = scan_code_files(code_dir)
            for k, v in scanned.items():
                records[k] = v

    print(f"[*] Finding encoded methods...")
    encoded = dex.find_encoded_methods()
    print(f"[*] Found {len(encoded)} encoded methods")

    # Build string table for reading class names
    string_ids_off = dex.string_ids_off
    string_ids_size = dex.string_ids_size
    type_ids_off = dex.type_ids_off
    type_ids_size = dex.type_ids_size
    method_ids_off = dex.method_ids_off

    def read_string(str_idx):
        if str_idx >= string_ids_size:
            return f"<str_{str_idx}>"
        str_off = struct.unpack_from('<I', dex.data, string_ids_off + str_idx * 4)[0]
        if str_off >= len(dex.data):
            return f"<str_{str_idx}_oob>"
        end = dex.data.find(b'\0', str_off)
        if end < 0:
            return f"<str_{str_idx}_nul>"
        return dex.data[str_off:end].decode('utf-8', errors='replace')

    def read_type_str(type_idx):
        if type_idx >= type_ids_size:
            return f"<type_{type_idx}>"
        str_idx = struct.unpack_from('<I', dex.data, type_ids_off + type_idx * 4)[0]
        return read_string(str_idx)

    def get_method_name(method_idx):
        if method_idx >= dex.method_ids_size:
            return f"<method_{method_idx}>"
        off = method_ids_off + method_idx * 8
        class_idx = struct.unpack_from('<H', dex.data, off)[0]
        proto_idx = struct.unpack_from('<H', dex.data, off + 2)[0]
        name_idx = struct.unpack_from('<I', dex.data, off + 4)[0]
        class_name = read_type_str(class_idx)
        method_name = read_string(name_idx)
        return f"{class_name}.{method_name}"

    # Categorize methods
    total = len(encoded)
    abstract_native = 0
    with_code = 0
    missing = 0
    missing_by_class = defaultdict(int)
    missing_by_package = defaultdict(int)
    missing_by_dex_key = defaultdict(int)

    # Access flags
    kAccAbstract = 0x0400
    kAccNative = 0x0100

    for m in encoded:
        if m['access_flags'] & (kAccAbstract | kAccNative):
            abstract_native += 1
        elif m['code_off'] == 0 or m['code_off'] >= len(dex.data):
            missing += 1
            # Get class info
            method_name = get_method_name(m['method_idx'])
            cls = method_name.rsplit('.', 1)[0] if '.' in method_name else '?'
            pkg = '.'.join(cls.split('.')[:-1]) if '.' in cls else '?'
            missing_by_class[cls] += 1
            missing_by_package[pkg] += 1
        else:
            with_code += 1

    print(f"\n[*] Coverage Summary")
    print(f"    Total encoded methods: {total}")
    print(f"    Abstract/native:       {abstract_native}")
    print(f"    With code_off:         {with_code}")
    print(f"    Missing code:          {missing}")

    # Match records to DEX
    code_file_count = len(records)
    matched = 0
    for (dk, midx) in records:
        for m in encoded:
            if m['method_idx'] == midx:
                matched += 1
                break

    print(f"\n[*] Code Items")
    print(f"    Total .code files: {code_file_count}")
    print(f"    Matched to DEX:    {matched}")
    print(f"    Unmatched:         {code_file_count - matched}")

    # Top 20 missing classes
    print(f"\n[*] Top 20 classes with missing code:")
    sorted_classes = sorted(missing_by_class.items(), key=lambda x: -x[1])[:20]
    for cls, count in sorted_classes:
        print(f"    {cls}: {count} methods")

    # Top 10 missing packages
    print(f"\n[*] Top 10 packages with missing code:")
    sorted_pkgs = sorted(missing_by_package.items(), key=lambda x: -x[1])[:10]
    for pkg, count in sorted_pkgs:
        print(f"    {pkg}: {count} methods")

    # Build report
    report = {
        'dex_path': dex_path,
        'total_methods': total,
        'abstract_native_methods': abstract_native,
        'methods_with_code_off': with_code,
        'methods_missing_code': missing,
        'dumped_code_items': code_file_count,
        'matched_code_items': matched,
        'unmatched_code_items': code_file_count - matched,
        'missing_by_class': {k: v for k, v in sorted_classes},
        'missing_by_package': {k: v for k, v in sorted_pkgs},
        'missing_by_dex_key': dict(missing_by_dex_key),
    }

    if out_path:
        with open(out_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[*] Report saved to: {out_path}")

    return report


def main():
    parser = argparse.ArgumentParser(description='FART-LOS21 Coverage Report Tool')
    parser.add_argument('--dex', required=True, help='DEX file to analyze')
    parser.add_argument('--csv', default='', help='method_index.csv path')
    parser.add_argument('--code-dir', default='methods/', help='CodeItem directory')
    parser.add_argument('--out', default='', help='Output coverage.json path')
    args = parser.parse_args()

    analyze(args.dex, args.csv or '', args.code_dir, args.out)


if __name__ == '__main__':
    main()
