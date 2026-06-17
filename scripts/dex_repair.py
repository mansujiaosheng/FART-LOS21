#!/usr/bin/env python3
# dex_repair.py – Stage 2.6: PC-side dex repairer
#
# Takes a dumped dex file + CodeItem dump files (.json + .code)
# and produces a repaired.dex with restored method bodies.
#
# Usage:
#   python3 scripts/dex_repair.py \
#     --dex ./fart_dump/dex_*.dex \
#     --methods ./fart_dump/methods \
#     --out ./repaired.dex \
#     --report ./repair_report.json
"""
Stage 2.6: PC端 dex repairer

输入:
  --dex: 单个 .dex 文件路径（多文件时报错）
  --methods: methods/ 目录路径
  --out: 输出 repaired.dex
  --report: 输出 repair_report.json

只修 tries_size==0 && dump_complete==true 的方法。
不重建 map_list（MVP）。
"""

import argparse
import json
import os
import struct
import sys
from typing import Dict, List, Optional, Set, Tuple, Any

import sys
import os
# Add parent directory to path for imports when running from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dex_structs import (
    DexHeader,
    MethodId,
    ClassDef,
    ClassData,
    EncodedMethod,
    align4,
    compute_checksum,
    compute_signature,
    encode_class_data,
    parse_class_data,
    parse_class_defs,
    parse_method_ids,
    parse_string_ids,
    get_string,
    parse_type_ids,
    decode_uleb128,
)


def load_json(path: str) -> Optional[Dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        return None


def load_code(path: str, expected_size: int) -> Optional[bytes]:
    try:
        data = open(path, 'rb').read()
        if len(data) != expected_size:
            return None
        return data
    except Exception:
        return None


# ──────────────────────────────────────────────
# Core repair logic
# ──────────────────────────────────────────────

class RepairContext:
    """Holds all state needed for one dex repair."""
    def __init__(self, dex_path: str, methods_dir: str):
        self.dex_path = dex_path
        self.methods_dir = methods_dir
        self.data = open(dex_path, 'rb').read()
        self.hdr = DexHeader(self.data)
        self.methods_dir = methods_dir

        # Parse tables
        self.method_ids = parse_method_ids(self.data, self.hdr)
        self.class_defs = parse_class_defs(self.data, self.hdr)
        self.string_offsets = parse_string_ids(self.data, self.hdr)
        self.type_ids = parse_type_ids(self.data, self.hdr)

        # Preload class_data for each class_def
        self.class_data_map: Dict[int, ClassData] = {}  # class_def index -> ClassData
        for i, cd in enumerate(self.class_defs):
            cl = parse_class_data(self.data, cd.class_data_off)
            if cl is not None:
                self.class_data_map[i] = cl

        # Build class_idx -> descriptor map
        self.class_descriptors: Dict[int, str] = {}
        for i, cd in enumerate(self.class_defs):
            type_name_idx = self.type_ids[cd.class_idx]
            self.class_descriptors[i] = get_string(self.data, self.string_offsets, type_name_idx)

        # Build class_idx -> class_def index map
        self.class_idx_to_def_idx: Dict[int, int] = {}
        for i, cd in enumerate(self.class_defs):
            self.class_idx_to_def_idx[cd.class_idx] = i

        # Build method_idx -> method info
        # method_info = dict with class_idx, name_str, class_desc
        self.method_info: Dict[int, Dict] = {}
        for i, mid in enumerate(self.method_ids):
            name = get_string(self.data, self.string_offsets, mid.name_idx)
            desc_off = self.type_ids[mid.class_idx]
            desc = get_string(self.data, self.string_offsets, desc_off)
            self.method_info[i] = {
                'method_idx': i,
                'class_idx': mid.class_idx,
                'name': name,
                'class_desc': desc,
                'def_idx': self.class_idx_to_def_idx.get(mid.class_idx, -1),
            }

    def get_class_data_for_method(self, method_idx: int) -> Optional[Tuple[int, EncodedMethod]]:
        """Find which class_data contains this method, and return (def_idx, encoded_method)."""
        for def_idx, cd in enumerate(self.class_defs):
            cl = self.class_data_map.get(def_idx)
            if cl is None:
                continue
            for m in cl.direct_methods + cl.virtual_methods:
                if m.method_idx == method_idx:
                    return def_idx, m
        return None

    def class_def_idx_for_method(self, method_idx: int) -> int:
        info = self.method_info.get(method_idx)
        if info:
            return info['def_idx']
        return -1


def collect_dumps(methods_dir: str) -> List[Dict]:
    """Collect all valid CodeItem dumps from methods/ directory."""
    dumps = []
    csv_path = os.path.join(methods_dir, 'method_index.csv')
    if not os.path.exists(csv_path):
        # Fallback: list all .json files
        json_files = sorted(f for f in os.listdir(methods_dir) if f.endswith('.json') and f != 'method_index.csv')
    else:
        # Read from CSV
        with open(csv_path) as f:
            lines = f.readlines()
        json_files = []
        for line in lines[1:]:  # Skip header
            parts = line.strip().split(',')
            if len(parts) >= 2:
                # Format: method_idx,sha256_prefix,insns_size,dump_size,status,source
                json_files.append(f"method_{int(parts[0]):08d}_{parts[1]}.json")
        # Also scan directory for any extra jsons
        all_files = set(f for f in os.listdir(methods_dir) if f.endswith('.json') and f != 'method_index.csv')
        for f in all_files:
            if f not in json_files:
                json_files.append(f)

    for jf in json_files:
        jpath = os.path.join(methods_dir, jf)
        dump = load_json(jpath)
        if dump is None:
            continue
        method_idx = dump.get('method_idx')
        if method_idx is None:
            continue
        dump_complete = dump.get('dump_complete', False)
        tries_size = dump.get('tries_size', -1)
        insns_size = dump.get('insns_size', 0)
        dump_size = dump.get('dump_size', 0)

        if not dump_complete or tries_size != 0 or insns_size <= 0:
            continue

        # Verify dump_size
        expected_size = 16 + insns_size * 2
        if dump_size != expected_size:
            continue

        # Find .code file
        # Try multiple naming patterns
        base = jf.replace('.json', '')
        code_paths = [
            os.path.join(methods_dir, f"{base}.code"),
            os.path.join(methods_dir, jf.replace('.json', '.code')),
        ]
        code_data = None
        for cp in code_paths:
            if os.path.exists(cp):
                code_data = load_code(cp, dump_size)
                break

        if code_data is None:
            continue

        dump['_code'] = code_data
        dump['_json_path'] = jpath
        dumps.append(dump)

    return dumps


def run_repair(dex_path: str, methods_dir: str, out_path: str, report_path: str) -> Dict:
    """Main repair routine. Returns report dict."""
    ctx = RepairContext(dex_path, methods_dir)
    data = bytearray(ctx.data)

    # ── Step 1: Collect valid dumps ──
    dumps = collect_dumps(methods_dir)
    # Validate: check method_idx exists in dex, class_desc matches
    valid_dumps = []
    skipped_reasons = {
        'tries_size_gt_0': 0,
        'dump_incomplete': 0,
        'method_not_found': 0,
        'class_mismatch': 0,
        'code_file_missing': 0,
        'insns_size_zero': 0,
    }

    # Re-count manually from directory
    all_json_files = [f for f in os.listdir(methods_dir) if f.endswith('.json') and f != 'method_index.csv']
    total_dumps = len(all_json_files)

    for d in dumps:
        mi = d['method_idx']

        # Check method_idx exists
        if mi >= len(ctx.method_ids):
            skipped_reasons['method_not_found'] += 1
            continue

        # Check class_desc
        expected_desc = d.get('class_desc', '')
        if expected_desc:
            info = ctx.method_info.get(mi)
            if info and info['class_desc'] != expected_desc:
                skipped_reasons['class_mismatch'] += 1
                continue

        valid_dumps.append(d)

    # ── Step 2: Append new CodeItems and record new offsets ──
    code_item_appends: List[Tuple[int, bytes, int]] = []  # (method_idx, code_bytes, new_off)
    append_offset = align4(len(data))  # Start appending at aligned end of dex

    for d in valid_dumps:
        code = d['_code']
        # Align and record
        code_off = append_offset
        append_offset = align4(append_offset + len(code))
        code_item_appends.append((d['method_idx'], code, code_off))

    # Extend data with all new CodeItems
    for _, code, _ in code_item_appends:
        # Align first
        while len(data) % 4 != 0:
            data.append(0)
        data.extend(code)

    # ── Step 3: Build new_class_data map ──
    # Group repairs by class_def index
    repairs_by_def: Dict[int, List[Tuple[int, int]]] = {}  # def_idx -> [(method_idx, new_code_off)]
    for method_idx, _, new_code_off in code_item_appends:
        def_idx = ctx.class_def_idx_for_method(method_idx)
        if def_idx < 0:
            continue
        if def_idx not in repairs_by_def:
            repairs_by_def[def_idx] = []
        repairs_by_def[def_idx].append((method_idx, new_code_off))

    # Build new_class_data map: def_idx -> encoded bytes
    new_class_data_map: Dict[int, bytes] = {}
    repaired_methods = []
    for def_idx, repairs in repairs_by_def.items():
        old_cd = ctx.class_data_map.get(def_idx)
        if old_cd is None:
            continue
        repair_set = {r[0] for r in repairs}
        new_cd = ClassData()
        # Direct methods
        for m in old_cd.direct_methods:
            nm = EncodedMethod(m.method_idx, m.access_flags, m.code_off)
            if m.method_idx in repair_set:
                new_code = dict(repairs)[m.method_idx]
                nm.code_off = new_code
                repaired_methods.append({
                    'method_idx': m.method_idx,
                    'old_code_off': m.code_off,
                    'new_code_off': new_code,
                })
            new_cd.direct_methods.append(nm)
        # Virtual methods
        for m in old_cd.virtual_methods:
            nm = EncodedMethod(m.method_idx, m.access_flags, m.code_off)
            if m.method_idx in repair_set:
                new_code = dict(repairs)[m.method_idx]
                nm.code_off = new_code
                repaired_methods.append({
                    'method_idx': m.method_idx,
                    'old_code_off': m.code_off,
                    'new_code_off': new_code,
                })
            new_cd.virtual_methods.append(nm)
        # Serialize
        new_class_data_map[def_idx] = encode_class_data(new_cd)

    # ── Step 4: Append new class_data_items and update class_defs ──
    patch_class_def_off: Dict[int, int] = {}
    for def_idx, encoded in new_class_data_map.items():
        new_off = align4(len(data))
        while len(data) % 4 != 0:
            data.append(0)
        data.extend(encoded)
        patch_class_def_off[def_idx] = new_off

    # ── Step 5: Update class_def_item.class_data_off ──
    for def_idx, new_class_data_off in patch_class_def_off.items():
        cd = ctx.class_defs[def_idx]
        old_off = cd.class_data_off
        # Patch in data
        class_def_start = ctx.hdr.class_defs_off + def_idx * 32
        struct.pack_into('<I', data, class_def_start + 24, new_class_data_off)

    # ── Step 6: Update header ──
    new_file_size = len(data)
    struct.pack_into('<I', data, 32, new_file_size)    # file_size
    struct.pack_into('<I', data, 104, new_file_size - ctx.hdr.data_off)  # data_size

    # ── Step 7: Update signature (SHA-1) ──
    sig = compute_signature(bytes(data))
    data[12:32] = sig

    # ── Step 8: Update checksum (Adler32) ──
    cksum = compute_checksum(bytes(data))
    struct.pack_into('<I', data, 8, cksum)

    # ── Step 9: Write output ──
    with open(out_path, 'wb') as f:
        f.write(data)

    # ── Build report ──
    methods_skipped = total_dumps - len(valid_dumps) + sum(1 for d in dumps if d not in valid_dumps)
    methods_skipped_explicit = total_dumps - len(valid_dumps)

    report = {
        'input_dex': os.path.basename(dex_path),
        'output_dex': os.path.basename(out_path),
        'methods_total': total_dumps,
        'methods_repaired': len(repaired_methods),
        'methods_skipped': methods_skipped_explicit,
        'skipped_reasons': skipped_reasons,
        'repaired_methods': repaired_methods,
        'map_list_rebuilt': False,
    }

    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[DONE] Repaired {len(repaired_methods)} methods in {os.path.basename(dex_path)}")
    print(f"  Output: {out_path}")
    print(f"  Report: {report_path}")
    return report


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='FART-LOS21 dex repairer (Stage 2.6)')
    parser.add_argument('--dex', required=True, help='Path to dumped DEX file')
    parser.add_argument('--methods', required=True, help='Path to methods/ directory')
    parser.add_argument('--out', required=True, help='Output repaired.dex path')
    parser.add_argument('--report', required=True, help='Output repair_report.json path')
    args = parser.parse_args()

    # Check: single dex only
    dex_path = args.dex
    if not os.path.isfile(dex_path):
        print(f"[ERROR] --dex must be a single file, not found: {dex_path}")
        sys.exit(1)
    if not dex_path.endswith('.dex'):
        print(f"[WARN] --dex doesn't end with .dex: {dex_path}")

    if not os.path.isdir(args.methods):
        print(f"[ERROR] --methods must be a directory: {args.methods}")
        sys.exit(1)

    run_repair(dex_path, args.methods, args.out, args.report)


if __name__ == '__main__':
    main()
