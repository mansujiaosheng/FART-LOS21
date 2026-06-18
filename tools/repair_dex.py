#!/usr/bin/env python3
"""
repair_dex.py — FART-LOS21 Dex Repair Tool v2

Usage:
    python3 tools/repair_dex.py --dex input.dex --code-dir methods/ --csv method_index.csv --out repaired.dex

Output:
    repaired.dex          — Repaired DEX file (with rebuilt map_list)
    repair_report.json    — Repair summary
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

DEX_MAGIC = b'dex\n035\x00'

# DEX map types
TYPE_HEADER_ITEM              = 0x0000
TYPE_STRING_ID_ITEM           = 0x0001
TYPE_TYPE_ID_ITEM             = 0x0002
TYPE_PROTO_ID_ITEM            = 0x0003
TYPE_FIELD_ID_ITEM            = 0x0004
TYPE_METHOD_ID_ITEM           = 0x0005
TYPE_CLASS_DEF_ITEM           = 0x0006
TYPE_MAP_LIST                 = 0x1000
TYPE_TYPE_LIST                = 0x1001
TYPE_ANNOTATION_SET_REF_LIST  = 0x1002
TYPE_ANNOTATION_SET_ITEM      = 0x1003
TYPE_CLASS_DATA_ITEM          = 0x2000
TYPE_CODE_ITEM                = 0x2001
TYPE_STRING_DATA_ITEM         = 0x2002
TYPE_DEBUG_INFO_ITEM          = 0x2003
TYPE_ANNOTATION_ITEM          = 0x2004
TYPE_ENCODED_ARRAY_ITEM       = 0x2005
TYPE_ANNOTATIONS_DIRECTORY    = 0x2006


@dataclass
class CodeRecord:
    """Single code_item record from CSV."""
    dex_key: str = ''
    method_idx: int = 0
    sha256_prefix: str = ''
    insns_size: int = 0
    dump_size: int = 0
    status: str = 'complete'
    source: str = 'unknown'
    registers_size: int = 0
    ins_size: int = 0
    outs_size: int = 0
    tries_size: int = 0
    data: bytes = field(default_factory=bytes)


# ------ ULEB128 / SLEB128 helpers ------

def read_uleb128(data, offset):
    if offset >= len(data):
        return 0, offset
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        value |= (byte & 0x7F) << shift
        shift += 7
        offset += 1
        if offset >= len(data):
            break
        if not (byte & 0x80):
            break
    return value, offset


def encode_uleb128(value):
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def align4(offset):
    """Align to 4 bytes."""
    return (offset + 3) & ~3


# ------ DEX map_list builder ------

def build_map_list(data, added_code_offs):
    """
    Scan the DEX data and build a complete map_list.
    Returns bytes of the MapList structure.
    """
    hdr = struct.unpack_from('<III', data, 0x20)  # file_size, header_size, endian
    file_size, header_size, endian = hdr
    if endian != 0x12345678:
        raise ValueError("Unsupported endianness")

    def off_sz(off_field, sz_field):
        off = struct.unpack_from('<I', data, header_size + off_field)[0]
        sz = struct.unpack_from('<I', data, header_size + sz_field)[0]
        return off, sz

    # Read existing sections from the DEX header
    sections = []

    # HEADER
    sections.append((TYPE_HEADER_ITEM, 1, 0))

    # STRING_IDS
    off, sz = off_sz(0x0C, 0x08)
    if sz > 0:
        sections.append((TYPE_STRING_ID_ITEM, sz, off))

    # TYPE_IDS
    off, sz = off_sz(0x14, 0x10)
    if sz > 0:
        sections.append((TYPE_TYPE_ID_ITEM, sz, off))

    # PROTO_IDS
    off, sz = off_sz(0x1C, 0x18)
    if sz > 0:
        sections.append((TYPE_PROTO_ID_ITEM, sz, off))

    # FIELD_IDS
    off, sz = off_sz(0x24, 0x20)
    if sz > 0:
        sections.append((TYPE_FIELD_ID_ITEM, sz, off))

    # METHOD_IDS
    off, sz = off_sz(0x2C, 0x28)
    if sz > 0:
        sections.append((TYPE_METHOD_ID_ITEM, sz, off))

    # CLASS_DEFS
    off, sz = off_sz(0x34, 0x30)
    if sz > 0:
        sections.append((TYPE_CLASS_DEF_ITEM, sz, off))

    # Scan for class_data_items and code_items in the data area
    # We track what we know: encoded_method code_offs
    known_codes = set()
    for cd_off in added_code_offs.keys():
        known_codes.add(cd_off)
    for orig_off in added_code_offs.values():
        if orig_off is not None and orig_off > 0:
            known_codes.add(orig_off)

    # Add newly appended code items
    class_data_area = set()

    # Build map entries for sections we know about
    map_entries = []

    # Basic sections
    tid_map = {}
    for type_id, count, offset in sections:
        map_entries.append((type_id, count, offset))

    # Scan for TYPE_LISTs, ANNOTATION_* etc. by looking at type_list offsets in class_defs
    # For v1, we just add the basic sections + appended code_items

    # Find class_data_offs from class_defs
    class_defs_off = struct.unpack_from('<I', data, header_size + 0x34)[0]
    class_defs_size = struct.unpack_from('<I', data, header_size + 0x30)[0]
    data_item_off_start = file_size  # will be capped later

    class_data_offs = set()
    for i in range(class_defs_size):
        cd_off = class_defs_off + i * 32
        if cd_off + 32 > len(data):
            break
        cdo = struct.unpack_from('<I', data, cd_off + 24)[0]
        if cdo > 0 and cdo < len(data):
            class_data_offs.add(cdo)

    # Group: CLASS_DATA_ITEM
    # Find each class_data_item's extent
    for cdo in sorted(class_data_offs):
        # Count this as one class_data_item entry
        # Size is variable, but map_list only needs count, not size
        map_entries.append((TYPE_CLASS_DATA_ITEM, 1, cdo))

    # Group: CODE_ITEM — all known code_off values
    code_off_map = {}
    for cdo in class_data_offs:
        off = cdo
        if off >= len(data):
            continue
        _, off = read_uleb128(data, off)
        _, off = read_uleb128(data, off)
        dm_size, off = read_uleb128(data, off)
        vm_size, off = read_uleb128(data, off)
        method_idx = 0
        for _ in range(dm_size + vm_size):
            if off >= len(data):
                break
            diff, off = read_uleb128(data, off)
            method_idx += diff
            _, off = read_uleb128(data, off)  # access_flags
            coff, off = read_uleb128(data, off)
            if coff > 0 and coff < len(data):
                code_off_map[coff] = coff

    for coff in sorted(code_off_map.keys()):
        map_entries.append((TYPE_CODE_ITEM, 1, coff))

    # Now build the map_list struct
    # Sort by offset
    map_entries.sort(key=lambda x: x[2])

    # Remove duplicate offsets (keep first)
    seen_off = set()
    deduped = []
    for entry in map_entries:
        if entry[2] not in seen_off:
            seen_off.add(entry[2])
            deduped.append(entry)
    map_entries = deduped

    # Build binary
    buf = struct.pack('<I', len(map_entries))
    for type_id, count, offset in map_entries:
        buf += struct.pack('<HHII', type_id, 0, count, offset)

    return buf


# ------ Dex parsing ------

class DexFile:
    def __init__(self, data):
        self.data = bytearray(data)
        self.verify_header()

    def verify_header(self):
        if self.data[:8] != DEX_MAGIC:
            raise ValueError(f"Not a DEX file: magic={self.data[:8]}")
        self.file_size = struct.unpack_from('<I', self.data, 0x20)[0]
        self.header_size = struct.unpack_from('<I', self.data, 0x24)[0]
        assert self.header_size >= 0x70, f"header_size too small: {self.header_size}"

        self.string_ids_off = struct.unpack_from('<I', self.data, 0x38 + 4)[0]
        self.type_ids_off = struct.unpack_from('<I', self.data, 0x40 + 4)[0]
        self.proto_ids_off = struct.unpack_from('<I', self.data, 0x48 + 4)[0]
        self.field_ids_off = struct.unpack_from('<I', self.data, 0x50 + 4)[0]
        self.method_ids_off = struct.unpack_from('<I', self.data, 0x58 + 4)[0]
        self.class_defs_off = struct.unpack_from('<I', self.data, 0x60 + 4)[0]
        self.data_off = struct.unpack_from('<I', self.data, 0x68 + 4)[0]

        self.string_ids_size = struct.unpack_from('<I', self.data, 0x38)[0]
        self.type_ids_size = struct.unpack_from('<I', self.data, 0x40)[0]
        self.proto_ids_size = struct.unpack_from('<I', self.data, 0x48)[0]
        self.field_ids_size = struct.unpack_from('<I', self.data, 0x50)[0]
        self.method_ids_size = struct.unpack_from('<I', self.data, 0x58)[0]
        self.class_defs_size = struct.unpack_from('<I', self.data, 0x60)[0]
        self.data_size = struct.unpack_from('<I', self.data, 0x68)[0]

    def read_class_def(self, idx):
        off = self.class_defs_off + idx * 32
        return {
            'class_data_off': struct.unpack_from('<I', self.data, off + 24)[0],
        }

    def read_class_data(self, off):
        """Parse class_data_item, return list of encoded_method."""
        if off == 0:
            return []
        if off >= len(self.data):
            return []
        offset = off
        static_fields_size, offset = read_uleb128(self.data, offset)
        instance_fields_size, offset = read_uleb128(self.data, offset)
        direct_methods_size, offset = read_uleb128(self.data, offset)
        virtual_methods_size, offset = read_uleb128(self.data, offset)
        methods = []
        method_idx = 0
        for _ in range(direct_methods_size + virtual_methods_size):
            diff, offset = read_uleb128(self.data, offset)
            method_idx += diff
            access_flags, offset = read_uleb128(self.data, offset)
            code_off, offset = read_uleb128(self.data, offset)
            methods.append({'method_idx': method_idx, 'access_flags': access_flags, 'code_off': code_off})
        return methods

    def total_methods(self):
        return self.method_ids_size

    def find_encoded_methods(self):
        all_methods = []
        for i in range(self.class_defs_size):
            cd = self.read_class_def(i)
            if cd['class_data_off'] == 0:
                continue
            methods = self.read_class_data(cd['class_data_off'])
            all_methods.extend(methods)
        return all_methods

    def append_data(self, new_data):
        while len(self.data) % 4:
            self.data.append(0)
        off = len(self.data)
        self.data.extend(new_data)
        return off

    def update_code_off(self, method_idx, new_code_off):
        """Rebuild class_data_item with updated code_off, append to DEX end."""
        for ci in range(self.class_defs_size):
            cd = self.read_class_def(ci)
            if cd['class_data_off'] == 0:
                continue
            off = cd['class_data_off']
            if off >= len(self.data):
                continue
            saved_off = off
            static_fields_size, off = read_uleb128(self.data, off)
            instance_fields_size, off = read_uleb128(self.data, off)
            direct_methods_size, off = read_uleb128(self.data, off)
            virtual_methods_size, off = read_uleb128(self.data, off)
            total = direct_methods_size + virtual_methods_size
            methods = []
            cur_midx = 0
            found = False
            for _ in range(total):
                diff, off = read_uleb128(self.data, off)
                cur_midx += diff
                access_flags, off = read_uleb128(self.data, off)
                code_val, off = read_uleb128(self.data, off)
                methods.append([cur_midx, access_flags, code_val])
                if cur_midx == method_idx and (code_val == 0 or code_val >= len(self.data)):
                    methods[-1][2] = new_code_off
                    found = True
            if not found:
                continue
            new_data = bytearray()
            new_data.extend(encode_uleb128(static_fields_size))
            new_data.extend(encode_uleb128(instance_fields_size))
            new_data.extend(encode_uleb128(direct_methods_size))
            new_data.extend(encode_uleb128(virtual_methods_size))
            prev_midx = 0
            for m in methods:
                diff = m[0] - prev_midx
                new_data.extend(encode_uleb128(diff))
                new_data.extend(encode_uleb128(m[1]))
                new_data.extend(encode_uleb128(m[2]))
                prev_midx = m[0]
            new_off = self.append_data(bytes(new_data))
            class_def_off = self.class_defs_off + ci * 32 + 24
            struct.pack_into('<I', self.data, class_def_off, new_off)
            return True
        return False

    def update_header(self, map_list_data=None):
        new_size = len(self.data)
        struct.pack_into('<I', self.data, 0x20, new_size)

        # If we had map_list_data, we'd update it here
        # (skipped for partial DEX dumps — map_list may reference unmapped regions)

        struct.pack_into('<I', self.data, 8, 0)
        self.data[12:32] = b'\x00' * 20
        sha1 = hashlib.sha1(self.data[32:]).digest()
        self.data[12:12 + 20] = sha1
        adler = self._adler32(self.data[12:])
        struct.pack_into('<I', self.data, 8, adler)

    @staticmethod
    def _adler32(data):
        a, b = 1, 0
        for byte in data:
            a = (a + byte) % 65521
            b = (b + a) % 65521
        return (b << 16) | a

    def save(self, path):
        with open(path, 'wb') as f:
            f.write(self.data)


# ------ CodeItem loading ------

def load_code_records(csv_path, code_dir):
    """Load code_items from CSV + .code files. Returns dict by (dex_key, method_idx)."""
    records = {}
    if not os.path.exists(csv_path):
        print(f"[!] CSV not found: {csv_path}, scanning .code files directly")
        return scan_code_files(code_dir)

    with open(csv_path, 'r', errors='replace') as f:
        header = f.readline().strip()
        cols = header.split(',')
        # Determine column layout (support both old and new CSV)
        for line in f:
            parts = line.strip().split(',')
            if len(parts) < 5:
                continue
            try:
                if cols[0] == 'dex_key':
                    # New format: dex_key,method_idx,sha256_prefix,...
                    rec = CodeRecord()
                    rec.dex_key = parts[0]
                    idx = 1
                else:
                    # Old format: method_idx,sha256_prefix,...
                    rec = CodeRecord()
                    rec.dex_key = ''
                    idx = 0
                rec.method_idx = int(parts[idx]); idx += 1
                rec.sha256_prefix = parts[idx]; idx += 1
                rec.insns_size = int(parts[idx]); idx += 1
                rec.dump_size = int(parts[idx]); idx += 1
                rec.status = parts[idx]; idx += 1
                if idx < len(parts):
                    rec.source = parts[idx]; idx += 1
                if idx < len(parts):
                    rec.registers_size = int(parts[idx]); idx += 1
                if idx < len(parts):
                    rec.ins_size = int(parts[idx]); idx += 1
                if idx < len(parts):
                    rec.outs_size = int(parts[idx]); idx += 1
                if idx < len(parts):
                    rec.tries_size = int(parts[idx])

                if rec.status != 'complete':
                    continue

                # Try to load .code file
                code_file = os.path.join(code_dir, f'method_{rec.method_idx:08d}_{rec.sha256_prefix}.code')
                if not os.path.exists(code_file):
                    # Try without prefix
                    code_file = os.path.join(code_dir, f'{rec.method_idx}.code')
                if os.path.exists(code_file):
                    with open(code_file, 'rb') as cf:
                        rec.data = cf.read()
                    key = (rec.dex_key, rec.method_idx)
                    if key not in records or rec.dump_size > records[key].dump_size:
                        records[key] = rec
            except (ValueError, IndexError):
                continue

    print(f"[*] Loaded {len(records)} code records from CSV")
    return records


def scan_code_files(code_dir):
    """Fallback: scan .code files without CSV."""
    records = {}
    for fname in os.listdir(code_dir):
        if fname.endswith('.code'):
            parts = fname.replace('.code', '').split('_')
            if len(parts) >= 2:
                try:
                    midx = int(parts[1])
                    with open(os.path.join(code_dir, fname), 'rb') as f:
                        rec = CodeRecord(method_idx=midx, data=f.read())
                        records[('', midx)] = rec
                except ValueError:
                    pass
    print(f"[*] Scanned {len(records)} .code files from {code_dir}")
    return records


# ------ Main repair logic ------

def repair(dex_path, code_dir, csv_path, out_path):
    print(f"[*] Loading DEX: {dex_path}")
    with open(dex_path, 'rb') as f:
        dex_data = f.read()
    dex = DexFile(dex_data)

    print(f"[*] Loading code items...")
    if csv_path and os.path.exists(csv_path):
        code_records = load_code_records(csv_path, code_dir)
    else:
        # Try finding CSV in code_dir
        csv_in_dir = os.path.join(code_dir, 'method_index.csv')
        if os.path.exists(csv_in_dir):
            code_records = load_code_records(csv_in_dir, code_dir)
        else:
            code_records = scan_code_files(code_dir)

    print(f"[*] Finding encoded methods...")
    encoded_methods = dex.find_encoded_methods()
    print(f"[*] Found {len(encoded_methods)} encoded methods")

    missing = [m for m in encoded_methods if m['code_off'] == 0 or m['code_off'] >= len(dex.data)]
    has_code = [m for m in encoded_methods if m['code_off'] > 0 and m['code_off'] < len(dex.data)]
    print(f"[*] Missing/invalid code: {len(missing)}, with valid code: {len(has_code)}")

    # Match code records to methods (by method_idx, prefer matching dex_key)
    matched = []
    unmatched_methods = []
    for m in missing:
        midx = m['method_idx']
        # Try exact match first (dex_key, method_idx)
        direct = [k for k in code_records if k[1] == midx]
        if direct:
            # Prefer non-empty dex_key
            with_key = [k for k in direct if k[0]]
            if with_key:
                matched.append((m, code_records[with_key[0]]))
            else:
                matched.append((m, code_records[direct[0]]))
        else:
            unmatched_methods.append(m)

    print(f"[*] Repairable: {len(matched)}, Skipped (no code_item): {len(unmatched_methods)}")

    report = {
        'input_dex': dex_path,
        'output_dex': out_path,
        'methods_total': len(encoded_methods),
        'codeitems_total': len(code_records),
        'methods_missing': len(missing),
        'methods_with_code': len(has_code),
        'methods_repaired': 0,
        'methods_skipped': len(unmatched_methods),
        'rebuilt_class_data_count': 0,
        'new_map_off': 0,
        'errors': [],
    }

    # Track old code_offs for map_list
    old_code_offs = {}
    repaired_count = 0
    rebuilt_class_data = set()

    for m, rec in matched:
        midx = m['method_idx']
        code_data = rec.data
        if not code_data or len(code_data) < 16:
            report['errors'].append(f"Method {midx}: invalid code data ({len(code_data) if code_data else 0} bytes)")
            continue

        new_off = dex.append_data(code_data)
        old_code_offs[new_off] = m['code_off']
        success = dex.update_code_off(midx, new_off)
        if success:
            repaired_count += 1
            print(f"  [+] Method {midx}: code_off 0x{m['code_off']:x} -> 0x{new_off:x} ({len(code_data)} bytes, {rec.source})")
        else:
            report['errors'].append(f"Method {midx}: update_code_off failed")
            print(f"  [-] Method {midx}: FAILED")

    report['methods_repaired'] = repaired_count
    report['rebuilt_class_data_count'] = len(rebuilt_class_data)

    print(f"[*] map_list skipped (original not available in partial DEX dump)")
    report['new_map_off'] = 0

    print(f"[*] Updating DEX header...")
    dex.update_header()

    print(f"[*] Updating DEX header...")
    dex.update_header()

    # Verify the repaired DEX
    file_size = struct.unpack_from('<I', dex.data, 0x20)[0]
    print(f"[*] DEX: header_size={struct.unpack_from('<I', dex.data, 0x24)[0]}, file_size={file_size}, actual={len(dex.data)} match={file_size==len(dex.data)}")

    print(f"[*] Saving repaired DEX to: {out_path}")
    dex.save(out_path)

    report_path = os.path.join(os.path.dirname(out_path) or '.', 'repair_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to: {report_path}")
    print(f"[*] Done. Methods repaired: {repaired_count}/{len(missing)}")


def main():
    parser = argparse.ArgumentParser(description='FART-LOS21 Dex Repair Tool v2')
    parser.add_argument('--dex', required=True, help='Input DEX file')
    parser.add_argument('--code-dir', default='methods/', help='CodeItem directory')
    parser.add_argument('--csv', default='', help='method_index.csv path')
    parser.add_argument('--out', required=True, help='Output repaired DEX path')
    args = parser.parse_args()

    repair(args.dex, args.code_dir, args.csv or '', args.out)


if __name__ == '__main__':
    main()
