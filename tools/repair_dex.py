#!/usr/bin/env python3
"""
repair_dex.py — FART-LOS21 Dex Repair Tool

Reads a dumped DEX file and CodeItem directory, then repairs the DEX
by appending real code_items and updating code_off in encoded_methods.

Usage:
    python3 repair_dex.py --dex input.dex --code-dir methods/ --out repaired.dex

Output:
    repaired.dex          — Repaired DEX file
    repair_report.json    — Repair summary
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEX_MAGIC = b'dex\n035\x00'

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

def read_sleb128(data, offset):
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        value |= (byte & 0x7F) << shift
        shift += 7
        offset += 1
        if not (byte & 0x80):
            if byte & 0x40:
                value |= -(1 << shift)
            break
    return value, offset


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
        """Parse class_data_item, return list of encoded_method (direct then virtual)."""
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
            methods.append({
                'method_idx': method_idx,
                'access_flags': access_flags,
                'code_off': code_off,
            })
        return methods

    def total_methods(self):
        return self.method_ids_size

    def find_encoded_methods(self):
        """Find all encoded_methods from all class_defs."""
        all_methods = []
        for i in range(self.class_defs_size):
            cd = self.read_class_def(i)
            if cd['class_data_off'] == 0:
                continue
            methods = self.read_class_data(cd['class_data_off'])
            all_methods.extend(methods)
        return all_methods

    def find_missing_code_items(self, encoded_methods):
        """Return encoded_methods where code_off == 0 (no code_item)."""
        missing = [m for m in encoded_methods if m['code_off'] == 0]
        return missing

    def append_data(self, new_data):
        """Append data to the end of the DEX, return the offset where it was written."""
        # Align to 4 bytes
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
            # Parse counts
            static_fields_size, off = read_uleb128(self.data, off)
            instance_fields_size, off = read_uleb128(self.data, off)
            direct_methods_size, off = read_uleb128(self.data, off)
            virtual_methods_size, off = read_uleb128(self.data, off)

            total = direct_methods_size + virtual_methods_size

            # Parse all encoded_methods
            methods = []
            cur_midx = 0
            found = False
            for _ in range(total):
                diff, off = read_uleb128(self.data, off)
                cur_midx += diff
                access_flags, off = read_uleb128(self.data, off)
                code_val, off = read_uleb128(self.data, off)
                methods.append([cur_midx, access_flags, code_val])
                if cur_midx == method_idx and code_val == 0:
                    methods[-1][2] = new_code_off
                    found = True

            if not found:
                continue

            # Re-encode the entire class_data_item
            new_data = bytearray()
            new_data.extend(self._encode_uleb128(static_fields_size))
            new_data.extend(self._encode_uleb128(instance_fields_size))
            new_data.extend(self._encode_uleb128(direct_methods_size))
            new_data.extend(self._encode_uleb128(virtual_methods_size))
            prev_midx = 0
            for m in methods:
                diff = m[0] - prev_midx
                new_data.extend(self._encode_uleb128(diff))
                new_data.extend(self._encode_uleb128(m[1]))  # access_flags
                new_data.extend(self._encode_uleb128(m[2]))  # code_off
                prev_midx = m[0]

            # Append to DEX end
            new_off = self.append_data(bytes(new_data))

            # Update class_def's class_data_off
            class_def_off = self.class_defs_off + ci * 32 + 24
            struct.pack_into('<I', self.data, class_def_off, new_off)

            return True

        return False

    @staticmethod
    def _encode_uleb128(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def update_header(self):
        """Recalculate and update file_size, signature, checksum."""
        new_size = len(self.data)
        struct.pack_into('<I', self.data, 0x20, new_size)

        # Clear checksum (offset 8) and signature (offset 12, 20 bytes)
        struct.pack_into('<I', self.data, 8, 0)
        self.data[12:32] = b'\x00' * 20

        # Signature = SHA-1 of everything after signature field (from offset 32)
        sha1 = hashlib.sha1(self.data[32:]).digest()
        self.data[12:12 + 20] = sha1

        # Checksum = adler32 of everything after checksum field (from offset 12)
        # Note: Android uses adler32 starting from offset 12 (after checksum field)
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


# ------ Main repair logic ------

def load_code_items(code_dir):
    """Load code_item files from methods/ directory.
    Returns dict mapping method_idx -> {data, registers_size, ...}
    """
    items = {}
    csv_path = os.path.join(code_dir, 'method_index.csv')
    if os.path.exists(csv_path):
        with open(csv_path, 'r', errors='replace') as f:
            for line in f:
                if line.startswith('method_idx'):
                    continue
                parts = line.strip().split(',')
                if len(parts) >= 5:
                    method_idx = int(parts[0])
                    sha_prefix = parts[1]
                    insns_size = int(parts[2])
                    dump_size = int(parts[3])
                    status = parts[4]
                    source = parts[5] if len(parts) > 5 else 'unknown'
                    if status == 'complete':
                        code_file = os.path.join(code_dir, f'method_{method_idx:08d}_{sha_prefix}.code')
                        json_file = os.path.join(code_dir, f'method_{method_idx:08d}_{sha_prefix}.json')
                        if os.path.exists(code_file):
                            with open(code_file, 'rb') as cf:
                                data = cf.read()
                                items[method_idx] = {
                                    'data': data,
                                    'source': source,
                                    'sha_prefix': sha_prefix,
                                }
        # Also try loading by method_idx without prefix
        for fname in os.listdir(code_dir):
            if fname.endswith('.code') and fname.startswith('method_'):
                parts = fname.split('_')
                if len(parts) >= 2:
                    try:
                        midx = int(parts[1])
                        if midx not in items:
                            with open(os.path.join(code_dir, fname), 'rb') as cf:
                                items[midx] = {'data': cf.read(), 'source': 'direct', 'sha_prefix': fname.split('_')[2].split('.')[0]}
                    except ValueError:
                        pass
    else:
        # No CSV, scan .code files
        for fname in os.listdir(code_dir):
            if fname.endswith('.code') and fname.startswith('method_'):
                parts = fname.split('_')
                if len(parts) >= 2:
                    try:
                        midx = int(parts[1])
                        with open(os.path.join(code_dir, fname), 'rb') as cf:
                            items[midx] = {'data': cf.read(), 'source': 'direct', 'sha_prefix': fname.split('_')[2].split('.')[0]}
                    except ValueError:
                        pass
    return items


def repair(dex_path, code_dir, out_path):
    print(f"[*] Loading DEX: {dex_path}")
    with open(dex_path, 'rb') as f:
        dex_data = f.read()
    dex = DexFile(dex_data)

    print(f"[*] Loading code_items from: {code_dir}")
    code_items = load_code_items(code_dir)
    print(f"[*] Loaded {len(code_items)} code items")

    print(f"[*] Finding encoded methods...")
    encoded_methods = dex.find_encoded_methods()
    print(f"[*] Found {len(encoded_methods)} encoded methods")

    missing = [m for m in encoded_methods if m['code_off'] == 0]
    print(f"[*] Methods without code: {len(missing)}")

    available = [m for m in missing if m['method_idx'] in code_items]
    skipped = [m for m in missing if m['method_idx'] not in code_items]
    print(f"[*] Repairable: {len(available)}, Skipped (no code_item): {len(skipped)}")

    report = {
        'input_dex': dex_path,
        'output_dex': out_path,
        'methods_total': len(encoded_methods),
        'codeitems_available': len(code_items),
        'methods_repaired': 0,
        'methods_skipped': len(skipped),
        'errors': [],
    }

    # Repair each missing method
    repaired_count = 0
    for m in available:
        midx = m['method_idx']
        ci = code_items[midx]
        code_data = ci['data']

        # Append code_item to DEX
        new_off = dex.append_data(code_data)

        # Update code_off in encoded_method
        success = dex.update_code_off(midx, new_off)
        if success:
            repaired_count += 1
            print(f"  [+] Method {midx}: code_off -> 0x{new_off:x}")
        else:
            # Fallback: rebuild from scratch not implemented yet
            report['errors'].append(f"Method {midx}: failed to patch code_off (size mismatch)")
            print(f"  [-] Method {midx}: FAILED to patch code_off")

    report['methods_repaired'] = repaired_count

    print(f"[*] Updating DEX header...")
    dex.update_header()

    print(f"[*] Saving repaired DEX to: {out_path}")
    dex.save(out_path)

    report_path = os.path.join(os.path.dirname(out_path) or '.', 'repair_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report saved to: {report_path}")
    print(f"[*] Done. Methods repaired: {repaired_count}/{len(missing)}")


def main():
    parser = argparse.ArgumentParser(description='FART-LOS21 Dex Repair Tool')
    parser.add_argument('--dex', required=True, help='Input DEX file')
    parser.add_argument('--code-dir', required=True, help='CodeItem directory (methods/)')
    parser.add_argument('--out', required=True, help='Output repaired DEX path')
    args = parser.parse_args()

    repair(args.dex, args.code_dir, args.out)


if __name__ == '__main__':
    main()
