#!/usr/bin/env python3
"""Fix DEX file checksum and signature for memory-dumped DEX files.

When a packer modifies DEX data in memory, the checksum and SHA-1 signature
become invalid. This tool recomputes them so tools like jadx can load the DEX.

DEX header layout:
  0x00-0x07: magic ("dex\n035\0" or "dex\n039\0")
  0x08-0x0B: checksum (Adler32 of bytes[12:])
  0x0C-0x1F: SHA-1 signature of bytes[32:]
  0x20-0x23: file size

Usage:
  python3 fix_dex_checksum.py <dex_file> [dex_file2 ...]
"""

import sys
import struct
import hashlib
import zlib


def fix_dex(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if len(data) < 0x24:
        print(f"  SKIP: too small ({len(data)} bytes)")
        return False

    if data[0:3] != b'dex':
        print(f"  SKIP: not a DEX file")
        return False

    # Fix SHA-1 signature (bytes 0x0C-0x1F = SHA-1 of bytes[0x20:])
    sha1 = hashlib.sha1(bytes(data[0x20:])).digest()
    old_sig = bytes(data[0x0C:0x20])
    data[0x0C:0x20] = sha1

    # Fix Adler32 checksum (bytes 0x08-0x0B = Adler32 of bytes[0x0C:])
    checksum = zlib.adler32(bytes(data[0x0C:])) & 0xFFFFFFFF
    old_cksum = struct.unpack_from('<I', data, 0x08)[0]
    struct.pack_into('<I', data, 0x08, checksum)

    sig_fixed = old_sig != sha1
    cksum_fixed = old_cksum != checksum

    if sig_fixed or cksum_fixed:
        with open(path, 'wb') as f:
            f.write(data)
        print(f"  FIXED: checksum 0x{old_cksum:08x} -> 0x{checksum:08x}, sig {'changed' if sig_fixed else 'ok'}")
        return True
    else:
        print(f"  OK: already valid")
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dex_file> [dex_file2 ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        print(f"Fixing: {path}")
        fix_dex(path)
