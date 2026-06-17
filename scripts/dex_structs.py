# dex_structs.py – DEX file format structures + ULEB128/SLEB128
#
# Reference: https://source.android.com/docs/core/runtime/dex-format
#
# DEX Header:          0x70 bytes
# StringIds:           string_ids_off, string_ids_size * 4
# TypeIds:             type_ids_off, type_ids_size * 4
# ProtoIds:            proto_ids_off, proto_ids_size * 12
# FieldIds:            field_ids_off, field_ids_size * 8
# MethodIds:           method_ids_off, method_ids_size * 8
# ClassDefs:           class_defs_off, class_defs_size * 32
# DataSection:         data_off, data_size
# MapList:             map_off

import struct
import hashlib
import zlib
from typing import Tuple, List, Optional, Dict, Any

# ──────────────────────────────────────────────
# ULEB128 / SLEB128
# ──────────────────────────────────────────────

def decode_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode ULEB128 at offset, returns (value, new_offset)."""
    value = 0
    shift = 0
    pos = offset
    while True:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if (byte & 0x80) == 0:
            break
    return value, pos


def encode_uleb128(value: int) -> bytes:
    """Encode an unsigned integer as ULEB128."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def decode_sleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode SLEB128 at offset, returns (value, new_offset)."""
    value = 0
    shift = 0
    pos = offset
    while True:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if (byte & 0x80) == 0:
            if (byte & 0x40) != 0:  # sign bit
                value |= -(1 << shift)
            break
    return value, pos


def encode_sleb128(value: int) -> bytes:
    """Encode a signed integer as SLEB128."""
    result = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


# ──────────────────────────────────────────────
# ULEB128 tests (run with python3 dex_structs.py)
# ──────────────────────────────────────────────

def _test_uleb128():
    test_values = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456]
    for v in test_values:
        enc = encode_uleb128(v)
        dec, _ = decode_uleb128(enc, 0)
        assert dec == v, f"ULEB128 roundtrip failed: {v} -> {enc.hex()} -> {dec}"
    print(f"[OK] ULEB128 roundtrip: {len(test_values)} values")


def _test_sleb128():
    test_values = [0, -1, 1, -127, 127, -128, 16383, -16384, 2097151, -2097152]
    for v in test_values:
        enc = encode_sleb128(v)
        dec, _ = decode_sleb128(enc, 0)
        assert dec == v, f"SLEB128 roundtrip failed: {v} -> {enc.hex()} -> {dec}"
    print(f"[OK] SLEB128 roundtrip: {len(test_values)} values")


# ──────────────────────────────────────────────
# DEX Parsing
# ──────────────────────────────────────────────

DEX_MAGIC_035 = b'dex\n035\x00'
DEX_MAGIC_037 = b'dex\n037\x00'
DEX_MAGIC_038 = b'dex\n038\x00'
DEX_MAGIC_039 = b'dex\n039\x00'
DEX_MAGICS = {DEX_MAGIC_035, DEX_MAGIC_037, DEX_MAGIC_038, DEX_MAGIC_039}

DEX_HEADER_SIZE = 0x70


class DexHeader:
    """Parsed DEX header fields."""
    def __init__(self, data: bytes):
        assert len(data) >= DEX_HEADER_SIZE, "DEX too small for header"
        self.magic = data[0:8]
        assert self.magic in DEX_MAGICS, f"Bad DEX magic: {self.magic!r}"
        self.checksum = struct.unpack_from('<I', data, 8)[0]
        self.signature = data[12:32]
        self.file_size = struct.unpack_from('<I', data, 32)[0]
        self.header_size = struct.unpack_from('<I', data, 36)[0]
        self.endian_tag = struct.unpack_from('<I', data, 40)[0]
        self.link_size = struct.unpack_from('<I', data, 44)[0]
        self.link_off = struct.unpack_from('<I', data, 48)[0]
        self.map_off = struct.unpack_from('<I', data, 52)[0]
        self.string_ids_size = struct.unpack_from('<I', data, 56)[0]
        self.string_ids_off = struct.unpack_from('<I', data, 60)[0]
        self.type_ids_size = struct.unpack_from('<I', data, 64)[0]
        self.type_ids_off = struct.unpack_from('<I', data, 68)[0]
        self.proto_ids_size = struct.unpack_from('<I', data, 72)[0]
        self.proto_ids_off = struct.unpack_from('<I', data, 76)[0]
        self.field_ids_size = struct.unpack_from('<I', data, 80)[0]
        self.field_ids_off = struct.unpack_from('<I', data, 84)[0]
        self.method_ids_size = struct.unpack_from('<I', data, 88)[0]
        self.method_ids_off = struct.unpack_from('<I', data, 92)[0]
        self.class_defs_size = struct.unpack_from('<I', data, 96)[0]
        self.class_defs_off = struct.unpack_from('<I', data, 100)[0]
        self.data_size = struct.unpack_from('<I', data, 104)[0]
        self.data_off = struct.unpack_from('<I', data, 108)[0]


def parse_string_ids(data: bytes, hdr: DexHeader) -> List[int]:
    """Returns list of string offsets (one per string_id_item)."""
    offsets = []
    for i in range(hdr.string_ids_size):
        off = struct.unpack_from('<I', data, hdr.string_ids_off + i * 4)[0]
        offsets.append(off)
    return offsets


def get_string(data: bytes, string_offsets: List[int], idx: int) -> str:
    """Get the string at the given string_ids index."""
    off = string_offsets[idx]
    # String is MUTF-8: length prefix (uleb128) + data + null terminator
    length, pos = decode_uleb128(data, off)
    raw = data[pos:pos + length]
    # Decode as modified UTF-8 (treat as Latin-1 for simplicity)
    return raw.decode('utf-8', errors='replace')


def parse_type_ids(data: bytes, hdr: DexHeader) -> List[int]:
    """Returns list of string_idx for each type_id_item."""
    result = []
    for i in range(hdr.type_ids_size):
        idx = struct.unpack_from('<I', data, hdr.type_ids_off + i * 4)[0]
        result.append(idx)
    return result


class ProtoId:
    def __init__(self, shorty_idx: int, return_type_idx: int, params_off: int):
        self.shorty_idx = shorty_idx
        self.return_type_idx = return_type_idx
        self.params_off = params_off


def parse_proto_ids(data: bytes, hdr: DexHeader) -> List[ProtoId]:
    result = []
    for i in range(hdr.proto_ids_size):
        off = hdr.proto_ids_off + i * 12
        shorty_idx = struct.unpack_from('<I', data, off)[0]
        return_type_idx = struct.unpack_from('<I', data, off + 4)[0]
        params_off = struct.unpack_from('<I', data, off + 8)[0]
        result.append(ProtoId(shorty_idx, return_type_idx, params_off))
    return result


class MethodId:
    def __init__(self, class_idx: int, proto_idx: int, name_idx: int):
        self.class_idx = class_idx
        self.proto_idx = proto_idx
        self.name_idx = name_idx


def parse_method_ids(data: bytes, hdr: DexHeader) -> List[MethodId]:
    result = []
    for i in range(hdr.method_ids_size):
        off = hdr.method_ids_off + i * 8
        class_idx = struct.unpack_from('<H', data, off)[0]
        proto_idx = struct.unpack_from('<H', data, off + 2)[0]
        name_idx = struct.unpack_from('<I', data, off + 4)[0]
        result.append(MethodId(class_idx, proto_idx, name_idx))
    return result


class ClassDef:
    def __init__(self):
        self.class_idx = 0
        self.access_flags = 0
        self.superclass_idx = 0
        self.interfaces_off = 0
        self.source_file_idx = 0
        self.annotations_off = 0
        self.class_data_off = 0
        self.static_values_off = 0


def parse_class_defs(data: bytes, hdr: DexHeader) -> List[ClassDef]:
    result = []
    for i in range(hdr.class_defs_size):
        off = hdr.class_defs_off + i * 32
        cd = ClassDef()
        cd.class_idx = struct.unpack_from('<I', data, off)[0]
        cd.access_flags = struct.unpack_from('<I', data, off + 4)[0]
        cd.superclass_idx = struct.unpack_from('<I', data, off + 8)[0]
        cd.interfaces_off = struct.unpack_from('<I', data, off + 12)[0]
        cd.source_file_idx = struct.unpack_from('<I', data, off + 16)[0]
        cd.annotations_off = struct.unpack_from('<I', data, off + 20)[0]
        cd.class_data_off = struct.unpack_from('<I', data, off + 24)[0]
        cd.static_values_off = struct.unpack_from('<I', data, off + 28)[0]
        result.append(cd)
    return result


class EncodedField:
    def __init__(self, field_idx: int, access_flags: int):
        self.field_idx = field_idx
        self.access_flags = access_flags


class EncodedMethod:
    def __init__(self, method_idx: int, access_flags: int, code_off: int):
        self.method_idx = method_idx
        self.access_flags = access_flags
        self.code_off = code_off


class ClassData:
    def __init__(self):
        self.static_fields: List[EncodedField] = []
        self.instance_fields: List[EncodedField] = []
        self.direct_methods: List[EncodedMethod] = []
        self.virtual_methods: List[EncodedMethod] = []


def parse_class_data(data: bytes, class_data_off: int) -> Optional[ClassData]:
    """Parse class_data_item at the given offset. Returns None if off==0."""
    if class_data_off == 0:
        return None
    result = ClassData()
    pos = class_data_off

    static_fields_size, pos = decode_uleb128(data, pos)
    instance_fields_size, pos = decode_uleb128(data, pos)
    direct_methods_size, pos = decode_uleb128(data, pos)
    virtual_methods_size, pos = decode_uleb128(data, pos)

    current_field_idx = 0
    for _ in range(static_fields_size):
        field_idx_diff, pos = decode_uleb128(data, pos)
        current_field_idx += field_idx_diff
        flags, pos = decode_uleb128(data, pos)
        result.static_fields.append(EncodedField(current_field_idx, flags))

    current_field_idx = 0
    for _ in range(instance_fields_size):
        field_idx_diff, pos = decode_uleb128(data, pos)
        current_field_idx += field_idx_diff
        flags, pos = decode_uleb128(data, pos)
        result.instance_fields.append(EncodedField(current_field_idx, flags))

    current_method_idx = 0
    for _ in range(direct_methods_size):
        method_idx_diff, pos = decode_uleb128(data, pos)
        current_method_idx += method_idx_diff
        flags, pos = decode_uleb128(data, pos)
        code_off, pos = decode_uleb128(data, pos)
        result.direct_methods.append(EncodedMethod(current_method_idx, flags, code_off))

    current_method_idx = 0
    for _ in range(virtual_methods_size):
        method_idx_diff, pos = decode_uleb128(data, pos)
        current_method_idx += method_idx_diff
        flags, pos = decode_uleb128(data, pos)
        code_off, pos = decode_uleb128(data, pos)
        result.virtual_methods.append(EncodedMethod(current_method_idx, flags, code_off))

    return result


def encode_class_data(cd: ClassData) -> bytes:
    """Serialize a ClassData back to ULEB128 bytes."""
    result = bytearray()
    result.extend(encode_uleb128(len(cd.static_fields)))
    result.extend(encode_uleb128(len(cd.instance_fields)))
    result.extend(encode_uleb128(len(cd.direct_methods)))
    result.extend(encode_uleb128(len(cd.virtual_methods)))

    prev = 0
    for f in cd.static_fields:
        result.extend(encode_uleb128(f.field_idx - prev))
        result.extend(encode_uleb128(f.access_flags))
        prev = f.field_idx
    prev = 0
    for f in cd.instance_fields:
        result.extend(encode_uleb128(f.field_idx - prev))
        result.extend(encode_uleb128(f.access_flags))
        prev = f.field_idx
    prev = 0
    for m in cd.direct_methods:
        result.extend(encode_uleb128(m.method_idx - prev))
        result.extend(encode_uleb128(m.access_flags))
        result.extend(encode_uleb128(m.code_off))
        prev = m.method_idx
    prev = 0
    for m in cd.virtual_methods:
        result.extend(encode_uleb128(m.method_idx - prev))
        result.extend(encode_uleb128(m.access_flags))
        result.extend(encode_uleb128(m.code_off))
        prev = m.method_idx

    return bytes(result)


def align4(offset: int) -> int:
    """Round up to 4-byte alignment."""
    return (offset + 3) & ~3


def compute_signature(data: bytes) -> bytes:
    """SHA-1 of data[32:] (everything after signature field)."""
    return hashlib.sha1(data[32:]).digest()


def compute_checksum(data: bytes) -> int:
    """Adler32 of data[12:] (everything after checksum field)."""
    return zlib.adler32(data[12:]) & 0xFFFFFFFF


# ──────────────────────────────────────────────
# Main: self-test
# ──────────────────────────────────────────────

if __name__ == '__main__':
    _test_uleb128()
    _test_sleb128()
    print("[OK] All dex_structs tests passed")
