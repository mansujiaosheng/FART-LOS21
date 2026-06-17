#!/usr/bin/env python3
"""Generate minimal valid AXML for FART Controller."""
import struct, zipfile, os, sys

bd = sys.argv[1]
PKG = 'com.fartlos21.controller'

strings = [
    '', 'http://schemas.android.com/apk/res/android',
    'manifest', 'package', PKG,
    'uses-sdk', 'minSdkVersion',
    'application', 'label', 'FART\u63a7\u5236\u5668',
    'activity', 'name', '.MainActivity', 'exported',
    'intent-filter', 'action', 'android.intent.action.MAIN',
    'category', 'android.intent.category.LAUNCHER',
]

def build_sp(strs):
    offs, buf = [], b''
    for s in strs:
        offs.append(len(buf))
        buf += s.encode('utf-16-le') + b'\x00\x00'
    while len(buf) % 4: buf += b'\x00\x00'
    n = len(strs); h = 28; sz = h + n * 4 + len(buf)
    c = struct.pack('<HHI', 0x0001, h, sz)
    c += struct.pack('<IIII', n, 0, 0, h + n * 4) + struct.pack('<I', 0)
    for o in offs: c += struct.pack('<I', o)
    c += buf
    return c

def rv(dt, dv): return struct.pack('<HBB', 8, 0, dt) + struct.pack('<I', dv)

def stag(name, attrs):
    n = len(attrs)
    total = 36 + n * 20  # 16(header) + 20(attrExt) + n*20(attrs)
    c = struct.pack('<HHI', 0x0102, 16, total)
    c += struct.pack('<II', 0, 0xFFFFFFFF)
    c += struct.pack('<II', 0xFFFFFFFF, name)
    c += struct.pack('<HHHHHH', 20, 20, n, 0xFFFF, 0xFFFF, 0xFFFF)
    for a in attrs:
        c += struct.pack('<III', a[0], a[1], a[2]) + rv(a[3], a[4])
    return c

def etag(name):
    return struct.pack('<HHI', 0x0103, 16, 24) + struct.pack('<II', 0, 0xFFFFFFFF) + struct.pack('<II', 0xFFFFFFFF, name)

def nstag(uri, start=True):
    t = 0x0100 if start else 0x0101
    return struct.pack('<HHI', t, 0x10, 24) + struct.pack('<II', 0, 0xFFFFFFFF) + struct.pack('<II', 0, uri)

data = bytearray()
data += build_sp(strings)
data += nstag(1, True)
data += stag(2, [(0xFFFFFFFF, 3, 4, 3, 4)])  # manifest
data += stag(5, [(1, 6, 7, 3, 7)])  # uses-sdk
data += etag(5)
data += stag(7, [(1, 8, 9, 3, 9)])  # application
data += stag(10, [(1, 11, 12, 3, 12), (1, 13, 0xFFFFFFFF, 0x12, 0xFFFFFFFF)])  # activity
data += stag(14, [])  # intent-filter
data += stag(15, [(1, 11, 16, 3, 16)])  # action
data += etag(15)
data += stag(17, [(1, 11, 18, 3, 18)])  # category
data += etag(17)
data += etag(14)
data += etag(10)
data += etag(7)
data += etag(2)
data += nstag(1, False)

axml = struct.pack('<HHI', 0x0003, 0x0008, 8 + len(data)) + bytes(data)
with open(os.path.join(bd, 'AndroidManifest.xml'), 'wb') as f:
    f.write(axml)
print(f'Generated AXML: {len(axml)} bytes')
