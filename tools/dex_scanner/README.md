# dex_scanner

Android DEX memory dumper - dump DEX files from any running app process without injection.

## Why

Traditional DEX dump tools (frida-dexdump, fdex2, etc.) inject code into the target process, which triggers packer detection and gets killed. dex_scanner takes a different approach: it runs as an independent root process and reads target memory via `/proc/<pid>/mem`, leaving zero trace in the target process.

## Test Results

| App | Packer | frida-dexdump | dex_scanner | jadx quality |
|-----|--------|---------------|-------------|-------------|
| China Construction Bank | SecNeo.A (Bangcle) | 0 DEX (killed) | 86 DEX | 93% method body intact |
| ICBC | SecNeo.B (Bangcle) | 0 DEX (killed) | 81 DEX | 94% method body intact |
| Funshion Video | KADP (Bangbang) | App crash | 73 DEX | 91% method body intact |
| Xianyu (Idle Fish) | Alibaba Security | 20 DEX (incomplete) | 67 DEX | 94% method body intact |
| Qidian Reader | Tencent Legu | N/A | 70 DEX | 96% method body intact |

## How It Works

1. Reads `/proc/<pid>/maps` to find readable memory regions
2. Scans each 4KB page for DEX magic (`dex\n`)
3. Reads DEX header to get file size
4. Dumps entire DEX via `pread()` on `/proc/<pid>/mem`
5. Auto-fixes Adler32 checksum and SHA-1 signature in memory
6. Writes fixed DEX to file - jadx can open directly

## Build

Requires Android NDK r27+:

```bash
make
```

Or manually:

```bash
aarch64-linux-android34-clang -O2 -static -o dex_scanner dex_scanner.c
```

## Usage

```bash
# 1. Start target app normally
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

# 2. Get PID
adb shell pidof com.example.app

# 3. Dump (need root)
adb root
adb shell /data/local/tmp/dex_scanner <pid> [output_dir]

# 4. Pull and analyze
adb pull /data/local/tmp/fart_dump/ ./dump/
jadx -d output ./dump/classes.dex
```

## Tools

- `dex_scanner.c` - Main tool: scan + dump + auto-fix checksum
- `fix_dex_checksum.py` - Standalone Python script to fix DEX checksum (for manually dumped files)

## DEX Checksum Auto-Fix

When packers modify DEX data in memory, the checksum and SHA-1 signature become invalid. dex_scanner automatically fixes them:

1. Recompute SHA-1 of `bytes[0x20:]` → write to `[0x0C:0x20]`
2. Recompute Adler32 of `bytes[0x0C:]` → write to `[0x08:0x0C]`

Order matters: SHA-1 is fixed first because it falls within the Adler32 checksum range.

## Why It Bypasses Packer Detection

| Detection Method | frida-dexdump | dex_scanner |
|-----------------|---------------|-------------|
| `/proc/self/maps` SO scanning | Detected (frida-agent-64.so) | Not detected (no injection) |
| Inline hook detection | May trigger | No hooks installed |
| ptrace detection | May trigger | No ptrace (uses /proc/pid/mem) |
| Thread enumeration | Detected (frida thread) | Not detected (separate process) |

## Limitations

- Only works on first-generation packers (whole-app encryption at startup)
- Second-generation packers (DexVMP, per-method decryption) will dump stub methods
- Requires root access
- DEX must be fully decrypted in memory at scan time

## License

MIT
