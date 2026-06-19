// dex_scanner.c - Scan /proc/<pid>/mem for DEX files, dump and auto-fix checksum
// Build: aarch64-linux-android34-clang -O2 -static -o dex_scanner dex_scanner.c
// Usage: dex_scanner <pid> [output_dir]
//
// Auto-fix: After dumping each DEX, recomputes Adler32 checksum and SHA-1
// signature so tools like jadx can load the file directly.
// No external dependencies - SHA-1 and Adler32 are implemented inline.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"

// ---- Minimal SHA-1 implementation (no external deps) ----
typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} SHA1_CTX;

#define ROL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static void sha1_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;          k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else              { f = b ^ c ^ d;          k = 0xCA62C1D6; }
        uint32_t tmp = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)(ctx->count % 64);
    ctx->count += len;
    size_t i = 0;
    if (idx) {
        size_t need = 64 - idx;
        if (len < need) { memcpy(ctx->buffer + idx, data, len); return; }
        memcpy(ctx->buffer + idx, data, need);
        sha1_transform(ctx->state, ctx->buffer);
        i = need;
    }
    for (; i + 64 <= len; i += 64)
        sha1_transform(ctx->state, data + i);
    if (i < len) memcpy(ctx->buffer, data + i, len - i);
}

static void sha1_final(SHA1_CTX *ctx, uint8_t digest[20]) {
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while ((ctx->count % 64) != 56) sha1_update(ctx, &zero, 1);
    uint8_t len_be[8];
    for (int i = 0; i < 8; i++) len_be[i] = (uint8_t)(bits >> (56 - i * 8));
    sha1_update(ctx, len_be, 8);
    for (int i = 0; i < 5; i++) {
        digest[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}
// ---- End SHA-1 ----

// ---- Minimal Adler32 implementation (no external deps) ----
// Same algorithm as zlib adler32: RFC 1950
#define ADLER32_BASE 65521
static uint32_t my_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % ADLER32_BASE;
        b = (b + a) % ADLER32_BASE;
    }
    return (b << 16) | a;
}
// ---- End Adler32 ----

// Fix DEX checksum and signature in memory before writing to file.
// DEX spec: signature = SHA1(bytes[32:]), checksum = Adler32(bytes[12:])
// Order matters: fix SHA-1 first (it's in the checksum range), then Adler32.
static void fix_dex_in_memory(uint8_t *data, size_t size) {
    if (size < 0x24 || memcmp(data, kDexMagic, 4) != 0) return;

    // 1. Fix SHA-1 signature: SHA1(bytes[0x20:]) stored at [0x0C:0x20]
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data + 0x20, size - 0x20);
    uint8_t sha1[20];
    sha1_final(&ctx, sha1);
    memcpy(data + 0x0C, sha1, 20);

    // 2. Fix Adler32 checksum: adler32(bytes[0x0C:]) stored at [0x08:0x0C]
    //    Must be after SHA-1 fix since checksum covers the signature field
    uint32_t cksum = my_adler32(data + 0x0C, size - 0x0C);
    memcpy(data + 0x08, &cksum, 4);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [output_dir]\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    const char* out_dir = argc > 2 ? argv[2] : "/data/local/tmp/fart_dump";

    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mkdir(out_dir, 0777);

    FILE* mfp = fopen(maps_path, "r");
    if (!mfp) {
        fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
        return 1;
    }

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
        fclose(mfp);
        return 1;
    }

    printf("Scanning PID=%d for DEX files...\n", pid);

    char line[512];
    int dex_count = 0;
    uint8_t buf[4096];

    while (fgets(line, sizeof(line), mfp)) {
        uintptr_t start, end;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (perms[0] != 'r') continue;

        size_t region_size = end - start;
        if (region_size < 64 || region_size > 0x20000000) continue;

        for (uintptr_t addr = start; addr < end; addr += 4096) {
            ssize_t n = pread(mem_fd, buf, sizeof(buf), (off_t)addr);
            if (n < 64) continue;

            for (int i = 0; i <= n - 4; i++) {
                if (memcmp(buf + i, kDexMagic, 4) != 0) continue;

                uintptr_t dex_addr = addr + i;

                uint32_t dex_size = 0;
                if (i + 0x24 <= n) {
                    memcpy(&dex_size, buf + i + 0x20, 4);
                } else {
                    uint8_t hdr[64];
                    pread(mem_fd, hdr, 64, (off_t)dex_addr);
                    memcpy(&dex_size, hdr + 0x20, 4);
                }

                if (dex_size < 64 || dex_size > 0x10000000) continue;

                dex_count++;
                printf("Found DEX #%d at 0x%lx size=%u\n",
                       dex_count, (unsigned long)dex_addr, dex_size);

                char outfile[512];
                snprintf(outfile, sizeof(outfile),
                         "%s/dex_ext_%d_%d.dex", out_dir, pid, dex_count);

                uint8_t* dex_data = (uint8_t*)malloc(dex_size);
                if (!dex_data) { fprintf(stderr, "malloc failed\n"); continue; }

                ssize_t read_total = 0;
                while (read_total < (ssize_t)dex_size) {
                    ssize_t r = pread(mem_fd, dex_data + read_total,
                                      dex_size - read_total,
                                      (off_t)(dex_addr + read_total));
                    if (r <= 0) break;
                    read_total += r;
                }

                if (read_total > 0) {
                    // Auto-fix checksum and signature in memory before writing
                    fix_dex_in_memory(dex_data, read_total);
                    int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                    if (fd >= 0) {
                        write(fd, dex_data, read_total);
                        close(fd);
                        printf("Dumped+Fixed: %s (%zd bytes)\n", outfile, read_total);
                    } else {
                        fprintf(stderr, "Cannot create %s: %s\n", outfile, strerror(errno));
                    }
                } else {
                    fprintf(stderr, "Cannot read DEX at 0x%lx\n", (unsigned long)dex_addr);
                }
                free(dex_data);

                i += (dex_size > 4096 ? 4096 : dex_size);
            }
        }
    }

    close(mem_fd);
    fclose(mfp);
    printf("Done. Found %d DEX files in %s\n", dex_count, out_dir);
    return 0;
}
