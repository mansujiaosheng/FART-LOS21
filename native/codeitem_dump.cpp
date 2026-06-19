// codeitem_dump.cpp – Stage 2.4: Passive CodeItem dump worker
#include "codeitem_dump.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// -----------------------------------------------------------------------
// Inline SHA-256 (same algorithm as dex_dump.cpp, self-contained)
// -----------------------------------------------------------------------
namespace {

struct Sha256Ctx {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
};

static const uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(Sha256Ctx* ctx, const uint8_t block[64]) {
  uint32_t W[64];
  for (int i = 0; i < 16; i++) {
    W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
           ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
  }
  for (int i = 16; i < 64; i++) {
    W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
  }

  uint32_t a = ctx->state[0], b = ctx->state[1];
  uint32_t c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5];
  uint32_t g = ctx->state[6], h = ctx->state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t t1 = h + EP1(e) + CH(e, f, g) + kSha256K[i] + W[i];
    uint32_t t2 = EP0(a) + MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->state[0] += a; ctx->state[1] += b;
  ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f;
  ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx* ctx) {
  ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

static void sha256_update(Sha256Ctx* ctx, const uint8_t* data, size_t len) {
  size_t idx = (size_t)(ctx->count & 0x3f);
  ctx->count += len;
  size_t free = 64 - idx;
  if (len >= free) {
    memcpy(ctx->buffer + idx, data, free);
    sha256_transform(ctx, ctx->buffer);
    for (size_t i = free; i + 64 <= len; i += 64) {
      sha256_transform(ctx, data + i);
    }
    idx = 0;
  } else {
    free = len;
  }
  memcpy(ctx->buffer + idx, data + len - free, free);
}

static void sha256_final(Sha256Ctx* ctx, uint8_t out[32]) {
  uint64_t bits = ctx->count << 3;
  size_t idx = (size_t)(ctx->count & 0x3f);
  ctx->buffer[idx++] = 0x80;

  if (idx > 56) {
    memset(ctx->buffer + idx, 0, 64 - idx);
    sha256_transform(ctx, ctx->buffer);
    idx = 0;
  }
  memset(ctx->buffer + idx, 0, 56 - idx);

  for (int i = 0; i < 8; i++) {
    ctx->buffer[56 + i] = (uint8_t)(bits >> (56 - i*8));
  }
  sha256_transform(ctx, ctx->buffer);

  for (int i = 0; i < 8; i++) {
    out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
    out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
    out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
    out[i*4+3] = (uint8_t)(ctx->state[i]);
  }
}

#undef ROTR
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

}  // anonymous namespace

// -----------------------------------------------------------------------
// Free functions for SHA256 (used by both CodeItemDumpTask and CodeItemDumper)
// -----------------------------------------------------------------------
namespace {

static void codeitem_sha256(const uint8_t* data, size_t size, uint8_t out[32]) {
  Sha256Ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, size);
  sha256_final(&ctx, out);
}

static void codeitem_hex(const uint8_t* bytes, size_t len, char* out_hex) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out_hex[i * 2]     = hex[bytes[i] >> 4];
    out_hex[i * 2 + 1] = hex[bytes[i] & 0xf];
  }
  out_hex[len * 2] = '\0';
}

}  // anonymous namespace

// -----------------------------------------------------------------------
// CodeItemDumpTask
// -----------------------------------------------------------------------
namespace fart {

CodeItemDumpTask::CodeItemDumpTask() {
  sha256_prefix[0] = '\0';
  source[0] = '\0';
  dex_key[0] = '\0';
  process_name[0] = '\0';
}

CodeItemDumpTask::~CodeItemDumpTask() {
  delete[] data;
  data = nullptr;
}

bool CodeItemDumpTask::CopyData(const uint8_t* src, size_t sz) {
  if (src == nullptr || sz == 0) return false;
  uint8_t* new_data = new (std::nothrow) uint8_t[sz];
  if (new_data == nullptr) return false;
  memcpy(new_data, src, sz);
  delete[] data;
  data = new_data;
  dump_size = sz;

  // Compute SHA256 from owned buffer
  uint8_t sha256[32];
  codeitem_sha256(data, sz, sha256);
  char hex[65];
  codeitem_hex(sha256, 32, hex);
  memcpy(sha256_prefix, hex, 16);
  sha256_prefix[16] = '\0';
  return true;
}

// -----------------------------------------------------------------------
// SHA256 helpers
// -----------------------------------------------------------------------
void CodeItemDumper::ComputeSha256(const uint8_t* data, size_t size, uint8_t out[32]) {
  codeitem_sha256(data, size, out);
}

void CodeItemDumper::BytesToHex(const uint8_t* bytes, size_t len, char* out_hex) {
  codeitem_hex(bytes, len, out_hex);
}

// -----------------------------------------------------------------------
// CodeItemDumper
// -----------------------------------------------------------------------
CodeItemDumper::CodeItemDumper() = default;

CodeItemDumper::~CodeItemDumper() {
  running_ = false;
  cv_.notify_all();
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
  LOGI("CodeItemDumper: total=%zu dups=%zu", dumped_count_.load(), dup_count_.load());
}

bool CodeItemDumper::Init(const char* dump_dir, uint32_t max_dumps) {
  if (dump_dir == nullptr || dump_dir[0] == '\0') {
    LOGE("CodeItemDumper: invalid dump dir");
    return false;
  }
  dump_dir_ = dump_dir;
  max_dumps_ = max_dumps;

  // Create base dump directory if needed
  struct stat st;
  if (stat(dump_dir_.c_str(), &st) != 0) {
    if (mkdir(dump_dir_.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("CodeItemDumper: cannot create %s: %d", dump_dir_.c_str(), errno);
      return false;
    }
  }

  running_ = true;
  worker_thread_ = std::thread(&CodeItemDumper::WorkerLoop, this);
  LOGI("CodeItemDumper: dir=%s max_dumps=%u", dump_dir_.c_str(), max_dumps_);
  return true;
}

int CodeItemDumper::QueueDump(const CodeItemDumpTask& task) {
  if (!running_) return 3;
  if (task.data == nullptr || task.dump_size == 0) {
    LOGW("codeitem_dump: invalid task (null data or zero size)");
    return 3;
  }

  // Check max limit
  if (dumped_count_.load() >= max_dumps_) {
    LOGW("codeitem_dump: max dump reached (%u)", max_dumps_);
    return 2;
  }

  // Dedup: sha256_prefix + method_idx
  std::string dedup_key = std::string(task.sha256_prefix, 16) + ":" + std::to_string(task.method_idx);
  {
    std::lock_guard<std::mutex> lock(dedup_mutex_);
    if (dedup_set_.find(dedup_key) != dedup_set_.end()) {
      dup_count_.fetch_add(1);
      return 1;  // duplicate
    }
    dedup_set_.insert(dedup_key);
  }

  // Copy task into owned queue
  CodeItemDumpTask copy;
  copy.pid = task.pid;
  copy.tid = task.tid;
  copy.method_idx = task.method_idx;
  copy.registers_size = task.registers_size;
  copy.ins_size = task.ins_size;
  copy.outs_size = task.outs_size;
  copy.tries_size = task.tries_size;
  copy.insns_size = task.insns_size;
  copy.dump_size = task.dump_size;
  copy.dump_complete = task.dump_complete;
  memcpy(copy.sha256_prefix, task.sha256_prefix, 17);
  memcpy(copy.process_name, task.process_name, 64);

  if (!copy.CopyData(task.data, task.dump_size)) {
    LOGE("codeitem_dump: CopyData failed");
    return 3;
  }

  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    queue_.push(std::move(copy));
  }
  cv_.notify_one();
  return 0;
}

size_t CodeItemDumper::QueueSize() const {
  std::lock_guard<std::mutex> lock(queue_mutex_);
  return queue_.size();
}

// -----------------------------------------------------------------------
// CodeItem size calculation
// -----------------------------------------------------------------------
size_t CodeItemDumper::CalculateCodeItemSize(const uint8_t* code_item,
                                              uint16_t tries_size,
                                              uint32_t insns_size) {
  // Base: 16-byte header + instructions (2 bytes each)
  size_t size = 16 + (size_t)insns_size * 2;

  if (tries_size > 0) {
    // Padding: if insns_size is odd, 2 bytes padding before try_items
    if (insns_size & 1) size += 2;

    // try_items: each is 8 bytes
    size += (size_t)tries_size * 8;

    // Parse encoded_catch_handler_list after try_items
    const uint8_t* ptr = code_item + size;
    uint32_t handlers_size = 0;
    // ULEB128 decode handlers_size
    uint32_t shift = 0;
    while (*ptr & 0x80) { handlers_size |= (*ptr & 0x7F) << shift; shift += 7; ptr++; }
    handlers_size |= (*ptr & 0x7F) << shift; ptr++;

    for (uint32_t h = 0; h < handlers_size; h++) {
      // SLEB128 size (negative = catch_all present)
      int32_t handler_size = 0;
      shift = 0;
      while (*ptr & 0x80) { handler_size |= (*ptr & 0x7F) << shift; shift += 7; ptr++; }
      handler_size |= (*ptr & 0x7F) << shift; ptr++;
      if (handler_size & (1 << (shift < 7 ? 6 : (shift - 1)))) {
        // Sign extend
        handler_size |= -1 << (shift < 7 ? 7 : (shift + 1));
      }
      size += (ptr - (code_item + size));  // account for already-read handler_size bytes
      // Reset ptr to point past handler_size
      // Actually we need to count properly:
      // handler_size ULEB bytes already counted in ptr advancement
      // Now count type_addr_pairs
      uint32_t count = (uint32_t)(handler_size > 0 ? handler_size : -handler_size);
      for (uint32_t i = 0; i < count; i++) {
        // type_idx ULEB128
        while (*ptr & 0x80) { size++; ptr++; }
        size++; ptr++;
        // addr ULEB128
        while (*ptr & 0x80) { size++; ptr++; }
        size++; ptr++;
      }
      if (handler_size <= 0) {
        // catch_all_addr ULEB128
        while (*ptr & 0x80) { size += 2; ptr++; }
        size++; ptr++;
      }
    }
  }

  return size;
}

bool CodeItemDumper::IsValidCodeItem(const CodeItemDumpTask& task) {
  if (task.data == nullptr || task.dump_size == 0) return false;
  if (task.registers_size > 256) return false;
  if (task.ins_size > 256) return false;
  if (task.outs_size > 256) return false;
  if (task.insns_size == 0 || task.insns_size > 524288) return false;  // max 1MB/2
  if (task.tries_size > 65535) return false;
  if (task.dump_size > 2 * 1024 * 1024) return false;  // max 2MB
  return true;
}

// -----------------------------------------------------------------------
// CompactDex CodeItem decoding
// -----------------------------------------------------------------------
// CompactDexFile::CodeItem layout (from compact_dex_file.h):
//   offset 0x00: fields_ (uint16_t) — packed [regs:4|ins:4|outs:4|tries:4]
//   offset 0x02: insns_count_and_flags_ (uint16_t) — [5bit flags|11bit insns_size]
//   offset 0x04: insns_[1] (uint16_t[])
//
// PreHeader mechanism: when field values exceed 4-bit/11-bit range,
// extra uint16_t values are inserted BEFORE the CodeItem (lower address).
// Flags in insns_count_and_flags_ indicate which preheader fields exist.
//
// Bit layout of fields_:
//   bits [15:12] = registers_size (low 4 bits, actual = decoded + ins_size)
//   bits [11:8]  = ins_size (low 4 bits)
//   bits [7:4]   = outs_size (low 4 bits)
//   bits [3:0]   = tries_size (low 4 bits)
//
// Bit layout of insns_count_and_flags_:
//   bits [15:5]  = insns_size_in_code_units (low 11 bits, max 2047)
//   bit 4        = kFlagPreHeaderInsnsSize
//   bit 3        = kFlagPreHeaderTriesSize
//   bit 2        = kFlagPreHeaderOutsSize
//   bit 1        = kFlagPreHeaderInsSize
//   bit 0        = kFlagPreHeaderRegistersSize

static const uint16_t kCompactFlagPreHeaderRegistersSize = 0x0001;
static const uint16_t kCompactFlagPreHeaderInsSize       = 0x0002;
static const uint16_t kCompactFlagPreHeaderOutsSize      = 0x0004;
static const uint16_t kCompactFlagPreHeaderTriesSize     = 0x0008;
static const uint16_t kCompactFlagPreHeaderInsnsSize     = 0x0010;
static const int kCompactInsnsSizeShift = 5;

bool CodeItemDumper::DecodeCompactCodeItem(const uint8_t* compact_ci,
                                            uint16_t& out_regs, uint16_t& out_ins,
                                            uint16_t& out_outs, uint16_t& out_tries,
                                            uint32_t& out_insns) {
  if (compact_ci == nullptr) return false;

  // Read fields_ and insns_count_and_flags_
  uint16_t fields = *(const uint16_t*)(compact_ci + 0);
  uint16_t insns_count_and_flags = *(const uint16_t*)(compact_ci + 2);

  // Decode inline values
  uint16_t regs_low  = (fields >> 12) & 0xF;
  uint16_t ins_low   = (fields >> 8) & 0xF;
  uint16_t outs_low  = (fields >> 4) & 0xF;
  uint16_t tries_low = fields & 0xF;
  uint32_t insns_low = (insns_count_and_flags >> kCompactInsnsSizeShift) & 0x7FF;

  // Decode preheader values by walking backwards from CodeItem start
  // Preheader order (from CodeItem address going backwards):
  //   -1: insns_size low16 (if kFlagPreHeaderInsnsSize)
  //   -2: insns_size high16 (if kFlagPreHeaderInsnsSize)
  //   -3: registers_size (if kFlagPreHeaderRegistersSize)
  //   -4: ins_size (if kFlagPreHeaderInsSize)
  //   -5: outs_size (if kFlagPreHeaderOutsSize)
  //   -6: tries_size (if kFlagPreHeaderTriesSize)
  const uint16_t* preheader = reinterpret_cast<const uint16_t*>(compact_ci);
  int preheader_idx = -1;  // walk backwards

  uint32_t insns_extra = 0;
  uint16_t regs_extra = 0;
  uint16_t ins_extra = 0;
  uint16_t outs_extra = 0;
  uint16_t tries_extra = 0;

  if (insns_count_and_flags & kCompactFlagPreHeaderInsnsSize) {
    uint16_t insns_lo = preheader[preheader_idx--];
    uint16_t insns_hi = preheader[preheader_idx--];
    insns_extra = ((uint32_t)insns_hi << 16) | insns_lo;
  }

  if (insns_count_and_flags & kCompactFlagPreHeaderRegistersSize) {
    regs_extra = preheader[preheader_idx--];
  }

  if (insns_count_and_flags & kCompactFlagPreHeaderInsSize) {
    ins_extra = preheader[preheader_idx--];
  }

  if (insns_count_and_flags & kCompactFlagPreHeaderOutsSize) {
    outs_extra = preheader[preheader_idx--];
  }

  if (insns_count_and_flags & kCompactFlagPreHeaderTriesSize) {
    tries_extra = preheader[preheader_idx--];
  }

  // Compute final values
  out_ins   = ins_low + (ins_extra << 4);
  out_outs  = outs_low + (outs_extra << 4);
  out_tries = tries_low + (tries_extra << 4);
  out_insns = insns_low + (insns_extra << 11);
  // registers_size = decoded_value + ins_size (per CompactDex spec)
  out_regs  = regs_low + (regs_extra << 4) + out_ins;

  // Basic validation
  if (out_insns == 0 || out_insns > 524288) return false;
  if (out_regs > 65535 || out_ins > 65535 || out_outs > 65535) return false;

  return true;
}

size_t CodeItemDumper::CalculateCompactCodeItemSize(const uint8_t* compact_ci,
                                                     uint16_t tries_size,
                                                     uint32_t insns_size) {
  // CompactDex CodeItem: 4-byte header + instructions
  // Preheader size needs to be accounted for if we want the full dump
  // But for size calculation from the CodeItem start (not including preheader):
  size_t size = 4 + (size_t)insns_size * 2;  // header + insns

  if (tries_size > 0) {
    // CompactDex uses 2-byte alignment (not 4-byte like StandardDex)
    if (insns_size & 1) size += 2;

    // try_items: each is 8 bytes
    size += (size_t)tries_size * 8;

    // Parse encoded_catch_handler_list (same LEB128 format as StandardDex)
    const uint8_t* ptr = compact_ci + size;
    uint32_t handlers_size = 0;
    uint32_t shift = 0;
    while (*ptr & 0x80) { handlers_size |= (*ptr & 0x7F) << shift; shift += 7; ptr++; }
    handlers_size |= (*ptr & 0x7F) << shift; ptr++;

    for (uint32_t h = 0; h < handlers_size; h++) {
      int32_t handler_size = 0;
      shift = 0;
      while (*ptr & 0x80) { handler_size |= (*ptr & 0x7F) << shift; shift += 7; ptr++; }
      handler_size |= (*ptr & 0x7F) << shift; ptr++;
      if (handler_size & (1 << (shift < 7 ? 6 : (shift - 1)))) {
        handler_size |= -1 << (shift < 7 ? 7 : (shift + 1));
      }
      size += (ptr - (compact_ci + size));
      uint32_t count = (uint32_t)(handler_size > 0 ? handler_size : -handler_size);
      for (uint32_t i = 0; i < count; i++) {
        while (*ptr & 0x80) { size++; ptr++; }
        size++; ptr++;
        while (*ptr & 0x80) { size++; ptr++; }
        size++; ptr++;
      }
      if (handler_size <= 0) {
        while (*ptr & 0x80) { size += 2; ptr++; }
        size++; ptr++;
      }
    }
  }

  return size;
}

// -----------------------------------------------------------------------
// Directory & file writing
// -----------------------------------------------------------------------
bool CodeItemDumper::EnsureMethodsDir() {
  if (dump_dir_.empty()) return false;
  struct stat st;

  // Ensure dump_dir_ exists with 777
  if (stat(dump_dir_.c_str(), &st) != 0) {
    if (mkdir(dump_dir_.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("codeitem_dump: cannot create %s: %d", dump_dir_.c_str(), errno);
      return false;
    }
  } else {
    // Fix permissions on existing dir
    chmod(dump_dir_.c_str(), 0777);
  }

  // Create/verify dump_dir/methods/ with 777
  std::string dir = dump_dir_ + "/methods";
  if (stat(dir.c_str(), &st) != 0) {
    if (mkdir(dir.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("codeitem_dump: cannot create %s: %d", dir.c_str(), errno);
      return false;
    }
  } else {
    // Fix permissions on existing methods dir
    chmod(dir.c_str(), 0777);
  }
  return true;
}

bool CodeItemDumper::WriteJsonFile(const CodeItemDumpTask& task) {
  if (!EnsureMethodsDir()) return false;

  char filename[512];
  snprintf(filename, sizeof(filename), "%s/methods/method_%08u_%.16s.json",
           dump_dir_.c_str(), task.method_idx, task.sha256_prefix);

  int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    LOGE("codeitem_dump: cannot create %s: %d", filename, errno);
    return false;
  }

  // Build JSON manually (no JSON library dependency)
  char buf[2048];
  int n = snprintf(buf, sizeof(buf),
      "{\n"
      "  \"dex_key\": \"%s\",\n"
      "  \"pid\": %d,\n"
      "  \"process_name\": \"%s\",\n"
      "  \"tid\": %d,\n"
      "  \"method_idx\": %u,\n"
      "  \"sha256_prefix\": \"%.16s\",\n"
      "  \"registers_size\": %u,\n"
      "  \"ins_size\": %u,\n"
      "  \"outs_size\": %u,\n"
      "  \"tries_size\": %u,\n"
      "  \"insns_size\": %u,\n"
      "  \"dump_size\": %zu,\n"
      "  \"dump_complete\": %s,\n"
      "  \"source\": \"%s\"\n"
      "}\n",
      task.dex_key,
      task.pid, task.process_name, task.tid,
      task.method_idx, task.sha256_prefix,
      task.registers_size, task.ins_size, task.outs_size,
      task.tries_size, task.insns_size,
      task.dump_size,
      task.dump_complete ? "true" : "false",
      task.source);

  ssize_t written = write(fd, buf, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1));
  close(fd);
  if (written <= 0) {
    LOGE("codeitem_dump: write json failed %s", filename);
    unlink(filename);
    return false;
  }
  return true;
}

bool CodeItemDumper::WriteCodeFile(const CodeItemDumpTask& task) {
  if (!EnsureMethodsDir()) return false;
  if (task.data == nullptr || task.dump_size == 0) {
    LOGW("codeitem_dump: write_code invalid task");
    return false;
  }

  char filename[512];
  snprintf(filename, sizeof(filename), "%s/methods/method_%08u_%.16s.code",
           dump_dir_.c_str(), task.method_idx, task.sha256_prefix);

  int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    LOGE("codeitem_dump: cannot create %s: %d", filename, errno);
    return false;
  }

  // Write in 64KB chunks
  const size_t chunk_size = 65536;
  size_t remaining = task.dump_size;
  const uint8_t* ptr = task.data;
  while (remaining > 0) {
    size_t to_write = (remaining > chunk_size) ? chunk_size : remaining;
    ssize_t w = write(fd, ptr, to_write);
    if (w <= 0) {
      LOGE("codeitem_dump: write code failed %s", filename);
      close(fd);
      unlink(filename);
      return false;
    }
    remaining -= (size_t)w;
    ptr += w;
  }
  close(fd);
  return true;
}

bool CodeItemDumper::AppendCsv(const CodeItemDumpTask& task) {
  if (!EnsureMethodsDir()) return false;

  char filename[512];
  snprintf(filename, sizeof(filename), "%s/methods/method_index.csv", dump_dir_.c_str());

  int fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (fd < 0) {
    LOGE("codeitem_dump: cannot open csv %s: %d", filename, errno);
    return false;
  }

  char line[640];
  int n = snprintf(line, sizeof(line), "%s,%u,%.16s,%u,%zu,%s,%s,%d,%.63s,%u,%u,%u,%u\n",
                   task.dex_key,
                   task.method_idx, task.sha256_prefix,
                   task.insns_size, task.dump_size,
                   task.dump_complete ? "complete" : "partial",
                   task.source,
                   task.pid, task.process_name,
                   task.registers_size, task.ins_size, task.outs_size, task.tries_size);
  write(fd, line, (size_t)(n < (int)sizeof(line) ? n : (int)sizeof(line) - 1));
  close(fd);
  return true;
}

// -----------------------------------------------------------------------
// Worker loop
// -----------------------------------------------------------------------
void CodeItemDumper::WorkerLoop() {
  LOGI("CodeItemDumper worker started");

  // Write CSV header
  {
    char filename[512];
    // Use dump_dir_ directly (it's set in Init)
    std::string dir = dump_dir_;
    if (!dir.empty()) {
      // Ensure methods dir exists
      struct stat st;
      std::string methods_dir = dir + "/methods";
      if (stat(methods_dir.c_str(), &st) != 0) {
        mkdir(methods_dir.c_str(), 0777);
      }

      snprintf(filename, sizeof(filename), "%s/methods/method_index.csv", dir.c_str());
      int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
      if (fd >= 0) {
        const char* header = "dex_key,method_idx,sha256_prefix,insns_size,dump_size,status,source,pid,process_name,registers_size,ins_size,outs_size,tries_size\n";
        write(fd, header, strlen(header));
        close(fd);
      }
    }
  }

  while (running_) {
    CodeItemDumpTask task;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      cv_.wait_for(lock, std::chrono::seconds(1), [this]() {
        return !queue_.empty() || !running_;
      });

      if (!running_) break;
      if (queue_.empty()) continue;

      task = std::move(queue_.front());
      queue_.pop();
    }

    // Check max limit
    if (dumped_count_.load() >= max_dumps_) {
      LOGW("codeitem_dump: max reached, dropping queue (remaining=%zu)", queue_.size());
      continue;
    }

    // Validate before writing
    if (!IsValidCodeItem(task)) {
      LOGW("codeitem_dump: invalid task for method_%u (regs=%u ins=%u outs=%u tries=%u insns=%u)",
           task.method_idx, task.registers_size, task.ins_size, task.outs_size,
           task.tries_size, task.insns_size);
      continue;
    }

    bool ok = WriteJsonFile(task);
    if (ok) ok = WriteCodeFile(task);
    if (ok) ok = AppendCsv(task);

    if (ok) {
      dumped_count_.fetch_add(1);
      LOGI("codeitem_dump: method_%08u_%.16s (%zu bytes) [%s]",
           task.method_idx, task.sha256_prefix,
           task.dump_size, task.dump_complete ? "complete" : "partial");
    } else {
      LOGE("codeitem_dump: write failed for method_%08u", task.method_idx);
    }
  }

  LOGI("CodeItemDumper worker exited (dumped=%zu)", dumped_count_.load());
}

}  // namespace fart
