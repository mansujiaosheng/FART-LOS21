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
  strcpy(source, "unknown");
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
// Directory & file writing
// -----------------------------------------------------------------------
bool CodeItemDumper::EnsureMethodsDir() {
  if (dump_dir_.empty()) return false;
  struct stat st;

  // Create dump_dir/methods/ if needed
  std::string dir = dump_dir_ + "/methods";
  if (stat(dir.c_str(), &st) != 0) {
    if (mkdir(dir.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("codeitem_dump: cannot create %s: %d", dir.c_str(), errno);
      return false;
    }
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
      "  \"pid\": %d,\n"
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
      task.pid, task.tid,
      task.method_idx, task.sha256_prefix,
      task.registers_size, task.ins_size, task.outs_size,
      task.tries_size, task.insns_size,
      task.dump_size,
      task.dump_complete ? "true" : "false");

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

  char line[256];
  int n = snprintf(line, sizeof(line), "%u,%.16s,%u,%u,%s\n",
                   task.method_idx, task.sha256_prefix,
                   task.insns_size, task.dump_size,
                   task.dump_complete ? "complete" : "partial");
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
        const char* header = "method_idx,sha256_prefix,insns_size,dump_size,status\n";
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
