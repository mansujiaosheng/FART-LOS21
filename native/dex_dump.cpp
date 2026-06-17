#include "dex_dump.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// -----------------------------------------------------------------------
// Minimal SHA-256 implementation (public domain)
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
// DexDumpTask
// -----------------------------------------------------------------------
namespace fart {

DexDumpTask::~DexDumpTask() {
  delete[] data;
  data = nullptr;
}

bool DexDumpTask::CopyData(const uint8_t* src, size_t sz) {
  if (src == nullptr || sz == 0) return false;
  uint8_t* new_data = new (std::nothrow) uint8_t[sz];
  if (new_data == nullptr) return false;
  memcpy(new_data, src, sz);
  delete[] data;
  data = new_data;
  size = sz;
  return true;
}

// -----------------------------------------------------------------------
// DexDumper
// -----------------------------------------------------------------------
static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"

DexDumper::DexDumper() = default;

DexDumper::~DexDumper() {
  running_ = false;
  cv_.notify_all();
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

bool DexDumper::Init(const char* dump_dir) {
  if (dump_dir == nullptr || dump_dir[0] == '\0') {
    LOGE("Invalid dump directory");
    return false;
  }
  dump_dir_ = dump_dir;

  // Create base dump directory
  struct stat st;
  if (stat(dump_dir_.c_str(), &st) != 0) {
    if (mkdir(dump_dir_.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("Failed to create dump dir %s: %d", dump_dir_.c_str(), errno);
      return false;
    }
  }

  running_ = true;
  worker_thread_ = std::thread(&DexDumper::WorkerLoop, this);
  LOGI("DexDumper initialized: dir=%s", dump_dir_.c_str());
  return true;
}

bool DexDumper::IsValidDex(const uint8_t* data, size_t size) {
  if (data == nullptr || size < sizeof(uint32_t) * 4) return false;
  // Check magic: "dex\n" + version digits
  if (memcmp(data, kDexMagic, 4) != 0) return false;
  // Check version (035, 037, 038, 039)
  uint8_t v0 = data[4], v1 = data[5], v2 = data[6];
  if (v0 < '0' || v0 > '9' || v1 < '0' || v1 > '9' || v2 < '0' || v2 > '9') {
    return false;
  }
  // Check end of version line: '\0'
  if (data[7] != 0) return false;
  return true;
}

void DexDumper::ComputeSha256(const uint8_t* data, size_t size, uint8_t out[32]) {
  Sha256Ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, size);
  sha256_final(&ctx, out);
}

std::string DexDumper::Sha256Prefix(const uint8_t sha256[32]) {
  static const char hex[] = "0123456789abcdef";
  char buf[17] = {0};
  for (int i = 0; i < 8; i++) {
    buf[i * 2] = hex[sha256[i] >> 4];
    buf[i * 2 + 1] = hex[sha256[i] & 0xf];
  }
  return std::string(buf);
}

bool DexDumper::QueueDex(const DexDumpTask& task) {
  if (!running_) return false;

  // Validate dex
  if (!IsValidDex(task.data, task.size)) {
    LOGW("Invalid dex: location=%s, size=%zu", task.location.c_str(), task.size);
    return false;
  }

  // Copy data FIRST (avoid reading from ART heap during computation)
  DexDumpTask copy;
  copy.package_name = task.package_name;
  copy.pid = task.pid;
  copy.tid = task.tid;
  copy.location = task.location;
  if (!copy.CopyData(task.data, task.size)) {
    LOGE("Failed to copy dex data");
    return false;
  }

  // Compute SHA256 from COPY (safe, not in ART heap)
  uint8_t sha256[32];
  ComputeSha256(copy.data, copy.size, sha256);
  memcpy(copy.sha256, sha256, 32);
  std::string prefix = Sha256Prefix(sha256);

  // Queue for async write
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    queue_.push(std::move(copy));
  }
  cv_.notify_one();
  return true;
}

size_t DexDumper::QueueSize() const {
  std::lock_guard<std::mutex> lock(queue_mutex_);
  return queue_.size();
}

bool DexDumper::EnsurePackageDir(const std::string& package) {
  if (package.empty()) return false;

  std::string pkg_dir = dump_dir_ + "/" + package;
  struct stat st;
  if (stat(pkg_dir.c_str(), &st) != 0) {
    if (mkdir(pkg_dir.c_str(), 0777) != 0 && errno != EEXIST) {
      LOGE("Failed to create package dir %s: %d", pkg_dir.c_str(), errno);
      return false;
    }
  }
  return true;
}

bool DexDumper::WriteDexFile(const DexDumpTask& task) {
  if (!EnsurePackageDir(task.package_name)) return false;

  std::string prefix = Sha256Prefix(task.sha256);
  char filename[512];
  snprintf(filename, sizeof(filename), "%s/%s/dex_%d_%zu_%s.dex",
           dump_dir_.c_str(), task.package_name.c_str(),
           task.pid, dumped_count_.load(), prefix.c_str());

  int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    LOGE("Failed to open %s: %d", filename, errno);
    return false;
  }

  // Write in chunks to avoid large single write crashes
  const size_t chunk_size = 65536; // 64KB chunks
  size_t remaining = task.size;
  const uint8_t* ptr = task.data;
  while (remaining > 0) {
    size_t to_write = (remaining > chunk_size) ? chunk_size : remaining;
    // Validate pointer before write
    if (ptr == nullptr) { LOGE("null data pointer"); close(fd); unlink(filename); return false; }
    volatile uint8_t validate = ptr[0]; (void)validate; // touch memory
    ssize_t written = write(fd, ptr, to_write);
    if (written <= 0) {
      LOGE("write error at offset %zu: %d", task.size - remaining, errno);
      close(fd); unlink(filename); return false;
    }
    remaining -= (size_t)written;
    ptr += written;
  }
  close(fd);

  LOGI("Dumped dex: %s (%zu bytes)", filename, task.size);
  return true;
}

void DexDumper::WorkerLoop() {
  LOGI("Dump worker thread started");

  while (running_) {
    DexDumpTask task;
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

    if (WriteDexFile(task)) {
      dumped_count_.fetch_add(1);
    }
  }

  LOGI("Dump worker thread exited (total=%zu, dup=%zu)",
       dumped_count_.load(), dup_count_.load());
}

}  // namespace fart
