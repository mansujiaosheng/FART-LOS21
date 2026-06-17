#ifndef FART_LOS21_DEX_DUMP_H_
#define FART_LOS21_DEX_DUMP_H_

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_set>

namespace fart {

// Represents a DexFile to dump
struct DexDumpTask {
  std::string package_name;
  int pid;
  int tid;
  std::string location;
  uint8_t* data = nullptr;
  size_t size = 0;
  uint8_t sha256[32];

  ~DexDumpTask();
  bool CopyData(const uint8_t* src, size_t sz);
};

// Async dex dump worker
class DexDumper {
 public:
  DexDumper();
  ~DexDumper();

  // Initialize with dump directory
  bool Init(const char* dump_dir);

  // Queue a dex for dumping (called from hook callback - NO heavy IO!)
  // Returns true if queued, false if duplicate
  bool QueueDex(const DexDumpTask& task);

  // Get current queue size
  size_t QueueSize() const;

  // Get total dumped count
  size_t DumpedCount() const { return dumped_count_.load(); }

  // Get duplicate count
  size_t DupCount() const { return dup_count_.load(); }

 private:
  std::string dump_dir_;
  std::thread worker_thread_;
  std::atomic<bool> running_{false};
  std::atomic<size_t> dumped_count_{0};
  std::atomic<size_t> dup_count_{0};

  // Dedup set (SHA256 first 8 bytes in hex)
  std::unordered_set<std::string> dedup_set_;
  mutable std::mutex dedup_mutex_;

  // Task queue
  std::queue<DexDumpTask> queue_;
  mutable std::mutex queue_mutex_;
  std::condition_variable cv_;

  // Worker thread function
  void WorkerLoop();

  // Validate dex magic
  static bool IsValidDex(const uint8_t* data, size_t size);

  // Compute SHA256
  static void ComputeSha256(const uint8_t* data, size_t size, uint8_t out[32]);

  // Get hex fingerprint for dedup
  static std::string Sha256Prefix(const uint8_t sha256[32]);

  // Actual file write (called from worker thread)
  bool WriteDexFile(const DexDumpTask& task);

  // Ensure dump directory for package exists
  bool EnsurePackageDir(const std::string& package);
};

}  // namespace fart

#endif  // FART_LOS21_DEX_DUMP_H_
