#ifndef FART_LOS21_CODEITEM_DUMP_H_
#define FART_LOS21_CODEITEM_DUMP_H_

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_set>

namespace fart {

// A task representing a single CodeItem to dump (with owned buffer)
struct CodeItemDumpTask {
  int pid;
  int tid;
  uint32_t method_idx;
  uint16_t registers_size;
  uint16_t ins_size;
  uint16_t outs_size;
  uint16_t tries_size;
  uint32_t insns_size;
  size_t dump_size;           // total bytes to write (header + insns)
  bool dump_complete;         // false if tries>0 (try/catch not dumped)
  uint8_t* data = nullptr;    // owned buffer

  // SHA256 first 8 hex chars for dedup
  char sha256_prefix[17];

  CodeItemDumpTask();
  ~CodeItemDumpTask();

  // Copy code_item bytes into owned buffer and compute hash
  bool CopyData(const uint8_t* src, size_t sz);
};

// Async CodeItem dump worker
class CodeItemDumper {
 public:
  CodeItemDumper();
  ~CodeItemDumper();

  // Initialize with dump directory and max limit
  bool Init(const char* dump_dir, uint32_t max_dumps);

  // Queue a CodeItem for dumping (called from hook callback - NO heavy IO!)
  // Returns:
  //   0 = queued
  //   1 = duplicate (dedup hit)
  //   2 = max limit reached
  //   3 = invalid / error
  int QueueDump(const CodeItemDumpTask& task);

  // Current queue size
  size_t QueueSize() const;

 private:
  std::string dump_dir_;
  std::thread worker_thread_;
  std::atomic<bool> running_{false};
  std::atomic<size_t> dumped_count_{0};
  std::atomic<size_t> dup_count_{0};
  uint32_t max_dumps_ = 500;

  // Dedup set: "<sha256_prefix>:<method_idx>"
  std::unordered_set<std::string> dedup_set_;
  mutable std::mutex dedup_mutex_;

  // Task queue
  std::queue<CodeItemDumpTask> queue_;
  mutable std::mutex queue_mutex_;
  std::condition_variable cv_;

  // Worker thread function
  void WorkerLoop();

  // Compute SHA256 of data (uses the same inline SHA256 from dex_dump.h)
  static void ComputeSha256(const uint8_t* data, size_t size, uint8_t out[32]);
  static void BytesToHex(const uint8_t* bytes, size_t len, char* out_hex);

  // Ensure methods directory exists
  bool EnsureMethodsDir();

  // Write JSON metadata file
  bool WriteJsonFile(const CodeItemDumpTask& task);

  // Write raw CodeItem bytes file
  bool WriteCodeFile(const CodeItemDumpTask& task);

  // Append to method_index.csv
  bool AppendCsv(const CodeItemDumpTask& task);
};

}  // namespace fart

#endif  // FART_LOS21_CODEITEM_DUMP_H_
