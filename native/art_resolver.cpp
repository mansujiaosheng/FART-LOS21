#include "art_resolver.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>
#include <sys/mman.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace fart {

ArtResolver::ArtResolver() = default;
ArtResolver::~ArtResolver() = default;

bool ArtResolver::FindLibArtInMaps() {
  FILE* fp = fopen("/proc/self/maps", "r");
  if (!fp) {
    LOGE("Failed to open /proc/self/maps");
    return false;
  }

  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    // Look for libart.so executable segment
    if (strstr(line, "libart.so") && strstr(line, "r-xp")) {
      uintptr_t start, end, file_off = 0;
      // Parse: start-end perms offset ... path
      // The offset is the 3rd field (file offset)
      char perms[8] = {0};
      if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &file_off) >= 3) {
        // libart_base_ should be file base, not segment base
        // Subtract file offset to get file base address in memory
        libart_base_ = start - file_off;
        libart_size_ = end - start;
        LOGI("Found libart.so: seg_start=0x%lx file_off=0x%lx file_base=0x%lx",
             start, file_off, libart_base_);
        fclose(fp);
        return true;
      }
    }
  }
  fclose(fp);

  // Try fallback: find any executable segment of libart
  fp = fopen("/proc/self/maps", "r");
  if (!fp) return false;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libart.so")) {
      uintptr_t start, end, file_off = 0;
      char perms[8] = {0};
      if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &file_off) >= 3) {
        uintptr_t file_base = start - file_off;
        if (libart_base_ == 0 || file_base < libart_base_) {
          libart_base_ = file_base;
        }
        libart_size_ = (end - start > 0) ? (end - start) : libart_size_;
      }
    }
  }
  fclose(fp);

  if (libart_base_ != 0) {
    LOGI("Found libart.so (fallback) at base=0x%lx", libart_base_);
    return true;
  }

  LOGE("libart.so not found in process maps");
  return false;
}

bool ArtResolver::Init() {
  if (initialized_) return true;
  initialized_ = FindLibArtInMaps();
  return initialized_;
}

void* ArtResolver::ResolveByName(const char* symbol_name) {
  if (!initialized_) Init();

  // Try dlsym first (works with .dynsym if not fully stripped)
  void* addr = dlsym(RTLD_DEFAULT, symbol_name);
  if (addr != nullptr) {
    LOGI("Resolved symbol '%s' via dlsym: %p", symbol_name, addr);
    return addr;
  }

  // Try RTLD_NEXT
  addr = dlsym(RTLD_NEXT, symbol_name);
  if (addr != nullptr) {
    LOGI("Resolved symbol '%s' via RTLD_NEXT: %p", symbol_name, addr);
    return addr;
  }

  LOGW("Symbol '%s' not found via dlsym", symbol_name);
  return nullptr;
}

void* ArtResolver::ResolveByOffset(int64_t offset) {
  if (!initialized_) Init();
  if (libart_base_ == 0) {
    LOGE("libart base not available for offset resolution");
    return nullptr;
  }
  void* addr = reinterpret_cast<void*>(libart_base_ + offset);
  LOGI("Resolved by offset 0x%lx -> 0x%lx", offset, reinterpret_cast<uintptr_t>(addr));
  return addr;
}

void* ArtResolver::ResolveByPattern(const char* pattern, size_t pattern_len, int64_t scan_range) {
  if (!initialized_) Init();
  if (libart_base_ == 0) {
    LOGE("libart base not available for pattern scan");
    return nullptr;
  }

  size_t scan_size = (scan_range > 0 && static_cast<size_t>(scan_range) < libart_size_)
                         ? static_cast<size_t>(scan_range)
                         : libart_size_;

  const uint8_t* begin = reinterpret_cast<const uint8_t*>(libart_base_);
  const uint8_t* end = begin + scan_size;

  // Pattern matching with wildcards (?? = any byte)
  for (const uint8_t* p = begin; p + pattern_len < end; ++p) {
    bool match = true;
    for (size_t i = 0; i < pattern_len; ++i) {
      if (pattern[i] == '?' && pattern[i] == '?') continue; // wildcard
      if (static_cast<uint8_t>(pattern[i]) != p[i]) {
        match = false;
        break;
      }
    }
    if (match) {
      uintptr_t offset = p - begin;
      LOGI("Pattern match at offset 0x%lx", offset);
      return const_cast<uint8_t*>(p);
    }
  }

  LOGE("Pattern not found in scan range 0x%lx", scan_size);
  return nullptr;
}

void ArtResolver::DumpArtSymbols(const std::vector<std::string>& keywords) {
  if (!initialized_) Init();
  LOGI("libart.so base=0x%lx, size=0x%zx", libart_base_, libart_size_);

  for (const auto& kw : keywords) {
    // Try dlsym for each keyword
    void* addr = dlsym(RTLD_DEFAULT, kw.c_str());
    if (addr != nullptr) {
      uintptr_t offset = reinterpret_cast<uintptr_t>(addr) - libart_base_;
      LOGI("  Symbol '%s' -> addr=%p, offset=0x%lx", kw.c_str(), addr, offset);
    } else {
      LOGI("  Symbol '%s' not found via dlsym", kw.c_str());
    }
  }
}

}  // namespace fart
