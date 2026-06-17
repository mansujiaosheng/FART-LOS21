// arm64_hook.h – ARM64 inline hook (absolute jump in trampoline)
#pragma once
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace fart {

class Arm64InlineHook {
 public:
  Arm64InlineHook() = default;
  ~Arm64InlineHook() { Unhook(); }

  bool Hook(void* target, void* replacement, void** original) {
    if (!target || !replacement) return false;
    target_addr_ = (uintptr_t)target;
    static constexpr size_t kH = 16;
    memcpy(saved_bytes_, target, kH);
    trampoline_addr_ = (uintptr_t)mmap(nullptr, 32, PROT_READ|PROT_WRITE|PROT_EXEC,
                                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (!trampoline_addr_) return false;
    memcpy((void*)trampoline_addr_, saved_bytes_, kH);
    *(uint32_t*)(trampoline_addr_ + kH) = 0x58000000 | (17 << 0) | (2 << 5);
    *(uint32_t*)(trampoline_addr_ + kH + 4) = 0xD61F0000 | (17 << 5);
    *(uint64_t*)(trampoline_addr_ + kH + 8) = target_addr_ + kH;
    if (original) *original = (void*)trampoline_addr_;
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t pg = target_addr_ & ~(uintptr_t)(ps - 1);
    mprotect((void*)pg, ps, PROT_READ|PROT_WRITE|PROT_EXEC);
    __sync_synchronize();
    *(uint32_t*)target_addr_ = 0x58000000 | (17 << 0) | (2 << 5);
    *(uint32_t*)(target_addr_ + 4) = 0xD61F0000 | (17 << 5);
    *(uint64_t*)(target_addr_ + 8) = (uintptr_t)replacement;
    __builtin___clear_cache((char*)target_addr_, (char*)(target_addr_ + 16));
    hooked_ = true;
    return true;
  }

  bool Unhook() {
    if (!hooked_) return true;
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t pg = target_addr_ & ~(uintptr_t)(ps - 1);
    mprotect((void*)pg, ps, PROT_READ|PROT_WRITE|PROT_EXEC);
    __sync_synchronize();
    memcpy((void*)target_addr_, saved_bytes_, 16);
    __builtin___clear_cache((char*)target_addr_, (char*)(target_addr_ + 16));
    if (trampoline_addr_) munmap((void*)trampoline_addr_, 32);
    hooked_ = false;
    return true;
  }

 private:
  uintptr_t target_addr_ = 0;
  uint8_t saved_bytes_[16] = {};
  uintptr_t trampoline_addr_ = 0;
  bool hooked_ = false;
};

}  // namespace fart
