#ifndef FART_LOS21_FART_HOOK_H_
#define FART_LOS21_FART_HOOK_H_

#include "config.h"
#include "art_resolver.h"
#include "dex_dump.h"
#include "arm64_hook.h"

#include <string>
#include <atomic>
#include <cstdint>

namespace fart {

// Hook manager
class HookManager {
 public:
  HookManager();
  ~HookManager();

  // Initialize with config
  bool Init(const Config& config);

  // Setup all hooks
  bool SetupHooks();

  // Remove all hooks
  bool RemoveHooks();

  // Check if hooks are active
  bool IsActive() const { return hooks_active_.load(); }

  // Get current package name (set during onModuleLoad)
  void SetCurrentPackage(const char* pkg) { current_package_ = pkg ? pkg : ""; }
  const std::string& GetCurrentPackage() const { return current_package_; }

  // Access dumper
  DexDumper* GetDumper() { return &dumper_; }

  // Crash counter
  void IncrementCrashCount() { crash_count_.fetch_add(1); }
  int GetCrashCount() const { return crash_count_.load(); }

 private:
  ArtResolver resolver_;
  DexDumper dumper_;
  std::atomic<bool> hooks_active_{false};
  std::atomic<int> crash_count_{0};
  std::string current_package_;

 public:
  Config config_;

  // Hook targets
  void* define_class_addr_ = nullptr;
  void* art_method_invoke_addr_ = nullptr;

  // Persistent inline hook instances
  Arm64InlineHook* define_class_hook_ = nullptr;
  Arm64InlineHook* art_method_invoke_hook_ = nullptr;

  // Original function pointers
  using DefineClassFunc = void* (*)(void* self, const char* descriptor,
                                     size_t hash, void* class_loader,
                                     void* dex_file, void* dex_class_def);
  using ArtMethodInvokeFunc = void (*)(void* method, void* self,
                                        uint32_t* args, uint32_t args_size,
                                        void* result, const char* shorty);

  DefineClassFunc original_define_class_ = nullptr;
  ArtMethodInvokeFunc original_art_method_invoke_ = nullptr;

  // Hook callbacks (static)
  static void* DefineClassCallback(void* self, const char* descriptor,
                                    size_t hash, void* class_loader,
                                    void* dex_file, void* dex_class_def);
  static void ArtMethodInvokeCallback(void* method, void* self,
                                       uint32_t* args, uint32_t args_size,
                                       void* result, const char* shorty);

  // Helper: check if current package is in allowlist
  bool IsCurrentPackageAllowed() const;

  // Register crash signal handler
  void InstallCrashHandler();
};

// Global instance access
HookManager* GetHookManager();

}  // namespace fart

#endif  // FART_LOS21_FART_HOOK_H_
