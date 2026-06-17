// Minimal Zygisk API type declarations (compatible with Magisk Zygisk v4 / ZygiskNext)
// Only declares what the FART loader needs.

#ifndef ZYGISK_LOADER_H_
#define ZYGISK_LOADER_H_

#include <jni.h>
#include <dlfcn.h>

namespace zygisk {

// Opaque API pointer passed to onModuleLoad
struct Api;

// Arguments passed to pre/post specialize hooks
struct AppSpecializeArgs {
  jint* nice_name;          // ptr to jint uid
  jboolean* is_child_zygote;
  jstring* nice_name_str;   // ptr to jstring for process name
  jstring* app_data_dir;    // ptr to jstring for app data dir
  jintArray* gids;
  jint* runtime_flags;
  jintArray* mounted_ns_fds;
};

// Base class for Zygisk modules
class ModuleBase {
 public:
  // Called when module is loaded into Zygote process
  virtual void onLoad(Api* api) {}

  // Called before app process specialization (in Zygote)
  virtual void preAppSpecialize(AppSpecializeArgs* args) {}

  // Called after app process specialization (in app process)
  virtual void postAppSpecialize(AppSpecializeArgs* args) {}

  // Called before system server specialization
  virtual void preServerSpecialize(AppSpecializeArgs* args) {}

  // Called after system server specialization
  virtual void postServerSpecialize(AppSpecializeArgs* args) {}

  virtual ~ModuleBase() = default;
};

}  // namespace zygisk

// Registration macro (Zygisk scans for this symbol or uses it via RTLD)
#define REGISTER_ZYGISK_MODULE(ModuleClass) \
  extern "C" __attribute__((visibility("default"))) \
  zygisk::ModuleBase* zygisk_module_create(zygisk::Api* api) { \
    auto* mod = new ModuleClass(); \
    mod->onLoad(api); \
    return mod; \
  }

#endif  // ZYGISK_LOADER_H_
