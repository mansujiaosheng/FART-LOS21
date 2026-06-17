// zygisk_loader_cpp.cpp -- Zygisk module loader (C++ ABI, no libc++ runtime)
//
// Compiled with -nostdlib++ to avoid libc++_shared.so dependency.
// Uses only C APIs internally (open/read/strcmp/dlopen).
// C++ virtual functions for Zygisk ModuleBase ABI compatibility.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>
#include <jni.h>

#define LOG_TAG "FART_LOS21_LOADER"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace {

// ======== Zygisk Core API types ========
// These must match what ZygiskNext expects exactly (from Magisk Zygisk API v4)
namespace zygisk {
struct ApiBase {
  void* vt; // vtable pointer
};
struct AppSpecializeArgs {
  jint* nice_name;
  jboolean* is_child_zygote;
  jstring* nice_name_str;
  jstring* app_data_dir;
  jintArray* gids;
  jint* runtime_flags;
  jintArray* mounted_ns_fds;
};

class ModuleBase {
 public:
  virtual ~ModuleBase() = default;
  virtual void onLoad(Api* api) {}
  virtual void preAppSpecialize(AppSpecializeArgs* args) {}
  virtual void postAppSpecialize(AppSpecializeArgs* args) {}
  virtual void preServerSpecialize(AppSpecializeArgs* args) {}
  virtual void postServerSpecialize(AppSpecializeArgs* args) {}
};

struct Api {
  void* vtable;
  int api_version;
};

// Also accept old API name
[[gnu::weak]] struct ModuleBaseOld { virtual ~ModuleBaseOld() = default; virtual void onLoad(void* api) {} };
}

// ======== Config paths ========
static const char* kConfigPaths[] = {
  "/data/local/tmp/fart/config.json",
  "/data/adb/modules/fart-los21/config/config.json",
  nullptr
};
static const char* kHookLib = "/data/adb/modules/fart-los21/lib64/libfart-hook.so";

// ======== Minimal JSON helpers ========
static char* read_file(const char* path) {
  FILE* f = fopen(path, "r");
  if (!f) return nullptr;
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  if (len <= 0) { fclose(f); return nullptr; }
  fseek(f, 0, SEEK_SET);
  char* buf = (char*)malloc((size_t)(len + 1));
  if (!buf) { fclose(f); return nullptr; }
  size_t n = fread(buf, 1, (size_t)len, f);
  fclose(f);
  buf[n] = 0;
  return buf;
}

static bool json_bool(const char* j, const char* key) {
  if (!j) return false;
  const char* p = strstr(j, key);
  if (!p) return false;
  p = strchr(p, ':');
  if (!p) return false;
  p++; while (*p == ' ' || *p == '\t') p++;
  return strncmp(p, "true", 4) == 0;
}

static bool json_in_array(const char* j, const char* key, const char* val) {
  if (!j) return false;
  char sk[64]; snprintf(sk, sizeof(sk), "\"%s\"", key);
  const char* p = strstr(j, sk);
  if (!p) return false;
  p = strchr(p, '['); if (!p) return false;
  p++;
  while (*p && *p != ']') {
    const char* q = strchr(p, '"'); if (!q) break; q++;
    const char* r = strchr(q, '"'); if (!r) break;
    int len = (int)(r - q);
    if ((size_t)len == strlen(val) && strncmp(q, val, (size_t)len) == 0) return true;
    p = r + 1;
  }
  return false;
}

static const char* kBuiltinBlacklist[] = {
  "android", "com.android.systemui", "com.android.phone",
  "com.android.settings", "system_server", "zygote", "zygote64", nullptr
};

} // anonymous namespace

// ======== ModuleBase class - C++ ABI compatible ========
class FartLoader {
 public:
  // Virtual destructor is essential for correct vtable layout!
  virtual ~FartLoader() {}

  virtual void onLoad(Api* api) {
    LOGI("onLoad: loaded in zygote (api=%p)", api);
  }

  virtual void preAppSpecialize(AppSpecializeArgs* args) {
    // Read process name from /proc/self/cmdline
    char cmdline[256] = {};
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
      close(fd);
      if (n > 0) cmdline[n] = 0;
    }
    if (cmdline[0] == 0) return;

    // Check built-in blacklist
    for (int i = 0; kBuiltinBlacklist[i]; i++) {
      if (strcmp(cmdline, kBuiltinBlacklist[i]) == 0) return;
    }

    // Save for postAppSpecialize
    strncpy(process_name_, cmdline, sizeof(process_name_) - 1);
    LOGI("preAppSpecialize: %s", process_name_);
  }

  void postAppSpecialize(AppSpecializeArgs* args) {
    (void)args;
    const char* name = process_name_;
    if (name[0] == 0) return;

    LOGI("postAppSpecialize: %s", name);

    // Check built-in blacklist
    for (int i = 0; kBuiltinBlacklist[i]; i++) {
      if (strcmp(name, kBuiltinBlacklist[i]) == 0) return;
    }

    // Load config
    char* json = nullptr;
    for (int i = 0; kConfigPaths[i]; i++) {
      json = read_file(kConfigPaths[i]);
      if (json) break;
    }
    if (!json) { LOGW("No config"); return; }

    bool enable = json_bool(json, "\"enable\"");
    if (!enable) { LOGI("Disabled by config"); free(json); return; }

    if (json_in_array(json, "blacklist_packages", name)) {
      LOGI("Blacklisted: %s", name); free(json); return;
    }
    if (!json_in_array(json, "packages", name)) {
      LOGI("Not in allowlist: %s", name); free(json); return;
    }
    free(json);

    // Load hook library
    LOGI("✅ Loading hook for %s", name);
    if (access(kHookLib, R_OK) != 0) {
      LOGE("Hook lib not found: %s", kHookLib); return;
    }

    void* h = dlopen(kHookLib, RTLD_NOW);
    if (h) {
      LOGI("✅ %s loaded (handle=%p)", kHookLib, h);
    } else {
      LOGE("❌ dlopen: %s", dlerror());
    }
  }

  // Server hooks (no-op)
  void preServerSpecialize(void* args) { (void)args; }
  void postServerSpecialize(void* args) { (void)args; }

 private:
  char process_name_[256] = {};
};

// ======== VTable and instance ========
static FartLoader g_loader;

// ======== Exported entry points ========
// Note: ZN calls zygisk_module_create and uses the returned pointer
// as a zygisk::ModuleBase*. The return type must match what ZN expects.
// Using FartLoader* directly since it has the same vtable layout.

extern "C" __attribute__((visibility("default")))
FartLoader* zygisk_module_create(void* api) {
  LOGI("zygisk_module_create: loader=%p", &g_loader);
  g_loader.onLoad((Api*)api);
  return &g_loader;
}

extern "C" __attribute__((visibility("default")))
FartLoader* zygisk_module_entry(void* api) {
  return zygisk_module_create(api);
}
