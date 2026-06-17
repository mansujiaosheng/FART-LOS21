// zygisk_loader.c -- FART Zygisk loader module (pure C)
//
// Minimal Zygisk module entry. In postAppSpecialize:
//   - read config
//   - check allowlist/blacklist
//   - dlopen libfart-hook.so
//
// Pure C - no C++ runtime dependency. Links cleanly into zygote.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define CONFIG_PATH  "/data/local/tmp/fart/config.json"
#define MODULE_CONF  "/data/adb/modules/fart-los21/config/config.json"
#define HOOK_LIB     "/data/adb/modules/fart-los21/lib64/libfart-hook.so"

// Built-in blacklist (system processes)
#define BUILTIN_BLACKLIST \
  "android\0com.android.systemui\0com.android.phone\0" \
  "com.android.settings\0system_server\0zygote\0zygote64\0"

// ======== Minimal JSON reader (C) ========
static char* read_file(const char* path) {
  FILE* f = fopen(path, "r");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  if (len <= 0) { fclose(f); return NULL; }
  fseek(f, 0, SEEK_SET);
  char* buf = (char*)malloc((size_t)len + 1);
  if (!buf) { fclose(f); return NULL; }
  size_t n = fread(buf, 1, (size_t)len, f);
  fclose(f);
  buf[n] = 0;
  return buf;
}

static int json_enabled(const char* json) {
  const char* p = strstr(json, "\"enable\"");
  if (!p) return 0;
  p = strchr(p, ':');
  if (!p) return 0;
  p++; while (*p == ' ' || *p == '\t' || *p == '\n') p++;
  return (strncmp(p, "true", 4) == 0);
}

static int in_array(const char* json, const char* key, const char* value) {
  char search[64];
  snprintf(search, sizeof(search), "\"%s\"", key);
  const char* p = strstr(json, search);
  if (!p) return 0;
  p = strchr(p, '[');
  if (!p) return 0;
  p++;
  while (*p && *p != ']') {
    const char* q = strchr(p, '"');
    if (!q) break;
    q++;
    const char* r = strchr(q, '"');
    if (!r) break;
    size_t len = (size_t)(r - q);
    if (len == strlen(value) && strncmp(q, value, len) == 0) return 1;
    p = r + 1;
  }
  return 0;
}

// ======== Config loading ========
static int load_config(int* enable, const char** config_ptr) {
  *enable = 0;
  char* json = read_file(CONFIG_PATH);
  if (!json) json = read_file(MODULE_CONF);
  if (!json) {
    LOGW("Config not found at %s or %s", CONFIG_PATH, MODULE_CONF);
    return 0;
  }
  *enable = json_enabled(json);
  *config_ptr = json;
  return 1;
}

static int is_blacklisted(const char* pkg, const char* json) {
  // Built-in blacklist
  static const char* blist[] = {
    "android", "com.android.systemui", "com.android.phone",
    "com.android.settings", "system_server", "zygote", "zygote64", NULL
  };
  for (int i = 0; blist[i]; i++)
    if (strcmp(pkg, blist[i]) == 0) return 1;

  // Config blacklist
  if (json) return in_array(json, "blacklist_packages", pkg);
  return 0;
}

static int is_allowed(const char* pkg, const char* json) {
  if (!json) return 0;
  return in_array(json, "packages", pkg);
}

// ======== Process name ========
static void get_process_name(char* out, int out_size) {
  int fd = open("/proc/self/cmdline", O_RDONLY);
  if (fd < 0) { out[0] = 0; return; }
  int n = (int)read(fd, out, (size_t)out_size - 1);
  close(fd);
  if (n > 0) out[n] = 0; else out[0] = 0;
}

// ======== Zygisk exports ========
// ZygiskNext/Magisk Zygisk expects these symbols from zygisk/arm64-v8a.so:

// The Api struct - opaque pointer, we don't need its contents in postAppSpecialize
struct Api { void* vtable; };
struct AppSpecializeArgs {
  jint* nice_name;
  jboolean* is_child_zygote;
  jstring* nice_name_str;
  jstring* app_data_dir;
  jintArray* gids;
  jint* runtime_flags;
  jintArray* mounted_ns_fds;
};

// Module base - Zygisk calls these hooks
struct ModuleBase { void* vtable; };

// Zygisk API vtable (for getModuleInfo, connectCompanion, etc.)
// We don't need most of these; just store the pointer.
// module api
struct ModuleApi {
  void* api_vtable;
  int api_version;
};

// The module instance
static struct ModuleBase g_module;
static struct ModuleApi g_api;

// Pre/post specialize hooks
typedef void (*pre_specialize_t)(struct ModuleBase*, struct AppSpecializeArgs*);
typedef void (*post_specialize_t)(struct ModuleBase*, struct AppSpecializeArgs*);

// ======== Helper: get process name from JNI ========
static char g_process_name[256] = "";

// Always use /proc/self/cmdline (no JNI dependency at dlopen time)
static void store_process_name(struct AppSpecializeArgs* args) {
  (void)args;
  get_process_name(g_process_name, sizeof(g_process_name));
}

// ======== Hook implementations ========
static void on_load(struct ModuleBase* self, struct Api* api) {
  LOGI("onLoad: FART loader loaded in zygote");
  // Store API ptr - not used yet since we only need postAppSpecialize
  (void)self;
  (void)api;
}

static void pre_app_specialize(struct ModuleBase* self,
                                struct AppSpecializeArgs* args) {
  (void)self;
  store_process_name(args);
}

static void post_app_specialize(struct ModuleBase* self,
                                 struct AppSpecializeArgs* args) {
  (void)self;
  (void)args;

  LOGI("postAppSpecialize: process=%s", g_process_name);

  if (g_process_name[0] == '\0') return;

  // Build-in blacklist
  if (is_blacklisted(g_process_name, NULL)) {
    LOGI("System process '%s' skipped", g_process_name);
    return;
  }

  // Load config
  int enable = 0;
  const char* json = NULL;
  if (!load_config(&enable, &json)) {
    LOGW("Config not loaded, skipping");
    return;
  }

  if (!enable) {
    LOGI("FART disabled by config");
    if (json) free((void*)json);
    return;
  }

  // Blacklist check
  if (is_blacklisted(g_process_name, json)) {
    LOGI("'%s' in blacklist, skipped", g_process_name);
    if (json) free((void*)json);
    return;
  }

  // Allowlist check
  if (!is_allowed(g_process_name, json)) {
    LOGI("'%s' not in allowlist, skipped", g_process_name);
    if (json) free((void*)json);
    return;
  }

  if (json) free((void*)json);

  // ✅ Hit! Load hook lib
  LOGI("✅ '%s' in allowlist, loading hook lib", g_process_name);

  if (access(HOOK_LIB, R_OK) != 0) {
    LOGE("Hook lib not found at %s", HOOK_LIB);
    return;
  }

  void* handle = dlopen(HOOK_LIB, RTLD_NOW);
  if (handle) {
    LOGI("✅ Hook lib loaded: %s (handle=%p)", HOOK_LIB, handle);
  } else {
    LOGE("❌ dlopen failed: %s", dlerror());
  }
}

static void pre_server_specialize(struct ModuleBase* self,
                                   struct AppSpecializeArgs* args) {
  (void)self; (void)args;
  LOGI("preServerSpecialize");
}

static void post_server_specialize(struct ModuleBase* self,
                                    struct AppSpecializeArgs* args) {
  (void)self; (void)args;
  LOGI("postServerSpecialize");
}

// Virtual table for ModuleBase
static void* module_vtable[] = {
  (void*)on_load,
  (void*)pre_app_specialize,
  (void*)post_app_specialize,
  (void*)pre_server_specialize,
  (void*)post_server_specialize,

};

// ZygiskModule constructor
__attribute__((constructor))
static void module_init(void) {
  g_module.vtable = module_vtable;
}

// Export: zygisk_module_create (Magisk Zygisk API) - MUST be default visibility
__attribute__((visibility("default")))
struct ModuleBase* zygisk_module_create(void* api) {
  if (api) g_api.api_vtable = api;
  LOGI("zygisk_module_create: module=%p, api=%p", &g_module, api);
  on_load(&g_module, (struct Api*)api);
  return &g_module;
}

// Export: zygisk_module_entry (ZygiskNext API)
__attribute__((visibility("default")))
struct ModuleBase* zygisk_module_entry(void* api) {
  return zygisk_module_create(api);
}
