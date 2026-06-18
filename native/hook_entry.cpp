// hook_entry.cpp – FART hook core
// Constructor: just logs. Init via fart_on_app_specialize() called by loader.

#include "config.h"
#include "art_resolver.h"
#include "dex_dump.h"
#include "arm64_hook.h"
#include "codeitem_dump.h"
#include "active_invoke.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <android/log.h>
#include <jni.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static thread_local bool g_fart_active_dump = false;
static thread_local bool g_fart_in_invoke = false;
static JNIEnv* g_env = nullptr;
static char g_package[256] = {};

namespace {

using namespace fart;

static Config g_config;
static ArtResolver* g_resolver = nullptr;
static DexDumper* g_dumper = nullptr;
static void* g_define_class_orig = nullptr;
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_hooks_active{false};
static Arm64InlineHook* g_define_hook = nullptr;

// ArtMethod::Invoke hook (Phase 2)
static Arm64InlineHook* g_artmethod_hook = nullptr;
static void* g_artmethod_invoke_orig = nullptr;
static std::atomic<bool> g_artmethod_hook_active{false};

// Stage 2.4: CodeItem dump worker
static CodeItemDumper* g_codeitem_dumper = nullptr;

// Stage 2.5: Active invoke engine
static ActiveInvokeEngine* g_active_invoke_engine = nullptr;

// P5: ClassLinker::LoadMethod hook
static Arm64InlineHook* g_load_method_hook = nullptr;
static void* g_load_method_orig = nullptr;

// Crash handlers
static struct sigaction old_sigsegv;
static struct sigaction old_sigbus;

static void CrashHandler(int sig, siginfo_t* info, void* context) {
  LOGE("CRASH: signal=%d, addr=%p, disabling hooks", sig, info->si_addr);
  if (g_define_hook) { g_define_hook->Unhook(); delete g_define_hook; g_define_hook = nullptr; }
  if (g_artmethod_hook) { g_artmethod_hook->Unhook(); delete g_artmethod_hook; g_artmethod_hook = nullptr; }
  g_hooks_active = false;
  g_artmethod_hook_active = false;
  struct sigaction* old = (sig == SIGSEGV) ? &old_sigsegv : &old_sigbus;
  if (old->sa_sigaction) old->sa_sigaction(sig, info, context);
  else if (old->sa_handler) old->sa_handler(sig);
  else { signal(sig, SIG_DFL); raise(sig); }
}

static void InstallCrashHandler() {
  struct sigaction sa; memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = CrashHandler; sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGSEGV, &sa, &old_sigsegv); sigaction(SIGBUS, &sa, &old_sigbus);
}

// ===== Memory validation =====
// Check if [addr, addr+size) is fully within a readable mapping
static bool IsRangeReadable(const void* addr, size_t size) {
  if (!addr || size == 0) return false;
  uintptr_t start = (uintptr_t)addr;
  uintptr_t end = start + size;
  FILE* fp = fopen("/proc/self/maps", "r");
  if (!fp) return false;
  char line[512];
  bool ok = false;
  while (fgets(line, sizeof(line), fp)) {
    uintptr_t map_start, map_end;
    char perms[8] = {};
    if (sscanf(line, "%lx-%lx %7s", &map_start, &map_end, perms) >= 3) {
      if (perms[0] == 'r' && start >= map_start && end <= map_end) {
        ok = true; break;
      }
    }
  }
  fclose(fp);
  return ok;
}

// ===== DefineClass Hook =====
extern "C" __attribute__((used))
void* DefineClassHook(void* class_linker, void* thread, const char* descriptor,
                       size_t hash, void* class_loader_handle,
                       void* dex_file_ptr, void* dex_class_def_ptr) {
  LOGI("DefineClassHook ENTER pid=%d tid=%d desc=%s dex_file=%p",
       getpid(), (int)syscall(__NR_gettid),
       descriptor ? descriptor : "null", dex_file_ptr);

  void* result = nullptr;
  if (g_define_class_orig) {
    auto orig = reinterpret_cast<void* (*)(void*, void*, const char*, size_t,
                                            void*, void*, void*)>(g_define_class_orig);
    result = orig(class_linker, thread, descriptor, hash,
                  class_loader_handle, dex_file_ptr, dex_class_def_ptr);
  }

  if (!g_hooks_active.load() || !g_config.dump_dex || !dex_file_ptr) return result;

  // Mask pointer tags (Android 14 uses TBI/tagged pointers)
  uintptr_t dex_obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFF;

  // Read begin_ from DexFile+8 (after vtable)
  const uint8_t* begin = *(const uint8_t**)(dex_obj + 8);
  if (!begin) { LOGW("begin_ is null"); return result; }
  if (!IsRangeReadable(begin, 32)) { LOGW("begin not readable"); return result; }

  // Verify dex magic
  static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a};
  if (memcmp(begin, kDexMagic, 4) != 0) { LOGW("bad dex magic"); return result; }

  // Read file_size from header (offset 0x20)
  uint32_t dex_size = *(const uint32_t*)(begin + 0x20);
  if (dex_size < 64 || dex_size > 0x20000000) { LOGW("invalid size: %u", dex_size); return result; }

  // Cap to the first readable mapped segment containing begin_
  {
    FILE* mf = fopen("/proc/self/maps", "r");
    if (mf) {
      uintptr_t b = (uintptr_t)begin;
      char line[512];
      while (fgets(line, sizeof(line), mf)) {
        uintptr_t s, e;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) >= 3) {
          if (perms[0] == 'r' && b >= s && b < e) {
            size_t max_size = (size_t)(e - b);
            if (max_size < (size_t)dex_size) {
              LOGI("Dex: begin=%p header_size=%u mapped_size=%zu", begin, dex_size, max_size);
              dex_size = (uint32_t)max_size;
            }
            break;
          }
        }
      }
      fclose(mf);
    }
  }

  // Deep copy and write synchronously (to /data/local/tmp/ for SELinux compatibility)
  pid_t pid = getpid();
  char filename[512];
  snprintf(filename, sizeof(filename), "%s/dex_%d_%d.dex",
           g_config.dump_dir.c_str(),
           pid, (int)syscall(__NR_gettid));

  // Read into stack/local buffer first (validate), then write
  int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) { LOGE("cannot open %s", filename); return result; }

  // Write in chunks
  const uint8_t* ptr = begin;
  size_t remaining = dex_size;
  bool write_ok = true;
  while (remaining > 0) {
    size_t chunk = (remaining > 65536) ? 65536 : remaining;
    // Validate first byte of each chunk before writing
    volatile uint8_t check = ptr[0]; (void)check;
    ssize_t w = write(fd, ptr, chunk);
    if (w <= 0) { write_ok = false; break; }
    remaining -= (size_t)w;
    ptr += w;
  }
  close(fd);
  if (write_ok) {
    LOGI("Dumped dex: %s (%u bytes)", filename, dex_size);
  } else {
    LOGE("write failed for %s", filename);
    unlink(filename);
  }

  return result;
}

// ===== ArtMethod::Invoke Hook (Phase 2) =====
// Signature matches ART source: Invoke(Thread*, uint32_t*, uint32_t, JValue*, const char*)
extern "C" __attribute__((used))
void ArtMethodInvokeHook(void* art_method, void* thread, uint32_t* args,
                          uint32_t args_size, void* result, const char* shorty) {
  // Reentry guard: prevent recursion if ArtMethod::Invoke is called
  // within our own callback (e.g. via LOGI -> android_log_print -> ...)
  if (g_fart_in_invoke) {
    goto call_original;
  }
  g_fart_in_invoke = true;

  // Stage 2.1: Sampling log (only when hook is active)
  if (g_artmethod_hook_active.load()) {
    static thread_local uint64_t g_invoke_count = 0;
    g_invoke_count++;

    uint32_t rate = g_config.artmethod_sample_rate;
    if (rate == 0) rate = 1000;
    if (g_invoke_count % rate == 1) {
      LOGI("Invoke #%lu: method=%p tid=%d",
           g_invoke_count, art_method, (int)syscall(__NR_gettid));

      // Stage 2.2: Parse ArtMethod fields
      uintptr_t m = (uintptr_t)art_method & 0x00FFFFFFFFFFFFFFULL;
      if (m != 0 && IsRangeReadable((void*)m, 0x20)) {
        // ArtMethod field offsets (Android 14 / LOS21, ARM64):
        //   0x00: declaring_class_ (GcRoot<Class>, 4 bytes compressed ref)
        //   0x04: access_flags_ (std::atomic<uint32_t>, 4 bytes)
        //   0x08: dex_method_index_ (uint32_t, 4 bytes)
        //   0x0C: method_index_ (uint16_t, 2 bytes)
        //   0x0E: hotness_count_ (uint16_t, 2 bytes)
        //   0x10: ptr_sized_fields_.data_ (void*, 8 bytes)
        //   0x18: entry_point_from_quick_compiled_code_ (void*, 8 bytes)

        uint32_t class_ref = *(const uint32_t*)(m + 0x00);
        uint32_t access_flags = *(const uint32_t*)(m + 0x04);
        uint32_t dex_idx = *(const uint32_t*)(m + 0x08);

        // Filter: skip uninitialized, runtime methods, native, abstract
        bool skip = false;
        if (class_ref == 0) skip = true;
        if (dex_idx == 0xFFFFFFFF) skip = true;  // kRuntimeMethodDexMethodIndex
        if (access_flags & 0x0100) skip = true;  // kAccNative
        if (access_flags & 0x0400) skip = true;  // kAccAbstract

        if (!skip) {
          LOGI("Method: class_ref=0x%x dex_idx=%u flags=0x%x",
               class_ref, dex_idx, access_flags);

          // Stage 2.3: Read CodeItem metadata from ptr_sized_fields_.data_ (offset 0x10)
          // At runtime, data_ is a direct CodeItem* pointer (bit 0 may be a flag)
          uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);
          const uint8_t* ci = (const uint8_t*)(data_ptr & ~1ULL);
          if (ci != nullptr && IsRangeReadable(ci, 16)) {
            uint16_t regs  = *(const uint16_t*)(ci + 0);
            uint16_t ins   = *(const uint16_t*)(ci + 2);
            uint16_t outs  = *(const uint16_t*)(ci + 4);
            uint16_t tries = *(const uint16_t*)(ci + 6);
            // Skip debug_info_off at +8 (4 bytes)
            uint32_t insns = *(const uint32_t*)(ci + 12);
            if (insns > 0 && insns < 65536) {
              LOGI("CodeItem: regs=%u ins=%u outs=%u tries=%u insns=%u ptr=%p",
                   regs, ins, outs, tries, insns, ci);

              // Stage 2.4: Passive CodeItem dump (header + insns only)
              if (g_config.enable_codeitem_dump && g_codeitem_dumper != nullptr) {
                CodeItemDumpTask citask;
                citask.pid = getpid();
                citask.tid = (pid_t)syscall(__NR_gettid);
                citask.method_idx = dex_idx;
                citask.registers_size = regs;
                citask.ins_size = ins;
                citask.outs_size = outs;
                citask.tries_size = tries;
                citask.insns_size = insns;
                citask.dump_size = CodeItemDumper::CalculateCodeItemSize(ci, tries, insns);
                citask.dump_complete = true;
                snprintf(citask.source, sizeof(citask.source), "%s",
                         g_active_invoke_running ? "active_invoke" : "ArtMethodInvoke");
                // Compute dex_key from code_item base (approximate DEX identity)
                uintptr_t ci_page = (uintptr_t)ci & ~0xFFFULL;
                snprintf(citask.dex_key, sizeof(citask.dex_key), "%lx", ci_page);

                // Sync memcpy to owned buffer (safe copy)
                if (citask.CopyData(ci, citask.dump_size)) {
                  int rc = g_codeitem_dumper->QueueDump(citask);
                  if (rc == 0) {
                    LOGI("codeitem_dump: queued method_%u (%zu bytes, %s)",
                         dex_idx, citask.dump_size,
                         citask.dump_complete ? "complete" : "partial");
                  } else if (rc == 1) {
                    LOGI("codeitem_dump: duplicate method_%u", dex_idx);
                  } else if (rc == 2) {
                    LOGW("codeitem_dump: max reached, skip method_%u", dex_idx);
                  } else {
                    LOGW("codeitem_dump: queue failed for method_%u", dex_idx);
                  }
                } else {
                  LOGW("codeitem_dump: CopyData failed for method_%u", dex_idx);
                }
              }
            } else {
              LOGI("CodeItem: invalid insns=%u (data_ptr=0x%zx)", insns, data_ptr);
            }
          } else {
            LOGI("CodeItem: null or not readable (data_ptr=0x%zx)", data_ptr);
          }
        }
      }
    }
  }

call_original:
  if (g_artmethod_invoke_orig) {
    auto orig = reinterpret_cast<void (*)(void*, void*, uint32_t*, uint32_t, void*, const char*)>(
        g_artmethod_invoke_orig);
    orig(art_method, thread, args, args_size, result, shorty);
  }
  g_fart_in_invoke = false;
}

// ===== Post-hook snapshot dump via Java reflection =====
static void DumpAlreadyLoadedDex(JNIEnv* env) {
  if (!env || !g_dumper) { LOGW("snapshot: no env or dumper"); return; }
  LOGI("snapshot: enumerating loaded dex files...");

  // Get class loaders via Java reflection
  // Path: activityThread -> Context -> ClassLoader -> BaseDexClassLoader -> pathList -> dexElements -> DexFile -> mCookie

  // 1. Get class loader for the current thread's context
  //    In postAppSpecialize, we need to get the app's class loader.
  //    We can use: Thread.currentThread().getContextClassLoader()

  jclass threadClass = env->FindClass("java/lang/Thread");
  if (!threadClass) { LOGW("snapshot: no Thread class"); return; }
  jmethodID currentThreadMid = env->GetStaticMethodID(threadClass, "currentThread", "()Ljava/lang/Thread;");
  jmethodID getContextClassLoaderMid = env->GetMethodID(threadClass, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
  if (!currentThreadMid || !getContextClassLoaderMid) { LOGW("snapshot: no Thread methods"); return; }

  jobject thread = env->CallStaticObjectMethod(threadClass, currentThreadMid);
  jobject classLoader = env->CallObjectMethod(thread, getContextClassLoaderMid);
  if (!classLoader) { LOGW("snapshot: no classLoader"); return; }
  LOGI("snapshot: got classLoader=%p", classLoader);

  // 2. Get DexPathList from BaseDexClassLoader
  //    pathList field: dalvik.system.BaseDexClassLoader.pathList
  jclass baseDexClassLoaderClass = env->FindClass("dalvik/system/BaseDexClassLoader");
  jfieldID pathListFid = env->GetFieldID(baseDexClassLoaderClass, "pathList", "Ldalvik/system/DexPathList;");
  if (!pathListFid) { LOGW("snapshot: no pathList field"); return; }
  jobject pathList = env->GetObjectField(classLoader, pathListFid);
  if (!pathList) { LOGW("snapshot: no pathList"); return; }

  // 3. Get dexElements array from DexPathList
  jclass dexPathListClass = env->FindClass("dalvik/system/DexPathList");
  jfieldID dexElementsFid = env->GetFieldID(dexPathListClass, "dexElements", "[Ldalvik/system/DexPathList$Element;");
  if (!dexElementsFid) { LOGW("snapshot: no dexElements field"); return; }
  jobjectArray dexElements = (jobjectArray)env->GetObjectField(pathList, dexElementsFid);
  if (!dexElements) { LOGW("snapshot: no dexElements"); return; }

  jsize elementCount = env->GetArrayLength(dexElements);
  LOGI("snapshot: %d dex elements", elementCount);

  // 4. For each element, get the DexFile and mCookie
  jclass elementClass = env->FindClass("dalvik/system/DexPathList$Element");
  jfieldID dexFileFid = env->GetFieldID(elementClass, "dexFile", "Ldalvik/system/DexFile;");

  jclass dexFileClass = env->FindClass("dalvik/system/DexFile");
  jfieldID mCookieFid = env->GetFieldID(dexFileClass, "mCookie", "Ljava/lang/Object;");

  // Also try to get the DexFile name
  jmethodID getNameMid = env->GetMethodID(dexFileClass, "getName", "()Ljava/lang/String;");

  for (int i = 0; i < elementCount; i++) {
    jobject element = env->GetObjectArrayElement(dexElements, i);
    if (!element) continue;
    jobject dexFile = env->GetObjectField(element, dexFileFid);
    if (!dexFile) continue;

    // Get name
    std::string loc = "unknown";
    if (getNameMid) {
      jstring nameStr = (jstring)env->CallObjectMethod(dexFile, getNameMid);
      if (nameStr) {
        const char* chars = env->GetStringUTFChars(nameStr, nullptr);
        if (chars) { loc = chars; env->ReleaseStringUTFChars(nameStr, chars); }
      }
    }

    // Get mCookie
    jobject cookie = env->GetObjectField(dexFile, mCookieFid);
    if (!cookie) { LOGI("snapshot[%d]: %s - no cookie", i, loc.c_str()); continue; }

    // mCookie is either a long (single dex) or long[] (multi-dex)
    // Try as long[] first, then as long
    jclass cookieClass = env->GetObjectClass(cookie);
    jboolean isArray = env->IsInstanceOf(cookie, env->FindClass("[J"));

    if (isArray) {
      jlongArray cookieArray = (jlongArray)cookie;
      jsize len = env->GetArrayLength(cookieArray);
      jlong* cookies = env->GetLongArrayElements(cookieArray, nullptr);
      LOGI("snapshot[%d]: %s - %d cookies", i, loc.c_str(), len);
      for (int c = 0; c < len; c++) {
        uintptr_t dex_ptr = (uintptr_t)cookies[c];
        if (dex_ptr == 0) continue;
        LOGI("snapshot[%d][%d]: cookie=0x%lx", i, c, dex_ptr);
        // Try to find dex magic near this pointer
        const uint8_t* begin = nullptr;
        size_t size = 0;
        static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a};
        for (int offs = -32; offs < 64; offs += 8) {
          const uint8_t* candidate = *(const uint8_t**)(dex_ptr + offs);
          if (!candidate) continue;
          if (memcmp(candidate, kDexMagic, 4) == 0) {
            uint32_t fsz = *(const uint32_t*)(candidate + 0x20);
            if (fsz > 64 && fsz < 0x4000000) {
              begin = candidate; size = fsz;
              LOGI("snapshot[%d][%d]: dex at offs=%d begin=%p size=%u", i, c, offs, begin, fsz);
              break;
            }
          }
        }
        if (begin && size > 0) {
          DexDumpTask task;
          task.package_name = g_package;
          task.pid = getpid(); task.tid = (pid_t)syscall(__NR_gettid);
          task.location = loc + ":" + std::to_string(c);
          task.CopyData(begin, size);
          g_dumper->QueueDex(task);
        }
      }
      env->ReleaseLongArrayElements(cookieArray, cookies, JNI_ABORT);
    } else {
      // Single long cookie (mCookie is a Long object)
      jclass longClass = env->FindClass("java/lang/Long");
      jmethodID longValueMid = env->GetMethodID(longClass, "longValue", "()J");
      if (longValueMid) {
        jlong val = env->CallLongMethod(cookie, longValueMid);
        uintptr_t dex_ptr = (uintptr_t)val;
        LOGI("snapshot[%d]: %s - single cookie=0x%lx", i, loc.c_str(), dex_ptr);
        if (dex_ptr != 0) {
          const uint8_t* begin = nullptr;
          size_t size = 0;
          static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a};
          for (int offs = -32; offs < 64; offs += 8) {
            const uint8_t* candidate = *(const uint8_t**)(dex_ptr + offs);
            if (!candidate) continue;
            if (memcmp(candidate, kDexMagic, 4) == 0) {
              uint32_t fsz = *(const uint32_t*)(candidate + 0x20);
              if (fsz > 64 && fsz < 0x4000000) {
                begin = candidate; size = fsz; break;
              }
            }
          }
          if (begin && size > 0) {
            DexDumpTask task;
            task.package_name = g_package;
            task.pid = getpid(); task.tid = (pid_t)syscall(__NR_gettid);
            task.location = loc;
            task.CopyData(begin, size);
            g_dumper->QueueDex(task);
          }
        }
      }
    }
  }
  LOGI("snapshot: done, queue=%zu", g_dumper->QueueSize());
}

// ===== ClassLinker::LoadMethod Hook (P5) =====
// Called when ART loads a method from DEX. This is where code_item becomes available.
// Signature (from class_linker.h):
//   void LoadMethod(const DexFile& dex_file, const ClassAccessor::Method& method,
//                   ObjPtr<mirror::Class> klass, ArtMethod* dst)
extern "C" __attribute__((used))
void LoadMethodHook(void* class_linker, void* dex_file_ptr, void* class_method_ptr,
                     void* klass, void* dst) {
  // Call original first
  if (!g_load_method_orig) return;
  auto orig = reinterpret_cast<void (*)(void*, void*, void*, void*, void*)>(g_load_method_orig);
  orig(class_linker, dex_file_ptr, class_method_ptr, klass, dst);
  if (!dst || !g_hooks_active.load()) return;

  // Read ArtMethod fields (same offsets as ArtMethodInvokeHook)
  uintptr_t m = (uintptr_t)dst & 0x00FFFFFFFFFFFFFFULL;
  if (m == 0) return;

  uint32_t dex_idx = *(const uint32_t*)(m + 0x08);
  if (dex_idx == 0 || dex_idx == 0xFFFFFFFF) return;

  uint32_t access_flags = *(const uint32_t*)(m + 0x04);
  if (access_flags & 0x0100) return;  // native
  if (access_flags & 0x0400) return;  // abstract

  // Read code_item pointer from ptr_sized_fields_.data_ (offset 0x10)
  uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);
  const uint8_t* ci = (const uint8_t*)(data_ptr & ~1ULL);
  if (ci == nullptr) return;

  // Read code_item header
  uint16_t regs  = *(const uint16_t*)(ci + 0);
  uint16_t ins   = *(const uint16_t*)(ci + 2);
  uint16_t outs  = *(const uint16_t*)(ci + 4);
  uint16_t tries = *(const uint16_t*)(ci + 6);
  uint32_t insns = *(const uint32_t*)(ci + 12);
  if (insns == 0 || insns > 524288) return;

  if (!g_config.enable_codeitem_dump || g_codeitem_dumper == nullptr) return;

  CodeItemDumpTask citask;
  citask.pid = getpid();
  citask.tid = (pid_t)syscall(__NR_gettid);
  citask.method_idx = dex_idx;
  citask.registers_size = regs;
  citask.ins_size = ins;
  citask.outs_size = outs;
  citask.tries_size = tries;
  citask.insns_size = insns;
  // Compute dex_key from code_item base page
  uintptr_t ci_page = (uintptr_t)ci & ~0xFFFULL;
  snprintf(citask.dex_key, sizeof(citask.dex_key), "%lx", ci_page);
  citask.dump_size = CodeItemDumper::CalculateCodeItemSize(ci, tries, insns);
  citask.dump_complete = true;
  snprintf(citask.source, sizeof(citask.source), "LoadMethod");

  if (citask.CopyData(ci, citask.dump_size)) {
    int rc = g_codeitem_dumper->QueueDump(citask);
    if (rc == 0) {
      LOGI("LoadMethod: queued method_%u (%zu bytes, tries=%u)",
           dex_idx, citask.dump_size, tries);
    } else if (rc == 1) {
      // duplicate, skip
    } else {
      LOGW("LoadMethod: queue failed for method_%u (rc=%d)", dex_idx, rc);
    }
  }
}

// ===== Setup Hooks =====
static bool SetupHooks() {
  if (g_initialized.load()) return true;

  g_resolver = new ArtResolver();
  if (!g_resolver->Init()) { LOGE("Failed to init ART resolver"); return false; }

  g_dumper = new DexDumper();
  if (!g_dumper->Init(g_config.dump_dir.c_str())) { LOGE("Failed to init dumper"); return false; }

  InstallCrashHandler();

  // Find DefineClass
  void* define_class_addr = nullptr;
  const char* names[] = {
    "_ZN3art12ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE",
    nullptr
  };
  for (int i = 0; names[i]; i++) {
    define_class_addr = g_resolver->ResolveByName(names[i]);
    if (define_class_addr) break;
  }
  if (!define_class_addr) define_class_addr = g_resolver->ResolveByOffset(0x2c4930);
  if (!define_class_addr) { LOGE("DefineClass not found"); return false; }
  LOGI("Found DefineClass at %p", define_class_addr);

  // Hook
  g_define_hook = new Arm64InlineHook();
  if (!g_define_hook->Hook(define_class_addr, (void*)DefineClassHook, &g_define_class_orig)) {
    LOGE("Hook failed"); delete g_define_hook; g_define_hook = nullptr; return false;
  }

  g_hooks_active = true;
  g_initialized = true;
  LOGI("✅ FART hooks activated (pid=%d)", getpid());

  // Phase 2: ArtMethod::Invoke Hook (conditional)
  if (g_config.enable_artmethod_hook) {
    void* invoke_addr = g_resolver->ResolveByOffset(0x340da0);
    if (!invoke_addr) {
      invoke_addr = g_resolver->ResolveByName(
          "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
    }
    if (invoke_addr) {
      g_artmethod_hook = new Arm64InlineHook();
      if (g_artmethod_hook->Hook(invoke_addr, (void*)ArtMethodInvokeHook,
                                  &g_artmethod_invoke_orig)) {
        g_artmethod_hook_active = true;
        LOGI("✅ ArtMethod::Invoke hooked at %p (sample_rate=%u)",
             invoke_addr, g_config.artmethod_sample_rate);
      } else {
        LOGE("ArtMethod::Invoke hook failed");
        delete g_artmethod_hook;
        g_artmethod_hook = nullptr;
      }
    } else {
      LOGE("ArtMethod::Invoke NOT FOUND");
    }
  }

  LOGI("FART hooks: DefineClass=%s, ArtMethod::Invoke=%s",
       g_hooks_active.load() ? "active" : "off",
       g_artmethod_hook_active.load() ? "active" : "off");

  // Stage 2.4: Init CodeItem dumper (only when enabled)
  if (g_config.enable_codeitem_dump && g_config.enable_artmethod_hook) {
    std::string codeitem_dir = g_config.dump_dir;
    g_codeitem_dumper = new CodeItemDumper();
    if (!g_codeitem_dumper->Init(codeitem_dir.c_str(), g_config.max_codeitem_dumps)) {
      LOGE("CodeItemDumper init failed");
      delete g_codeitem_dumper;
      g_codeitem_dumper = nullptr;
    } else {
      LOGI("✅ CodeItem dumper ready (max=%u)", g_config.max_codeitem_dumps);
    }
  }

  // P5: ClassLinker::LoadMethod Hook (always, for reliable code_item capture)
  {
    void* load_method_addr = g_resolver->ResolveByName(
        "_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6ObjPtrINS_6mirror5ClassEEEPNS_9ArtMethodE");
    // Fallback: offset from device libart.so (readelf -s result)
    if (!load_method_addr) {
      load_method_addr = g_resolver->ResolveByOffset(0x2d4510);
    }
    if (load_method_addr) {
      // Initialize the orig function pointer in the hook
      g_load_method_hook = new Arm64InlineHook();
      if (g_load_method_hook->Hook(load_method_addr, (void*)LoadMethodHook, &g_load_method_orig)) {
        LOGI("✅ ClassLinker::LoadMethod hooked at %p", load_method_addr);
      } else {
        LOGW("ClassLinker::LoadMethod hook failed");
        delete g_load_method_hook;
        g_load_method_hook = nullptr;
      }
    } else {
      LOGW("ClassLinker::LoadMethod NOT FOUND via dlsym");
    }
  }

  return true;
}

}  // anonymous namespace

// ===== Exported initialization function (called by zygisk loader) =====
extern "C" __attribute__((visibility("default")))
void fart_on_app_specialize(JNIEnv* env, const char* package_name, const char* module_dir) {
  LOGI("fart_on_app_specialize: pkg=%s", package_name ?: "null");

  if (!env || !package_name) { LOGE("invalid args"); return; }

  // Save for callbacks
  g_env = env;
  strncpy(g_package, package_name, sizeof(g_package) - 1);

  // Load config
  char config_path[256];
  snprintf(config_path, sizeof(config_path), "%s/config/config.json", module_dir);
  if (!LoadConfig(&g_config, config_path)) {
    // Fallback to default
    snprintf(config_path, sizeof(config_path), "/data/local/tmp/fart/config.json");
    LoadConfig(&g_config, config_path);
  }

  if (!g_config.enable) { LOGI("disabled by config"); return; }

  // Phase 1A: Check if dump_dir is writable; fallback to app's data dir
  if (access(g_config.dump_dir.c_str(), W_OK) != 0) {
    // Construct path using package name: /data/data/<pkg>/files/fart_dump/
    char new_dump_dir[512];
    snprintf(new_dump_dir, sizeof(new_dump_dir), "/data/data/%s/files/fart_dump", package_name);
    mkdir(new_dump_dir, 0777);
    chmod(new_dump_dir, 0777);
    g_config.dump_dir = std::string(new_dump_dir);
    LOGI("dump_dir fallback to app data dir: %s", new_dump_dir);

    // Also create methods subdirectory (for codeitem dump)
    char methods_dir[512];
    snprintf(methods_dir, sizeof(methods_dir), "%s/methods", new_dump_dir);
    mkdir(methods_dir, 0777);
    chmod(methods_dir, 0777);
  } else {
    LOGI("dump_dir is writable: %s", g_config.dump_dir.c_str());
  }

  // Setup hooks
  if (SetupHooks()) {
    // Snapshot: dump already-loaded dex files
    DumpAlreadyLoadedDex(env);

    // Stage 2.5: Start active invoke engine (if enabled)
    if (g_config.enable_active_invoke &&
        g_config.enable_artmethod_hook &&
        !g_config.active_invoke_classes.empty()) {
      if (g_active_invoke_engine == nullptr) {
        g_active_invoke_engine = new ActiveInvokeEngine();
        g_active_invoke_engine->Start(env, package_name,
                                       g_config.active_invoke_classes,
                                       g_config.active_invoke_delay_ms,
                                       g_config.active_invoke_max_methods);
      }
    }
  }
}

// ===== Constructor: minimal, just log =====
extern "C" __attribute__((constructor))
void OnLibraryLoaded() {
  LOGI("Library loaded! pid=%d", getpid());
}
