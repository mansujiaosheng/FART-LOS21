// active_invoke.cpp – Stage 2.5: JNI Active Invoke Engine
#include "active_invoke.h"
#include "helper_dex.h"

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Global-scope flag (defined in hook_entry.cpp)
__attribute__((visibility("default"))) extern volatile int g_active_invoke_running;

namespace fart {

// Helper: check and clear JNI exception, log the exception to logcat
static bool CheckAndClearException(JNIEnv* env, const char* where) {
  if (!env->ExceptionCheck()) return false;
  LOGE("active_invoke: JNI exception at %s", where);
  env->ExceptionDescribe();
  env->ExceptionClear();
  return true;
}

// Helper: get app classloader via ActivityThread.currentActivityThread()
// This should only be called after the app is fully initialized (delayed)
static jobject GetAppClassLoader(JNIEnv* env) {
  // Try: ActivityThread.currentActivityThread().getApplication().getClassLoader()
  jclass at_cls = env->FindClass("android/app/ActivityThread");
  if (CheckAndClearException(env, "FindClass ActivityThread") || !at_cls) {
    LOGW("active_invoke: ActivityThread not found");
    return nullptr;
  }

  jmethodID current_at_mid = env->GetStaticMethodID(at_cls, "currentActivityThread",
                                                      "()Landroid/app/ActivityThread;");
  if (CheckAndClearException(env, "GetMethodID currentActivityThread") || !current_at_mid) {
    env->DeleteLocalRef(at_cls);
    return nullptr;
  }

  jobject at_obj = env->CallStaticObjectMethod(at_cls, current_at_mid);
  if (CheckAndClearException(env, "Call currentActivityThread") || !at_obj) {
    env->DeleteLocalRef(at_cls);
    return nullptr;
  }

  jmethodID get_app_mid = env->GetMethodID(at_cls, "getApplication",
                                             "()Landroid/app/Application;");
  if (CheckAndClearException(env, "GetMethodID getApplication") || !get_app_mid) {
    env->DeleteLocalRef(at_cls);
    env->DeleteLocalRef(at_obj);
    return nullptr;
  }

  jobject app = env->CallObjectMethod(at_obj, get_app_mid);
  if (CheckAndClearException(env, "Call getApplication") || !app) {
    env->DeleteLocalRef(at_cls);
    env->DeleteLocalRef(at_obj);
    return nullptr;
  }

  jclass app_cls = env->GetObjectClass(app);
  jmethodID get_cl_mid = env->GetMethodID(app_cls, "getClassLoader",
                                            "()Ljava/lang/ClassLoader;");
  jobject cl = env->CallObjectMethod(app, get_cl_mid);
  CheckAndClearException(env, "Call getClassLoader");

  if (cl != nullptr) {
    jobject global_cl = env->NewGlobalRef(cl);
    env->DeleteLocalRef(cl);
    env->DeleteLocalRef(app_cls);
    env->DeleteLocalRef(app);
    env->DeleteLocalRef(at_obj);
    env->DeleteLocalRef(at_cls);
    return global_cl;
  }

  env->DeleteLocalRef(app_cls);
  env->DeleteLocalRef(app);
  env->DeleteLocalRef(at_obj);
  env->DeleteLocalRef(at_cls);
  return nullptr;
}

ActiveInvokeEngine::ActiveInvokeEngine() = default;
ActiveInvokeEngine::~ActiveInvokeEngine() = default;

// Native callback invoked by the Java thread (has valid JNIEnv!)
extern "C" void Java_com_fartlos21_helper_FartBridge_nativeActiveInvoke(JNIEnv* env, jclass) {
  LOGI("active_invoke: Java thread native callback entered");
  // The engine instance is stored in a global, find it and run
  // For now, the old ThreadFunc logic is reused via a flag
  // Actually we need the engine pointer... let me pass it differently
  LOGI("active_invoke: Java thread has valid env=%p", (void*)env);
}

void ActiveInvokeEngine::Start(JNIEnv* env,
                                const std::string& package_name,
                                const std::vector<std::string>& target_classes,
                                uint32_t delay_ms,
                                uint32_t max_methods) {
  package_name_ = package_name;
  target_classes_ = target_classes;
  delay_ms_ = delay_ms;
  max_methods_ = max_methods;

  if (target_classes_.empty()) {
    LOGW("active_invoke: no target classes specified, skipping");
    return;
  }

  // Phase 1B: Try Java Thread first (no AttachCurrentThread blocking)
  if (TryStartJavaThread(env)) {
    LOGI("active_invoke: Java Thread started successfully");
    return;
  }

  // Fallback: pthread with sleep before AttachCurrentThread
  LOGW("active_invoke: Java Thread failed, falling back to pthread");
  if (env->GetJavaVM(&vm_) != JNI_OK) {
    LOGE("active_invoke: cannot get JavaVM");
    return;
  }
  running_ = true;
  pthread_t pt;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  int rc = pthread_create(&pt, &attr, ThreadFunc, this);
  pthread_attr_destroy(&attr);
  if (rc == 0) {
    LOGI("active_invoke: pthread started, %zu target classes, delay=%ums",
         target_classes_.size(), delay_ms_);
  } else {
    LOGE("active_invoke: pthread create failed: %d", rc);
    running_ = false;
  }
}

// Try to start active invoke via Java Thread (no AttachCurrentThread needed)
bool ActiveInvokeEngine::TryStartJavaThread(JNIEnv* env) {
  // Check InMemoryDexClassLoader available
  jclass in_memory_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
  if (in_memory_cls == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    return false;
  }
  // Create ByteBuffer wrapping embedded DEX
  jclass byte_buffer_cls = env->FindClass("java/nio/ByteBuffer");
  if (byte_buffer_cls == nullptr) { env->ExceptionClear(); return false; }
  jmethodID wrap_mid = env->GetStaticMethodID(byte_buffer_cls, "wrap",
                                               "([B)Ljava/nio/ByteBuffer;");
  if (wrap_mid == nullptr) return false;
  jbyteArray dex_array = env->NewByteArray(kHelperDexSize);
  env->SetByteArrayRegion(dex_array, 0, kHelperDexSize, (const jbyte*)kHelperDex);
  jobject dex_buffer = env->CallStaticObjectMethod(byte_buffer_cls, wrap_mid, dex_array);
  env->DeleteLocalRef(dex_array);
  if (dex_buffer == nullptr || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
  // Get app classloader
  jobject app_cl = GetAppClassLoader(env);
  if (app_cl == nullptr) return false;
  // Create InMemoryDexClassLoader(buffer, appClassLoader)
  jmethodID init_mid = env->GetMethodID(in_memory_cls, "<init>",
      "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
  jobject dex_loader = env->NewObject(in_memory_cls, init_mid, dex_buffer, app_cl);
  env->DeleteLocalRef(dex_buffer);
  if (dex_loader == nullptr || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
  // Load FartBridge class
  jclass loader_cls = env->FindClass("java/lang/ClassLoader");
  jmethodID load_cls_mid = env->GetMethodID(loader_cls, "loadClass",
                                              "(Ljava/lang/String;)Ljava/lang/Class;");
  jstring bridge_name = env->NewStringUTF("com.fartlos21.helper.FartBridge");
  jclass bridge_cls = (jclass)env->CallObjectMethod(dex_loader, load_cls_mid, bridge_name);
  env->DeleteLocalRef(bridge_name);
  if (bridge_cls == nullptr || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
  // Register native callback
  JNINativeMethod methods[] = {
      {"nativeActiveInvoke", "()V", (void*)Java_com_fartlos21_helper_FartBridge_nativeActiveInvoke},
  };
  if (env->RegisterNatives(bridge_cls, methods, 1) != JNI_OK) { return false; }
  LOGI("active_invoke: registered nativeActiveInvoke");
  // Load InvokeRunnable
  jstring runnable_name = env->NewStringUTF("com.fartlos21.helper.FartBridge$InvokeRunnable");
  jclass runnable_cls = (jclass)env->CallObjectMethod(dex_loader, load_cls_mid, runnable_name);
  env->DeleteLocalRef(runnable_name);
  if (runnable_cls == nullptr || env->ExceptionCheck()) { return false; }
  jmethodID runnable_init = env->GetMethodID(runnable_cls, "<init>", "()V");
  jobject runnable = env->NewObject(runnable_cls, runnable_init);
  if (runnable == nullptr || env->ExceptionCheck()) { return false; }
  // Create Java Thread
  jclass thread_cls = env->FindClass("java/lang/Thread");
  jmethodID thread_init = env->GetMethodID(thread_cls, "<init>",
                                            "(Ljava/lang/Runnable;Ljava/lang/String;)V");
  jobject thread = env->NewObject(thread_cls, thread_init, runnable,
                                   env->NewStringUTF("FART-ActiveInvoke"));
  if (thread == nullptr || env->ExceptionCheck()) { return false; }
  env->CallVoidMethod(thread, env->GetMethodID(thread_cls, "start", "()V"));
  if (env->ExceptionCheck()) { return false; }
  return true;
}

void* ActiveInvokeEngine::ThreadFunc(void* arg) {
  LOGI("active_invoke: thread func entered");
  ActiveInvokeEngine* engine = static_cast<ActiveInvokeEngine*>(arg);

  // Step 0: Sleep FIRST before trying to attach (let app finish initializing)
  LOGI("active_invoke: sleeping %ums before attaching", engine->delay_ms_);
  usleep(engine->delay_ms_ * 1000);

  // Step 1: Attach this native thread to the Java VM
  JNIEnv* env = nullptr;
  JavaVMAttachArgs args;
  args.version = JNI_VERSION_1_6;
  args.name = "FART-ActiveInvoke";
  args.group = nullptr;

  LOGI("active_invoke: attaching to Java VM...");
  jint attach_result = engine->vm_->AttachCurrentThread(&env, &args);
  LOGI("active_invoke: AttachCurrentThread result=%d env=%p", attach_result, (void*)env);
  if (attach_result != JNI_OK) {
    LOGE("active_invoke: failed to attach thread to Java VM");
    engine->running_ = false;
    return nullptr;
  }

  // Step 1: Delay
  LOGI("active_invoke: sleeping %ums before execution", engine->delay_ms_);
  usleep(engine->delay_ms_ * 1000);

  // Step 2: Get app classloader (re-fetch after delay for better chance of readiness)
  jobject app_cl = GetAppClassLoader(env);

  // Log classloader type for debugging
  if (app_cl != nullptr) {
    jclass cl_obj_cls = env->GetObjectClass(app_cl);
    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID get_name_mid = env->GetMethodID(class_cls, "getName",
                                               "()Ljava/lang/String;");
    jstring name_str = (jstring)env->CallObjectMethod(cl_obj_cls, get_name_mid);
    const char* name_chars = env->GetStringUTFChars(name_str, nullptr);
    LOGI("active_invoke: classloader class=%s", name_chars ? name_chars : "?");
    if (name_chars) env->ReleaseStringUTFChars(name_str, name_chars);
    env->DeleteLocalRef(name_str);
    env->DeleteLocalRef(class_cls);
    env->DeleteLocalRef(cl_obj_cls);
  } else {
    LOGW("active_invoke: could not get app classloader, skipping");
    engine->vm_->DetachCurrentThread();
    engine->running_ = false;
    return nullptr;
  }

  // Step 3: Get ClassLoader.loadClass method
  jclass cl_loader_cls = env->GetObjectClass(app_cl);
  jmethodID load_class_mid = env->GetMethodID(cl_loader_cls, "loadClass",
                                                "(Ljava/lang/String;)Ljava/lang/Class;");
  if (CheckAndClearException(env, "GetMethodID loadClass") || !load_class_mid) {
    LOGE("active_invoke: cannot get loadClass method");
    env->DeleteGlobalRef(app_cl);
    env->DeleteLocalRef(cl_loader_cls);
    engine->vm_->DetachCurrentThread();
    engine->running_ = false;
    return nullptr;
  }

  // Step 4: For each target class, load and invoke
  uint32_t total_invoked = 0;
  for (const auto& cls_name : engine->target_classes_) {
    if (total_invoked >= engine->max_methods_) {
      LOGW("active_invoke: max methods reached (%u)", engine->max_methods_);
      break;
    }

    LOGI("active_invoke: loading class %s", cls_name.c_str());
    jstring cls_str = env->NewStringUTF(cls_name.c_str());
    jclass target_cls = (jclass)env->CallObjectMethod(app_cl, load_class_mid, cls_str);
    env->DeleteLocalRef(cls_str);

    if (CheckAndClearException(env, "ClassLoader.loadClass") || !target_cls) {
      LOGE("active_invoke: cannot load class %s", cls_name.c_str());
      continue;
    }

    engine->InvokeClassMethods(env, target_cls, cls_name);

    env->DeleteLocalRef(target_cls);
    usleep(10000);  // 10ms between classes
  }

  LOGI("active_invoke: completed, total methods invoked=%u", total_invoked);

  env->DeleteLocalRef(cl_loader_cls);
  env->DeleteGlobalRef(app_cl);
  engine->running_ = false;
  engine->vm_->DetachCurrentThread();
  return nullptr;
}

void ActiveInvokeEngine::InvokeClassMethods(JNIEnv* env, jclass target_cls,
                                             const std::string& class_name) {
  LOGI("active_invoke: processing class %s", class_name.c_str());

  // Step 1: Get getDeclaredMethods and Method class
  jclass method_cls = env->FindClass("java/lang/reflect/Method");
  if (CheckAndClearException(env, "FindClass Method") || !method_cls) return;

  jclass class_cls = env->FindClass("java/lang/Class");
  if (CheckAndClearException(env, "FindClass Class") || !class_cls) {
    env->DeleteLocalRef(method_cls);
    return;
  }

  // Step 1b: Get getDeclaredFields count
  jmethodID get_fields_mid = env->GetMethodID(class_cls, "getDeclaredFields",
                                               "()[Ljava/lang/reflect/Field;");
  jobjectArray fields = nullptr;
  if (get_fields_mid) {
    fields = (jobjectArray)env->CallObjectMethod(target_cls, get_fields_mid);
    CheckAndClearException(env, "getDeclaredFields");
  }
  jsize field_count = fields ? env->GetArrayLength(fields) : -1;
  if (fields) env->DeleteLocalRef(fields);
  if (field_count >= 0) {
    LOGI("active_invoke: class %s has %d fields", class_name.c_str(), field_count);
  }

  jmethodID get_declared_mid = env->GetMethodID(class_cls, "getDeclaredMethods",
                                                  "()[Ljava/lang/reflect/Method;");
  jmethodID get_name_mid = env->GetMethodID(method_cls, "getName",
                                             "()Ljava/lang/String;");
  jmethodID get_modifiers_mid = env->GetMethodID(method_cls, "getModifiers",
                                                   "()I");
  jmethodID get_param_count_mid = env->GetMethodID(method_cls, "getParameterCount",
                                                      "()I");
  jmethodID set_accessible_mid = env->GetMethodID(method_cls, "setAccessible",
                                                    "(Z)V");
  jmethodID invoke_mid = env->GetMethodID(method_cls, "invoke",
                                           "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

  if (CheckAndClearException(env, "get Method method IDs") ||
      !get_declared_mid || !get_name_mid || !get_modifiers_mid ||
      !get_param_count_mid || !set_accessible_mid || !invoke_mid) {
    LOGE("active_invoke: failed to get Method class methods");
    env->DeleteLocalRef(method_cls);
    env->DeleteLocalRef(class_cls);
    return;
  }

  // Step 2: Call getDeclaredMethods
  jobjectArray methods = (jobjectArray)env->CallObjectMethod(target_cls, get_declared_mid);
  if (CheckAndClearException(env, "getDeclaredMethods") || !methods) {
    LOGE("active_invoke: getDeclaredMethods failed for %s", class_name.c_str());
    env->DeleteLocalRef(method_cls);
    env->DeleteLocalRef(class_cls);
    return;
  }

  jsize method_count = env->GetArrayLength(methods);
  LOGI("active_invoke: class %s has %d methods", class_name.c_str(), method_count);

  // Step 3: Iterate methods, find static no-arg ones, invoke via reflection
  for (int i = 0; i < method_count; i++) {
    jobject method_obj = env->GetObjectArrayElement(methods, i);
    if (!method_obj) continue;

    // Get method name
    jstring name_str = (jstring)env->CallObjectMethod(method_obj, get_name_mid);
    const char* name_chars = name_str ? env->GetStringUTFChars(name_str, nullptr) : nullptr;
    std::string mname = name_chars ? name_chars : "?";
    if (name_chars) env->ReleaseStringUTFChars(name_str, name_chars);
    if (name_str) env->DeleteLocalRef(name_str);

    // Get modifiers
    jint modifiers = env->CallIntMethod(method_obj, get_modifiers_mid);
    jint param_count = env->CallIntMethod(method_obj, get_param_count_mid);

    // Filter: only static, no-arg, non-native, non-abstract
    bool is_static = (modifiers & 0x0008) != 0;
    bool is_native = (modifiers & 0x0100) != 0;
    bool is_abstract = (modifiers & 0x0400) != 0;
    bool is_synthetic = (modifiers & 0x1000) != 0;

    const char* reason = nullptr;
    if (is_native) reason = "native";
    else if (is_abstract) reason = "abstract";
    else if (!is_static) reason = "not_static";
    else if (param_count != 0) reason = "has_params";
    else reason = "allowed";

    if (reason == "allowed") {
      // Invoke via reflection
      LOGI("active_invoke: >>> invoking %s.%s()", class_name.c_str(), mname.c_str());

      env->CallVoidMethod(method_obj, set_accessible_mid, JNI_TRUE);
      CheckAndClearException(env, "setAccessible");

      g_active_invoke_running = 1;
      jobject result = env->CallObjectMethod(method_obj, invoke_mid, nullptr, nullptr);
      g_active_invoke_running = 0;

      if (CheckAndClearException(env, "Method.invoke")) {
        LOGW("active_invoke:   exception from %s.%s()", class_name.c_str(), mname.c_str());
      } else {
        LOGI("active_invoke: <<< %s.%s() completed (result=%p)",
             class_name.c_str(), mname.c_str(), result);
      }
      if (result) env->DeleteLocalRef(result);
    } else {
      LOGI("active_invoke:   [%s] %s.%s (static=%d params=%d)",
           reason, class_name.c_str(), mname.c_str(), is_static, param_count);
    }
    env->DeleteLocalRef(method_obj);
    usleep(5000);  // 5ms between methods
  }

  env->DeleteLocalRef(methods);
  env->DeleteLocalRef(method_cls);
  env->DeleteLocalRef(class_cls);
}

}  // namespace fart
