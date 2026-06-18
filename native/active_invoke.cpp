// active_invoke.cpp – Minimal Active Invoke Engine (Stage 2.5)
// Calls static no-arg methods on configured classes via JNI reflection.
#include "active_invoke.h"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <android/log.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace fart {

volatile int g_active_invoke_running = 0;

ActiveInvokeEngine::ActiveInvokeEngine() = default;

ActiveInvokeEngine::~ActiveInvokeEngine() {
  running_ = false;
  g_active_invoke_running = 0;
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

void ActiveInvokeEngine::Start(JNIEnv* env, const char* package_name,
                                const std::vector<std::string>& classes,
                                uint32_t delay_ms, uint32_t max_methods) {
  if (env == nullptr || package_name == nullptr) {
    LOGW("ActiveInvoke: invalid args");
    return;
  }

  // Save JavaVM for worker thread
  env->GetJavaVM(&java_vm_);
  package_name_ = package_name;
  classes_ = classes;
  delay_ms_ = delay_ms;
  max_methods_ = max_methods;

  running_ = true;
  g_active_invoke_running = 1;
  worker_thread_ = std::thread(&ActiveInvokeEngine::WorkerThread, this);
  LOGI("ActiveInvoke: started for %s (%zu classes, delay=%ums, max=%u)",
       package_name_.c_str(), classes_.size(), delay_ms_, max_methods_);
}

void ActiveInvokeEngine::WorkerThread() {
  LOGI("ActiveInvoke: worker thread started");

  // If no classes configured, log a warning and exit
  if (classes_.empty()) {
    LOGW("ActiveInvoke: no classes configured, skipping");
    running_ = false;
    g_active_invoke_running = 0;
    java_vm_->DetachCurrentThread();
    return;
  }

  // Wait for initial delay
  if (delay_ms_ > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms_));
  }

  // Attach to JVM
  JNIEnv* env = nullptr;
  if (java_vm_ == nullptr) {
    LOGE("ActiveInvoke: no JavaVM");
    running_ = false;
    g_active_invoke_running = 0;
    return;
  }

  JavaVMAttachArgs args = {JNI_VERSION_1_6, "FART-ActiveInvoke", nullptr};
  jint attach_result = java_vm_->AttachCurrentThread(&env, &args);
  if (attach_result != JNI_OK || env == nullptr) {
    LOGE("ActiveInvoke: AttachCurrentThread failed: %d", attach_result);
    running_ = false;
    g_active_invoke_running = 0;
    return;
  }

  LOGI("ActiveInvoke: attached to JVM");

  // Invoke methods for each configured class
  int total_invoked = 0;
  for (const auto& cls_name : classes_) {
    if (!running_) break;
    int n = InvokeClassMethods(env, cls_name);
    total_invoked += n;
    LOGI("ActiveInvoke: %s -> %d methods invoked", cls_name.c_str(), n);
  }

  LOGI("ActiveInvoke: finished, total=%d methods invoked", total_invoked);

  // Detach
  java_vm_->DetachCurrentThread();
  running_ = false;
  g_active_invoke_running = 0;
  LOGI("ActiveInvoke: worker thread exited");
}

int ActiveInvokeEngine::InvokeClassMethods(JNIEnv* env, const std::string& class_name) {
  if (env == nullptr || class_name.empty()) return 0;

  // Convert "com.example.Foo" to "com/example/Foo"
  std::string internal_name = class_name;
  for (auto& c : internal_name) {
    if (c == '.') c = '/';
  }

  // Find class
  jclass clazz = env->FindClass(internal_name.c_str());
  if (clazz == nullptr) {
    LOGW("ActiveInvoke: class not found: %s", class_name.c_str());
    env->ExceptionClear();
    return 0;
  }

  // Get declared methods
  jmethodID getMethods = env->GetMethodID(
      env->GetObjectClass(clazz), "getDeclaredMethods", "()[Ljava/lang/reflect/Method;");
  if (getMethods == nullptr) {
    LOGW("ActiveInvoke: no getDeclaredMethods for %s", class_name.c_str());
    env->ExceptionClear();
    env->DeleteLocalRef(clazz);
    return 0;
  }

  jobjectArray methods = (jobjectArray)env->CallObjectMethod(clazz, getMethods);
  if (methods == nullptr || env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(clazz);
    return 0;
  }

  jsize method_count = env->GetArrayLength(methods);
  LOGI("ActiveInvoke: %s has %d methods", class_name.c_str(), method_count);

  // Get Method method IDs
  jclass methodClass = env->FindClass("java/lang/reflect/Method");
  jmethodID getModifiers = env->GetMethodID(methodClass, "getModifiers", "()I");
  jmethodID getParamTypes = env->GetMethodID(methodClass, "getParameterTypes", "()[Ljava/lang/Class;");
  jmethodID invokeMethod = env->GetMethodID(methodClass, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
  jmethodID setAccessible = env->GetMethodID(methodClass, "setAccessible", "(Z)V");
  jmethodID getName = env->GetMethodID(methodClass, "getName", "()Ljava/lang/String;");

  if (getModifiers == nullptr || getParamTypes == nullptr || invokeMethod == nullptr ||
      setAccessible == nullptr || getName == nullptr) {
    LOGE("ActiveInvoke: failed to get Method method IDs");
    env->ExceptionClear();
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(methods);
    return 0;
  }

  // Static modifier flag
  const int kModifierStatic = 0x0008;

  int invoked = 0;
  int max = (int)max_methods_;

  for (int i = 0; i < method_count && running_ && invoked < max; i++) {
    jobject method = env->GetObjectArrayElement(methods, i);
    if (method == nullptr) continue;

    // Check: static only
    jint modifiers = env->CallIntMethod(method, getModifiers);
    if (!(modifiers & kModifierStatic)) {
      env->DeleteLocalRef(method);
      continue;
    }

    // Check: no-arg only
    jobjectArray paramTypes = (jobjectArray)env->CallObjectMethod(method, getParamTypes);
    jsize paramCount = (paramTypes != nullptr) ? env->GetArrayLength(paramTypes) : -1;
    if (paramTypes != nullptr) env->DeleteLocalRef(paramTypes);
    if (paramCount != 0) {
      env->DeleteLocalRef(method);
      continue;
    }

    // Skip native and abstract (check via access_flags)
    if (modifiers & 0x0100) { // native
      env->DeleteLocalRef(method);
      continue;
    }
    if (modifiers & 0x0400) { // abstract
      env->DeleteLocalRef(method);
      continue;
    }

    // Set accessible
    env->CallVoidMethod(method, setAccessible, JNI_TRUE);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      env->DeleteLocalRef(method);
      continue;
    }

    // Get method name for logging
    jstring nameStr = (jstring)env->CallObjectMethod(method, getName);
    const char* method_name = (nameStr != nullptr) ? env->GetStringUTFChars(nameStr, nullptr) : "?";
    LOGI("ActiveInvoke: invoking %s.%s()", class_name.c_str(), method_name ? method_name : "?");

    // Invoke static method with no args
    env->CallStaticObjectMethod(clazz, env->FromReflectedMethod(method));

    if (env->ExceptionCheck()) {
      LOGW("ActiveInvoke: exception in %s.%s()", class_name.c_str(), method_name ? method_name : "?");
      env->ExceptionClear();
    } else {
      invoked++;
    }

    if (nameStr) {
      env->ReleaseStringUTFChars(nameStr, method_name);
      env->DeleteLocalRef(nameStr);
    }
    env->DeleteLocalRef(method);
  }

  env->DeleteLocalRef(methods);
  env->DeleteLocalRef(clazz);
  return invoked;
}

}  // namespace fart
