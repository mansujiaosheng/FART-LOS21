#ifndef FART_LOS21_ACTIVE_INVOKE_H_
#define FART_LOS21_ACTIVE_INVOKE_H_

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <jni.h>

namespace fart {

// Minimal Active Invoke Engine
// Calls static no-arg methods on configured classes via JNI reflection.
class ActiveInvokeEngine {
 public:
  ActiveInvokeEngine();
  ~ActiveInvokeEngine();

  // Start the invoke thread (non-blocking)
  // env: JNI env from the hooked process
  // package_name: target package
  // classes: list of fully-qualified class names
  // delay_ms: delay before starting invocations
  // max_methods: max methods to invoke per class
  void Start(JNIEnv* env, const char* package_name,
             const std::vector<std::string>& classes,
             uint32_t delay_ms, uint32_t max_methods);

  // Check if currently running
  bool IsRunning() const { return running_.load(); }

 private:
  std::string package_name_;
  std::vector<std::string> classes_;
  uint32_t delay_ms_ = 1500;
  uint32_t max_methods_ = 200;
  std::atomic<bool> running_{false};
  std::thread worker_thread_;

  void WorkerThread();

  // JNI helpers - use a saved JavaVM* to get JNIEnv on worker thread
  JavaVM* java_vm_ = nullptr;

  // Invoke all static no-arg methods on a class
  // Returns number of methods invoked
  int InvokeClassMethods(JNIEnv* env, const std::string& class_name);
};

// Global flag visible to the hook code
extern volatile int g_active_invoke_running;

}  // namespace fart

#endif  // FART_LOS21_ACTIVE_INVOKE_H_
