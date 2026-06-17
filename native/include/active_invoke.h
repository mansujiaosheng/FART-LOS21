#ifndef FART_LOS21_ACTIVE_INVOKE_H_
#define FART_LOS21_ACTIVE_INVOKE_H_

#include <string>
#include <vector>
#include <jni.h>

namespace fart {

// Stage 2.5: JNI active invoke engine
// Runs in a background thread after fart_on_app_specialize.
// Uses JNI reflection to call static no-arg methods on target classes,
// which triggers ArtMethod::Invoke hook and feeds the CodeItem dump pipeline.
class ActiveInvokeEngine {
 public:
  ActiveInvokeEngine();
  ~ActiveInvokeEngine();

  // Initialize and start the background thread.
  // Called from fart_on_app_specialize after hooks are set up.
  void Start(JNIEnv* env,
             const std::string& package_name,
             const std::vector<std::string>& target_classes,
             uint32_t delay_ms,
             uint32_t max_methods);

 private:
  std::string package_name_;
  std::vector<std::string> target_classes_;
  uint32_t delay_ms_ = 1500;
  uint32_t max_methods_ = 200;
  bool running_ = false;
  JavaVM* vm_ = nullptr;

  // The background thread function
  static void* ThreadFunc(void* arg);

  // Invoke all static no-arg methods on a preloaded class
  void InvokeClassMethods(JNIEnv* env, jclass target_cls, const std::string& cls_name);
};

}  // namespace fart

#endif  // FART_LOS21_ACTIVE_INVOKE_H_
