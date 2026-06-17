#ifndef FART_LOS21_CONFIG_H_
#define FART_LOS21_CONFIG_H_

#include <string>
#include <vector>

namespace fart {

struct Config {
  bool enable = false;
  std::vector<std::string> packages;
  std::string dump_dir = "/data/local/tmp/fart";
  bool dump_dex = true;
  bool dump_code_item = false;
  bool active_invoke = false;

  // Phase 2: ArtMethod::Invoke hook
  bool enable_artmethod_hook = false;
  uint32_t artmethod_sample_rate = 1000;

  // Stage 2.4: CodeItem dump
  bool enable_codeitem_dump = false;
  uint32_t max_codeitem_dumps = 500;

  // Stage 2.5: Active invoke (JNI reflective call trigger)
  bool enable_active_invoke = false;
  uint32_t active_invoke_delay_ms = 1500;
  uint32_t active_invoke_max_classes = 50;
  uint32_t active_invoke_max_methods = 200;
  bool active_invoke_skip_execute = true;
  std::vector<std::string> active_invoke_classes;

  bool IsAllowed(const char* package_name) const;
};

bool LoadConfig(Config* config, const char* path);

}  // namespace fart

#endif  // FART_LOS21_CONFIG_H_
