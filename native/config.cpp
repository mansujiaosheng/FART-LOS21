#include "config.h"

#include <string>
#include <fstream>
#include <sstream>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "FART_LOS21"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace fart {

bool Config::IsAllowed(const char* package_name) const {
  if (!enable || package_name == nullptr || package_name[0] == '\0') {
    return false;
  }
  for (const auto& pkg : packages) {
    if (pkg == package_name) {
      return true;
    }
  }
  return false;
}

bool LoadConfig(Config* config, const char* path) {
  if (config == nullptr || path == nullptr) {
    return false;
  }

  std::ifstream file(path);
  if (!file.is_open()) {
    LOGE("Cannot open config: %s", path);
    return false;
  }

  std::stringstream ss;
  ss << file.rdbuf();
  file.close();
  std::string content = ss.str();

  // Simple manual JSON parsing (minimal, no external deps)
  // Parse "enable": true/false
  auto find_bool = [&](const char* key, bool* out) -> bool {
    auto pos = content.find(key);
    if (pos == std::string::npos) return false;
    auto colon = content.find(':', pos);
    if (colon == std::string::npos) return false;
    auto val_start = content.find_first_not_of(" \t\r\n", colon + 1);
    if (val_start == std::string::npos) return false;
    if (content.substr(val_start, 4) == "true") {
      *out = true;
      return true;
    } else if (content.substr(val_start, 5) == "false") {
      *out = false;
      return true;
    }
    return false;
  };

  // Parse string values
  auto find_string = [&](const char* key, std::string* out) -> bool {
    auto pos = content.find(key);
    if (pos == std::string::npos) return false;
    auto colon = content.find(':', pos);
    if (colon == std::string::npos) return false;
    auto val_start = content.find('"', colon);
    if (val_start == std::string::npos) return false;
    auto val_end = content.find('"', val_start + 1);
    if (val_end == std::string::npos) return false;
    *out = content.substr(val_start + 1, val_end - val_start - 1);
    return true;
  };

  // Parse packages array
  auto find_packages = [&](std::vector<std::string>* out) -> bool {
    auto pos = content.find("\"packages\"");
    if (pos == std::string::npos) return false;
    auto colon = content.find(':', pos);
    if (colon == std::string::npos) return false;
    auto arr_start = content.find('[', colon);
    if (arr_start == std::string::npos) return false;
    auto arr_end = content.find(']', arr_start);
    if (arr_end == std::string::npos) return false;

    std::string arr = content.substr(arr_start + 1, arr_end - arr_start - 1);
    size_t p = 0;
    while (true) {
      auto q = arr.find('"', p);
      if (q == std::string::npos) break;
      auto r = arr.find('"', q + 1);
      if (r == std::string::npos) break;
      out->push_back(arr.substr(q + 1, r - q - 1));
      p = r + 1;
    }
    return !out->empty();
  };

  find_bool("\"enable\"", &config->enable);
  find_string("\"dump_dir\"", &config->dump_dir);
  find_bool("\"dump_dex\"", &config->dump_dex);
  find_bool("\"dump_code_item\"", &config->dump_code_item);
  find_bool("\"active_invoke\"", &config->active_invoke);
  find_packages(&config->packages);

  LOGI("Config loaded: enable=%d, packages=%zu, dump_dex=%d, dump_code_item=%d, active_invoke=%d",
       config->enable, config->packages.size(),
       config->dump_dex, config->dump_code_item, config->active_invoke);

  return true;
}

}  // namespace fart
