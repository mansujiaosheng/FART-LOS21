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

  bool IsAllowed(const char* package_name) const;
};

bool LoadConfig(Config* config, const char* path);

}  // namespace fart

#endif  // FART_LOS21_CONFIG_H_
