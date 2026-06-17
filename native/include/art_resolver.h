#ifndef FART_LOS21_ART_RESOLVER_H_
#define FART_LOS21_ART_RESOLVER_H_

#include <string>
#include <cstdint>
#include <vector>

namespace fart {

// Result of symbol resolution
struct SymbolInfo {
  bool found = false;
  void* address = nullptr;
  std::string name;   // Symbol name matched
  int64_t offset = 0; // Offset from libart base (if found by offset)
};

// Resolver for ART runtime functions in libart.so
class ArtResolver {
 public:
  ArtResolver();
  ~ArtResolver();

  // Initialize: find libart base address in current process
  bool Init();

  // Resolve by symbol name (works with unstripped or .dynsym)
  void* ResolveByName(const char* symbol_name);

  // Resolve by known offset from libart base
  void* ResolveByOffset(int64_t offset);

  // Resolve by pattern scan (fallback)
  void* ResolveByPattern(const char* pattern, size_t pattern_len, int64_t scan_range = 0x100000);

  // Get libart base address
  uintptr_t GetLibArtBase() const { return libart_base_; }

  // Get libart size
  size_t GetLibArtSize() const { return libart_size_; }

  // Print loaded ART symbols for debugging
  void DumpArtSymbols(const std::vector<std::string>& keywords);

 private:
  uintptr_t libart_base_ = 0;
  size_t libart_size_ = 0;
  bool initialized_ = false;

  // Scan /proc/self/maps for libart.so
  bool FindLibArtInMaps();
};

}  // namespace fart

#endif  // FART_LOS21_ART_RESOLVER_H_
