// fart-injector.c - FART process injector for APatch
// Pure C99. Uses ptrace to inject libfart-hook.so into target processes.
// Writes to /data/local/tmp/fart/injector.log instead of logcat.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdarg.h>

static const char* kConfigPath = "/data/local/tmp/fart/config.json";
static const char* kHookLibPath = "/data/local/tmp/fart/libfart-hook.so";

static int g_enable = 0;
static char g_packages[64][256];
static int g_package_count = 0;

static FILE* g_log = NULL;

static void log_write(const char* fmt, ...) {
  if (!g_log) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_log, fmt, ap);
  fprintf(g_log, "\n");
  fflush(g_log);
  va_end(ap);
}

// Simple JSON string parser - find value between quotes
static int json_read_string(const char* json, const char* key, char* out, int out_size) {
  char search[64];
  snprintf(search, sizeof(search), "\"%s\"", key);
  const char* p = strstr(json, search);
  if (!p) return 0;
  p = strstr(p, ":");
  if (!p) return 0;
  p = strchr(p, '"');
  if (!p) return 0;
  p++;
  const char* end = strchr(p, '"');
  if (!end) return 0;
  int len = (int)(end - p);
  if (len >= out_size) len = out_size - 1;
  strncpy(out, p, len);
  out[len] = 0;
  return 1;
}

// Simple JSON bool parser (handles unquoted true/false)
static int json_read_bool(const char* json, const char* key) {
  char search[64];
  snprintf(search, sizeof(search), "\"%s\"", key);
  const char* p = strstr(json, search);
  if (!p) return 0;
  p = strstr(p, ":");
  if (!p) return 0;
  // Skip whitespace
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
  return (strncmp(p, "true", 4) == 0);
}

// Parse packages array (only reads from the "packages" key's value)
static int json_read_packages(const char* json) {
  const char* p = strstr(json, "\"packages\"");
  if (!p) return 0;
  p = strchr(p, ':');
  if (!p) return 0;
  p = strchr(p, '[');
  if (!p) return 0;
  p++;
  int count = 0;
  while (*p && *p != ']' && count < 64) {
    const char* q = strchr(p, '"');
    if (!q) break;
    q++;
    const char* r = strchr(q, '"');
    if (!r) break;
    int len = (int)(r - q);
    if (len > 255) len = 255;
    strncpy(g_packages[count], q, (size_t)len);
    g_packages[count][len] = 0;
    count++;
    p = r + 1;
  }
  return count;
}

static void load_config() {
  FILE* f = fopen(kConfigPath, "r");
  if (!f) return;
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  if (len <= 0) { fclose(f); return; }
  fseek(f, 0, SEEK_SET);
  char* content = (char*)malloc((size_t)len + 1);
  if (!content) { fclose(f); return; }
  size_t n = fread(content, 1, (size_t)len, f);
  fclose(f);
  content[n] = 0;

  g_enable = json_read_bool(content, "enable");
  g_package_count = json_read_packages(content);

  free(content);
}

static int is_target(const char* pkg) {
  if (!g_enable || !pkg || !pkg[0]) return 0;
  for (int i = 0; i < g_package_count; i++) {
    if (strcmp(g_packages[i], pkg) == 0) return 1;
  }
  return 0;
}

static void get_cmdline(pid_t pid, char* out, int out_size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) { out[0] = 0; return; }
  int n = (int)read(fd, out, (size_t)out_size - 1);
  close(fd);
  if (n > 0) out[n] = 0; else out[0] = 0;
}

static int lib_loaded(pid_t pid) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE* f = fopen(path, "r");
  if (!f) return 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "libfart-hook.so")) { fclose(f); return 1; }
  }
  fclose(f);
  return 0;
}

static uintptr_t find_func(pid_t pid, const char* lib, const char* func) {
  char line[512];
  uintptr_t local_addr = (uintptr_t)dlsym(RTLD_DEFAULT, func);
  if (!local_addr) return 0;

  // Local base
  FILE* f = fopen("/proc/self/maps", "r");
  uintptr_t local_base = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, lib) && strstr(line, "r-xp")) {
      sscanf(line, "%" SCNxPTR "-%*lx", &local_base);
      break;
    }
  }
  fclose(f);
  if (!local_base) return 0;

  // Remote base
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  f = fopen(path, "r");
  uintptr_t remote_base = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, lib) && strstr(line, "r-xp")) {
      sscanf(line, "%" SCNxPTR "-%*lx", &remote_base);
      break;
    }
  }
  fclose(f);
  if (!remote_base) return 0;

  return remote_base + (local_addr - local_base);
}

static int inject(pid_t pid) {
  log_write("Injecting pid=%d", pid);
  if (lib_loaded(pid)) { log_write("Already loaded in pid=%d", pid); return 1; }

  // Attach
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
    log_write("ptrace ATTACH failed: pid=%d errno=%d", pid, errno);
    return 0;
  }
  int status;
  waitpid(pid, &status, 0);
  if (!WIFSTOPPED(status)) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return 0; }

  // Find dlopen
  uintptr_t dlopen_addr = find_func(pid, "libdl.so", "dlopen");
  if (!dlopen_addr) dlopen_addr = find_func(pid, "libdl.so", "__dl_dlopen");
  if (!dlopen_addr) {
    log_write("No dlopen in pid=%d", pid);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
  }

  // Save regs
  struct user_regs_struct regs;
  struct iovec iov = {&regs, sizeof(regs)};
  ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);

  uintptr_t stack_ptr = regs.sp - 4096;
  size_t path_len = strlen(kHookLibPath) + 1;

  // Write path + ret gadget to target memory
  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int mem_fd = open(mem_path, O_RDWR);
  if (mem_fd < 0) {
    log_write("Cannot open mem pid=%d: %d", pid, errno);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
  }

  // Write library path
  lseek(mem_fd, (off_t)stack_ptr, SEEK_SET);
  write(mem_fd, kHookLibPath, path_len);

  // Write RET instruction (ARM64: ret = 0xd65f03c0)
  uint32_t ret_insn = 0xd65f03c0;
  lseek(mem_fd, (off_t)(stack_ptr + path_len), SEEK_SET);
  write(mem_fd, &ret_insn, sizeof(ret_insn));
  close(mem_fd);

  // Setup call: x0=path, x30=ret_addr, pc=dlopen
  regs.regs[0] = (uint64_t)stack_ptr;
  regs.regs[30] = (uint64_t)(stack_ptr + path_len);
  regs.pc = (uint64_t)dlopen_addr;
  ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

  // Continue
  ptrace(PTRACE_CONT, pid, NULL, NULL);
  waitpid(pid, &status, 0);

  // Detach
  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  log_write("Injected pid=%d (status=%d)", pid, status);
  return 1;
}

int main(int argc, char* argv[]) {
  // Open log file
  g_log = fopen("/data/local/tmp/fart/injector.log", "a");
  if (!g_log) g_log = stderr;

  log_write("=== FART injector start ===");
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      kConfigPath = argv[i + 1];
      i++;
    }
  }

  load_config();

  struct stat st;
  if (stat(kHookLibPath, &st) != 0) {
    log_write("ERROR: hook lib not found at %s", kHookLibPath);
    if (g_log != stderr) fclose(g_log);
    return 1;
  }

  log_write("Running (enable=%d, packages=%d)", g_enable, g_package_count);

  // Allow g_enable to be toggled at runtime
  g_enable = 1; // force enable for now

  while (1) {
    load_config();
    DIR* proc = opendir("/proc");
    if (proc) {
      struct dirent* entry;
      while ((entry = readdir(proc)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        pid_t pid = (pid_t)atol(entry->d_name);
        if (pid <= 0) continue;

        char name[256];
        get_cmdline(pid, name, sizeof(name));
        if (!name[0]) continue;
        if (strcmp(name, "android") == 0) continue;

        if (is_target(name)) {
          log_write("Target found: %s (pid=%d)", name, pid);
          inject(pid);
        }
      }
      closedir(proc);
    }
    sleep(3);
  }

  if (g_log != stderr) fclose(g_log);
  return 0;
}
