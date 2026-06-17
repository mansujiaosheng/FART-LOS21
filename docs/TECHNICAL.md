# FART-LOS21 技术实现文档

## 1. 概述

**FART-LOS21** 是一个基于 ZygiskNext + APatch 的 ART DexFile 自动脱壳模块，目标平台为 **LineageOS 21 / Android 14 / ARM64**，目标设备为一加 9 (lemonade)。

### 核心功能

- 在目标 app 启动时，通过 ZygiskNext 注入到 app 进程
- Hook ART 的 `ClassLinker::DefineClass` 函数 (被动 DexFile dump)
- 可选 Hook ART 的 `ArtMethod::Invoke` 函数 (反射/JNI 方法调用入口)
- 在类加载时提取 DexFile 的原始字节并写入磁盘
- 支持 allowlist / blacklist 包名过滤
- 支持禁用模块后恢复系统原状

### 工作原理

```
ZygiskNext (system linker 模式)
  ↓
zygisk/arm64-v8a.so (loader, 8KB)
  ↓
postAppSpecialize → JNI nice_name 获取包名
  ↓
检查 hard allowlist → 检查 config allowlist/blacklist
  ↓
dlopen libfart-hook.so
  ↓
fart_on_app_specialize(JNIEnv*, package_name, module_dir)
  ↓
SetupHooks():
  ├── resolve DefineClass → Arm64InlineHook (DefineClassHook)
  └── [条件] resolve ArtMethod::Invoke → Arm64InlineHook (ArtMethodInvokeHook)
  ↓
DumpAlreadyLoadedDex(): Java反射枚举 DexFile
  ↓
DefineClassHook 回调: DexFile+8 读取 begin_ → IsRangeReadable 验证
  ↓
同步写文件 → /data/local/tmp/fart_dump/dex_*.dex
  ↓
[条件] ArtMethodInvokeHook 回调: 采样日志 + 字段解析
```

---

## 2. 环境准备

### 2.1 编译环境

- Ubuntu 20.04+
- Android NDK r27 (arm64 cross-compilation)
- ADB with remote host support
- APatch root (su 已改为 `kp`)
- ZygiskNext v1.3.4 模块
- 已 root 的 LineageOS 21 设备 (OnePlus 9)

### 2.2 关键路径

```bash
# NDK
NDK_PATH=/lina_android/android-ndk-r27
TOOLCHAIN=$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64
CXX=$TOOLCHAIN/bin/aarch64-linux-android34-clang++
CC=$TOOLCHAIN/bin/aarch64-linux-android34-clang

# 设备 ART 运行时
DEVICE_LIBART=/apex/com.android.art/lib64/libart.so

# ADB 连接
ADB="adb -H 192.168.238.1 -P 5037"
# root 使用 kp 而非 su
$ADB shell 'kp -c "command"'
```

---

## 3. 模块结构

```
fart-los21/
├── module/
│   ├── customize.sh              # 安装脚本
│   ├── service.sh                # 开机自启
│   └── sepolicy.rule             # SELinux 策略
├── config/
│   └── config.json               # 运行时配置
├── native/
│   ├── Makefile                  # NDK 交叉编译
│   ├── zygisk_loader.cpp         # Zygisk 模块入口 (loader)
│   ├── hook_entry.cpp            # Hook 核心 + DefineClass 回调
│   ├── config.cpp                # JSON 配置解析
│   ├── art_resolver.cpp          # libart 符号解析
│   ├── dex_dump.cpp              # Dex 文件写入 + SHA256 去重
│   ├── include/
│   │   ├── zygisk.hpp            # Zygisk API 头文件 (无 lambda)
│   │   ├── arm64_hook.h          # ARM64 inline hook 引擎
│   │   ├── config.h
│   │   ├── art_resolver.h
│   │   └── dex_dump.h
│   └── Dobby/                    # Dobby inline hook 框架 (备用)
└── scripts/
    ├── install_module.sh
    ├── disable_module.sh
    ├── pull_dump.sh
    ├── collect_crashlog.sh
    ├── check_art_symbols.py
    └── package_module.sh
```

### 3.1 部署到设备的模块结构

```
/data/adb/modules/fart-los21/
├── module.prop
├── customize.sh
├── service.sh
├── sepolicy.rule
├── config/
│   └── config.json               # 模块内部默认配置
├── zygisk/
│   └── arm64-v8a.so              # Zygisk loader (8KB)
└── lib64/
    └── libfart-hook.so           # Hook 核心库 (1.3MB)
```

---

## 4. 关键编译配置

### 4.1 Makefile 关键参数

```makefile
# loader: 最小体积，无 STL，无 C++ 运行时
LOADER_CFLAGS := $(COMMON_FLAGS) -fno-rtti -fno-exceptions
LOADER_LDFLAGS := -shared ... -nostdlib++ -llog -lc -ldl -lm

# hook lib: 全静态链接，避免 libc++_shared 依赖
HOOK_LDFLAGS := -shared ... -nostdlib++ \
    -Wl,--whole-archive \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++_static.a \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++abi.a \
    -Wl,--no-whole-archive
```

### 4.2 为什么 loader 和 hook lib 分开编译

- **loader**: 被 ZN 在 zygote 阶段加载，必须无外部依赖，限制在 10KB 以内
- **hook lib**: 在 app 进程中加载，可以静态链接 libc++，功能完整

---

## 5. Zygisk 模块入口

### 5.1 zygisk.hpp 设计

使用 **无 lambda、无 STL** 的自定义 Zygisk API 头文件，避免 libc++_shared.so 依赖：

```cpp
// REGISTER_ZYGISK_MODULE 使用静态 thunk 函数指针，不创建 lambda
#define REGISTER_ZYGISK_MODULE(CLAZZ) \
    namespace { \
        static void _t_onL(void *m, zygisk::Api *a, JNIEnv *e) { ((CLAZZ*)m)->onLoad(a, e); } \
        static void _t_preA(void *m, zygisk::AppSpecializeArgs *a) { ((CLAZZ*)m)->preAppSpecialize(a); } \
        static void _t_postA(void *m, const zygisk::AppSpecializeArgs *a) { ((CLAZZ*)m)->postAppSpecialize(a); } \
        ... \
    } \
    extern "C" __attribute__((visibility("default"))) \
    void zygisk_module_entry(zygisk::internal::api_table *table, JNIEnv *env) { \
        static CLAZZ module; \
        static zygisk::internal::module_abi abi; \
        abi.api_version = 4; \
        abi.impl = &module; \
        abi.preAppSpecialize = (...)\_t_preA; \
        ... \
        if (table->registerModule) table->registerModule(table, &abi); \
        module.onLoad(nullptr, env); \
    }
```

### 5.2 api_table 和 module_abi 结构

```cpp
struct module_abi {
    long api_version;                      // offset 0
    ModuleBase *impl;                      // offset 8
    void (*preAppSpecialize)(ModuleBase *, AppSpecializeArgs *);  // offset 16
    void (*postAppSpecialize)(ModuleBase *, const AppSpecializeArgs *); // offset 24
    ...
};

struct api_table {
    void *impl;                            // offset 0 (内部实现)
    bool (*registerModule)(api_table *, module_abi *); // offset 8
    void *reserved[8];
};
```

---

## 6. Loader 流程 (zygisk_loader.cpp)

### 6.1 postAppSpecialize 三级包名获取

```cpp
void postAppSpecialize(const zygisk::AppSpecializeArgs *args) {
    // Level 1: nice_name (JNI string from args)
    JNIEnv *env = ...;
    const char *chars = env->GetStringUTFChars(args->nice_name, nullptr);
    if (chars && 有'.'且无'/') { strcpy(pkg, chars); return; }

    // Level 2: app_data_dir (/data/user/<uid>/<package>)
    chars = env->GetStringUTFChars(args->app_data_dir, nullptr);
    const char *slash = strrchr(chars, '/');
    if (slash && 有'.'且无'/') { strcpy(pkg, slash+1); return; }

    // Level 3: /proc/self/cmdline (fallback for non-zygote processes)
    int fd = open("/proc/self/cmdline", O_RDONLY);
    read(fd, pkg, sizeof(pkg)-1); close(fd);
}
```

### 6.2 安全检查链

```cpp
// 1. 硬编码白名单（只有这些包可以触发后续逻辑）
static const char* allow[] = {
    "infosecadventures.allsafe",
    "com.funshion.video.mobile",
    "com.example.farttest",
    nullptr
};
if (!inHardAllow(pkg)) return;

// 2. dlopen hook lib
void *h = dlopen("/data/local/tmp/fart/libfart-hook.so", RTLD_NOW);

// 3. 调用显式初始化函数
typedef void (*Init_t)(JNIEnv*, const char*, const char*);
Init_t init = (Init_t)dlsym(h, "fart_on_app_specialize");
init(env, pkg, "/data/adb/modules/fart-los21");
```

---

## 7. Hook 核心 (hook_entry.cpp)

### 7.1 显式初始化入口

```cpp
extern "C" __attribute__((visibility("default")))
void fart_on_app_specialize(JNIEnv* env, const char* pkg, const char* mod_dir) {
    // 1. Load config
    LoadConfig(&g_config, config_path);

    // 2. Setup ARM64 inline hook on DefineClass
    SetupHooks();

    // 3. Snapshot: dump already-loaded dex files via Java reflection
    DumpAlreadyLoadedDex(env);
}
```

### 7.2 ARM64 Inline Hook 实现

```cpp
class Arm64InlineHook {
    bool Hook(void* target, void* replacement, void** original) {
        // 1. 保存原始 16 字节
        memcpy(saved_bytes_, target, 16);

        // 2. 分配蹦床 (mmap)
        trampoline_addr_ = mmap(nullptr, 32, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0);

        // 3. 蹦床: 原始16字节 + 绝对跳转回 target+16
        memcpy(trampoline, saved_bytes_, 16);
        *(uint32_t*)(trampoline+16) = LDR_X17_#8;    // 0x58000000 | (17<<0) | (2<<5)
        *(uint32_t*)(trampoline+20) = BR_X17;          // 0xD61F0000 | (17<<5)
        *(uint64_t*)(trampoline+24) = target + 16;     // 8字节目标地址

        // 4. 在目标地址写钩子
        mprotect(page, RWX);
        *(uint32_t*)target = LDR_X17_#8;      // LDR X17, [PC, #8]
        *(uint32_t*)(target+4) = BR_X17;        // BR X17
        *(uint64_t*)(target+8) = replacement;   // 替换函数地址
        clear_cache(target, target+16);
    }
};
```

### 7.3 DefineClass 回调

```cpp
void* DefineClassHook(void* this, void* thread, const char* descriptor,
                       size_t hash, void* class_loader,
                       void* dex_file_ptr, void* dex_class_def) {
    // 1. 调用原始 DefineClass（让类正常加载）
    result = original(..., dex_file_ptr, ...);

    // 2. 从 DexFile 对象直接读 begin_ 指针 (offset 8)
    uintptr_t obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFF;  // 去标签
    const uint8_t* begin = *(const uint8_t**)(obj + 8);

    // 3. 验证 dex magic ("dex\n")
    if (memcmp(begin, "dex\n", 4) != 0) return result;

    // 4. 读 header->file_size (offset 0x20)
    uint32_t dex_size = *(const uint32_t*)(begin + 0x20);
    if (dex_size < 64 || dex_size > 0x20000000) return result;

    // 5. 检查内存范围可读 (/proc/self/maps)
    if (!IsRangeReadable(begin, dex_size)) return result;

    // 6. 同步写文件（chunked write）
    int fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    while (remaining > 0) {
        write(fd, ptr, chunk);
        remaining -= number;
        ptr += chunk;
    }
    close(fd);
}
```

### 7.4 内存验证

```cpp
static bool IsRangeReadable(const void* addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    FILE* fp = fopen("/proc/self/maps", "r");
    while (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%lx-%lx %7s", &map_start, &map_end, perms);
        if (perms[0] == 'r' && start >= map_start && end <= map_end)
            return true;
    }
    return false;
}
```

### 7.5 ART 运行时 DexFile 内存布局

从 `/lina_android/lineage/art/libdexfile/dex/dex_file.h` 确认的字段偏移：

```cpp
class DexFile {
    // offset 0: vtable pointer (8 bytes, 编译器自动)
    const uint8_t* const begin_;       // offset 8  ← DEX 数据起始
    size_t unused_size_;               // offset 16
    ArrayRef<const uint8_t> data_;     // offset 24 (16 bytes)
    std::string location_;             // offset 40 (24 bytes on Android)
    uint32_t location_checksum_;       // offset 64
    const Header* const header_;       // offset 72
    ...
};
```

`begin_` 指向 dex 文件在内存中的起始地址，即 `dex\n035`/`dex\n039` magic 的位置。
`header_->file_size_` (at `begin + 0x20`) 包含完整 dex 文件大小。

---

## 7a. Phase 2: ArtMethod::Invoke Hook

### 7a.1 设计动机

`ArtMethod::Invoke` 是 ART 中 Java 方法调用的 C++ 入口函数。虽然普通 Java 编译代码通过 `art_quick_invoke_stub` 直接执行绕过此函数，但**反射调用**（`Method.invoke()`）、**JNI 调用**和**解释执行**的场景仍会经过 `ArtMethod::Invoke`。Hook 此函数可以捕获：

- 反射执行的脱壳方法
- JNI 回调的 Java 方法
- 解释器模式下的方法执行
- 后续可以扩展为 CodeItem dump 和主动调用

### 7a.2 符号与偏移

```cpp
// 完整 mangled 符号
_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc

// C++ 签名
void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size,
                       JValue* result, const char* shorty);
```

从设备 `libart.so` 分析确认偏移：

```bash
readelf -Ws libart_device.so | grep ArtMethod6Invoke
# ➜ 0x340da0  536  FUNC  _ZN3art9ArtMethod6Invoke...
```

解析顺序：`ResolveByOffset(0x340da0)` → `ResolveByName(mangled)`。

### 7a.3 ArtMethod 结构体布局 (Android 14 / LineageOS 21, ARM64)

从 `art/runtime/art_method.h` 源码确认的字段偏移：

```cpp
class ArtMethod {
    // offset 0x00: GcRoot<mirror::Class> declaring_class_   (4 bytes compressed ref)
    // offset 0x04: std::atomic<uint32_t> access_flags_       (4 bytes)
    // offset 0x08: uint32_t dex_method_index_                 (4 bytes)
    // offset 0x0C: uint16_t method_index_                     (2 bytes)
    // offset 0x0E: uint16_t hotness_count_                    (2 bytes)
    // ---- align to 8 bytes ----
    // offset 0x10: void* ptr_sized_fields_.data_              (8 bytes)
    // offset 0x18: void* entry_point_from_quick_compiled_code_ (8 bytes)
};
// total: 0x20 = 32 bytes
```

### 7a.4 Hook 回调实现

```cpp
extern "C" void ArtMethodInvokeHook(
    void* art_method,  // X0 = this (ArtMethod*)
    void* thread,      // X1 = Thread*
    void* args,        // X2 = uint32_t*
    void* args_size,   // X3 = uint32_t (value)
    void* result,      // X4 = JValue*
    void* shorty)      // X5 = const char*
{
    // Reentry guard (thread_local)
    if (g_fart_in_invoke) goto call_original;
    g_fart_in_invoke = true;

    // Stage 2.1: Sampling log
    static thread_local uint64_t g_invoke_count = 0;
    g_invoke_count++;
    if (g_invoke_count % g_config.artmethod_sample_rate == 1) {
        LOGI("Invoke #%lu: method=%p tid=%d", ...);
    }

    // Stage 2.2: Field parsing
    uintptr_t m = (uintptr_t)art_method & 0x00FFFFFFFFFFFFFFULL;
    if (IsRangeReadable(m, 0x20)) {
        uint32_t class_ref = *(uint32_t*)(m + 0x00);
        uint32_t access_flags = *(uint32_t*)(m + 0x04);
        uint32_t dex_idx = *(uint32_t*)(m + 0x08);
        // Filter: skip native(0x0100), abstract(0x0400), runtime(0xFFFFFFFF)
        if (!skip) LOGI("Method: class_ref=0x%x dex_idx=%u flags=0x%x", ...);
    }

call_original:
    // Call original Invoke via trampoline
    orig(art_method, thread, args, args_size_val, result, shorty);
    g_fart_in_invoke = false;
}
```

### 7a.5 关键设计

| 设计点 | 说明 |
|--------|------|
| **reentry guard** | `thread_local bool` 防止递归（LOGI → android_log_print → ... 可能绕回 Invoke） |
| **采样率** | `artmethod_sample_rate` 控制日志频率，默认 1000。Invoke 是高频函数，不采样会瞬间刷屏 |
| **TBI 清除** | ARM64 Top Byte Ignore 标签与 DefineClass 处理一致 |
| **字段过滤** | `kRuntimeMethodDexMethodIndex(0xFFFFFFFF)`、`kAccNative(0x0100)`、`kAccAbstract(0x0400)` 跳过 |
| **Crash 保护** | SIGSEGV 时同时 Unhook DefineClass + ArtMethod 两个 hook |
| **默认关闭** | `enable_artmethod_hook=false` 不影响现有 DefineClass dump |

### 7a.6 入口指令检查

从设备 `libart.so` 在 offset `0x340da0` 处的 16 字节：

```asm
SUB SP, SP, #0x20       ; 分配 32 字节栈帧
STP x29, x30, [SP, #0x40]  ; 保存 FP/LR
STP x24, x23, [SP, #0x50]  ; 保存被调用者保存寄存器
STP x22, x21, [SP, #0x60]  ; 保存被调用者保存寄存器
```

前 4 条指令均为栈帧操作，**无 PC-relative 指令**，inline hook 的 trampoline 复制执行安全。

### 7a.7 内存安全验证路径

```cpp
// ArtMethod pointer check
uintptr_t m = (uintptr_t)art_method & 0x00FFFFFFFFFFFFFFULL;
if (m == 0 || !IsRangeReadable((void*)m, 0x20)) return;

// declaring_class_ at +0x00, 4 bytes compressed ref
uint32_t class_ref = *(const uint32_t*)(m + 0x00);
if (class_ref == 0) return;  // uninitialized

// dex_method_index_ at +0x08
uint32_t dex_idx = *(const uint32_t*)(m + 0x08);
if (dex_idx == 0xFFFFFFFF) return;  // runtime method

// access_flags_ at +0x04
uint32_t flags = *(const uint32_t*)(m + 0x04);
if (flags & 0x0100) return;  // kAccNative
if (flags & 0x0400) return;  // kAccAbstract
```

### 7a.8 配置项

```json
{
    "enable_artmethod_hook": false,
    "artmethod_sample_rate": 1000
}
```

### 7a.9 Stage 2.3: CodeItem Metadata 定位

#### 访问路径

从 `art/runtime/art_method-inl.h:457-467` 确认，运行时 `ArtMethod` 的 `ptr_sized_fields_.data_`（offset 0x10）**直接是 CodeItem* 指针**，不需经过 `GetDexFile()` 或 `GetDexCache()`。

```cpp
inline const dex::CodeItem* ArtMethod::GetCodeItem() {
  if (!HasCodeItem()) return nullptr;            // 已由 Stage 2.2 过滤
  // AOT compiler: data_ 是文件偏移
  // Runtime: data_ 是直接 CodeItem* 指针, bit0 可能为标记
  return runtime->IsAotCompiler()
      ? GetDexFile()->GetCodeItem((uint32_t)GetDataPtrSize(pointer_size))
      : (const dex::CodeItem*)((uintptr_t)GetDataPtrSize(pointer_size) & ~1);
}
```

#### 读取流程

```cpp
// 1. 从 ArtMethod+0x10 读 data_ pointer
uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);
// 2. 清除 bit0 标记（运行时标记）
const uint8_t* ci = (const uint8_t*)(data_ptr & ~1ULL);
// 3. 验证可读 + 范围检查
if (ci && IsRangeReadable(ci, 16)) {
    uint32_t insns = *(const uint32_t*)(ci + 12);
    if (insns > 0 && insns < 65536) {
        uint16_t regs  = *(const uint16_t*)(ci + 0);
        uint16_t ins   = *(const uint16_t*)(ci + 2);
        uint16_t outs  = *(const uint16_t*)(ci + 4);
        uint16_t tries = *(const uint16_t*)(ci + 6);
        // 输出 metadata（不写文件）
        LOGI("CodeItem: regs=%u ins=%u outs=%u tries=%u insns=%u", ...);
    }
}
```

#### CodeItem 结构（StandardDexFile）

```
offset  +0: registers_size_    (uint16_t)  — 使用的寄存器总数
offset  +2: ins_size_          (uint16_t)  — 输入参数字数
offset  +4: outs_size_         (uint16_t)  — 传出参数空间
offset  +6: tries_size_        (uint16_t)  — try_item 数量
offset  +8: debug_info_off_    (uint32_t)  — debug info 偏移
offset +12: insns_size_in_code_units_ (uint32_t) — 字节码大小(2字节单位)
offset +16: insns_[1]          (uint16_t[]) — 实际字节码
```

#### 安全保证

- 只读不写：不打文件，只打日志
- 两级验证：`IsRangeReadable(ci, 16)` + `insns_size` 范围检查 0~65535
- 复用已有过滤：Stage 2.2 已过滤 native/abstract/runtime
- reentry guard 保护：不递归

### 7a.10 Stage 2.4: 被动 CodeItem Dump

#### 设计原则

- **不主动调用**：只在 ArtMethod::Invoke 已自然触发的方法上 dump
- **不修改 dex**：只读写入，不修复 CodeItem
- **只 dump header + insns**：tries/catch handler 暂不处理
- **安全优先**：sync memcpy 到 owned buffer，worker 线程只写 owned buffer

#### 输出目录

```
/data/local/tmp/fart_dump/methods/
├── method_index.csv                          # CSV 索引
├── method_001234_a1b2c3d4.json               # metadata JSON
└── method_001234_a1b2c3d4.code               # raw CodeItem (header + insns)
```

#### JSON 格式

```json
{
  "pid": 12345,
  "tid": 12345,
  "method_idx": 1234,
  "sha256_prefix": "a1b2c3d4e5f6...",
  "registers_size": 4,
  "ins_size": 2,
  "outs_size": 1,
  "tries_size": 0,
  "insns_size": 12,
  "dump_size": 40,
  "dump_complete": true,
  "source": "ArtMethodInvoke"
}
```

#### dump_size 计算

```
dump_size = 16 + insns_size * 2
           (header)  (bytecode)
```

- `tries_size == 0` → `dump_complete = true`
- `tries_size > 0` → `dump_complete = false`（try/catch 未包含）

#### 去重策略

组合 key: `sha256_prefix(8 hex) + ":" + method_idx` → 存 `unordered_set`

同一方法（相同 dex + 相同 idx + 相同 insns hash）只写一次。

#### 安全读取流程

```
Hook 线程 (ArtMethodInvokeHook):
  IsRangeReadable(code_item_ptr, dump_size)                 ← 已有
  → CodeItemDumpTask::CopyData(src, dump_size):             ← 新增
      new uint8_t[dump_size] + memcpy (owned buffer)
      → Compute SHA256 of owned buffer
      → Generate sha256_prefix for dedup
  → QueueDump(task):                                        ← 新增
      dedup check
      max limit check (max_codeitem_dumps)
      push to worker queue

Worker 线程:
  pop queue
  → WriteJsonFile()     → method_<idx>_<hash>.json
  → WriteCodeFile()     → method_<idx>_<hash>.code
  → AppendCsv()         → method_index.csv
```

#### 配置项

```json
{
    "enable_codeitem_dump": false,
    "max_codeitem_dumps": 500
}
```

默认全部关闭，需同时开启 `enable_artmethod_hook=true` + `enable_codeitem_dump=true` 才生效。

---

## 8. DefineClass 函数地址解析

### 8.1 符号映射

```cpp
// 1. 先尝试 dlsym (device libart 可能 strip)
void* addr = dlsym(RTLD_DEFAULT,
    "_ZN3art12ClassLinker11DefineClassE"
    "PNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEE"
    "RKNS_7DexFileERKNS_3dex8ClassDefE");

// 2. 失败则使用从 device libart 提取的固定偏移
if (!addr) addr = resolver->ResolveByOffset(0x2c4930);
```

### 8.2 偏移获取

```bash
# 从设备拉取 libart.so
adb pull /apex/com.android.art/lib64/libart.so
# 查看动态符号表
readelf -Ws libart.so | grep DefineClass
# 输出: 0x2c4930  26844  FUNC  _ZN3art12ClassLinker11DefineClass...
```

### 8.3 libart base 地址修正

```cpp
// 从 /proc/self/maps 解析 libart.so 的 file offset
// r-xp 段从 file offset 0x200000 开始
// libart_base = segment_start - file_offset
// libart_base = 0x7323a3a000 - 0x200000 = 0x732383a000
// DefineClass = libart_base + 0x2c4930 = 0x7323afe930
```

---

## 9. 已加载 DEX 快照补充

### 9.1 Java 反射路径

```java
// Java 反射路径 (通过 JNI 实现):
Thread.currentThread()
    .getContextClassLoader()                        // ClassLoader
    .pathList                                      // DexPathList (反射字段)
    .dexElements[]                                  // Element[]
    [i].dexFile                                    // DexFile (反射字段)
    .mCookie                                       // Object (反射字段)
```

`mCookie` 可能是 `long` (单 dex) 或 `long[]` (multi-dex)，每个值是 native DexFile 指针。

### 9.2 Cookie 到 DexFile 数据的提取

```cpp
// mCookie 值是 native DexFile 指针
uintptr_t dex_ptr = (uintptr_t)cookie;
// 与 DefineClass 回调同样的方法提取 begin_
const uint8_t* begin = *(const uint8_t**)(dex_ptr + 8);
// 验证 magic、file_size
if (memcmp(begin, "dex\n", 4) != 0) continue;
uint32_t size = *(const uint32_t*)(begin + 0x20);
```

---

## 10. 安装与部署

### 10.1 首次安装

```bash
# 1. 编译
cd /lina_android/fart-los21/native
make clean && make -j4

# 2. 打包模块
cd .. && scripts/package_module.sh

# 3. 推送并安装
$ADB push fart-los21-module.zip /data/local/tmp/
$ADB push config/config.json /data/local/tmp/
$ADB shell 'kp -c "apd module install /data/local/tmp/fart-los21-module.zip"'

# 4. 装 ZygiskNext (如果未装)
$ADB push ZygiskNext-*.zip /data/local/tmp/
$ADB shell 'kp -c "apd module install /data/local/tmp/ZygiskNext-*.zip"'

# 5. 部署运行时文件
$ADB shell 'kp -c "\
    mkdir -p /data/local/tmp/fart /data/local/tmp/fart_dump && \
    cp /data/adb/modules/fart-los21/config/config.json /data/local/tmp/fart/ && \
    cp /data/adb/modules/fart-los21/lib64/libfart-hook.so /data/local/tmp/fart/ && \
    chmod 777 /data/local/tmp/fart/libfart-hook.so && \
    chcon u:object_r:system_lib_file:s0 /data/local/tmp/fart/libfart-hook.so && \
    chcon u:object_r:app_data_file:s0 /data/local/tmp/fart_dump && \
    chmod 777 /data/local/tmp/fart_dump"'

# 6. ZN 使用 system linker
$ADB shell 'kp -c "znctl linker system"'

# 7. 重启
$ADB reboot
```

### 10.2 测试流程

```bash
# 清理旧 dump
$ADB shell 'kp -c "rm -f /data/local/tmp/fart_dump/*.dex"'
$ADB shell 'kp -c "logcat -c"'

# 启动目标 app (Allsafe)
$ADB shell 'kp -c "monkey -p infosecadventures.allsafe 1"'

# 检查 FART 日志
$ADB logcat -d | grep 'FART_LOS21' | grep -E '✅|DefineClass|Dumped'

# 拉取 dump 文件
$ADB shell 'kp -c "cp /data/local/tmp/fart_dump/*.dex /data/local/tmp/ && chmod 644 /data/local/tmp/*.dex"'
$ADB pull /data/local/tmp/dex_*.dex ./

# 验证 (jadx)
jadx dex_*.dex -d output/
```

### 10.3 禁用与回滚

```bash
# 禁用模块
$ADB shell 'kp -c "touch /data/adb/modules/fart-los21/disable"'
$ADB shell 'kp -c "touch /data/adb/modules/zygisksu/disable"'
$ADB reboot

# 删除模块
$ADB shell 'kp -c "touch /data/adb/modules/fart-los21/remove"'
$ADB reboot
```

---

## 11. 遇到的坑与问题记录

本节按照实际排查顺序，记录每个障碍的现象、定位方法和最终解决方案。

### 坑 1: ZygiskNext 模块入口符号错误

**现象**：ZN 注册模块为 `modules64:1,fart-los21`，但 `dump-zn` 显示 `Modules: 0`，`preAppSpecialize` / `postAppSpecialize` 从未被调用。

**定位**：
```bash
# 检查模块描述
$ADB shell 'kp -c "apd module list"' | grep -i zygisk
# 输出: [❌ Stop inject zygote due to crash]
```

```bash
# 检查导出符号
$ADB shell 'kp -c "readelf -Ws /data/adb/modules/fart-los21/zygisk/arm64-v8a.so"' \ 
  | grep zygisk
```
发现只有 `zygisk_module_create` 而没有 `zygisk_module_entry`。

**根因**：自己写的入口函数 `zygisk_module_create` 不符合 ZygiskNext 的 API——ZN 期望的是 `zygisk_module_entry`，由 `REGISTER_ZYGISK_MODULE` 宏生成。

**解决**：使用官方的 `REGISTER_ZYGISK_MODULE(ClassName)` 宏，它生成正确的 `zygisk_module_entry`。最初使用的官方 zygisk.hpp (从 topjohnwu/zygisk-module-sample 下载) 中的 lambda 构造函数需要 libc++ 运行时，导致 zygote 加载崩溃。最终改为无 lambda 的静态 thunk 版本。

**教训**：**不要自己手写 Zygisk 入口**。必须用标准宏。

---

### 坑 2: ZygiskNext 内置 linker 地址预留不足

**现象**：ZN 内置 linker 报 `open module 0 with builtin linker failed: not preloaded`

**定位**：
```bash
$ADB logcat | grep zn-zygisk-loader64
# 输出: open module 0 with builtin linker failed: not preloaded
```

**根因**：ZN v1.3.4 的内置 linker 在预加载阶段只预留了 4096 字节的地址空间，且使用不兼容的预加载机制。

**解决**：切换到系统 linker 模式 (`znctl linker system`)。系统 linker 通过 dlopen 加载，工作正常。

**教训**：ZN 的内置 linker 模式在 APatch 上有兼容性问题，首次部署应默认使用系统 linker。

---

### 坑 3: 包名获取始终为 "zygote64"

**现象**：`postAppSpecialize` 中读取 `/proc/self/cmdline` 显示 "zygote64"，导致 allowlist 检查失败。

**定位**：
```cpp
// 最初使用的代码
char cmdline[256];
int fd = open("/proc/self/cmdline", O_RDONLY);
read(fd, cmdline, sizeof(cmdline)-1);
// 输出: pkg=zygote64
```

**根因**：`postAppSpecialize` 在 app 进程被 fork 后立即执行，此时 `/proc/self/cmdline` 尚未被更新为实际包名（仍显示父进程 "zygote64"）。

**解决**：改为三级 fallback：
1. `args->nice_name` (JNI string) — 最可靠
2. `args->app_data_dir` — `/data/user/<uid>/<package>` 提取最后一节
3. `/proc/self/cmdline` — 仅用于非 zygote 派生的进程

```cpp
// 最终使用的三级实现
if (args) {
    // Level 1: nice_name (通过 JNI 获取)
    JNIEnv* env = getJniEnv();
    if (env) {
        const char* n = env->GetStringUTFChars(args->nice_name, nullptr);
        if (n && strchr(n, '.') && !strchr(n, '/')) { pkg = n; got = true; }
        env->ReleaseStringUTFChars(args->nice_name, n);
    }
    // Level 2: app_data_dir
    if (!got) {
        const char* d = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (d) {
            const char* slash = strrchr(d, '/');
            if (slash && strchr(slash+1, '.')) { pkg = slash+1; got = true; }
            env->ReleaseStringUTFChars(args->app_data_dir, d);
        }
    }
}
// Level 3: cmdline (fallback)
if (!got) { readCmdline(pkg); }
```

**教训**：**永远不要只依赖 `/proc/self/cmdline`** 来获取 app 进程包名。

---

### 坑 4: ARM64 inline hook 蹦床崩溃

**现象**：DefineClassHook ENTER 触发后，在调用原始函数时 SIGSEGV。

**定位**：
```bash
$ADB logcat | grep DEBUG
# #01 pc 0x9cc90 in libfart-hook.so
# blr x8 → 调用蹦床中的原始函数 → 崩溃
```

```bash
# 反汇编查看蹦床代码
llvm-objdump -d libfart-hook.so | grep -A10 "9cc80:"
# 蹦床中的 B 指令: B offset ... 跳转到 target+16
# 但 offset 计算可能需要 ±128MB 范围内，mmap 分配地址可能太远
```

**根因**：第一个版本的蹦床使用 `B <target+16>` (PC-relative branch, 范围 ±128MB)。mmap 分配的蹦床地址可能超出此范围。

**解决**：将蹦床回跳指令从 `B` 改为绝对跳转 (`LDR X17, #8; BR X17; <8字节目标地址>`)，额外 12 字节但无范围限制。

```cpp
// 修复后的蹦床布局
*(uint32_t*)(trampoline+16) = 0x58000000 | (17<<0) | (2<<5);  // LDR X17, [PC, #8]
*(uint32_t*)(trampoline+20) = 0xD61F0000 | (17<<5);            // BR X17
*(uint64_t*)(trampoline+24) = target + 16;                      // 绝对目标地址
```

**教训**：ARM64 inline hook 的蹦台必须使用绝对跳转，不能用 PC-relative 指令。

---

### 坑 5: DexFile 内存布局变化 (Android 14)

**现象**：最初通过扫描 DexFile 对象偏移来查找 dex magic (`memcmp(candidate, "dex\n", 4) == 0`)，结果不稳定。

**定位**：在 Android 14 上 StandardDexFile 的内存布局发生了变化。之前的 FART 教程 (Android 6-10) 依赖的经验偏移在此已不适用。

**解决**：直接查 LineageOS 21 源码确认字段位置。
```bash
grep -n "begin_\|header_\|location_" \
  /lina_android/lineage/art/libdexfile/dex/dex_file.h
```

确认 `begin_` 在 DexFile 的 offset 8 (vtable 之后)，是 `const uint8_t* const`。不再需要扫描偏移。

```cpp
// 直接从已知偏移读取
uintptr_t obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFF;
const uint8_t* begin = *(const uint8_t**)(obj + 8);
uint32_t size = *(const uint32_t*)(begin + 0x20);  // header->file_size
```

**教训**：不同 Android 版本的 ART 内部结构不同，**必须从源码确认**而不是套用旧版本偏移。

---

### 坑 6: 同步写文件 vs 异步 worker 线程崩溃

**现象**：使用异步 worker 线程 (`std::thread`) 写 dex 文件时，worker 线程 SIGSEGV。

**定位**：
```bash
$ADB logcat | grep CRASH
# CRASH: signal=11, addr=0x72accc33e0, disabling hooks
# 崩溃线程 TID != PID (worker 线程)
```

**根因**：
1. Worker 线程通过 std::thread 创建，C++ 运行时在子线程中的初始化可能不完全
2. 写文件时任务对象的 smart pointer 移动语义导致 data 指针悬空
3. 写大文件 (9.7MB) 时内存访问触发 GC 移动

**解决**：改为**同步写入**——直接从 Hook 回调中写文件，不再经过 worker 线程。分块写入并逐块验证内存可读性。

```cpp
// 同步写入 + 分块 (64KB)
int fd = open(filename, O_CREAT|O_WRONLY|O_TRUNC, 0644);
while (remaining > 0) {
    size_t chunk = (remaining > 65536) ? 65536 : remaining;
    volatile uint8_t check = ptr[0]; (void)check;  // 验证可读
    ssize_t w = write(fd, ptr, chunk);
    if (w <= 0) break;
    remaining -= w;
    ptr += w;
}
close(fd);
```

**教训**：Hook 回调中不要创建 C++ 线程。小规模 dump 用同步写即可；大规模需单独的 C 语言工作线程。

---

### 坑 7: SELinux 写文件权限

**现象**：`cannot open /data/local/tmp/fart/.../dex_*.dex`

**定位**：
```bash
$ADB shell 'ls -laZ /data/local/tmp/fart'
# drwxrwxrwx root root u:object_r:shell_data_file:s0
# 而 app 进程的 context 是 u:r:untrusted_app:s0:c226
```

**根因**：即使目录有 777 权限，SELinux 策略也禁止 `untrusted_app` 域写入 `shell_data_file` 类型。

**解决**：创建专用输出目录，设正确的 SELinux context：
```bash
mkdir -p /data/local/tmp/fart_dump
chcon u:object_r:app_data_file:s0 /data/local/tmp/fart_dump
chmod 777 /data/local/tmp/fart_dump
```

**教训**：Android 14 的 SELinux 强制执行，需要创建正确的 directory context。

---

### 坑 8: 模块加载导致系统黑屏

**现象**：安装模块后系统能启动、电源菜单正常、但屏幕黑屏。

**定位**：
```bash
# 检查 ZN 状态
$ADB shell 'kp -c "apd module list"' | grep -i zygisk
# 输出: [❌ Stop inject zygote due to crash]
```

```bash
# 检查崩溃 tombstones
$ADB logcat -b crash | grep 'arm64-v8a.so\|libfart-hook.so'
```

**根因**：**多个不同原因**曾导致过黑屏：
1. 第一次: `zygisk.hpp` 中 `api_table.registerModule` 函数指针布局不正确，调用 ZN 的 libzygisk.so 时崩溃 → ZN 停止注入
2. 第二次: hook 核心 (234KB) 太大，ZN 系统 linker 地址预留不足
3. 第三次: 仅 `onLoad` 被调用（注册正常），但 `preAppSpecialize` 因 cmdline 读取错误未能正确 allowlist 判断

**解决** (每次):
1. 修正 `api_table` 和 `module_abi` 布局 → 不调用 `registerModule` 直接返回
2. loader 精简到 8KB → 去掉所有 C++ 运行时依赖
3. 改用 JNI nice_name 获取包名

**教训**：**安全规范**——始终维护 `disable` 标记文件，出问题立即 `touch /data/adb/modules/*/disable` 并重启。

---

### 坑 9: 官方 zygisk.hpp 的 lambda 导致 zygote 崩溃

**现象**：使用从 topjohnwu/zygisk-module-sample 下载的官方 `zygisk.hpp`，loader 在 zygote 阶段崩溃。

**定位**：
```bash
readelf -d arm64-v8a.so | grep NEEDED
# libc++_shared.so 存在
# zygote 进程没有预加载此库
```

**根因**：官方 `module_abi` 构造函数使用的 lambda 捕捉了变量，需要 C++ 运行时 (operator new / lambda closure)，导致静态链接的 libc++ 代码在 zygote 初始化阶段访问未初始化的堆。

**解决**：重写 `REGISTER_ZYGISK_MODULE` 宏，用静态函数 thunk 替代 lambda，完全消除 C++ 运行时依赖。

**教训**：Zygisk loader 不能有任何 lambda，必须用函数指针实现回调分派。

---

### 坑 10: Android 14 的指针标签 (TBI)

**现象**：从 `DexFile` 对象读取 `begin_` 指针时得到非法地址。

**定位**：`DefineClass` 的 `dex_file_ptr` 参数值为 `0xb4000073b7c79f70`，高字节 `0xb4` 是 TBL (Top Byte Ignore) 标签。

**根因**：Android 14 使用 ARM64 的 TBL 特性对指针打标签，访问内存前需要清除标签。

**解决**：
```cpp
uintptr_t obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFFULL;
```

**教训**：Android 14 处理 ART 对象指针时，先用 `& 0x00FFFFFFFFFFFFFF` 清除标签。

---

### 坑 11: 第一次挂钩成功但回调从未触发

**现象**：`✅ FART hooks activated` 后，`DefineClassHook ENTER` 从未出现。

**定位**：
```bash
$ADB logcat | grep 'Found DefineClass'
# Found DefineClass at 0x7323cfe930  ← 错误地址！

# 正确计算:
# file_base = 0x732383a000 (从 maps 解析)
# correct = 0x732383a000 + 0x2c4930 = 0x7323afe930
```

**根因**：`art_resolver.cpp` 中的 `FindLibArtInMaps()` 使用 `r-xp` 段起始地址 (0x7323a3a000) 作为 libart base。但 libart.so 的 `r-xp` 段从文件偏移 0x200000 开始，而 `readelf` 给出的 DefineClass 偏移 0x2c4930 是从文件起始计算的。差值 0x200000 导致挂钩地址错误。

**解决**：修正 maps 解析，从 `sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &file_off)` 提取文件偏移，计算 `file_base = segment_start - file_off`。

**教训**：**`readelf` 偏移是相对于 ELF 文件起始的**，不是相对于代码段的。

---

### 坑 12: loader 和 test module 行为不一致

**现象**：最小测试模块（`class TestModule`）能正常触发 `preAppSpecialize/postAppSpecialize`，但完整 FART loader（`class FartLoader`）不行。两个模块使用相同的 `REGISTER_ZYGISK_MODULE` 宏和编译参数。

**定位**：通过二进制 diffing，测试模块输出 231KB (含完整 libc++ 静态链接)，而 FART loader 输出 10KB (只含 -nostdlib++)。ZN 内置 linker 只预加载了测试模块，loader 因为太小触发不同的预加载逻辑。

**解决**：统一使用 10KB 版本的 loader，切换到系统 linker 模式。

**教训**：**两种 linker 模式对模块大小的处理不同**——内置 linker 不接受 10KB 的模块，系统 linker 不接受 234KB 的模块。需要测试确认目标 linker mode 的接受范围。


---

## 12. 验收标准

| 编号 | 条件 | 状态 |
|------|------|------|
| 1 | 模块开机自动加载 | ✅ |
| 2 | 只对 allowlist package 生效 | ✅ |
| 3 | app 不崩溃 | ✅ |
| 4 | 从 libart.so 找到并 Hook DefineClass | ✅ offset 0x2c4930 |
| 5 | 启动测试 app 后在输出目录生成 dex | ✅ 6 个 dex |
| 6 | dex 文件 jadx 能打开 | ✅ dex\n035 + dex\n039 |
| 7 | 删除模块或关配置后系统恢复正常 | ✅ |
| 8 | Phase 2: ArtMethod::Invoke Hook 安装 + 默认关闭不影响 DefineClass | ✅ |
| 9 | Phase 2: enable_artmethod_hook=true 后 Hook 安装成功、app 不崩溃 | ✅ |
| 10 | Phase 2: 字段解析 (class_ref + dex_idx + flags) + 过滤 native/abstract/runtime | ✅ |
| 11 | Phase 2: 4 个 Git 分支已推送到 GitHub | ✅ |
