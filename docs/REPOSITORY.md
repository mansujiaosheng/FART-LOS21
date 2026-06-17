# FART-LOS21 代码仓库结构说明

## 顶层目录

```
fart-los21/                          ← 项目根目录
├── module/                           ← APatch/Zygisk 模块定义文件
├── config/                           ← 运行时配置文件
├── native/                           ← native 代码 + 编译系统
│   ├── include/                      ← 所有头文件
│   │   ├── config.h
│   │   ├── codeitem_dump.h
│   │   ├── active_invoke.h
│   │   ├── helper_dex.h             ← 嵌入的 Java helper DEX 数据
│   │   └── ...
│   ├── Makefile                      ← NDK 交叉编译
│   ├── hook_entry.cpp               ← Hook 核心 (DefineClass + ArtMethod::Invoke)
│   ├── config.cpp                    ← JSON 解析
│   ├── art_resolver.cpp             ← ART 符号解析
│   ├── dex_dump.cpp                  ← DEX 写入
│   ├── codeitem_dump.cpp            ← Stage 2.4: CodeItem dump worker
│   ├── active_invoke.cpp            ← Stage 2.5: 主动调用引擎
│   ├── zygisk_loader.cpp            ← Zygisk 入口 (无 STL)
│   ├── helper/                      ← Java helper 源码
│   │   └── com/fartlos21/helper/FartBridge.java
│   └── injector.c                   ← 已废弃
├── scripts/                          ← 管理脚本 + PC 端工具
│   ├── dex_structs.py               ← Stage 2.6: DEX 结构 + ULEB128
│   ├── dex_repair.py                ← Stage 2.6: dex 修复器
│   └── ...
├── docs/                             ← 文档
│   ├── TECHNICAL.md                 ← 技术参考 + 坑记录
│   ├── REPOSITORY.md                ← 仓库结构
│   └── stage2.4-quality-report.md
├── libart_device.so                  ← 从设备拉取的 libart.so
├── art_symbol_analysis.json          ← libart 符号分析结果
├── fxsp_dump/                        ← 风行视频脱壳数据 (6 dex)
└── fart-los21-module.zip             ← 打包好的模块 zip
```

---

## module/ — APatch 模块定义

| 文件 | 用途 |
|------|------|
| `module.prop` | 模块元数据 (id, name, version, author, description) |
| `customize.sh` | 安装脚本: 设置权限, 创建目录, 复制默认配置 |
| `service.sh` | 开机自启: 创建 dump 目录, 启动 injector 守护进程 (可选) |
| `sepolicy.rule` | SELinux 策略: 允许 app 进程写入 tmpfs |

---

## config/ — 运行时配置

| 文件 | 用途 |
|------|------|
| `config.json` | 模块运行时配置: enable, packages (allowlist), blacklist_packages, dump_dir, dump_dex, dump_code_item, active_invoke, enable_artmethod_hook, artmethod_sample_rate |

**配置格式**:
```json
{
    "enable": true,
    "packages": [
        "infosecadventures.allsafe",
        "com.funshion.video.mobile",
        "com.example.farttest"
    ],
    "blacklist_packages": [],
    "dump_dir": "/data/local/tmp/fart",
    "dump_dex": true,
    "dump_code_item": false,
    "active_invoke": false,
    "enable_artmethod_hook": false,
    "artmethod_sample_rate": 1000
}
```

---

## native/ — native 代码

### 目录结构

```
native/
├── Makefile              ← 编译入口: `make` 构建所有产物
├── include/              ← 头文件
│   ├── zygisk.hpp        ← Zygisk API 头文件 (无 lambda / 无 STL)
│   ├── arm64_hook.h      ← ARM64 inline hook 引擎 (绝对跳转版本)
│   ├── config.h          ← Config 结构体定义
│   ├── art_resolver.h    ← libart 符号解析器
│   ├── dex_dump.h        ← Dex 文件写入器
│   └── fart_hook.h       ← HookManager (当前未使用)
├── zygisk_loader.cpp     ← **Zygisk 模块入口 (loader)**
├── hook_entry.cpp         ← **Hook 核心 + DefineClass 回调 + snapshot dump**
├── config.cpp            ← JSON 配置解析 (不依赖外部库)
├── art_resolver.cpp      ← 符号解析器 (dlsym → offset → pattern scan)
├── dex_dump.cpp          ← 异步/同步 dex 文件写入 + SHA256
├── injector.c            ← Ptrace 注入器 (已废弃，仅供历史参考)
├── test_zn_module.cpp    ← 最小 Zygisk 测试模块 (用于调试 ZN 环境)
├── Dobby/                ← Dobby inline hook 框架 (备用，当前未使用)
└── out/                  ← 编译产物目录
    ├── zygisk/
    │   └── arm64-v8a.so  ← Zygisk loader (8KB)
    ├── lib64/
    │   └── libfart-hook.so ← Hook 核心库 (1.3MB, 全静态链接)
    └── test/
        └── arm64-v8a.so  ← 测试模块
```

### 编译产物

| 产物 | 源文件 | 大小 | 依赖 |
|------|--------|------|------|
| `zygisk/arm64-v8a.so` | `zygisk_loader.cpp` | 8KB | liblog, libc, libdl, libm |
| `lib64/libfart-hook.so` | `hook_entry.cpp` + `config.cpp` + `art_resolver.cpp` + `dex_dump.cpp` | 1.3MB | liblog, libc, libdl, libm (全静态链接) |
| `test/arm64-v8a.so` | `test_zn_module.cpp` | 231KB | liblog, libc, libdl (带静态 libc++) |

### 编译命令

```bash
# 构建所有产物 (loader + hook core)
make clean && make -j4

# 只构建 loader
make zygisk

# 只构建测试模块
make test
```

---

## native/ 源文件详细说明

### zygisk_loader.cpp — Zygisk 模块入口

**职责**: 作为 Zygisk 模块的入口点, 在 app 进程的 `postAppSpecialize` 阶段:
1. 通过 JNI 获取当前进程包名 (三级 fallback)
2. 检查硬编码白名单 (安全约束)
3. `dlopen` libfart-hook.so
4. 调用 `fart_on_app_specialize` 显式初始化函数

**关键函数**:
- `postAppSpecialize(zygisk::AppSpecializeArgs*)` — 主入口
- 包名解析: `nice_name` (JNI) → `app_data_dir` → `/proc/self/cmdline`

**编译选项**:
- `-fno-rtti -fno-exceptions`: 禁用 C++ RTTI 和异常
- `-nostdlib++`: 不链接 libc++
- `-fvisibility=hidden`: 隐藏符号
- **不包含任何 STL** — 纯 C 风格实现 (char[] 代替 std::string, FILE* 代替 std::ifstream)

---

### hook_entry.cpp — Hook 核心

**职责**:
1. `fart_on_app_specialize()` — 显式初始化入口 (由 loader 通过 dlsym 调用)
   - 解析配置 + 获取 app files dir (SELinux 安全输出路径)
   - 调用 SetupHooks() + DumpAlreadyLoadedDex()
   - 条件启动 ActiveInvokeEngine
2. `SetupHooks()` — 解析 DefineClass + ArtMethod::Invoke 地址, 安装 ARM64 inline hook
3. `DefineClassHook()` — DefineClass 回调:
   - 读取 DexFile.begin_ → 验证 dex magic → 去重 (begin_ addr set) → 写文件
4. `ArtMethodInvokeHook()` — ArtMethod::Invoke 回调:
   - Stage 2.1: 采样计数 + 日志
   - Stage 2.2: 字段解析 (declaring_class, dex_method_index, access_flags)
   - Stage 2.3: CodeItem metadata (regs, ins, outs, tries, insns)
   - Stage 2.4: CodeItem dump (QueueDump → 异步写入)
   - Phase 2: skip_execute 检测 + JValue 填充 (主动调用跳过执行)
5. `DumpAlreadyLoadedDex()` — Java 反射枚举已加载 dex
6. `IsRangeReadable()` — 内存可读性验证 (/proc/self/maps)
7. `CrashHandler()` — SIGSEGV 信号处理器 (清理所有 hook)

**关键架构决策**:
- constructor 仅打日志, 不做任何初始化
- 所有初始化通过 `fart_on_app_specialize` 显式执行
- 使用同步写入 (不用工作线程) 避免 C++ 运行时兼容性问题

---

### config.cpp — 配置解析

**职责**: 解析 JSON 格式的运行时配置文件

**实现**: 不依赖任何 JSON 库, 使用简单的字符串查找和状态机解析:
- `json_read_bool()` — 解析 `"enable": true/false`
- `json_read_string()` — 解析字符串值
- `json_read_array()` — 解析 `"packages": ["pkg1", "pkg2"]` 数组

**支持的字段**: enable, packages, blacklist_packages, dump_dir, dump_dex, dump_code_item, active_invoke, enable_artmethod_hook, artmethod_sample_rate

---

### art_resolver.cpp — ART 符号解析

**职责**: 在运行时查找 libart.so 中的 ART 函数地址

**实现**:
1. `FindLibArtInMaps()` — 从 `/proc/self/maps` 解析 libart.so 的基址
   - 读取 `r-xp` 段的 `start`, `end`, 和 `file_offset`
   - 计算 `file_base = segment_start - file_offset`
2. `ResolveByName()` — dlsym 查找符号
3. `ResolveByOffset()` — 使用预知的文件偏移计算地址
4. `ResolveByPattern()` — 字节模式扫描 (备用)

**关键修复**: 正确处理 maps 中的 file offset, 以正确计算 file base。

---

### dex_dump.cpp — Dex 写入器

**职责**: 将 dex 数据写入磁盘, 支持去重

**实现**:
- `IsValidDex()` — 验证 dex magic
- `ComputeSha256()` — 内嵌的 SHA256 实现 (不依赖 OpenSSL)
- `WriteDexFile()` — 同步写入 (分块 64KB)
- `WorkerLoop()` — 异步写入线程 (已被同步模式替代)
- `QueueDex()` — 带去重的 async queue 接口

**去重**: 使用 SHA256 前 8 字节的 hex 字符串作为 key, 存在内存中的 `unordered_set`

---

## include/ — 头文件

### zygisk.hpp — Zygisk API 头文件

**注意**: **不是** topjohnwu 官方的 zygisk.hpp。这是一个重写版本, 核心区别:

| 特性 | 官方版本 | 本项目版本 |
|------|----------|-----------|
| `module_abi` 构造函数 | 使用 lambda | **使用静态 thunk 函数指针** |
| 运行时依赖 | 需要 libc++ (lambda --> operator new) | **无 C++ 运行时依赖** |
| REGISTER_ZYGISK_MODULE | 生成 `zygisk_module_entry` | 同样, 但内部实现不同 |
| `api_table` 布局 | 完整 vtable | 简化为 `{impl, registerModule, reserved[8]}` |

定义了:
- `zygisk::ModuleBase` — 虚基类: onLoad, preAppSpecialize, postAppSpecialize, preServerSpecialize, postServerSpecialize
- `zygisk::AppSpecializeArgs` — 参数 struct: uid, gid, nice_name, app_data_dir, ...
- `zygisk::internal::module_abi` — 模块 ABI: impl + 4 个函数指针
- `zygisk::internal::api_table` — ZN 传递的 API 表
- `REGISTER_ZYGISK_MODULE(Class)` — 注册宏

---

### arm64_hook.h — ARM64 Inline Hook 引擎

**职责**: 在 ARM64 指令级别实现函数钩子

**实现**: 
- 在目标地址写入 `LDR X17, #8; BR X17; <8字节地址>` 共 16 字节
- 使用 mmap 分配蹦床 (prot = rwx)
- 蹦台: 原始 16 字节 + 绝对跳转回 `target+16`
- 绝对跳转: `LDR X17, #8; BR X17; <8字节地址>`

**解决的问题**:
- PC-relative B 指令范围限制 → 改用绝对跳转
- 蹦台地址与目标距离 → 不再相关 (绝对跳转没有距离限制)

---

## scripts/ — 管理脚本

| 脚本 | 用途 |
|------|------|
| `install_module.sh` | 编译 → 打包 → 推送 → `apd module install` |
| `disable_module.sh` | 设置 disable 标记 → 重启 |
| `pull_dump.sh` | 从设备拉取 dump 目录 |
| `collect_crashlog.sh` | 收集 logcat + tombstone + 模块日志 |
| `check_art_symbols.py` | 分析设备 libart.so 符号表 |
| `package_module.sh` | 打包模块为 zip |

---

## docs/ — 文档

| 文档 | 内容 |
|------|------|
| `TECHNICAL.md` | 完整技术实现文档 (本项目的伴随文档) |
| `DESIGN.md` | 架构设计说明 (TODO) |

---

## 设备部署结构

```
/data/adb/modules/fart-los21/        ← APatch 模块目录
├── module.prop
├── customize.sh
├── service.sh
├── sepolicy.rule
├── config/
│   └── config.json                   ← 模块内部配置 (安装时复制到 /data/local/tmp/fart/)
├── zygisk/
│   └── arm64-v8a.so                  ← loader (8KB)
└── lib64/
    └── libfart-hook.so               ← hook 核心 (1.3MB)

/data/local/tmp/fart/                 ← 运行时目录
├── config.json                       ← 运行时可改配置
├── libfart-hook.so                   ← hook 核心 (可独立更新)
├── injector.log                      ← injector 日志 (废弃)
└── module.log                        ← 模块日志

/data/local/tmp/fart_dump/            ← dex 输出目录
└── dex_<pid>_<tid>.dex               ← dump 出的 dex 文件
```

---

## 关键设计原则

1. **模块化**: loader 和 hook core 是两个独立的 .so, 通过 `fart_on_app_specialize` 接口通信
2. **最小依赖**: loader 不依赖任何 C++ 运行时, 纯 C 实现
3. **静态链接**: hook core 使用 `--whole-archive` 全静态链接 libc++, 避免 libc++_shared 缺失
4. **三级安全保护**: loader hard allowlist → config allowlist → hook constructor 安全检查
5. **可回滚**: 任何模块修改通过 `disable` 标记即可恢复
6. **不修改系统**: 所有文件在 `/data/adb/modules/` 或 `/data/local/tmp/`, 不碰 system 分区
7. **ArtMethod 钩子线程安全**: ArtMethod::Invoke 是高频率函数, 使用 thread_local reentry guard 防止递归, 按 sample_rate 采样避免性能损耗

---

## 构建依赖

```makefile
NDK_PATH  = /lina_android/android-ndk-r27
TOOLCHAIN = $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
CXX       = $(TOOLCHAIN)/bin/aarch64-linux-android34-clang++
CC        = $(TOOLCHAIN)/bin/aarch64-linux-android34-clang
STRIP     = $(TOOLCHAIN)/bin/llvm-strip
SYSROOT   = $(TOOLCHAIN)/sysroot
```

- **无外部库依赖** (Dobby 源码已包含但未使用)
- **无 gradle / cmake** — 只用 GNU Make
- 编译目标: Android 14 (API level 34), ARM64 (aarch64)
