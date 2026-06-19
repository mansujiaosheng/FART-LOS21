# FART-LOS21 项目交接文档

> 最后更新：2026-06-19
> Git HEAD: `1272b44` (feat/session-repair-apk)
> Tags: `v0.1-fart-pipeline-mvp`, `v0.2-coverage-safe-load`

---

## 一、项目概述

FART-LOS21 是一个面向 **Android 14 / LineageOS 21** 的 ART 层 DexFile / CodeItem dump 与 dex repair 研究项目。

基于 APatch + ZygiskNext 注入 Zygisk 模块，通过 inline hook 拦截 ART `ClassLinker::DefineClass`、`ArtMethod::Invoke` 和 `ClassLinker::LoadMethod`，在应用运行时将内存中的 DEX 字节码和 CodeItem 同步 dump 到文件系统，并通过 `repair_dex.py` 修复抽取的方法体。

**当前状态：MVP 可用** — 已形成完整链路：

```text
控制器开关 → Zygisk注入 → DefineClass dump DEX
→ LoadMethod 捕获 code_item → CSV/code 文件落盘
→ repair_dex.py 修复 → jadx 可分析
```

---

## 二、目录结构

```text
/lina_android/fart-los21/
├── FartController/             # Android 可视化控制器 App
│   ├── app/src/main/java/.../
│   │   ├── MainActivity.java   # 主界面 + 应用列表 + 配置生成
│   │   └── RootShell.java      # 本地文件操作 + 状态管理
│   └── build.sh                # 一键编译脚本
├── module/                     # APatch/Zygisk 模块
│   ├── module.prop
│   ├── service.sh              # 后台守护：配置搬运 + 心跳 + 自动导出
│   ├── customize.sh
│   ├── sepolicy.rule
│   ├── zygisk/arm64-v8a.so    # Zygisk 加载器
│   └── lib64/libfart-hook.so  # Hook 核心库 (1.3MB)
├── config/                     # 默认 config.json
├── native/                     # Native hook 核心源码
│   ├── include/                # C++ 头文件
│   │   ├── config.h            # 配置结构体
│   │   ├── dex_dump.h          # DexDumpTask + DexDumper
│   │   ├── codeitem_dump.h     # CodeItemDumpTask + CodeItemDumper
│   │   ├── active_invoke.h     # ActiveInvokeEngine
│   │   ├── arm64_hook.h        # ARM64 inline hook
│   │   ├── art_resolver.h      # libart 符号解析
│   │   └── zygisk_loader.h     # Zygisk 加载器
│   ├── zygisk_loader.cpp       # Zygisk 加载器（最小 STL 依赖）
│   ├── hook_entry.cpp          # Hook 核心：DefineClass + ArtMethod::Invoke + LoadMethod
│   ├── config.cpp              # Minimal JSON 解析
│   ├── dex_dump.cpp            # DEX 校验 / SHA256 / 写入
│   ├── codeitem_dump.cpp       # CodeItem 被动/主动 dump + CalculateCodeItemSize
│   ├── active_invoke.cpp       # JNI 反射主动调用/加载引擎
│   └── art_resolver.cpp        # libart 符号/偏移解析器
├── tools/                      # 修复工具
│   ├── repair_dex.py           # DEX repair v3（支持 --carrier-dex）
│   ├── repair_apk.py           # APK 级批量 repair
│   └── report_coverage.py      # 覆盖率分析
├── scripts/                    # 构建/安装/调试脚本
├── docs/                       # 技术文档
└── libart_device.so            # 设备 libart.so（符号分析用）
```

---

## 三、已实现功能

### 3.1 Hook 点

| Hook | 触发时机 | 覆盖率 |
|------|---------|--------|
| `ClassLinker::DefineClass` | 每个类加载时 | 全部 DEX |
| `ArtMethod::Invoke` | 反射/JNI 调用时 | 低（仅反射路径） |
| `ClassLinker::LoadMethod` | **每个方法加载时** | **高（全部方法）** |

LoadMethod 是最关键的 Hook 点 — 它在 ART 加载每个方法时触发，此时 code_item 指针已就绪。覆盖范围远超 ArtMethod::Invoke。

### 3.2 数据采集

- **DEX dump**：通过 DefineClass hook 读取 `DexFile::begin_`，写入 `/data/data/<pkg>/files/fart_dump/`
- **CodeItem dump**：通过 LoadMethod hook 读取 `ArtMethod::data_`（code_item 指针），计算完整大小（含 try/catch handler），写入 `<dump_dir>/methods/`
- **主动调用/加载**：可配置的 `active_invoke_classes`，支持 safe load（不触发 `<clinit>`）和 full invoke
- **SELinux 适配**：dump 写入 app 私有目录（`/data/data/<pkg>/files/`），规避 `untrusted_app` 无法写入 `shell_data_file` 的问题

### 3.3 DEX Repair

- **`repair_dex.py` v3**：
  - 解析 DEX header、class_defs、class_data_item、encoded_methods
  - 按 `(dex_key, method_idx)` 匹配 code_item（支持多 DexFile）
  - 重建 class_data_item（处理 ULEB128 尺寸变化）
  - 支持 `--carrier-dex`（用原始完整 DEX 做结构基底）
  - 验证：map_off、data_off、class_data_off 硬检查
  - 修复 header（file_size、sha1 signature、adler32 checksum）
- **`repair_apk.py`**：自动提取 APK 中所有 classes*.dex，匹配 dump 数据，批量 repair
- **`report_coverage.py`**：按类/包分析缺失方法分布，检测异常统计

### 3.4 配置桥接

Android 14 mount namespace 隔离导致 app 进程无法访问 `/system/bin/kp` 和 `/data/adb/modules/`。采用 service.sh 桥接方案：

```text
App 写 /data/data/<pkg>/files/config.json
         ↓ service.sh 每 2 秒轮询（以 root 运行）
复制到 /data/adb/modules/fart-los21/config/config.json
复制到 /data/local/tmp/fart/config.json
```

### 3.5 FartController App

- Android 可视化控制器
- 选择目标应用 → 允许/关闭脱壳
- service.sh 自动 force-stop + 配置搬运
- 统计显示 + 导出到 sdcard

---

## 四、当前验证状态

### 验证数据（风行视频 com.funshion.video.mobile）

```text
DEX 文件完整大小：11,489,496 bytes (11.9MB)
map_list 位置：    0xaf4ffc（文件内）
encoded methods：  57,672
  - 已有 code：    54,461
  - 缺失 code：     3,211
.code 文件数：      2,530
已修复方法数：      38
修复后 status：     complete（validation 通过）
```

### 关键修复历史

| 问题 | 修复 |
|------|------|
| DEX 被 maps 截断到 10MB | 去掉 maps cap，改为 EFAULT 页跳过 |
| class_data_off 64% 超出文件 | 上面修复后归零 |
| LoadMethod 符号找不到 | 添加 offset fallback `0x2d4510` |
| SELinux 拒绝 dlopen | service.sh 添加 `chcon system_lib_file:s0` |
| CodeItem size 固定计算 | 实现 CalculateCodeItemSize（含 ULEB128 handler） |
| carrier 不匹配 stub DEX | 添加 exact match 检测 + fallback |

---

## 五、使用方式

### 5.1 快速测试

```bash
# 打开 FartController → 选应用 → 允许脱壳 → 手动打开 app → 等待

# 拉取 dump 数据
adb -H 192.168.238.1 -P 5037 shell kp -c \
  "cp /data/data/<pkg>/files/fart_dump/dex_*.dex /sdcard/ && \
   cp /data/data/<pkg>/files/fart_dump/methods/* /sdcard/methods/"

adb pull /sdcard/ ./fart_dump/

# 修复
python3 tools/repair_dex.py \
  --dex ./fart_dump/dex_largest.dex \
  --code-dir ./fart_dump/methods/ \
  --out repaired.dex

# 查看
jadx repaired.dex
```

### 5.2 覆盖率分析

```bash
python3 tools/report_coverage.py \
  --dex dumped.dex \
  --csv method_index.csv \
  --code-dir methods/ \
  --out coverage.json
```

### 5.3 APK 级批量修复

```bash
# 需要原始 APK
python3 tools/repair_apk.py \
  --apk target.apk \
  --dump-dir ./fart_dump/ \
  --out repaired_apk/
```

---

## 六、关键配置项

config.json 支持以下字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| enable | bool | false | 总开关 |
| packages | string[] | [] | 目标包名白名单 |
| dump_dir | string | /data/local/tmp/fart | dump 目录（会被运行时覆盖） |
| dump_dex | bool | true | 是否 dump DEX |
| enable_artmethod_hook | bool | false | 启用 ArtMethod::Invoke hook |
| artmethod_sample_rate | uint | 1000 | Invoke 采样率 |
| enable_codeitem_dump | bool | false | 启用 CodeItem dump |
| max_codeitem_dumps | uint | 5000 | CodeItem 最大数 |
| enable_active_invoke | bool | false | 启用主动调用 |
| active_load_classes | bool | false | 启用安全类加载（无 `<clinit>`） |
| class_init | bool | false | 初始化类（触发 `<clinit>`） |
| active_invoke_classes | string[] | [] | 要调用/加载的类名 |
| active_invoke_delay_ms | uint | 2000 | 主动调用延迟 |
| active_invoke_max_methods | uint | 500 | 每类最大方法数 |
| active_invoke_skip_execute | bool | true | 跳过方法执行 |

---

## 七、已知问题

### 7.1 仍需完善的

1. **`map_list` 未重建** — repaired DEX 的 map_list 来自原始 DEX dump。如果 dump 时 map_list 完好则没问题，否则 `dexdump` 会报 map 错误。`jadx` 和 `baksmali` 不依赖 map_list。
2. **3,211 个缺失方法** — LoadMethod 还没捕获到这些方法。需要更充分的 app 运行（走完所有 UI 路径）或主动类加载。
3. ~~**多 session 数据混叠** — CSV 中的 .code 文件来自不同进程启动。建议添加 `--session-pid` 过滤，但 pid 未写入 CSV。~~ → **已解决**：CSV 已增加 pid/process_name 列，repair_dex.py 支持 `--extra-code-dirs` 跨 session 去重合并。

### 7.2 架构限制

1. ~~**`ClassLinker::LinkCode` 未 Hook** — 静态函数，无导出符号，需 offset 寻址。延后处理。~~ → **已确认**：LinkCode 已被编译器内联到 LoadClass 中，无法单独 hook。LoadMethod hook 已覆盖 CodeItem 捕获需求。
2. ~~**CDEX (dex039) 不支持** — CompactDex 格式的 DEX 文件（以 `dex\n039` 开头）当前会被跳过。需要 CompactDex 专用解析器。~~ → **已解决**：实现了 `DecodeCompactCodeItem()` 和 `CalculateCompactCodeItemSize()`，LoadMethodHook 和 ArtMethodInvokeHook 均已支持 CompactDex CodeItem 解析。
3. **Active Invoke 需手动配置类名** — 不会自动扫描所有类。安全原因，避免触发 `<clinit>` 副作用。
4. **service.sh 需重启后生效** — 更新 service.sh 后必须重启或手动 kill 旧进程。

---

## 八、后续建议

按优先级排列：

1. **P7.5: 用真实加固样本验证** — 用 2-3 个不同的抽取壳 APK 测试完整链路
2. ~~**P6.4: 去重合并** — 跨 session 的 .code 文件去重策略（同 dex_key+method_idx 取最大 size）~~ → **已完成**：repair_dex.py 新增 `merge_code_records()` 和 `--extra-code-dirs`
3. ~~**P6.3: `LinkCode` Hook** — 需要用 readelf 找到设备 libart.so 中 LinkCode 的偏移~~ → **已确认不可行**：LinkCode 已被编译器内联到 LoadClass，LoadMethod hook 已覆盖需求
4. ~~**CSV 增加 pid/process_name** — 便于 session 隔离~~ → **已完成**：CSV 新增 pid 和 process_name 列
5. ~~**CDEX 支持** — 处理 `dex\n039` CompactDex 格式~~ → **已完成**：实现 DecodeCompactCodeItem + CalculateCompactCodeItemSize

---

## 九、设备环境

```text
设备：    OnePlus 9 (lemonade)
系统：    Android 14 / LineageOS 21
Root：    APatch
Zygisk：  ZygiskNext（须使用 system linker 模式）
ADB：     adb -H 192.168.238.1 -P 5037
Root cmd：kp -c
NDK：     /lina_android/android-ndk-r27
```

---

## 十一、邦邦加固 (KADP) 脱壳实战指南

> 本章节详细记录了对风行视频 (com.funshion.video.mobile) 使用邦邦加固 (KADP) 的 App 进行脱壳的完整过程，包括每一步操作、遇到的问题和解决方案。按照本指南可以复现整个脱壳流程。

### 11.1 邦邦加固 (KADP) 技术背景

**邦邦加固** 是一种常见的 Android 应用加固方案，其核心保护机制：

| 保护机制 | 实现方式 | 对脱壳的影响 |
|----------|---------|-------------|
| DEX 加密 | APK 内的 classes.dex 是壳 DEX（只有 stub），真实 DEX 在运行时由 native 解密加载 | 直接解压 APK 得不到真实代码 |
| ClassLoader 替换 | 使用自定义 ClassLoader 替换 PathClassLoader，在加载类时动态解密 | DefineClass hook 能捕获解密后的 DEX |
| SO 路径扫描 | `UniverseSecNo2` 模块扫描 `/proc/self/maps`，检测可疑 SO 路径 | 任何注入的 SO 都会被发现 |
| Inline hook 检测 | 检测关键函数的指令是否被修改 | 传统的 inline hook 方案会被检测 |
| `[hit] No6` 告警 | 在 maps 中发现 `fart`/`zygisk`/`magisk` 等关键字 | App 立即崩溃或退出 |

**关键发现**：邦邦加固的安全检查不是在 app 启动瞬间执行的，而是在 `libkadp.so` 初始化完成后异步执行。这给了我们一个时间窗口。

### 11.2 脱壳策略：No-hook 模式 + dlclose + 外部进程扫描

面对邦邦加固的检测机制，传统的 inline hook 方案完全失效。我们设计了三层防御策略：

```
┌─────────────────────────────────────────────────────────────┐
│ 第 1 层：No-hook 模式 — 不安装任何 native hook               │
│   → 邦邦加固的 inline hook 检测无效                           │
│                                                               │
│ 第 2 层：dlclose 卸载 SO — 在安全检查前移除注入的 SO           │
│   → 邦邦加固的 SO 路径扫描找不到可疑 SO                       │
│                                                               │
│ 第 3 层：外部进程扫描 — 从 root shell 读取 app 进程内存       │
│   → 绕过 postAppSpecialize 时 DEX 尚未加载的问题              │
└─────────────────────────────────────────────────────────────┘
```

### 11.3 环境准备

#### 11.3.1 设备要求

```text
设备：    OnePlus 9 (lemonade) 或其他已 root 的 Android 14 设备
系统：    Android 14 / LineageOS 21
Root：    APatch (内核级 root)
Zygisk：  ZygiskNext（须使用 system linker 模式）
ADB：     adb -H 192.168.238.1 -P 5037（远程 ADB 连接）
NDK：     /lina_android/android-ndk-r27
```

#### 11.3.2 确认 ADB 连接

```bash
# 测试 ADB 连接
adb -H 192.168.238.1 -P 5037 devices

# 切换到 root 模式（重要：su 命令在此设备上不可用，必须用 adb root）
adb -H 192.168.238.1 -P 5037 root

# 验证 root 权限
adb -H 192.168.238.1 -P 5037 shell id
# 应输出: uid=0(root) gid=0(root)
```

> **坑 #1：adb root vs su**
> 在此设备上 `su` 命令不可用（APatch 的 su 实现可能有问题），必须使用 `adb root` 重启 adbd 为 root 模式。如果 `adb root` 提示 "adbd cannot run as root in production builds"，需要确认设备已正确 root。

#### 11.3.3 确认 FART 模块已安装

```bash
# 检查模块目录
adb -H 192.168.238.1 -P 5037 shell ls /data/adb/modules/fart-los21/

# 应看到以下文件：
# module.prop  service.sh  customize.sh  sepolicy.rule
# zygisk/  lib64/  config/

# 检查 Zygisk 模块 SO
adb -H 192.168.238.1 -P 5037 shell ls -la /data/adb/modules/fart-los21/zygisk/
# arm64-v8a.so  (约 9.5KB)

# 检查 Hook 核心 SO
adb -H 192.168.238.1 -P 5037 shell ls -la /data/adb/modules/fart-los21/lib64/
# libfart-hook.so  (约 1.3MB)
```

### 11.4 编译 FART 模块

#### 11.4.1 编译 Zygisk 加载器 (arm64-v8a.so)

Zygisk 加载器必须非常小（虚拟地址空间 < 0x5000 = 20KB），因为 ZygiskNext 对模块 SO 的地址空间有限制。

```bash
cd /lina_android/fart-los21/native

# 编译 Zygisk 加载器
/lina_android/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++ \
  -O2 -fno-exceptions -fno-rtti -fvisibility=hidden \
  -shared -static-libstdc++ \
  -I/lina_android/fart-los21/native/include \
  -o out/zygisk/arm64-v8a.so \
  zygisk_loader.cpp \
  -ldl -llog

# 验证大小
ls -la out/zygisk/arm64-v8a.so
# 应小于 20KB

# 检查虚拟地址空间
readelf -l out/zygisk/arm64-v8a.so | grep LOAD
# 虚拟地址范围不应超过 0x5000
```

> **坑 #2：ZygiskNext 地址空间限制**
> ZygiskNext 为模块 SO 保留了 0x5000 (20KB) 的虚拟地址空间。如果编译出的 SO 超过这个大小，加载时会崩溃。解决方案：
> - 使用 `-fno-exceptions -fno-rtti` 禁用 C++ 异常和 RTTI
> - 使用 `-fvisibility=hidden` 减少导出符号
> - 使用 `-static-libstdc++` 静态链接 STL
> - 保持代码极简，只做 dlopen + dlsym + 调用

#### 11.4.2 编译 Hook 核心库 (libfart-hook.so)

```bash
cd /lina_android/fart-los21/native

# 使用 Makefile 编译
make clean && make

# 或者手动编译
/lina_android/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++ \
  -O2 -fno-exceptions -fno-rtti \
  -shared \
  -I/lina_android/fart-los21/native/include \
  -o out/lib64/libfart-hook.so \
  hook_entry.cpp config.cpp dex_dump.cpp codeitem_dump.cpp \
  active_invoke.cpp art_resolver.cpp \
  -ldl -llog
```

### 11.5 部署模块到设备

#### 11.5.1 推送编译产物

```bash
ADB="adb -H 192.168.238.1 -P 5037"

# 推送 Zygisk 加载器
$ADB push out/zygisk/arm64-v8a.so /data/adb/modules/fart-los21/zygisk/arm64-v8a.so

# 推送 Hook 核心库到模块目录
$ADB push out/lib64/libfart-hook.so /data/adb/modules/fart-los21/lib64/libfart-hook.so

# 推送 Hook 核心库到运行时目录（service.sh 会每 2 秒从模块目录复制）
$ADB push out/lib64/libfart-hook.so /data/local/tmp/fart/libfart-hook.so
```

> **坑 #3：service.sh 覆盖 SO 文件**
> 模块的 `service.sh` 每 2 秒从 `/data/adb/modules/fart-los21/lib64/` 复制 `libfart-hook.so` 到 `/data/local/tmp/fart/`。如果你只推送了 `/data/local/tmp/fart/` 的 SO，2 秒后就会被旧版本覆盖！
>
> **解决方案**：必须同时更新两个位置的 SO 文件：
> ```bash
> # 两个位置都要推！
> $ADB push out/lib64/libfart-hook.so /data/adb/modules/fart-los21/lib64/libfart-hook.so
> $ADB push out/lib64/libfart-hook.so /data/local/tmp/fart/libfart-hook.so
> ```
>
> 验证 MD5 是否一致：
> ```bash
> $ADB shell md5sum /data/adb/modules/fart-los21/lib64/libfart-hook.so
> $ADB shell md5sum /data/local/tmp/fart/libfart-hook.so
> # 两个 MD5 必须相同
> ```

#### 11.5.2 配置 nohook 模式

创建配置文件 `/tmp/fart_config.json`：

```json
{
  "enable": true,
  "packages": ["com.funshion.video.mobile"],
  "dump_dir": "/data/local/tmp/fart_dump",
  "dump_dex": false,
  "enable_artmethod_hook": false,
  "dump_dex_delay_ms": 500
}
```

**关键配置说明**：

| 字段 | 值 | 含义 |
|------|---|------|
| `dump_dex` | `false` | 不使用 DefineClass hook dump DEX（避免被检测） |
| `enable_artmethod_hook` | `false` | 不安装 ArtMethod::Invoke hook（避免被检测） |
| `dump_dex_delay_ms` | `500` | > 0 即触发 nohook 模式（具体值不重要） |

**nohook 模式触发条件**：`dump_dex == false && dump_dex_delay_ms > 0`

推送配置到设备：

```bash
# 先写本地文件再 adb push（避免 shell 转义问题）
cat > /tmp/fart_config.json << 'EOF'
{"enable":true,"packages":["com.funshion.video.mobile"],"dump_dir":"/data/local/tmp/fart_dump","dump_dex":false,"enable_artmethod_hook":false,"dump_dex_delay_ms":500}
EOF

$ADB push /tmp/fart_config.json /data/adb/modules/fart-los21/config/config.json
$ADB push /tmp/fart_config.json /data/local/tmp/fart/config.json
```

> **坑 #4：JSON 配置 shell 转义问题**
> 不要用 `adb shell echo '...' > /path/config.json` 写入 JSON，shell 会破坏引号。正确做法是先写本地文件再 `adb push`。

#### 11.5.3 重启设备使 Zygisk 模块生效

```bash
$ADB reboot

# 等待设备重启完成（约 60 秒）
sleep 60

# 确认模块已加载
$ADB shell cat /proc/1/maps | grep fart
```

### 11.6 启动目标 App 并验证

#### 11.6.1 启动风行视频

```bash
# 先 force-stop 确保 app 从头启动
$ADB shell am force-stop com.funshion.video.mobile

# 启动 app
$ADB shell am start -n com.funshion.video.mobile/.mobile.MainActivity
```

#### 11.6.2 检查日志

```bash
# 过滤 FART 日志
$ADB logcat -s FART_LOS21

# 期望看到以下关键日志：
# FART_LOS21: postAppSpecialize pid=XXXX
# FART_LOS21: pkg=com.funshion.video.mobile
# FART_LOS21: dlopen OK (nohook=1)
# FART_LOS21: No-hook mode (sync): dump_dex_delay_ms=500, skipping all native hooks
# FART_LOS21: No-hook sync: starting immediate DEX scan (pid=XXXX)
# FART_LOS21: DumpDexFromMaps: found 0 DEX regions    ← 正常！DEX 还没加载
# FART_LOS21: No-hook sync: all dumps complete, safe to dlclose
# FART_LOS21: nohook: dlclose hook lib to hide from packer detection
```

#### 11.6.3 确认 App 正常启动

```bash
# 检查 app 进程是否存活
$ADB shell pidof com.funshion.video.mobile
# 应返回一个 PID（如 3827）

# 如果返回空，说明 app 崩溃了，查看崩溃日志
$ADB logcat -s FART_LOS21 AndroidRuntime
```

> **坑 #5：邦邦加固检测到 SO 导致崩溃**
> 如果 nohook 模式或 dlclose 策略有 bug，邦邦加固的 `UniverseSecNo2` 模块会检测到 `libfart-hook.so` 在 `/proc/self/maps` 中，触发 `[hit] No6` 告警，app 会立即崩溃。
>
> **排查方法**：
> ```bash
> # 查看 maps 中是否有 fart 相关条目
> $ADB shell cat /proc/<PID>/maps | grep fart
> # 如果 dlclose 成功，应该看不到 libfart-hook.so
> ```

### 11.7 nohook 模式核心代码解析

#### 11.7.1 Zygisk 加载器 (zygisk_loader.cpp)

加载器在 `postAppSpecialize` 回调中执行以下流程：

```cpp
void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
    // 1. 获取包名
    // 2. 读取配置，检查包名白名单
    // 3. 判断是否 nohook 模式
    bool nohook = isNohookMode(json);  // dump_dex=false && dump_dex_delay_ms > 0

    // 4. dlopen 加载 hook SO
    void *h = dlopen(kHookLib, RTLD_NOW);

    // 5. 调用初始化函数
    FartInit_t init = (FartInit_t)dlsym(h, "fart_on_app_specialize");
    init(env_local, pkg, "/data/adb/modules/fart-los21");

    // 6. nohook 模式：dlclose 卸载 SO（关键！）
    if (nohook) {
        dlclose(h);  // 在邦邦加固安全检查前移除 SO
    }
}
```

**dlclose 的时机**：`fart_on_app_specialize()` 返回后立即 `dlclose`，此时邦邦加固的 `UniverseSecNo2` 还没开始运行。

#### 11.7.2 Hook 核心 (hook_entry.cpp) nohook 分支

```cpp
void fart_on_app_specialize(JNIEnv* env, const char* package_name, const char* module_path) {
    // ... 配置加载、目录创建 ...

    if (g_config.dump_dex_delay_ms > 0 && !g_config.dump_dex) {
        LOGI("No-hook mode (sync): skipping all native hooks");

        // 关键：不初始化 DexDumper！
        // DexDumper::Init() 会启动 worker 线程，持有对 SO 代码的引用
        // 导致 dlclose 无法真正卸载 SO

        // 直接同步扫描 /proc/self/maps 中的 DEX 区域
        DumpDexFromMaps(true /* sync */);

        LOGI("No-hook sync: all dumps complete, safe to dlclose");
        return;  // 跳过所有 hook 安装
    }

    // ... 正常模式的 hook 安装 ...
}
```

> **坑 #6：DexDumper worker 线程阻止 dlclose 卸载 SO**
> `DexDumper::Init()` 会启动一个后台 worker 线程来异步写 DEX 文件。这个线程的代码在 `libfart-hook.so` 中，线程运行时持有对 SO 代码段的引用。`dlclose` 只减少引用计数，如果引用计数 > 0 就不会真正卸载 SO。
>
> **症状**：`dlclose` 后，`/proc/self/maps` 中仍然能看到 `libfart-hook.so`，邦邦加固仍然检测到。
>
> **解决方案**：nohook 模式不初始化 DexDumper，改用 `WriteDexSync()` 同步写文件，不启动 worker 线程。

#### 11.7.3 SafeMemRead — 安全内存读取

```cpp
// 通过 pread 读取 /proc/self/mem，避免直接内存访问导致的 SIGBUS/SIGSEGV
static size_t SafeMemRead(uintptr_t addr, void* buf, size_t size) {
    int fd = open("/proc/self/mem", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = pread(fd, buf, size, (off_t)addr);
    close(fd);
    return (n > 0) ? (size_t)n : 0;
}
```

> **坑 #7：直接内存访问导致 SIGBUS**
> 在 `DumpDexFromMaps` 中使用 `memcmp`/`memcpy` 直接访问内存，而邦邦加固正在同时修改同一内存页（解密 DEX），会导致 `SIGBUS` (signal 7, BUS_ADRERR)。
>
> **原因**：当进程尝试访问正在被 packer 修改（mprotect 等）的内存页时，CPU 会触发总线错误。
>
> **解决方案**：使用 `pread` 从 `/proc/self/mem` 读取，内核会处理页面映射，不会触发 SIGBUS。

#### 11.7.4 WriteDexSync — 同步写 DEX 文件

```cpp
static void WriteDexSync(const uint8_t* begin, uint32_t size, const char* filename) {
    uint8_t* copy = (uint8_t*)malloc(size);

    // 优先使用 SafeMemRead（通过 /proc/self/mem）
    size_t copied = SafeMemRead((uintptr_t)begin, copy, size);

    if (copied == 0) {
        // Fallback: 直接 memcpy + 页面跳过
        // 对每个 64KB 块检查是否可读，不可读则填零跳过
        const uint8_t* ptr = begin;
        while (copied < size) {
            size_t chunk = size - copied;
            if (chunk > 65536) chunk = 65536;
            if (IsRangeReadable(ptr, chunk)) {
                memcpy(copy + copied, ptr, chunk);
                copied += chunk; ptr += chunk;
            } else {
                memset(copy + copied, 0, 4096);
                copied += 4096; ptr += 4096;
            }
        }
    }

    // 同步写文件
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(fd, copy, copied);
    close(fd);
    free(copy);
}
```

> **坑 #8：usleep 阻塞 postAppSpecialize 导致 SIGSEGV**
> 最初尝试在 nohook 模式中使用 `usleep(500000)` 延迟 500ms，等待 DEX 加载后再扫描。但在 `postAppSpecialize` 回调中阻塞会导致 SIGSEGV 崩溃：
>
> ```
> Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000136700
> pc=0x136700, x17=0x136700  (PLT 调用未映射地址)
> ```
>
> **原因**：Zygisk 的 `postAppSpecialize` 回调在 Zygote fork 后的子进程中执行。ART 运行时对此回调有特殊要求，阻塞会导致 PLT 调用跳转到未映射地址。
>
> **解决方案**：移除 usleep，改为立即扫描。虽然此时 DEX 还没加载（0 个 DEX），但 dlclose 可以成功卸载 SO，app 可以正常启动。DEX 的 dump 改用外部进程方案。

### 11.8 外部进程 DEX 扫描方案

由于 nohook 模式在 `postAppSpecialize` 时扫描太早（DEX 尚未加载），我们使用外部 root 进程在 app 运行后扫描其内存。

#### 11.8.1 编译 dex_scanner 工具

创建 `/tmp/dex_scanner.c`：

```c
// dex_scanner.c - Scan /proc/<pid>/mem for DEX files and dump them
// Build: aarch64-linux-android34-clang -O2 -static -o dex_scanner dex_scanner.c
// Usage: dex_scanner <pid> [output_dir]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static const uint8_t kDexMagic[] = {0x64, 0x65, 0x78, 0x0a}; // "dex\n"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid> [output_dir]\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    const char* out_dir = argc > 2 ? argv[2] : "/data/local/tmp/fart_dump";

    char maps_path[64], mem_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    mkdir(out_dir, 0777);

    FILE* mfp = fopen(maps_path, "r");
    if (!mfp) {
        fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
        return 1;
    }

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
        fclose(mfp);
        return 1;
    }

    printf("Scanning PID=%d for DEX files...\n", pid);

    char line[512];
    int dex_count = 0;
    uint8_t buf[4096];

    while (fgets(line, sizeof(line), mfp)) {
        uintptr_t start, end;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (perms[0] != 'r') continue;

        size_t region_size = end - start;
        if (region_size < 64 || region_size > 0x20000000) continue;

        // 逐页扫描 DEX magic
        for (uintptr_t addr = start; addr < end; addr += 4096) {
            ssize_t n = pread(mem_fd, buf, sizeof(buf), (off_t)addr);
            if (n < 64) continue;

            for (int i = 0; i <= n - 4; i++) {
                if (memcmp(buf + i, kDexMagic, 4) != 0) continue;

                uintptr_t dex_addr = addr + i;

                // 读取 DEX header 获取 size
                uint32_t dex_size = 0;
                if (i + 0x24 <= n) {
                    dex_size = *(uint32_t*)(buf + i + 0x20);
                } else {
                    uint8_t hdr[64];
                    pread(mem_fd, hdr, 64, (off_t)dex_addr);
                    memcpy(&dex_size, hdr + 0x20, 4);
                }

                if (dex_size < 64 || dex_size > 0x10000000) continue;

                dex_count++;
                printf("Found DEX #%d at 0x%lx size=%u\n",
                       dex_count, (unsigned long)dex_addr, dex_size);

                // Dump DEX 到文件
                char outfile[512];
                snprintf(outfile, sizeof(outfile),
                         "%s/dex_ext_%d_%d.dex", out_dir, pid, dex_count);

                uint8_t* dex_data = (uint8_t*)malloc(dex_size);
                ssize_t read_total = 0;
                while (read_total < (ssize_t)dex_size) {
                    ssize_t r = pread(mem_fd, dex_data + read_total,
                                      dex_size - read_total,
                                      (off_t)(dex_addr + read_total));
                    if (r <= 0) break;
                    read_total += r;
                }

                if (read_total > 0) {
                    int fd = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                    if (fd >= 0) {
                        write(fd, dex_data, read_total);
                        close(fd);
                        printf("Dumped: %s (%zd bytes)\n", outfile, read_total);
                    }
                }
                free(dex_data);

                // 跳过已处理的 DEX 数据
                i += (dex_size > 4096 ? 4096 : dex_size);
            }
        }
    }

    close(mem_fd);
    fclose(mfp);
    printf("Done. Found %d DEX files in %s\n", dex_count, out_dir);
    return 0;
}
```

编译并部署：

```bash
# 静态编译（不依赖设备上的动态库）
/lina_android/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -o /tmp/dex_scanner /tmp/dex_scanner.c

# 推送到设备
adb -H 192.168.238.1 -P 5037 push /tmp/dex_scanner /data/local/tmp/dex_scanner

# 添加执行权限
adb -H 192.168.238.1 -P 5037 shell chmod +x /data/local/tmp/dex_scanner
```

> **坑 #9：dex_scanner 权限不足**
> `adb shell` 默认不是 root，无法读取其他进程的 `/proc/<pid>/mem`。
>
> **解决方案**：使用 `adb root` 重启 adbd 为 root 模式：
> ```bash
> adb -H 192.168.238.1 -P 5037 root
> adb -H 192.168.238.1 -P 5037 shell id
> # 应输出: uid=0(root)
> ```

#### 11.8.2 运行 dex_scanner

```bash
# 1. 确认风行视频正在运行
adb -H 192.168.238.1 -P 5037 shell pidof com.funshion.video.mobile
# 输出 PID，如 3827

# 2. 创建输出目录
adb -H 192.168.238.1 -P 5037 shell mkdir -p /data/local/tmp/fart_dump

# 3. 运行 dex_scanner
adb -H 192.168.238.1 -P 5037 shell /data/local/tmp/dex_scanner 3827 /data/local/tmp/fart_dump

# 期望输出：
# Scanning PID=3827 for DEX files...
# Found DEX #1 at 0x... size=...
# Found DEX #2 at 0x... size=...
# ...
# Found DEX #73 at 0x... size=...
# Done. Found 73 DEX files in /data/local/tmp/fart_dump
```

> **坑 #10：SELinux 阻止 app 写入 dump 目录**
> nohook 模式在 app 进程内运行，dump 目录如果是 `/data/local/tmp/fart_dump`（`shell_data_file` 上下文），app 进程（`untrusted_app` 上下文）无法写入：
>
> ```
> avc: denied { write } for name="fart_dump" ... tcontext=u:object_r:shell_data_file:s0
> ```
>
> **解决方案**：外部 `dex_scanner` 以 root 运行，不受 SELinux 限制。nohook 模式在 app 进程内的 dump 会失败（0 DEX），但外部进程方案绕过了此问题。

### 11.9 拉取 DEX 文件并验证

#### 11.9.1 拉取 DEX 到本地

```bash
# 拉取所有 dump 的 DEX 文件
mkdir -p /lina_android/fart_dump
adb -H 192.168.238.1 -P 5037 pull /data/local/tmp/fart_dump/ /lina_android/fart_dump/

# 查看文件列表和大小
ls -lhS /lina_android/fart_dump/fart_dump/*.dex | head -20
```

#### 11.9.2 用 jadx 验证脱壳结果

```bash
# 对最大的 DEX 文件（通常是主 DEX）运行 jadx
jadx -d /tmp/jadx_out /lina_android/fart_dump/fart_dump/dex_ext_3827_7.dex --no-res

# 检查是否包含目标 App 的业务逻辑代码
find /tmp/jadx_out -name "*.java" | grep -i funshion | head -20

# 查看关键类
cat /tmp/jadx_out/sources/com/funshion/video/mobile/MainActivity.java
cat /tmp/jadx_out/sources/com/funshion/video/ad/FSAdImpl.java
```

#### 11.9.3 验证结果判断标准

| jadx 输出 | 含义 | 脱壳状态 |
|-----------|------|---------|
| 完整的 Java 方法体，包含业务逻辑 | 脱壳成功 | 成功 |
| 方法体只有 `throw new RuntimeException("stub")` | 壳 DEX，未脱壳 | 失败 |
| `Load failed! No classes for decompile!` | DEX 头部损坏 | 部分成功 |
| 类名混淆为 a/b/c 但有完整逻辑 | ProGuard 混淆，脱壳成功 | 成功 |

### 11.10 DEX 文件分析

#### 11.10.1 DEX 格式识别

```bash
# 检查 DEX 文件头部的版本号
xxd <dex_file> | head -1

# dex\n035 = 标准 DEX (StandardDex)
# dex\n038 = Android 8+ DEX
# dex\n039 = CompactDex (ART 内部优化格式)
```

| 格式 | jadx 支持 | 说明 |
|------|----------|------|
| `dex\n035` | 是 | 标准 DEX，最常见 |
| `dex\n038` | 是 | Android 8+ 新增特性 |
| `dex\n039` | 部分 | CompactDex，ART 内部格式，部分 jadx 版本不支持 |

#### 11.10.2 筛选业务逻辑 DEX

73 个 DEX 中大部分是框架/库 DEX，需要筛选出包含目标 App 业务逻辑的 DEX：

```bash
# 搜索包含目标包名的 DEX 文件
for f in /lina_android/fart_dump/fart_dump/dex_ext_*.dex; do
    count=$(strings "$f" 2>/dev/null | grep -ci "com.funshion");
    if [ "$count" -gt 0 ]; then
        echo "$(basename $f): $count funshion refs";
    fi
done

# 输出示例：
# dex_ext_3827_5.dex: 617 funshion refs   ← 主 DEX（但头部损坏）
# dex_ext_3827_7.dex: 600 funshion refs   ← 核心 DEX（jadx 可解析）
# dex_ext_3827_10.dex: 617 funshion refs  ← 与 #5 重复
# dex_ext_3827_6.dex: 3 funshion refs     ← 仅引用
# dex_ext_3827_8.dex: 14 funshion refs    ← 仅引用
```

#### 11.10.3 DEX 头部损坏问题

**现象**：26MB 的 DEX 文件（dex_ext_3827_5.dex）包含 617 个风行引用，但 jadx 报 `No classes for decompile!`。

**原因**：邦邦加固在内存中加载真实 DEX 时，可能覆盖了原始壳 DEX 的内存区域。DEX 头部保留的是壳 DEX 的元数据（3 个 class_defs, 154 个 string_ids），但数据区包含真实 App 的代码。

```bash
# 检查 DEX 头部
xxd dex_ext_3827_5.dex | head -5
# offset 0x38: string_ids_size = 0x9A (154) — 太少了！26MB 的 DEX 不可能只有 154 个字符串
# offset 0x60: class_defs_size = 0x03 (3)    — 只有 3 个类定义！
# 但数据区有 617 个 funshion 引用

# 对比正常 DEX
xxd dex_ext_3827_7.dex | head -5
# 有正确的 class_defs_size 和 string_ids_size
```

**解决方案**：头部损坏的 DEX 无法直接用 jadx 解析。需要：
1. 使用头部完好的 DEX（如 #7）作为主要分析对象
2. 或尝试从 CompactDex (039) 格式的 DEX 中提取代码
3. 或编写工具重建 DEX 头部（高级，暂未实现）

### 11.11 完整操作流程速查表

```text
步骤 1: 编译
  cd /lina_android/fart-los21/native && make clean && make

步骤 2: 部署
  adb push out/zygisk/arm64-v8a.so /data/adb/modules/fart-los21/zygisk/
  adb push out/lib64/libfart-hook.so /data/adb/modules/fart-los21/lib64/
  adb push out/lib64/libfart-hook.so /data/local/tmp/fart/

步骤 3: 配置 nohook 模式
  echo '{"enable":true,"packages":["<目标包名>"],"dump_dir":"/data/local/tmp/fart_dump","dump_dex":false,"enable_artmethod_hook":false,"dump_dex_delay_ms":500}' > /tmp/fart_config.json
  adb push /tmp/fart_config.json /data/adb/modules/fart-los21/config/config.json
  adb push /tmp/fart_config.json /data/local/tmp/fart/config.json

步骤 4: 重启
  adb reboot && sleep 60

步骤 5: 启动目标 App
  adb shell am force-stop <目标包名>
  adb shell am start -n <目标包名>/.<主Activity>

步骤 6: 获取 PID
  adb shell pidof <目标包名>

步骤 7: 外部扫描 DEX
  adb root
  adb shell /data/local/tmp/dex_scanner <PID> /data/local/tmp/fart_dump

步骤 8: 拉取并验证
  adb pull /data/local/tmp/fart_dump/ ./fart_dump/
  jadx -d /tmp/jadx_out ./fart_dump/fart_dump/dex_ext_<PID>_7.dex --no-res
  find /tmp/jadx_out -name "*.java" | grep -i <目标关键字>
```

### 11.12 问题排查手册

#### 问题：App 启动后立即崩溃

```bash
# 查看崩溃日志
adb logcat -s FART_LOS21 AndroidRuntime DEBUG

# 常见原因 1：邦邦加固检测到 SO
# 日志特征：UniverseSecNo2 [hit] No6
# 解决：确认 nohook 模式配置正确，dlclose 生效

# 常见原因 2：SIGSEGV in postAppSpecialize
# 日志特征：Fatal signal 11, pc=0x136700
# 解决：确认没有在 postAppSpecialize 中使用 usleep

# 常见原因 3：SIGBUS in DumpDexFromMaps
# 日志特征：Fatal signal 7, BUS_ADRERR
# 解决：确认使用 SafeMemRead 而非直接 memcmp/memcpy
```

#### 问题：dlclose 后 SO 仍在 maps 中

```bash
# 检查 maps
adb shell cat /proc/<PID>/maps | grep fart

# 原因：DexDumper worker 线程持有 SO 引用
# 解决：确认 nohook 模式不初始化 DexDumper
# 检查代码：hook_entry.cpp 中 nohook 分支不应调用 DexDumper::Init()
```

#### 问题：dex_scanner 找到 0 个 DEX

```bash
# 确认 app 正在运行
adb shell pidof <目标包名>

# 确认 root 权限
adb shell id

# 确认 app 已完全启动（等待 5-10 秒后再扫描）
sleep 10 && adb shell /data/local/tmp/dex_scanner <PID>
```

#### 问题：jadx 无法加载 DEX

```bash
# 检查 DEX 头部
xxd <dex_file> | head -5

# 如果 class_defs_size 很小（如 3）但文件很大，说明头部损坏
# 尝试其他 DEX 文件

# 如果是 CompactDex (039)，尝试更新版本的 jadx
jadx --version  # 需要 1.5.0+
```

### 11.13 技术原理总结

#### 为什么 nohook + dlclose + 外部扫描能绕过邦邦加固？

```
时间线：
  T0: Zygote fork → 子进程创建
  T1: postAppSpecialize 回调执行
      → dlopen libfart-hook.so
      → fart_on_app_specialize() 执行
        → nohook 模式：扫描 maps（0 DEX，太早了）
        → 不启动 DexDumper worker 线程
        → 返回
      → dlclose libfart-hook.so  ← SO 从 maps 中消失
  T2: ART 继续初始化 app
  T3: 邦邦加固 libkadp.so 加载
      → 解密真实 DEX 到内存
      → 替换 ClassLoader
  T4: 邦邦加固安全检查启动
      → UniverseSecNo2 扫描 /proc/self/maps
      → 找不到 libfart-hook.so ✓  ← dlclose 已移除
      → 找不到 inline hook ✓      ← nohook 模式没装 hook
      → 检查通过，app 正常运行
  T5: 外部 dex_scanner 以 root 身份读取 /proc/<PID>/mem
      → 扫描已解密的 DEX 区域
      → dump 到文件
      → 成功脱壳！
```

#### 关键设计决策

| 决策 | 原因 | 替代方案 |
|------|------|---------|
| 不安装任何 native hook | 邦邦加固检测 inline hook | 修改 hook 检测逻辑（更复杂） |
| dlclose 卸载 SO | 邦邦加固扫描 maps 中的可疑 SO | 修改 SO 文件名（不够隐蔽） |
| 不启动 DexDumper worker | worker 线程阻止 dlclose | 等 worker 完成后 dlclose（时机不可控） |
| 不使用 usleep 延迟 | 阻塞 postAppSpecialize 导致 SIGSEGV | 用新线程延迟（但 ART 未初始化完成） |
| 外部进程扫描 | 绕过 SELinux 和时机问题 | 在 app 进程内延迟扫描（需 hook） |
| SafeMemRead via pread | 避免直接内存访问导致 SIGBUS | 信号处理器 + sigsetjmp（更复杂） |

---

## 十二、Git 历史摘要

```text
1272b44  fix: remove maps-based DEX truncation, use EFAULT skip
4fcf0cd  add hard validation + improve carrier matching
c265663  P7.3: add tools/repair_apk.py
9e8fa68  P7.2: add --session-pid filter
2dbb8ea  P7.1: fix report_coverage.py statistics
6b72831  P6.1: add report_coverage.py
f9cfb0d  P6.2: add active_load_classes
9ecb94e  repair v3: add --carrier-dex
36e62ff  repair v2: add dex_key, CodeRecord
5e7a3f5  add dex_key to CodeItemDumpTask
a238978  P5: add LoadMethod hook
f0206f0  P3: fix Invoke signature, codeitem improvements
3d459b3  P0: move semantics, config fixes; P1: active_invoke
5642cbd  fix: force-stop via service.sh
0c179fa  fix: remove stats check on export
cea85a2  fix: revert hook lib path to /data/local/tmp/fart/
16fda20  fix: use full path /system/bin/kp
c18f050  fix: writeConfig via base64
500802a  fix: base64 writeConfig
b41cfdd  feat: customizable su command
eefc434  refactor: simplify controller UI
4d6a711  fix: replace dx with d8
71a1e91  fix: aapt2 from local SDK
529f71a  feat: add FartController, rewrite README

Tags:
  v0.2-coverage-safe-load
  v0.1-fart-pipeline-mvp
```
