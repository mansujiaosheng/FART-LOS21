# FART-LOS21

**FART-LOS21** 是一个面向 **Android 14 / LineageOS 21** 的 ART 层 DexFile / CodeItem dump 与 dex repair 研究项目。

基于 APatch + ZygiskNext 注入 Zygisk 模块，通过 inline hook 拦截 ART `ClassLinker::DefineClass`，在应用运行时将内存中的 DEX 字节码同步 dump 到文件系统。

---

## 法律声明 / Disclaimer

本项目**仅限**用于：
- 自写样本 / 自研 App 的脱壳测试
- 授权安全测试 / 渗透测试靶场
- Android Runtime 内部原理学习与研究
- CTF 竞赛

**严禁**用于：
- 未授权商业 App 的脱壳、逆向工程
- 绕过版权保护或数字版权管理（DRM）
- 恶意软件分析或未授权的安全评估

使用者须自行承担全部法律责任。项目作者不对任何滥用行为负责。

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **Dex Only** | Hook `DefineClass`，拦截新加载的 dex 并 dump 到文件 |
| **已加载 DEX 快照** | 通过 Java 反射枚举 `BaseDexClassLoader` 中的已加载 dex 文件 |
| **CodeItem Dump** | Hook `ArtMethod::Invoke`，采样时提取方法的 CodeItem 元数据 |
| **Active Invoke** | JNI 反射方式主动调用目标方法，触发 CodeItem 解析 |
| **FartController** | Android 可视化控制器 App，三种模式一键切换 |

---

## 目录结构

```text
fart-los21/
├── FartController/           # Android 可视化控制器 App
│   ├── app/src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/fartlos21/controller/
│   │   │   ├── MainActivity.java    # 主界面 + 应用列表 + 配置生成
│   │   │   └── RootShell.java       # kp root 命令 + 文件操作
│   │   └── res/values/strings.xml
│   ├── build.sh              # 一键编译脚本
│   ├── build_simple.py       # 二进制 AXML 生成器
│   └── build/                # 编译输出（gitignore）
├── module/                   # APatch/Zygisk 模块元数据
├── config/                   # 运行时 config.json
├── native/                   # Native hook 核心源码
│   ├── include/              # C++ 头文件
│   ├── zygisk_loader.cpp     # Zygisk 加载器（最小 STL 依赖）
│   ├── hook_entry.cpp        # Hook 核心：DefineClass + ArtMethod::Invoke
│   ├── config.cpp            # Minimal JSON 解析
│   ├── art_resolver.cpp      # libart 符号解析器
│   ├── dex_dump.cpp          # DEX 校验 / SHA256 / 写入
│   ├── codeitem_dump.cpp     # CodeItem 被动/主动 dump
│   └── active_invoke.cpp     # JNI 反射主动调用引擎
├── scripts/                  # 构建/安装/调试脚本
├── docs/                     # 技术文档
└── libart_device.so          # 设备 libart.so（符号分析用）
```

---

## 环境要求

### 设备端
- **设备**：OnePlus 9 (`lemonade`)
- **系统**：Android 14 / LineageOS 21
- **Root**：APatch
- **Zygisk**：ZygiskNext（必须使用 **system linker 模式**）

### 构建端（Linux）
- NDK r27（`/lina_android/android-ndk-r27`）
- Java 8+（javac、keytool）
- Python 3
- `aapt2`（Android SDK build-tools，可选，用于资源编译）
- `apksigner`（LineageOS 预置或 Android SDK）

---

## 安装指南

### 1. 构建 Native Hook 模块

```bash
cd fart-los21/native
make clean && make -j4
make zygisk
```

输出：
- `native/out/zygisk/arm64-v8a.so` — Zygisk 加载器
- `native/out/lib64/libfart-hook.so` — Hook 核心库

### 2. 打包 APatch 模块

```bash
cd fart-los21
scripts/package_module.sh
```

生成 `fart-los21-module.zip`。

### 3. 安装模块

```bash
# 推送模块
adb push fart-los21-module.zip /data/local/tmp/
adb push config/config.json /data/local/tmp/

# APatch 安装
adb shell 'kp -c "apd module install /data/local/tmp/fart-los21-module.zip"'

# 安装 ZygiskNext
adb push ZygiskNext-*.zip /data/local/tmp/
adb shell 'kp -c "apd module install /data/local/tmp/ZygiskNext-*.zip"'

# 初始化 dump 目录
adb shell 'kp -c "mkdir -p /data/local/tmp/fart /data/local/tmp/fart_dump"'
adb shell 'kp -c "chmod 777 /data/local/tmp/fart /data/local/tmp/fart_dump"'
adb shell 'kp -c "chcon u:object_r:system_lib_file:s0 /data/local/tmp/fart/libfart-hook.so"'
adb shell 'kp -c "chcon u:object_r:app_data_file:s0 /data/local/tmp/fart_dump"'

# 设置 system linker 模式
adb shell 'kp -c "znctl linker system"'

# 重启
adb reboot
```

### 4. 构建并安装 FartController

```bash
cd fart-los21/FartController
bash build.sh
```

输出 `FartController/build/FARTController.apk`（约 13KB），然后：

```bash
adb install -t FartController/build/FARTController.apk
```

> **注意**：如果 `adb install` 报 `INSTALL_FAILED_NO_MATCHING_ABIS`，请确保编译环境有 Java 8+ 且 `aapt2`/`dx` 路径正确。

---

## FartController 使用说明

### 主界面

打开名为 **FART控制器** 的 App，界面包含：

| 控件 | 说明 |
|------|------|
| **模块状态** | 显示 ✓ 已安装 或 ✗ 未找到 |
| **刷新** | 重新检测模块状态和 dump 统计 |
| **选择应用** | 弹出列表，选择目标非系统应用 |
| **模式选择** | Dex Only / CodeItem / Active Invoke |
| **写入并启动** | 生成 config.json → 写入模块目录 → force-stop → monkey 启动 |
| **统计** | 显示 Dex / JSON / Code 文件计数 |
| **导出到 /sdcard** | 将 dump 文件复制到 `/sdcard/FART-LOS21/<包名>/` |

### 三种模式详解

#### Dex Only
- Hook `DefineClass` 拦截新加载的 dex
- 不启用 `ArtMethod::Invoke` hook
- 适合快速验证和基础 dex dump

#### CodeItem
- 启用 `DefineClass` + `ArtMethod::Invoke` 双 hook
- `ArtMethod::Invoke` 以 1:100 采样率记录方法调用
- 提取 CodeItem 元数据（registers_size、ins_size、outs_size、tries_size、insns_size）
- 将 CodeItem 二进制数据写入 `methods/*.code` 目录

#### Active Invoke
- 在以上基础上启用**主动调用引擎**
- 通过 JNI 反射方式主动调用目标类构造方法
- 可选：设置目标类名（每行一个）、最大方法数、延迟
- 勾选「跳过执行」可以在 dump 后不实际执行方法体
- 适合深度修复场景（类方法需要被调用才能加载 CodeItem）

### 测试示例

```bash
# 清理旧 dump
adb shell 'kp -c "rm -f /data/local/tmp/fart_dump/*.dex"'
adb shell 'kp -c "logcat -c"'

# 打开 FartController → 选择应用 → Dex Only → 写入并启动

# 查看日志
adb logcat -d | grep FART_LOS21

# 拉取 dump 文件
adb shell 'kp -c "cp /data/local/tmp/fart_dump/*.dex /data/local/tmp/ && chmod 644 /data/local/tmp/*.dex"'
adb pull /data/local/tmp/dex_*.dex ./

# 反编译
jadx dex_*.dex -d output/
```

---

## 配置文件格式

模块通过 `config/config.json` 控制行为。FartController 会自动生成此文件，也可手动编辑：

```json
{
  "enable": true,
  "packages": ["com.example.target"],
  "dump_dir": "/data/local/tmp/fart_dump",
  "dump_dex": true,
  "enable_artmethod_hook": false,
  "artmethod_sample_rate": 1000,
  "enable_codeitem_dump": false,
  "max_codeitem_dumps": 500,
  "enable_active_invoke": false,
  "active_invoke_delay_ms": 1500,
  "active_invoke_max_methods": 200,
  "active_invoke_skip_execute": true,
  "active_invoke_classes": []
}
```

---

## 故障排除

| 问题 | 检查点 |
|------|--------|
| 模块状态显示未安装 | `adb shell kp -c "ls /data/adb/modules/fart-los21/"` |
| 没有 dump 文件 | 检查 logcat: `adb logcat -d | grep FART_LOS21` |
| 应用崩溃 | `scripts/collect_crashlog.sh`，禁用模块后排查 |
| FartController 无法写入配置 | 确认 `kp` root 命令可用: `adb shell kp -c "id"` |
| 黑屏/循环重启 | `adb shell kp -c "touch /data/adb/modules/fart-los21/disable"` 再重启 |

---

## License

本项目仅供学习研究使用。请遵守当地法律法规。

**FART-LOS21** — ART layer DEX dumping research for Android 14 / LineageOS 21.
