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
| **DexFile Dump** | Hook `DefineClass`，拦截新加载的 dex 并 dump 到文件 |
| **已加载 DEX 快照** | 通过 Java 反射枚举 `BaseDexClassLoader` 中的已加载 dex 文件 |
| **CodeItem Dump** | Hook `ArtMethod::Invoke`，采样时提取方法的 CodeItem 元数据 |
| **内存映射感知** | 通过 `/proc/self/maps` 检测实际可读区域，防止写超出映射范围 |
| **FartController** | Android 可视化控制器 App，一键允许/关闭脱壳 |
| **自动导出** | service.sh 自动搬运 DEX 文件到 `/sdcard/FART-LOS21/<包名>/` |
| **SHA256 去重** | 自动导出时通过 hash 去重，避免重复文件 |

---

## 目录结构

```text
fart-los21/
├── FartController/           # Android 可视化控制器 App
│   ├── app/src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/fartlos21/controller/
│   │   │   ├── MainActivity.java    # 主界面 + 应用列表 + 配置生成
│   │   │   └── RootShell.java       # 本地文件操作 + 状态管理
│   │   └── res/values/strings.xml
│   ├── build.sh              # 一键编译脚本
│   ├── build_simple.py       # 二进制 AXML 生成器（备用）
│   └── build/                # 编译输出（gitignore）
├── module/                   # APatch/Zygisk 模块元数据
│   ├── module.prop
│   ├── service.sh            # 后台守护：配置搬运 + 心跳 + 自动导出
│   ├── customize.sh
│   ├── sepolicy.rule
│   ├── zygisk/arm64-v8a.so   # Zygisk 加载器
│   └── lib64/libfart-hook.so # Hook 核心库
├── config/                   # 默认 config.json
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
- Android SDK（aapt2、d8、android.jar）

---

## 安装指南

### 1. 构建 Native Hook 模块

```bash
cd fart-los21/native
make clean && make -j4
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
adb -H <设备IP> -P 5037 push fart-los21-module.zip /data/local/tmp/
adb -H <设备IP> -P 5037 shell kp -c "apd module install /data/local/tmp/fart-los21-module.zip"

# 设置 system linker 模式（必须！否则模块不会注入）
adb -H <设备IP> -P 5037 shell kp -c "znctl linker system"

# 重启
adb -H <设备IP> -P 5037 reboot
```

### 4. 构建并安装 FartController

```bash
cd fart-los21/FartController
bash build.sh
adb -H <设备IP> -P 5037 install -t FartController/build/FARTController.apk
```

---

## FartController 使用说明

### 主界面

打开名为 **FART控制器** 的 App：

| 控件 | 说明 |
|------|------|
| **模块状态** | 显示 ✓ 已安装 或 ✗ 未检测到 |
| **选择目标应用** | 弹出列表，选择要脱壳的非系统应用 |
| **允许脱壳** | 一键写入配置，service.sh 自动 force-stop 目标应用 |
| **关闭脱壳** | 恢复目标应用正常启动 |
| **统计** | 显示当前 Dex / CodeItem 文件计数 |
| **导出 DEX** | 手动触发导出到 `/sdcard/FART-LOS21/<包名>/` |
| **自动导出** | 文件稳定后自动复制到 sdcard |

### 工作流程

```text
FartController 点"允许脱壳"
  ├─ 写入 config.json 到 /data/data/.../files/
  ├─ 写入 .launch_trigger 到 /data/data/.../files/
  └─ Toast 提示"已停止，重新打开即可自动脱壳"

service.sh（每 2 秒轮询）
  ├─ 检测到 config.json → 复制到模块目录 + /data/local/tmp/fart/
  ├─ 检测到 .launch_trigger → am force-stop 目标应用
  └─ 检测到 .export_trigger → SHA256 去重复制到 /sdcard/

用户手动打开目标应用
  └─ 全新进程 → Zygisk 注入 → hook DefineClass → dump DEX
```

### 使用步骤

1. 打开 **FART控制器**
2. 点 **选择目标应用** → 选一个非系统 app
3. 点 **允许脱壳** → 等待 toast
4. 等 2-3 秒让 service.sh 完成配置搬运 + force-stop
5. 从桌面**手动打开**目标应用
6. 等待 dex 文件生成（统计数字会增加）
7. 点 **导出 DEX** 或等自动导出
8. 到 `/sdcard/FART-LOS21/<包名>/` 取文件

---

## 架构说明

### 配置桥接

App 进程由于 Android 14 mount namespace 隔离，无法访问 `/system/bin/kp` 和 `/data/adb/modules/`。因此采用 **service.sh 桥接**模式：

```text
App 写 /data/data/.../files/config.json
         │
         ▼ service.sh 每 2 秒轮询（以 root 运行）
         │
         ▼
  复制到 /data/adb/modules/fart-los21/config/config.json  (模块目录)
  复制到 /data/local/tmp/fart/config.json                  (loader 备用路径)
```

### DEX 写入保护

Android 14 ART 可能对 DEX 文件进行 mmap 映射，此时 header 中的 `file_size` 可能大于实际映射范围。hook 在写入前扫描 `/proc/self/maps`，取实际可读区域大小进行写入，避免文件截断。

### SELinux

Hook 库 `libfart-hook.so` 需要 `system_lib_file` 的 SELinux context 才能被 app 进程 `dlopen`。service.sh 在每次启动时执行 `chcon` 确保 context 正确。

---

## 故障排除

| 问题 | 检查点 |
|------|--------|
| 模块状态显示未安装 | 确认已执行 `znctl linker system` 并重启 |
| 点击允许脱壳后 app 闪退 | 检查 logcat: `adb logcat -d | grep FART_LOS21` |
| 没有 dump 文件 | 确认已手动打开目标应用（非桌面缓存恢复） |
| DEX 文件无法用 jadx 打开 | 确认已更新最新 hook lib（含 maps 截断保护） |
| dlopen permission denied | 检查 SELinux context: `ls -laZ /data/local/tmp/fart/libfart-hook.so` |
| 导出提示"未发现 dump 文件" | 文件可能已被 auto-export 搬走，直接去 sdcard 目录检查 |
| 黑屏/循环重启 | `adb shell kp -c "touch /data/adb/modules/fart-los21/disable"` 再重启 |

---

## License

本项目仅供学习研究使用。请遵守当地法律法规。

**FART-LOS21** — ART layer DEX dumping research for Android 14 / LineageOS 21.
