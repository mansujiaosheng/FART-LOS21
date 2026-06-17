# Stage 2.4 质量验收报告

## 测试环境
- 目标设备: OnePlus 9 (lemonade), LineageOS 21 / Android 14
- 测试应用: infosecadventures.allsafe (debuggable)
- 框架状态: enable_artmethod_hook=true, enable_codeitem_dump=true, sample_rate=1

## 验收结果

| 测试项 | 结果 | 说明 |
|--------|------|------|
| Config 解析 | ✅ | `codeitem_dump=1, max_dumps=500` 正确解析 |
| CodeItemDumper 初始化 | ✅ | `dir=/data/local/tmp/fart_dump max_dumps=500` |
| Worker 线程 | ✅ | `CodeItemDumper worker started` |
| methods/ 目录 | ✅ | 已创建 `method_index.csv` (53 bytes, header 行) |
| DefineClass dump | ✅ | 正常运行，继续生成 dex 文件 |
| **ArtMethod::Invoke 触发** | **❌** | **正常 app 启动/交互期间从未触发** |
| CodeItem .code 文件 | **❌** | 因 Invoke 未触发，无数据写入 |

## 核心发现

`ArtMethod::Invoke` 在 Android 14 ART 中的调用条件：

| 调用方式 | 是否触发 ArtMethod::Invoke | 说明 |
|----------|--------------------------|------|
| 普通 Java method 调用 | ❌ | 走 JIT/AOT 编译代码，直接通过 entry_point 跳转 |
| Activity 启动/触摸事件 | ❌ | 同上，编译代码路径 |
| Method.invoke() 反射 | ✅ | 唯一触发路径 |
| JNI CallXMethod 系列 | ✅ | JNI 调用 |
| 解释器执行 | ✅ | 仅 debug/强制解释模式 |

## 测试验证记录

1. **Allsafe 正常启动** (am start): 0 次 Invoke 调用
2. **monkey 随机事件** (100/500 events): 0 次 Invoke 调用
3. **Broadcast 发送** (PROCESS_NOTE): 0 次 Invoke 调用
4. **风行视频启动** (com.funshion.video.mobile): 0 次 Invoke 调用
5. **dalvikvm 直接运行**: 进程不经过 Zygisk 注入，无法测试

## 结论

**Stage 2.4 框架（管道）是完全正确的**——配置解析、Dumper 初始化、Worker 线程、目录创建、CSV 写入均已验证通过。

**但数据源 `ArtMethod::Invoke` 在正常 app 执行中不触发**，这是 ART 架构的固有特性，不是框架 bug。正常 Java 方法调用通过 JIT/AOT 编译代码直接执行，`ArtMethod::Invoke` 仅在反射/JNI 入口被调用。

## 建议下一步方向

| 方案 | 工作量 | 覆盖范围 | 风险 |
|------|--------|---------|------|
| 1. Hook `art_quick_invoke_stub` (汇编层) | 中 | 所有 compiled method | 中（汇编兼容性） |
| 2. Hook `instrumentation::GetCodeForInvoke` | 低 | instrumentation 路径 | 低 |
| 3. **修改 Config: 添加反射触发** | **低** | **控制流** | **低** |
| 4. 主动枚举 class + 反射触发 | 中 | 全量 dump | 低 |

**建议方案 3**：在 fart_on_app_specialize 或某个 JNI 回调中，直接通过 JNI 调用 `Class.forName().getDeclaredMethods()` + `Method.invoke()` 主动触发目标 class 的 method，从而走 `ArtMethod::Invoke` 路径。
