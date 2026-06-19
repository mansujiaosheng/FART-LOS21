# LineageOS 21 / Android 14 ART 源码参考文档

> 基于 `/lina_android/lineage/art/` 源码整理
> 目标平台: ARM64, Android 14 / LineageOS 21
> 最后更新: 2026-06-18

---

## 目录

1. [源码文件索引](#1-源码文件索引)
2. [类加载调用链](#2-类加载调用链)
3. [ClassLinker 核心方法](#3-classlinker-核心方法)
4. [ArtMethod 布局与关键方法](#4-artmethod-布局与关键方法)
5. [DexFile C++ 运行时对象布局](#5-dexfile-c-运行时对象布局)
6. [DEX On-Disk 结构](#6-dex-on-disk-结构)
7. [CodeItem 结构与大小计算](#7-codeitem-结构与大小计算)
8. [CompactDex 差异](#8-compactdex-差异)
9. [mirror::Class 布局](#9-mirrorclass-布局)
10. [访问标志定义](#10-访问标志定义)
11. [Hook 开发速查](#11-hook-开发速查)

---

## 1. 源码文件索引

### Runtime 层

| 文件 | 内容 |
|------|------|
| `runtime/class_linker.h` | ClassLinker 类声明，所有类加载方法 |
| `runtime/class_linker.cc` | ClassLinker 实现（DefineClass, LoadMethod, FindClass 等） |
| `runtime/art_method.h` | ArtMethod 类声明，字段布局，访问器 |
| `runtime/art_method.cc` | ArtMethod::Invoke 实现 |
| `runtime/art_method-inl.h` | GetCodeItem(), HasCodeItem() 内联实现 |
| `runtime/gc_root.h` | GcRoot 模板，CompressedReference |
| `runtime/mirror/class.h` | mirror::Class 声明，字段偏移 |
| `runtime/mirror/object_reference.h` | CompressedReference, ObjectReference 基类 |

### libdexfile 层

| 文件 | 内容 |
|------|------|
| `libdexfile/dex/dex_file.h` | DexFile 类声明，Header，字段偏移 |
| `libdexfile/dex/dex_file.cc` | DexFile 构造函数，初始化逻辑 |
| `libdexfile/dex/dex_file_structs.h` | 所有 on-disk 原始结构体（ClassDef, MethodId, CodeItem 空基类等） |
| `libdexfile/dex/dex_file_types.h` | 索引类型（StringIndex, TypeIndex, ProtoIndex） |
| `libdexfile/dex/standard_dex_file.h` | StandardDexFile::CodeItem 布局 |
| `libdexfile/dex/compact_dex_file.h` | CompactDexFile::CodeItem 布局，PreHeader 机制 |
| `libdexfile/dex/code_item_accessors.h` | 三级 CodeItem 访问器 |
| `libdexfile/dex/code_item_accessors-inl.h` | CodeItemDataEnd() 大小计算核心逻辑 |
| `libdexfile/dex/class_accessor.h` | ClassAccessor，替代旧 ClassDataItemIterator |
| `libdexfile/dex/dex_file-inl.h` | GetTryItems/GetCatchHandlerData 定位逻辑 |
| `libdexfile/dex/dex_file_exception_helpers.cc` | CatchHandlerIterator 解码 |
| `libdexfile/dex/modifiers.h` | 访问标志常量定义 |

### 工具层

| 文件 | 内容 |
|------|------|
| `dexlayout/dex_writer.cc` | StandardDex CodeItem 写入逻辑 |
| `dexlayout/compact_dex_writer.cc` | CompactDex CodeItem 写入逻辑 |
| `dexdump/dexdump.cc` | DEX 文件 dump 工具 |

---

## 2. 类加载调用链

```
FindClass(self, descriptor, class_loader)
  |
  +-> LookupClass()                          // 查找已加载类
  |     +-> EnsureResolved()                 // 若已存在
  |
  +-> [Boot ClassLoader 路径]
  |     FindInClassPath() -> DefineClass()
  |
  +-> [App ClassLoader 路径]
        FindClassInBaseDexClassLoader()
          +-> FindClassInBootClassLoaderClassPath() -> DefineClass()
          +-> FindClassInBaseDexClassLoaderClassPath() -> DefineClass()
          +-> FindClassInSharedLibraries()
          +-> ClassLoader.loadClass()        // Java 回调

DefineClass(self, descriptor, hash, class_loader, dex_file, dex_class_def)
  |
  +-> AllocClass()                           // 分配 Class 对象
  +-> ClassPreDefine 回调
  +-> RegisterDexFile()                      // 注册 DexCache
  +-> SetupClass()                           // 设置基础字段，状态 -> kIdx
  +-> InsertClass()                          // 插入类表
  +-> LoadClass()                            // 加载字段和方法
  |     |
  |     +-> LoadField()                      // 加载字段
  |     +-> LoadMethod()                     // 加载方法元数据 ★
  |     +-> LinkCode()                       // 设置方法入口点 ★
  |
  +-> LoadSuperAndInterfaces()               // 状态 -> kLoaded
  +-> ClassLoad 回调
  +-> LinkClass()                            // 状态 -> kResolved
  +-> ClassPrepare 回调
  +-> 返回已链接的 Class 对象
```

**关键**: `LoadMethod` + `LinkCode` 在 `LoadClass` 内部对每个方法依次调用。`LinkCode` 是静态函数（非成员方法），无导出符号。

---

## 3. ClassLinker 核心方法

### 3.1 DefineClass

```cpp
// class_linker.h:232  |  class_linker.cc:3392
ObjPtr<mirror::Class> ClassLinker::DefineClass(
    Thread* self,
    const char* descriptor,                    // "Lcom/example/MyClass;"
    size_t hash,
    Handle<mirror::ClassLoader> class_loader,
    const DexFile& dex_file,                   // ★ 包含 DEX 数据
    const dex::ClassDef& dex_class_def)        // ★ 类定义条目
    REQUIRES_SHARED(Locks::mutator_lock_)
    REQUIRES(!Locks::dex_lock_);
```

**Mangled 符号**:
```
_ZN3art12ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE
```

**设备偏移**: `0x2c4930`（从 libart_device.so readelf 获取）

**Hook 可获取的参数**:
- `dex_file_ptr` (第5参数): DexFile 对象指针，可读取 `begin_`(offset 0x08) 获取 DEX 内存基地址
- `dex_class_def` (第6参数): ClassDef 条目

### 3.2 LoadMethod

```cpp
// class_linker.h:1031  |  class_linker.cc:3940
void ClassLinker::LoadMethod(
    const DexFile& dex_file,
    const ClassAccessor::Method& method,
    ObjPtr<mirror::Class> klass,
    ArtMethod* dst)                            // ★ 已分配的目标方法
    REQUIRES_SHARED(Locks::mututer_lock_);
```

**Mangled 符号**:
```
_ZN3art12ClassLinker10LoadMethodERKNS_7DexFileERKNS_13ClassAccessor6MethodENS_6ObjPtrINS_6mirror5ClassEEPNS_9ArtMethodE
```

**设备偏移**: `0x2d4510`

**关键行为**:
- 普通方法: `dst->SetCodeItem(dex_file.GetCodeItem(code_item_offset), is_compact_dex_code_item)`
- Native 方法: `dst->SetDataPtrSize(nullptr, image_pointer_size_)`
- Abstract 方法: `dst->SetDataPtrSize(nullptr, image_pointer_size_)`

**Hook 可获取的参数**:
- `dst` (第4参数): ArtMethod 指针，hook 后可读取 `data_`(offset 0x10) 获取 CodeItem 指针
- `dex_file` (第1参数): 可读取 dex_key 用于多 DEX 区分

### 3.3 LinkCode

```cpp
// class_linker.cc:3698
static void LinkCode(
    ClassLinker* class_linker,
    ArtMethod* method,
    const OatFile::OatClass* oat_class,
    uint32_t class_def_method_index)
    REQUIRES_SHARED(Locks::mutater_lock_);
```

**注意**: 这是文件作用域的**静态函数**，不是 ClassLinker 成员方法，无导出符号。需要通过 offset 寻址。

**关键行为**:
1. AOT 编译器直接返回: `if (runtime->IsAotCompiler()) return;`
2. 设置方法入口点: `InitializeMethodsCode(method, quick_code)`
3. Native 方法: 设置 JNI dlsym lookup 桩函数

### 3.4 FindClass

```cpp
// class_linker.cc:3167
ObjPtr<mirror::Class> ClassLinker::FindClass(
    Thread* self,
    const char* descriptor,
    Handle<mirror::ClassLoader> class_loader)
    REQUIRES_SHARED(Locks::mutater_lock_)
    REQUIRES(!Locks::dex_lock_);
```

### 3.5 SetupClass

```cpp
// class_linker.cc:3735
void ClassLinker::SetupClass(
    const DexFile& dex_file,
    const dex::ClassDef& dex_class_def,
    Handle<mirror::Class> klass,
    ObjPtr<mirror::ClassLoader> class_loader)
    REQUIRES_SHARED(Locks::mutater_lock_);
```

---

## 4. ArtMethod 布局与关键方法

### 4.1 字段布局 (ARM64, PointerSize::k64)

```
offset 0x00: declaring_class_              GcRoot<mirror::Class>     4 bytes  (压缩引用)
offset 0x04: access_flags_                 std::atomic<uint32_t>     4 bytes
offset 0x08: dex_method_index_             uint32_t                  4 bytes
offset 0x0C: method_index_                 uint16_t                  2 bytes
offset 0x0E: hotness_count_/imt_index_     uint16_t (union)          2 bytes
offset 0x10: ptr_sized_fields_.data_       void*                     8 bytes
offset 0x18: entry_point_from_quick_compiled_code_  void*            8 bytes
                                                          总计: 0x20 = 32 bytes
```

**偏移计算**:
```cpp
PtrSizedFieldsOffset = RoundUp(0x0E + 2, 8) = 0x10
Size = 0x10 + (16/8)*8 = 0x20
```

### 4.2 data_ 字段含义（按方法类型）

| 方法类型 | data_ 含义 |
|----------|-----------|
| Native | JNI 函数指针或 JNI 解析函数指针 |
| Resolution | 方法解析函数 + @CriticalNative JNI 函数 |
| Conflict | `ImtConflictTable*` |
| Abstract/接口 | 单实现的 `ArtMethod*` (可能为 null) |
| Proxy | 原始接口方法或构造器的 `ArtMethod*` |
| 普通方法 (AOT) | CodeItem 在 DEX 文件中的偏移量 (uint32_t) |
| **普通方法 (运行时)** | **CodeItem\* 指针** (最低位为 compact_dex 标志) |

### 4.3 GetCodeItem() 实现

```cpp
// art_method-inl.h:457-467
inline const dex::CodeItem* ArtMethod::GetCodeItem() {
    if (!HasCodeItem()) return nullptr;
    Runtime* runtime = Runtime::Current();
    PointerSize pointer_size = runtime->GetClassLinker()->GetImagePointerSize();
    return runtime->IsAotCompiler()
        ? GetDexFile()->GetCodeItem(reinterpret32<uint32_t>(GetDataPtrSize(pointer_size)))
        : reinterpret_cast<const dex::CodeItem*>(
            reinterpret_cast<uintptr_t>(GetDataPtrSize(pointer_size)) & ~1);
}
```

**运行时读取 CodeItem 的方式**:
```cpp
uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);       // 读取 data_ 字段
const uint8_t* ci = (const uint8_t*)(data_ptr & ~1ULL);    // 清除 bit0 (compact_dex 标志)
```

### 4.4 SetCodeItem() 实现

```cpp
// art_method.cc:922-929
void ArtMethod::SetCodeItem(const dex::CodeItem* code_item, bool is_compact_dex_code_item) {
    uintptr_t data = reinterpret_cast<uintptr_t>(code_item) | (is_compact_dex_code_item ? 1 : 0);
    SetDataPtrSize(reinterpret_cast<void*>(data), kRuntimePointerSize);
}
```

### 4.5 HasCodeItem() 实现

```cpp
// art_method.h:873-880
bool HasCodeItem() {
    uint32_t access_flags = GetAccessFlags();
    return !IsNative(access_flags) &&
           !IsAbstract(access_flags) &&
           !IsDefaultConflicting(access_flags) &&
           !IsRuntimeMethod() &&
           !IsProxyMethod();
}
```

### 4.6 ArtMethod::Invoke 签名

```cpp
// art_method.h:676  |  art_method.cc:364
NO_STACK_PROTECTOR
void ArtMethod::Invoke(
    Thread* self,
    uint32_t* args,
    uint32_t args_size,
    JValue* result,
    const char* shorty)
    REQUIRES_SHARED(Locks::mutater_lock_);
```

**Mangled 符号**:
```
_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc
```

**设备偏移**: `0x340da0`

**Invoke 执行路径**:
1. 栈溢出检查
2. 运行时未启动 / 强制解释执行 -> `interpreter::EnterInterpreterFromInvoke`
3. 有 quick_code -> `art_quick_invoke_stub` / `art_quick_invoke_static_stub`
4. 无 quick_code -> `art_quick_to_interpreter_bridge`

**重要**: 正常编译代码不经过 `ArtMethod::Invoke`，只有反射/JNI/解释器路径才触发。

---

## 5. DexFile C++ 运行时对象布局

### 5.1 字段偏移 (ARM64)

```
offset 0x00: vtable ptr                           8 bytes
offset 0x08: begin_                const uint8_t*  8 bytes   ← DEX 数据基地址
offset 0x10: unused_size_          size_t          8 bytes
offset 0x18: data_                 ArrayRef        16 bytes  (指针+长度)
offset 0x28: location_             std::string     24 bytes  (SSO)
offset 0x40: location_checksum_    uint32_t        4 bytes
offset 0x44: (padding)                             4 bytes
offset 0x48: header_               const Header*   8 bytes   ← 指向 on-disk Header
offset 0x50: string_ids_           const StringId* 8 bytes
offset 0x58: type_ids_             const TypeId*   8 bytes
offset 0x60: field_ids_            const FieldId*  8 bytes
offset 0x68: method_ids_           const MethodId* 8 bytes
offset 0x70: proto_ids_            const ProtoId*  8 bytes
offset 0x78: class_defs_           const ClassDef* 8 bytes
offset 0x80: method_handles_       const MethodHandleItem* 8 bytes
offset 0x88: num_method_handles_   size_t          8 bytes
offset 0x90: call_site_ids_        const CallSiteIdItem* 8 bytes
offset 0x98: num_call_site_ids_    size_t          8 bytes
offset 0xA0: hiddenapi_class_data_ const HiddenapiClassData* 8 bytes
offset 0xA8: oat_dex_file_         const OatDexFile* (mutable) 8 bytes
offset 0xB0: container_            shared_ptr<DexFileContainer> 16 bytes
offset 0xC0: is_compact_dex_       const bool      1 byte
offset 0xC1: hiddenapi_domain_     Domain (mutable) 1 byte
```

**关键读取方式**:
```cpp
// 清除 ARM64 TBI 标签
uintptr_t obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFFULL;
// 读取 begin_ (DEX 内存基地址)
const uint8_t* begin = *(const uint8_t**)(obj + 0x08);
// 读取 header_ (on-disk Header 指针)
const void* header = *(const void**)(obj + 0x48);
// 读取 is_compact_dex_
bool is_compact = *(const bool*)(obj + 0xC0);
```

---

## 6. DEX On-Disk 结构

### 6.1 Header (0x70 = 112 bytes)

```
offset 0x00: magic_              uint8_t[8]    "dex\n035" / "dex\n039" / "cdex001"
offset 0x08: checksum_           uint32_t      Adler32 校验和
offset 0x0C: signature_          uint8_t[20]   SHA-1 签名
offset 0x20: file_size_          uint32_t      整个文件大小
offset 0x24: header_size_        uint32_t      头部大小 (标准=0x70, V41=0x78)
offset 0x28: endian_tag_         uint32_t      0x12345678
offset 0x2C: link_size_          uint32_t      (未使用)
offset 0x30: link_off_           uint32_t      (未使用)
offset 0x34: map_off_            uint32_t      MapList 偏移
offset 0x38: string_ids_size_    uint32_t
offset 0x3C: string_ids_off_     uint32_t
offset 0x40: type_ids_size_      uint32_t
offset 0x44: type_ids_off_       uint32_t
offset 0x48: proto_ids_size_     uint32_t
offset 0x4C: proto_ids_off_      uint32_t
offset 0x50: field_ids_size_     uint32_t
offset 0x54: field_ids_off_      uint32_t
offset 0x58: method_ids_size_    uint32_t
offset 0x5C: method_ids_off_     uint32_t
offset 0x60: class_defs_size_    uint32_t
offset 0x64: class_defs_off_     uint32_t
offset 0x68: data_size_          uint32_t
offset 0x6C: data_off_           uint32_t
```

### 6.2 HeaderV41 扩展 (0x78 = 120 bytes)

```
offset 0x70: container_size_     uint32_t      容器总大小
offset 0x74: header_offset_      uint32_t      此 DEX 头部在容器中的偏移
```

### 6.3 ClassDef (0x20 = 32 bytes)

```
offset 0x00: class_idx_          TypeIndex (uint16_t)   类的类型索引
offset 0x02: pad1_               uint16_t              = 0
offset 0x04: access_flags_       uint32_t              访问标志
offset 0x08: superclass_idx_     TypeIndex (uint16_t)  父类类型索引
offset 0x0A: pad2_               uint16_t              = 0
offset 0x0C: interfaces_off_     uint32_t              TypeList 偏移
offset 0x10: source_file_idx_    StringIndex (uint32_t) 源文件名索引
offset 0x14: annotations_off_    uint32_t              annotations_directory_item 偏移
offset 0x18: class_data_off_     uint32_t              class_data_item 偏移
offset 0x1C: static_values_off_  uint32_t              EncodedArray 偏移
```

### 6.4 MethodId (0x08 = 8 bytes)

```
offset 0x00: class_idx_          TypeIndex (uint16_t)   定义类的类型索引
offset 0x02: proto_idx_          ProtoIndex (uint16_t)  方法原型索引
offset 0x04: name_idx_           StringIndex (uint32_t) 方法名索引
```

### 6.5 FieldId (0x08 = 8 bytes)

```
offset 0x00: class_idx_          TypeIndex (uint16_t)   定义类的类型索引
offset 0x02: type_idx_           TypeIndex (uint16_t)   字段类型索引
offset 0x04: name_idx_           StringIndex (uint32_t) 字段名索引
```

### 6.6 ProtoId (0x0C = 12 bytes)

```
offset 0x00: shorty_idx_         StringIndex (uint32_t) 短描述符索引
offset 0x04: return_type_idx_    TypeIndex (uint16_t)   返回类型索引
offset 0x06: pad_                uint16_t              = 0
offset 0x08: parameters_off_     uint32_t              参数类型列表偏移
```

### 6.7 其他结构

| 结构 | 大小 | 说明 |
|------|------|------|
| StringId | 4 bytes | `string_data_off_` (uint32_t) |
| TypeId | 4 bytes | `descriptor_idx_` (uint32_t) |
| TryItem | 8 bytes | `start_addr_(4) + insn_count_(2) + handler_off_(2)` |
| MapItem | 12 bytes | `type_(2) + unused_(2) + size_(4) + offset_(4)` |
| MapList | 4+ bytes | `size_(4) + list_[](12*N)` |
| MethodHandleItem | 8 bytes | `method_handle_type_(2) + reserved1_(2) + field_or_method_idx_(2) + reserved2_(2)` |
| CallSiteIdItem | 4 bytes | `data_off_` (uint32_t) |

---

## 7. CodeItem 结构与大小计算

### 7.1 StandardDexFile::CodeItem

```
offset 0x00: registers_size_              uint16_t    2 bytes
offset 0x02: ins_size_                    uint16_t    2 bytes
offset 0x04: outs_size_                   uint16_t    2 bytes
offset 0x06: tries_size_                  uint16_t    2 bytes
offset 0x08: debug_info_off_              uint32_t    4 bytes
offset 0x0C: insns_size_in_code_units_    uint32_t    4 bytes
offset 0x10: insns_[1]                    uint16_t[]  变长
--- 后续 (tries_size > 0 时) ---
[padding]                                  0~2 bytes  (4字节对齐填充)
[try_items_0 ... try_items_M-1]           8*M bytes
[encoded_catch_handler_data]              变长 (LEB128)
```

**固定头部大小**: 0x10 = 16 字节
**对齐**: 4 字节

### 7.2 大小计算公式 (StandardDexFile)

```
header_size = 16
insns_bytes = insns_size_in_code_units * 2

if tries_size == 0:
  total = header_size + insns_bytes
else:
  padding = RoundUp(insns_bytes, 4) - insns_bytes
  try_items_bytes = tries_size * 8
  catch_handler_data_bytes = (需逐个解析 LEB128)
  total = header_size + insns_bytes + padding + try_items_bytes + catch_handler_data_bytes
```

### 7.3 CatchHandler 编码格式

```
[ULEB128 handlers_size]
对于每个 handler:
  [SLEB128 count]             // 正数=类型handler数; 负数=类型handler数+catch_all
  对于每个类型 handler:
    [ULEB128 type_idx]
    [ULEB128 address]
  如果有 catch_all (count为负时):
    [ULEB128 address]         // 无 type_idx
```

### 7.4 CodeItemDataEnd() 核心逻辑

```cpp
// code_item_accessors-inl.h:149-168
const void* CodeItemDataAccessor::CodeItemDataEnd() const {
  const uint8_t* handler_data = GetCatchHandlerData();
  if (TriesSize() == 0 || handler_data == nullptr) {
    return &end().Inst();  // insns_ + insns_size_in_code_units_
  }
  const uint32_t handlers_size = DecodeUnsignedLeb128(&handler_data);
  for (uint32_t i = 0; i < handlers_size; ++i) {
    int32_t uleb128_count = DecodeSignedLeb128(&handler_data) * 2;
    if (uleb128_count <= 0) {
      uleb128_count = -uleb128_count + 1;
    }
    for (int32_t j = 0; j < uleb128_count; ++j) {
      DecodeUnsignedLeb128(&handler_data);
    }
  }
  return reinterpret_cast<const void*>(handler_data);
}
```

---

## 8. CompactDex 差异

### 8.1 CompactDexFile::CodeItem

```
offset 0x00: fields_                  uint16_t    2 bytes  [regs:4|ins:4|outs:4|tries:4]
offset 0x02: insns_count_and_flags_   uint16_t    2 bytes  [5位标志|11位insns_size]
offset 0x04: insns_[1]                uint16_t[]  变长
```

**固定头部大小**: 0x04 = 4 字节
**对齐**: 2 字节

### 8.2 fields_ 位域

```
bits [15:12] = registers_size (低4位, 实际值 = 解码值 + ins_size)
bits [11:8]  = ins_size (低4位)
bits [7:4]   = outs_size (低4位)
bits [3:0]   = tries_size (低4位)
```

### 8.3 insns_count_and_flags_ 位域

```
bits [15:5] = insns_size_in_code_units (低11位, 最大 2047)
bit 4       = kFlagPreHeaderInsnsSize
bit 3       = kFlagPreHeaderTriesSize
bit 2       = kFlagPreHeaderOutsSize
bit 1       = kFlagPreHeaderInsSize
bit 0       = kFlagPreHeaderRegistersSize
```

### 8.4 PreHeader 机制

当字段值超过 4 位/11 位范围时，在 CodeItem **之前**（低地址方向）插入最多 6 个 uint16_t 的扩展值。解码时从 CodeItem 地址向低地址回溯读取。

### 8.5 CompactDex vs StandardDex 对比

| 特性 | StandardDex | CompactDex |
|------|-------------|------------|
| Magic | `dex\n` | `cdex` |
| 版本 | 035/037/038/039/040/041 | 001 |
| CodeItem 头部 | 16 字节 | 4 字节 + 可选 preheader |
| debug_info_off | 内嵌 CodeItem | 外部 CompactOffsetTable |
| 字段存储 | 独立 uint16_t | 4 位打包 + preheader |
| insns_size | 独立 uint32_t | 11 位内嵌 + preheader |
| CodeItem 对齐 | 4 字节 | 2 字节 |
| 生成方式 | dx/d8 编译器 | dex2oat 运行时优化 (vdex 内) |
| 用途 | APK 内 .dex 文件 | ART 内部优化格式 (vdex/odex) |

### 8.6 CompactDex Header 扩展字段

```
offset 0x70: feature_flags_                      uint32_t
offset 0x74: debug_info_offsets_pos_              uint32_t
offset 0x78: debug_info_offsets_table_offset_     uint32_t
offset 0x7C: debug_info_base_                     uint32_t
offset 0x80: owned_data_begin_                    uint32_t
offset 0x84: owned_data_end_                      uint32_t
```

---

## 9. mirror::Class 布局

继承自 mirror::Object (klass_ 4B + monitor_ 4B = 8B):

```
offset 0x08: class_loader_        HeapReference<ClassLoader>   4 bytes
offset 0x0C: component_type_     HeapReference<Class>         4 bytes
offset 0x10: dex_cache_          HeapReference<DexCache>      4 bytes
offset 0x14: ext_data_           HeapReference<ClassExt>      4 bytes
offset 0x18: iftable_            HeapReference<IfTable>       4 bytes
offset 0x1C: name_               HeapReference<String>        4 bytes
offset 0x20: super_class_        HeapReference<Class>         4 bytes
offset 0x24: vtable_             HeapReference<PointerArray>  4 bytes
offset 0x28: ifields_            uint64_t (压缩指针对)        8 bytes
offset 0x30: methods_            uint64_t (压缩指针对)        8 bytes
offset 0x38: sfields_            uint64_t (压缩指针对)        8 bytes
offset 0x40: access_flags_       uint32_t                     4 bytes
offset 0x44: class_flags_        uint32_t                     4 bytes
offset 0x48: class_size_         uint32_t                     4 bytes
offset 0x4C: clinit_thread_id_   pid_t (int32_t)              4 bytes
offset 0x50: dex_class_def_idx_  int32_t                      4 bytes
offset 0x54: dex_type_idx_       int32_t                      4 bytes
offset 0x58: num_reference_instance_fields_  uint32_t         4 bytes
offset 0x5C: num_reference_static_fields_    uint32_t         4 bytes
offset 0x60: object_size_        uint32_t                     4 bytes
offset 0x64: object_size_alloc_fast_path_    uint32_t         4 bytes
offset 0x68: primitive_type_     uint32_t                     4 bytes
offset 0x6C: reference_instance_offsets_     uint32_t         4 bytes
offset 0x70: status_             uint32_t (含 ClassStatus)    4 bytes
offset 0x74: copied_methods_offset_  uint16_t                 2 bytes
offset 0x76: virtual_methods_offset_  uint16_t                 2 bytes
--- 之后是嵌入式 IMT、VTable、静态字段 ---
```

**status_ 字段**: 高 4 位存储 ClassStatus 枚举值，读取方式: `field_value >> (32 - 4)`

---

## 10. 访问标志定义

### 10.1 Java 规范标志 (低 16 位)

| 标志 | 值 | 适用范围 |
|------|-----|---------|
| kAccPublic | 0x0001 | class, field, method, ic |
| kAccPrivate | 0x0002 | field, method, ic |
| kAccProtected | 0x0004 | field, method, ic |
| kAccStatic | 0x0008 | field, method, ic |
| kAccFinal | 0x0010 | class, field, method, ic |
| kAccSynchronized | 0x0020 | method (仅 native) |
| kAccBridge | 0x0040 | method |
| kAccVarargs | 0x0080 | method |
| **kAccNative** | **0x0100** | method |
| kAccInterface | 0x0200 | class, ic |
| **kAccAbstract** | **0x0400** | class, method, ic |
| kAccStrict | 0x0800 | method |
| kAccSynthetic | 0x1000 | class, field, method, ic |
| kAccAnnotation | 0x2000 | class, ic |
| kAccEnum | 0x4000 | class, field, ic |

### 10.2 运行时扩展标志 (高 16 位)

| 标志 | 值 | 说明 |
|------|-----|------|
| kAccConstructor | 0x00010000 | `<init>` / `<clinit>` |
| kAccFastNative | 0x00080000 | 快速 Native |
| kAccCriticalNative | 0x00100000 | 关键 Native |
| kAccSingleImplementation | 0x08000000 | 单实现 |
| kAccPublicApi | 0x10000000 | 公开 API |
| kAccCorePlatformApi | 0x20000000 | 核心平台 API |

### 10.3 Hook 过滤常用

```cpp
// 无 CodeItem 的方法
kAccNative    = 0x0100    // Native 方法
kAccAbstract  = 0x0400    // 抽象方法

// 运行时方法标识
kRuntimeMethodDexMethodIndex = 0xFFFFFFFF  // dex_method_index_ 值
```

---

## 11. Hook 开发速查

### 11.1 从 DefineClass 获取 DEX 数据

```cpp
// DefineClassHook 的 dex_file_ptr 参数
uintptr_t obj = (uintptr_t)dex_file_ptr & 0x00FFFFFFFFFFFFFFULL;
const uint8_t* begin = *(const uint8_t**)(obj + 0x08);  // begin_
// 验证
if (memcmp(begin, "dex\n", 4) != 0) return result;
uint32_t file_size = *(const uint32_t*)(begin + 0x20);  // header->file_size_
if (file_size < 64 || file_size > 0x20000000) return result;
if (!IsRangeReadable(begin, file_size)) return result;
// dump
```

### 11.2 从 LoadMethod 获取 CodeItem

```cpp
// LoadMethodHook 的 dst (ArtMethod*) 参数
uintptr_t m = (uintptr_t)art_method & 0x00FFFFFFFFFFFFFFULL;
uint32_t access_flags = *(const uint32_t*)(m + 0x04);
uint32_t dex_idx = *(const uint32_t*)(m + 0x08);
// 过滤
if (dex_idx == 0xFFFFFFFF) return;  // runtime method
if (access_flags & 0x0100) return;  // native
if (access_flags & 0x0400) return;  // abstract
// 读取 CodeItem
uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);
const uint8_t* ci = (const uint8_t*)(data_ptr & ~1ULL);
if (!ci || !IsRangeReadable(ci, 16)) return;
// 解析 StandardDexFile::CodeItem
uint16_t regs = *(const uint16_t*)(ci + 0x00);
uint16_t ins  = *(const uint16_t*)(ci + 0x02);
uint16_t outs = *(const uint16_t*)(ci + 0x04);
uint16_t tries = *(const uint16_t*)(ci + 0x06);
uint32_t insns_size = *(const uint32_t*)(ci + 0x0C);
```

### 11.3 区分 StandardDex vs CompactDex

```cpp
// 方法1: 检查 DexFile::is_compact_dex_ 字段
bool is_compact = *(const bool*)(dex_file_obj + 0xC0);

// 方法2: 检查 DEX magic
const uint8_t* begin = *(const uint8_t**)(dex_file_obj + 0x08);
bool is_compact = (memcmp(begin, "cdex", 4) == 0);

// 方法3: 检查 ArtMethod data_ 的 bit0
uintptr_t data_ptr = *(const uintptr_t*)(m + 0x10);
bool is_compact_dex_code_item = (data_ptr & 1);
```

### 11.4 libart 符号解析顺序

```cpp
// 1. dlsym (设备 libart 可能 strip)
void* addr = dlsym(RTLD_DEFAULT, mangled_symbol);

// 2. 已知偏移 fallback
if (!addr) addr = resolver->ResolveByOffset(known_offset);

// 3. 偏移计算
// file_base = executable_segment_start - segment_file_offset
// target_address = file_base + symbol_file_offset
```

### 11.5 已确认的设备偏移 (OnePlus 9 / LineageOS 21)

| 符号 | 偏移 | Mangled Name |
|------|------|-------------|
| DefineClass | 0x2c4930 | `_ZN3art12ClassLinker11DefineClassE...` |
| LoadMethod | 0x2d4510 | `_ZN3art12ClassLinker10LoadMethodE...` |
| ArtMethod::Invoke | 0x340da0 | `_ZN3art9ArtMethod6InvokeE...` |
| LinkCode | 需从 readelf 查找 | 静态函数，无导出符号 |
