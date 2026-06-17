# FART-LOS21 native build Makefile

NDK_PATH   ?= /lina_android/android-ndk-r27
TOOLCHAIN  := $(NDK_PATH)/toolchains/llvm/prebuilt/linux-x86_64
CC         := $(TOOLCHAIN)/bin/aarch64-linux-android34-clang
CXX        := $(TOOLCHAIN)/bin/aarch64-linux-android34-clang++
STRIP      := $(TOOLCHAIN)/bin/llvm-strip
SYSROOT    := $(TOOLCHAIN)/sysroot

OUT_DIR    := out
ZYGISK_SO  := $(OUT_DIR)/zygisk/arm64-v8a.so
HOOK_SO    := $(OUT_DIR)/lib64/libfart-hook.so
TEST_SO    := $(OUT_DIR)/test/arm64-v8a.so

# ---- Zygisk loader ----
LOADER_SRC := zygisk_loader.cpp
LOADER_OBJ := $(OUT_DIR)/zygisk_loader.o

# ---- Hook core ----
HOOK_SRCS  := config.cpp art_resolver.cpp dex_dump.cpp codeitem_dump.cpp hook_entry.cpp
HOOK_OBJS  := $(patsubst %.cpp,$(OUT_DIR)/%.o,$(HOOK_SRCS))

# Dobby source files
DOBBY_DIR  := Dobby
DOBBY_SRC  := $(DOBBY_DIR)/source
DOBBY_FILES := \
    $(DOBBY_SRC)/dobby.cpp \
    $(DOBBY_SRC)/Backend/UserMode/ExecMemory/clear-cache-tool-all.c \
    $(DOBBY_SRC)/Backend/UserMode/MultiThreadSupport/ThreadSupport.cpp \
    $(DOBBY_SRC)/InterceptRouting/InstrumentRouting/instrument_routing_handler.cpp
DOBBY_OBJS := $(patsubst $(DOBBY_SRC)/%.cpp,$(OUT_DIR)/dobby/%.o,$(patsubst $(DOBBY_SRC)/%.c,$(OUT_DIR)/dobby/%.o,$(DOBBY_FILES)))

# ---- Test module ----
TEST_SRC   := test_zn_module.cpp
TEST_OBJ   := $(OUT_DIR)/test_zn_module.o

COMMON_FLAGS := -target aarch64-linux-android34 -DANDROID -D__ANDROID_API__=34 \
    -D__aarch64__ -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
    -fstack-protector-strong -O2 -Wno-format -Wno-unused-parameter -Iinclude

LOADER_CFLAGS := $(COMMON_FLAGS) -fno-rtti -fno-exceptions
HOOK_CFLAGS   := $(COMMON_FLAGS)
TEST_CFLAGS   := $(COMMON_FLAGS) -fno-rtti -fno-exceptions

LOADER_LDFLAGS := -shared -fPIC -Wl,--hash-style=sysv -Wl,--gc-sections \
    -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -llog -lc -ldl -lm \
    -nostdlib++

HOOK_LDFLAGS := -shared -fPIC -Wl,--hash-style=sysv -Wl,--gc-sections \
    -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -llog -lc -lm -ldl \
    -nostdlib++ \
    -Wl,--whole-archive \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++_static.a \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++abi.a \
    -Wl,--no-whole-archive

TEST_LDFLAGS := -shared -fPIC -Wl,--hash-style=sysv -Wl,--gc-sections \
    -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -llog -lc \
    -nostdlib++ \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++_static.a \
    $(SYSROOT)/usr/lib/aarch64-linux-android/libc++abi.a

.PHONY: all clean test

all: dirs $(ZYGISK_SO) $(HOOK_SO)

test: dirs $(TEST_SO)

dirs:
	@mkdir -p $(OUT_DIR)/zygisk $(OUT_DIR)/lib64 $(OUT_DIR)/test

$(ZYGISK_SO): $(LOADER_OBJ)
	$(CXX) $< $(LOADER_LDFLAGS) -o $@
	$(STRIP) -s $@
	@echo "  zygisk/arm64-v8a.so ready"

$(LOADER_OBJ): $(LOADER_SRC)
	$(CXX) $(LOADER_CFLAGS) -c $< -o $@

$(HOOK_SO): $(HOOK_OBJS)
	$(CXX) $^ $(HOOK_LDFLAGS) -o $@
	$(STRIP) -s $@

$(TEST_SO): $(TEST_OBJ)
	$(CC) $< $(TEST_LDFLAGS) -o $@
	$(STRIP) -s $@
	@echo "  test/arm64-v8a.so ready"

$(TEST_OBJ): $(TEST_SRC)
	$(CXX) $(TEST_CFLAGS) -c $< -o $@

$(OUT_DIR)/%.o: %.cpp
	$(CXX) $(HOOK_CFLAGS) -c $< -o $@

# Dobby compilation rules
$(OUT_DIR)/dobby/%.o: $(DOBBY_SRC)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(HOOK_CFLAGS) -c $< -o $@

$(OUT_DIR)/dobby/%.o: $(DOBBY_SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(HOOK_CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUT_DIR)
