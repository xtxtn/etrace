BUILD_DIR := build

BPF_OBJ := $(BUILD_DIR)/mini_etrace.bpf.o
TARGET  := $(BUILD_DIR)/mini_etrace

CROSS_COMPILE ?= aarch64-linux-gnu-
CC      := $(CROSS_COMPILE)gcc
AR      := $(CROSS_COMPILE)ar
STRIP   := $(CROSS_COMPILE)strip

CLANG   := clang
LLVM_STRIP := llvm-strip

ADB    := adb
DEVICE ?=
DST    := /data/local/tmp
ADB_CMD := $(ADB) $(if $(DEVICE),-s $(DEVICE),)

ELIB_ROOT := aarch64-elib
ELIB_INC  := $(ELIB_ROOT)/include
ELIB_LIB  := $(ELIB_ROOT)/lib

LOCAL_INC := include

# ARM64 toolchain information
SYSROOT := $(shell $(CC) -print-sysroot)
MULTIARCH := $(shell $(CC) -print-multiarch)
GCC_INCLUDE := $(shell $(CC) -print-file-name=include)

BPF_SYS_INCLUDES := \
	-I$(ELIB_INC) \
	-I$(LOCAL_INC) \
	-I/usr/$(MULTIARCH)/include


BPF_CFLAGS := \
	-O2 \
	-g \
	-target bpf \
	-D__TARGET_ARCH_arm64 \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	$(BPF_SYS_INCLUDES)


USER_CFLAGS := \
	-O2 \
	-g \
	-Wall \
	-Wextra \
	-I$(ELIB_INC) \
	-I$(LOCAL_INC)


STATIC_LIBS := \
	$(ELIB_LIB)/libbpf.a \
	$(ELIB_LIB)/libelf.a \
	$(ELIB_LIB)/libz.a \
	$(ELIB_LIB)/libblazesym_c.a

USER_LDFLAGS := \
	-static \
	-Wl,--gc-sections

SYSTEM_LIBS := \
	-lpthread \
	-ldl

.PHONY: all clean install

all: $(BPF_OBJ) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BPF_OBJ): src/mini_etrace.bpf.c | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) \
		-c $< \
		-o $@

$(TARGET): src/mini_etrace.c src/sysdecode.c src/syscall_tables_generated.c
	$(CC) $(USER_CFLAGS) \
		$^ \
		-o $@ \
		$(USER_LDFLAGS) \
		$(STATIC_LIBS) \
		$(SYSTEM_LIBS)
	$(STRIP) $@


install:
	$(ADB_CMD) push $(BPF_OBJ) $(DST)
	$(ADB_CMD) push $(TARGET) $(DST)

clean:
	rm -f $(BUILD_DIR)
