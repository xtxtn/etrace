TARGET      := mini_etrace
BPF_OBJ     := mini_etrace.bpf.o

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

ELIB_ROOT := $(HOME)/elib/aarch64-elib
ELIB_INC  := $(ELIB_ROOT)/include
ELIB_LIB  := $(ELIB_ROOT)/lib


# ARM64 toolchain information
SYSROOT := $(shell $(CC) -print-sysroot)
MULTIARCH := $(shell $(CC) -print-multiarch)
GCC_INCLUDE := $(shell $(CC) -print-file-name=include)

BPF_SYS_INCLUDES := \
	-I$(ELIB_INC) \
	-I$(SYSROOT)/usr/include \
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
	-I$(ELIB_INC)


STATIC_LIBS := \
	$(ELIB_LIB)/libbpf.a \
	$(ELIB_LIB)/libelf.a \
	$(ELIB_LIB)/libz.a


USER_LDFLAGS := \
	-static \
	-Wl,--gc-sections

SYSTEM_LIBS := \
	-lpthread \
	-ldl

.PHONY: all clean install

all: $(BPF_OBJ) $(TARGET)


$(BPF_OBJ): mini_etrace.bpf.c mini_etrace.h
	$(CLANG) $(BPF_CFLAGS) \
		-c $< \
		-o $@

$(TARGET): mini_etrace.c mini_etrace.h
	$(CC) $(USER_CFLAGS) \
		$< \
		-o $@ \
		$(USER_LDFLAGS) \
		$(STATIC_LIBS) \
		$(SYSTEM_LIBS)
	$(STRIP) $(TARGET)


install: 
	$(ADB_CMD) push $(BPF_OBJ) $(DST)
	$(ADB_CMD) push $(TARGET) $(DST)

clean:
	rm -f $(TARGET)
	rm -f $(BPF_OBJ)
