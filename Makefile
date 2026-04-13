# bperf Makefile
# Builds the BPF object, generates skeleton, and compiles userspace tool

CLANG       ?= clang-18
LLVM_STRIP  ?= llvm-strip-18
BPFTOOL     ?= bpftool
CC          ?= gcc

ARCH        := $(shell uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x86/')

# Directories
SRC_DIR     := src
INC_DIR     := include
BUILD_DIR   := build

# BPF compilation flags
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
               -I$(INC_DIR) -I. \
               -Wall -Wno-unused-function

# Userspace compilation flags
CFLAGS      := -g -O2 -Wall -Wextra -Wno-unused-parameter \
               -I$(INC_DIR) -I$(BUILD_DIR) -I.
LDFLAGS     := -lbpf -lelf -lz

# Source files
USER_SRCS   := $(SRC_DIR)/bperf.c \
               $(SRC_DIR)/record.c \
               $(SRC_DIR)/oncpu.c \
               $(SRC_DIR)/offcpu.c \
               $(SRC_DIR)/writer.c \
               $(SRC_DIR)/proc.c
USER_OBJS   := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(USER_SRCS))

# Targets
BPF_OBJ     := $(BUILD_DIR)/bperf.bpf.o
BPF_SKEL    := $(BUILD_DIR)/bperf.skel.h
TARGET      := bperf

.PHONY: all clean

all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile BPF program
$(BPF_OBJ): $(SRC_DIR)/bperf.bpf.c vmlinux.h $(INC_DIR)/bperf_common.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ) | $(BUILD_DIR)
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace objects (each depends on skeleton and headers)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(BPF_SKEL) $(INC_DIR)/bperf_common.h $(INC_DIR)/perf_file.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link final binary
$(TARGET): $(USER_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
