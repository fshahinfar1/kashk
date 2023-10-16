#! /bin/bash
set -e
set -x

SOURCE=$1
BINARY=bpf.o
OUTPUT_DIR_BPF=/tmp

CC=clang
LLC=llc
BINARY="$OUTPUT_DIR_BPF/bpf.o"
LL_FILE="$OUTPUT_DIR_BPF/bpf.ll"
$CC $INCLUDES \
	-target bpf \
	-S \
	-D BPF_PROG \
	-D__KERNEL__  \
	-D__BPF_TRACING__ \
	-D__TARGET_ARCH_x86 \
	-Wall \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-O2 -g -emit-llvm -c $SOURCE -o $LL_FILE
$LLC -mcpu=v3 -march=bpf -filetype=obj -o $BINARY $LL_FILE