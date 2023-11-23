#! /bin/bash
set -e
set -x

# CC=clang
# LLC=llc

CC=clang-16
LLC=llc-16

# CC=/home/farbod/clang/clang+llvm-17.0.5-x86_64-linux-gnu-ubuntu-22.04/bin/clang
# LLC=/home/farbod/clang/clang+llvm-17.0.5-x86_64-linux-gnu-ubuntu-22.04/bin/llc

OUTPUT_DIR_BPF=/tmp
LL_FILE="$OUTPUT_DIR_BPF/bpf.ll"

SOURCE=$1
if [ $# -ge 2 ]; then
	BINARY=$2
else
	BINARY="$OUTPUT_DIR_BPF/bpf.o"
fi

$CC --version

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
