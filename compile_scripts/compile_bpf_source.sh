#! /bin/bash
set -e
# set -x

CURDIR=$(realpath $(dirname $0))
KASHK_SPECIFIC_HEADERS=$(realpath "$CURDIR/../src/headers/my_bpf_headers")

CC=clang
LLC=llc
CFLAGS="$CFLAGS -Wall -I $KASHK_SPECIFIC_HEADERS"

# CC=clang-18
# LLC=llc-18

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
if [ -f $LL_FILE ]; then
	rm $LL_FILE
fi
# $CC \
# 	-target bpf \
# 	-Wall \
# 	-O2 -g \
# 	-c $SOURCE \
# 	-o $BINARY

$CC -S \
	-target bpf \
	-D __BPF_TRACING__ \
	$CFLAGS \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-O2 -emit-llvm -c -g -o $LL_FILE $SOURCE
$LLC -mcpu=probe -march=bpf -filetype=obj -o $BINARY $LL_FILE
