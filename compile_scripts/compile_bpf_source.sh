#! /bin/bash
set -e
# set -x

CURDIR=$(realpath $(dirname $0))
KASHK_SPECIFIC_HEADERS=$(realpath "$CURDIR/../src/headers/my_bpf_headers")

CC=clang
LLC=llc
CFLAGS="$CFLAGS -Wall -I $KASHK_SPECIFIC_HEADERS"
BPF_CFLAGS="-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-O2 -emit-llvm -c -g"

# CC=clang-11
# LLC=llc-11

# CC=clang-18
# LLC=llc-18

# CC=/home/farbod/clang/clang+llvm-17.0.5-x86_64-linux-gnu-ubuntu-22.04/bin/clang
# LLC=/home/farbod/clang/clang+llvm-17.0.5-x86_64-linux-gnu-ubuntu-22.04/bin/llc

OUTPUT_DIR_BPF=/tmp
SOURCE=$1
if [ $# -ge 2 ]; then
	BINARY=$2
else
	BINARY="$OUTPUT_DIR_BPF/bpf.o"
fi

if [ $# -ge 3 ]; then
	LL_FILE=$3
else
	LL_FILE="$OUTPUT_DIR_BPF/bpf.ll"
fi

$CC --version
if [ -f $LL_FILE ]; then
	rm $LL_FILE
fi

$CC -S \
	-target bpf \
	-D __BPF_TRACING__ \
	$CFLAGS \
	$BPF_CFLAGS \
	-o $LL_FILE $SOURCE
$LLC -mcpu=probe -march=bpf -filetype=obj -o $BINARY $LL_FILE
