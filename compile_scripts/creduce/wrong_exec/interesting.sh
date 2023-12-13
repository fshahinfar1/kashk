#! /bin/bash
# Check if the bpf program has the weird property of considering two values for
# the same variable in the same scope !!!

# The tester.c program will use BPF_PROG_TEST_RUN to execute the bpf program.
# The program will generate some logs. If the logs contain our keywords, there
# is a problem.

set -e

echo "YOU CAN NOT RUN THIS SCRIPT IN PARALLEL"
CURDIR=$(realpath $(dirname $0))
TESTER=$CURDIR/build/tester


# Compiling the BPF program
# make run
if [ -z "$KASHK_DIR" ]; then
	echo "KASHK_DIR is not defined"
	exit 1
fi
if [ ! -f $TESTER ]; then
	echo "Tester program not found"
	exit 1
fi
BPF_COMPILE_SCRIPT=$KASHK_DIR/compile_scripts/compile_bpf_source.sh
bash $BPF_COMPILE_SCRIPT ./bpf.c ./bpf.o
sudo $TESTER -b ./bpf.o

sudo cat /sys/kernel/debug/tracing/trace | grep "n="
tmp=( $(sudo cat /sys/kernel/debug/tracing/trace | grep "n=" | head -n 2 | cut -d ";" -f 2) )
x1=$(printf ${tmp[0]} | cut -d "-" -f 1)
x2=$(printf ${tmp[1]} | cut -d "-" -f 1)
v1=$(printf ${tmp[0]} | cut -d "=" -f 2)
v2=$(printf ${tmp[1]} | cut -d "=" -f 2)

# Clear the pipe for the next run
# It is okay if the timeout kicks in. That is why there is the `true' in the
# end.
sudo timeout 1 cat /sys/kernel/debug/tracing/trace_pipe 2>&1 > /dev/null || true

echo line1: $x1 $v1
echo line2: $x2 $v2

# Check if it is interesting execution
if [ "x$x1" == "xs1" -a "x$x2" == "xs2" ]; then
	if [ $v1 != $v2 ]; then
		if [ $v1 == "10" -a $v2 == "0" ]; then
			echo interesting!
			exit 0
		fi
	fi
	echo here
fi

# not interesting
printf "line 1: %s\n" ${tmp[0]}
printf "line 2: %s\n" ${tmp[1]}
exit 1
