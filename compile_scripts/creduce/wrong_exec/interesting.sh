#! /bin/bash
# Check if the bpf program has the weird property of considering two values for
# the same variable in the same scope !!!

# The tester.c program will use BPF_PROG_TEST_RUN to execute the bpf program.
# The program will generate some logs. If the logs contain our keywords, there
# is a problem.

set -e

echo "YOU CAN NOT RUN THIS SCRIPT IN PARALLEL"
CURDIR=$(realpath $(dirname $0))
TESTER=$CURDIR/tester


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

if [ -f ./bpf.o ]; then
	echo "Removing the old bpf.o"
	rm ./bpf.o
fi
echo Compiling...
bash $BPF_COMPILE_SCRIPT ./bpf.c ./bpf.o
echo Testing...
sudo $TESTER -b ./bpf.o
echo After test
sudo cat /sys/kernel/debug/tracing/trace
echo "Found the line in the log"
if [ $? -ne 0 ]; then
	echo "Does not have BOOM"
	exit 1;
fi
left=$(sudo cat /sys/kernel/debug/tracing/trace | grep "BOOM" | tail -n 1 | cut -d ';' -f 2)
right=$(sudo cat /sys/kernel/debug/tracing/trace | grep "BOOM" | tail -n 1 | cut -d ';' -f 3)

if [ -z "$left" -o -z "$right" ]; then
	echo "Do not have left or right?"
	exit 1;
fi
echo "Checking.."


if [ $left -ge $right ]; then
	echo "left is greater-than-equal than right"
	echo "i=$left value_size=$right"
	exit 1;
fi
echo "Should be fine"

if [ $left -ne 0 -o $right -ne 24 ]; then
	echo "Wrong values are being printed! we want the loop index and value size"
	exit 1;
fi
echo "Everything is fine"

# Clear the pipe for the next run
# It is okay if the timeout kicks in. That is why there is the `true' in the
# end.
sudo timeout 1 cat /sys/kernel/debug/tracing/trace_pipe 2>&1 > /dev/null || true

echo "It is interesting!"
exit 0
