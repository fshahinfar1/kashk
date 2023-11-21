#! /bin/bash
CURDIR=$(dirname $(realpath $0))
BPF_GEN_DIR=$HOME/auto_bpf_offload/kashk
BPF_GEN=$BPF_GEN_DIR/src/main.py
COMPILE_SCRIPT=$BPF_GEN_DIR/compile_scripts/compile_bpf_source.sh
LOAD_SCRIPT=$BPF_GEN_DIR/compile_scripts/load.sh

# MUST be a relative path
SOURCE=./bpf.c
# MUST be relative path
BINARY=./bpf.o
LOG_FILE=./test_log.txt

rm $BINARY
rm $LOG_FILE

bash $COMPILE_SCRIPT $SOURCE $BINARY &> /dev/null
RETCODE=$?
# echo compile return code $RETCODE
if [ $RETCODE -ne 0 ]; then
	# Failed to compile not interesting
	exit 1
fi

bash $LOAD_SCRIPT $BINARY &> $LOG_FILE
RETCODE=$?
# echo load return code $RETCODE
if [ $RETCODE -eq 255 ]; then
	grep "!read_ok" $LOG_FILE &> /dev/null
	RETCODE=$?
	# echo grep return code $RETCODE
	if [ $RETCODE -ne 0 ]; then
		# The error changed not interesting
		exit 1
	fi
	exit 0
fi
# Not interesting anymore
exit 1
