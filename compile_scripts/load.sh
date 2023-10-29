#! /bin bash

set -e

BPF_BIN=$1
PIN_PATH=/sys/fs/bpf/test_prog
sudo bpftool prog load $BPF_BIN $PIN_PATH
echo The program loaded into kernel
sudo rm $PIN_PATH
echo The program was unloaded
