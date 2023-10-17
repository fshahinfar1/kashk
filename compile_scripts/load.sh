#! /bin bash

BPF_BIN=$1
PIN_PATH=/sys/fs/bpf/test_prog
sudo bpftool prog load $BPF_BIN $PIN_PATH
sudo rm $PIN_PATH
