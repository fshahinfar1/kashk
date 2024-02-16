# Description of files in this directory

* `compile_bpf_source`: a script for compiling a `bpf.c` file
* `load.sh`: a script for testing if a `bpf.o` object can be loaded to the kernel
* `loader`: it is a tool (binary) for loading `xdp`, `sk_skb`, `tc` bpf
  programs the actual source code for this tool is at
  `auto_kern_offload_bench/src/userspace/loader` (another repository).
