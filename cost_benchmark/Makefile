CC = clang
CFLAGS = -O2 -g -Wall

LOADER_CFLAGS=$(shell pkg-config --cflags libbpf)
LOADER_LDFLAGS=$(shell pkg-config --libs libbpf)
OUTDIR = ./build
RUNNER = $(OUTDIR)/runner
RUNNER_HEADERS = $(wildcard *.h)
SERVER = $(OUTDIR)/server
COMPILE_SCRIPT = ../compile_scripts/compile_bpf_source.sh
BPF_FILES = $(wildcard ./benchmarks/*.c)

# Use a locally installed libbpf when compiling BPF benchmarks
# Useful when the globally installed libbpf is old
BPF_CFLAGS = -I /home/farbod/auto_kern_offload_bench/deps/usr/include

default: $(SERVER) $(RUNNER) bpf

# .SILENT:

$(SERVER): server.c
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) -o $(SERVER) server.c

$(RUNNER): runner.c $(RUNNER_HEADERS)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) $(LOADER_CFLAGS) -o $(RUNNER) runner.c $(LOADER_LDFLAGS) -lrt

bpf:
	for file in $(BPF_FILES); do \
		out="$(OUTDIR)/$$(basename $$file | cut -d '.' -f 1).o" ; \
		echo "$$file --> $$out" ;\
		sudo CFLAGS="$(BPF_CFLAGS) " bash $(COMPILE_SCRIPT) $$file $$out > /dev/null ;\
	done
