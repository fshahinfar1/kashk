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
BPF_OUT = $(addprefix $(OUTDIR)/, $(addsuffix .o, $(basename $(notdir $(BPF_FILES)))))

# Use a locally installed libbpf when compiling BPF benchmarks
# Useful when the globally installed libbpf is old
BPF_CFLAGS = -I /home/farbod/auto_kern_offload_bench/deps/usr/include

.PHONY: default bpf clean

default: $(SERVER) $(RUNNER) bpf $(OUTDIR)/memcpy_bench

clean:
	rm -r $(OUTDIR)

# .SILENT:

$(SERVER): server.c
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) -o $(SERVER) server.c

$(RUNNER): runner.c $(RUNNER_HEADERS)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) $(LOADER_CFLAGS) -o $(RUNNER) runner.c $(LOADER_LDFLAGS) -lrt

$(BPF_OUT): $(OUTDIR)/%.o:./benchmarks/%.c
	echo "$< --> $@" ;\
	CFLAGS="$(BPF_CFLAGS) " bash $(COMPILE_SCRIPT) $< $@ > /dev/null ;

bpf: $(BPF_OUT)
# for file in $(BPF_FILES); do \
# 	out="$(OUTDIR)/$$(basename $$file | cut -d '.' -f 1).o" ; \
# 	echo "$$file --> $$out" ;\
# 	sudo CFLAGS="$(BPF_CFLAGS) " bash $(COMPILE_SCRIPT) $$file $$out > /dev/null ;\
# done

BASE_NO_SIMD_FLAGS=-DNO_SIMD -fno-tree-vectorize -mno-mmx -mno-sse -mno-avx -mno-avx512f
BASE_SIMD_FLAGS=-march=native -msse2 -mavx # -mavx512f
MEMCPY_BENCH_FILES = $(wildcard ./memcpy_bench/*.c)
$(OUTDIR)/memcpy_bench: $(MEMCPY_BENCH_FILES)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(BASE_SIMD_FLAGS) $(CFLAGS) -o $@ $(MEMCPY_BENCH_FILES)
	$(CC) $(BASE_NO_SIMD_FLAGS) $(CFLAGS) -o $@_no_simd $(MEMCPY_BENCH_FILES)
