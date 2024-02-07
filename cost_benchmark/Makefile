CC = clang
CFLAGS = -O2 -g -Wall
OUTDIR = ./build
LDFLAGS = -lbpf
RUNNER = $(OUTDIR)/runner
RUNNER_HEADERS = $(wildcard *.h)
COMPILE_SCRIPT = ../compile_scripts/compile_bpf_source.sh
BPF_FILES = $(wildcard ./benchmarks/*.c)

default: $(RUNNER) bpf

# .SILENT:

$(RUNNER): runner.c $(RUNNER_HEADERS)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) -o $(RUNNER) runner.c $(LDFLAGS)

bpf:
	for file in $(BPF_FILES); do \
		out="$(OUTDIR)/$$(basename $$file | cut -d '.' -f 1).o" ; \
		echo "$$file --> $$out" ;\
		sudo bash $(COMPILE_SCRIPT) $$file $$out > /dev/null ;\
	done
