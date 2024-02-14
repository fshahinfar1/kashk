CC = clang
CFLAGS = -O2 -g -Wall
OUTDIR = ./build
RUNNER = $(OUTDIR)/runner
RUNNER_HEADERS = $(wildcard *.h)
SERVER = $(OUTDIR)/server
COMPILE_SCRIPT = ../compile_scripts/compile_bpf_source.sh
BPF_FILES = $(wildcard ./benchmarks/*.c)

default: $(SERVER) $(RUNNER) bpf

# .SILENT:

$(SERVER): server.c
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) -o $(SERVER) server.c

$(RUNNER): runner.c $(RUNNER_HEADERS)
	if [ ! -d $(OUTDIR) ]; then mkdir -p $(OUTDIR) ; fi
	$(CC) $(CFLAGS) -o $(RUNNER) runner.c -lbpf -lrt

bpf:
	for file in $(BPF_FILES); do \
		out="$(OUTDIR)/$$(basename $$file | cut -d '.' -f 1).o" ; \
		echo "$$file --> $$out" ;\
		sudo bash $(COMPILE_SCRIPT) $$file $$out > /dev/null ;\
	done
