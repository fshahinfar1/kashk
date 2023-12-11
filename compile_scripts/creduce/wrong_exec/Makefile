CC = gcc
CFLAGS = -Wall -g -O2

ifndef KASHK_DIR
	$(error the KASHK_DIR variable is not set)
endif
# $(info expect ${KASHK_DIR})

BPF_GEN_DIR = $(KASHK_DIR)
BPF_COMPILE_SCRIPT = $(BPF_GEN_DIR)/compile_scripts/compile_bpf_source.sh


.PHONY: default run clean

default: ./build/tester
	bash  $(BPF_COMPILE_SCRIPT) ./bpf.c ./build/bpf.o

./build/tester: ./tester.c
	echo Compiling tester program
	if [ ! -d ./build/ ]; then mkdir -p ./build/ ; fi
	$(CC) $(CFLAGS) -o ./build/tester ./tester.c -lbpf -lelf -lz

run: default
	sudo ./build/tester -b ./build/bpf.o

clean:
	rm -r ./build/


bpf_load:
	bash $(BPF_GEN_DIR)/compile_scripts/load.sh ./bpf/bpf.o

gold:
	echo Compiling...
	$(CC) $(CFLAGS) -o ./golden/loader ./golden/load.c -lbpf -lelf -lz
	echo Compiling 1st option
	mkdir -p ./golden/build/
	bash $(BPF_GEN_DIR)/compile_scripts/compile_bpf_source.sh ./golden/bpf_1.c ./golden/build/bpf_1.o
	# bash $(BPF_GEN_DIR)/compile_scripts/load.sh /tmp/bpf.o
	echo Trying 1st option
	sudo ./golden/loader -b ./golden/build/bpf_1.o -l

gold_clean:
	rm -rf ./golden/build/

gold_run: gold_clean gold
	if [ -z "${NET_IFACE}" ]; then echo "NET_IFACE" is not set; exit 1; fi
	sudo ./golden/loader -b ./golden/build/bpf_1.o -i ${NET_IFACE}
