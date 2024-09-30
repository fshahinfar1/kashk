MODULE_NAME = memcpy_bench
KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(PWD)/build

KMOD = $(BUILD_DIR)/$(MODULE_NAME).ko
KMOD_FILES = bench.c

USER_PROG = $(BUILD_DIR)/run_bench
USER_FILES = user.c

.PHONY: default clean load unload

default: $(BUILD_DIR) $(KMOD) $(USER_PROG)

$(BUILD_DIR):
	mkdir -p "$@"

$(KMOD): $(KMOD_FILES)
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) modules

$(USER_PROG): $(USER_FILES)
	$(CC) -Wall -g -O2 -o $@ $(USER_FILES)

clean:
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) clean
	rm $(USER_PROG)

load: unload
	sudo insmod $(KMOD)

unload:
	sudo rmmod $(MODULE_NAME) | true

test: load
	DEBUG_FILE_PATH=/sys/kernel/debug/lkmc_ioctl/f && \
			sudo $(USER_PROG) $$DEBUG_FILE_PATH

