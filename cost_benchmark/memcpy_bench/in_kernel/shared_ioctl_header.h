#ifndef IOCTL_H
#define IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

typedef struct {
	__u64 duration;
	__u64 array_size;
	__u64 repeat;
} lkmc_ioctl_struct;
#define LKMC_IOCTL_MAGIC 0x33
#define LKMC_IOCTL_RUN_BENCH     _IOWR(LKMC_IOCTL_MAGIC, 0, lkmc_ioctl_struct)
#endif
