#include <asm/uaccess.h> /* copy_from_user, copy_to_user */
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/printk.h> /* printk */
#include <linux/vmalloc.h>

#include "shared_ioctl_header.h"

#define REPEAT 100

MODULE_LICENSE("GPL");

static struct dentry *dir;

struct item {
	char data[1000];
};

static inline void __do_exp(struct item *arr, struct item *d)
{
	for (int i = 1; i < (REPEAT + 1); i++) {
		struct item *it = &arr[i];
		memcpy(it->data, d->data, 1000);
	}
}

static int __do_benchmark(lkmc_ioctl_struct *s /*out*/)
{
	__u64 begin, duration;
	struct item *arr = vmalloc((REPEAT + 1) * sizeof(struct item));
	if (arr == NULL) {
		pr_info("failed to allocate memory!\n");
		return -1;
	}
	struct item *d = &arr[0];

	/* The assumption is that item has 1000 bytes, remember to update here
	 * if changing it */
	for (int i = 0; i < 1000; i++) {
		d->data[i] = 'a' + (i % 26);
	}

	const int repeat = 10000;
	begin = ktime_get_ns();
	for (int i = 0; i < repeat; i++) {
		__do_exp(arr, d);
	}
	duration = ktime_get_ns() - begin;
	/* Let's not do division and module inside the kernel. Pass information
	 * to usersace
	 * */
	s->duration = duration;
	s->array_size = REPEAT;
	s->repeat = repeat;

	/* Let's pretend that this calculation is somehow important (prevent
	 * compiler from doing weird optimizations) */
	int x = 0;
	for (int i = 0; i < REPEAT; i++) {
		for (int j = 0; j < 1000; j++) {
			x += (unsigned int)arr[i].data[j];
		}
	}

	/* Remember to free the memory we got from the kernel */
	vfree(arr);

	/* Both paths are fine */
	if (x == 1234) return 1;
	return 0;
}

static long unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long argp)
{
	void __user *arg_user;
	union {
		lkmc_ioctl_struct s;
	} arg_kernel;

	arg_user = (void __user *)argp;
	pr_info("cmd = %x\n", cmd);
	switch (cmd) {
		case LKMC_IOCTL_RUN_BENCH:
			/* if (copy_from_user(&arg_kernel.s, arg_user, sizeof(arg_kernel.s))) { */
			/* 	return -EFAULT; */
			/* } */
			/* pr_info("1 arg = %d %d\n", arg_kernel.s.i, arg_kernel.s.j); */
			__do_benchmark(&arg_kernel.s);
			if (copy_to_user(arg_user, &arg_kernel.s, sizeof(arg_kernel.s))) {
				return -EFAULT;
			}
			break;
		default:
			return -EINVAL;
			break;
	}
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = unlocked_ioctl
};

static int myinit(void)
{
	dir = debugfs_create_dir("lkmc_ioctl", 0);
	/* ioctl permissions are not automatically restricted by rwx as for read / write,
	 * but we could of course implement that ourselves:
	 * https://stackoverflow.com/questions/29891803/user-permission-check-on-ioctl-command */
	debugfs_create_file("f", 0, dir, NULL, &fops);
	return 0;
}

static void myexit(void)
{
	debugfs_remove_recursive(dir);
}

module_init(myinit)
module_exit(myexit)
