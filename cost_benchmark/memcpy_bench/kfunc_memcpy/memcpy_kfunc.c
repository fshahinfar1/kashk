#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h> /* memcpy */
#include <linux/btf.h>
MODULE_LICENSE("GPL");

/* Define a kfunc function */
__bpf_kfunc_start_defs();

__bpf_kfunc void *my_kfunc_memcpy(void *dst, void *src, __u32 src__sz)
{
	return memcpy(dst, src, src__sz);
}

__bpf_kfunc_end_defs();

/* Encode the function(s) into BTF */

/*
 * These will probably be the new API
 * */
/* BTF_KFUNCS_START(bpf_my_string_set) */
/* BTF_ID_FLAGS(func, my_kfunc_memcpy, 0) */
/* BTF_KFUNCS_END(bpf_my_string_set) */

BTF_SET8_START(bpf_my_string_set)
BTF_ID_FLAGS(func, my_kfunc_memcpy, 0)
BTF_SET8_END(bpf_my_string_set)

static const struct btf_kfunc_id_set my_kfunc_memcpy_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &bpf_my_string_set,
};

static int myinit(void)
{
	/* Register the BTF */
	register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &my_kfunc_memcpy_kfunc_set);
	pr_info("Load memcpy kfunc\n");
	return 0;
}

static void myexit(void)
{
	pr_info("Unloading memcpy kfunc\n");
}

module_init(myinit)
module_exit(myexit)
