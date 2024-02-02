#ifndef __MY_BPF_COMMONS
#define __MY_BPF_COMMONS
/* Make sure these types are defined */
#ifndef __u32
typedef unsigned char        __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
#endif

#ifndef NULL
#define NULL 0
#endif

#define sinline static inline __attribute__((__always_inline__))
#define mem_barrier asm volatile("": : :"memory")

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif

#define ABS(val) ((val) < 0) ? (-(val)) : (val)
#define CAP(val, cap) (val > cap ? cap : val)
#define SIGNED(val, neg) (neg ? -val : val)

static inline __attribute__((__always_inline__))
int __adjust_skb_size(struct __sk_buff *skb, __u16 new_size)
{
	/* Addjust SKB size */
	/* TODO: (Farbod) this is ridiculous: use two calls to
	 * bpf_skb_adjust_room size to allow for changing skb size upto
	 * 8KByte */
	__u16 prev_size = skb->len;
	int shrink = new_size < prev_size;
	int total_delta = ABS(prev_size - new_size);
	int delta = CAP(total_delta, 0x0fff); /* delta that we can do in one function call */
	total_delta -= delta; /* rest of the delta */
	if (bpf_skb_adjust_room(skb, SIGNED(delta, shrink), 0, 0) <  0) {
		bpf_printk("failed to resize the packet");
		return -1;
	}
	if (total_delta && bpf_skb_adjust_room(skb, SIGNED(total_delta, shrink), 0, 0) < 0) {
		/* If three is left over packet size change, try to do it one more time */
		bpf_printk("failed to resize the packet (2)");
		bpf_printk("prev: %d new: %d", prev_size, new_size);
		return -1;
	}
	return 0;
}
#endif
