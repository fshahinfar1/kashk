#ifndef __HASH_FN
#define __HASH_FN
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define FNV_OFFSET_BASIS_32 2166136261
#define FNV_PRIME_32 16777619
#define UNROLL_SIZE 16

struct hash_loop_context {
  const __u8 *message;
  const void *data_end;
  __u32 hash;
  __u32 err;
};

static long
hash_loop_fn(__u32 off, void *_ctx)
{
  struct hash_loop_context *ctx = _ctx;
  /* Bound checking */
  if ((void *)ctx->message + UNROLL_SIZE > ctx->data_end) {
    /* Index out of range */
    ctx->err = 1;
    /* break; */
    return 1;
  }
  /* do some unrolling by hand :) */
  ctx->hash ^= ctx->message[0];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[1];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[2];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[3];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[4];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[5];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[6];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[7];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[8];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[9];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[10];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[11];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[12];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[13];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[14];
  ctx->hash *= FNV_PRIME_32;
  ctx->hash ^= ctx->message[15];
  ctx->hash *= FNV_PRIME_32;
  /* Move pointer forward */
  ctx->message += UNROLL_SIZE;
  return 0;
}

/* Fowler–Noll–Vo hash function
 * */
static inline __attribute__((__always_inline__))
__u32 _fnv_hash(const __u8 *message, __u16 length, const void *data_end,
    __u32 *hash)
{
  __u16 left, i;
  struct hash_loop_context loop_ctx = {
    .message = message,
    .data_end = data_end,
    .hash = *hash,
    .err = 0,
  };

  /* TODO: if less than 3 do something */
  bpf_loop(length / UNROLL_SIZE, hash_loop_fn, &loop_ctx, 0);
  left = length % UNROLL_SIZE;

  for (i = 0; i < UNROLL_SIZE; i++) {
    if (i >= left) break;

    if ((void *)loop_ctx.message + 1 > data_end) {
      return 1;
    }

    loop_ctx.hash ^= loop_ctx.message[0];
    loop_ctx.hash *= FNV_PRIME_32;
    loop_ctx.message++;
  }

  if (loop_ctx.err) { return 1; }
  /* Update hash value */
  *hash = loop_ctx.hash;
  return 0;
}

static inline __attribute__((__always_inline__))
__u32 __fnv_hash(const __u8 *msg, __u16 len, const void *end)
{
  __u32 hash = FNV_OFFSET_BASIS_32;
  int ret = _fnv_hash(msg, len, end, &hash);
  if (ret == 0)
    return hash;
  return -1;
}
#endif

#ifndef __XDP_HELPER_H
#define __XDP_HELPER_H
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#ifndef _CSUM_HELPER
#define _CSUM_HELPER
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Check-sum calculation helpers */
struct csum_loop_ctx {
	unsigned short *next_iph_u16;
	void *data_end;
	unsigned long long *csum;
};

static inline unsigned short
csum_fold_helper(unsigned long long csum)
{
	int i;
	#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16) {
			csum = (csum & 0xffff) + (csum >> 16);
		}
	}
	return ~csum;
}

static inline void
ipv4_csum_inline(void *iph, unsigned long long *csum)
{
	unsigned int i;
	unsigned short *next_iph_u16 = (unsigned short *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += bpf_ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static long
csum_loop(unsigned int i, void *_ctx)
{
	struct csum_loop_ctx *ctx = (struct csum_loop_ctx *)_ctx;
	if ((void *)(ctx->next_iph_u16 + 1) > ctx->data_end) {
		return 1;
	}
	*ctx->csum += bpf_ntohs(*ctx->next_iph_u16);
	ctx->next_iph_u16++;
	return 0;
}

static inline void
ipv4_l4_csum_inline(void *data_end, void *l4_hdr, struct iphdr *iph,
		unsigned long long *csum)
{
	unsigned int ip_addr;
	unsigned short *next_iph_u16;
	unsigned char *last_byte;

	/* Psuedo header */
	ip_addr = bpf_ntohl(iph->saddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	ip_addr = bpf_ntohl(iph->daddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	*csum += (unsigned short)iph->protocol;
	*csum += (unsigned short)((long)data_end - (long)l4_hdr);

	next_iph_u16 = (unsigned short *)l4_hdr;
	const unsigned short length = (unsigned long long)data_end - (unsigned long long)next_iph_u16;
	const unsigned short nr = length / 2;
	struct csum_loop_ctx loop_ctx = {
		.next_iph_u16 = next_iph_u16,
		.data_end = data_end,
		.csum = csum,
	};
	bpf_loop(nr, (void *)csum_loop, &loop_ctx, 0);
	if (loop_ctx.next_iph_u16 != data_end) {
		last_byte = (unsigned char *)next_iph_u16;
		if ((void *)(last_byte + 1) <= data_end) {
			*csum += (unsigned short)(*last_byte) << 8;
		}
	}
	*csum = csum_fold_helper(*csum);
}
/* ------------------------------------------------------------- */
#endif


static inline int
__prepare_headers_before_pass(struct xdp_md *xdp)
{
  struct ethhdr *eth = (void *)(__u64)xdp->data;
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  struct udphdr *udp = (struct udphdr *)(ip + 1);
  if ((void *)(udp + 1) > (void *)(__u64)xdp->data_end)
    return -1;
  const __u32 new_packet_len = ((__u64)xdp->data_end - (__u64)xdp->data);
  const __u32 new_ip_len  = new_packet_len - sizeof(struct ethhdr);
  const __u32 new_udp_len = new_ip_len - sizeof(struct iphdr);
  __u64 csum;
  /* IP fields */
  ip->tot_len = bpf_htons(new_ip_len);
  ip->ttl = 64;
  ip->frag_off = 0;
  ip->check = 0;
  csum = 0;
  ipv4_csum_inline(ip, &csum);
  ip->check = bpf_htons(csum);

  /* UDP  fields */
  udp->len = bpf_htons(new_udp_len);
  udp->check = 0;
  return 0;
}

/* A helper for sending responses */
static inline int
__prepare_headers_before_send(struct xdp_md *xdp)
{
  struct ethhdr *eth = (void *)(__u64)xdp->data;
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  struct udphdr *udp = (struct udphdr *)(ip + 1);
  if ((void *)(udp + 1) > (void *)(__u64)xdp->data_end)
    return -1;
  /* Swap MAC */
  __u8 tmp;
  for (int i = 0; i < 6; i++) {
    tmp = eth->h_source[i];
    eth->h_source[i] = eth->h_dest[i];
    eth->h_dest[i] = tmp;
  }
  /* Swap IP */
  __u32 tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;
  /* Swap port */
  __u16 tmp_port = udp->source;
  udp->source = udp->dest;
  udp->dest = tmp_port;

  const __u32 new_packet_len = ((__u64)xdp->data_end - (__u64)xdp->data);
  const __u32 new_ip_len  = new_packet_len - sizeof(struct ethhdr);
  const __u32 new_udp_len = new_ip_len - sizeof(struct iphdr);
  __u64 csum;

  /* IP fields */
  ip->tot_len = bpf_htons(new_ip_len);
  ip->ttl = 64;
  ip->frag_off = 0;
  ip->check = 0;
  csum = 0;
  ipv4_csum_inline(ip, &csum);
  ip->check = bpf_htons(csum);

  /* UDP  fields */
  udp->len = bpf_htons(new_udp_len);
  /* UDP checksum ? */
  /* udp->check = 0; */
  /* csum = 0; */
  /* ipv4_l4_csum_inline((void *)(__u64)xdp->data_end, udp, ip, */
  /*     &csum); */
  /* udp->check = bpf_ntohs(csum); */

  /* no checksum */
  udp->check = 0;
  /* bpf_printk("data: %s", (char *)(__u64)xdp->data + DATA_OFFSET); */
  return 0;
}
#endif

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif
#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif
#ifndef memset
#define memset(d, c, len) __builtin_memset(d, c, len)
#endif
typedef char bool;
#define PKT_OFFSET_MASK 0xfff
#define MAX_PACKET_SIZE 1472
#define DATA_OFFSET                                                            \
  (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define DEBUG(...) bpf_printk(__VA_ARGS__)

struct parsed_request {
  char kind;
  char *key;
  unsigned short key_size;
  char *value;
  unsigned short value_size;
};

struct item {
  unsigned short key_size;
  unsigned short value_size;
  char key[255];
  char value[255];
};

struct meta_1 {
  int failure_number;
  char wbuf1[2048];
  char wbuf2[32];
};

struct meta_2 {
  int failure_number;
  char wbuf2[32];
  char wbuf1[2048];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, unsigned int);
  __type(value, struct item);
  __uint(max_entries, 1024);
} my_cache_map SEC(".maps");
struct stack_obj_1 {
  char data[2048];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, unsigned int);
  __type(value, struct stack_obj_1);
  __uint(max_entries, 1);
} stack_obj_1_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, unsigned int);
  __type(value, struct item);
  __uint(max_entries, 2);
} preq_map SEC(".maps");

struct bpf_memcpy_ctx {
  unsigned short i;
  char *dest;
  char *src;
  unsigned short n;
  void *end_dest;
  void *end_src;
};
static long bpf_memcpy_loop(unsigned int index, void *arg) {
  struct bpf_memcpy_ctx *ll = arg;
  if ((void *)(ll->dest + ll->i + 1) > ll->end_dest)
    return 1;
  if ((void *)(ll->src + ll->i + 1) > ll->end_src)
    return 1;
  ll->dest[ll->i] = ll->src[ll->i];
  if (ll->i >= ll->n - 1) {
    return 1;
  }
  ll->i++;
  return 0;
}
struct my_bpf_strncmp_loop_ctx {
  int i;
  char *str1;
  char *str2;
  unsigned short len;
  int ret;
};
static long my_bpf_strncmp_loop(unsigned int index, void *arg) {
  struct my_bpf_strncmp_loop_ctx *ll = arg;
  if (ll->i == ll->len) {
    ll->ret = 0;
    return 1;
  }
  if (ll->str1[ll->i] != ll->str2[ll->i] || ll->str1[ll->i] == '\0') {
    ll->ret = (ll->str1[ll->i] - ll->str2[ll->i]);
    return 1;
  }
  return 0;
}
struct _new_loop_0_ctx {
  int off;
  unsigned short rsize;
  char *head;
  char found;
  struct xdp_md *xdp;
  unsigned char __loop_ret_flag;
  int __loop_ret_val;
};

struct _new_loop_1_ctx {
  int off;
  unsigned short rsize;
  char *head;
  char found;
  struct xdp_md *xdp;
  unsigned char __loop_ret_flag;
  int __loop_ret_val;
};

struct _new_loop_2_ctx {
  int off;
  unsigned short rsize;
  char *head;
  char found;
  struct xdp_md *xdp;
  unsigned char __loop_ret_flag;
  int __loop_ret_val;
};

static long _new_loop_2_func(unsigned int index, void *arg) {
  struct _new_loop_2_ctx *ll = arg;
  if (!(ll->off < 1024 && ll->off < ll->rsize)) {
    return (1);
  }
  ll->off = ll->off & PKT_OFFSET_MASK;
  if ((void *)(ll->head + ll->off + 1) >
      (void *)((unsigned long long)(ll->xdp->data_end))) {
    ll->__loop_ret_flag = 1;
    ll->__loop_ret_val = (int)0;
    return (1);
  }
  if (ll->head[ll->off] == '\n') {
    ll->found = 1;
    return (1);
  }
  ll->off++;
  return (0);
}

static long _new_loop_1_func(unsigned int index, void *arg) {
  struct _new_loop_1_ctx *ll = arg;
  if (!(ll->off < 255 && ll->off < ll->rsize)) {
    return (1);
  }
  ll->off = ll->off & PKT_OFFSET_MASK;
  if ((void *)(ll->head + ll->off + 1) >
      (void *)((unsigned long long)(ll->xdp->data_end))) {
    ll->__loop_ret_flag = 1;
    ll->__loop_ret_val = (int)0;
    return (1);
  }
  if (ll->head[ll->off] == '\n') {
    ll->found = 1;
    return (1);
  }
  ll->off++;
  return (0);
}

static long _new_loop_0_func(unsigned int index, void *arg) {
  struct _new_loop_0_ctx *ll = arg;
  if (!(ll->off < 255 && ll->off < ll->rsize)) {
    return (1);
  }
  ll->off = ll->off & PKT_OFFSET_MASK;
  if ((void *)(ll->head + ll->off + 1) >
      (void *)((unsigned long long)(ll->xdp->data_end))) {
    ll->__loop_ret_flag = 1;
    ll->__loop_ret_val = (int)0;
    return (1);
  }
  if (ll->head[ll->off] == '\n') {
    ll->found = 1;
    return (1);
  }
  ll->off++;
  return (0);
}

static inline int my_bpf_strncmp(char *str1, char *str2, unsigned short len) {
  struct my_bpf_strncmp_loop_ctx ll = {
      .i = 0,
      .str1 = str1,
      .str2 = str2,
      .len = len,
      .ret = -(10000),
  };
  bpf_loop(256, my_bpf_strncmp_loop, &ll, 0);
  return ll.ret;
}

static inline void bpf_memcpy(char *dest, char *src, unsigned short n,
                              void *end_dest, void *end_src) {
  /* DEBUG("N is %d", n); */
  /* if (n == 0) { */
  /*   DEBUG("N is zero"); */
  /*   return; */
  /* } */
  struct bpf_memcpy_ctx ll = {
      .i = 0,
      .dest = dest,
      .src = src,
      .n = n,
      .end_dest = end_dest,
      .end_src = end_src,
  };
  bpf_loop(256, bpf_memcpy_loop, &ll, 0);

  /* for (__u16 i = 0; i < n && i < 1024; i++) { */
  /*   if (src + i + 1 > end_src) return; */
  /*   if (dest + i + 1 > end_dest) return; */
  /*   dest[i] = src[i]; */
  /* } */
}

static inline void my_atoi(short num, char *buf, int *res_size) {
  if (num == 0) {
    buf[0] = '0';
    *res_size = 1;
    return;
  }
  int i;
  int size;
  char tmp[6];
  for (i = 0; i < 5 && num > 0; i++) {
    tmp[i] = '0' + (num % 10);
    num = num / 10;
  }
  *res_size = i;
  buf[i] = '\0';
  i--;
  size = i;
  for (; i >= 0; i--) {
    buf[size - i] = tmp[i];
  }
  return;
}

__attribute__((noinline)) __attribute__((optnone))
static void handle_set(struct parsed_request *preq,
                              struct xdp_md *xdp, char *__send_flag,
                              char *__fail_flag) {
  int _tmp_118;
  int _tmp_117;
  struct item *_tmp_116;
  struct item *it;
  char wbuf2[32];
  char *value;
  value = preq->value;
  __u32 value_size = preq->value_size;
  __u32 key_size = preq->key_size;
  _tmp_117 = __fnv_hash(preq->key, key_size, (void *)(unsigned long long)(xdp->data_end)) % 1024;
  /* DEBUG("key index: %d", _tmp_117); */
  _tmp_116 = bpf_map_lookup_elem(&my_cache_map, &_tmp_117);
  if (_tmp_116 != NULL) {
    if (preq->key_size > 255) {
      return;
    }
    /* bpf_memcpy(_tmp_116->key, preq->key, preq->key_size, */
    /*            (void *)(_tmp_116 + 1), */
    /*            (void *)(xdp->data_end)); */

    for (__u16 i = 0; i < key_size && i < 255; i++) {
      /* DEBUG("%d:%c", i, preq->key[i]); */
      _tmp_116->key[i] = preq->key[i];
    }
    _tmp_116->key_size = key_size;
    value_size = value_size & PKT_OFFSET_MASK;
    if (value_size > 255) {
      return;
    }
    /* bpf_memcpy(_tmp_116->value, value, preq->value_size, */
    /*            (void *)(_tmp_116 + 1), */
    /*            (void *)(xdp->data_end)); */
    long long i = 0;
    DEBUG("value_size: %d", value_size);
    if (i >= value_size) {
      DEBUG("BOOM;%d;%d", i, value_size);
    } else {
      DEBUG("OKAY;%d;%d", i, value_size);
    }
    for (; i < value_size && i < 1024; i++) {
      DEBUG("%d:%c", i, preq->value[i]);
      _tmp_116->value[i] = value[i];
    }
    _tmp_116->value_size =value_size;
    /* DEBUG("i.key[%d]: %s", key_size, _tmp_116->key); */
    /* DEBUG("i.val[%d]: %s", value_size, _tmp_116->value); */
  }
  *__fail_flag = 2;
  /* Return from this point to the caller */
  return;
}

static inline unsigned short prepare_get_resp(char *wbuf, struct item *it) {
  unsigned short size;
  char *head;
  char ascii_val_size[8];
  int ascii_val_size_len;
  my_atoi(it->value_size, (char *)(ascii_val_size), &ascii_val_size_len);
  size = 0;
  head = wbuf;
  memcpy(head, "VALUE ", 6);
  size += 6;
  bpf_memcpy(head + size, it->key, it->key_size, head + size + it->key_size,
             it->key + it->key_size);
  size += it->key_size;
  size = size & 0xfff;
  if (size > sizeof(struct item)) return 0;
  head[size] = ' ';
  size += 1;
  bpf_memcpy(head + size, ascii_val_size, ascii_val_size_len,
             head + size + ascii_val_size_len,
             ascii_val_size + ascii_val_size_len);
  size += ascii_val_size_len;
  size = size & 0xfff;
  if (size > sizeof(struct item)) return 0;
  head[size] = '\n';
  size += 1;
  bpf_memcpy(head + size, it->value, it->value_size,
             head + size + it->value_size, it->value + it->value_size);
  size += it->value_size;
  size = size & 0xfff;
  if (size > sizeof(struct item)) return 0;
  memcpy(head + size, "\nEND\n", 5);
  size += 5;
  return (size);
}


__attribute__((__always_inline__))
static inline void handle_get(struct parsed_request *preq,
                              struct xdp_md *xdp, char *__send_flag,
                              char *__fail_flag) {
  int _tmp_106;
  int _tmp_105;
  struct item *_tmp_104;
  int _tmp_103;
  int wsize;
  struct item *it;
  _tmp_103 = __fnv_hash((__u8 *)preq->key, preq->key_size,
                        (void *)(__u64)(xdp->data_end)) % 1024;
  _tmp_104 = bpf_map_lookup_elem(&my_cache_map, &_tmp_103);
  _tmp_105 = 1;
  if (_tmp_104 != NULL) {
    if (_tmp_104->key_size == preq->key_size) {
      _tmp_106 = my_bpf_strncmp(_tmp_104->key, preq->key, preq->key_size);
      if (_tmp_106 == 0) {
        it = _tmp_104;
        _tmp_105 = 0;
      }
    }
  }
  if (_tmp_105) {
    *__fail_flag = 1;
    /* Return from this point to the caller */
    return;
  }
  if (it == ((void *)(NULL))) {
    int _tmp_114;
    _tmp_114 = 4 + DATA_OFFSET -
               (unsigned short)((void *)((unsigned long long)(xdp->data_end)) -
                                (void *)((unsigned long long)(xdp->data +
                                                              DATA_OFFSET)));
    bpf_xdp_adjust_tail(xdp, _tmp_114);
    if ((void *)((unsigned long long)(xdp->data + DATA_OFFSET)) + 4 >
        (void *)((unsigned long long)(xdp->data_end))) {
      return;
    }
    memcpy((void *)((unsigned long long)(xdp->data + DATA_OFFSET)), "END\n", 4);
    *__send_flag = 1;
    return;
  } else {
    struct stack_obj_1 *_tmp_113 = NULL;
    {
      const int zero = 0;
      _tmp_113 = bpf_map_lookup_elem(&stack_obj_1_map, &zero);
      if (_tmp_113 == NULL) {
        return;
      }
    }
    char *wbuf1;
    wbuf1 = _tmp_113->data;

    wsize = prepare_get_resp(wbuf1, it);
    int _tmp_115;
    _tmp_115 = wsize + DATA_OFFSET -
               (unsigned short)((void *)((unsigned long long)(xdp->data_end)) -
                                (void *)((unsigned long long)(xdp->data +
                                                              DATA_OFFSET)));
    bpf_xdp_adjust_tail(xdp, _tmp_115);
    if ((void *)((unsigned long long)(xdp->data + DATA_OFFSET)) + wsize >
        (void *)((unsigned long long)(xdp->data_end))) {
      return;
    }
    bpf_memcpy((void *)((unsigned long long)(xdp->data + DATA_OFFSET)), wbuf1,
               wsize, (void *)((unsigned long long)(xdp->data_end)),
               wbuf1 + wsize);
    *__send_flag = 1;
    return;
  }
  return;
}

static inline int parse_request(char *buffer, unsigned short size,
                                struct parsed_request *preq,
                                struct xdp_md *xdp) {
  unsigned short rsize;
  int off;
  char found;
  char *head;
  rsize = size;
  if ((void *)(buffer + 0 + 1) >
      (void *)((unsigned long long)(xdp->data_end))) {
    return ((int)0);
  }
  if (buffer[0] == 'g') {
    if ((void *)(buffer + 3 + 1) >
        (void *)((unsigned long long)(xdp->data_end))) {
      return ((int)0);
    }
    if (buffer[1] != 'e' || buffer[2] != 't' || buffer[3] != ' ') {
      return (-1);
    }
    head = &buffer[4];
    rsize -= 4;
    preq->kind = 'g';
    preq->key = head;
    found = 0;
    off = 0;
    struct _new_loop_0_ctx _tmp_119 = {.off = off,
                                       .rsize = rsize,
                                       .head = head,
                                       .found = found,
                                       .xdp = xdp,
                                       .__loop_ret_flag = (unsigned char)0,
                                       .__loop_ret_val = (int)0};
    bpf_loop(255, _new_loop_0_func, &_tmp_119, 0);
    off = _tmp_119.off;
    found = _tmp_119.found;
    if (_tmp_119.__loop_ret_flag != 0) {
      return (_tmp_119.__loop_ret_val);
    }
    if (found == 0) {
      return (-1);
    }
    off = off & PKT_OFFSET_MASK;
    if ((void *)(head + off + 1) >
        (void *)((unsigned long long)(xdp->data_end))) {
      return ((int)0);
    }
    head[off] = '\0';
    preq->key_size = off;
    rsize -= off + 1;
    if (rsize != 0) {
      return (-1);
    }
    return (0);
  } else {
    if ((void *)(buffer + 0 + 1) >
        (void *)((unsigned long long)(xdp->data_end))) {
      return ((int)0);
    }
    if (buffer[0] == 's') {
      if ((void *)(buffer + 3 + 1) >
          (void *)((unsigned long long)(xdp->data_end))) {
        return ((int)0);
      }
      if (buffer[1] != 'e' || buffer[2] != 't' || buffer[3] != ' ') {
        return (-1);
      }
      head = &buffer[4];
      rsize -= 4;
      preq->kind = 's';
      preq->key = head;
      found = 0;
      off = 0;
      struct _new_loop_1_ctx _tmp_120 = {.off = off,
                                         .rsize = rsize,
                                         .head = head,
                                         .found = found,
                                         .xdp = xdp,
                                         .__loop_ret_flag = (unsigned char)0,
                                         .__loop_ret_val = (int)0};
      ;
      bpf_loop(255, _new_loop_1_func, &_tmp_120, 0);
      off = _tmp_120.off;
      found = _tmp_120.found;
      if (_tmp_120.__loop_ret_flag != 0) {
        return (_tmp_120.__loop_ret_val);
      }
      if (found == 0) {
        return (-1);
      }
      off = off & PKT_OFFSET_MASK;
      if ((void *)(head + off + 1) >
          (void *)((unsigned long long)(xdp->data_end))) {
        return ((int)0);
      }
      head[off] = '\0';
      preq->key_size = off;
      head = &head[off + 1];
      rsize -= off + 1;
      preq->value = head;
      found = 0;
      off = 0;
      struct _new_loop_2_ctx _tmp_121 = {.off = off,
                                         .rsize = rsize,
                                         .head = head,
                                         .found = found,
                                         .xdp = xdp,
                                         .__loop_ret_flag = (unsigned char)0,
                                         .__loop_ret_val = (int)0};
      ;
      bpf_loop(1024, _new_loop_2_func, &_tmp_121, 0);
      off = _tmp_121.off;
      found = _tmp_121.found;
      if (_tmp_121.__loop_ret_flag != 0) {
        return (_tmp_121.__loop_ret_val);
      }
      if (found == 0) {
        return (-1);
      }
      off = off & PKT_OFFSET_MASK;
      if ((void *)(head + off + 1) >
          (void *)((unsigned long long)(xdp->data_end))) {
        return ((int)0);
      }
      head[off] = '\0';
      preq->value_size = off;
      head = ((void *)(NULL));
      rsize -= off + 1;
      if (rsize != 0) {
        return (-1);
      }
      return (0);
    } else {
      return (-1);
    }
  }
  return (-1);
}

SEC("xdp")
int xdp_prog(struct xdp_md *xdp) {
  /* DEBUG("in xdp"); */
  {
    void *data = (void *)(unsigned long long)xdp->data;
    void *data_end = (void *)(unsigned long long)xdp->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
      return XDP_PASS;
    if (udp->dest != bpf_htons(8080))
      return XDP_PASS;
  }
  /* DEBUG("new request"); */
  char __fail_flag = 0;
  char __send_flag = 0;
  int ret;
  char *rbuf;
  int req_size;
  rbuf = (void *)((unsigned long long)(xdp->data + DATA_OFFSET));
  req_size =
      (unsigned short)((void *)((unsigned long long)(xdp->data_end)) -
                       (void *)((unsigned long long)(xdp->data + DATA_OFFSET)));
  if (req_size <= 0) {
    return (XDP_DROP);
  }
  struct parsed_request _preq;
  struct parsed_request *preq = &_preq;
  memset(preq, 0, sizeof(struct parsed_request));
  ret = parse_request(rbuf, req_size, preq, xdp);
  if (ret != 0) {
    return (XDP_DROP);
  }
  /* DEBUG("Parsed packet: %c", preq->kind); */
  /* DEBUG("key[%d]  | %s", preq->key_size, preq->key); */
  /* DEBUG("value[%d]| %s", preq->value_size, preq->value); */
  switch (preq->kind) {
  case ('g'):
    handle_get(preq, xdp, &__send_flag, &__fail_flag);
    /* check if function fail */
    int _tmp_109;
    switch (__fail_flag) {
    case (0):
      /* No errors */
      break;
    case (1):
      return XDP_PASS;
    }
    if (__send_flag != 0) {
      __prepare_headers_before_send(xdp);
      return (XDP_TX);
    }
    break;
  case ('s'):
    handle_set(preq, xdp, &__send_flag, &__fail_flag);
    /* check if function fail */
    switch (__fail_flag) {
    case (0):
      break;
    case (2):
      return XDP_PASS;
    }
    if (__send_flag != 0) {
      __prepare_headers_before_send(xdp);
      return (XDP_TX);
    }
    break;
  }
  return (XDP_DROP);
}

char _license[] SEC("license") = "GPL";
