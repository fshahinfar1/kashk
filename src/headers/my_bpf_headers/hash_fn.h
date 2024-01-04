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
