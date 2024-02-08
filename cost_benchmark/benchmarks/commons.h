#ifndef BENCHMARK_COMMONS_H
#define BENCHMARK_COMMONS_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "xdp_helper.h"
#include "hash_fn.h"

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
#define DATA_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
char _license[] SEC("license") = "GPL";
#endif


