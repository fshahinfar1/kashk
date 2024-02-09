#include "./commons.h"
SEC("xdp")
int prog(struct xdp_md *xdp)
{
	void *data = (void *)(unsigned long long)xdp->data;
	void *data_end = (void *)(unsigned long long)xdp->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip  = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip  + 1);
	if ((void *)(udp + 1) > data_end) return XDP_PASS;
	if (udp->dest != bpf_htons(8080)) return XDP_PASS;
	/* __u32 tmp = 0; */
	/* void *data = (void *)(__u64)xdp->data; */
	/* void *data_end = (void *)(__u64)xdp->data_end; */
	/* struct ethhdr *eth = data; */
	/* struct iphdr *ip = (void *)(eth + 1); */
	/* struct udphdr *udp = (void *)(ip + 1); */
	/* if ((void *)(udp + 1) > data_end) { */
	/* 	return XDP_DROP; */
	/* } */

	/* tmp = *(__u32 *)eth->h_dest */
	/* *(__u32 *)eth->h_dest = *(__u32 *)eth->h_source; */
	/* *(__u32 *)eth->h_source = tmp; */
	/* tmp = 0; */
	/* tmp = *(__u16 *)&eth->h_dest[4]; */
	/* *(__u16 *)&eth->h_dest[4] = *(__u16 *)&eth->h_source[4]; */
	/* *(__u16 *)&eth->h_source[4] = tmp; */

	/* tmp = 0; */
	/* tmp = ip->daddr; */
	/* ip->daddr = ip->saddr; */
	/* ip->saddr = ip->daddr; */

	/* tmp = 0; */
	/* tmp = udp->dest; */
	/* udp->dest = udp->source; */
	/* udp->source = tmp; */

	__prepare_headers_before_send(xdp);
	return XDP_TX;
}
