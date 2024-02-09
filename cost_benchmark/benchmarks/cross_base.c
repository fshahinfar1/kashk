#include "./commons.h"

/* struct xdp_config { */
/*   int ifindex; */
/* }; */

/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_ARRAY); */
/* 	__type(key,  __u32); */
/* 	__type(value, struct xdp_config); */
/* 	__uint(max_entries, 1); */
/* } a_map SEC(".maps"); */

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

	__u64 *payload = (void *)(udp + 1);
	if ((void *)(payload + 2) > data_end) {
		bpf_printk("drop it");
		return XDP_DROP;
	}
	__u64 ts = bpf_ktime_get_ns();
	payload[1] = ts;
	udp->check = 0; /* The UDP checksum is wrong now, disable it */
	return XDP_PASS;

	/* const int zero = 0; */
	/* struct xdp_config *config = bpf_map_lookup_elem(&a_map, &zero); */
	/* if (config == NULL) { */
	/* 	return XDP_DROP; */
	/* } */

	/* struct ethhdr *eth = data; */
	/* if ((void *)(eth + 1) > data_end) { */
	/* 	return XDP_DROP; */
	/* } */
	/* bpf_printk("Packet size: %ld\n", (__u64)(xdp->data_end - xdp->data)); */
	/* bpf_printk("Src MAC: %x:%x:%x:", eth->h_source[0], eth->h_source[1], */
	/* 		eth->h_source[2]); */
	/* bpf_printk("%x:%x:%x\n", eth->h_source[3], eth->h_source[4], */
	/* 		eth->h_source[5]); */
	/* bpf_printk("Dest MAC: %x:%x:%x:", eth->h_dest[0], eth->h_dest[1], */
	/* 		eth->h_dest[2]); */
	/* bpf_printk("%x:%x:%x\n", eth->h_dest[3], eth->h_dest[4], */
	/* 		eth->h_dest[5]); */
	/* bpf_printk("Ether Type: %x\n", bpf_ntohs(eth->h_proto)); */
	/* if (eth->h_proto == bpf_htons(ETH_P_IP)) { */
	/* 	struct iphdr *ip = (struct iphdr *)(eth + 1); */
	/* 	if ((void *)(ip + 1) > data_end) { */
	/* 		return XDP_DROP; */
	/* 	} */
	/* 	// Swap IP */
	/* 	bpf_printk("Src IP: %x\n", bpf_ntohl(ip->saddr)); */
	/* 	bpf_printk("Dst IP: %x\n", bpf_ntohl(ip->daddr)); */
	/* 	bpf_printk("ip checksum: %d\n", ip->check); */
	/* 	bpf_printk("ip len: %d\n", bpf_ntohs(ip->tot_len)); */
	/* 	if (ip->protocol == IPPROTO_UDP) { */
	/* 		struct udphdr *udp = (void *)((__u64)xdp->data + */
	/* 				(sizeof(*eth) + (ip->ihl * 4))); */
	/* 		if ((void *)(udp + 1) > data_end) { */
	/* 			return XDP_DROP; */
	/* 		} */
	/* 		// struct udphdr *udp = (struct udphdr *)(ip + 1); */
	/* 		bpf_printk("Transport: UDP\n"); */
	/* 		bpf_printk("Src PORT: %d\n", bpf_ntohs(udp->source)); */
	/* 		bpf_printk("Dst PORT: %d\n", bpf_ntohs(udp->dest)); */
	/* 		bpf_printk("checksum: %d\n", udp->check); */
	/* 		bpf_printk("udp len: %d\n", bpf_ntohs(udp->len)); */
	/* 		payload = udp + 1; */
	/* 		bpf_printk("payload: %s\n", payload); */
	/* 	} */
	/* } */
	/* return bpf_redirect(config->ifindex, BPF_F_INGRESS); */
}

