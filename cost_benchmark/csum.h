#ifndef CSUM_H
#define CSUM_H
#include <arpa/inet.h>
#include <linux/ip.h>
static inline unsigned short
csum_fold_helper(unsigned long csum)
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
ipv4_csum_inline(void *iph, unsigned long *csum)
{
	unsigned int i;
	unsigned short *next_iph_u16 = (unsigned short *)iph;
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}
#endif
