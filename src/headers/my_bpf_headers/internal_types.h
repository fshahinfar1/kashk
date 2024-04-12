#ifndef __KASHK_INTERNAL_TYPES_H
#define  __KASHK_INTERNAL_TYPES_H
struct connection_state;
struct __five_tuple {
	unsigned int proto;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int src_ip;
	unsigned int dst_ip;
} __attribute__((packed));

/* Context of a socket */
struct sock_context {
	unsigned int sock_map_index;
	struct connection_state state;
};
#endif
