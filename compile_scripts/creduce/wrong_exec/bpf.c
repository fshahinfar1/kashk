#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif
#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif
#ifndef memset
#define memset(d, s, len) __builtin_memset(d, s, len)
#endif
typedef char bool;
#define PKT_OFFSET_MASK 0xfff
#define MAX_PACKET_SIZE 1472
#define DATA_OFFSET  (sizeof(struct ethhdr) + sizeof(struct iphdr) \
		+ sizeof(struct udphdr))

#define DEBUG(...) bpf_printk(__VA_ARGS__)

#include "csum_helper.h"

/* A helper for sending responses */
static inline int
__prepare_headers_before_send(struct xdp_md *xdp)
{
	struct ethhdr *eth = (void *)(unsigned long long)xdp->data;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	if ((void *)(udp + 1) > (void *)(unsigned long long)xdp->data_end)
		return -1;
	/* Swap MAC */
	unsigned char tmp;
	for (int i = 0; i < 6; i++) {
		tmp = eth->h_source[i];
		eth->h_source[i] = eth->h_dest[i];
		eth->h_dest[i] = tmp;
	}
	/* Swap IP */
	unsigned int tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;
	/* Swap port */
	unsigned short tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;

	const unsigned short new_packet_len = ((unsigned long long)xdp->data_end
			- (unsigned long long)xdp->data);
	const unsigned short new_ip_len  = new_packet_len - sizeof(struct ethhdr);
	const unsigned short new_udp_len = new_ip_len - sizeof(struct iphdr);
	unsigned long long csum;

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
	/* ipv4_l4_csum_inline((void *)(unsigned long long)xdp->data_end, udp, ip, */
	/*     &csum); */
	/* udp->check = bpf_ntohs(csum); */

	/* no checksum */
	udp->check = 0;
	/* bpf_printk("data: %s", (char *)(unsigned long long)xdp->data + DATA_OFFSET); */
	return 0;
}
/* ---------------------------------------------------------------- */

struct context {
	int fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
};

struct parsed_request {
	char kind;
	char * key;
	unsigned short key_size;
	char * value;
	unsigned short value_size;
};

struct item {
	unsigned short key_size;
	unsigned short value_size;
	char key[255];
	char value[255];
};

struct bucket {
	struct item list[8];
};

struct stack_obj_1 {
	char data[2048];
};

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   unsigned int);
	__type(value, struct stack_obj_1);
	__uint(max_entries, 1);
} stack_obj_1_map SEC(".maps");

struct bpf_memcpy_ctx {
	unsigned short i;
	unsigned short n;
	char *dest;
	char *src;
};

/* NOTE: it is important to disable optimization for this function. weird
 * things are happening here.
 * */
static long __attribute__((noinline, optnone))
bpf_memcpy_loop(unsigned int index, void *arg)
{
	int diff;
	struct bpf_memcpy_ctx *ll = arg;
	/* NOTE: using index provided by the BPF loop does not pass the
	 * verifier. I have to define the loop variable on the context and
	 * increment it my self.
	 * */
	ll->dest[ll->i] = ll->src[ll->i];
	ll->i++;
	/* NOTE: value comparison was not working correctly. I had to calculate
	 * the diff and compare it with zero. Am I making a stupid mistake or
	 * is there a bug with the bpf_loop?
	 * */
	diff = ll->i - ll->n;
	if (diff >= 0) {
		return 1;
	}
	return 0;
}

struct _new_loop_0_ctx {
	int off;
	unsigned short rsize;
	char * head;
	char found;
	struct xdp_md * xdp;
	char loop_ret_flag;
	int loop_ret_val;
};

struct _new_loop_1_ctx {
	int off;
	unsigned short rsize;
	char * head;
	char found;
	struct xdp_md * xdp;
	char loop_ret_flag;
	int loop_ret_val;
};

struct _new_loop_2_ctx {
	int off;
	unsigned short rsize;
	char * head;
	char found;
	struct xdp_md * xdp;
	char loop_ret_flag;
	int loop_ret_val;
};

/* The globaly shared state is in this structure */
struct shared_state {
	struct bucket hash_table[1024];
	int fd;
	struct sockaddr_in sk_addr;
};

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, struct shared_state);
	__uint(max_entries, 1);
} shared_map SEC(".maps");

static long __attribute__((noinline, optnone))
_new_loop_2_func (unsigned int index, void * arg) {
	struct _new_loop_2_ctx * ll = arg;
	if (!(ll->off < 1024 && ll->off < ll->rsize)) {
		return (1);
	}
	ll->off = ll->off & PKT_OFFSET_MASK;
	if ((void *)(ll->head + ll->off + 1) > (void *)((unsigned long long)(ll->xdp->data_end))) {
		ll->loop_ret_flag = 1;
		ll->loop_ret_val = -1;
		return (1);
	}
	if (ll->head[ll->off] == '\n') {
		ll->found = 1;
		return (1);
	}
	ll->off++;
	return (0);
}

static long __attribute__((noinline, optnone))
_new_loop_1_func (unsigned int index, void * arg) {
	struct _new_loop_1_ctx * ll = arg;
	if (!(ll->off < 255 && ll->off < ll->rsize)) {
		return (1);
	}
	ll->off = ll->off & PKT_OFFSET_MASK;
	if ((void *)(ll->head + ll->off + 1) > (void *)((unsigned long long)(ll->xdp->data_end))) {
		ll->loop_ret_flag = 1;
		ll->loop_ret_val = -1;
		return (1);
	}
	if (ll->head[ll->off] == '\n') {
		ll->found = 1;
		return (1);
	}
	ll->off++;
	return (0);
}

static long __attribute__((noinline, optnone))
_new_loop_0_func (unsigned int index, void * arg) {
		struct _new_loop_0_ctx * ll = arg;
		if (!(ll->off < 255 && ll->off < ll->rsize)) {
			return (1);
		}
		ll->off = ll->off & PKT_OFFSET_MASK;
		if ((void *)(ll->head + ll->off + 1) > (void *)((unsigned long long)(ll->xdp->data_end))) {
			ll->loop_ret_flag = 1;
			ll->loop_ret_val = -1;
			return (1);
		}
		if (ll->head[ll->off] == '\n') {
			ll->found = 1;
			return (1);
		}
		ll->off++;
		return (0);
	}

static void
bpf_memcpy (char * dest, char * src, unsigned int n)
{
	/* NOTE: I want to do the n == 0 check and return immidietly, but,
	 * weird things happen when I uncomment this part of the code
	 * */
	bpf_printk("BPF MEMCPY n=%d", n);
	if (n == 0) {
		bpf_printk("n is zero n=%d", n);
		return;
	}
	/* DEBUG("BPF MEMCPY"); */

	struct bpf_memcpy_ctx ll = {};
	ll.i = 0;
	ll.n = n;
	ll.dest = dest;
	ll.src = src;
	bpf_loop(256, bpf_memcpy_loop, &ll, 0);
}

static void
my_itoa (short num, char * buf, int * res_size) {
	if (num == 0) {
		buf[0] = '0';
		*res_size = 1;
		return;
	}
	int i;
	int size;
	char tmp[6];
	for(i = 0; i < 5 && num > 0; i++) {
		tmp[i] = '0' + (num % 10);
		num = num / 10;
	}
	*res_size = i;
	buf[i] = '\0';
	i--;
	size = i;
	for(; i >= 0; i--) {
		buf[size - i] = tmp[i];
	}
	return;
}

static inline
unsigned int calc_hash (char * key, unsigned short size) {
	return (123);
}

static inline int
is_match (struct item * it, char * key, unsigned short key_size) {
	int ret;
	if (it->key_size != key_size) {
		return (0);
	}
	ret = 1; /* assume there is a difference initially */
	for (int i = 0; i < 256 && i < key_size; i++) {
		ret = it->key[i] - key[i];
		if (ret != 0) {
			break;
		}
	}
	/* ret = my_bpf_strncmp(it->key, key, key_size); */
	return ret == 0;
}

static unsigned short
prepare_get_resp (char * wbuf, struct item * it)
{
	unsigned short size;
	char * head;
	char ascii_val_size[8];
	int ascii_val_size_len;
	my_itoa(it->value_size, (char *)(ascii_val_size), &ascii_val_size_len);
	size = 0;
	head = wbuf;
	memcpy(head, "VALUE ", 6);
	size += 6;
	bpf_memcpy(head + size, it->key, it->key_size);
	size += it->key_size;
	size = size & 0xfff;
	if (size >= sizeof(struct stack_obj_1)) {
		return 0;
	}
	head[size] = ' ';
	size += 1;
	size = size & 0xfff;
	if (size >= sizeof(struct stack_obj_1)) {
		return 0;
	}
	bpf_memcpy(head + size, ascii_val_size, ascii_val_size_len);
	size += ascii_val_size_len;
	size = size & 0xfff;
	if (size >= sizeof(struct stack_obj_1)) {
		return 0;
	}
	head[size] = '\n';
	size += 1;
	size = size & 0xfff;
	if (size >= sizeof(struct stack_obj_1)) {
		return 0;
	}
	bpf_memcpy(head + size, it->value, it->value_size);
	size += it->value_size;
	size = size & 0xfff;
	if (size + 5 > sizeof(struct stack_obj_1)) {
		return 0;
	}
	memcpy(head + size, "\nEND\n", 5);
	size += 5;
	return (size);
}

static struct item *
lookup (char * key, unsigned short size)
{
	unsigned int hash;
	unsigned int bucket_index;
	struct bucket * bucket;
	struct item * head;
	hash = calc_hash(key, size);
	bucket_index = hash % 1024;
	struct shared_state * shared = NULL;
	unsigned int zero = 0;
	shared = bpf_map_lookup_elem(&shared_map, &zero);
	if (shared == NULL) {
		return NULL;
	}
	bucket = &shared->hash_table[bucket_index];
	int i;
	for(i = 0; i < 8; i++) {
		head = &bucket->list[i];
		int _tmp_100;
		_tmp_100 = is_match(head, key, size);
		if (_tmp_100) {
			return (head);
		}
	}
	return (((void *)(NULL)));
}

static struct item *
update (char * key, unsigned short key_size, char * value,
		unsigned short value_size)
{
	unsigned int hash;
	unsigned int bucket_index;
	struct bucket * bucket;
	struct item * head;
	char found;
	found = 0;
	hash = calc_hash(key, key_size);
	bucket_index = hash % 1024;
	struct shared_state * shared = NULL;
	int zero = 0;
	shared = bpf_map_lookup_elem(&shared_map, &zero);
	if (shared == NULL) {
		return NULL;
	}
	bucket = &shared->hash_table[bucket_index];
	int i;
	for(i = 0; i < 8; i++) {
		head = &bucket->list[i];
		if (head->key_size > 0) {
			int _tmp_101;
			_tmp_101 = is_match(head, key, key_size);
			if (_tmp_101) {
				found = 1;
				break;
			} else {
				continue;
			}
		} else {
			found = 1;
			break;
		}
	}
	if (found) {
		head->key_size = key_size;
		head->value_size = value_size;
		bpf_memcpy(head->key, key, key_size);
		bpf_memcpy(head->value, value, value_size);
		DEBUG("Copy key and values on an item");
		DEBUG("item key [%d]:   %s", head->key_size, head->key);
		DEBUG("item value [%d]: %s", head->value_size, head->value);
		return (head);
	}
	return NULL;
}

static inline void
handle_set (struct parsed_request * preq, struct xdp_md * xdp,
		char * __send_flag)
{
	struct item * it;
	it = update(preq->key, preq->key_size, preq->value, preq->value_size);
	if (it == ((void *)(NULL))) {
		int _tmp_106;
		_tmp_106 = DATA_OFFSET + 15
			- (unsigned short)((unsigned long long)(xdp->data_end)
					- (unsigned long long)(xdp->data));
		bpf_xdp_adjust_tail(xdp, _tmp_106);
		if ((void *)((unsigned long long)(xdp->data)) + DATA_OFFSET + 15 > (void *)((unsigned long long)(xdp->data_end))) {
			return;
		}
		memcpy((void *)((unsigned long long)(xdp->data)) + DATA_OFFSET,
				"NOT_STORED\nEND\n", 15);
		*__send_flag = 1;
		return;
	} else {
		DEBUG("Successful update");
		int _tmp_107;
		_tmp_107 = DATA_OFFSET + 11
			- (unsigned short)((unsigned long long)(xdp->data_end)
					- (unsigned long long)(xdp->data));
		bpf_xdp_adjust_tail(xdp, _tmp_107);
		if ((void *)((unsigned long long)(xdp->data)) + DATA_OFFSET + 11 > (void *)((unsigned long long)(xdp->data_end))) {
			DEBUG("Out of range after resizing");
			return;
		}
		memcpy((void *)((unsigned long long)(xdp->data + DATA_OFFSET)),
				"STORED\nEND\n", 11);
		*__send_flag = 1;
		return;
	}
	return;
}

static int __attribute__((noinline))
parse_request (char * buffer, unsigned short size,
		struct parsed_request * preq, struct xdp_md * xdp)
{
	unsigned short rsize;
	int off;
	char found;
	char * head;
	rsize = size;
	if ((void *)(buffer + 0 + 1) > (void *)((unsigned long long)(xdp->data_end))) {
		return (-1);
	}
	if (buffer[0] == 'g') {
		if ((void *)(buffer + 3 + 1) > (void *)((unsigned long long)(xdp->data_end))) {
			return (-1);
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

		struct _new_loop_0_ctx _tmp_108 = {
			.off = off,
			.rsize = rsize,
			.head = head,
			.found = found,
			.xdp = xdp,
			.loop_ret_flag = 0,
			.loop_ret_val = 0,
		};
		bpf_loop(255, _new_loop_0_func, &_tmp_108, 0);
		off = _tmp_108.off;
		found = _tmp_108.found;
		if (_tmp_108.loop_ret_flag != 0) {
			/* TODO: I do not understand why there is a problem
			 * when returning the value from the struct
			 * */
			/* return _tmp_108.loop_ret_val; */
			return -1;
		}

		if (found == 0) {
			return (-1);
		}
		off = off & PKT_OFFSET_MASK;
		if ((void *)(head + off + 1) > (void *)((unsigned long long)(xdp->data_end))) {
			return (-1);
		}
		head[off] = '\0';
		preq->key_size = off;
		rsize -= off + 1;
		if (rsize != 0) {
			DEBUG("Remaining unparsed data %d", rsize);
			return (-1);
		}
		return (0);
	} else {
		if (buffer[0] == 's') {
			if ((void *)(buffer + 3 + 1) > (void *)((unsigned long long)(xdp->data_end))) {
				return (-1);
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
			struct _new_loop_1_ctx _tmp_109 = {};
			_tmp_109.off = off;
			_tmp_109.rsize = rsize;
			_tmp_109.head = head;
			_tmp_109.found = found;
			_tmp_109.xdp = xdp;
			_tmp_109.loop_ret_flag = 0;
			_tmp_109.loop_ret_val = 0;
			bpf_loop(256, _new_loop_1_func, &_tmp_109, 0);
			off = _tmp_109.off;
			found = _tmp_109.found;
			/* TODO: this memset is here to satisfy the verifier */
			memset(&_tmp_109, 0, sizeof(_tmp_109));
			if (_tmp_109.loop_ret_flag == 1) {
				return (_tmp_109.loop_ret_val);
				/* return -1; */
			}
			if (found == 0) {
				return (-1);
			}
			off = off & PKT_OFFSET_MASK;
			if ((void *)(head + off + 1) > (void *)((unsigned long long)(xdp->data_end))) {
				return (-1);
			}
			head[off] = '\0';
			preq->key_size = off;
			head = &head[off + 1];
			rsize -= off + 1;
			preq->value = head;
			found = 0;
			off = 0;
			struct _new_loop_2_ctx _tmp_110 = {
				.off = off,
				.rsize = rsize,
				.head = head,
				.found = found,
				.xdp = xdp,
				.loop_ret_flag = 0,
				.loop_ret_val = 0,
			};;
			bpf_loop(256, _new_loop_2_func, &_tmp_110, 0);
			off = _tmp_110.off;
			found = _tmp_110.found;
			memset(&_tmp_109, 0, sizeof(_tmp_110));
			if (_tmp_110.loop_ret_flag == 1) {
				return (_tmp_110.loop_ret_val);
				/* return -1; */
			}
			if (found == 0) {
				return (-1);
			}
			off = off & PKT_OFFSET_MASK;
			if ((void *)(head + off + 1) > (void *)((unsigned long long)(xdp->data_end))) {
				return (-1);
			}
			head[off] = '\0';
			preq->value_size = off;
			head = ((void *)(NULL));
			rsize -= off + 1;
			if (rsize != 0) {
				return (-1);
			}
			/* DEBUG("%d %d", preq->key_size, preq->value_size); */
			return (0);
		} else {
			/* Invalid request */
			return (-1);
		}
	}
	/* bpf_printk("parsing end of func!"); */
	return (-1);
}

static inline void
handle_get (struct parsed_request * preq, struct xdp_md * xdp,
		char * __send_flag)
{
	struct item * it;
	it = lookup(preq->key, preq->key_size);
	if (it == NULL) {
		DEBUG("Failed lookup");
		int _tmp_103;
		const short current_packet_length = (unsigned short)((unsigned long long)(xdp->data_end) - (unsigned long long)(xdp->data));
		const short target_packet_length = DATA_OFFSET + 4;
		_tmp_103 =  target_packet_length - current_packet_length;
		bpf_xdp_adjust_tail(xdp, _tmp_103);
		if ((void *)((unsigned long long)(xdp->data + DATA_OFFSET)) + 4 > (void *)((unsigned long long)(xdp->data_end))) {
			/* bpf_printk("failed after resizing the packet"); */
			return;
		}
		memcpy((void *)((unsigned long long)(xdp->data + DATA_OFFSET)), "END\n", 4);
		*__send_flag = 1;
		return;
	} else {
		DEBUG("Successful lookup");
		DEBUG("item key [%d]:   %s", it->key_size, it->key);
		DEBUG("item value: %s", it->value);
		struct stack_obj_1 * _tmp_102 = NULL;
		const int zero = 0;
		_tmp_102 = bpf_map_lookup_elem(&stack_obj_1_map, &zero);
		if (_tmp_102 == NULL) {
			return ;
		}
		int wsize;
		char * wbuf;
		wbuf = _tmp_102->data;
		wsize = prepare_get_resp(wbuf, it);
		int _tmp_104;
		_tmp_104 = wsize - (unsigned short)((unsigned long long)(xdp->data_end) - (unsigned long long)(xdp->data + DATA_OFFSET));
		bpf_xdp_adjust_tail(xdp, _tmp_104);
		if ((void *)((unsigned long long)(xdp->data + DATA_OFFSET)) + wsize > (void *)((unsigned long long)(xdp->data_end))) {
			return;
		}
		bpf_memcpy((void *)((unsigned long long)(xdp->data + DATA_OFFSET)), wbuf, wsize);
		*__send_flag = 1;
		return;
	}
	return;
}

SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{
	/* DEBUG("In XDP"); */
	/* Check the program is processing the right packets */
	void *data = (void *)(unsigned long long)xdp->data;
	void *data_end = (void *)(unsigned long long)xdp->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip  = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip  + 1);
	if ((void *)(udp + 1) > data_end) return XDP_PASS;
	if (udp->dest != bpf_htons(8080)) return XDP_PASS;
	DEBUG("Recv target packet");

	char __send_flag = 0;
	int ret;
	char * rbuf;
	int req_size;
	rbuf = (void *)((unsigned long long)(xdp->data + DATA_OFFSET));
	req_size = (unsigned short)((unsigned long long)(xdp->data_end)
			- (unsigned long long)(xdp->data + DATA_OFFSET));
	struct parsed_request preq = {};
	ret = parse_request(rbuf, req_size, &preq, xdp);
	if (ret != 0) {
		DEBUG("Parsing failed");
		return XDP_DROP;
	}
	DEBUG("Parsed packet: %c", preq.kind);
	DEBUG("key[%d]:   %s", preq.key_size, preq.key);
	DEBUG("value[%d]: %s", preq.value_size, preq.value);

	switch (preq.kind) {
		case ('g'):
			handle_get(&preq, xdp, &__send_flag);
			if (__send_flag != 0) {
				if (__prepare_headers_before_send(xdp) == 0) {
					DEBUG("Send a response");
					return (XDP_TX);
				} else {
					DEBUG("Failed to prepare the headers");
					return XDP_DROP;
				}
			}
			break;
		case ('s'):
			handle_set(&preq, xdp, &__send_flag);
			if (__send_flag != 0) {
				ret = __prepare_headers_before_send(xdp);
				if (ret == 0 ) {
					DEBUG("Send a response");
					return (XDP_TX);
				} else {
					DEBUG("Failed to prepare the headers");
					return XDP_DROP;
				}
			}
			break;
	}
	DEBUG("End of XDP");
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
