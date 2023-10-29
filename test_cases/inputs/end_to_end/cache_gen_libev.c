#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>


/* [BPF Friendly Data Structure]
 * This is the structure I have defined for doing the caching
 * */
struct cached_resp {
	char data[1024];
	int size;
};

struct resp {
	char *ptr;
	int size;
};

struct conn {
	char *rbuf;
	int rsize;
	struct resp resp;
};

/* This is the function we want to memoize.
 *
 * Since the body of the function is not provided it would fail fallback to
 * userspace when this function is called.
 * */
char *lookup_hashtable(char *key, int key_len, void **val, unsigned short *val_len);
char *update_hashtable(char *key, int key_len, char *val, int val_len);

void event_handler(int fd, short which, void *arg)
{

	/* The cache protocol
	 * 1 byte of proto
	 * 2 byte of key size
	 * n bytes of key
	 * [2 byte of val size]
	 * [n2 byte of val]
	 * */

	char proto;
	unsigned short key_len;
	unsigned short val_len;
	char *key;
	char *val;
	unsigned int size;
	struct conn *c;
	struct sockaddr_in addr;
	socklen_t sock_addr_size;

	/*                      id,           key_kind,   key_t, key_size, value_kind, value_t,            value_size */
	__ANNOTATE_DEFINE_CACHE("main_cache", BYTE_ARRAY, "char", "0",       STRUCT,   "struct cached_resp", "1028")

	c = arg;
	sock_addr_size = sizeof(addr);
	size = recvfrom(fd, c->rbuf, c->rsize, 0, (struct sockaddr *)&addr, &sock_addr_size);
	if (size < 3) {
		return;
	}

	proto = c->rbuf[0];
	key_len = *(unsigned short *)&c->rbuf[1];
	key = &c->rbuf[3];

	/* TODO: what should I do about this? I should automaticall add these instructions */
	/* key_len = key_len & 0xfff; */

	switch (proto) {
		case 'G':
			/* Get request */
			__ANNOTATE_BEGIN_CACHE("main_cache", "key", "key_len", "val")
			lookup_hashtable(key, key_len, (void **)&val, &val_len);
			__ANNOTATE_END_CACHE("main_cache", "val = (char *)%p->data; val_len = %p->size;")
			if (val == NULL) {
				strncpy(c->rbuf, "Miss END\r\n", 10);
				sendto(fd, c->rbuf, 10, 0, (struct sockaddr *)&addr, sock_addr_size);
			} else {
				/* TODO: I need to automatically generate this check in the tool because the rbuf is a map */
				/* val_len = val_len & 0xfff; */
				/* if (val_len > 1000) */
				/* 	return; */
				strncpy(c->rbuf, val, val_len);
				sendto(fd, c->rbuf, val_len, 0, (struct sockaddr *)&addr, sock_addr_size);
			}
			break;
		case 'S':
			/* Set request */

			/* TODO: I should track that c->rbuf is a map pointer just like the BPF verifier */
			/* if (3 + key_len > 1000) */
			/* 	return; */

			val_len = *(unsigned short *)(c->rbuf + 3 + key_len);
			val = (c->rbuf + 3 + key_len + 2);

			/* TODO: what should I do about this? I should automaticall add these instructions */
			/* val_len = val_len & 0xfff; */
			/* if (val_len > 1000) return; */

			__ANNOTATE_BEGIN_UPDATE_CACHE("main_cache", "key", "key_len", "val", "val_len")
			update_hashtable(key, key_len, val, val_len);
			__ANNOTATE_END_UPDATE_CACHE("main_cache", ";")
			strncpy(c->rbuf, "Done END\r\n", 10);
			sendto(fd, c->rbuf, 10, 0, (struct sockaddr *)&addr, sock_addr_size);
			break;
		default:
			/* Wrong request */
			strncpy(c->rbuf, "Wrong END\r\n", 11);
			sendto(fd, c->rbuf, 11, 0, (struct sockaddr *)&addr, sock_addr_size);
			break;
	}
}

int main()
{
	struct conn c;
	c.rsize = 1024;
	c.rbuf = malloc(c.rsize);
	event_handler(0, 0, &c);
	return 0;
}

void _prepare_event_handler_args(void)
{
	/* This is telling me how to prepare the event handler */
	int fd = 0;
	short which = 0;
	struct conn _c;
	memset(&c, 0, sizeof(struct conn));
	/* _c.rsize = 1024; */
	/* _c.rbuf = malloc(1024); */
	void *arg = &_c;
}
