#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#define ITEM_CAS 2
#define ITEM_CFLAGS 256
#define ITEM_suffix(item) ((char*) &((item)->data) + (item)->nkey + 1 \
		+ (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define FLAGS_CONV(it, flag) { \
	if ((it)->it_flags & ITEM_CFLAGS) { \
		flag = *((uint32_t *)ITEM_suffix((it))); \
	} else { \
		flag = 0; \
	} \
}

typedef unsigned int rel_time_t ;

typedef struct _stritem {
	/* Protected by LRU locks */
	struct _stritem *next;
	struct _stritem *prev;
	/* Rest are protected by an item lock */
	struct _stritem *h_next;    /* hash chain next */
	rel_time_t      time;       /* least recent access */
	rel_time_t      exptime;    /* expire time */
	int             nbytes;     /* size of data */
	unsigned short  refcount;
	uint16_t        it_flags;   /* ITEM_* above */
	uint8_t         slabs_clsid;/* which slab class we're in */
	uint8_t         nkey;       /* key length, w/terminating null and padding */
	/* this odd type prevents type-punning issues when we do
	 * the little shuffle to save space when not using CAS. */
	union {
		uint64_t cas;
		char end;
	} data[];
	/* if it_flags & ITEM_CAS we have 8 bytes CAS */
	/* then null-terminated key */
	/* then " flags length\r\n" (no terminating null) */
	/* then data with terminating \r\n (no terminating null; it's binary!) */
} item;


item *do_get_it(void)
{
	item *it = calloc(1, sizeof(item));
	assert(it != NULL);
	return it;
}

void fancy(void) {
	int flags;
	item *old_it = do_get_it();
	FLAGS_CONV(old_it, flags);
}


int main(int argc, char *argv[])
{

	fancy();
	return 0;
}
