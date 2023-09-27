#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>
#include <event.h>

int main(int argc, char *argv[]) {
	struct ethhdr eth;
	/* This struct is private from the API point of view.
	 * The tool should understand this and treat this as private struct.
	 * (it is part of libevent)
	 * */
	struct event_base *ev;
	memset(&eth, 0, sizeof(eth));
	return 0;
}
