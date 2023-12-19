#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define memset(b, c, d) __builtin_memset(b, c, d)
#define e(...) bpf_printk(__VA_ARGS__)

struct f {
  short g;
};

struct u {
  int l;
  char *head;
  char found;
  struct xdp_md *xdp;
};

static long loop(int index, void *arg) {
  struct u *ll = arg;
  if ((void *)(ll->head + 1) > (void *)(__u64)ll->xdp->data_end)
    return 0;
  if (ll->head[ll->l] == '\n') {
    ll->found = 1;
    return 0;
  }
  ll->l++;
  return 0;
}

/* NOTE: Allowing for optimization solves the issue for this simple program */
__attribute__((optnone))
static void test(struct f *n) {
  __u32 g = n->g;
  long i = 0;
  /* NOTE: removing the else block seems to solve the issue */
  if (i >= g)
    e("BOOM;%d;%d", i, g);
  else
    ;
}

int parse(char *b, struct f *n, struct xdp_md *xdp) {
  char *head = &b[4];
  struct u t = {
    .l = 0,
    .head = head,
    .found = 0,
    .xdp = xdp
  };
  /* NOTE: It seems for iters=25 is the smallest value that causes the bug */
  bpf_loop(55, loop, &t, 0);
  if (t.found == 0)
    return 0;
  n->g = t.l;
  return 0;
}

SEC("xdp")
void xdp_prog(struct xdp_md *xdp) {
  char *q = (void *)(__u64)xdp->data + sizeof(struct iphdr) +
    sizeof(struct udphdr);
  struct f r;
  memset(&r, 0, sizeof(struct f));
  parse(q, &r, xdp);
  test(&r);
}

char s[] SEC("license") = "GPL";
