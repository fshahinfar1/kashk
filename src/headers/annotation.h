#ifndef __KASHK_ANNOTATION
#define __KASHK_ANNOTATION
struct __annotation {
	char *message; /* Information about annotation */
	int kind; /* What kind of annotation */
};
enum {
	ANN_SKIP,
	ANN_FUNC_PTR,
};
#define __ANNOTATE(_m, _k) (struct __annotation){ \
	.message = _m, \
	.kind = _k,  \
};
#define __ANNOTATE_SKIP __ANNOTATE("SKIP", ANN_SKIP)
#define __ANNOTATE_FUNC_PTR_IS(x, y) __ANNOTATE(x "-->" y, ANN_FUNC_PTR)

#endif
