#ifndef __KASHK_ANNOTATION
#define __KASHK_ANNOTATION
struct __annotation {
	char *message; /* Information about annotation */
	int kind; /* What kind of annotation */
};
enum {
	ANN_SKIP,
	ANN_FUNC_PTR,
	ANN_CACHE_BEGIN,
	ANN_CACHE_END,
};
#define __ANNOTATE(_m, _k) (struct __annotation){ \
	.message = _m, \
	.kind = _k,  \
};
#define __ANNOTATE_SKIP __ANNOTATE("SKIP", ANN_SKIP)
#define __ANNOTATE_FUNC_PTR_IS(x, y) __ANNOTATE(x "-->" y, ANN_FUNC_PTR)
#define __ANNOTATE_BEGIN_CACHE(id, key, key_size) __ANNOTATE("{id:\"" id "\", key:\"" key "\", key_size: \"" key_size "\"}", ANN_CACHE_BEGIN) 
#define __ANNOTATE_END_CACHE(id) __ANNOTATE("{id:\"" id "\"}", ANN_CACHE_END) 

#endif
