#ifndef __KASHK_ANNOTATION
#define __KASHK_ANNOTATION
struct __annotation { char *message; };
#define __ANNOTATE(msg) (struct __annotation){ .message = msg };
#define __ANNOTATE_SKIP __ANNOTATE("SKIP")

#endif
