#ifndef __KASHK_ANNOTATION
#define __KASHK_ANNOTATION
struct __annotation {
	char *message; /* Information about annotation */
	int kind; /* What kind of annotation */
};
enum {
	ANN_SKIP,
	ANN_FUNC_PTR,
	ANN_CACNE_DEFINE,
	ANN_CACHE_BEGIN,
	ANN_CACHE_END,
};
#define __ANNOTATE(_m, _k) (struct __annotation){ \
	.message = _m, \
	.kind = _k,  \
};
#define __ANNOTATE_SKIP __ANNOTATE("SKIP", ANN_SKIP)
#define __ANNOTATE_FUNC_PTR_IS(x, y) __ANNOTATE(x "-->" y, ANN_FUNC_PTR)

#define JSON_FIELD(k,v) "\""k"\": \""v"\""
#define JSON_COMMA ","
#define JSON_FIELD_MID(k,v) JSON_FIELD(k,v) JSON_COMMA

#define BYTE_ARRAY "BYTE_ARRAY"
#define STRUCT     "STRUCT"

#define __ANNOTATE_DEFINE_CACHE(id, key_kind, key_t, key_size, value_kind, value_t, value_size) \
	__ANNOTATE("{" \
			JSON_FIELD_MID("id", id) \
			JSON_FIELD_MID("key_kind", key_kind) \
			JSON_FIELD_MID("key_type", key_t) \
			JSON_FIELD_MID("key_size", key_size) \
			JSON_FIELD_MID("value_kind", value_kind) \
			JSON_FIELD_MID("value_type", value_t) \
			JSON_FIELD("value_size", value_size) \
			"}", ANN_CACNE_DEFINE)

/*
 * id:  string literal: which map
 * key:        pointer: from which memory to read value of key
 * key_size:  interger: how many bytes is the key (for keys of BYTE_ARRAY)
 * value_ref:  pointer: where to store the result of lookup (if successful)
 * */
#define __ANNOTATE_BEGIN_CACHE(id, key, key_size, value_ref) \
	__ANNOTATE("{" \
			JSON_FIELD_MID("id", id) \
			JSON_FIELD_MID("key", key) \
			JSON_FIELD_MID("key_size", key_size) \
			JSON_FIELD("value_ref", value_ref) \
		"}", ANN_CACHE_BEGIN)

#define __ANNOTATE_END_CACHE(id) __ANNOTATE("{id:\"" id "\"}", ANN_CACHE_END)

#endif
