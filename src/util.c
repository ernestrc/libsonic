#include <stdbool.h>
#include <arpa/inet.h>

#include "config.h"
#include "util.h"

INLINE static int snprintj_array(char* dst, int dst_len, const json_object* j)
{
	int res = 0;
	int want = 0;
	int first = 1;

	SNPRINTF_WANT(dst, dst_len, want, res, "[");
	for (int i = 0; i < json_object_array_length(j); i++) {
		if (!first) {
			SNPRINTF_WANT(dst, dst_len, want, res, ",");
		} else {
			first = 0;
		}
		want = snprintj(dst, dst_len, json_object_array_get_idx(j, i));
		UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);
	}

	SNPRINTF_WANT(dst, dst_len, want, res, "]");

	return res;
}

INLINE static int snprintj_object(char* dst, int dst_len, const json_object* j)
{
	int res = 0;
	int want = 0;
	int first = 1;
	struct json_object_iter iter;

	SNPRINTF_WANT(dst, dst_len, want, res, "{");
	json_object_object_foreachC(j, iter)
	{
		if (!first) {
			SNPRINTF_WANT(dst, dst_len, want, res, ",\"%s\":", iter.key);
		} else {
			SNPRINTF_WANT(dst, dst_len, want, res, "\"%s\":", iter.key);
			first = 0;
		}

		want = snprintj(dst, dst_len, iter.val);
		UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);
	}

	SNPRINTF_WANT(dst, dst_len, want, res, "}");

	return res;
}

INLINE static int snprintj_string(
  char* dst, size_t dst_len, const json_object* j)
{
	const char* str = json_object_get_string((json_object*)j);
	return snprintf(dst, dst_len, "\"%s\"", str);
}

int snprintj(char* dst, int dst_len, const json_object* j)
{
	switch (json_object_get_type(j)) {
	case json_type_null:
		return snprintf(dst, dst_len, "null");
	case json_type_boolean:
		return json_object_get_boolean(j) ? snprintf(dst, dst_len, "true") :
											snprintf(dst, dst_len, "false");
	case json_type_double:
		// FIXME should be %g
		return snprintf(dst, dst_len, "%.4f", json_object_get_double(j));
	case json_type_int:
		return snprintf(dst, dst_len, "%ld", json_object_get_int64(j));
	case json_type_string:
		return snprintj_string(dst, dst_len, j);
	case json_type_object:
		return snprintj_object(dst, dst_len, j);
	case json_type_array:
		return snprintj_array(dst, dst_len, j);
	}

	abort();
}
