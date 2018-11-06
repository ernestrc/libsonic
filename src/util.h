#ifndef SONIC_UTIL_H
#define SONIC_UTIL_H

#include <json-c/json.h>
#include <stdio.h>

#define UPDATE_SNPRINTF_WANT(want, buf, blen, res)                             \
	blen -= want;                                                              \
	if (blen < 0) {                                                            \
		blen = 0;                                                              \
	} else {                                                                   \
		buf += want;                                                           \
	}                                                                          \
	res += want;

#define SNPRINTF_WANT(dst, dst_len, want, res, tmpl, ...)                      \
	want = snprintf(dst, dst_len, tmpl, ##__VA_ARGS__);                        \
	UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);

int snprintj(char* dst, int dst_len, const json_object* j);

#endif
