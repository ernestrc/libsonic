#ifndef SONIC_UTIL_H
#define SONIC_UTIL_H

#include <netdb.h>
#include <stdio.h>

#include <json-c/json.h>

#include "config.h"

#ifdef SONIC_DEBUG
#define SONIC_LOG(...) fprintf(stderr, __VA_ARGS__);
#else
#define SONIC_LOG(...)
#endif

/* note that dst_len must be a signed integer/long*/
#define UPDATE_SNPRINTF_WANT(want, dst, dst_len, res)                          \
	if (dst_len >= want) {                                                     \
		dst_len -= want;                                                       \
		dst += want;                                                           \
	} else {                                                                   \
		dst_len = 0;                                                           \
	}                                                                          \
	res += want;

#define SNPRINTF_WANT(dst, dst_len, want, res, tmpl, ...)                      \
	want = snprintf(dst, dst_len, tmpl, ##__VA_ARGS__);                        \
	UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);

#define intcmp(a, b) ((a) < (b) ? -1 : ((a) > (b) ? 1 : 0))

#define GET_CFG_INT(field, def, name)                                          \
	if (cfg->field == 0) {                                                     \
		cfg->field = def;                                                      \
	} else if (cfg->field < 0) {                                               \
		SONIC_LOG("invalid " name ": %d\n", cfg->field);                       \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}

int snprintj(char* dst, int dst_len, const json_object* j);

#endif
