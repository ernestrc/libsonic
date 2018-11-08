#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "message.h"
#include "util.h"

#define RESET_MSG(sm) memset(sm, 0, sizeof(struct sonic_message))

void userdata_free(struct json_object* jso, void* userdata) { free(userdata); }

void sonic_message_init_ack(struct sonic_message* sm)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_ACK;
}

void sonic_message_init_started(struct sonic_message* sm, const char* msg)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_STARTED;
	sm->message.started.msg = msg;
}

void sonic_message_init_query(struct sonic_message* sm, const char* query)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_QUERY;
	sm->message.query.query = query;
}

void sonic_message_init_auth(
  struct sonic_message* sm, const char* user, const char* key)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_AUTH;
	sm->message.auth.user = user;
	sm->message.auth.key = key;
}

void sonic_message_init_metadata(
  struct sonic_message* sm, const struct sonic_message_metadata* meta)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_METADATA;
	// FIXME empty metadata is encoded as NULL meta so this breaks
	sm->message.metadata = *meta;
}

void sonic_message_init_progress(struct sonic_message* sm,
  enum sonic_status status, int progress, int total, const char* units)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_PROGRESS;
	sm->message.progress.status = status;
	sm->message.progress.progress = progress;
	sm->message.progress.total = total;
	sm->message.progress.units = units;
}

void sonic_message_init_output(
  struct sonic_message* sm, const struct sonic_message_output* output)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_OUTPUT;
	// FIXME empty output is encoded as NULL meta so this breaks
	sm->message.output = *output;
}

void sonic_message_init_completed(struct sonic_message* sm)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_COMPLETED;
}

// TODO rest of fields config and auth
INLINE static int sonic_message_decode_query(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	const char* query = json_object_get_string(vval);
	if (query == NULL) {
		errno = EINVAL;
		return 1;
	}
	sonic_message_init_query(dst, query);
	return 0;
}

INLINE static int sonic_message_decode_auth(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	json_object* juser;
	const char* user = NULL;
	const char* key = json_object_get_string(vval);
	if (key == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (json_object_get_type(pval) != json_type_null) {
		juser = json_object_object_get(pval, "user");
		switch (json_object_get_type(juser)) {
		case json_type_string:
			user = json_object_get_string(juser);
			break;
		case json_type_null:
			break;
		default:
			errno = EINVAL;
			return 1;
		}
	}
	sonic_message_init_auth(dst, user, key);
	return 0;
}

INLINE static int sonic_message_decode_progress(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	json_object *jstatus, *jprogress, *jtotal, *junits;
	enum json_type jstatus_type, jprogress_type, jtotal_type, junits_type;
	enum sonic_status status;
	int progress, total;
	const char* units = NULL;

	if (json_object_get_type(pval) == json_type_null) {
		errno = EINVAL;
		return 1;
	}

	jstatus = json_object_object_get(pval, "s");
	jstatus_type = json_object_get_type(jstatus);

	junits = json_object_object_get(pval, "u");
	junits_type = json_object_get_type(junits);

	jprogress = json_object_object_get(pval, "p");
	jprogress_type = json_object_get_type(jprogress);

	jtotal = json_object_object_get(pval, "t");
	jtotal_type = json_object_get_type(jtotal);

	if ((jstatus_type != json_type_int && jstatus_type != json_type_double) ||
	  (jprogress_type != json_type_int && jprogress_type != json_type_double) ||
	  (jtotal_type != json_type_int && jtotal_type != json_type_double)) {
		errno = EINVAL;
		return 1;
	}

	status = json_object_get_int(jstatus);
	progress = json_object_get_double(jprogress);
	total = json_object_get_double(jtotal);

	if (junits_type != json_type_null) {
		if (junits_type != json_type_string) {
			errno = EINVAL;
			return 1;
		}
		units = json_object_get_string(junits);
	}

	sonic_message_init_progress(dst, status, progress, total, units);
	return 0;
}

INLINE static int sonic_message_decode_metadata(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	int len;
	struct sonic_message_metadata* meta;

	if (json_object_get_type(pval) != json_type_array) {
		errno = EINVAL;
		return 1;
	}
	if ((len = json_object_array_length(pval)) == 0) {
		sonic_message_init_metadata(dst, NULL);
		return 0;
	}

	if ((meta = calloc(len, sizeof(struct sonic_message_metadata))) == NULL)
		return 1;

	// tight lifecycle of meta with pval
	json_object_set_userdata(pval, meta, userdata_free);

	json_object* obj;
	struct json_object_iter iter;
	struct sonic_message_metadata* tmp = meta;
	int i = 0;

#define GET_NEXT_META()                                                        \
	obj = json_object_array_get_idx(pval, i);                                  \
	if (json_object_get_type(obj) != json_type_object) {                       \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}                                                                          \
	json_object_object_foreachC(obj, iter)                                     \
	{                                                                          \
		tmp->name = iter.key;                                                  \
		if (json_object_get_type(iter.val) != json_type_string) {              \
			errno = EINVAL;                                                    \
			return 1;                                                          \
		}                                                                      \
		tmp->type = json_object_get_string(iter.val);                          \
		/* only one key/val pair is allowed */                                 \
		break;                                                                 \
	}

	for (; i < len - 1; i++, tmp++) {
		GET_NEXT_META();
		tmp->next = tmp;
	}
	GET_NEXT_META();
	tmp->next = NULL;

	sonic_message_init_metadata(dst, meta);

	return 0;
}

INLINE static int sonic_message_decode_output(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	int len;
	struct sonic_message_output* out;

	if (json_object_get_type(pval) != json_type_array) {
		errno = EINVAL;
		return 1;
	}
	if ((len = json_object_array_length(pval)) == 0) {
		sonic_message_init_output(dst, NULL);
		return 0;
	}

	if ((out = calloc(len, sizeof(struct sonic_message_output))) == NULL)
		return 1;

	// tight lifecycle of out with pval
	json_object_set_userdata(pval, out, userdata_free);

	// extract values and link linked list
	int i = 0;
	struct sonic_message_output* tmp = out;
	for (; i < len - 1; i++, tmp++) {
		tmp->value = json_object_array_get_idx(pval, i);
		tmp->next = tmp;
	}
	tmp->value = json_object_array_get_idx(pval, i);
	tmp->next = NULL;

	sonic_message_init_output(dst, out);

	return 0;
}

int sonic_message_decode(
  struct sonic_message* dst, const char* src, size_t src_len)
{
	static json_tokener* tokener;
	int lerrno, ret;
	json_object* json = NULL;

	if (tokener == NULL && (tokener = json_tokener_new()) == NULL) {
		lerrno = ENOMEM;
		ret = 1;
		goto exit;
	}

	if ((json = json_tokener_parse_ex(tokener, src, src_len)) == NULL) {
		fprintf(stderr, "json_tokener_parse_ex: error: %d\n",
		  json_tokener_get_error(tokener));
		errno = EINVAL;
		ret = 1;
		goto exit;
	}

	json_object* type = json_object_object_get(json, "e");
	if (json_object_get_type(type) != json_type_string) {
		fprintf(stderr, "invalid sonic message: 'e' is of type %d\n",
		  json_object_get_type(type));
		errno = EINVAL;
		ret = 1;
		goto exit;
	}

	json_object* v = json_object_object_get(json, "v");
	enum json_type vt = json_object_get_type(v);
	if (vt != json_type_string && vt != json_type_null) {
		fprintf(stderr, "invalid sonic message: 'v' is of type %d\n", vt);
		errno = EINVAL;
		ret = 1;
		goto exit;
	}

	json_object* p = json_object_object_get(json, "p");

	switch (*json_object_get_string(type)) {
	case SONIC_TYPE_ACK:
		sonic_message_init_ack(dst);
		ret = 0;
		break;
	case SONIC_TYPE_STARTED:
		sonic_message_init_started(dst, NULL);
		ret = 0;
		break;
	case SONIC_TYPE_QUERY:
		ret = sonic_message_decode_query(dst, v, p);
		break;
	case SONIC_TYPE_AUTH:
		ret = sonic_message_decode_auth(dst, v, p);
		break;
	case SONIC_TYPE_METADATA:
		ret = sonic_message_decode_metadata(dst, v, p);
		break;
	case SONIC_TYPE_PROGRESS:
		ret = sonic_message_decode_progress(dst, v, p);
		break;
	case SONIC_TYPE_OUTPUT:
		ret = sonic_message_decode_output(dst, v, p);
		break;
	case SONIC_TYPE_COMPLETED:
		sonic_message_init_completed(dst);
		ret = 0;
		break;
	default:
		errno = EINVAL;
		ret = 1;
	}

exit:
	if (ret) {
		json_object_put(json);
	} else {
		dst->backing = json;
	}
	lerrno = errno;
	if (tokener)
		json_tokener_reset(tokener);
	errno = lerrno;
	return ret;
}

void sonic_message_deinit(struct sonic_message* msg)
{
	if (msg->backing != NULL)
		json_object_put(msg->backing);
}

INLINE static int sonic_message_cmp_query(
  struct sonic_message* a, struct sonic_message* b)
{
	return strcmp(a->message.query.query, b->message.query.query);
}

INLINE static int sonic_message_cmp_auth(
  struct sonic_message* a, struct sonic_message* b)
{
	return strcmp(a->message.auth.user, b->message.auth.user) ||
	  strcmp(a->message.auth.key, b->message.auth.key);
}

INLINE static int sonic_message_cmp_progress(
  struct sonic_message* a, struct sonic_message* b)
{
	return intcmp(a->message.progress.status, b->message.progress.status) ||
	  intcmp(a->message.progress.progress, b->message.progress.progress) ||
	  intcmp(a->message.progress.total, b->message.progress.total) ||
	  strcmp(a->message.progress.units, b->message.progress.units);
}

INLINE static int sonic_message_cmp_metadata(
  struct sonic_message* a, struct sonic_message* b)
{
	int ret = 0;

	struct sonic_message_metadata *ameta, *bmeta;
	for (ameta = &a->message.metadata, bmeta = &b->message.metadata;
		 ameta != NULL && bmeta != NULL && ret == 0;
		 ameta = ameta->next, bmeta = bmeta->next) {
		ret =
		  strcmp(ameta->name, bmeta->name) || strcmp(ameta->type, bmeta->type);
	}

	return ameta != bmeta || ret;
}

INLINE static int sonic_message_cmp_output(
  struct sonic_message* a, struct sonic_message* b)
{
	int ret = 0;

	struct sonic_message_output *aout, *bout;
	for (aout = &a->message.output, bout = &b->message.output;
		 aout != NULL && bout != NULL && ret == 0;
		 aout = aout->next, bout = bout->next) {
		ret = !json_object_equal(
		  (json_object*)aout->value, (json_object*)bout->value);
	}

	return aout != bout || ret;
}

int sonic_message_cmp(struct sonic_message* a, struct sonic_message* b)
{
	int tcmp = intcmp(a->type, b->type);
	if (tcmp) {
		return tcmp;
	}

	switch (a->type) {
	case SONIC_TYPE_QUERY:
		return sonic_message_cmp_query(a, b);
	case SONIC_TYPE_AUTH:
		return sonic_message_cmp_auth(a, b);
	case SONIC_TYPE_METADATA:
		return sonic_message_cmp_metadata(a, b);
	case SONIC_TYPE_PROGRESS:
		return sonic_message_cmp_progress(a, b);
	case SONIC_TYPE_OUTPUT:
		return sonic_message_cmp_output(a, b);
	case SONIC_TYPE_STARTED:
		/* fallthrough */
	case SONIC_TYPE_COMPLETED:
		/* fallthrough */
	case SONIC_TYPE_ACK:
		return 0;
	}
}

int sonic_message_encode(
  char* dst, size_t dst_len, const struct sonic_message* src)
{
	abort();
}
