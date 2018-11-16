#include <assert.h>
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

void sonic_message_init_started(struct sonic_message* sm)
{
	RESET_MSG(sm);
	sm->type = SONIC_TYPE_STARTED;
}

void sonic_message_init_query(struct sonic_message* sm, const char* query,
  const char* auth, const json_object* config)
{
	RESET_MSG(sm);
	assert(query != NULL);
	assert(config != NULL);

	sm->type = SONIC_TYPE_QUERY;
	sm->message.query.query = query;
	sm->message.query.auth = auth;
	sm->message.query.config = config;
}

void sonic_message_init_auth(
  struct sonic_message* sm, const char* key, const char* user)
{
	RESET_MSG(sm);
	assert(key != NULL);

	sm->type = SONIC_TYPE_AUTH;
	sm->message.auth.user = user;
	sm->message.auth.key = key;
}

void sonic_message_init_metadata(
  struct sonic_message* sm, const struct sonic_message_metadata* meta)
{
	RESET_MSG(sm);

	struct sonic_message_metadata* tmp = (struct sonic_message_metadata*)meta;
	while (tmp != NULL) {
		assert(tmp->name != NULL);
		tmp = tmp->next;
	}

	sm->type = SONIC_TYPE_METADATA;
	sm->message.metadata = meta;
}

void sonic_message_init_progress(struct sonic_message* sm,
  enum sonic_status status, double progress, double total, const char* units)
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
	sm->message.output = output;
}

void sonic_message_init_completed(struct sonic_message* sm)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_COMPLETED;
}

INLINE static int sonic_message_decode_query(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	const char *query, *auth;
	const json_object *config, *jauth;

	if ((query = json_object_get_string(vval)) == NULL) {
		SONIC_LOG("invalid sonic query: query is null %p, %p\n", vval, query);
		errno = EINVAL;
		return 1;
	}
	if ((config = json_object_object_get(pval, "config")) == NULL) {
		SONIC_LOG("invalid sonic query: 'config' not found in payload\n");
		errno = EINVAL;
		return 1;
	}
	jauth = json_object_object_get(pval, "auth");
	if (jauth != NULL) {
		if (json_object_get_type(jauth) != json_type_string) {
			SONIC_LOG("invalid sonic query: 'auth' is %d\n",
			  json_object_get_type(jauth));
			errno = EINVAL;
			return 1;
		}
		auth = json_object_get_string((json_object*)jauth);
	} else {
		auth = NULL;
	}
	sonic_message_init_query(dst, query, auth, config);
	return 0;
}

INLINE static int sonic_message_decode_auth(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	json_object* juser;
	const char* user = NULL;
	const char* key = json_object_get_string(vval);
	if (key == NULL) {
		SONIC_LOG("invalid sonic auth message: key is null\n");
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
			SONIC_LOG("invalid sonic auth message: user is neither a string "
					  "nor a null: %d\n",
			  json_object_get_type(juser));
			errno = EINVAL;
			return 1;
		}
	}
	sonic_message_init_auth(dst, key, user);
	return 0;
}

INLINE static int sonic_message_decode_progress(
  struct sonic_message* dst, json_object* vval, json_object* pval)
{
	json_object *jstatus, *jprogress, *jtotal, *junits;
	enum json_type jstatus_type, jprogress_type, jtotal_type, junits_type;
	enum sonic_status status;
	double progress, total;
	const char* units = NULL;

	if (json_object_get_type(pval) != json_type_object) {
		SONIC_LOG("invalid sonic progress message: payload is %d\n",
		  json_object_get_type(pval));
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
	  (jprogress_type != json_type_int && jprogress_type != json_type_double)) {
		SONIC_LOG(
		  "invalid sonic progress message: status is %d; progress is %d\n",
		  jstatus_type, jprogress_type);
		errno = EINVAL;
		return 1;
	}

	if (jtotal_type != json_type_null) {
		if (jtotal_type != json_type_int && jtotal_type != json_type_double) {
			SONIC_LOG(
			  "invalid sonic progress message: total is %d\n", jtotal_type);
			errno = EINVAL;
			return 1;
		}
		total = json_object_get_double(jtotal);
	} else {
		total = 0;
	}

	status = json_object_get_int(jstatus);
	progress = json_object_get_double(jprogress);

	if (junits_type != json_type_null) {
		if (junits_type != json_type_string) {
			SONIC_LOG(
			  "invalid sonic progress message: units is %d\n", junits_type);
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
		SONIC_LOG("invalid sonic metadata: payload is %d\n",
		  json_object_get_type(pval));
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
	struct sonic_message_metadata* tmp = meta;
	int mlen;
	int i = 0;

#define GET_NEXT_META()                                                        \
	obj = json_object_array_get_idx(pval, i);                                  \
	if (json_object_get_type(obj) != json_type_array) {                        \
		SONIC_LOG("invalid sonic metadata: entity at index %d is %d\n", i,     \
		  json_object_get_type(obj));                                          \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}                                                                          \
	obj = json_object_array_get_idx(pval, i);                                  \
	if (json_object_get_type(obj) != json_type_array) {                        \
		SONIC_LOG("invalid sonic metadata: entity at index %d is %d\n", i,     \
		  json_object_get_type(obj));                                          \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}                                                                          \
	if ((mlen = json_object_array_length(obj)) < 2) {                          \
		SONIC_LOG(                                                             \
		  "invalid sonic metadata: expected array of size >=2 but found %d\n", \
		  mlen);                                                               \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}                                                                          \
	json_object *mkey, *mval;                                                  \
	mkey = json_object_array_get_idx(obj, 0);                                  \
	mval = json_object_array_get_idx(obj, 1);                                  \
                                                                               \
	if (json_object_get_type(mkey) != json_type_string) {                      \
		SONIC_LOG("invalid sonic metadata: expected k/v pair of string: json " \
				  "value, found "                                              \
				  "%d and %d\n",                                               \
		  json_object_get_type(mkey), json_object_get_type(mval));             \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}                                                                          \
	tmp->name = json_object_get_string(mkey);                                  \
	tmp->type = json_object_get_type(mval);

	for (; i < len - 1; i++) {
		GET_NEXT_META();
		tmp->next = tmp + 1;
		tmp = tmp->next;
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
		SONIC_LOG(
		  "invalid sonic output: payload is %d\n", json_object_get_type(pval));
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
	for (; i < len - 1; i++) {
		tmp->value = json_object_array_get_idx(pval, i);
		tmp->next = tmp + 1;
		tmp = tmp->next;
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
		SONIC_LOG("json_tokener_parse_ex: error: %d\n",
		  json_tokener_get_error(tokener));
		errno = EINVAL;
		ret = 1;
		goto exit;
	}

	json_object* type = json_object_object_get(json, "e");
	if (json_object_get_type(type) != json_type_string) {
		SONIC_LOG("invalid sonic message: 'e' is of type %d\n",
		  json_object_get_type(type));
		errno = EINVAL;
		ret = 1;
		goto exit;
	}

	json_object* v = json_object_object_get(json, "v");
	enum json_type vt = json_object_get_type(v);
	if (vt != json_type_string && vt != json_type_null) {
		SONIC_LOG("invalid sonic message: 'v' is of type %d\n", vt);
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
		sonic_message_init_started(dst);
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
		SONIC_LOG("invalid sonic message: unexpected type: %d\n",
		  *json_object_get_string(type));
		errno = EINVAL;
		ret = 1;
	}

exit:
	lerrno = errno;
	if (ret) {
		json_object_put(json);
	} else {
		dst->backing = json;
	}
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
	return strcmp(a->message.query.query, b->message.query.query) ||
	  !json_object_equal((json_object*)a->message.query.config,
		(json_object*)b->message.query.config) ||
	  (a->message.query.auth != b->message.query.auth &&
		strcmp(a->message.query.auth, b->message.query.auth));
}

INLINE static int sonic_message_cmp_auth(
  struct sonic_message* a, struct sonic_message* b)
{
	return strcmp(a->message.auth.key, b->message.auth.key) ||
	  (a->message.auth.user != b->message.auth.user &&
		strcmp(a->message.auth.user, b->message.auth.user));
}

INLINE static int sonic_message_cmp_progress(
  struct sonic_message* a, struct sonic_message* b)
{
	return intcmp(a->message.progress.status, b->message.progress.status) ||
	  intcmp(a->message.progress.progress, b->message.progress.progress) ||
	  intcmp(a->message.progress.total, b->message.progress.total) ||
	  (a->message.progress.units != b->message.progress.units &&
		strcmp(a->message.progress.units, b->message.progress.units));
}

INLINE static int sonic_message_cmp_metadata(
  struct sonic_message* a, struct sonic_message* b)
{
	int ret = 0;

	const struct sonic_message_metadata *ameta, *bmeta;
	for (ameta = a->message.metadata, bmeta = b->message.metadata;
		 ameta != NULL && bmeta != NULL && ret == 0;
		 ameta = ameta->next, bmeta = bmeta->next) {
		ret = strcmp(ameta->name, bmeta->name) || ameta->type != bmeta->type;
	}

	return ameta != bmeta || ret;
}

INLINE static int sonic_message_cmp_output(
  struct sonic_message* a, struct sonic_message* b)
{
	int ret = 0;

	const struct sonic_message_output *aout, *bout;
	for (aout = a->message.output, bout = b->message.output;
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
	default:
		abort();
	}
}

INLINE static size_t sonic_message_encode_metadata(
  char* dst, size_t dst_len, const struct sonic_message_metadata* meta)
{
	size_t res = 0;
	size_t want = 0;

	SNPRINTF_WANT(dst, dst_len, want, res, "{\"e\":\"T\",\"p\":[");

	if (meta == NULL)
		goto exit;

#define PRINT_META()                                                           \
	switch (meta->type) {                                                      \
	case json_type_null:                                                       \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",null]", meta->name);   \
		break;                                                                 \
	case json_type_boolean:                                                    \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",true]", meta->name);   \
		break;                                                                 \
	case json_type_double:                                                     \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",0.1]", meta->name);    \
		break;                                                                 \
	case json_type_int:                                                        \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",1]", meta->name);      \
		break;                                                                 \
	case json_type_object:                                                     \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",{}]", meta->name);     \
		break;                                                                 \
	case json_type_array:                                                      \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",[]]", meta->name);     \
		break;                                                                 \
	case json_type_string:                                                     \
		SNPRINTF_WANT(dst, dst_len, want, res, "[\"%s\",\"\"]", meta->name);   \
		break;                                                                 \
	}

	PRINT_META();
	for (meta = meta->next; meta != NULL; meta = meta->next) {
		SNPRINTF_WANT(dst, dst_len, want, res, ",");
		PRINT_META();
	}

exit:
	SNPRINTF_WANT(dst, dst_len, want, res, "]}");

	return res;
}

INLINE static size_t sonic_message_encode_output(
  char* dst, size_t dst_len, const struct sonic_message_output* out)
{
	size_t res = 0;
	size_t want = 0;

	SNPRINTF_WANT(dst, dst_len, want, res, "{\"e\":\"O\",\"p\":[");

	if (out == NULL)
		goto exit;

	want = snprintj(dst, dst_len, out->value);
	UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);

	for (out = out->next; out != NULL; out = out->next) {
		SNPRINTF_WANT(dst, dst_len, want, res, ",");
		want = snprintj(dst, dst_len, out->value);
		UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);
	}

exit:
	SNPRINTF_WANT(dst, dst_len, want, res, "]}");

	return res;
}

INLINE static size_t sonic_message_encode_progress(char* dst, size_t dst_len,
  enum sonic_status status, double progress, double total, const char* units)
{
	size_t res = 0;
	size_t want = 0;

	SNPRINTF_WANT(dst, dst_len, want, res,
	  "{\"e\":\"P\",\"p\":{\"p\":%g,\"s\":%d", progress, status);

	if (total != 0) {
		SNPRINTF_WANT(dst, dst_len, want, res, ",\"t\":%g", total);
	}

	if (units != NULL) {
		SNPRINTF_WANT(dst, dst_len, want, res, ",\"u\":\"%s\"", units);
	}

	SNPRINTF_WANT(dst, dst_len, want, res, "}}");

	return res;
}

INLINE static size_t sonic_message_encode_auth(
  char* dst, size_t dst_len, const char* key, const char* user)
{
	size_t res = 0;
	size_t want = 0;
	assert(key != NULL);

	SNPRINTF_WANT(dst, dst_len, want, res, "{\"e\":\"H\",\"v\":\"%s\"", key);

	if (user != NULL) {
		SNPRINTF_WANT(
		  dst, dst_len, want, res, ",\"p\":{\"user\":\"%s\"}", user);
	}

	SNPRINTF_WANT(dst, dst_len, want, res, "}");

	return res;
}

INLINE static size_t sonic_message_encode_query(char* dst, size_t dst_len,
  const char* query, const char* auth, const json_object* config)
{
	size_t res = 0;
	size_t want = 0;
	assert(config != NULL);

	SNPRINTF_WANT(dst, dst_len, want, res,
	  "{\"e\":\"Q\",\"v\":\"%s\",\"p\":{\"config\":", query);

	want = snprintj(dst, dst_len, config);
	UPDATE_SNPRINTF_WANT(want, dst, dst_len, res);

	if (auth != NULL) {
		SNPRINTF_WANT(dst, dst_len, want, res, ",\"auth\":\"%s\"", auth);
	}

	SNPRINTF_WANT(dst, dst_len, want, res, "}}");

	return res;
}

size_t sonic_message_encode(
  char* dst, size_t dst_len, const struct sonic_message* src)
{
	switch (src->type) {
	case SONIC_TYPE_ACK:
		return snprintf(dst, dst_len, "{\"e\":\"A\"}");
	case SONIC_TYPE_STARTED:
		return snprintf(dst, dst_len, "{\"e\":\"S\"}");
	case SONIC_TYPE_COMPLETED:
		return snprintf(dst, dst_len, "{\"e\":\"D\"}");
	case SONIC_TYPE_QUERY:
		return sonic_message_encode_query(dst, dst_len,
		  src->message.query.query, src->message.query.auth,
		  src->message.query.config);
	case SONIC_TYPE_AUTH:
		return sonic_message_encode_auth(
		  dst, dst_len, src->message.auth.key, src->message.auth.user);
	case SONIC_TYPE_PROGRESS:
		return sonic_message_encode_progress(dst, dst_len,
		  src->message.progress.status, src->message.progress.progress,
		  src->message.progress.total, src->message.progress.units);
	case SONIC_TYPE_METADATA:
		return sonic_message_encode_metadata(
		  dst, dst_len, src->message.metadata);
	case SONIC_TYPE_OUTPUT:
		return sonic_message_encode_output(dst, dst_len, src->message.output);
	default:
		abort();
	}
}
