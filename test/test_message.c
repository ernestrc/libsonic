#include "../src/message.h"
#include "test.h"

void* init_test_metadata(int n)
{
	struct sonic_message_metadata* meta = NULL;

	for (int i = 0; i < n; i++) {
		struct sonic_message_metadata* tmp = meta;
		meta = rcmalloc(1 * sizeof(struct sonic_message_metadata));
		if (meta == NULL) {
			perror("rcmalloc");
			return NULL;
		}
		meta->next = tmp;

		meta->name = "name";
		meta->type = json_type_object;
	}

	return meta;
}

void* init_test_output(int n)
{
	struct sonic_message_output* out = NULL;

	for (int i = 0; i < n; i++) {
		struct sonic_message_output* tmp = out;
		out = rcmalloc(1 * sizeof(struct sonic_message_output));
		if (out == NULL) {
			perror("rcmalloc");
			return NULL;
		}
		out->next = tmp;

		out->value = NULL;
	}

	return out;
}

int test_message_serde()
{
#define N_CASES 14
	struct {
		char* se_expected;
		char* se_output;
		struct sonic_message de_output;
		struct sonic_message de_expected;
	} cases[N_CASES];

	cases[0].se_expected =
	  "{\"e\":\"Q\",\"v\":\"1234\",\"p\":{\"config\":\"whatever\"}}";
	cases[0].se_output = malloc(strlen(cases[0].se_expected) + 1);
	json_object* config0 = json_object_new_string("whatever");
	assert(config0 != NULL);
	sonic_message_init_query(&cases[0].de_expected, "1234", NULL, config0);

	cases[1].se_expected = "{\"e\":\"Q\",\"v\":\"1234\",\"p\":{\"config\":{"
						   "\"str\":\"whatever\"},\"auth\":\"token\"}}";
	cases[1].se_output = malloc(strlen(cases[1].se_expected) + 1);
	json_object* config1 = json_object_new_object();
	json_object_object_add(config1, "str", json_object_new_string("whatever"));
	assert(config1 != NULL);
	sonic_message_init_query(&cases[1].de_expected, "1234", "token", config1);

	cases[2].se_expected = "{\"e\":\"A\"}";
	cases[2].se_output = malloc(strlen(cases[2].se_expected) + 1);
	sonic_message_init_ack(&cases[2].de_expected);

	cases[3].se_expected = "{\"e\":\"S\"}";
	cases[3].se_output = malloc(strlen(cases[3].se_expected) + 1);
	sonic_message_init_started(&cases[3].de_expected);

	cases[4].se_expected = "{\"e\":\"D\"}";
	cases[4].se_output = malloc(strlen(cases[4].se_expected) + 1);
	sonic_message_init_completed(&cases[4].de_expected);

	cases[5].se_expected = "{\"e\":\"H\",\"v\":\"apikey\"}";
	cases[5].se_output = malloc(strlen(cases[5].se_expected) + 1);
	sonic_message_init_auth(&cases[5].de_expected, "apikey", NULL);

	cases[6].se_expected =
	  "{\"e\":\"H\",\"v\":\"apikey\",\"p\":{\"user\":\"myuser\"}}";
	cases[6].se_output = malloc(strlen(cases[6].se_expected) + 1);
	sonic_message_init_auth(&cases[6].de_expected, "apikey", "myuser");

	cases[7].se_expected =
	  "{\"e\":\"P\",\"p\":{\"p\":10,\"s\":1,\"t\":100,\"u\":\"perc\"}}";
	cases[7].se_output = malloc(strlen(cases[7].se_expected) + 1);
	sonic_message_init_progress(
	  &cases[7].de_expected, SONIC_STATUS_STARTED, 10, 100, "perc");

	cases[8].se_expected =
	  "{\"e\":\"P\",\"p\":{\"p\":2000,\"s\":3,\"u\":\"perc\"}}";
	cases[8].se_output = malloc(strlen(cases[8].se_expected) + 1);
	sonic_message_init_progress(
	  &cases[8].de_expected, SONIC_STATUS_WAITING, 2000, 0, "perc");

	cases[9].se_expected =
	  "{\"e\":\"P\",\"p\":{\"p\":0.5556,\"s\":2,\"t\":1.2345}}";
	cases[9].se_output = malloc(strlen(cases[9].se_expected) + 1);
	sonic_message_init_progress(
	  &cases[9].de_expected, SONIC_STATUS_RUNNING, 0.5556, 1.2345, NULL);

	cases[10].se_expected = "{\"e\":\"P\",\"p\":{\"p\":0.0005,\"s\":4}}";
	cases[10].se_output = malloc(strlen(cases[10].se_expected) + 1);
	sonic_message_init_progress(
	  &cases[10].de_expected, SONIC_STATUS_FINISHED, 0.0005, 0, NULL);

	cases[11].se_expected = "{\"e\":\"O\",\"p\":[1,null,\"num\",true,5.1234]}";
	cases[11].se_output = malloc(strlen(cases[11].se_expected) + 1);
#define OUT_LEN 5
	struct sonic_message_output out[OUT_LEN];
	out[0].value = json_object_new_int64(1);
	out[0].next = &out[1];
	out[1].value = NULL;
	out[1].next = &out[2];
	out[2].value = json_object_new_string("num");
	out[2].next = &out[3];
	out[3].value = json_object_new_boolean(1);
	out[3].next = &out[4];
	out[4].value = json_object_new_double(5.1234);
	out[4].next = NULL;
	sonic_message_init_output(&cases[11].de_expected, out);

	cases[12].se_expected = "{\"e\":\"T\",\"p\":[]}";
	cases[12].se_output = malloc(strlen(cases[12].se_expected) + 1);
	sonic_message_init_metadata(&cases[12].de_expected, NULL);

	cases[13].se_expected =
	  "{\"e\":\"T\",\"p\":[[\"my_number\",1],[\"my_obj\",{}],[\"my_"
	  "string\",\"\"],[\"my_bool\",true],[\"my_float\",0.1]]}";
	cases[13].se_output = malloc(strlen(cases[13].se_expected) + 1);
#define META_LEN 5
	struct sonic_message_metadata meta[META_LEN];
	meta[0].name = "my_number";
	meta[0].type = json_type_int;
	meta[0].next = &meta[1];
	meta[1].name = "my_obj";
	meta[1].type = json_type_object;
	meta[1].next = &meta[2];
	meta[2].name = "my_string";
	meta[2].type = json_type_string;
	meta[2].next = &meta[3];
	meta[3].name = "my_bool";
	meta[3].type = json_type_boolean;
	meta[3].next = &meta[4];
	meta[4].name = "my_float";
	meta[4].type = json_type_double;
	meta[4].next = NULL;
	sonic_message_init_metadata(&cases[13].de_expected, meta);

	for (int i = 0; i < N_CASES; i++) {
		ASSERT_RET_PERROR(sonic_message_decode(&cases[i].de_output,
		  cases[i].se_expected, strlen(cases[i].se_expected)));
		ASSERT_MSG_EQ(&cases[i].de_expected, &cases[i].de_output);
		ASSERT_INT_EQ(
		  sonic_message_encode(cases[i].se_output,
			strlen(cases[i].se_expected) + 1, &cases[i].de_expected),
		  strlen(cases[i].se_expected));
		ASSERT_STR_EQ(cases[i].se_expected, cases[i].se_output);
		sonic_message_deinit(&cases[i].de_output);
		free(cases[i].se_output);
	}

	for (int i = 0; i < OUT_LEN; i++) {
		if (out[i].value) {
			json_object_put((json_object*)out[i].value);
		}
	}

	json_object_put(config0);
	json_object_put(config1);

	return 0;
}

int test_message_init()
{
	struct sonic_message msg;

	{
		sonic_message_init_ack(&msg);
		ASSERT_EQ(msg.type, SONIC_TYPE_ACK);
	}

	{
		sonic_message_init_started(&msg);
		ASSERT_EQ(msg.type, SONIC_TYPE_STARTED);
	}

	{
		const char* test_query = "select * from ballz";
		const char* test_auth = "my_token";
		json_object* test_config = json_object_new_object();
		sonic_message_init_query(&msg, test_query, test_auth, test_config);
		ASSERT_EQ(msg.type, SONIC_TYPE_QUERY);
		ASSERT_EQ(msg.message.query.query, test_query);
		ASSERT_EQ(msg.message.query.auth, test_auth);
		ASSERT_EQ(msg.message.query.config, test_config);
		json_object_put(test_config);
	}

	{
		const char* test_user = "my user";
		const char* test_key = "my_key_1234";
		sonic_message_init_auth(&msg, test_key, test_user);
		ASSERT_EQ(msg.type, SONIC_TYPE_AUTH);
		ASSERT_EQ(msg.message.auth.user, test_user);
		ASSERT_EQ(msg.message.auth.key, test_key);
	}

	{
		int n = 3;
		struct sonic_message_metadata* meta = init_test_metadata(n);
		if (meta == NULL) {
			perror("init_test_metdata");
			return 1;
		}
		sonic_message_init_metadata(&msg, meta);
		ASSERT_EQ(msg.type, SONIC_TYPE_METADATA);
		for (const struct sonic_message_metadata* next = msg.message.metadata;
			 next != NULL; next = next->next) {
			n--;
		}
		ASSERT_EQ(n, 0);
	}

	{
		enum sonic_status status = SONIC_STATUS_STARTED;
		int progress = 10;
		int total = 100;
		const char* units = "my units";
		sonic_message_init_progress(&msg, status, progress, total, units);
		ASSERT_EQ(msg.type, SONIC_TYPE_PROGRESS);
		ASSERT_EQ(msg.message.progress.status, status);
		ASSERT_EQ(msg.message.progress.progress, progress);
		ASSERT_EQ(msg.message.progress.total, total);
		ASSERT_EQ(msg.message.progress.units, units);
	}

	{
		int m = 100;
		struct sonic_message_output* out = init_test_output(m);
		if (out == NULL) {
			perror("init_test_output");
			return 1;
		}
		sonic_message_init_output(&msg, out);
		ASSERT_EQ(msg.type, SONIC_TYPE_OUTPUT);
		for (const struct sonic_message_output* next = msg.message.output;
			 next != NULL; next = next->next) {
			m--;
		}
		ASSERT_EQ(m, 0);
	}

	{
		sonic_message_init_completed(&msg);
		ASSERT_EQ(msg.type, SONIC_TYPE_COMPLETED);
	}
	return 0;
}

int main(int argc, char* argv[])
{
	test_ctx_t ctx;
	TEST_INIT(ctx, argc, argv);

	TEST_RUN(ctx, test_message_init);
	TEST_RUN(ctx, test_message_serde);

	TEST_RELEASE(ctx);
}
