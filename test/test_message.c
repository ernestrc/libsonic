#include <errno.h>

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
		meta->type = "type";
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

int test_message_decode()
{
	const int n = 1;
	struct {
		char* input;
		struct sonic_message output;
		struct sonic_message expected;
	} cases[n];

	cases[0].input = "{\"e\":\"Q\",\"p\":{\"config\":\"whatever\",\"auth\":"
					 "null},\"v\":\"1234\"}";
	sonic_message_init_query(&cases[0].expected, "1234");

	for (int i = 0; i < n; i++) {
		ASSERT_RET_PERROR(sonic_message_decode(
		  &cases[i].output, cases[i].input, strlen(cases[i].input)));
		ASSERT_MSG_EQ(&cases[i].expected, &cases[i].output);
		sonic_message_deinit(&cases[i].output);
	}

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
		sonic_message_init_started(&msg, NULL);
		ASSERT_EQ(msg.type, SONIC_TYPE_STARTED);
		ASSERT_EQ(msg.message.started.msg, NULL);
	}

	{
		const char* test_msg = "my msg";
		sonic_message_init_started(&msg, test_msg);
		ASSERT_EQ(msg.type, SONIC_TYPE_STARTED);
		ASSERT_EQ(msg.message.started.msg, test_msg);
	}

	{
		const char* test_query = "select * from ballz";
		sonic_message_init_query(&msg, test_query);
		ASSERT_EQ(msg.type, SONIC_TYPE_QUERY);
		ASSERT_EQ(msg.message.query.query, test_query);
	}

	{
		const char* test_user = "my user";
		const char* test_key = "my_key_1234";
		sonic_message_init_auth(&msg, test_user, test_key);
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
		for (struct sonic_message_metadata* next = &msg.message.metadata;
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
		for (struct sonic_message_output* next = &msg.message.output;
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
	TEST_RUN(ctx, test_message_decode);

	TEST_RELEASE(ctx);
}
