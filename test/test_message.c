#include <errno.h>

#include "../src/message.h"
#include "test.h"

int test_message_parse()
{
}

int main(int argc, char* argv[])
{
	test_ctx_t ctx;
	TEST_INIT(ctx, argc, argv);

	TEST_RUN(ctx, test_message_parse);

	TEST_RELEASE(ctx);
}
