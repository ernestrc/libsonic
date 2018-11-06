#include <assert.h>

#include "../src/util.h"
#include "test.h"

// int snprintj(char* dst, int dst_len, const json_object* j);
int test_snprintj()
{
	/* prepare json object */
	json_object* root = json_object_new_object();
	assert(root != NULL);

	json_object* str = json_object_new_string("str");
	assert(str != NULL);
	json_object_object_add(root, "string", str);

	json_object* b = json_object_new_boolean(1);
	assert(b != NULL);
	json_object_object_add(root, "bool", b);

	json_object* d = json_object_new_double(2.2);
	assert(d != NULL);
	json_object_object_add(root, "double", d);

	json_object* i = json_object_new_int(2);
	assert(i != NULL);
	json_object_object_add(root, "int", i);

	json_object* l = json_object_new_int64(INT64_MAX);
	assert(l != NULL);
	json_object_object_add(root, "int64", l);

	json_object* obj = NULL;
	ASSERT_EQ(json_object_deep_copy(root, &obj, NULL), 0);
	assert(obj != NULL);
	json_object_object_add(root, "obj", obj);

	json_object* arr = json_object_new_array();
	assert(arr != NULL);

	json_object* arr2 = json_object_new_array();
	assert(arr != NULL);
	json_object_array_add(arr, arr2);

	json_object* i2 = json_object_new_int(2);
	assert(i2 != NULL);
	json_object_array_add(arr2, i2);

	json_object_object_add(root, "arr", arr);

	/* test print */

	int need = snprintj(NULL, 0, root);
	char* buf = rcmalloc(need + 1);
	snprintj(buf, need + 1, root);

	const char* should =
	  "{\"string\":\"str\",\"bool\":true,\"double\":2.2000,\"int\":2,\"int64\":"
	  "9223372036854775807,\"obj\":{\"string\":\"str\",\"bool\":true,"
	  "\"double\":2.2000,\"int\":2,\"int64\":9223372036854775807},\"arr\":[[2]]"
	  "}";

	ASSERT_STR_EQ(buf, should);

	/* release */
	json_object_put(root);

	return 0;
}

int main(int argc, char* argv[])
{
	test_ctx_t ctx;
	TEST_INIT(ctx, argc, argv);

	TEST_RUN(ctx, test_snprintj);

	TEST_RELEASE(ctx);
}
