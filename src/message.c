#include <string.h>

#include "message.h"

#define RESET_MSG(sm) memset(sm, 0, sizeof(struct sonic_message))

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
	sm->message.output = *output;
}

void sonic_message_init_completed(struct sonic_message* sm)
{
	RESET_MSG(sm);

	sm->type = SONIC_TYPE_COMPLETED;
}

int sonic_message_decode(
  struct sonic_message* dst, const char* src, size_t src_len)
{
	abort();
}

int sonic_message_encode(
  char* dst, size_t dst_len, const struct sonic_message* src)
{
	abort();
}
