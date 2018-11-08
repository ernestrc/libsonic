#ifndef SONIC_MESSAGE_H
#define SONIC_MESSAGE_H

#include <json-c/json.h>

enum sonic_message_type {
	SONIC_TYPE_ACK = 'A',
	SONIC_TYPE_STARTED = 'S',
	SONIC_TYPE_QUERY = 'Q',
	SONIC_TYPE_AUTH = 'H',
	SONIC_TYPE_METADATA = 'T',
	SONIC_TYPE_PROGRESS = 'P',
	SONIC_TYPE_OUTPUT = 'O',
	SONIC_TYPE_COMPLETED = 'D'
};

struct sonic_message_ack {
};

struct sonic_message_started {
	const char* msg;
};

struct sonic_message_query {
	const char* query;
};

struct sonic_message_auth {
	const char* user;
	const char* key;
};

struct sonic_message_metadata {
	const char* name;
	const char* type;
	struct sonic_message_metadata* next;
};

enum sonic_status {
	SONIC_STATUS_QUEUED,
	SONIC_STATUS_STARTED,
	SONIC_STATUS_RUNNING,
	SONIC_STATUS_WAITING,
	SONIC_STATUS_FINISHED
};

struct sonic_message_progress {
	enum sonic_status status;
	int progress;
	int total;
	const char* units;
};

struct sonic_message_output {
	const json_object* value;
	struct sonic_message_output* next;
};

struct sonic_message_completed {
};

struct sonic_message {
	enum sonic_message_type type;
	union {
		struct sonic_message_ack ack;
		struct sonic_message_started started;
		struct sonic_message_query query;
		struct sonic_message_auth auth;
		struct sonic_message_metadata metadata;
		struct sonic_message_progress progress;
		struct sonic_message_output output;
		struct sonic_message_completed completed;
	} message;
	json_object* backing;
};

void sonic_message_init_ack(struct sonic_message* sm);

void sonic_message_init_started(struct sonic_message* sm, const char* msg);

void sonic_message_init_query(struct sonic_message* sm, const char* query);

void sonic_message_init_auth(
  struct sonic_message* sm, const char* user, const char* key);

void sonic_message_init_metadata(
  struct sonic_message* sm, const struct sonic_message_metadata* metadata);

void sonic_message_init_progress(struct sonic_message* sm,
  enum sonic_status status, int progress, int total, const char* units);

void sonic_message_init_output(
  struct sonic_message* sm, const struct sonic_message_output* output);

void sonic_message_init_completed(struct sonic_message* sm);

int sonic_message_decode(
  struct sonic_message* dst, const char* src, size_t src_len);

void sonic_message_deinit(struct sonic_message* msg);

int sonic_message_cmp(struct sonic_message* a, struct sonic_message* b);

int sonic_message_encode(
  char* dst, size_t dst_len, const struct sonic_message* src);

#endif
