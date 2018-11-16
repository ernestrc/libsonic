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
	const char* trace_id;
};

struct sonic_message_query {
	const char* query;
	const char* auth;
	const json_object* config;
};

struct sonic_message_auth {
	const char* user;
	const char* key;
};

struct sonic_message_metadata {
	const char* name;
	enum json_type type;
	struct sonic_message_metadata* next;
};

enum sonic_status {
	SONIC_STATUS_QUEUED = 0,
	SONIC_STATUS_STARTED = 1,
	SONIC_STATUS_RUNNING = 2,
	SONIC_STATUS_WAITING = 3,
	SONIC_STATUS_FINISHED = 4
};

struct sonic_message_progress {
	enum sonic_status status;
	double progress;
	double total;
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
		struct sonic_message_progress progress;
		const struct sonic_message_metadata* metadata;
		const struct sonic_message_output* output;
		struct sonic_message_completed completed;
	} message;
	json_object* backing;
};

void sonic_message_init_ack(struct sonic_message* sm);

void sonic_message_init_started(struct sonic_message* sm);

void sonic_message_init_query(struct sonic_message* sm, const char* query,
  const char* auth, const json_object* config);

void sonic_message_init_auth(
  struct sonic_message* sm, const char* user, const char* key);

void sonic_message_init_metadata(
  struct sonic_message* sm, const struct sonic_message_metadata* metadata);

void sonic_message_init_progress(struct sonic_message* sm,
  enum sonic_status status, double progress, double total, const char* units);

void sonic_message_init_output(
  struct sonic_message* sm, const struct sonic_message_output* output);

void sonic_message_init_completed(struct sonic_message* sm);

int sonic_message_decode(
  struct sonic_message* dst, const char* src, size_t src_len);

void sonic_message_deinit(struct sonic_message* msg);

int sonic_message_cmp(struct sonic_message* a, struct sonic_message* b);

size_t sonic_message_encode(
  char* dst, size_t dst_len, const struct sonic_message* src);

#endif
