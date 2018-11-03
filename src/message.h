#ifndef SONIC_MESSAGE_H
#define SONIC_MESSAGE_H

#include <json-c/json.h>

enum sonic_message_type {
	SONIC_ACK = 'A',
	SONIC_STARTED = 'S',
	SONIC_QUERY = 'Q',
	SONIC_AUTH = 'H',
	SONIC_METADATA = 'T',
	SONIC_PROGRESS = 'P',
	SONIC_OUTPUT = 'O',
	SONIC_COMPLETED = 'D'
};

struct sonic_message_ack {};
struct sonic_message_started {
	char* msg;
};

struct sonic_message_query {
	char* query;
};

struct sonic_message_auth {
	char* user;
	char* key;
};

struct sonic_message_metadata {
	char* name;
	char* type;
	struct sonic_message_metadata* next;
};

enum sonic_status {
	queued,
	started,
	running,
	waiting,
	finished
};

struct sonic_message_progress {
	enum sonic_status status;
	int progress;
	int total;
	char* units;
};

struct sonic_message_output {
	json_object* value;
	struct sonic_message_output* next;
};

struct sonic_message_completed {
};

struct sonic_message {
	enum sonic_message_type type;
	char* variation;
	char* payload;
	union {
		struct sonic_message_ack ack;
		struct sonic_message_started started;
		struct sonic_message_query query;
		struct sonic_message_auth auth;
		struct sonic_message_metadata meta;
		struct sonic_message_progress progress;
		struct sonic_message_output output;
		struct sonic_message_completed completed;
	} msg;
};

#endif
