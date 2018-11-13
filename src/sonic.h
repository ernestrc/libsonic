#ifndef SONIC_SONIC_H
#define SONIC_SONIC_H

#include "message.h"

struct sonic_stream_ctx {
	void (*on_started)(void*);
	void (*on_progress)(const struct sonic_message_progress*, void*);
	void (*on_metadata)(const struct sonic_message_metadata*, void*);
	void (*on_data)(const struct sonic_message_output*, void*);
	void (*on_error)(const char* err, void*);
	void (*on_complete)(void*);
	void* userdata;
};

#endif
