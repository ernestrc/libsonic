#ifndef SONIC_CLIENT_H
#define SONIC_CLIENT_H

#include <h2o.h>
#include <openssl/ssl.h>

#include "message.h"
#include "tcp.h"
#include "ws.h"

enum sonic_client_type { SONIC_WS_CLIENT, SONIC_TCP_CLIENT };

struct sonic_client {
	enum sonic_client_type type;
	union {
		struct sonic_ws_client ws;
		struct sonic_tcp_client tcp;
	} client;
	SSL_CTX* ssl_ctx;
};

struct sonic_config {
	const char* url;
	struct sonic_ws_config ws;
	struct sonic_tcp_config tcp;
};

struct sonic_query_result {
	struct sonic_message_metadata* meta;
	struct sonic_message_output* data;
};

struct sonic_query_ctx {
	const char* query;
	const char* auth;
	const json_object* config;
	void* userdata;
};

typedef void (*sonic_stream_callback)(
  struct sonic_query_ctx*, struct sonic_query_result*);

struct sonic_client* sonic_client_create(
  uv_loop_t* loop, struct sonic_config* cfg);

int sonic_client_init(
  struct sonic_client* c, uv_loop_t* loop, struct sonic_config* cfg);

int sonic_client_query(struct sonic_client* c, struct sonic_query_ctx* ctx,
  sonic_stream_callback* cb);

void sonic_client_deinit(struct sonic_client* c);

void sonic_client_free(struct sonic_client* c);

#endif
