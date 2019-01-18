#ifndef SONIC_CLIENT_H
#define SONIC_CLIENT_H

#include <h2o.h>
#include <openssl/ssl.h>

#include "message.h"
#include "tcp.h"

struct sonic_client {
	struct sonic_tcp_client tcp;
	struct sonic_tcp_config tcp_cfg;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t sockpool;
	uv_loop_t* loop;
	uv_timer_t* close_dispatcher;
};

struct sonic_config {
	SSL_CTX* ssl_ctx;
	const char* url;
	int pool_capacity;
	int pool_timeout;
	/* TODO: implement on tcp client */
	int io_timeout;
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

int sonic_client_send(struct sonic_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx);

void sonic_client_free(struct sonic_client* c);

#endif
