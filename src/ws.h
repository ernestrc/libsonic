#ifndef SONIC_WS_H
#define SONIC_WS_H

#include <h2o.h>

#include "sonic.h"
#include "message.h"

struct sonic_ws_config {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	int io_timeout;
	int pool_timeout;
	int pool_capacity;
	int websocket_timeout;
	h2o_socketpool_t* sockpool;
};

struct sonic_ws_client {
	uv_loop_t* loop;
	int http_timeout;
	h2o_timeout_t io_timeout;
	h2o_socketpool_t sockpool;
	h2o_url_t url;
	h2o_http1client_t* http_client;
	h2o_http1client_ctx_t ctx;
};

int sonic_ws_client_init(
  struct sonic_ws_client* c, h2o_url_t url, struct sonic_ws_config* cfg);

int sonic_ws_client_send(struct sonic_ws_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx);

void sonic_ws_client_deinit(struct sonic_ws_client* c);

#endif
