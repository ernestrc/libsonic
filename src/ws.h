#ifndef SONIC_WS_H
#define SONIC_WS_H

#include <h2o.h>
#include <openssl/ssl.h>
#include <uv.h>
#include <wslay/wslay.h>

#include "message.h"
#include "sonic.h"

struct sonic_ws_ctx {
	struct sonic_ws_ctx* next;
	h2o_http1client_ctx_t httpctx;
	h2o_iovec_t httpreq;
	struct sonic_message* cmd;
	struct sonic_stream_ctx* sctx;
	struct sonic_ws_client* client;
	h2o_iovec_t buf;
	h2o_http1client_t* req;
	h2o_socket_t* sock; // TODO needed?
	h2o_timeout_t io_timeout;
	wslay_event_context_ptr wslay_ctx;
};

struct sonic_ws_client {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	struct sonic_ws_ctx* reqs;
	const char* host;
	int io_timeout;
};

struct sonic_ws_config {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	/* used for tls handshake */
	const char* host;
	int io_timeout;
};

int sonic_ws_client_init(
  struct sonic_ws_client* c, h2o_url_t url, struct sonic_ws_config* cfg);

int sonic_ws_client_send(struct sonic_ws_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx);

void sonic_ws_client_deinit(struct sonic_ws_client* c);

#endif
