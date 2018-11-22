#ifndef SONIC_TCP_H
#define SONIC_TCP_H

#include <h2o.h>
#include <openssl/ssl.h>
#include <uv.h>

#include "message.h"
#include "sonic.h"

struct sonic_tcp_ctx {
	struct sonic_message* cmd;
	struct sonic_stream_ctx* sctx;
	struct sonic_tcp_client* client;
	h2o_iovec_t buf;
	h2o_socketpool_connect_request_t* req;
	h2o_socket_t* sock;
	struct sonic_tcp_ctx* next;
};

struct sonic_tcp_client {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	struct sonic_tcp_ctx* reqs;
	const char* host;
};

struct sonic_tcp_config {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	/* used for tls handshake */
	const char* host;
};

int sonic_tcp_client_init(
  struct sonic_tcp_client* c, struct sonic_tcp_config* cfg);

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx);

void sonic_tcp_client_deinit(struct sonic_tcp_client* c);

#endif
