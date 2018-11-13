#ifndef SONIC_TCP_H
#define SONIC_TCP_H

#include <uv.h>

#include "message.h"
#include "sonic.h"

struct sonic_tcp_client {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	h2o_multithread_receiver_t* getaddr_receiver;
	const char* host;
};

struct sonic_tcp_config {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	h2o_multithread_receiver_t* getaddr_receiver;
	/* used for tls handshake */
	const char* host;
};

int sonic_tcp_client_init(
  struct sonic_tcp_client* c, struct sonic_tcp_config* cfg);

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx);

void sonic_tcp_client_deinit(struct sonic_tcp_client* c);

#endif
