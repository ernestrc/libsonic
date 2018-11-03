#ifndef SONIC_CLIENT_H
#define SONIC_CLIENT_H

#include <h2o.h>

struct sonic_client {
	int http_timeout;
	h2o_timeout_t io_timeout;
	h2o_socketpool_t sockpool;
	h2o_mem_pool_t mempool;
	h2o_url_t url;
	h2o_http1client_t* http_client;
	h2o_http1client_ctx_t ctx;
	h2o_multithread_receiver_t getaddr_receiver;
	h2o_multithread_queue_t* queue;
};

struct sonic_config {
	const char* url;
	int io_timeout;
	int pool_timeout;
	int pool_capacity;
	int websocket_timeout;
};

struct sonic_client* sonic_client_create(
  uv_loop_t* loop, struct sonic_config* cfg);
int sonic_client_init(
  struct sonic_client* c, uv_loop_t* loop, struct sonic_config* cfg);
void sonic_client_free(struct sonic_client* c);

#endif
