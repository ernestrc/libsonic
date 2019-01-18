#ifndef SONIC_TCP_H
#define SONIC_TCP_H

#include <h2o.h>
#include <openssl/ssl.h>
#include <uv.h>

#include "message.h"
#include "sonic.h"

struct sonic_tcp_client_ctx {
	struct sonic_message* cmd;
	struct sonic_client_ctx* sctx;
	struct sonic_tcp_client* client;
	h2o_iovec_t buf;
	h2o_socketpool_connect_request_t* req;
	h2o_socket_t* sock;
	struct sonic_tcp_client_ctx* next;
};

struct sonic_tcp_client {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	struct sonic_tcp_client_ctx* reqs;
	const char* host;
};

struct sonic_tcp_client_config {
	uv_loop_t* loop;
	SSL_CTX* ssl_ctx;
	h2o_socketpool_t* sockpool;
	/* used for tls handshake */
	const char* host;
};

struct sonic_tcp_server {
	uv_loop_t* loop;
	h2o_globalconf_t h2o_config;
	// TODO struct sonic_tcp_listen_ctx* ctxs;
};

struct sonic_tcp_server_config {
	uv_loop_t* loop;
	h2o_globalconf_t* h2o_config;
};

struct sonic_tcp_listen_config {
	int conn_backlog;
	SSL_CTX* ssl_ctx;
	const char* iface;
	int port;
};

int sonic_tcp_client_init(
  struct sonic_tcp_client* c, struct sonic_tcp_client_config* cfg);

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_client_ctx* ctx);

// TODO sonic_tcp_client_close(); and pass h2o_socket ptr to callback in
// sonic_client_ctx*

void sonic_tcp_client_deinit(struct sonic_tcp_client* c);

struct sonic_tcp_server_socket {
	struct sonic_tcp_server* server;
	uv_tcp_t conn;
	h2o_socket_t* sock;
	void (*close_cb)(struct sonic_tcp_server_socket*);
	void (*msg_cb)(
	  struct sonic_tcp_server_socket*, const char* err, struct sonic_message*);
};

typedef void (*sonic_tcp_server_accept_cb)(
  const char* err, struct sonic_tcp_server_socket*);

typedef void (*sonic_tcp_server_send_cb)(
  const char* err, struct sonic_tcp_server_socket*);

int sonic_tcp_server_init(
  struct sonic_tcp_server* c, struct sonic_tcp_server_config* cfg);

int sonic_tcp_server_listen(struct sonic_tcp_server* c,
  struct sonic_tcp_listen_config* config, sonic_tcp_server_accept_cb cb);

void sonic_tcp_server_send(struct sonic_tcp_server_socket* sock,
  struct sonic_message* cmd, sonic_tcp_server_send_cb* cb);

void sonic_tcp_server_close(struct sonic_tcp_server_socket* sock);

void sonic_tcp_server_deinit(struct sonic_tcp_server* c);

#endif
