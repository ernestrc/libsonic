#include <netdb.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <h2o.h>

#include "tcp.h"
#include "util.h"

#define DEFAULT_CONN_BACKLOG 128

#define LENGTH_PREFIX 4

#define MESSAGE_GET_SIZE(data)                                                 \
	(data[0] & 255) << 24 | (data[1] & 255) << 16 | (data[2] & 255) << 8 |     \
	  (data[3] & 255)

#define CONSUME(data, size_left, sock, n)                                      \
	h2o_buffer_consume(&(sock)->input, n);                                     \
	(data) += (n);                                                             \
	(size_left) -= (n);

static const struct sonic_message SONIC_MESSAGE_ACK =
  (struct sonic_message){SONIC_TYPE_ACK};

INLINE static int tcp_send_msg(h2o_socket_t* sock,
  const struct sonic_message* msg, h2o_iovec_t* buf, h2o_socket_cb cb)
{
	int msg_size = sonic_message_encode(NULL, 0, msg);
	if (msg_size <= 0) {
		errno = EINVAL;
		return -1;
	}
	int encoded_size = msg_size + 1;
	int storage_size = LENGTH_PREFIX + encoded_size;
	int wire_size = LENGTH_PREFIX + msg_size;

	if ((buf->base = realloc(buf->base, storage_size)) == NULL) {
		errno = ENOMEM;
		return -1;
	}
	buf->base[0] = (msg_size << 24) & 255;
	buf->base[1] = (msg_size << 16) & 255;
	buf->base[2] = (msg_size << 8) & 255;
	buf->base[3] = msg_size & 255;
	buf->len = wire_size;

	sonic_message_encode(buf->base + LENGTH_PREFIX, encoded_size, msg);

	SONIC_LOG("sending message, size: %d, encoded_size: %d, storage_size: %d, "
			  "wire_size: %d, socket: %p, msg: '%s'\n",
	  msg_size, encoded_size, storage_size, wire_size, sock,
	  buf->base + LENGTH_PREFIX);

	h2o_socket_write(sock, buf, 1, cb);

	return 0;
}

/* CLIENT */

#define RELEASE_CLIENT_CTX(ctx)                                                \
	if ((ctx)->buf.base) {                                                     \
		free((ctx)->buf.base);                                                 \
		(ctx)->buf.base = NULL;                                                \
	}                                                                          \
	if ((ctx)->req != NULL) {                                                  \
		SONIC_LOG("canceling connect request %p", (ctx)->req);                 \
		h2o_socketpool_cancel_connect((ctx)->req);                             \
		(ctx)->req = NULL;                                                     \
	}                                                                          \
	if ((ctx)->sock != NULL) {                                                 \
		SONIC_LOG("closing socket %p\n", (ctx)->sock);                         \
		h2o_socket_close((ctx)->sock);                                         \
		(ctx)->sock = NULL;                                                    \
	}                                                                          \
	UNLINK_NODE(struct sonic_tcp_client_ctx, ctx);                             \
	free(ctx);

#define HANDLE_CLIENT_ERROR(ctx, err, msg)                                     \
	if ((err) != NULL) {                                                       \
		CALL_HANDLER((ctx)->sctx->on_error, (err), (ctx)->sctx->userdata);     \
		SONIC_LOG("%s: %s", (err), msg "\n");                                  \
		RELEASE_CLIENT_CTX(ctx);                                               \
		return;                                                                \
	}

static void on_ack(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_client_ctx* ctx = (struct sonic_tcp_client_ctx*)sock->data;
	HANDLE_CLIENT_ERROR(ctx, err, "failed to write ack message to socket");

	SONIC_LOG("written ack, socket: %p\n", sock);

	RELEASE_CLIENT_CTX(ctx);
}

static void on_client_read(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_client_ctx* ctx = (struct sonic_tcp_client_ctx*)sock->data;
	HANDLE_CLIENT_ERROR(ctx, err, "failed to write message to socket");

	int size_left = sock->input->size;
	char* data = sock->input->bytes;

	int chunk_size, msg_size;
	struct sonic_message msg;
	while (size_left > LENGTH_PREFIX) {
		msg_size = MESSAGE_GET_SIZE(data);
		chunk_size = LENGTH_PREFIX + msg_size;
		if (chunk_size > size_left) {
			SONIC_LOG("chunk size %d is greater than size read %d\n",
			  chunk_size, size_left);
			return;
		}

		CONSUME(data, size_left, sock, LENGTH_PREFIX);

		if (sonic_message_decode(&msg, data, msg_size) != 0)
			HANDLE_CLIENT_ERROR(
			  ctx, strerror(errno), "failed to decode message");

		switch (msg.type) {
		case SONIC_TYPE_STARTED:
			CALL_HANDLER(ctx->sctx->on_started, ctx->sctx->userdata);
			break;
		case SONIC_TYPE_PROGRESS:
			CALL_HANDLER(ctx->sctx->on_progress, &msg.message.progress,
			  ctx->sctx->userdata);
			break;
		case SONIC_TYPE_METADATA:
			CALL_HANDLER(ctx->sctx->on_metadata, msg.message.metadata,
			  ctx->sctx->userdata);
			break;
		case SONIC_TYPE_OUTPUT:
			CALL_HANDLER(
			  ctx->sctx->on_data, msg.message.output, ctx->sctx->userdata);
			break;
		case SONIC_TYPE_COMPLETED:
			CALL_HANDLER(ctx->sctx->on_complete, ctx->sctx->userdata);
			sonic_message_deinit(&msg);
			CONSUME(data, size_left, sock, msg_size);
			h2o_socket_read_stop(sock);
			if (tcp_send_msg(sock, &SONIC_MESSAGE_ACK, &ctx->buf, on_ack) !=
			  0) {
				HANDLE_CLIENT_ERROR(
				  ctx, strerror(errno), "failed to send ack message");
			}
			return;
		case SONIC_TYPE_ACK:
			HANDLE_CLIENT_ERROR(ctx, "unexpected message", "SONIC_TYPE_ACK")
		case SONIC_TYPE_AUTH:
			HANDLE_CLIENT_ERROR(ctx, "unexpected message", "SONIC_TYPE_AUTH")
		case SONIC_TYPE_QUERY:
			HANDLE_CLIENT_ERROR(ctx, "unexpected message", "SONIC_TYPE_QUERY")
		}
		sonic_message_deinit(&msg);
		CONSUME(data, size_left, sock, msg_size);
	}
}

static void on_write_cmd(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_client_ctx* ctx = (struct sonic_tcp_client_ctx*)sock->data;
	HANDLE_CLIENT_ERROR(ctx, err, "failed to write command message to socket");

	SONIC_LOG("written cmd, socket: %p\n", sock);

	h2o_socket_read_start(sock, on_client_read);
}

static void on_handshake_complete(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_client_ctx* ctx = (struct sonic_tcp_client_ctx*)sock->data;
	HANDLE_CLIENT_ERROR(ctx, err, "TLS handshake failed");

	if (tcp_send_msg(sock, ctx->cmd, &ctx->buf, on_write_cmd) != 0) {
		HANDLE_CLIENT_ERROR(ctx, strerror(errno), "failed to send command");
	}
}

static void on_connect(h2o_socket_t* sock, const char* err, void* data)
{
	struct sonic_tcp_client_ctx* ctx = (struct sonic_tcp_client_ctx*)data;
	HANDLE_CLIENT_ERROR(ctx, err, "failed to connect to host");

	SONIC_LOG("connect request %p: connected socket: %p\n", ctx->req, sock);

	ctx->req = NULL;
	ctx->sock = sock;
	sock->data = ctx;

	if (ctx->client->ssl_ctx != NULL) {
		h2o_socket_ssl_handshake(
		  sock, ctx->client->ssl_ctx, ctx->client->host, on_handshake_complete);
		return;
	}

	if (tcp_send_msg(sock, ctx->cmd, &ctx->buf, on_write_cmd) != 0) {
		HANDLE_CLIENT_ERROR(ctx, strerror(errno), "failed to send command");
	}
}

int sonic_tcp_client_init(
  struct sonic_tcp_client* c, struct sonic_tcp_client_config* cfg)
{
	c->sockpool = cfg->sockpool;
	c->loop = cfg->loop;
	c->ssl_ctx = cfg->ssl_ctx;
	c->host = cfg->host;
	c->reqs = NULL;

	return 0;
}

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_client_ctx* sctx)
{
	struct sonic_tcp_client_ctx* ctx = NULL;

	if ((ctx = calloc(1, sizeof(struct sonic_tcp_client_ctx))) == NULL)
		goto error;

	ctx->sctx = sctx;
	ctx->cmd = cmd;
	ctx->client = c;

	h2o_socketpool_connect(
	  &ctx->req, c->sockpool, c->loop, NULL, on_connect, ctx);

	SONIC_LOG("created connect request %p\n", ctx->req);

	ctx->next = c->reqs;
	ctx->sock = NULL;
	c->reqs = ctx;

	return 0;

error:
	if (ctx)
		free(ctx);
	return 1;
}

void sonic_tcp_client_deinit(struct sonic_tcp_client* c)
{
	struct sonic_tcp_client_ctx *tmp, *next = c->reqs;
	while (next != NULL) {
		tmp = next->next;
		RELEASE_CLIENT_CTX(next);
		next = tmp;
	}
	c->reqs = NULL;
}

/* SERVER */

struct sonic_tcp_listen_ctx {
	uv_tcp_t listener;
	h2o_accept_ctx_t accept_ctx;
	h2o_context_t h2o_ctx;
	sonic_tcp_server_accept_cb user_cb;
	struct sonic_tcp_listen_ctx* next;
};

INLINE static void sonic_tcp_ctx_free(struct sonic_tcp_listen_ctx* ctx)
{
	if (ctx) {
		uv_close((uv_handle_t*)&ctx->listener, NULL);
		if (ctx->h2o_ctx.loop != NULL) {
			h2o_context_dispose(&ctx->h2o_ctx);
		}
		free(ctx);
	}
}

INLINE static bool sanitized_listen_config(
  struct sonic_tcp_listen_config* config)
{
	if (config == NULL) {
		return false;
	}

	if (config->port < 0 || config->port > 65535) {
		return false;
	}

	if (config->conn_backlog < 0) {
		return false;
	}

	if (config->iface == NULL) {
		config->iface = "127.0.0.1";
	}

	if (config->conn_backlog == 0) {
		config->conn_backlog = DEFAULT_CONN_BACKLOG;
	}

	return true;
}

static void server_socket_free_from_uv(uv_handle_t* handle)
{
	struct sonic_tcp_server_socket* socket =
	  (struct sonic_tcp_server_socket*)handle->data;
	free(socket);
}

static void server_socket_close_from_uv(uv_handle_t* handle)
{
	struct sonic_tcp_server_socket* socket =
	  (struct sonic_tcp_server_socket*)handle->data;

	if (socket->close_cb) {
		socket->close_cb(socket);
	}

	server_socket_free_from_uv(handle);
}

INLINE static struct sonic_tcp_server_socket* server_socket_create(
  struct sonic_tcp_listen_ctx* ctx)
{
	int lerrno;
	struct sonic_tcp_server_socket* socket = NULL;
	h2o_socket_t* h2o_socket = NULL;

	if ((socket = calloc(1, sizeof(struct sonic_tcp_server_socket))) == NULL)
		goto error;

	if ((lerrno = uv_tcp_init(ctx->listener.loop, &socket->conn)) != 0) {
		errno = -lerrno;
		goto error;
	}

	if ((h2o_socket = h2o_uv_socket_create(
		   (uv_stream_t*)&socket->conn, server_socket_close_from_uv)) == NULL) {
		errno = ENOMEM;
		goto error;
	}

	if ((lerrno = uv_accept(
		   (uv_stream_t*)&ctx->listener, (uv_stream_t*)&socket->conn)) != 0) {
		errno = -lerrno;
		goto error;
	}

	socket->sock = h2o_socket;
	socket->conn.data = socket;
	h2o_socket->data = socket;

	return socket;

error:
	lerrno = errno;
	if (h2o_socket)
		h2o_socket_close(h2o_socket);
	if (socket)
		uv_close((uv_handle_t*)&socket->conn, server_socket_free_from_uv);
	errno = lerrno;
	return NULL;
}

// TODO
// TODO
// TODO
// TODO
// TODO
// TODO
// TODO
static void on_server_read(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_server_socket* socket =
	  (struct sonic_tcp_server_socket*)sock->data;
	if (err) {
		socket->msg_cb(socket, err, NULL);
		return;
	}

	int size_left = sock->input->size;
	char* data = sock->input->bytes;

	int chunk_size, msg_size;
	struct sonic_message msg;
	while (size_left > LENGTH_PREFIX) {
		msg_size = MESSAGE_GET_SIZE(data);
		chunk_size = LENGTH_PREFIX + msg_size;
		if (chunk_size > size_left) {
			SONIC_LOG("chunk size %d is greater than size read %d\n",
			  chunk_size, size_left);
			return;
		}

		CONSUME(data, size_left, sock, LENGTH_PREFIX);

		if (sonic_message_decode(&msg, data, msg_size) != 0) {
			// TODO add an error callback force_snprintf(err, "failed to decode message: %s", );
			socket->msg_cb(socket, err, NULL);
		}
			// HANDLE_CLIENT_ERROR(
			  // ctx, strerror(errno), "failed to decode message");

		switch (msg.type) {
		}
	}
}

INLINE static void server_socket_free(struct sonic_tcp_server_socket* socket)
{
	if (socket) {
		// will call callback to call user_cb and free up memory
		h2o_socket_close(socket->sock);
	}
}

static void on_accept(uv_stream_t* listener, int status)
{
	struct sonic_tcp_server_socket* sock = NULL;
	char* err = NULL;
	struct sonic_tcp_listen_ctx* ctx =
	  (struct sonic_tcp_listen_ctx*)listener->data;

	if (status != 0) {
		err_snprintf(err, "uv on_connection_cb non-zero, status: %d, ctx: %p",
		  status, ctx);
		goto error;
	}

	if ((sock = server_socket_create(ctx)) == NULL) {
		err_snprintf(err, "server_socket_create: %s", strerror(errno));
		goto error;
	}

	h2o_socket_read_start(sock->sock, on_server_read);

	return;

error:
	if (err) {
		ctx->user_cb(err, NULL);
		free(err);
	} else {
		ctx->user_cb("out of memory", NULL);
	}
	server_socket_free(sock);
}

int sonic_tcp_server_listen(struct sonic_tcp_server* c,
  struct sonic_tcp_listen_config* config, sonic_tcp_server_accept_cb cb)
{
	struct sonic_tcp_listen_ctx* ctx = NULL;
	struct sockaddr_in addr;
	int r;

	if (!sanitized_listen_config(config)) {
		errno = EINVAL;
		return -1;
	}

	if ((r = uv_ip4_addr(config->iface, config->port, &addr)) != 0) {
		errno = -r;
		return -1;
	}

	if ((ctx = calloc(1, sizeof(struct sonic_tcp_listen_ctx))) == NULL) {
		r = -ENOMEM;
		goto error;
	}

	if ((r = uv_tcp_init(c->loop, &ctx->listener)) != 0)
		goto error;

	if ((r = uv_tcp_bind(&ctx->listener, (struct sockaddr*)&addr, 0)) != 0) {
		goto error;
	}

	h2o_context_init(&ctx->h2o_ctx, c->loop, &c->h2o_config);
	ctx->accept_ctx.ctx = &ctx->h2o_ctx;
	ctx->accept_ctx.hosts = c->h2o_config.hosts;
	ctx->accept_ctx.ssl_ctx = config->ssl_ctx;
	ctx->user_cb = cb;

	ctx->listener.data = ctx;
	if ((r = uv_listen((uv_stream_t*)&ctx->listener, config->conn_backlog,
		   on_accept)) != 0) {
		goto error;
	}

	// link to client
	// TODO ctx->next = c->ctxs;
	// TODO c->ctxs = ctx;

	return 0;

error:
	sonic_tcp_ctx_free(ctx);
	errno = -r;
	return -1;
}

void sonic_tcp_server_send(struct sonic_tcp_server_socket* sock,
  struct sonic_message* cmd, sonic_tcp_server_send_cb* cb)
{
}

void sonic_tcp_server_close(struct sonic_tcp_server_socket* sock) {}

int sonic_tcp_server_init(
  struct sonic_tcp_server* c, struct sonic_tcp_server_config* cfg)
{
	memset(c, 0, sizeof(struct sonic_tcp_server));

	c->loop = cfg->loop;

	if (cfg->h2o_config != NULL) {
		c->h2o_config = *cfg->h2o_config;
	} else {
		h2o_config_init(&c->h2o_config);
	}

	return 0;
}

// TODO sonic_tcp_server_deinit
//	-	should dispose h2o resources
//	-	should close all listen ctxs
