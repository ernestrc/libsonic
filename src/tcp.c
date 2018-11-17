#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <h2o.h>

#include "tcp.h"
#include "util.h"

#define LENGTH_PREFIX 4

#define RELEASE_CTX(ctx)                                                       \
	if ((ctx)->buf.base)                                                       \
		free((ctx)->buf.base);                                                 \
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
	unlink_ctx(ctx);                                                           \
	free(ctx);

#define CALL_HANDLER(handler, ...)                                             \
	if ((handler) != NULL) {                                                   \
		(handler)(__VA_ARGS__);                                                \
	}

#define HANDLE_ERR(ctx, err, msg)                                              \
	if (err != NULL) {                                                         \
		CALL_HANDLER((ctx)->sctx->on_error, err, (ctx)->sctx->userdata);       \
		SONIC_LOG("%s: %s", err, msg "\n");                                    \
		RELEASE_CTX(ctx);                                                      \
		return;                                                                \
	}

struct sonic_tcp_ctx {
	struct sonic_message* cmd;
	struct sonic_stream_ctx* sctx;
	struct sonic_tcp_client* client;
	h2o_iovec_t buf;
	h2o_socketpool_connect_request_t* req;
	h2o_socket_t* sock;
	struct sonic_tcp_ctx* next;
};

static const struct sonic_message SONIC_MESSAGE_ACK =
  (struct sonic_message){SONIC_TYPE_ACK};

static void send_msg(h2o_socket_t* sock, const struct sonic_message* msg,
  struct sonic_tcp_ctx* ctx, h2o_socket_cb cb);

INLINE static void unlink_ctx(struct sonic_tcp_ctx* ctx)
{
	struct sonic_tcp_ctx *next, *prev;
	for (prev = NULL, next = ctx->client->reqs; next != NULL;
		 prev = next, next = next->next) {
		if (next == ctx) {
			if (prev == NULL) {
				ctx->client->reqs = next->next;
			} else {
				prev->next = next->next;
			}
			return;
		}
	}

	abort();
}

static void on_write_ack(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, err, "failed to write ack message to socket");

	SONIC_LOG("written ack, socket: %p\n", sock);

	RELEASE_CTX(ctx);
}

static void on_read(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, err, "failed to write message to socket");

	int size_left = sock->input->size;
	char* data = sock->input->bytes;

	int chunk_size, msg_size;
	struct sonic_message msg;

#define CONSUME(bytes)                                                         \
	h2o_buffer_consume(&sock->input, bytes);                                   \
	data += bytes;                                                             \
	size_left -= bytes;

	while (size_left > LENGTH_PREFIX) {
		msg_size = (data[0] & 255) << 24 | (data[1] & 255) << 16 |
		  (data[2] & 255) << 8 | (data[3] & 255);

		chunk_size = LENGTH_PREFIX + msg_size;

		if (chunk_size > size_left) {
			SONIC_LOG("chunk size %d is greater than size read %d\n",
			  chunk_size, size_left);
			return;
		}

		CONSUME(LENGTH_PREFIX);

		if (sonic_message_decode(&msg, data, msg_size) != 0)
			HANDLE_ERR(ctx, strerror(errno), "failed to decode message");

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
			CONSUME(msg_size);
			h2o_socket_read_stop(sock);
			send_msg(sock, &SONIC_MESSAGE_ACK, ctx, on_write_ack);
			return;
		case SONIC_TYPE_ACK:
			HANDLE_ERR(ctx, "unexpected message", "SONIC_TYPE_ACK")
		case SONIC_TYPE_AUTH:
			HANDLE_ERR(ctx, "unexpected message", "SONIC_TYPE_AUTH")
		case SONIC_TYPE_QUERY:
			HANDLE_ERR(ctx, "unexpected message", "SONIC_TYPE_QUERY")
		}

		sonic_message_deinit(&msg);
		CONSUME(msg_size);
	}
}

static void on_write_cmd(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, err, "failed to write command message to socket");

	SONIC_LOG("written cmd, socket: %p\n", sock);

	h2o_socket_read_start(sock, on_read);
}

INLINE static void send_msg(h2o_socket_t* sock, const struct sonic_message* msg,
  struct sonic_tcp_ctx* ctx, h2o_socket_cb cb)
{
	int msg_size = sonic_message_encode(NULL, 0, msg);
	if (msg_size <= 0)
		HANDLE_ERR(ctx, strerror(errno), "failed to encode message");
	int encoded_size = msg_size + 1;
	int storage_size = LENGTH_PREFIX + encoded_size;
	int wire_size = LENGTH_PREFIX + msg_size;

	if ((ctx->buf.base = realloc(ctx->buf.base, storage_size)) == NULL) {
		HANDLE_ERR(
		  ctx, strerror(errno), "failed to allocate storage to encode message");
	}
	ctx->buf.base[0] = (msg_size << 24) & 255;
	ctx->buf.base[1] = (msg_size << 16) & 255;
	ctx->buf.base[2] = (msg_size << 8) & 255;
	ctx->buf.base[3] = msg_size & 255;
	ctx->buf.len = wire_size;

	sonic_message_encode(ctx->buf.base + LENGTH_PREFIX, encoded_size, msg);

	SONIC_LOG("sending message, size: %d, encoded_size: %d, storage_size: %d, "
			  "wire_size: %d, socket: %p, msg: '%s'\n",
	  msg_size, encoded_size, storage_size, wire_size, sock,
	  ctx->buf.base + LENGTH_PREFIX);

	h2o_socket_write(sock, &ctx->buf, 1, cb);
}

static void on_handshake_complete(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, err, "TLS handshake failed");

	send_msg(sock, ctx->cmd, ctx, on_write_cmd);
}

static void on_connect(h2o_socket_t* sock, const char* err, void* data)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)data;
	HANDLE_ERR(ctx, err, "failed to connect to host");

	SONIC_LOG("connect request %p: connected socket: %p\n", ctx->req, sock);

	ctx->req = NULL;
	ctx->sock = sock;
	sock->data = ctx;

	if (ctx->client->ssl_ctx != NULL) {
		h2o_socket_ssl_handshake(
		  sock, ctx->client->ssl_ctx, ctx->client->host, on_handshake_complete);
		return;
	}

	send_msg(sock, ctx->cmd, ctx, on_write_cmd);
}

int sonic_tcp_client_init(
  struct sonic_tcp_client* c, struct sonic_tcp_config* cfg)
{
	c->sockpool = cfg->sockpool;
	c->loop = cfg->loop;
	c->ssl_ctx = cfg->ssl_ctx;
	c->host = cfg->host;
	c->reqs = NULL;

	return 0;
}

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* sctx)
{
	struct sonic_tcp_ctx* ctx = NULL;

	if ((ctx = calloc(1, sizeof(struct sonic_tcp_ctx))) == NULL)
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
	struct sonic_tcp_ctx *tmp, *next = c->reqs;
	while (next != NULL) {
		tmp = next->next;
		RELEASE_CTX(next);
		next = tmp;
	}
	c->reqs = NULL;
}
