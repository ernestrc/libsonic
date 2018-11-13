#include <h2o.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "tcp.h"
#include "util.h"

#define LENGTH_PREFIX 4

#define RELEASE_CTX(ctx)                                                       \
	if ((ctx)->buf.base)                                                       \
		free((ctx)->buf.base);                                                 \
	free(ctx);

#define HANDLE_ERR(ctx, err, msg)                                              \
	if (err != NULL) {                                                         \
		DEBUG_LOG("%s: %s\n", msg, err);                                       \
		if ((ctx)->sctx->on_error != NULL) {                                   \
			(ctx)->sctx->on_error(err, (ctx)->sctx->userdata);                 \
		}                                                                      \
		h2o_socket_close(sock);                                                \
		RELEASE_CTX(ctx);                                                      \
		return;                                                                \
	}

static const struct sonic_message SONIC_MESSAGE_ACK =
  (struct sonic_message){SONIC_TYPE_ACK};

struct sonic_tcp_ctx {
	struct sonic_message* cmd;
	struct sonic_stream_ctx* sctx;
	struct sonic_tcp_client* client;
	h2o_iovec_t buf;
};

static void send_msg(h2o_socket_t* sock, const struct sonic_message* msg,
  struct sonic_tcp_ctx* ctx, h2o_socket_cb cb);

static void on_write_ack(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, "failed to write ack message to socket", err);
	h2o_socket_close(sock);
	RELEASE_CTX(ctx);
}

static void on_read(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, "failed to write message to socket", err);

	int size_left = sock->input->size;
	char* data = sock->input->bytes;

	while (size_left > LENGTH_PREFIX) {
		DEBUG_LOG("scanning %d bytes", size_left);

		int msg_size = ((int)data[0]) << 24 | ((int)data[1]) << 16 |
		  ((int)data[2]) << 8 | ((int)data[3]);
		int chunk_size = LENGTH_PREFIX + msg_size;
		if (chunk_size > size_left)
			return;

		DEBUG_LOG("consuming %d bytes", chunk_size);

		struct sonic_message msg;
		int res = sonic_message_decode(&msg, data, chunk_size);
		if (res < 0)
			HANDLE_ERR(ctx, "failed to decode message", strerror(errno));

		DEBUG_LOG("decoded message of type %c", (char)msg.type);

#define CALL_HANDLER(handler, ...)                                             \
	if ((handler) != NULL) {                                                   \
		(handler)(__VA_ARGS__);                                                \
	}

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

		h2o_buffer_consume(&sock->input, chunk_size);
		data += chunk_size;
		size_left -= chunk_size;
	}
}

static void on_write_cmd(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, "failed to write command message to socket", err);
	h2o_socket_read_start(sock, on_read);
}

static void send_msg(h2o_socket_t* sock, const struct sonic_message* msg,
  struct sonic_tcp_ctx* ctx, h2o_socket_cb cb)
{
	int msg_size = sonic_message_encode(NULL, 0, msg);
	if (msg_size <= 0)
		HANDLE_ERR(ctx, "failed to encode message", strerror(errno));
	int encoded_size = msg_size + 1;
	int storage_size = LENGTH_PREFIX + encoded_size;
	int wire_size = LENGTH_PREFIX + msg_size;

	if ((ctx->buf.base = realloc(ctx->buf.base, storage_size)) == NULL) {
		HANDLE_ERR(
		  ctx, "failed to allocate storage to encode message", strerror(errno));
	}
	ctx->buf.base[3] = (char)msg_size << 24;
	ctx->buf.base[2] = (char)msg_size << 16;
	ctx->buf.base[1] = (char)msg_size << 8;
	ctx->buf.base[0] = (char)msg_size;
	sonic_message_encode(ctx->buf.base + LENGTH_PREFIX, encoded_size, msg);
	ctx->buf.len = wire_size;
	h2o_socket_write(sock, &ctx->buf, 1, cb);
}

static void on_handshake_complete(h2o_socket_t* sock, const char* err)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)sock->data;
	HANDLE_ERR(ctx, "TLS handshake failed", err);

	send_msg(sock, ctx->cmd, ctx, on_write_cmd);
}

static void on_connect(h2o_socket_t* sock, const char* err, void* data)
{
	struct sonic_tcp_ctx* ctx = (struct sonic_tcp_ctx*)data;
	HANDLE_ERR(ctx, "failed to connect to host", err);

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
	c->getaddr_receiver = cfg->getaddr_receiver;
	c->loop = cfg->loop;
	c->ssl_ctx = cfg->ssl_ctx;
	c->host = cfg->host;

	return 0;
}

int sonic_tcp_client_send(struct sonic_tcp_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* sctx)
{
	struct sonic_tcp_ctx* ctx;

	if ((ctx = calloc(1, sizeof(struct sonic_tcp_ctx))) == NULL)
		goto error;

	ctx->sctx = sctx;

	h2o_socketpool_connect(
	  NULL, c->sockpool, c->loop, c->getaddr_receiver, on_connect, ctx);

	return 0;

error:
	if (ctx)
		free(ctx);
	return 1;
}

void sonic_tcp_client_deinit(struct sonic_tcp_client* c) {}
