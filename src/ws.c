#include <stdbool.h>
#include <sys/random.h>

#include "util.h"
#include "ws.h"
#include <wslay/wslay.h>

//#define RELEASE_WS_CTX(ctx)                                                    \
//	if ((ctx)->buf.base) {                                                     \
//		free((ctx)->buf.base);                                                 \
//		(ctx)->buf.base = NULL;                                                \
//	}                                                                          \
//	if ((ctx)->httpreq.base)                                                   \
//		free((ctx)->httpreq.base);                                             \
//	if ((ctx)->req != NULL) {                                                  \
//		SONIC_LOG("canceling connect request %p", (ctx)->req);                 \
//		h2o_http1client_cancel((ctx)->req);                                    \
//		(ctx)->req = NULL;                                                     \
//	}                                                                          \
//	if ((ctx)->wslay_ctx != NULL) {                                            \
//		wslay_event_context_free((ctx)->wslay_ctx);                            \
//	}                                                                          \
//	if ((ctx)->io_timeout.timeout != 0) {                                      \
//		h2o_timeout_dispose((ctx)->client->loop, &ctx->io_timeout);            \
//		(ctx)->io_timeout.timeout = 0;                                         \
//	}                                                                          \
//	if ((ctx)->sock != NULL) {                                                 \
//		SONIC_LOG("closing socket %p\n", (ctx)->sock);                         \
//		h2o_socket_close((ctx)->sock);                                         \
//		(ctx)->sock = NULL;                                                    \
//	}                                                                          \
//	UNLINK_NODE(struct sonic_ws_ctx, ctx);                                     \
//	free(ctx);
//
//#define DISPATCH_ERR(ctx, err, msg)                                            \
//	{                                                                          \
//		CALL_HANDLER((ctx)->sctx->on_error, (msg), (ctx)->sctx->userdata);     \
//		SONIC_LOG("%s: %s", (err), msg "\n");                                  \
//		RELEASE_WS_CTX(ctx);                                                   \
//		return NULL;                                                           \
//	}
//
//INLINE static const char* get_wslay_err(int err)
//{
//	switch (err) {
//	case WSLAY_ERR_WANT_READ:
//		return "WSLAY_ERR_WANT_READ";
//	case WSLAY_ERR_WANT_WRITE:
//		return "WSLAY_ERR_WANT_WRITE";
//	case WSLAY_ERR_PROTO:
//		return "WSLAY_ERR_PROTO";
//	case WSLAY_ERR_INVALID_ARGUMENT:
//		return "WSLAY_ERR_INVALID_ARGUMENT";
//	case WSLAY_ERR_INVALID_CALLBACK:
//		return "WSLAY_ERR_INVALID_CALLBACK";
//	case WSLAY_ERR_NO_MORE_MSG:
//		return "WSLAY_ERR_NO_MORE_MSG";
//	case WSLAY_ERR_CALLBACK_FAILURE:
//		return "WSLAY_ERR_CALLBACK_FAILURE";
//	case WSLAY_ERR_WOULDBLOCK:
//		return "WSLAY_ERR_WOULDBLOCK";
//	case WSLAY_ERR_NOMEM:
//		return "WSLAY_ERR_NOMEM";
//	}
//
//	abort();
//}
//
//int sonic_ws_client_init(
//  struct sonic_ws_client* c, h2o_url_t url, struct sonic_ws_config* cfg)
//{
//	c->sockpool = cfg->sockpool;
//	c->loop = cfg->loop;
//	c->ssl_ctx = cfg->ssl_ctx;
//	c->host = cfg->host;
//	c->reqs = NULL;
//	c->io_timeout = cfg->io_timeout;
//}
//
//// int client_read_handshake(rp_ctx_t* rp_ctx)
//// {
//// 	char *keyhdstart, *keyhdend;
//// 	ws_ctx_t* ws_ctx = rp_ctx->user_data;
//// 	buf_t* ibuf = ws_ctx->tcp_ctx->ibuf;
////
//// 	switch (tcp_conn_read(rp_ctx->conn, ibuf)) {
//// 	case -1:
//// 		perror("tcp_conn_read");
//// 		goto err;
//// 	case 1: /* buffer is full */
//// 		errno = ENOMEM;
//// 		goto err;
//// 	default:
//// 		if (ibuf->next_write < ibuf->buf + 4 ||
//// 		  memcmp(ibuf->next_write - 4, "\r\n\r\n", 4) != 0)
//// 			return 0;
//// 	}
////
//// 	/* verify accept key */
////
//// 	if ((keyhdstart = http_header_find_field_value(
//// 		   ibuf->buf, "Sec-WebSocket-Accept", NULL)) == NULL) {
//// 		errno = EBADMSG;
//// 		goto err;
//// 	}
////
//// 	for (; *keyhdstart == ' '; ++keyhdstart)
//// 		;
////
//// 	keyhdend = keyhdstart;
////
//// 	for (; *keyhdend != '\r' && *keyhdend != ' '; ++keyhdend)
//// 		;
////
//// 	if (buf_writable(ws_ctx->tcp_ctx->ibuf) <
//// 	  BASE64_ENCODE_RAW_LENGTH(20) + 1) {
//// 		errno = ENOMEM;
//// 		goto err;
//// 	}
////
//// 	create_accept_key(ws_ctx->tcp_ctx->obuf->next_write, ws_ctx->client_key);
////
//// 	if (memcmp(ws_ctx->tcp_ctx->obuf->next_write, keyhdstart,
//// 		  BASE64_ENCODE_RAW_LENGTH(20)) != 0) {
//// 		errno = EBADMSG;
//// 		goto err;
//// 	}
////
//// 	ws_ctx->state = WS_CONNECTED;
//// 	return 1;
//// err:
//// 	printf("%s\n", ws_ctx->tcp_ctx->obuf->next_read);
//// 	ws_ctx->state = WS_CLOSED;
//// 	return -1;
//// }
//
//static h2o_http1client_body_cb on_head(h2o_http1client_t* client,
//  const char* err, int minor_version, int status, h2o_iovec_t msg,
//  h2o_header_t* headers, size_t num_headers)
//{
//	int i;
//	struct sonic_ws_ctx* ctx = (struct sonic_ws_ctx*)client->data;
//	wslay_event_context_ptr wslay_ctx = NULL;
//
//	if (err != NULL && err != h2o_http1client_error_is_eos) {
//		DISPATCH_ERR(ctx, err, "failed to send WebSockets upgrade");
//	}
//
//	if (status != 101) {
//		DISPATCH_ERR(ctx, "unexpected HTTP status",
//		  "should be 101 Switching Protocols for WebSockets upgrade");
//	}
//
//	// TODO verify upgrade
//	SONIC_LOG(
//	  "HTTP/1.%d %d %.*s\n", minor_version, status, (int)msg.len, msg.base);
//	for (i = 0; i != num_headers; ++i)
//		SONIC_LOG("%.*s: %.*s\n", (int)headers[i].name->len,
//		  headers[i].name->base, (int)headers[i].value.len,
//		  headers[i].value.base);
//	SONIC_LOG("\n");
//
//	if (err == h2o_http1client_error_is_eos) {
//		SONIC_LOG("no body\n");
//		// TODO error
//	}
//
//	struct wslay_event_callbacks callbacks = {
//	  &wslay_recv_cb,
//	  &wslay_send_cb,
//	  &wslay_genmask_cb,
//	  NULL,
//	  NULL,
//	  NULL,
//	  &wslay_next_cb,
//	};
//
//	if ((i = wslay_event_context_client_init(&wslay_ctx, &callbacks, ctx)))
//		DISPATCH_ERR(
//		  ctx, get_wslay_err(i), "failed to initialzie wslay client context");
//
//	ctx->wslay_ctx = wslay_ctx;
//
//	return on_body;
//}
//
//static h2o_http1client_head_cb on_connect(h2o_http1client_t* client,
//  const char* err, h2o_iovec_t** reqbufs, size_t* reqbufcnt,
//  int* method_is_head)
//{
//	struct sonic_ws_ctx* ctx = (struct sonic_ws_ctx*)client->data;
//	HANDLE_ERR(ctx, err != NULL, "failed to connect");
//
//	*reqbufs = (h2o_iovec_t*)&ctx->httpreq;
//	*reqbufcnt = 1;
//	*method_is_head = 0;
//
//	return on_head;
//}
//
//INLINE static build_ws_upgrade(h2o_iovec_t* req)
//{
//	// TODO web sockets upgrade
//	// req->base = h2o_mem_alloc_pool(&pool, 1024);
//	// req->len =
//	//   snprintf(req->base, 1024, "GET %.*s HTTP/1.1\r\nhost: %.*s\r\n\r\n",
//	// 	(int)url_parsed.path.len, url_parsed.path.base,
//	// 	(int)url_parsed.authority.len, url_parsed.authority.base);
//	// assert(req->len < 1024);
//}
//
//int sonic_ws_client_send(struct sonic_ws_client* c, struct sonic_message* cmd,
//  struct sonic_stream_ctx* sctx)
//{
//	struct sonic_ws_ctx* ctx = NULL;
//
//	if ((ctx = calloc(1, sizeof(struct sonic_ws_ctx))) == NULL)
//		goto error;
//
//	ctx->sctx = sctx;
//	ctx->cmd = cmd;
//	ctx->client = c;
//
//	h2o_timeout_init(c->loop, &ctx->io_timeout, c->io_timeout);
//	ctx->httpctx.io_timeout = &ctx->io_timeout;
//	ctx->httpctx.ssl_ctx = c->ssl_ctx;
//
//	if (build_ws_upgrade(&ctx->httpreq) != 0) {
//		goto error;
//	}
//
//	h2o_http1client_connect_with_pool(
//	  &ctx->req, ctx, &ctx->httpctx, c->sockpool, on_connect);
//
//	SONIC_LOG("created connect request %p\n", ctx->req);
//
//	ctx->next = c->reqs;
//	ctx->sock = NULL; // TODO necessary?
//	c->reqs = ctx;
//
//	return 0;
//
//error:
//	if (ctx) {
//		if (ctx->httpreq.base) {
//			free(ctx->httpreq.base);
//		}
//		free(ctx);
//	}
//	return 1;
//}
//
//void sonic_ws_client_deinit(struct sonic_ws_client* c)
//{
//	struct sonic_ws_ctx *tmp, *next = c->reqs;
//	while (next != NULL) {
//		tmp = next->next;
//		RELEASE_WS_CTX(next);
//		next = tmp;
//	}
//	c->reqs = NULL;
//}

int sonic_ws_client_init(
  struct sonic_ws_client* c, h2o_url_t url, struct sonic_ws_config* cfg)
{
	abort();
}

int sonic_ws_client_send(struct sonic_ws_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx)
{
	abort();
}

void sonic_ws_client_deinit(struct sonic_ws_client* c)
{
	abort();
}
