#include <stdlib.h>

#include <h2o.h>
#include <stdbool.h>
#include <sys/random.h>

#include "client.h"
#include "message.h"
#include "config.h"

#define GET_CFG_INT(field, def, name)                                          \
	if (cfg->field == 0) {                                                     \
		cfg->field = def;                                                      \
	} else if (cfg->field < 0) {                                               \
		fprintf(stderr, "invalid " name ": %d\n", cfg->field);                 \
		errno = EINVAL;                                                        \
		return 1;                                                              \
	}

static int on_body(h2o_http1client_t* client, const char* errstr)
{
	if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
		fprintf(stderr, "%s\n", errstr);
		exit(1);
		return -1;
	}

	fwrite(client->sock->input->bytes, 1, client->sock->input->size, stdout);
	h2o_buffer_consume(&client->sock->input, client->sock->input->size);

	if (errstr == h2o_http1client_error_is_eos) {
		// TODO if (--cnt_left != 0) {
		// TODO    /* next attempt */
		// TODO    h2o_mem_clear_pool(&pool);
		// TODO    start_request(client->ctx);
		// TODO}
	}

	return 0;
}

h2o_http1client_body_cb on_head(h2o_http1client_t* client, const char* errstr,
  int minor_version, int status, h2o_iovec_t msg, h2o_header_t* headers,
  size_t num_headers)
{
	size_t i;

	if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
		fprintf(stderr, "%s\n", errstr);
		exit(1);
		return NULL;
	}

	printf(
	  "HTTP/1.%d %d %.*s\n", minor_version, status, (int)msg.len, msg.base);
	for (i = 0; i != num_headers; ++i)
		printf("%.*s: %.*s\n", (int)headers[i].name->len, headers[i].name->base,
		  (int)headers[i].value.len, headers[i].value.base);
	printf("\n");

	if (errstr == h2o_http1client_error_is_eos) {
		fprintf(stderr, "no body\n");
		exit(1);
		return NULL;
	}

	return on_body;
}

static h2o_http1client_head_cb sonic_on_connect(h2o_http1client_t* client,
  const char* errstr, h2o_iovec_t** reqbufs, size_t* reqbufcnt,
  int* method_is_head)
{
	if (errstr != NULL) {
		fprintf(stderr, "%s\n", errstr);
		exit(1);
		return NULL;
	}

	*reqbufs = (h2o_iovec_t*)client->data;
	*reqbufcnt = 1;
	*method_is_head = 0;

	return on_head;
}

// int copy_client_handshake(ws_ctx_t* ws_ctx, char* path, char* host, int port)
// {
// 	int ret;
// 	size_t size;
// 	char random_buf[16];
//
// 	while (
// 	  (ret = getrandom(&random_buf, sizeof(random_buf), GRND_NONBLOCK)) == -1 &&
// 	  errno == EINTR)
// 		;
//
// 	if (ret == -1) {
// 		perror("getrandom");
// 		return -1;
// 	}
//
// 	base64((uint8_t*)ws_ctx->client_key, (uint8_t*)random_buf, 16);
//
// 	ws_ctx->client_key[SEC_WEBSOCKET_KEY_LEN] = '\0';
//
// 	size = snprintf(ws_ctx->tcp_ctx->obuf->next_write,
// 	  buf_writable(ws_ctx->tcp_ctx->obuf), "GET %s HTTP/1.1\r\n"
// 										   "Host: %s:%d\r\n"
// 										   "Upgrade: websocket\r\n"
// 										   "Connection: Upgrade\r\n"
// 										   "Sec-WebSocket-Key: %s\r\n"
// 										   "Sec-WebSocket-Version: 13\r\n"
// 										   "\r\n",
// 	  path, host, port, ws_ctx->client_key);
//
// 	buf_extend(ws_ctx->tcp_ctx->obuf, size);
//
// 	return 0;
// }

static char* make_client_key(h2o_mem_pool_t* pool)
{
#define SEC_WEBSOCKET_KEY_LEN 24
#define RANDOM_BUF_LEN 16
	int ret;
	char random_buf[RANDOM_BUF_LEN];
	char* key;

	if ((key = h2o_mem_alloc_pool(pool, RANDOM_BUF_LEN)) == NULL) {
		perror("calloc");
		return NULL;
	}

	while (
	  (ret = getrandom(&random_buf, sizeof(random_buf), GRND_NONBLOCK)) == -1 &&
	  errno == EINTR)
		;
	if (ret == -1) {
		perror("getrandom");
		return NULL;
	}

	EVP_EncodeBlock((unsigned char*)key, random_buf, RANDOM_BUF_LEN);
	key[SEC_WEBSOCKET_KEY_LEN] = '\0';

	return key;
}

static h2o_iovec_t* make_websocket_upgrade(
  h2o_mem_pool_t* pool, h2o_url_t* url_parsed)
{
	h2o_iovec_t* req;
	char* client_key;

	if ((client_key = make_client_key(pool)) == NULL) {
		perror("make_client_key");
		return NULL;
	}

	if ((req = h2o_mem_alloc_pool(pool, sizeof(h2o_iovec_t))) == NULL) {
		perror("h2o_mem_alloc_pool");
		return NULL;
	}

#define UPGRADE_TMPL                                                           \
	"GET %.*s HTTP/1.1\r\n"                                                    \
	"Host: %.*s\r\n"                                                           \
	"Upgrade: websocket\r\n"                                                   \
	"Connection: Upgrade\r\n"                                                  \
	"Sec-WebSocket-Key: %s\r\n"                                                \
	"Sec-WebSocket-Version: 13\r\n"                                            \
	"\r\n"

	int need = snprintf(NULL, 0, UPGRADE_TMPL, url_parsed->path.len,
	  url_parsed->path.base, url_parsed->authority.len,
	  url_parsed->authority.base, client_key);

	if ((req->base = h2o_mem_alloc_pool(pool, need + 1)) == NULL) {
		perror("h2o_mem_alloc_pool");
		return NULL;
	}

	req->len = sprintf(req->base, UPGRADE_TMPL, url_parsed->path.len,
	  url_parsed->path.base, url_parsed->authority.len,
	  url_parsed->authority.base, client_key);

	return req;
}

int sonic_client_init_ws(struct sonic_client* c, bool is_tls)
{
	h2o_iovec_t* req;

	if ((req = make_websocket_upgrade(&c->mempool, &c->url)) == NULL) {
		perror("make_websocket_upgrade");
		goto error;
	}

	h2o_http1client_connect_with_pool(
	  &c->http_client, req, &c->ctx, &c->sockpool, sonic_on_connect);

	return 0;
error:
	return 1;
}

int sonic_client_init_tcp(struct sonic_client* c, bool is_tls)
{
	// TODO with pool
	// int ret, err;
	// struct addrinfo hints, *res = NULL;
	// memset(&hints, 0, sizeof(hints));
	// hints.ai_socktype = SOCK_STREAM;
	// hints.ai_protocol = IPPROTO_TCP;
	// hints.ai_flags = AI_ADDRCONFIG;

	// if ((err = getaddrinfo(host, port, &hints, &res)) != 0) {
	// 	fprintf(stderr, "failed to resolve %s:%s:%s\n", host, port,
	// 	  gai_strerror(err));
	// 	goto error;
	// }

	// void h2o_socketpool_connect(h2o_socketpool_connect_request_t **_req,
	// h2o_socketpool_t *pool, h2o_loop_t *loop, h2o_multithread_receiver_t
	// *getaddr_receiver, h2o_socketpool_connect_cb cb, void *data) if ((sock =
	// h2o_socket_connect( 	   loop, res->ai_addr, res->ai_addrlen, on_connect)) ==
	// NULL) { 	fprintf(stderr, "failed to create socket:%s\n", strerror(errno));
	// 	goto error;
	// }

	// sock->data = &send_data;
	abort();

	return 0;

error:
	return 1;
}

// TODO error handling of all functions
// TODO handle intermediate memory allocations in the case of error
int sonic_client_init(
  struct sonic_client* c, uv_loop_t* loop, struct sonic_config* cfg)
{
	int ret;
	bool is_tls = false;
	bool is_ws = false;

	if (c == NULL || cfg == NULL) {
		errno = EINVAL;
		return 1;
	}

	if (cfg->url == NULL ||
	  (h2o_url_parse(cfg->url, strlen(cfg->url), &c->url) != 0)) {
		fprintf(stderr, "unrecognized type of URL: %s\n", cfg->url);
		errno = EINVAL;
		return 1;
	}

	is_tls =
	  strncmp(c->url.scheme->name.base, "wss", c->url.scheme->name.len) == 0 ||
	  strncmp(c->url.scheme->name.base, "tls", c->url.scheme->name.len) == 0;

	is_ws =
	  strncmp(c->url.scheme->name.base, "wss", c->url.scheme->name.len) == 0 ||
	  strncmp(c->url.scheme->name.base, "ws", c->url.scheme->name.len) == 0;

	h2o_mem_init_pool(&c->mempool);

	GET_CFG_INT(io_timeout, SONIC_IO_TIMEOUT, "I/O timeout");
	GET_CFG_INT(pool_capacity, SONIC_POOL_CAPACITY, "pool capacity");
	GET_CFG_INT(pool_timeout, SONIC_POOL_TIMEOUT, "pool timeout");
	GET_CFG_INT(
	  websocket_timeout, SONIC_WEBSOCKET_TIMEOUT, "WebSocket timeout");

	h2o_timeout_init(loop, &c->io_timeout, cfg->io_timeout);

	h2o_socketpool_init_by_hostport(&c->sockpool, c->url.host,
	  h2o_url_get_port(&c->url), is_tls, cfg->pool_capacity);
	h2o_socketpool_set_timeout(&c->sockpool, loop, cfg->pool_timeout);

	c->ctx.loop = loop;
	c->ctx.io_timeout = &c->io_timeout;

	h2o_timeout_init(loop, c->ctx.websocket_timeout, cfg->websocket_timeout);

	c->queue = h2o_multithread_create_queue(c->ctx.loop);
	h2o_multithread_register_receiver(
	  c->queue, c->ctx.getaddr_receiver, h2o_hostinfo_getaddr_receiver);

	if (is_tls) {
		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		c->ctx.ssl_ctx = SSL_CTX_new(TLSv1_client_method());
		SSL_CTX_load_verify_locations(c->ctx.ssl_ctx,
		  H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
		SSL_CTX_set_verify(c->ctx.ssl_ctx,
		  SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	if (is_ws) {
		ret = sonic_client_init_ws(c, is_tls);
	} else {
		ret = sonic_client_init_tcp(c, is_tls);
	}

	return ret;
}

int sonic_client_send(struct sonic_client* c, struct sonic_cmd* cmd)
{
	// TODO
	// if (is_ws) {
	// 	ret = sonic_client_init_ws(c, is_tls);
	// } else {
	// 	ret = sonic_client_init_tcp(c, is_tls);
	// }
}

struct sonic_client* sonic_client_create(
  uv_loop_t* loop, struct sonic_config* cfg)
{
	struct sonic_client* client = calloc(1, sizeof(struct sonic_client));
	if (client == NULL) {
		perror("calloc");
		errno = ENOMEM;
		return NULL;
	}

	if (sonic_client_init(client, loop, cfg) != 0) {
		free(client);
		return NULL;
	}

	return client;
}

void sonic_client_free(struct sonic_client* c)
{
	if (c) {
		h2o_mem_clear_pool(&c->mempool);
	}
}
