#include <stdlib.h>

#include <h2o.h>
#include <netdb.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "client.h"
#include "config.h"
#include "util.h"

const h2o_url_scheme_t SONIC_URL_SCHEME_TCP = {{H2O_STRLIT("tcp")}, 10000};
const h2o_url_scheme_t SONIC_URL_SCHEME_TLS = {{H2O_STRLIT("tls")}, 10001};
const h2o_url_scheme_t SONIC_URL_SCHEME_WS = {{H2O_STRLIT("ws")}, 9111};
const h2o_url_scheme_t SONIC_URL_SCHEME_WSS = {{H2O_STRLIT("wss")}, 9112};

INLINE static int sonic_parse_url(h2o_url_t* dest, const char* url)
{
	int url_len;
	if ((url_len = strlen(url)) < 6) {
		return -1;
	}
	memset(dest, 0, sizeof(h2o_url_t));

	if (strncmp(url, "tls://", 6) == 0) {
		dest->scheme = &SONIC_URL_SCHEME_TLS;
		url += 4;
		url_len -= 4;
	} else if (strncmp(url, "wss://", 6) == 0) {
		dest->scheme = &SONIC_URL_SCHEME_WSS;
		url += 4;
		url_len -= 4;
	} else if (strncmp(url, "ws://", 5) == 0) {
		dest->scheme = &SONIC_URL_SCHEME_WS;
		url += 3;
		url_len -= 3;
	} else if (strncmp(url, "tcp://", 6) == 0) {
		dest->scheme = &SONIC_URL_SCHEME_TCP;
		url += 4;
		url_len -= 4;
	} else {
		return -1;
	}

	if (h2o_url_parse_relative(url, url_len, dest) != 0) {
		return -1;
	}

	return 0;
}

INLINE static int client_get_addr(
  struct sonic_client* c, h2o_url_t* url, struct sockaddr_in* res)
{
	struct addrinfo hints, *addr = NULL;
	char* host = NULL;
	int err, lerrno, ret = -1;

	if ((host = malloc(url->host.len + 1)) == NULL)
		goto exit;

	memcpy(host, url->host.base, url->host.len);
	host[url->host.len] = '\x00';

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;
	if ((err = getaddrinfo(host, NULL, &hints, &addr)) != 0) {
		SONIC_LOG("failed to resolve %s: %s\n", host, gai_strerror(err));
		goto exit;
	}

	memset(res, 0, sizeof(struct sockaddr_in));
	res->sin_family = AF_INET;
	res->sin_port = htons(h2o_url_get_port(url));
	res->sin_addr = ((struct sockaddr_in*)addr->ai_addr)->sin_addr;

	ret = 0;

exit:
	lerrno = errno;
	if (host)
		free(host);
	if (addr)
		freeaddrinfo(addr);
	errno = lerrno;

	return ret;
}

INLINE static int client_sockpool_init(struct sonic_client* c, uv_loop_t* loop,
  int is_tls, h2o_url_t* url, struct sonic_config* cfg)
{
	struct sockaddr_in addr;

	if (client_get_addr(c, url, &addr) != 0) {
		return -1;
	}

	SONIC_LOG("resolved url '%s' into ip: %s and port: %d\n", cfg->url,
	  inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	h2o_socketpool_init_by_address(&c->sockpool, (struct sockaddr*)&addr,
	  sizeof(struct sockaddr), is_tls, cfg->pool_capacity);
	h2o_socketpool_set_timeout(&c->sockpool, c->loop, cfg->pool_timeout);

	return 0;
}

INLINE static int sonic_client_sanitize_cfg(struct sonic_config* cfg)
{
	if (cfg->url == NULL) {
		errno = EINVAL;
		return -1;
	}
	GET_CFG_INT(io_timeout, SONIC_IO_TIMEOUT, "I/O timeout");
	GET_CFG_INT(pool_capacity, SONIC_POOL_CAPACITY, "pool capacity");
	GET_CFG_INT(pool_timeout, SONIC_POOL_TIMEOUT, "pool timeout");

	if (cfg->io_timeout < 0 || cfg->pool_timeout < 0 ||
	  cfg->pool_capacity <= 0) {
		errno = EINVAL;
		return -1;
	}

	SONIC_LOG("cfg after sanitization, url: '%s', io_timeout: %d, "
			  "pool_capacity: %d, pool_timeout: %d\n",
	  cfg->url, cfg->io_timeout, cfg->pool_capacity, cfg->pool_timeout);

	return 0;
}

int sonic_client_init(
  struct sonic_client* c, uv_loop_t* loop, struct sonic_config* cfg)
{
	int lerrno;
	h2o_url_t url;

	if (c == NULL || cfg == NULL) {
		errno = EINVAL;
		goto error;
	}

	if (sonic_client_sanitize_cfg(cfg) != 0)
		goto error;

	memset(c, 0, sizeof(struct sonic_client));
	c->loop = loop;

	if (sonic_parse_url(&url, cfg->url) != 0) {
		SONIC_LOG("unrecognized type of URL: %s\n", cfg->url);
		errno = EINVAL;
		goto error;
	}

	int is_tls = url.scheme == &SONIC_URL_SCHEME_WSS ||
	  url.scheme == &SONIC_URL_SCHEME_TLS;
	int is_ws =
	  url.scheme == &SONIC_URL_SCHEME_WSS || url.scheme == &SONIC_URL_SCHEME_WS;

	if (is_tls && cfg->ssl_ctx == NULL) {
		if (SSL_load_error_strings() || SSL_library_init() ||
		  OpenSSL_add_all_algorithms() ||
		  // TODO tls version should be in config ?
		  ((c->ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL)) {
			char buf[512];
			SONIC_LOG("SSL init: %s", ERR_error_string(ERR_get_error(), buf));
			errno = EINVAL;
			goto error;
		}
		// FIXME
		// SSL_CTX_load_verify_locations(
		//   ssl_ctx, H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
		// SSL_CTX_set_verify(
		//   ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		c->tcp_cfg.ssl_ctx = c->ssl_ctx;
		c->ws_cfg.ssl_ctx = c->ssl_ctx;
	} else if (is_tls) {
		/* managed externally */
		c->tcp_cfg.ssl_ctx = cfg->ssl_ctx;
		c->ws_cfg.ssl_ctx = cfg->ssl_ctx;
	}

	if (client_sockpool_init(c, loop, is_tls, &url, cfg) != 0)
		goto error;

	if (is_ws) {
		c->type = SONIC_WS_CLIENT;
		c->ws_cfg.sockpool = &c->sockpool;
		c->ws_cfg.loop = c->loop;
		c->ws_cfg.io_timeout = cfg->io_timeout;
		return sonic_ws_client_init(&c->client.ws, url, &c->ws_cfg);
	}

	c->type = SONIC_TCP_CLIENT;
	c->tcp_cfg.sockpool = &c->sockpool;
	c->tcp_cfg.loop = c->loop;
	return sonic_tcp_client_init(&c->client.tcp, &c->tcp_cfg);

error:
	lerrno = errno;
	if (c->ssl_ctx)
		SSL_CTX_free(c->ssl_ctx);
	if (c->sockpool.capacity != 0) {
		h2o_socketpool_dispose(&c->sockpool);
	}
	errno = lerrno;
	return 1;
}

int sonic_client_send(struct sonic_client* c, struct sonic_message* cmd,
  struct sonic_stream_ctx* ctx)
{
	switch (c->type) {
	case SONIC_TCP_CLIENT:
		return sonic_tcp_client_send(&c->client.tcp, cmd, ctx);
	case SONIC_WS_CLIENT:
		return sonic_ws_client_send(&c->client.ws, cmd, ctx);
	default:
		abort();
	}
}

INLINE static void sonic_client_deinit(struct sonic_client* c)
{
	switch (c->type) {
	case SONIC_TCP_CLIENT:
		sonic_tcp_client_deinit(&c->client.tcp);
		break;
	case SONIC_WS_CLIENT:
		sonic_ws_client_deinit(&c->client.ws);
		break;
	default:
		abort();
	}

	if (c->ssl_ctx) {
		SSL_CTX_free(c->ssl_ctx);
	}

	h2o_socketpool_dispose(&c->sockpool);
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

static void deferred_client_free(uv_timer_t* timer)
{
	struct sonic_client* c = (struct sonic_client*)timer->data;

	sonic_client_deinit(c);
	free(c);

	uv_timer_stop(timer);
	free(timer);
}

void sonic_client_free(struct sonic_client* c)
{
	if (c) {
		// for performance reasons, message handlers are dispatched
		// synchronously so in order to prevent lifecycle corruption we dispatch
		// deinitialization asynchronously
		if (c->close_dispatcher != NULL)
			return;

		if ((c->close_dispatcher = calloc(1, sizeof(uv_timer_t))) == NULL)
			h2o_fatal("failed to allocate storage for close dispatcher");
		uv_timer_init(c->loop, c->close_dispatcher);

		c->close_dispatcher->data = c;
		uv_timer_start(c->close_dispatcher, deferred_client_free, 0, 0);
	}
}
