#include <stdlib.h>

#include <h2o.h>
#include <openssl/err.h>

#include "client.h"
#include "config.h"
#include "util.h"

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

int sonic_client_init(
  struct sonic_client* c, uv_loop_t* loop, struct sonic_config* cfg)
{
	int lerrno;
	h2o_url_t url;

	if (c == NULL || cfg == NULL) {
		errno = EINVAL;
		goto error;
	}

	if (cfg->url == NULL ||
	  (h2o_url_parse(cfg->url, strlen(cfg->url), &url) != 0)) {
		DEBUG_LOG("unrecognized type of URL: %s\n", cfg->url);
		errno = EINVAL;
		goto error;
	}

	int is_tls =
	  strncmp(url.scheme->name.base, "tls", url.scheme->name.len) == 0;
	int is_wss =
	  strncmp(url.scheme->name.base, "wss", url.scheme->name.len) == 0;

	if ((is_wss && cfg->ws.ssl_ctx == NULL) ||
	  (is_tls && cfg->tcp.ssl_ctx == NULL)) {
		if (SSL_load_error_strings() || SSL_library_init() ||
		  OpenSSL_add_all_algorithms() ||
		  ((c->ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL)) {
			char buf[512];
			DEBUG_LOG("SSL init: %s", ERR_error_string(ERR_get_error(), buf));
			errno = EINVAL;
			goto error;
		}
		// SSL_CTX_load_verify_locations(
		//   ssl_ctx, H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
		// SSL_CTX_set_verify(
		//   ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		cfg->tcp.ssl_ctx = c->ssl_ctx;
		cfg->ws.ssl_ctx = c->ssl_ctx;
	}

	if (is_wss ||
	  strncmp(url.scheme->name.base, "ws", url.scheme->name.len) == 0) {
		return sonic_ws_client_init(&c->client.ws, loop, url, &cfg->ws);
	}

	if (is_tls ||
	  strncmp(url.scheme->name.base, "tcp", url.scheme->name.len) == 0) {
		return sonic_tcp_client_init(&c->client.tcp, loop, &cfg->tcp);
	}

	errno = EINVAL;
error:
	lerrno = errno;
	if (c->ssl_ctx) {
		SSL_CTX_free(c->ssl_ctx);
	}
	errno = lerrno;
	return 1;
}

void sonic_client_deinit(struct sonic_client* c)
{
	switch (c->type) {
	case SONIC_TCP_CLIENT:
		sonic_tcp_client_deinit(&c->client.tcp);
		break;
	case SONIC_WS_CLIENT:
		sonic_ws_client_deinit(&c->client.ws);
		break;
	}
}

void sonic_client_free(struct sonic_client* c)
{
	if (c) {
		sonic_client_deinit(c);
		SSL_CTX_free(c->ssl_ctx);
		free(c);
	}
}
