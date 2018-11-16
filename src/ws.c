#include <stdbool.h>
#include <sys/random.h>

#include "ws.h"

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
