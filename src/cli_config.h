#ifndef SONIC_CLI_CONFIG_H
#define SONIC_CLI_CONFIG_H

#include <json-c/json.h>

struct source_s {
	struct source_s* next;
	const char* key;
	json_object* val;
};

struct config_s {
	json_object* origin;
	const char* host;
	int port;
	struct source_s* sources;
};

int config_init(struct config_s* config, const char* cfg_file);
struct config_s* config_create(const char* cfg_file);
void config_free(struct config_s* config);

#endif