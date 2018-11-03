#include <json-c/json.h>
#include <stdio.h>

#include "cli_config.h"

static void config_free_sources(struct config_s* config)
{
	for (struct source_s* next = config->sources; next != NULL;) {
		struct source_s* tmp = next->next;
		free(next);
		next = tmp;
	}
	config->sources = NULL;
}

static const char* config_parse_sources(
  struct config_s* config, json_object* obj)
{
	const char* err = NULL;
	struct json_object_iter iter;

	json_object_object_foreachC(obj, iter)
	{
		if (!json_object_is_type(iter.val, json_type_object)) {
			err = "config_parse_sources: unexpected type for source: should "
				  "be JSON object";
			goto error;
		}
		struct source_s* source = calloc(1, sizeof(struct source_s));
		if (source == NULL) {
			perror("calloc");
			err = "config_parse_sources: failed to allocate storage";
			goto error;
		}
		source->next = config->sources;
		source->val = iter.val;
		source->key = iter.key;
		config->sources = source;
	}

	return NULL;
error:
	config_free_sources(config);
	return err;
}

static const char* config_parse(struct config_s* config, json_object* obj)
{
	json_object* url = NULL;
	json_object* sources = NULL;
	json_object* io_timeout = NULL;
	json_object* websocket_timeout = NULL;

	if (!json_object_object_get_ex(obj, "url", &url)) {
		return "config_parse: missing 'url' key in config file";
	}

	if (!json_object_is_type(url, json_type_string)) {
		return "config_parse: unexpected type for 'url' key in config file";
	}
	config->url = json_object_get_string(url);


	if (json_object_object_get_ex(obj, "io_timeout", &io_timeout)) {
		if (!json_object_is_type(io_timeout, json_type_int)) {
			return "config_parse: unexpected type for 'io_timeout' key in "
				   "config "
				   "file";
		}
		config->io_timeout = json_object_get_int(io_timeout);
	} else {
		config->io_timeout = 0; // will use default
	}

	if (json_object_object_get_ex(
		  obj, "websocket_timeout", &websocket_timeout)) {
		if (!json_object_is_type(websocket_timeout, json_type_int)) {
			return "config_parse: unexpected type for 'websocket_timeout' key "
				   "in config "
				   "file";
		}
		config->websocket_timeout = json_object_get_int(websocket_timeout);
	} else {
		config->websocket_timeout = 0; // will use default
	}

	if (!json_object_object_get_ex(obj, "sources", &sources)) {
		return "config_parse: missing 'sources' key in config file";
	}

	if (!json_object_is_type(sources, json_type_object)) {
		return "config_parse: unexpected type for 'sources' key in config file";
	}

	return config_parse_sources(config, sources);
}

int config_init(struct config_s* config, const char* cfg_file)
{
	const char* config_err = NULL;
	json_object* obj = NULL;

	obj = json_object_from_file(cfg_file);
	if (obj == NULL) {
		config_err = json_util_get_last_err();
		goto error;
	}
	if ((config_err = config_parse(config, obj)) != NULL)
		goto error;

	config->origin = obj;

	return 0;

error:
	printf("config_init: failed to parse JSON config: %s\n", config_err);
	if (obj) {
		json_object_put(obj);
	}
	return 1;
}

struct config_s* config_create(const char* cfg_file)
{
	struct config_s* config = calloc(1, sizeof(struct config_s));
	if (config == NULL) {
		perror("config_create");
		return NULL;
	}

	if (config_init(config, cfg_file) != 0) {
		free(config);
		return NULL;
	}

	return config;
}

void config_free(struct config_s* config)
{
	if (config) {
		config_free_sources(config);
		json_object_put(config->origin);
		free(config);
	}
}
