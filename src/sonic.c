#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <h2o.h>
#include <pcre2.h>
#include <slab/buf.h>
#include <uv.h>

#include "cli_config.h"
#include "client.h"
#include "config.h"
#include "util.h"

#define BUF_INIT_CAP 1024 * 64

#define do_exit(status)                                                        \
	all_free();                                                                \
	exit(status);

struct definevar_s {
	struct definevar_s* next;
	char* key;
	char* val;
};

struct args_s {
	const char* literal;
	const char* file;
	const char* source;
	const char* config;
	struct definevar_s* define;
	bool rows_only;
	bool silent;
};

int pret;
char* default_cfg_path;
struct args_s args;
struct config_s* config;
char* query_str;
struct sonic_message* query;
struct sonic_stream_ctx* ctx;
uv_signal_t sigint;
buf_t* query_buf;
uv_loop_t* loop;
struct sonic_client* client;

void print_version() { printf("sonic %s\n", SONIC_VERSION); }

void print_header()
{
	printf("\n"
		   "\n"
		   "                           d8b\n"
		   "                           Y8P\n"
		   "\n"
		   ".d8888b   .d88b.  88888b.  888  .d8888b\n"
		   "88K      d88\"\"88b 888 \"88b 888 d88P\"\n"
		   "\"Y8888b. 888  888 888  888 888 888\n"
		   "     X88 Y88..88P 888  888 888 Y88b.\n"
		   " 88888P'  \"Y88P\"  888  888 888  \"Y8888P\n");
}

void print_usage(const char* argv0)
{
	printf(
	  "\n"
	  "Usage:\n"
	  "  %1$s <source> [options] -e <literal>\n"
	  "  %1$s <source> [options] -f <file>\n"
	  "  %1$s -h | --help\n"
	  "  %1$s --version\n"
	  "\n"
	  "Options:\n"
	  "  -e, --execute=<query>		Run query literal\n"
	  "  -f, --file=<query>		Run query in file\n"
	  "  -c, --config=<config> 	Use configuration file [default: %2$s]\n"
	  "  -d, --define=<foo=var>	Replace variable `${foo}` with value `var`\n"
	  "  -r, --rows-only		Skip printing column names\n"
	  "  -S, --silent			Disable printing query progress\n"
	  "  -h, --help			Print this message\n"
	  "  -v, --version			Print version\n"
	  "\n",
	  argv0, args.config);
}

void args_define_free(struct definevar_s* define)
{
	for (struct definevar_s* next = define; next != NULL;) {
		struct definevar_s* tmp = next->next;
		free(next->key);
		free(next);
		next = tmp;
	}
}

void args_free()
{
	args_define_free(args.define);
	free(default_cfg_path);
}

void client_free()
{
	sonic_client_free(client);
	client = NULL;
}

void all_free()
{
	if (loop) {
		uv_loop_close(loop);
		free(loop);
	}
	if (query) {
		sonic_message_deinit(query);
		free(query);
	}
	if (query_str)
		free(query_str);
	if (ctx)
		free(ctx);
	client_free();
	buf_free(query_buf);
	config_free(config);
	args_free();
}

const char* sonic_message_status_string(enum sonic_status status)
{
	switch (status) {
	case SONIC_STATUS_QUEUED:
		return "queued";
	case SONIC_STATUS_STARTED:
		return "started";
	case SONIC_STATUS_RUNNING:
		return "running";
	case SONIC_STATUS_WAITING:
		return "waiting";
	case SONIC_STATUS_FINISHED:
		return "finished";
	}
	abort();
}

char* query_literal_replace_substitute(
  pcre2_code* code, char* query, buf_t* buf, char* value)
{
	PCRE2_SIZE outlengthptr = buf_writable(buf);
	PCRE2_UCHAR errorbuf[512];

	int n = pcre2_substitute(code, (PCRE2_SPTR8)query, PCRE2_ZERO_TERMINATED, 0,
	  PCRE2_SUBSTITUTE_GLOBAL, NULL, NULL, (PCRE2_SPTR8)value,
	  PCRE2_ZERO_TERMINATED, (PCRE2_UCHAR8*)buf->next_write, &outlengthptr);
	if (n < 0) {
		pcre2_get_error_message(n, errorbuf, sizeof(errorbuf));
		printf(
		  "query_literal_replace_substitute: PCRE2 failed: %s\n", errorbuf);
		errno = EINVAL;
		return NULL;
	}

	// redundant but good to decouple from caller
	buf_extend(buf, outlengthptr);

	return strdup(buf->next_read);
}

pcre2_code* query_literal_replace_compile(char* pattern)
{
	uint32_t options = PCRE2_MULTILINE | PCRE2_CASELESS;
	pcre2_code* code = NULL;
	PCRE2_SIZE erroroffset;
	PCRE2_UCHAR errorbuf[512];
	int errorcode;

	if ((code = pcre2_compile((PCRE2_SPTR8)pattern, PCRE2_ZERO_TERMINATED,
		   options, &errorcode, &erroroffset, NULL)) == NULL) {
		pcre2_get_error_message(errorcode, errorbuf, sizeof(errorbuf));
		printf("query_literal_replace_compile: PCRE2 failed at "
			   "offset %d: %s\n",
		  (int)erroroffset, errorbuf);
		errno = EINVAL;
		return NULL;
	}

	SONIC_LOG("compiled pattern '%s' into pcre2 code", pattern);

	return code;
}

// responsible of freeing query and return a replaced new string if success
// responsible of freeing query and any other storage allocated if error
// buffer is just a working buffer, returned query should be a strdup of the
char* query_literal_replace_define(
  char* query, buf_t* buf, struct definevar_s* define)
{
#define DEFINE_TEMPLATE "\\$\\{%s\\}"
#define DEFINE_TEMPLATE_LEN (strlen(pattern))
	char* pattern = NULL;
	char* result = NULL;
	pcre2_code* code = NULL;
	int lerrno = 0;
	int need;

	need = snprintf(NULL, 0, DEFINE_TEMPLATE, define->key);
	if ((pattern = malloc(need + 1)) == NULL) {
		perror("malloc");
		errno = ENOMEM;
		goto exit;
	}
	sprintf(pattern, DEFINE_TEMPLATE, define->key);

	// reset buffer offsets so it can be used by substitution routine
	buf_reset_offsets(buf);

	// make sure that buffer has enough space for the substitution
	if (buf_reserve(
		  buf, strlen(query) - DEFINE_TEMPLATE_LEN + strlen(define->val)) != 0)
		goto exit;

	if ((code = query_literal_replace_compile(pattern)) == NULL)
		goto exit;

	result = query_literal_replace_substitute(code, query, buf, define->val);

exit:
	lerrno = errno;
	free(query);
	if (pattern)
		free(pattern);
	if (code)
		pcre2_code_free(code);
	errno = lerrno;
	return result;
}

char* query_literal_init(
  const char* literal, struct definevar_s* define, buf_t* buf)
{
	char* query;
	int lerrno;

	if ((query = strdup(literal)) == NULL) {
		perror("malloc");
		errno = ENOMEM;
		goto error;
	}

	for (struct definevar_s* next = define; next != NULL; next = next->next)
		if ((query = query_literal_replace_define(query, buf, next)) == NULL)
			goto error;

	return query;

error:
	lerrno = errno;
	if (query)
		free(query);
	errno = lerrno;
	return NULL;
}

int query_file_read(buf_t* buf, int fd)
{
	int n;
	while (1) {
		errno = 0;
		n = read(fd, buf->buf, buf_writable(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return n;
		}
		if (n == 0) {
			if (buf_writable(buf) == 0) {
				buf_reserve(buf, BUF_INIT_CAP);
				continue;
			}
			break;
		}
		buf_extend(buf, n);
	}

	if (buf_writable(buf) == 0) {
		buf_reserve(buf, 1);
	}
	*buf->next_write = '\x00';

	SONIC_LOG("read query from file: %s", buf->buf);

	return 0;
}

char* query_file_init(
  const char* filename, struct definevar_s* define, buf_t* buf)
{
	char* query = NULL;
	int lerrno = 0;
	int fd = 0;

	if ((fd = open(filename, O_RDONLY)) < 0)
		goto exit;

	if (query_file_read(buf, fd) != 0)
		goto exit;

	query = query_literal_init(buf->buf, define, buf);

exit:
	lerrno = errno;
	if (fd)
		close(fd);
	errno = lerrno;
	return query;
}

void assert_args_coherent(const char* argv0)
{
	char* err;
	if (!args.literal && !args.file) {
		err = "either --execute, -e or --file, -f must be defined";
		goto error;
	}

	if (!args.source) {
		err = "<source> is missing";
		goto error;
	}

	return;

error:
	printf("Error: %s\n", err);
	print_usage(argv0);
	do_exit(1);
}

struct definevar_s* parse_define(struct definevar_s* head, char* arg)
{
	if (arg == NULL)
		return NULL;

	char c;
	int i;

	char* buf = strdup(arg);
	if (buf == NULL) {
		perror("strdup");
		return NULL;
	}
	struct definevar_s* var = calloc(1, sizeof(struct definevar_s));
	if (var == NULL) {
		free(buf);
		perror("calloc");
		return NULL;
	}

	for (c = buf[0], i = 0; c != 0; c = buf[++i]) {
		if (c == '=') {
			var->val = buf + i + 1;
			var->key = buf;
			buf[i] = 0;
			break;
		}
	}

	if (var->key == NULL || var->val == NULL || *var->key == 0 ||
	  *var->val == 0) {
		errno = EINVAL;
		free(var);
		free(buf);
		args_define_free(head);
		return NULL;
	}

	var->next = head;
	return var;
}

const char* get_default_config()
{
#define CFG_TMPL "%s/.sonicrc"
	struct passwd* pw = getpwuid(getuid());
	const char* homedir = pw->pw_dir;
	int need = snprintf(NULL, 0, CFG_TMPL, homedir);
	default_cfg_path = malloc(need + 1);
	sprintf(default_cfg_path, CFG_TMPL, homedir);
	return default_cfg_path;
}

void args_init(int argc, char* argv[])
{
	/* set defaults for arguments */
	args.literal = NULL;
	args.file = NULL;
	args.source = NULL;
	args.config = get_default_config();
	args.define = NULL; // head of linked list
	args.rows_only = false;
	args.silent = false;

	static struct option long_options[] = {
	  {"execute", required_argument, 0, 'e'},
	  {"file", required_argument, 0, 'f'},
	  {"config", required_argument, 0, 'c'},
	  {"define", required_argument, 0, 'd'}, {"rows-only", no_argument, 0, 'r'},
	  {"silent", no_argument, 0, 'S'}, {"help", no_argument, 0, 'h'},
	  {"version", no_argument, 0, 'v'}, {0, 0, 0, 0}};

	int option_index = 0;
	int c = 0;
	while ((c = getopt_long(
			  argc, argv, "e:f:c:d:rShv", long_options, &option_index)) != -1) {
		switch (c) {
		case 'v':
			print_version();
			do_exit(0);
			break;
		case 'h':
			print_header();
			print_usage(argv[0]);
			do_exit(0);
			break;
		case 'S':
			args.silent = true;
			break;
		case 'r':
			args.rows_only = true;
			break;
		case 'd':
			args.define = parse_define(args.define, optarg);
			if (args.define == NULL) {
				perror("parse_define");
				print_usage(argv[0]);
				do_exit(1);
			}
			break;
		case 'c':
			args.config = optarg;
			break;
		case 'f':
			args.file = optarg;
			break;
		case 'e':
			args.literal = optarg;
			break;
		default:
			abort();
		}
	}

	args.source = argv[optind];

	assert_args_coherent(argv[0]);

	SONIC_LOG(
	  "parsed_args: literal: %s, file: %s, source: %s, config: %s, define:",
	  args.literal, args.file, args.source, args.config);
	for (struct definevar_s* next = args.define; next != NULL;
		 next = next->next) {
		SONIC_LOG(" '%s'->'%s'", next->key, next->val);
	}
	SONIC_LOG(", rows_only: %d, silent: %d\n", args.rows_only, args.silent);
}

void close_all(int status_code)
{
	uv_signal_stop(&sigint);
	client_free();
	pret = status_code;
}

void shutdown_sig_h(uv_signal_t* handle, int signum)
{
	char* strsig = strsignal(signum);
	int exit_code = signum + 128;
	fprintf(stderr, "received signal %s\n", strsig);
	close_all(exit_code);
}

void on_started(void* userdata) { SONIC_LOG("stream starting"); }

void on_progress(const struct sonic_message_progress* msg, void* userdata)
{
	static double sofar;

	sofar += msg->progress;

	if (!args.silent) {
		fprintf(stderr, "\r%s: %g/%g %s",
		  sonic_message_status_string(msg->status), sofar, msg->total,
		  msg->units);

		if (msg->status == SONIC_STATUS_FINISHED)
			fprintf(stderr, "\n");
	}
}

void on_metadata(const struct sonic_message_metadata* msg, void* userdata)
{
	do {
		fprintf(stdout, "%s", msg->name);
	} while ((msg = msg->next) != NULL && fprintf(stderr, ","));

	fprintf(stdout, "\n");
}

void on_data(const struct sonic_message_output* msg, void* userdata)
{
	do {
		fprintf(
		  stdout, "%s", json_object_to_json_string((json_object*)msg->value));
	} while ((msg = msg->next) != NULL && fprintf(stderr, ","));

	fprintf(stdout, "\n");
}

void on_error(const char* err, void* userdata)
{
	fprintf(stderr, "ERROR: %s\n", err);
	close_all(1);
}

void on_complete(void* userdata)
{
	SONIC_LOG("stream completed successfully");

	close_all(0);

	fflush(stdout);
	fflush(stderr);
}

int loop_create()
{
	int ret;

	if ((loop = calloc(1, sizeof(uv_loop_t))) == NULL) {
		errno = ENOMEM;
		goto error;
	}

	if ((ret = uv_loop_init(loop)) < 0) {
		fprintf(stderr, "%s: %s\n", uv_err_name(ret), uv_strerror(ret));
		goto error;
	}

	SONIC_LOG("initialized event loop %p", loop);
	return 0;

error:
	if (loop) {
		free(loop);
		loop = NULL;
	}
	return 1;
}

struct sonic_stream_ctx* ctx_create()
{
	struct sonic_stream_ctx* res;

	if ((res = calloc(1, sizeof(struct sonic_stream_ctx))) == NULL)
		return NULL;

	res->on_started = on_started;
	res->on_progress = on_progress;
	res->on_metadata = on_metadata;
	res->on_data = on_data;
	res->on_error = on_error;
	res->on_complete = on_complete;
	// TODO
	res->userdata = NULL;

	return res;
}

struct sonic_message* query_create(
  char* query_str, const char* source, struct config_s* cli_config)
{
	struct sonic_message* query = NULL;
	int lerrno;

	if ((query = calloc(1, sizeof(struct sonic_message))) == NULL)
		goto error;

	struct source_s* source_config;
	for (source_config = cli_config->sources; source_config != NULL;
		 source_config = source_config->next) {
		if (strcmp(source_config->key, source) == 0)
			break;
	}

	/* no local config; pass source for backend to resolve */
	if (source_config == NULL) {
		json_object* val = json_object_new_string(source);
		sonic_message_init_query(query, query_str, cli_config->auth, val);
		query->backing = val;
	} else {
		sonic_message_init_query(
		  query, query_str, cli_config->auth, source_config->val);
	}

	return query;

error:
	lerrno = errno;
	if (query)
		free(query);
	errno = lerrno;
	return NULL;
}

struct sonic_client* client_create(uv_loop_t* loop, struct config_s* cli_config)
{
	struct sonic_config client_config = {0};
	struct sonic_client* c;

	client_config.url = cli_config->url;
	client_config.io_timeout = cli_config->io_timeout;
	client_config.pool_timeout = client_config.io_timeout * 2;
	client_config.pool_capacity = 1;

	if ((c = sonic_client_create(loop, &client_config)) == NULL) {
		perror("sonic_client_create");
		return NULL;
	}

	return c;
}

int signals_init(uv_loop_t* loop)
{
	int ret;

	if ((ret = uv_signal_init(loop, &sigint)) < 0)
		goto error;

	if ((ret = uv_signal_start(&sigint, shutdown_sig_h, SIGINT)) < 0)
		goto error;

	return 0;
error:
	fprintf(
	  stderr, "uv_signal_init: %s: %s\n", uv_err_name(ret), uv_strerror(ret));
	return ret;
}

int main(int argc, char* argv[])
{
	args_init(argc, argv);
	if ((config = config_create(args.config)) == NULL) {
		pret = 1;
		goto exit;
	}

	if ((query_buf = buf_create(BUF_INIT_CAP)) == NULL) {
		pret = 1;
		goto exit;
	}

	if (args.file &&
	  (query_str = query_file_init(args.file, args.define, query_buf)) ==
		NULL) {
		perror("query_file_init");
		pret = 1;
		goto exit;
	} else if (args.literal &&
	  (query_str = query_literal_init(args.literal, args.define, query_buf)) ==
		NULL) {
		perror("query_literal_init");
		pret = 1;
		goto exit;
	}

	if ((pret = loop_create()) != 0) {
		perror("loop_create");
		goto exit;
	}

	if ((pret = signals_init(loop)) != 0)
		goto exit;

	if ((client = client_create(loop, config)) == NULL) {
		pret = 1;
		goto exit;
	}

	if ((query = query_create(query_str, args.source, config)) == NULL) {
		pret = 1;
		goto exit;
	}

	if ((ctx = ctx_create()) == NULL) {
		pret = 1;
		goto exit;
	}

	if ((pret = sonic_client_send(client, query, ctx)) != 0)
		goto exit;

	SONIC_LOG("running query '%s'\n", query_str);

	while (uv_run(loop, UV_RUN_DEFAULT))
		;

	SONIC_LOG("uv loop exit; uv_loop_alive: %d\n", uv_loop_alive(loop));

exit:
	all_free();
	SONIC_LOG("exiting with status: %d\n", pret);
	return pret;
}
