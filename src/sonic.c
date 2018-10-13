#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <slab/buf.h>

#include "cli_config.h"
#include "config.h"

#define BUF_INIT_CAP 1024 * 64

#define debug_printf_chunk(tmpl, ...)                                          \
	if (args.verbose) {                                                        \
		printf((tmpl), __VA_ARGS__);                                           \
	}

#define debug_printf(tmpl, ...)                                                \
	if (args.verbose) {                                                        \
		printf("%lld: ", current_timestamp());                                 \
		printf((tmpl), __VA_ARGS__);                                           \
	}

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
	bool verbose;
	bool silent;
};

int pret;
char* default_cfg_path;
struct args_s args;
struct config_s* config;
char* query;
buf_t* query_buf;

void print_version() { printf("sonic %s\n", SONIC_VERSION); }

void print_header()
{
	printf("\n"
		   ".\n"
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
	  "  -S, --silent			Disable progress bar\n"
	  "  -V, --verbose			Enable debug level logging\n"
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

void all_free()
{
	if (query)
		free(query);
	buf_free(query_buf);
	config_free(config);
	args_free();
}

long long current_timestamp()
{
	struct timeval te;
	gettimeofday(&te, NULL);
	return te.tv_sec * 1000LL + te.tv_usec / 1000;
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

	debug_printf("compiled pattern '%s' into pcre2 code", pattern);

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

	debug_printf("read query from file: %s", buf->buf);

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

	if (args.verbose && args.silent) {
		err = "either --verbose or --silent can be defined";
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
	args.verbose = false;
	args.silent = false;

	static struct option long_options[] = {
	  {"execute", required_argument, 0, 'e'},
	  {"file", required_argument, 0, 'f'},
	  {"config", required_argument, 0, 'c'},
	  {"define", required_argument, 0, 'd'}, {"rows-only", no_argument, 0, 'r'},
	  {"silent", no_argument, 0, 'S'}, {"verbose", no_argument, 0, 'V'},
	  {"help", no_argument, 0, 'h'}, {"version", no_argument, 0, 'v'},
	  {0, 0, 0, 0}};

	int option_index = 0;
	int c = 0;
	while ((c = getopt_long(argc, argv, "e:f:c:d:rSVhv", long_options,
			  &option_index)) != -1) {
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
		case 'V':
			args.verbose = true;
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

	debug_printf(
	  "parsed_args: literal: %s, file: %s, source: %s, config: %s, define:",
	  args.literal, args.file, args.source, args.config);
	for (struct definevar_s* next = args.define; next != NULL;
		 next = next->next) {
		debug_printf_chunk(" '%s'->'%s'", next->key, next->val);
	}
	debug_printf_chunk(", rows_only: %d, verbose: %d, silent: %d\n",
	  args.rows_only, args.verbose, args.silent);
}

int main(int argc, char* argv[])
{
	args_init(argc, argv);
	if ((config = config_create(args.config)) == NULL) {
		pret = 1;
		goto exit;
	}

	if ((query_buf = buf_create(BUF_INIT_CAP)) == NULL)
		goto exit;

	if (args.file &&
	  (query = query_file_init(args.file, args.define, query_buf)) == NULL) {
		perror("query_file_init");
		pret = 1;
		goto exit;
	} else if (args.literal &&
	  (query = query_literal_init(args.literal, args.define, query_buf)) ==
		NULL) {
		perror("query_literal_init");
		pret = 1;
		goto exit;
	}

	debug_printf("running query:\n----------\n%s\n----------\n", query);

exit:
	all_free();
	debug_printf("freed all resources, exiting with status: %d\n", pret);
	return pret;
}
