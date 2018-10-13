#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "cli_config.h"
#include "config.h"

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

typedef struct definevar_s {
	struct definevar_s* next;
	char* key;
	char* val;
} definevar_t;

struct args_s {
	const char* literal;
	const char* file;
	const char* source;
	const char* config;
	definevar_t* define;
	bool rows_only;
	bool verbose;
	bool silent;
};

int pret;
char* default_cfg_path;
struct args_s args;
struct config_s* config;

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

void args_define_free(definevar_t* define)
{
	for (definevar_t* next = define; next != NULL;) {
		definevar_t* tmp = next->next;
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
	config_free(config);
	args_free();
}

long long current_timestamp()
{
	struct timeval te;
	gettimeofday(&te, NULL);
	return te.tv_sec * 1000LL + te.tv_usec / 1000;
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

definevar_t* parse_define(definevar_t* head, char* arg)
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
	definevar_t* var = calloc(1, sizeof(definevar_t));
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
	for (definevar_t* next = args.define; next != NULL; next = next->next) {
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

exit:
	all_free();
	debug_printf("freed all resources, exiting with status: %d\n", pret);
	return pret;
}
