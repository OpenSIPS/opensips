/*
 * OpenSIPS configuration file pre-processing
 *
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "config.h"
#include "globals.h"
#include "cfg_pp.h"
#include "ut.h"

extern const char *finame;
extern int startline;
extern int column;

extern FILE *yyin;
extern int yyparse();
#ifdef DEBUG_PARSER
extern int yydebug;
#endif

str include_v1 = str_init("include_file");
str include_v2 = str_init("import_file");

str cfgtok_line = str_init("__OSSPP_LINE__");
str cfgtok_filebegin = str_init("__OSSPP_FILEBEGIN__");
str cfgtok_fileend = str_init("__OSSPP_FILEEND__");

static FILE *flatten_opensips_cfg(FILE *cfg, const char *cfg_path);

int parse_opensips_cfg(const char *cfg_file, const char *preproc_cmdline)
{
	FILE *cfg_stream;

	/* fill missing arguments with the default values*/
	if (!cfg_file)
		cfg_file = CFG_FILE;

	if (strlen(cfg_file) == 1 && cfg_file[0] == '-') {
		cfg_stream = stdin;
	} else {
		/* load config file or die */
		cfg_stream = fopen(cfg_file, "r");
		if (!cfg_stream) {
			LM_ERR("loading config file %s: %s\n", cfg_file,
			       strerror(errno));
			return -1;
		}
	}

	cfg_stream = flatten_opensips_cfg(cfg_stream,
						cfg_stream == stdin ? "stdin" : cfg_file);
	if (!cfg_stream) {
		LM_ERR("failed to expand file imports for %s, oom?\n", cfg_file);
		return -1;
	}

	if (preproc_cmdline) {
		// TODO: some dup magic, to push into pp stdin / read from its stdout
		// TODO: execvp(chopped(preproc_cmdline), flattened_cfg)
		// TODO: cfg_stream = fdopen(stdout_fd);
	}

#ifdef DEBUG_PARSER
	/* used for parser debugging */
	yydebug = 1;
#endif

	/* parse the config file, prior to this only default values
	   e.g. for debugging settings will be used */
	yyin = cfg_stream;
	if (yyparse() != 0 || cfg_errors) {
		LM_ERR("bad config file (%d errors)\n", cfg_errors);
		fclose(cfg_stream);
		return -1;
	}

	fclose(cfg_stream);
	return 0;
}

static int extend_cfg_buf(char **buf, int *sz, int *bytes_left)
{
	*buf = realloc(*buf, *sz + 4096);
	if (!*buf) {
		LM_ERR("oom\n");
		return -1;
	}

	*sz += 4096;
	*bytes_left += 4096;
	return 0;
}

/* search for '(include|import)_file "filepath"' patterns */
int extract_included_file(char *line, int line_len, char **out_path)
{
	str lin;
	char *fstart, *p = NULL, enclose = 0;

	lin.s = line;
	lin.len = line_len;

	if (line_len > include_v1.len &&
	        !memcmp(line, include_v1.s, include_v1.len)) {
		p = line + include_v1.len;
		line_len -= include_v1.len;
	} else if (line_len > include_v2.len &&
	        !memcmp(line, include_v2.s, include_v2.len)) {
		p = line + include_v2.len;
		line_len -= include_v2.len;
	}

	if (!p)
		return -1;

	while (line_len > 0 && isspace(*p)) {
		line_len--;
		p++;
	}

	if (line_len < 3) // "f"
		return -1;

	if (*p != '"' && *p != '\'')
		return -1;

	enclose = *p++;
	line_len--;

	fstart = p;

	while (line_len > 0 && *p != enclose) {
		line_len--;
		p++;
	}

	if (line_len == 0 || p - fstart < 2) // ""_
		return -1;

	*out_path = malloc(p - fstart);
	if (!*out_path) {
		LM_ERR("oom\n");
		return -1;
	}

	memcpy(*out_path, fstart, p - fstart);
	return 0;
}

static int __flatten_opensips_cfg(FILE *cfg, const char *cfg_path,
                                  char **flattened, int *sz, int *bytes_left)
{
	FILE *included_cfg;
	ssize_t line_len;
	char *line = NULL, *included_cfg_path;
	unsigned long line_buf_sz = 0;
	int cfg_path_len = strlen(cfg_path);
	int line_counter = 1, printed;

	if (cfg_path_len >= 2048) {
		LM_ERR("file path too large: %.*s...\n", 2048, cfg_path);
		goto out_err;
	}

	if (*bytes_left < cfgtok_filebegin.len + 1 + 1+cfg_path_len+1 + 1) {
		if (extend_cfg_buf(flattened, sz, bytes_left) < 0) {
			LM_ERR("oom\n");
			goto out_err;
		}
	}

	/* print "start of file" adnotation */
	sprintf(*flattened + *sz - *bytes_left, "%.*s \"%.*s\"\n",
	        cfgtok_filebegin.len, cfgtok_filebegin.s, cfg_path_len, cfg_path);
	*bytes_left -= cfgtok_filebegin.len + 1 +1+cfg_path_len+1 + 1;

	for (;;) {
		line_len = getline(&line, &line_buf_sz, cfg);
		if (line_len == -1) {
			if (ferror(cfg)) {
				if (errno == EINTR) {
					continue;
				} else {
					LM_ERR("failed to read from cfg file %.*s: %d (%s)\n",
					       cfg_path_len, cfg_path, errno, strerror(errno));
					goto out_err;
				}
			}

			if (!feof(cfg)) {
				LM_ERR("unhandled read error in cfg file %.*s: %d (%s)\n",
				       cfg_path_len, cfg_path, errno, strerror(errno));
				goto out_err;
			}

			line_len = strlen(line);

			break;
		} else if (line_len == 0) {
			continue;
		}

		/* fix ending lines with a missing '\n' character ;) */
		if (feof(cfg)) {
			if (line[line_len - 1] != '\n') {
				if (line_buf_sz < line_len + 1) {
					line = realloc(line, line_len + 1);
					line_buf_sz = line_len + 1;
				}

				line[line_len] = '\n';
				line_len += 1;
			}
		}

		/* finally... we have a line! print "line number" adnotation */
		if (*bytes_left < cfgtok_line.len + 1 + 10) {
			if (extend_cfg_buf(flattened, sz, bytes_left) < 0) {
				LM_ERR("oom\n");
				goto out_err;
			}
		}

		printed = sprintf(*flattened + *sz - *bytes_left, "%.*s %d\n",
	                      cfgtok_line.len, cfgtok_line.s, line_counter);
		line_counter++;
		*bytes_left -= printed;

		/* if it's an include, skip printing the line, but do print the file */
		if (extract_included_file(line, line_len, &included_cfg_path) == 0) {
			included_cfg = fopen(included_cfg_path, "r");
			if (!included_cfg) {
				LM_ERR("failed to open %s: %d (%s)\n", included_cfg_path,
				       errno, strerror(errno));
				goto out_err;
			}

			if (__flatten_opensips_cfg(included_cfg, included_cfg_path,
			                           flattened, sz, bytes_left)) {
				LM_ERR("failed to flatten cfg file (internal err), oom?\n");
				fclose(included_cfg);
				goto out_err;
			}

			free(included_cfg_path);
			fclose(included_cfg);
		} else {
			if (*bytes_left < line_len) {
				if (extend_cfg_buf(flattened, sz, bytes_left) < 0) {
					LM_ERR("oom\n");
					goto out_err;
				}
			}

			printed = sprintf(*flattened + *sz - *bytes_left, "%.*s",
	                          (int)line_len, line);
			*bytes_left -= printed;
		}
	}

	free(line);

	if (*bytes_left < cfgtok_fileend.len + 1) {
		if (extend_cfg_buf(flattened, sz, bytes_left) < 0) {
			LM_ERR("oom\n");
			goto out_err;
		}
	}

	/* print "end of file" adnotation */
	sprintf(*flattened + *sz - *bytes_left, "%.*s\n",
	        cfgtok_fileend.len, cfgtok_fileend.s);
	*bytes_left -= cfgtok_fileend.len + 1;

	fclose(cfg);
	return 0;

out_err:
	fclose(cfg);
	return -1;
}

/*
 * - flatten any recursive includes into one big resulting file
 * - adnotate each line of the final file
 * - close given FILE * and return a new one, corresponding to the new file
 */
static FILE *flatten_opensips_cfg(FILE *cfg, const char *cfg_path)
{
	int sz = 0, bytes_left = 0;
	char *flattened = NULL;

	if (__flatten_opensips_cfg(cfg, cfg_path, &flattened, &sz, &bytes_left)) {
		LM_ERR("failed to flatten cfg file (internal err), out of memory?\n");
		return NULL;
	}

#ifdef EXTRA_DEBUG
	LM_NOTICE("flattened config file:\n%.*s\n", sz - bytes_left, flattened);
#endif

	cfg = fmemopen(flattened, sz, "r");
	if (!cfg)
		LM_ERR("failed to obtain file for flattened cfg buffer\n");

	return cfg;
}

const char *cfg_include_stack[CFG_MAX_INCLUDE_DEPTH];
const char **cfg_include_stackp;
int cfg_push(const char *cfg_file)
{
	if (!cfg_include_stackp) {
		cfg_include_stackp = cfg_include_stack;
	} else if (cfg_include_stackp - cfg_include_stack + 1 >=
	           CFG_MAX_INCLUDE_DEPTH) {
		LM_ERR("max nested cfg files reached! (%d)\n", CFG_MAX_INCLUDE_DEPTH);
		return -1;
	} else {
		cfg_include_stackp++;
	}

	*cfg_include_stackp = cfg_file;

	finame = cfg_file;
	startline = 1;
	column = 1;
	return 0;
}

int cfg_pop(void)
{
	if (!cfg_include_stackp) {
		LM_ERR("no more files to pop!\n");
		return -1;
	}

	if (cfg_include_stackp == cfg_include_stack) {
		cfg_include_stackp = NULL;
	} else {
		cfg_include_stackp--;
		finame = *cfg_include_stackp;
		column = 1;
	}

	return 0;
}

void cfg_dump_backtrace(int loglevel)
{
	const char **it;
	int frame = 0;

	LM_GEN1(loglevel, "IncludeStack (last included file at the bottom)\n");
	for (it = cfg_include_stack; it <= cfg_include_stackp; it++)
		LM_GEN1(loglevel, "%2d. %s\n", frame++, *it);
}
