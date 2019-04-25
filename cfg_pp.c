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

extern char *finame;
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
static FILE *exec_preprocessor(FILE *flat_cfg, const char *preproc_cmdline);

static struct cfg_context *cfg_context_new_file(const char *path);
static void cfg_context_append_line(struct cfg_context *con,
                                    char *line, int len);

int parse_opensips_cfg(const char *cfg_file, const char *preproc_cmdline,
															FILE **ret_stream)
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
		cfg_stream = exec_preprocessor(cfg_stream, preproc_cmdline);
		if (!cfg_stream) {
			LM_ERR("failed to exec preprocessor cmd: '%s'\n", preproc_cmdline);
			return -1;
		}
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

	/* do we have to return the cfg stream? */
	if (ret_stream)
		*ret_stream = cfg_stream;
	else
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
	char *p = NULL, enclose = 0;

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

	*out_path = p;

	while (line_len > 0 && *p != enclose) {
		line_len--;
		p++;
	}

	if (line_len == 0 || p - *out_path < 2) // ""_
		return -1;

	*p = '\0';
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
	struct cfg_context *con = NULL;

	if (cfg_path_len >= 2048) {
		LM_ERR("file path too large: %.*s...\n", 2048, cfg_path);
		goto out_err;
	}

	con = cfg_context_new_file(cfg_path);
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

		if (con)
			cfg_context_append_line(con, line, line_len);

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
				goto out_err;
			}
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

	cfg = fmemopen(flattened, sz - bytes_left, "r");
	if (!cfg)
		LM_ERR("failed to obtain file for flattened cfg buffer\n");

	return cfg;
}

static char *cfg_include_stack[CFG_MAX_INCLUDE_DEPTH];
static char **cfg_include_stackp;
int cfg_push(const str *cfg_file)
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

	*cfg_include_stackp = malloc(cfg_file->len + 1);
	if (!*cfg_include_stackp) {
		LM_ERR("oom\n");
		return -1;
	}
	memcpy(*cfg_include_stackp, cfg_file->s, cfg_file->len);
	(*cfg_include_stackp)[cfg_file->len] = '\0';

	finame = *cfg_include_stackp;
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

	/* the file path MUST NOT be freed, as the lexer and parser work in tandem,
	 * so by this point, there are plenty of structures referencing it */

	if (cfg_include_stackp == cfg_include_stack) {
		cfg_include_stackp = NULL;
	} else {
		cfg_include_stackp--;
		finame = *cfg_include_stackp;
		column = 1;
	}

	return 0;
}

static struct cfg_context {
	const char *path;
	int loc;
	char **lines;
	int bufsz;
	struct cfg_context *next;
} *__ccon;

static struct cfg_context *cfg_context_new_file(const char *path)
{
	struct cfg_context *con, *it;

	for (it = __ccon; it; it = it->next)
		if (!strcmp(it->path, path))
			return NULL;

	con = malloc(sizeof *con);
	memset(con, 0, sizeof *con);

	con->path = strdup(path);
	con->lines = malloc(32 * sizeof *con->lines);
	con->bufsz = 32;

	add_last(con, __ccon);
	return con;
}

static void cfg_context_append_line(struct cfg_context *con,
                                    char *line, int len)
{
	if (con->loc == con->bufsz) {
		con->bufsz *= 2;
		con->lines = realloc(con->lines, con->bufsz * sizeof *con->lines);
	}

	con->lines[con->loc] = malloc(len + 1);
	memcpy(con->lines[con->loc], line, len);
	con->lines[con->loc][len] = '\0';

	con->loc++;
}

void cfg_dump_context(const char *file, int line, int colstart, int colend)
{
	static int called_before;
	struct cfg_context *con;
	int i, iter = 1, len;
	char *p, *end, *wsbuf, *wb, *hiline;

	for (con = __ccon; con; con = con->next)
		if (!strcmp(con->path, file))
			break;

	if (!con || called_before)
		return;

	called_before = 1;

	/* 2 lines above */
	if (line >= 3) {
		startline = line - 2;
		iter += 2;
	} else {
		startline = 1;
		iter += line - 1;
	}

	for (i = startline - 1; iter > 0; i++, iter--)
		LM_GEN1(L_CRIT, "%s", con->lines[i]);

	/* error indicator line */
	len = strlen(con->lines[i-1]);
	wsbuf = malloc(len + 1);
	wb = wsbuf;
	for (p = con->lines[i-1], end = p + len; p < end && is_ws(*p); p++)
		*wb++ = *p;
	*wb = '\0';

	if (colend < colstart) {
		hiline = NULL;
	} else {
		hiline = malloc(colend - colstart);
		memset(hiline, '~', colend - colstart);
	}

	LM_GEN1(L_CRIT, "%s^%.*s\n", wsbuf,
	        colend >= colstart ? colend - colstart : 0, hiline);
	free(hiline);
	free(wsbuf);

	/* 2 lines below */
	if (line <= con->loc - 2)
		iter = 2;
	else
		iter = line <= con->loc ? con->loc - line : 0;

	for (; iter > 0; i++, iter--)
		LM_GEN1(L_CRIT, "%s", con->lines[i]);
}

void cfg_dump_backtrace(void)
{
	static int called_before;
	char **it;
	int frame = 0;

	if (called_before || !cfg_include_stackp)
		return;

	called_before = 1;
	LM_GEN1(L_CRIT, "Traceback (last included file at the bottom):\n");
	for (it = cfg_include_stack; it <= cfg_include_stackp; it++)
		LM_GEN1(L_CRIT, "%2d. %s\n", frame++, *it);
}

static FILE *exec_preprocessor(FILE *flat_cfg, const char *preproc_cmdline)
{
	FILE *final_cfg;
	int parent_w[2], parent_r[2];
	char chunk[1024];
	ssize_t left, written;
	size_t bytes;
	char *p, *tok, *cmd, **argv = NULL, *pp_binary = NULL;
	int argv_len = 0, ch;

	if (strlen(preproc_cmdline) == 0) {
		LM_ERR("preprocessor command (-p) is an empty string!\n");
		goto out_err;
	}

	if (pipe(parent_w) != 0 || pipe(parent_r) != 0) {
		LM_ERR("failed to create pipe: %d (%s)\n", errno, strerror(errno));
		goto out_err;
	}

	/* fork a data-hungry preprocessor beast! (a.k.a. some tiny sed) */
	if (fork() == 0) {
		close(parent_w[1]);
		if (dup2(parent_w[0], STDIN_FILENO) < 0) {
			LM_ERR("dup2 failed with: %d (%s)\n", errno, strerror(errno));
			exit(-1);
		}
		close(parent_w[0]);

		close(parent_r[0]);
		if (dup2(parent_r[1], STDOUT_FILENO) < 0) {
			LM_ERR("dup2 failed with: %d (%s)\n", errno, strerror(errno));
			exit(-1);
		}
		close(parent_w[1]);

		for (cmd = strdup(preproc_cmdline); ; cmd = NULL) {
			tok = strtok(cmd, " \t\r\n");
			if (!tok)
				break;

			if (!pp_binary)
				pp_binary = tok;

			argv = realloc(argv, (argv_len + 1) * sizeof *argv);
			argv[argv_len++] = tok;
		}

		argv = realloc(argv, (argv_len + 1) * sizeof *argv);
		argv[argv_len++] = NULL;

		execvp(pp_binary, argv);
		LM_ERR("failed to exec preprocessor '%s': %d (%s)\n",
		       preproc_cmdline, errno, strerror(errno));
		exit(-1);
	}

	close(parent_w[0]);
	close(parent_r[1]);

	/* push the cfg file into the new process' stdin */
	do {
		bytes = fread(chunk, 1, 1024, flat_cfg);
		if (ferror(flat_cfg)) {
			LM_ERR("failed to read from flat cfg: %d (%s)\n",
			       errno, strerror(errno));
			goto out_err_pipes;
		}

		if (bytes == 0)
			continue;

		left = bytes;
		p = chunk;
		do {
			written = write(parent_w[1], p, left);
			left -= written;
			p += written;
		} while (left > 0);

	} while (!feof(flat_cfg));

	fclose(flat_cfg);
	close(parent_w[1]);

	/* and we're done, let's see what the process barfed up! */
	final_cfg = fdopen(parent_r[0], "r");
	if (!final_cfg) {
		LM_ERR("failed to open final cfg file: %d (%s)\n",
		       errno, strerror(errno));
	} else {
		ch = fgetc(final_cfg);
		if (ch == EOF) {
			LM_ERR("no output from the preprocessor!  "
					"Make sure it prints to standard output!\n");
			fclose(final_cfg);
			final_cfg = NULL;
		} else {
			ungetc(ch, final_cfg);
		}
	}

	return final_cfg;

out_err_pipes:
	close(parent_w[1]);
	close(parent_r[0]);
out_err:
	fclose(flat_cfg);
	return NULL;
}

int eatback_pp_tok(struct str_buf *buf)
{
	char *p;
	str last_line;

	if (!buf->s)
		return 0;

	for (p = buf->crt - 1; p >= buf->s; p--)
		if (*p == '\n') {
			p++;
			goto match_pp_tok;
		}

	return 0;

match_pp_tok:
	last_line.s = p;
	last_line.len = buf->crt - p;

	if (last_line.len < 0) {
		LM_BUG("negative line len");
		return 0;
	}

	if (last_line.len >= cfgtok_line.len &&
		!memcmp(last_line.s, cfgtok_line.s, cfgtok_line.len))
		goto clear_last_line;

	if (last_line.len >= cfgtok_filebegin.len &&
		!memcmp(last_line.s, cfgtok_filebegin.s, cfgtok_filebegin.len))
		goto clear_last_line;

	if (last_line.len >= cfgtok_fileend.len &&
		!memcmp(last_line.s, cfgtok_fileend.s, cfgtok_fileend.len))
		goto clear_last_line;

	/* don't touch anything, this is an actual script line! */
	return 0;

clear_last_line:
	LM_DBG("clearing pp token line: '%.*s'\n", (int)(buf->crt - p), p);
	buf->left += buf->crt - p;
	*p = '\0';
	buf->crt = p;
	return 1;
}
