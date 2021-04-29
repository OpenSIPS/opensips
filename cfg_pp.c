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

#define _WITH_GETLINE

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>

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

static int flatten_opensips_cfg(FILE *cfg, const char *cfg_path, str *out);
static int exec_preprocessor(FILE *flat_cfg, const char *preproc_cmdline,
                             str *out);

static struct cfg_context *cfg_context_new_file(const char *path);
static void cfg_context_append_line(struct cfg_context *con,
                                    char *line, int len);

int parse_opensips_cfg(const char *cfg_file, const char *preproc_cmdline,
															str *ret_buffer)
{
	FILE *cfg_stream;
	str cfg_buf, pp_buf;

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

	if (flatten_opensips_cfg(cfg_stream,
				cfg_stream == stdin ? "stdin" : cfg_file, &cfg_buf) < 0) {
		LM_ERR("failed to resolve file imports for %s\n", cfg_file);
		return -1;
	}

	cfg_stream = fmemopen(cfg_buf.s, cfg_buf.len, "r");
	if (!cfg_stream) {
		LM_ERR("failed to open file for flattened cfg buffer\n");
		goto out_free;
	}

	if (preproc_cmdline) {
		if (exec_preprocessor(cfg_stream, preproc_cmdline, &pp_buf) < 0) {
			LM_ERR("failed to exec preprocessor cmd: '%s'\n", preproc_cmdline);
			goto out_free;
		}
		free(cfg_buf.s);
		cfg_buf = pp_buf;

		cfg_stream = fmemopen(cfg_buf.s, cfg_buf.len, "r");
		if (!cfg_stream) {
			LM_ERR("failed to open file for processed cfg buffer\n");
			goto out_free;
		}
	}

#ifdef DEBUG_PARSER
	/* used for parser debugging */
	yydebug = 1;
#endif

	/* parse the config file, prior to this only default values
	   e.g. for debugging settings will be used */
	yyin = cfg_stream;
	cfg_errors = 0;
	if (yyparse() != 0 || cfg_errors) {
		LM_ERR("bad config file (%d errors)\n", cfg_errors);
		fclose(cfg_stream);
		goto out_free;
	}

	fclose(cfg_stream);

	/* do we have to return the cfg buffer? */
	if (ret_buffer)
		*ret_buffer = cfg_buf;
	else
		free(cfg_buf.s);

	return 0;

out_free:
	free(cfg_buf.s);
	return -1;
}

static int extend_cfg_buf(char **buf, int *sz, int *bytes_left, int needed)
{
	if (needed < 4096)
		needed = 4096;

	*buf = realloc(*buf, *sz + needed);
	if (!*buf) {
		LM_ERR("failed to extend cfg buf to %d\n", *sz + needed);
		return -1;
	}

	*sz += needed;
	*bytes_left += needed;
	return 0;
}

/* search for '(include|import)_file "filepath"' patterns */
int mk_included_file_path(char *line, int line_len, const char *current_dir,
                          char **out_path)
{
	#define MAX_INCLUDE_FNAME   256
	static char full_path[MAX_INCLUDE_FNAME];
	struct stat _;
	char *p = NULL, enclose = 0;
	int len1, len2, fplen;

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
		return 1;

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

	/* is it a relative-path import? */
	if (**out_path != '/' && stat(*out_path, &_) < 0) {
		LM_DBG("%s not found (%d, %s), assuming it's relative to source cfg\n",
		       *out_path, errno, strerror(errno));

		/* this relative path is not inside the startup dir,
		 * so maybe it's relative to the importing file */
		len1 = strlen(current_dir);
		len2 = strlen(*out_path);

		if (len1 + 1 + len2 + 1 > MAX_INCLUDE_FNAME) {
			LM_ERR("file path too long (max %d): '%s' + '%s'\n",
			       MAX_INCLUDE_FNAME, current_dir, *out_path);
			return -1;
		}

		memcpy(full_path, current_dir, len1);
		fplen = len1;

		/* this test can only fail when opensips runs from '/' */
		if (current_dir[len1 - 1] != '/')
			full_path[fplen++] = '/';

		memcpy(full_path + fplen, *out_path, len2);
		fplen += len2;

		full_path[fplen] = '\0';
		*out_path = full_path;
	}

	LM_DBG("preparing to include %s\n", *out_path);
	return 0;
}

static struct cfg_context {
	const char *path;
	const char *dirname; /* useful for relative path includes */
	int loc;
	char **lines;
	int bufsz;
	struct cfg_context *next;
} *__ccon;

static struct cfg_context *cfg_context_new_file(const char *path)
{
	struct cfg_context *con, *it;
	char *cpy;

	for (it = __ccon; it; it = it->next)
		if (!strcmp(it->path, path))
			return it;

	con = malloc(sizeof *con);
	memset(con, 0, sizeof *con);

	con->path = strdup(path);

	cpy = strdup(path);
	con->dirname = strdup(dirname(cpy));
	free(cpy);

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
		if (!con->lines)
			return;
	}

	con->lines[con->loc] = malloc(len + 1);
	memcpy(con->lines[con->loc], line, len);
	con->lines[con->loc][len] = '\0';

	con->loc++;
}

static int __flatten_opensips_cfg(FILE *cfg, const char *cfg_path,
                        char **flattened, int *sz, int *bytes_left, int reclev)
{
	FILE *included_cfg;
	ssize_t line_len;
	char *line = NULL, *included_cfg_path;
	unsigned long line_buf_sz = 0;
	int cfg_path_len = strlen(cfg_path);
	int line_counter = 1, needed, printed;
	struct cfg_context *con = NULL;

	if (reclev > 50) {
		LM_ERR("Maximum import depth reached (50) or "
		       "you have an infinite include_file loop!\n");
		goto out_err;
	}

	if (cfg_path_len >= 2048) {
		LM_ERR("file path too large: %.*s...\n", 2048, cfg_path);
		goto out_err;
	}

	con = cfg_context_new_file(cfg_path);
	needed = cfgtok_filebegin.len + 1 + 1+cfg_path_len+1 + 1 + 1;
	if (*bytes_left < needed) {
		if (extend_cfg_buf(flattened, sz, bytes_left, needed) < 0) {
			LM_ERR("oom\n");
			goto out_err;
		}
	}

	/* print "start of file" adnotation */
	printed = snprintf(*flattened + *sz - *bytes_left, *bytes_left, "%.*s \"%.*s\"\n",
	        cfgtok_filebegin.len, cfgtok_filebegin.s, cfg_path_len, cfg_path);
	*bytes_left -= printed;

	for (;;) {
		line_len = getline(&line, (size_t*)&line_buf_sz, cfg);
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
		needed = cfgtok_line.len + 1 + 10 + 1 + 1;
		if (*bytes_left < needed) {
			if (extend_cfg_buf(flattened, sz, bytes_left, needed) < 0) {
				LM_ERR("oom\n");
				goto out_err;
			}
		}

		printed = snprintf(*flattened + *sz - *bytes_left, *bytes_left,
		            "%.*s %d\n", cfgtok_line.len, cfgtok_line.s, line_counter);
		line_counter++;
		*bytes_left -= printed;

		if (con)
			cfg_context_append_line(con, line, line_len);

		/* if it's an include, skip printing the line, but do print the file */
		if (mk_included_file_path(line, line_len, con->dirname, &included_cfg_path) == 0) {
			included_cfg = fopen(included_cfg_path, "r");
			if (!included_cfg) {
				LM_ERR("failed to open %s: %d (%s)\n", included_cfg_path,
				       errno, strerror(errno));
				goto out_err;
			}

			included_cfg_path = strdup(included_cfg_path);
			if (__flatten_opensips_cfg(included_cfg, included_cfg_path,
			                           flattened, sz, bytes_left, reclev + 1)) {
				free(included_cfg_path);
				LM_ERR("failed to flatten cfg file %s\n", cfg_path);
				goto out_err;
			}
			free(included_cfg_path);
		} else {
			needed = line_len + 1;
			if (*bytes_left < needed) {
				if (extend_cfg_buf(flattened, sz, bytes_left, needed) < 0) {
					LM_ERR("oom\n");
					goto out_err;
				}
			}

			printed = snprintf(*flattened + *sz - *bytes_left, *bytes_left,
							"%.*s", (int)line_len, line);
			*bytes_left -= printed;
		}
	}

	free(line);
	line = NULL;

	needed = cfgtok_fileend.len + 1 + 1;
	if (*bytes_left < needed) {
		if (extend_cfg_buf(flattened, sz, bytes_left, needed) < 0) {
			LM_ERR("oom\n");
			goto out_err;
		}
	}

	/* print "end of file" adnotation */
	printed = snprintf(*flattened + *sz - *bytes_left, *bytes_left, "%.*s\n",
	        cfgtok_fileend.len, cfgtok_fileend.s);
	*bytes_left -= printed;

	fclose(cfg);
	return 0;

out_err:
	if (line)
		free(line);
	fclose(cfg);
	return -1;
}

/*
 * - flatten any recursive includes into one big resulting file
 * - adnotate each line of the final file
 * - close given FILE * and return a buffer corresponding to the new file
 */
static int flatten_opensips_cfg(FILE *cfg, const char *cfg_path, str *out)
{
	int sz = 0, bytes_left = 0;
	char *flattened = NULL;

	if (__flatten_opensips_cfg(cfg, cfg_path, &flattened, &sz, &bytes_left, 0)) {
		LM_ERR("failed to flatten cfg file %s\n", cfg_path);
		return -1;
	}

	out->s = flattened;
	out->len = sz - bytes_left;

	if (strlen(out->s) != out->len) {
		LM_BUG("preprocessed buffer check failed (%lu vs. %d)",
		       strlen(out->s), out->len);
		LM_ERR("either this is a bug or your script contains '\\0' chars, "
		        "which are obviously NOT allowed!\n");
		return -1;
	}

	return 0;
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

void _cfg_dump_context(const char *file, int line, int colstart, int colend,
                       int run_once)
{
	static int called_before;
	struct cfg_context *con;
	int i, iter = 1, len;
	char *p, *end, *wsbuf, *wb, *hiline;

	if (!file)
		return;

	for (con = __ccon; con; con = con->next)
		if (!strcmp(con->path, file))
			break;

	if (!con || !con->lines[0] || (run_once && called_before))
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
	if (!wsbuf) {
		LM_ERR("oom\n");
		return;
	}

	wb = wsbuf;
	for (p = con->lines[i-1], end = p + len; p < end && is_ws(*p); p++)
		*wb++ = *p;
	*wb = '\0';

	if (colend < colstart) {
		hiline = NULL;
	} else {
		hiline = malloc(colend - colstart);
		if (!hiline) {
			LM_ERR("oom\n");
			free(wsbuf);
			return;
		}
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

static int exec_preprocessor(FILE *flat_cfg, const char *preproc_cmdline,
                             str *out)
{
	int parent_w[2], parent_r[2], cfgsz = 0, cfgbufsz = 0;
	char chunk[1024], *cfgbuf = NULL;
	ssize_t written, bytes;
	size_t bytes2write;
	char *p, *tok, *cmd, **argv = NULL, *pp_binary = NULL;
	int argv_len = 0, flags, have_input = 0, done_writing = 0;

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

		if (pp_binary) {
			execvp(pp_binary, argv);
			LM_ERR("failed to exec preprocessor '%s': %d (%s)\n",
				   preproc_cmdline, errno, strerror(errno));
		} else
			LM_ERR("no binary to run: '%s'\n", preproc_cmdline);

		exit(-1);
	}

	close(parent_w[0]);
	close(parent_r[1]);

	flags = fcntl(parent_w[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl GET 1 failed: %d - %s\n", errno, strerror(errno));
		goto out_err_pipes;
	}

	if (fcntl(parent_w[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl SET 1 failed: %d - %s\n", errno, strerror(errno));
		goto out_err_pipes;
	}

	flags = fcntl(parent_r[0], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl GET 2 failed: %d - %s\n", errno, strerror(errno));
		goto out_err_pipes;
	}

	if (fcntl(parent_r[0], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl SET 2 failed: %d - %s\n", errno, strerror(errno));
		goto out_err_pipes;
	}

	/* communicate with the preprocessor using alternating,
	 * non-blocking writes and reads */
	while (!done_writing) {
		/* fetch bytes to write */
		bytes2write = fread(chunk, 1, 1024, flat_cfg);
		if (ferror(flat_cfg)) {
			LM_ERR("failed to read from flat cfg: %d (%s)\n",
			       errno, strerror(errno));
			goto out_err_pipes;
		}

		if (bytes2write == 0) {
			done_writing = 1;
			close(parent_w[1]); /* signal EOF to the outside process! */
		} else {
			have_input = 1;
		}

		p = chunk;

send_bytes:
		/* write phase */
		while (bytes2write > 0) {
			written = write(parent_w[1], p, bytes2write);
			if (written < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				else if (errno == EINTR)
					continue;
				else
					goto out_err_pipes;
			}

			bytes2write -= written;
			p += written;
		}

		/* read phase */
		for (;;) {
			if (cfgsz + 1024 > cfgbufsz) {
				if (cfgbufsz == 0)
					cfgbufsz = 4096;
				else
					cfgbufsz *= 2;

				cfgbuf = realloc(cfgbuf, cfgbufsz);
				if (!cfgbuf) {
					LM_ERR("oom, failed to build config buffer\n");
					goto out_err;
				}
			}

			bytes = read(parent_r[0], cfgbuf + cfgsz, 1024);
			if (bytes < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					if (done_writing) {
						usleep(10);
						continue;
					} else {
						break;
					}
				} else if (errno == EINTR) {
					continue;
				} else {
					goto out_err_pipes;
				}
			} else if (bytes == 0) {
				bytes2write = 0;
				done_writing = 1;
				break;
			}

			cfgsz += bytes;
		}

		if (bytes2write > 0)
			goto send_bytes;
	}

	if (have_input && cfgsz == 0)
		LM_WARN("no output from the preprocessor! "
				"Does it print to standard output?\n");

	fclose(flat_cfg);
	close(parent_r[0]);

	out->s = cfgbuf;
	out->len = cfgsz;
	return 0;

out_err_pipes:
	close(parent_w[1]);
	close(parent_r[0]);
out_err:
	fclose(flat_cfg);
	free(cfgbuf);
	return -1;
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
