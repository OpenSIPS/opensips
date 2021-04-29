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

#ifndef __OSS_CFG_PP_H__
#define __OSS_CFG_PP_H__

#include <stdio.h>

#include "str.h"

#define CFG_MAX_INCLUDE_DEPTH	20

struct str_buf{
	char* s;
	char* crt;
	int left;
};

int parse_opensips_cfg(const char *cfg_file, const char *preproc_cmdline,
		str *ret_buffer);
int cfg_push(const str *cfg_file);
int cfg_pop(void);
void _cfg_dump_context(const char *file, int line, int colstart, int colend,
                       int run_once);
#define cfg_dump_context(f, l, s, e) _cfg_dump_context(f, l, s, e, 0)
void cfg_dump_backtrace(void);

/* ultimately helps correctly parse multi-line strings by eating any
 * additionally inserted preprocessor directive as the last line of the
 * given string buffer */
int eatback_pp_tok(struct str_buf *buf);

#endif /* __OSS_CFG_PP_H__ */
