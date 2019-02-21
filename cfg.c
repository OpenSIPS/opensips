/*
 * OpenSIPS configuration file parsing
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

#include <stdio.h>
#include <errno.h>

#include "config.h"
#include "globals.h"
#include "cfg.h"

extern FILE *yyin;
extern int yyparse();
#ifdef DEBUG_PARSER
extern int yydebug;
#endif

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

#ifdef DEBUG_PARSER
	/* used for parser debugging */
	yydebug = 1;
#endif

	/* parse the config file, prior to this only default values
	   e.g. for debugging settings will be used */
	yyin = cfg_stream;
	if (yyparse() != 0 || cfg_errors) {
		LM_ERR("bad config file (%d errors)\n", cfg_errors);
		return -1;
	}

	return 0;
}
