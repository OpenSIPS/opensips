/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 *  2012-01-19  created (vlad)
 */

#ifndef _cfg_script_h_
#define _cfg_script_h_

#define MACRO_INTERPRETER "m4"
typedef struct cfg_generation
{
	char *name;		/* Name of the cfg entry. Used for naming actual menu entries */
	char *output_name;	/* Less user friendly cfg name. Used for creating output cfg file */
	char *defs_m4;		/* Path to the m4 file that contains the defs */
	char *cfg_m4;		/* Path to the m4 file that contains the actual OpenSIPS script */
} cfg_gen_t;

extern cfg_gen_t configs[];
cfg_gen_t* find_cfg_entry(char *name);

#endif
