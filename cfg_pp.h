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

#define CFG_MAX_INCLUDE_DEPTH	20

int parse_opensips_cfg(const char *cfg_file, const char *preproc_cmdline);
int cfg_push(const char *cfg_file);
int cfg_pop(void);

#endif /* __OSS_CFG_PP_H__ */
