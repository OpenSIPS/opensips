/*
 * Handling for Globally Routable UA URIs
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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
 */

#ifndef _MID_REG_GRUU_
#define _MID_REG_GRUU_

#include "../../mod_fix.h"

#define PUB_GRUU ";pub-gruu="
#define PUB_GRUU_SIZE (sizeof(PUB_GRUU) - 1)

#define TEMP_GRUU ";temp-gruu="
#define TEMP_GRUU_SIZE (sizeof(TEMP_GRUU) - 1)

#define TEMP_GRUU_HEADER "tgruu."
#define TEMP_GRUU_HEADER_SIZE (sizeof(TEMP_GRUU_HEADER) - 1)

#define GR_PARAM ";gr="
#define GR_PARAM_SIZE (sizeof(GR_PARAM) - 1)

#define GR_NO_VAL ";gr"
#define GR_NO_VAL_SIZE (sizeof(GR_NO_VAL) - 1)

extern str default_gruu_secret;

int calc_temp_gruu_len(str* aor,str* instance,str *callid);
char * build_temp_gruu(str *aor,str *instance,str *callid,int *len);

#endif /* _MID_REG_GRUU_ */
