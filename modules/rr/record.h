/*
 * Route & Record-Route module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2003-04-04 Extracted from common.[ch] (janakj)
 * 2005-04-10 add_rr_param() function added (bogdan)
 */

/*!
 * \file
 * \brief Route & Record-Route module
 * \ingroup rr
 */

#ifndef RECORD_H
#define RECORD_H

#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../context.h"


/* index in processing context - status of RR */
extern int ctx_rrstat_idx;
#define ctx_rrstat_set(_val) \
	context_put_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_rrstat_idx, _val)
#define ctx_rrstat_get() \
	context_get_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_rrstat_idx)


/*! \brief
 * Insert a new Record-Route header field with lr parameter
 */
int record_route(struct sip_msg* _m, str* _param);


/*! \brief
 * Insert manually created Record-Route header, no checks, no restrictions,
 * always adds lr parameter, only fromtag is added automatically when requested
 */
int record_route_preset(struct sip_msg* _m, str* _data);


/*! \brief
 * Appends a new Record-Route parameter
 */
int add_rr_param(struct sip_msg* msg, str* rr_param);


#endif /* RECORD_H */
