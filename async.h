/*
 * Copyright (C) 2014 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2014-10-15  created (bogdan)
 */


#ifndef _ASYNC_H_
#define _ASYNC_H_

#include "route_struct.h"
#include "parser/msg_parser.h"

/* function to handle script function in async mode.
   Input: the sip message, the function/action (MODULE_T) and the ID of
          the resume route (where to continue after the I/O is done).
   Output: 0 if the async call was successfuly done and script execution
          must be terminated.
          -1 some error happened and the async call did not happened.
 */

typedef int (async_function)(struct sip_msg *msg, struct action* a , int resume_route);


int register_async_handler( async_function *f);


#endif

