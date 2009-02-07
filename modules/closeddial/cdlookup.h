/*
 * $Id$
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * History:
 * ---------
 * 2009-02-07 Initial version of closeddial module (saguti)
 */


#ifndef _CDLOOKUP_H_
#define _CDLOOKUP_H_

#include "../../parser/msg_parser.h"

/* Function which is exported to script */
int cd_lookup(struct sip_msg* _msg, char* _table, char* _group);

#endif /* _CDLOOKUP_H_ */
