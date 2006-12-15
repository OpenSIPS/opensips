/*
 * Copyright (C) 2006 Juha Heinanen
 *
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
 
#include "parse_from.h"
#include "parse_to.h"
#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "msg_parser.h"
#include "../ut.h"
#include "../mem/mem.h"

 
/*
 * This method is used to parse P-Preferred-Identity header (RFC 3325).
 *
 * Currently only one name-addr / addr-spec is supported in the header
 * and it must contain a sip or sips URI.
 *
 * params: msg : sip msg
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_ppi_header( struct sip_msg *msg )
{
    struct to_body* ppi_b;
    
    if ( !msg->ppi &&
	 (parse_headers(msg, HDR_PPI_F,0)==-1 || !msg->ppi)) {
	goto error;
    }
 
    /* maybe the header is already parsed! */
    if (msg->ppi->parsed)
	return 0;
 
    /* bad luck! :-( - we have to parse it */
    /* first, get some memory */
    ppi_b = pkg_malloc(sizeof(struct to_body));
    if (ppi_b == 0) {
	LOG(L_ERR, "ERROR:parse_ppi_header: out of pkg_memory\n");
	goto error;
    }
 
    /* now parse it!! */
    memset(ppi_b, 0, sizeof(struct to_body));
    parse_to(msg->ppi->body.s,
	     msg->ppi->body.s + msg->ppi->body.len+1,
	     ppi_b);
    if (ppi_b->error == PARSE_ERROR) {
	LOG(L_ERR, "ERROR:parse_ppi_header: bad P-Preferred-Identity header\n");
	pkg_free(ppi_b);
	goto error;
    }
 	msg->ppi->parsed = ppi_b;
 
 	return 0;
 error:
 	return -1;
}
