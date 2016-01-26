/*
 * $Id$
 *
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * UAC OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * UAC OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2005-01-31  first version (ramona)
 *  2006-03-02  UAC authentication looks first in AVPs for credential (bogdan)
 */


#include <ctype.h>
#include <string.h>

#include "../../str.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../md5global.h"
#include "../../md5.h"
#include "../../parser/parse_authenticate.h"
#include "../tm/tm_load.h"
#include "../uac_auth/uac_auth.h"



extern struct tm_binds uac_tmb;
extern uac_auth_api_t uac_auth_api;


static inline int apply_urihdr_changes( struct sip_msg *req,
													str *uri, str *hdr)
{
	struct lump* anchor;

	/* add the uri - move it to branch directly FIXME (bogdan)*/
	if (req->new_uri.s)
	{
		pkg_free(req->new_uri.s);
		req->new_uri.len=0;
	}
	req->parsed_uri_ok=0;
	req->new_uri.s = (char*)pkg_malloc(uri->len+1);
	if (req->new_uri.s==0)
	{
		LM_ERR("no more pkg\n");
		goto error;
	}
	memcpy( req->new_uri.s, uri->s, uri->len);
	req->new_uri.s[uri->len]=0;
	req->new_uri.len=uri->len;

	/* add the header */
	if (parse_headers(req, HDR_EOH_F, 0) == -1)
	{
		LM_ERR("failed to parse message\n");
		goto error;
	}

	anchor = anchor_lump(req, req->unparsed - req->buf, 0, 0);
	if (anchor==0)
	{
		LM_ERR("failed to get anchor\n");
		goto error;
	}

	if (insert_new_lump_before(anchor, hdr->s, hdr->len, 0) == 0)
	{
		LM_ERR("faield to insert lump\n");
		goto error;
	}

	return 0;
error:
	pkg_free( hdr->s );
	return -1;
}



int uac_auth( struct sip_msg *msg)
{
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	struct uac_credential *crd;
	int code, branch;
	struct sip_msg *rpl;
	struct cell *t;
	HASHHEX response;
	str *new_hdr;

	/* get transaction */
	t = uac_tmb.t_gett();
	if (t==T_UNDEFINED || t==T_NULL_CELL)
	{
		LM_CRIT("no current transaction found\n");
		goto error;
	}

	/* get the selected branch */
	branch = uac_tmb.t_get_picked();
	if (branch<0) {
		LM_CRIT("no picked branch (%d)\n",branch);
		goto error;
	}

	rpl = t->uac[branch].reply;
	code = t->uac[branch].last_received;
	LM_DBG("picked reply is %p, code %d\n",rpl,code);

	if (rpl==0)
	{
		LM_CRIT("empty reply on picked branch\n");
		goto error;
	}
	if (rpl==FAKED_REPLY)
	{
		LM_ERR("cannot process a FAKED reply\n");
		goto error;
	}

	if (code==WWW_AUTH_CODE) {
		if (0 == parse_www_authenticate_header(rpl))
			auth = get_www_authenticate(rpl);
	} else if (code==PROXY_AUTH_CODE) {
		if (0 == parse_proxy_authenticate_header(rpl))
			auth = get_proxy_authenticate(rpl);
	}

	if (auth == NULL) {
		LM_ERR("Unable to extract authentication info\n");
		goto error;
	}

	/* can we authenticate this realm? */
	/* look into existing credentials */
	crd = uac_auth_api._lookup_realm( &auth->realm );
	/* found? */
	if (crd==0)
	{
		LM_DBG("no credential for realm \"%.*s\"\n",
			auth->realm.len, auth->realm.s);
		goto error;
	}

	/* do authentication */
	uac_auth_api._do_uac_auth( &msg->first_line.u.request.method,
			&t->uac[branch].uri, crd, auth, &auth_nc_cnonce, response);

	/* build the authorization header */
	new_hdr = uac_auth_api._build_authorization_hdr( code, &t->uac[branch].uri,
		crd, auth, &auth_nc_cnonce, response);
	if (new_hdr==0)
	{
		LM_ERR("failed to build authorization hdr\n");
		goto error;
	}

	/* so far, so good -> add the header and set the proper RURI */
	if ( apply_urihdr_changes( msg, &t->uac[branch].uri, new_hdr)<0 )
	{
		LM_ERR("failed to apply changes\n");
		pkg_free(new_hdr->s);
		new_hdr->s = NULL; new_hdr->len = 0;
		goto error;
	}
	/* the Authorization hdr was already pushed into the message as a lump
	 * along with the buffer, so detach the buffer from new_hdr var */
	new_hdr->s = NULL; new_hdr->len = 0;

	new_hdr->s = NULL; new_hdr->len = 0;
	return 0;
error:
	return -1;
}

