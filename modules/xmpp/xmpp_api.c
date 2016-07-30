/*
 * XMPP Module
 * This file is part of opensips, a free SIP server.
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *
 */


#include <stdlib.h>
#include <string.h>

#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/shm_mem.h"
#include "xmpp_api.h"
#include "xmpp.h"

xmpp_cb_list_t *_xmpp_cb_list = 0;


int init_xmpp_cb_list(void)
{
	_xmpp_cb_list = (xmpp_cb_list_t*)shm_malloc(sizeof(xmpp_cb_list_t));
	if (_xmpp_cb_list==0) {
		LM_CRIT("no more shared memory\n");
		return -1;
	}
	memset(_xmpp_cb_list, 0, sizeof(xmpp_cb_list_t));
	return 0;
}


void destroy_xmpp_cb_list(void)
{
	xmpp_callback_t *it, *it1;

	if (_xmpp_cb_list==0)
		return;

	for(it=_xmpp_cb_list->first; it; ) {
		it1 = it;
		it = it->next;
		shm_free(it1);
	}

	shm_free(_xmpp_cb_list);
	_xmpp_cb_list = 0;
}



/* register a callback function 'f' for 'types' mask of events;
*/
int register_xmpp_cb( int types, xmpp_cb_f f, void *param )
{
	xmpp_callback_t *it;

	if(_xmpp_cb_list==0)
	{
		LM_CRIT("null callback list\n");
		return E_BUG;
	}

	/* check null functions */
	if (f==0) {
		LM_CRIT("null callback function\n");
		return E_BUG;
	}

	/* build callback structure */
	if (!(it=(xmpp_callback_t*)shm_malloc(sizeof(xmpp_callback_t))))
	{
		LM_ERR("no more share memory\n");
		return E_OUT_OF_MEM;
	}

	memset(it, 0, sizeof(xmpp_callback_t));
	it->next = _xmpp_cb_list->first;
	_xmpp_cb_list->first = it;
	_xmpp_cb_list->types |= types;

	it->cbf = f;
	it->cbp = param;
	it->types = types;

	return 1;
}


int bind_xmpp(xmpp_api_t* api)
{
	if (api==NULL)
	{
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	api->register_callback = register_xmpp_cb;
	api->uri_xmpp2sip= uri_xmpp2sip;
	api->uri_sip2xmpp= uri_sip2xmpp;
	api->xpacket    = xmpp_send_xpacket;
	api->xmessage   = xmpp_send_xmessage;
	api->xsubscribe = xmpp_send_xsubscribe;
	api->xnotify    = xmpp_send_xnotify;

	return 0;
}

