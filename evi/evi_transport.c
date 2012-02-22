/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 *  2011-05-xx  created (razvancrainea)
 */

#include "event_interface.h"
#include "evi_transport.h"
#include "../mem/shm_mem.h"

/* list with the transport modules */
static evi_trans_t *evi_trans_mods = NULL;
static int evi_trans_mods_size = 0;

/* functions used by the transport modules */

int register_event_mod(evi_export_t *ev)
{
	evi_trans_t *trans_mod;

	if (!ev || !ev->proto.len || !ev->proto.s) {
		LM_ERR("no export or name specified\n");
		goto error;
	}

	if (!ev->raise) {
		LM_ERR("raise function should be specified for protocol %.*s\n",
				ev->proto.len, ev->proto.s);
		goto error;
	}

	if (!ev->parse) {
		LM_ERR("parse function should be specified for protocol %.*s\n",
				ev->proto.len, ev->proto.s);
		goto error;
	}

	if (ev->flags) {
		if (ev->flags & EVI_FREE_LIST) {
			LM_ERR("module cannot have the id %x\n", ev->flags);
			goto error;
		}

		/* check to see if there are two modules with the same id (or protocol) */
		for (trans_mod = evi_trans_mods; trans_mod; trans_mod = trans_mod->next){
			if (trans_mod->module->flags & ev->flags) {
				LM_ERR("duplicate flag %x\n", ev->flags);
				goto error;
			}
			if (ev->proto.len == trans_mod->module->proto.len && 
					!memcmp(ev->proto.s,trans_mod->module->proto.s,ev->proto.len)){
				LM_ERR("duplicate transport module protocol <%.*s>\n", 
						ev->proto.len, ev->proto.s);
				goto error;
			}
		}
	}
		
	trans_mod = shm_malloc(sizeof(evi_trans_t));
	if (!trans_mod) {
		LM_ERR("no more shm memory\n");
		goto error;
	}

	trans_mod->module = ev;
	trans_mod->next = evi_trans_mods;
	evi_trans_mods = trans_mod;

	evi_trans_mods_size++;

	return 0;
error:
	return EVI_ERROR;
}

/* checks if there are any modules loaded */
int get_trans_mod_no(void)
{
	return evi_trans_mods_size;
}

/* Returns the transport export */
evi_export_t* get_trans_mod(str* tran)
{
	str t;
	char *p;
	evi_trans_t *ev = evi_trans_mods;

	if (!tran || !tran->len || !tran->s)
		return NULL;

	t.s = tran->s;
	p = memchr(tran->s, TRANSPORT_SEP, tran->len);
	if (!p)
		t.len = tran->len;
	else
		t.len = p - tran->s;

	while (ev) {
		if (ev->module->proto.len == t.len &&
				!memcmp(ev->module->proto.s, t.s, t.len))
			return ev->module;
		ev = ev->next;
	}

	return NULL;
}
