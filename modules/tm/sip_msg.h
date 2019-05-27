/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */



#ifndef _SIP_MSG_H
#define _SIP_MSG_H

#include "../../parser/msg_parser.h"
#include "../../mem/shm_mem.h"

#define free_cloned_msg_unsafe( _msg ) \
	do { \
		if ((_msg)->msg_flags & FL_SHM_UPDATABLE) { \
			if ((_msg)->new_uri.s) \
				shm_free_bulk((_msg)->new_uri.s);\
			if ((_msg)->dst_uri.s) \
				shm_free_bulk((_msg)->dst_uri.s);\
			if ((_msg)->path_vec.s) \
				shm_free_bulk((_msg)->path_vec.s);\
			if ((_msg)->set_global_address.s) \
				shm_free_bulk((_msg)->set_global_address.s);\
			if ((_msg)->set_global_port.s) \
				shm_free_bulk((_msg)->set_global_port.s);\
			if ((_msg)->add_rm) \
				shm_free_bulk((_msg)->add_rm);\
			if ((_msg)->body_lumps) \
				shm_free_bulk((_msg)->body_lumps);\
			if ((_msg)->reply_lump) \
				shm_free_bulk((_msg)->reply_lump);\
		}\
		if ((_msg)->body) { \
			/* ungly hack to free the body parts which do not support
			 * unsafe-free */ \
			shm_unlock(); \
			free_sip_body((_msg)->body);\
			shm_lock(); \
		}\
		shm_free_bulk((_msg));\
	}while(0)


#define free_cloned_msg( _msg ) \
	do { \
		if ((_msg)->msg_flags & FL_SHM_UPDATABLE) { \
			if ((_msg)->new_uri.s) \
				shm_free((_msg)->new_uri.s);\
			if ((_msg)->dst_uri.s) \
				shm_free((_msg)->dst_uri.s);\
			if ((_msg)->path_vec.s) \
				shm_free((_msg)->path_vec.s);\
			if ((_msg)->set_global_address.s) \
				shm_free((_msg)->set_global_address.s);\
			if ((_msg)->set_global_port.s) \
				shm_free((_msg)->set_global_port.s);\
			if ((_msg)->add_rm) \
				shm_free((_msg)->add_rm);\
			if ((_msg)->body_lumps) \
				shm_free((_msg)->body_lumps);\
			if ((_msg)->reply_lump) \
				shm_free((_msg)->reply_lump);\
		}\
		free_sip_body((_msg)->body);\
		shm_free((_msg));\
	}while(0)


struct sip_msg*  sip_msg_cloner( struct sip_msg *org_msg, int *sip_msg_len,
		int updatable );


static inline void clean_msg_clone(struct sip_msg *msg,void *min, void *max)
{
	struct hdr_field *hdr;

	/* free header's parsed structures that were added in pkg mem */
	for( hdr=msg->headers ; hdr ; hdr=hdr->next ) {
		if ( hdr->parsed && hdr_allocs_parse(hdr) &&
		(hdr->parsed<min || hdr->parsed>=max)) {
			/* header parsed filed doesn't point inside uas.request memory
			 * chunk -> it was added by failure funcs.-> free it as pkg */
			LM_DBG("removing hdr->parsed %d\n",	hdr->type);
			clean_hdr_field(hdr);
			hdr->parsed = 0;
		}
	}
}


int update_cloned_msg_from_msg(struct sip_msg *c_msg, struct sip_msg *msg);


#endif
