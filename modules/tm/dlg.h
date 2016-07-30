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
 *
 * History:
 * -------
 * 2003-03-29 Created by janakj
 * 2008-04-04 added support for local and remote dispaly name in TM dialogs
 *            (by Andrei Pisau <andrei.pisau at voice-system dot ro> )
 */

#ifndef DLG_H
#define DLG_H


#include <stdio.h>
#include "../../str.h"
#include "../../parser/parse_rr.h"
#include "../../parser/msg_parser.h"


/*
 * Dialog sequence
 */
typedef struct dlg_seq {
	unsigned int value;    /* Sequence value */
	unsigned char is_set;  /* is_set flag */
} dlg_seq_t;


/*
 * Dialog state
 */
typedef enum dlg_state {
	DLG_NEW = 0,   /* New dialog, no reply received yet */
	DLG_EARLY,     /* Early dialog, provisional response received */
	DLG_CONFIRMED, /* Confirmed dialog, 2xx received */
	DLG_DESTROYED  /* Destroyed dialog */
} dlg_state_t;


/*
 * Structure describing a dialog identifier
 */
typedef struct dlg_id {
	str call_id;    /* Call-ID */
	str rem_tag;    /* Remote tag of the dialog */
	str loc_tag;    /* Local tag of the dialog */
} dlg_id_t;


/*
 * It is necessary to analyze the dialog data to find out
 * what URI put into the Record-Route, where the message
 * should be really sent and how to construct the route
 * set of the message. This structure stores this information
 * so we don't have to calculate each time we want to send a
 * message within dialog
 */
typedef struct dlg_hooks {
	str ru;
	str nh;
	str* request_uri;   /* This should be put into Request-URI */
	str* next_hop;      /* Where the message should be really sent */
	rr_t* first_route;  /* First route to be printed into the message */
	str* last_route;    /* If not zero add this as the last route */
} dlg_hooks_t;


/*
 * Structure representing dialog state
 */
typedef struct dlg {
	dlg_id_t id;            /* Dialog identifier */
	dlg_seq_t loc_seq;      /* Local sequence number */
	dlg_seq_t rem_seq;      /* Remote sequence number */
	str loc_uri;            /* Local URI */
	str rem_uri;            /* Remote URI */
	str obp;                /* Outbound proxy */
	union sockaddr_union forced_to_su;	/* Forced remote sockaddr */
	str rem_target;         /* Remote target URI */
	str loc_dname;			/* Local Display Name */
	str rem_dname;			/* Remote Display Name */
	unsigned int T_flags;   /* Flags to be passed to transaction */
	dlg_state_t state;      /* State of the dialog */
	rr_t* route_set;        /* Route set */
	dlg_hooks_t hooks;      /* Various hooks used to store information that
				 * can be reused when building a message (to
				 * prevent repeated analyzing of the dialog data
				 */
	struct socket_info* send_sock;
	void *dialog_ctx;       /* backpointer to dialog ctx */
	struct usr_avp *avps;
} dlg_t;


/*
 * Create a new dialog
 */
int new_dlg_uac(str* _cid, str* _ltag, unsigned int _lseq, str* _luri, str* _ruri, dlg_t** _d);
typedef int (*new_dlg_uac_f)(str* _cid, str* _ltag, unsigned int _lseq, str* _luri, str* _ruri, dlg_t** _d);

/*
 * Create a auto new dialog (callid, from tag and CSEQ are auto generated)
 */
int new_auto_dlg_uac( str* _luri, str* _ruri, struct socket_info* sock, dlg_t** _d);
typedef int (*new_auto_dlg_uac_f)(str* _luri, str* _ruri, struct socket_info *sock, dlg_t** _d);

/*
 * Function which adds Display Names to an existing dialog
 */
int dlg_add_extra(dlg_t* _d, str* _ldname, str* _rdname);
typedef int (*dlg_add_extra_f)(dlg_t* _d, str* _ldname, str* _rdname);

/*
 * A response arrived, update dialog
 */
int dlg_response_uac(dlg_t* _d, struct sip_msg* _m);
typedef int (*dlg_response_uac_f)(dlg_t* _d, struct sip_msg* _m);

/*
 * Establishing a new dialog, UAS side
 */
int new_dlg_uas(struct sip_msg* _req, int _code, /*str* _tag,*/ dlg_t** _d);
typedef int (*new_dlg_uas_f)(struct sip_msg* _req, int _code, dlg_t** _d);


/*
 * UAS side - update a dialog from a request
 */
int dlg_request_uas(dlg_t* _d, struct sip_msg* _m);
typedef int (*dlg_request_uas_f)(dlg_t* _d, struct sip_msg* _m);


/*
 * Destroy a dialog state
 */
void free_dlg(dlg_t* _d);
typedef void (*free_dlg_f)(dlg_t* _d);


/*
 * Print a dialog structure, just for debugging
 */
void print_dlg(FILE* out, dlg_t* _d);
typedef void (*print_dlg_f)(FILE* out, dlg_t* _d);


/*
 * Calculate length of the route set
 */
int calculate_routeset_length(dlg_t* _d);


/*
 *
 * Print the route set
 */
char* print_routeset(char* buf, dlg_t* _d);

/*
 * wrapper to calculate_hooks
 * added by dcm
 */
int w_calculate_hooks(dlg_t* _d);

#endif /* DLG_H */
