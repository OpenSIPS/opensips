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
 * ----------
 * 2003-02-28 protocolization of t_uac_dlg completed (jiri)
 */

#ifndef _UAC_H
#define _UAC_H

#include <stdio.h>
#include "../../str.h"
#include "dlg.h"
#include "t_hooks.h"

#define DEFAULT_CSEQ 10 /* Default CSeq number */

/* Pass provisional replies to fifo applications */
extern int pass_provisional_replies;


/*
 * Function prototypes
 */
typedef int (*reqwith_t)(str* m, str* h, str* b, dlg_t* d,
		transaction_cb c, void* cp, release_tmcb_param release_func);
typedef int (*reqout_t)(str* m, str* t, str* f, str* h, str* b, dlg_t** d,
		transaction_cb c, void* cp, release_tmcb_param release_func);
typedef int (*req_t)(str* m, str* ru, str* t, str* f, str* h, str* b, str *obu,
		transaction_cb c, void* cp,release_tmcb_param release_func);

typedef void (*set_localT_holder_f)(struct cell**);

/*
 * Generate a fromtag based on given Call-ID
 */
void generate_fromtag(str* tag, str* callid);


/*
 * Initialization function
 */
int uac_init(void);


/*
 * Send a request
 */
int t_uac(str* method, str* headers, str* body, dlg_t* dialog,
		transaction_cb cb, void* cbp, release_tmcb_param release_func);


/*
 * Send a message within a dialog
 */
int req_within(str* m, str* h, str* b, dlg_t* d,
		transaction_cb c, void* cp, release_tmcb_param release_func);


/*
 * Send an initial request that will start a dialog
 */
int req_outside(str* m, str* t, str* f, str* h, str* b, dlg_t** d,
	transaction_cb c, void* cp, release_tmcb_param release_func);


/*
 * Send a transactional request, no dialogs involved
 */
int request(str* m, str* ruri, str* to, str* from, str* h, str* b, str *oburi,
		transaction_cb c, void* cp, release_tmcb_param release_func);

/*
 * Set a struct cell holder to get the last local transaction pointer
 * */
void setlocalTholder(struct cell** holder);

#endif
