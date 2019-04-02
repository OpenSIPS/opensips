/*
 * Copyright (C) 2006 SOMA Networks, Inc.
 * Written By Ron Winacott (karwin)
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 *
 * History:
 * --------
 * 2006-05-11 initial version (karwin)
 * 2006-10-10 Code cleanup of this header file. (karwin)
 */

#ifndef _SST_HANDLERS_H_
#define _SST_HANDLERS_H_

#include "../../pvar.h"
#include "../../parser/msg_parser.h"
#include "../dialog/dlg_load.h"


/**
 * Fag values used in the sst_info_t See below.
 */
enum sst_flags {
	SST_UNDF=0,             /* 0 - --- */
	SST_UAC=1,              /* 1 - 2^0 */
	SST_UAS=2,              /* 2 - 2^1 */
	SST_PXY=4,              /* 4 - 2^2 */
	SST_NSUP=8              /* 8 - 2^3 */
};

/**
 * The local state required to figure out if and who supports SST and
 * if and who will be the refresher.
 */
typedef struct sst_info_st {
	enum sst_flags requester;
	enum sst_flags supported;
	unsigned int interval;
	volatile unsigned int refcnt;
} sst_info_t;


/**
 * The static (opening) callback function for all dialog creations
 */
void sst_dialog_created_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params * params);

void sst_dialog_loaded_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params *params);

/**
 * The script function
 */
int sst_check_min(struct sip_msg *msg, int *flag);

/**
 * The handlers initializer function
 */
void sst_handler_init(unsigned int minSE, int flag, unsigned int reject,
                      unsigned int interval);

#endif /* _SST_HANDLERS_H_ */
