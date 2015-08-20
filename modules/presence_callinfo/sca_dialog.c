/*
 * Add "call-info" event to presence module
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * --------
 *  2010-07-13  added support for SCA Broadsoft with dialog module (bogdan)
 */


#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_call_info.h"
#include "../dialog/dlg_load.h"
#include "sca_dialog.h"
#include "add_events.h"


static struct dlg_binds dlgf;
static str calling_line_Dvar = {"PCI_calling_line",16};
static str called_line_Dvar =  {"PCI_called_line", 15};


int init_dialog_support(void)
{
	if (load_dlg_api(&dlgf)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}

	return 0;
}


static void sca_dialog_callback(struct dlg_cell *dlg, int type,
												struct dlg_cb_params *_params)
{
	str calling_line = {NULL,0};
	str called_line = {NULL,0};
	struct sca_line *line=NULL;
	int idx;
	int state;

	/* search the lines */
	if ( dlgf.fetch_dlg_value(dlg, &calling_line_Dvar, &calling_line, 1)==0 ||
	calling_line.s!=NULL) {
		LM_DBG("calling line <%.*s> found \n",calling_line.len,calling_line.s);
		/* search without auto create */
		line = get_sca_line( &calling_line, 0);
	} else if ( dlgf.fetch_dlg_value(dlg, &called_line_Dvar, &called_line, 1)==0 ||
	called_line.s!=NULL) {
		LM_DBG("called line <%.*s> found \n",called_line.len,called_line.s);
		/* search without auto create */
		line = get_sca_line( &called_line, 0);
	}

	if (line==NULL) {
		LM_ERR("could not found the line in dialog callback :( \n");
		return;
	}

	/* careful now, the line is LOCKED !! */

	/* get the index and the new state */
	idx = (int)(long)(*(_params->param));
	switch (type) {
		case DLGCB_FAILED:
		case DLGCB_TERMINATED:
		case DLGCB_EXPIRED:
			state = SCA_STATE_IDLE;
			break;
		case DLGCB_EARLY:
			state = calling_line.len?SCA_STATE_PROGRESSING:SCA_STATE_ALERTING;
			break;
		case DLGCB_CONFIRMED:
			state = SCA_STATE_ACTIVE;
			break;
		default:
			LM_CRIT("BUG: unsupported callback type %d \n",type);
			unlock_sca_line(line);
			return;
	}

	/* everything ok, change the state of the line and notify */
	set_sca_index_state( line, idx, state);

	do_callinfo_publish( line );
	/* now the line is unlocked */

	return;
}


int sca_set_line(struct sip_msg *msg, str *line_s, int calling)
{
	struct dlg_cell *dlg;
	unsigned int idx;
	struct sca_line *line;

	/* extract the index from the call-info line */
	if ( parse_call_info_header( msg )!=0 ) {
		LM_ERR("missing or bogus Call-Info header in INVITE\n");
		return -1;
	}
	idx = get_appearance_index(msg);
	if (idx==0) {
		LM_ERR("failed to extract line index from Call-Info hdr\n");
		return -1;
	}

	LM_DBG("looking for line  <%.*s>, idx %d, calling %d \n",
		line_s->len, line_s->s, idx, calling);

	/* search for the line (with no creation) */
	line = get_sca_line( line_s, 0);
	if (line==NULL) {
		LM_ERR("used line <%.*s> not found in hash. Using without seizing?\n",
			line_s->len, line_s->s);
		return -1;
	}
	/* NOTE: the line is now locked !!!!! */

	/* check if the index is seized */
	if (calling) {
		if (line->seize_state!=idx) {
			LM_ERR("line not seized or seized for other index "
				"(idx=%d,seize=%d)\n",idx,line->seize_state);
			goto error;
		}
	}

	/* create and bind to the dialog */
	if (dlgf.create_dlg(msg,0)< 0) {
		LM_ERR("failed to create dialog\n");
		goto error;
	}

	dlg = dlgf.get_dlg();

	LM_DBG("INVITE dialog created: using line <%.*s>\n",
		line_s->len, line_s->s);

	/* store the line variable into dialog */
	if (calling) {
		if(dlgf.store_dlg_value(dlg, &calling_line_Dvar, line_s)< 0) {
			LM_ERR("Failed to store calling line\n");
			goto error;
		}
	} else {
		if(dlgf.store_dlg_value(dlg, &called_line_Dvar, line_s)< 0) {
			LM_ERR("Failed to store called line\n");
			goto error;
		}
	}

	/* register callbacks */
	if (dlgf.register_dlgcb( dlg,
	DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
	DLGCB_EARLY , sca_dialog_callback, (void*)(long)idx, 0) != 0) {
		LM_ERR("cannot register callbacks for dialog\n");
		goto error;
	}

	/* STILL LOCKED HERE !! */
	terminate_line_sieze(line);
	/* lock released by above function */

	return 1;
error:
	unlock_sca_line(line);
	return -1;
}
