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
#include "../sipmsgops/sdp_ops.h"
#include "sca_dialog.h"
#include "add_events.h"
#include "presence_callinfo.h"


struct dlg_binds dlgf;
struct tm_binds tmf;
str calling_line_Dvar = str_init("PCI_calling_line");
str called_line_Dvar =  str_init("PCI_called_line");
str sca_engaged_Dvar = str_init("PCI_engaged");
str sca_branch_Dvar = str_init("PCI_branch_idx");

void try_callinfo_publish(str *line_uri, int line_idx, int new_state, int create);

int init_module_apis(void)
{
	if (load_tm_api(&tmf) != 0) {
		LM_ERR("failed to find the tm API - is tm module loaded?\n");
		return -1;
	}

	if (load_dlg_api(&dlgf)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}

	return 0;
}


void sca_dialog_sendpublish(struct dlg_cell *dlg, int type,
												struct dlg_cb_params *_params)
{
	struct sca_cb_params *param;
	struct sip_msg *msg = _params->msg;
	int branch, idx = 0, val_type, new_state;
	int_str isval;
	str *entity, *peer;

	if (type == DLGCB_REQ_WITHIN && msg->REQ_METHOD == METHOD_ACK) {
		LM_SCA("skip mid-dialog ACK\n");
		return;
	}

	param = (struct sca_cb_params *)(*_params->param);
	if (!param) {
		LM_ERR("NULL dialog param in dlgcb type %d\n", type);
		return;
	}

	peer = &param->peer.uri;
	entity = &param->entity.uri;

	if (type <= DLGCB_CONFIRMED) {
	    /* this is triggered in the context of a reply, so its branch
	     * is available here */
	    branch = isval.n = tmf.get_branch_index();
	    if (dlgf.store_dlg_value(dlg, &sca_branch_Dvar, &isval,
	        DLG_VAL_TYPE_INT) < 0) {
	        LM_ERR("Failed to store winning branch in dialog\n");
	    }

	    LM_SCA("dlgcb %d, stored branch is %d\n", type, branch);
	} else {
	    if (dlgf.fetch_dlg_value(dlg, &sca_branch_Dvar, &val_type, &isval, 0) < 0
				|| val_type != DLG_VAL_TYPE_INT) {
	        LM_ERR("Failed to retrieve winning branch from dialog\n");
			return;
		}

	    branch = isval.n;
	    LM_SCA("dlgcb %d, retrieved branch is %d\n", type, branch);
	}

	/* best-effort search for ";appearance-index" in Call-INFO hdr */
	if (!msg || msg == FAKED_REPLY) {
		LM_SCA("null/fake SIP message provided, assuming index 1 (%p)\n", msg);
		idx = 1;
	} else {
		struct sip_msg pkg_msg;

		memset(&pkg_msg, 0, sizeof pkg_msg);
		parse_msg(msg->buf, msg->len, &pkg_msg);

		if (parse_call_info_header(&pkg_msg) != 0) {
			LM_SCA("message has no Call-Info hf, assuming index 1\n");
			idx = 1;
		} else {
			idx = get_appearance_index(msg);
			if (idx == 0) {
				LM_SCA("message has Call-Info but index not found, assuming 1\n");
				idx = 1;
			}

			free_call_info(pkg_msg.call_info->parsed);
		}
	}

	/* get the index and the new state */
	switch (type) {
		case DLGCB_FAILED:
		case DLGCB_TERMINATED:
		case DLGCB_EXPIRED:
			new_state = SCA_STATE_IDLE;
			break;

		case DLGCB_EARLY:
			new_state = -1;
			break;

		case DLGCB_CONFIRMED:
			new_state = SCA_STATE_ACTIVE;
			break;

		case DLGCB_REQ_WITHIN:
			if (!msg || msg == FAKED_REPLY)
				return;

			new_state = is_audio_on_hold(msg) ? SCA_STATE_HELD : SCA_STATE_ACTIVE;
			break;

		default:
			LM_CRIT("BUG: unsupported callback type %d \n", type);
			return;
	}

	sca_sendpublish(dlg, branch, entity, peer, idx, new_state);
}


void sca_sendpublish(struct dlg_cell *dlg, int branch, str *entity, str *peer,
		int line_idx, int new_state)
{
	int_str sca_engaged, mute_val, isval;
	int val_type;
	str mute_var = STR_NULL, custom_peer = STR_NULL, name_u;

	sca_engaged.n = 0;
	mute_val.s = STR_NULL;
	isval.s = STR_NULL;

	LM_SCA("SCA publish attempt, branch %d, [%.*s] -> [%.*s], idx %d, new_state: %d\n",
			branch, entity->len, entity->s, peer->len, peer->s, line_idx, new_state);

	/* engage flags - caller vs. callees */
	if (dlgf.fetch_dlg_value(dlg, &sca_engaged_Dvar, &val_type,
		&sca_engaged, 0) < 0 || val_type != DLG_VAL_TYPE_INT) {
		LM_ERR("sca_engaged not found in dlg\n");
		return;
	}

	LM_SCA("SCA engage flags: %d (caller: %d/%d, callee: %d/%d)\n",
			sca_engaged.n, sca_engaged.n & SCA_PUB_A, SCA_PUB_A,
			sca_engaged.n & SCA_PUB_B, SCA_PUB_B);

	/* PUBLISH -- caller side */
	if (sca_engaged.n & SCA_PUB_A)
		try_callinfo_publish(entity, line_idx,
			new_state == -1 ? SCA_STATE_PROGRESSING : new_state, 0);
	else
		LM_SCA("skipping call-info for caller (new_state %d)\n", new_state);

	/* PUBLISH -- callee(s) side */
	if (!(sca_engaged.n & SCA_PUB_B)) {
		LM_SCA("skipping call-info for callee (new_state %d)\n", new_state);
		return;
	}

	/* try to see if there are any muting settings per branch */
	build_branch_mute_var_name( branch, &mute_var );
	if (dlgf.fetch_dlg_value(dlg, &mute_var, &val_type, &mute_val, 1) == 0) {
		if (mute_val.s.len != 2) {/* we expect a new letters string */
			pkg_free(mute_val.s.s);
			mute_val.s = STR_NULL;
		} else {
			LM_DBG("per-branch mute information was found as [%.*s]\n",
				mute_val.s.len, mute_val.s.s);
		}
	}

	if (!should_publish_B(sca_engaged.n, mute_val.s)) {
		LM_SCA("skipping call-info for callee on branch %d (muted, new_state %d)\n",
				branch, new_state);
		goto out;
	}

	/* try to see if there is any custom callee per branch */
	build_branch_callee_var_names( branch, &name_u);
	if (dlgf.fetch_dlg_value(dlg, &name_u, &val_type, &isval, 1) == 0) {
		custom_peer = isval.s;
		isval.s = STR_NULL;
		LM_SCA("per-branch callee/peer information was found: '%.*s' -> '%.*s'\n",
				peer->len, peer->s, custom_peer.len, custom_peer.s);
		peer = &custom_peer;
	}

	try_callinfo_publish(peer, line_idx,
		new_state == -1 ? SCA_STATE_ALERTING : new_state, 0);

	/* change the state of the line and notify */
	//set_sca_index_state( line, line_idx, state);

	//do_callinfo_publish( line );
	/* now the line is unlocked */
out:
	pkg_free(mute_val.s.s);
	pkg_free(custom_peer.s);
}


void try_callinfo_publish(str *line_uri, int line_idx, int new_state, int create)
{
	struct sca_idx *scai;
	struct sca_line *line;
	int old_state = -1;

	LM_SCA("attempt to PUBLISH on line <%.*s>, idx %d, new state: %d\n",
	        line_uri->len, line_uri->s, line_idx, new_state);

	if (sca_bad_state(new_state)) {
		LM_ERR("bad new state: %d, refusing to publish\n", new_state);
		return;
	}

	line = get_sca_line(line_uri, create);
	if (!line) {
		LM_ERR("could not %s calling line '%.*s' in hash\n",
		        create ? "create" : "find", line_uri->len, line_uri->s);
		return;
	}

	/* line is LOCKED! */
	if (new_state == SCA_STATE_ALERTING && line_idx == 0) {
		LM_SCA("assuming appearance-index=1 on 'alerting' event\n");
		line_idx = 1;
	}

	scai = get_sca_index(line, line_idx);
	if (!scai) {
		unlock_sca_line(line);
		LM_ERR("failed to get/allocate line index\n");
		return;
	}
	old_state = scai->state;

	LM_SCA("line/idx found, old_state: %d\n", old_state);
	if (old_state == new_state)
		goto nop;

	switch (scai->state) {
	case SCA_STATE_NONE:
	case SCA_STATE_IDLE:
		break;

	case SCA_STATE_SEIZED:
		switch (new_state) {
		case SCA_STATE_IDLE:
		case SCA_STATE_PROGRESSING:
		case SCA_STATE_ACTIVE:
			break;
		default:
			goto bad_transition;
		}
		break;

	case SCA_STATE_PROGRESSING:
	case SCA_STATE_ALERTING:
		switch (new_state) {
		case SCA_STATE_IDLE:
		case SCA_STATE_ACTIVE:
			break;
		default:
			goto bad_transition;
		}
		break;

	case SCA_STATE_ACTIVE:
		switch (new_state) {
		case SCA_STATE_IDLE:
		case SCA_STATE_HELD:
			break;
		default:
			goto bad_transition;
		}
		break;

	case SCA_STATE_HELD:
		switch (new_state) {
		case SCA_STATE_IDLE:
		case SCA_STATE_ACTIVE:
			break;
		default:
			goto bad_transition;
		}
		break;

	default:
		unlock_sca_line(line);
		LM_ERR("invalid index state: %d\n", old_state);
		return;
	}

	LM_SCA("valid transition %d -> %d, publishing...\n", old_state, new_state);

	scai->state = new_state;
	do_callinfo_publish(line );
	/* un-LOCKED */
	return;

nop:
	unlock_sca_line(line);
	LM_SCA("NOP transition %d -> %d, quick-exit\n", old_state, new_state);
	return;

bad_transition:
	unlock_sca_line(line);
	LM_ERR("bad state transition: (%d -> %d), refusing to publish\n",
	        old_state, new_state);
}


void build_branch_mute_var_name( int branch, str *var_m)
{
	#define MUTE_PATTERN "__sca_br_MUTE_XXXX"
	#define br_mute_var_end_offset 4
	static char br_mute_var[] = MUTE_PATTERN;
	char *p;
	int s;

	p = br_mute_var + sizeof(MUTE_PATTERN)-1 - br_mute_var_end_offset;
	s = br_mute_var_end_offset;
	int2reverse_hex( &p, &s, (unsigned int)branch );
	var_m->s = br_mute_var;
	var_m->len = sizeof(MUTE_PATTERN)-1 - s;

	LM_SCA("callee-muted dlgv for branch #%d: '%.*s'\n",
	        branch, var_m->len, var_m->s);
}


void build_branch_callee_var_names( int branch, str *var_u)
{
	#define URI_PATTERN "__sca_br_CALLEEU_XXXX"
	#define br_callee_var_end_offset 4
	static char br_calleeU_var[] = URI_PATTERN;
	char *p;
	int s;

	p = br_calleeU_var + sizeof(URI_PATTERN)-1 - br_callee_var_end_offset;
	s = br_callee_var_end_offset;
	int2reverse_hex( &p, &s, (unsigned int)branch );
	var_u->s = br_calleeU_var;
	var_u->len = sizeof(URI_PATTERN)-1 - s;

	LM_SCA("callee-uri dlgv for branch #%d: '%.*s'\n",
			branch, var_u->len, var_u->s);
}
