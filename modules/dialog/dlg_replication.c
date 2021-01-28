/*
 * Copyright (C) 2013-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "dlg_hash.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"

#include "dlg_replication.h"
#include "dlg_repl_profile.h"

#include "../../resolve.h"
#include "../../forward.h"
#include "../../pt.h"

extern int active_dlgs_cnt;
extern int early_dlgs_cnt;

extern stat_var *processed_dlgs;

extern stat_var *create_sent;
extern stat_var *update_sent;
extern stat_var *delete_sent;
extern stat_var *create_recv;
extern stat_var *update_recv;
extern stat_var *delete_recv;

struct clusterer_binds clusterer_api;

str shtag_dlg_val = str_init("dlgX_shtag");

static struct socket_info * fetch_socket_info(str *addr)
{
	struct socket_info *sock;
	int port, proto;
	str host;

	if (!addr->s || addr->s[0] == 0)
		return NULL;

	if (parse_phostport(addr->s, addr->len, &host.s, &host.len,
		&port, &proto) != 0) {
		LM_ERR("bad socket <%.*s>\n", addr->len, addr->s);
		return NULL;
	}

	sock = grep_internal_sock_info(&host, (unsigned short) port,
		(unsigned short) proto);
	if (!sock) {
		LM_WARN("non-local socket <%.*s>...ignoring\n", addr->len, addr->s);
	}

	return sock;
}

#define DLG_BIN_POP(_type, _p, _field, _label) \
	do { \
		if (bin_pop_ ## _type(_p, (str *)&_field) != 0) { \
			LM_WARN("cannot find %s field in bin packet!\n", #_field); \
			goto _label; \
		} \
	} while (0)

#define DLG_BIN_POP_ROUTE(_packet, _dlg, _type, _pre_linking_error) \
do { \
	str __s; \
	DLG_BIN_POP(str, _packet, __s, _pre_linking_error);\
	if (__s.len) {\
		_dlg->rt_ ## _type = get_script_route_ID_by_name_str( &__s, \
			sroutes->request, RT_NO); \
		if (_dlg->rt_ ## _type==-1) { \
			LM_WARN("replicated <%.*s>  ## _type route not found " \
				"in the script\n", __s.len, __s.s); \
			_dlg->rt_ ## _type = 0; \
		} \
	} else \
		_dlg->rt_ ## _type = 0; \
} while(0)

/*  Binary Packet receiving functions   */

/**
 * replicates a confirmed dialog from another OpenSIPS instance
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_create(bin_packet_t *packet, struct dlg_cell *cell,
												str *ftag, str *ttag, int safe)
{
	int h_entry, rc;
	str callid = { NULL, 0 }, from_uri, to_uri, from_tag, to_tag;
	str cseq1, cseq2, contact1, contact2, adv_ct1, adv_ct2;
	str rroute1, rroute2, mangled_fu, mangled_tu;
	str sdp1, sdp2, sdp3, sdp4;
	str sock, vars, profiles;
	struct dlg_cell *dlg = NULL;
	struct socket_info *caller_sock, *callee_sock;
	struct dlg_entry *d_entry;
	str tag_name;

	LM_DBG("Received replicated dialog!\n");
	if (!cell) {
		DLG_BIN_POP(str, packet, callid, malformed);
		DLG_BIN_POP(str, packet, from_tag, malformed);
		DLG_BIN_POP(str, packet, to_tag, malformed);
		DLG_BIN_POP(str, packet, from_uri, malformed);
		DLG_BIN_POP(str, packet, to_uri, malformed);

		h_entry = dlg_hash(&callid);
		d_entry = &d_table->entries[h_entry];

		if (safe)
			dlg_lock(d_table, d_entry);

		if (get_dlg_unsafe(d_entry, &callid, &from_tag, &to_tag, &dlg) == 0) {
			LM_DBG("Dialog with ci '%.*s' is already created\n",
			       callid.len, callid.s);
			/* unmark dlg as loaded from DB (otherwise it would have been
			 * dropped later when syncing from cluster is done) */
			dlg->flags &= ~DLG_FLAG_FROM_DB;
			dlg_unlock(d_table, d_entry);
			return 0;
		}

		dlg = build_new_dlg(&callid, &from_uri, &to_uri, &from_tag);
		if (!dlg) {
			LM_ERR("Failed to create replicated dialog!\n");
			goto pre_linking_error;
		}
	} else {
		h_entry = dlg_hash(&cell->callid);
		d_entry = &d_table->entries[h_entry];

		if (safe)
			dlg_lock(d_table, d_entry);

		from_tag = *ftag;
		to_tag = *ttag;
		dlg = cell;
	}
	if_update_stat(dlg_enable_stats, processed_dlgs, 1);

	DLG_BIN_POP(int, packet, dlg->h_id, pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->start_ts, pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->state, pre_linking_error);

	/* next_id follows the max value of all replicated ids */
	if (d_table->entries[dlg->h_entry].next_id <= dlg->h_id)
		d_table->entries[dlg->h_entry].next_id = dlg->h_id + 1;

	DLG_BIN_POP(str, packet, sock, pre_linking_error);

	caller_sock = fetch_socket_info(&sock);
	if (!caller_sock) {
		LM_ERR("Replicated dialog doesn't match caller's listening socket %.*s\n",
				sock.len, sock.s);
		goto pre_linking_error;
	}

	DLG_BIN_POP(str, packet, sock, pre_linking_error);

	callee_sock = fetch_socket_info(&sock);
	if (!callee_sock) {
		LM_ERR("Replicated dialog doesn't match callee's listening socket %.*s\n",
				sock.len, sock.s);
		goto pre_linking_error;
	}

	DLG_BIN_POP(str, packet, cseq1, pre_linking_error);
	DLG_BIN_POP(str, packet, cseq2, pre_linking_error);
	DLG_BIN_POP(str, packet, rroute1, pre_linking_error);
	DLG_BIN_POP(str, packet, rroute2, pre_linking_error);
	DLG_BIN_POP(str, packet, contact1, pre_linking_error);
	DLG_BIN_POP(str, packet, contact2, pre_linking_error);
	DLG_BIN_POP(str, packet, mangled_fu, pre_linking_error);
	DLG_BIN_POP(str, packet, mangled_tu, pre_linking_error);
	DLG_BIN_POP(str, packet, sdp1, pre_linking_error);
	DLG_BIN_POP(str, packet, sdp2, pre_linking_error);
	DLG_BIN_POP(str, packet, sdp3, pre_linking_error);
	DLG_BIN_POP(str, packet, sdp4, pre_linking_error);
	DLG_BIN_POP(str, packet, adv_ct1, pre_linking_error);
	DLG_BIN_POP(str, packet, adv_ct2, pre_linking_error);

	/* add the 2 legs */
	if (dlg_update_leg_info(0, dlg, &from_tag, &rroute1, &contact1, &adv_ct1,
		&cseq1, caller_sock, 0, 0, &sdp1, &sdp2) != 0 ||
		dlg_update_leg_info(1, dlg, &to_tag, &rroute2, &contact2, &adv_ct2,
		&cseq2, callee_sock, &mangled_fu, &mangled_tu, &sdp3, &sdp4) != 0) {
		LM_ERR("dlg_set_leg_info failed\n");
		goto pre_linking_error;
	}

	dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

	/* link the dialog into the hash */
	_link_dlg_unsafe(d_entry, dlg);

	DLG_BIN_POP(str, packet, vars, pre_linking_error);
	DLG_BIN_POP(str, packet, profiles, pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->user_flags, pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->mod_flags, pre_linking_error);

	DLG_BIN_POP(int, packet, dlg->flags, pre_linking_error);
	/* also save the dialog into the DB on this instance */
	dlg->flags |= DLG_FLAG_NEW;

	DLG_BIN_POP(int, packet, dlg->tl.timeout, pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->legs[DLG_CALLER_LEG].last_gen_cseq,
		pre_linking_error);
	DLG_BIN_POP(int, packet, dlg->legs[callee_idx(dlg)].last_gen_cseq,
		pre_linking_error);

	DLG_BIN_POP_ROUTE( packet, dlg, on_answer, pre_linking_error);
	DLG_BIN_POP_ROUTE( packet, dlg, on_timeout, pre_linking_error);
	DLG_BIN_POP_ROUTE( packet, dlg, on_hangup, pre_linking_error);

	if (dlg->tl.timeout <= (unsigned int) time(0))
		dlg->tl.timeout = 0;
	else
		dlg->tl.timeout -= (unsigned int) time(0);

	/* restore the timer values */
	if (insert_dlg_timer(&dlg->tl, (int) dlg->tl.timeout) != 0) {
		LM_CRIT("Unable to insert dlg %p [%u:%u] "
			"with clid '%.*s' and tags '%.*s' '%.*s'\n",
			dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg->legs[DLG_CALLER_LEG].tag.len,
			dlg->legs[DLG_CALLER_LEG].tag.s,
			dlg->legs[callee_idx(dlg)].tag.len,
			ZSW(dlg->legs[callee_idx(dlg)].tag.s));
		goto error;
	}

	/* timer list + this ref */
	ref_dlg_unsafe(dlg, 2);

	LM_DBG("Received initial timeout of %d for dialog %.*s, safe = %d\n",
		dlg->tl.timeout, callid.len, callid.s, safe);

	dlg->lifetime = 0;

	if (vars.s && vars.len != 0) {
		read_dialog_vars(vars.s, vars.len, dlg);
		run_dlg_callbacks(DLGCB_PROCESS_VARS, dlg,
				NULL, DLG_DIR_NONE, NULL, 1, 0);
	}

	dlg->locked_by = process_no;

	if ((rc = fetch_dlg_value(dlg, &shtag_dlg_val, &tag_name, 0)) == 0) {
		if (shm_str_dup(&dlg->shtag, &tag_name) < 0)
			LM_ERR("No more shm memory\n");
	} else if (rc == -1)
		LM_ERR("Failed to get dlg value for sharing tag\n");

	dlg->locked_by = 0;

	if (dlg_db_mode == DB_MODE_DELAYED) {
		/* to be later removed by timer */
		ref_dlg_unsafe(dlg, 1);
	}

	/* avoid AB/BA deadlock with pinging routines */
	dlg_unlock(d_table, d_entry);

	if (dlg->flags & DLG_FLAG_PING_CALLER || dlg->flags & DLG_FLAG_PING_CALLEE) {
		if (insert_ping_timer(dlg) != 0)
			LM_CRIT("Unable to insert dlg %p into ping timer\n",dlg);
		else {
			ref_dlg(dlg, 1);
		}
	}

	if (dlg_has_reinvite_pinging(dlg)) {
		if (insert_reinvite_ping_timer(dlg) != 0) {
			LM_CRIT("Unable to insert dlg %p into reinvite ping timer\n",dlg);
		} else {
			ref_dlg(dlg, 1);
		}
	}

	if (profiles.s && profiles.len != 0)
		read_dialog_profiles(profiles.s, profiles.len, dlg, 0, 1);

	if_update_stat(dlg_enable_stats, active_dlgs, 1);

	run_load_callback_per_dlg(dlg);

	unref_dlg(dlg, 1);
	return 0;

pre_linking_error:
	dlg_unlock(d_table, d_entry);
	if (dlg)
		destroy_dlg(dlg);
	return -1;

error:
	dlg_unlock(d_table, d_entry);
	if (dlg)
		unref_dlg(dlg, 1);

malformed:
	return -1;
}

/**
 * replicates the remote update of an ongoing dialog locally
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_update(bin_packet_t *packet)
{
	struct dlg_cell *dlg;
	str call_id, from_tag, to_tag, from_uri, to_uri, vars, profiles;
	int timeout, h_entry;
	str st;
	struct dlg_entry *d_entry;
	int rcv_flags, save_new_flag;

	bin_pop_str(packet, &call_id);
	bin_pop_str(packet, &from_tag);
	bin_pop_str(packet, &to_tag);
	bin_pop_str(packet, &from_uri);
	bin_pop_str(packet, &to_uri);

	LM_DBG("replicated update for ['%.*s' '%.*s' '%.*s' '%.*s' '%.*s']\n",
		call_id.len, call_id.s, from_tag.len, from_tag.s, to_tag.len, to_tag.s,
		from_uri.len, from_uri.s, to_uri.len, to_uri.s);

	h_entry = dlg_hash(&call_id);
	d_entry = &d_table->entries[h_entry];

	dlg_lock(d_table, d_entry);

	if (get_dlg_unsafe(d_entry, &call_id, &from_tag, &to_tag, &dlg) != 0) {
		LM_DBG("dialog not found, building new\n");

		dlg = build_new_dlg(&call_id, &from_uri, &to_uri, &from_tag);
		if (!dlg) {
			LM_ERR("Failed to create replicated dialog!\n");
			goto error;
		}

		return dlg_replicated_create(packet ,dlg, &from_tag, &to_tag, 0);
	}

	/* discard an update for a deleted dialog */
	if (dlg->state == DLG_STATE_DELETED) {
		dlg_unlock(d_table, d_entry);
		return 0;
	}

	bin_skip_int(packet, 2);
	bin_pop_int(packet, &dlg->state);

	/* sockets */
	bin_skip_str(packet, 2);

	bin_pop_str(packet, &st);
	if (dlg_update_cseq(dlg, DLG_CALLER_LEG, &st, 0) != 0) {
		LM_ERR("failed to update caller cseq\n");
		goto error;
	}

	bin_pop_str(packet, &st);
	if (dlg_update_cseq(dlg, callee_idx(dlg), &st, 0) != 0) {
		LM_ERR("failed to update callee cseq\n");
		goto error;
	}

	/* route set */
	bin_skip_str(packet, 2);

	/* sync caller and callee contact */
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[DLG_CALLER_LEG].contact, &st);
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[callee_idx(dlg)].contact, &st);

	/* from & to URIs set */
	bin_skip_str(packet, 2);

	/* sync SDPs */
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[DLG_CALLER_LEG].in_sdp, &st);
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[DLG_CALLER_LEG].out_sdp, &st);
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[callee_idx(dlg)].in_sdp, &st);
	bin_pop_str(packet, &st);
	shm_str_sync(&dlg->legs[callee_idx(dlg)].out_sdp, &st);

	/*
	 * advertised caller and callee contacts
	 * we shall skip these, as we're currently not re-learning sockets either,
	 * so we can't figure out the advertised contact to be used by this
	 * instance, in case it is different than the other one
	 */
	bin_skip_str(packet, 2);

	bin_pop_str(packet, &vars);
	bin_pop_str(packet, &profiles);
	bin_pop_int(packet, &dlg->user_flags);
	bin_pop_int(packet, &dlg->mod_flags);

	bin_pop_int(packet, &rcv_flags);
	/* make sure an update received immediately after a create can't
	 * incorrectly erase the DLG_FLAG_NEW before locally writing to DB */
	save_new_flag = dlg->flags & DLG_FLAG_NEW;
	dlg->flags = rcv_flags;
	dlg->flags |= ((save_new_flag ? DLG_FLAG_NEW : 0) | DLG_FLAG_CHANGED);

	bin_pop_int(packet, &timeout);
	bin_skip_int(packet, 2);
	DLG_BIN_POP_ROUTE( packet, dlg, on_answer, error);
	DLG_BIN_POP_ROUTE( packet, dlg, on_timeout, error);
	DLG_BIN_POP_ROUTE( packet, dlg, on_hangup, error);

	timeout -= time(0);
	LM_DBG("Received updated timeout of %d for dialog %.*s\n",
		timeout, call_id.len, call_id.s);

	if (dlg->lifetime != timeout) {
		dlg->lifetime = timeout;
		switch (update_dlg_timer(&dlg->tl, dlg->lifetime) ) {
		case -1:
			LM_ERR("failed to update dialog lifetime!\n");
			/* continue */
		case 0:
			/* timeout value was updated */
			break;
		case 1:
			/* dlg inserted in timer list with new expire (reference it)*/
			ref_dlg_unsafe(dlg,1);
		}
	}

	if (vars.s && vars.len != 0) {
		read_dialog_vars(vars.s, vars.len, dlg);
		run_dlg_callbacks(DLGCB_PROCESS_VARS, dlg,
				NULL, DLG_DIR_NONE, NULL, 1, 0);
	}

	dlg->flags |= DLG_FLAG_VP_CHANGED;

	ref_dlg_unsafe(dlg, 1);
	dlg_unlock(d_table, d_entry);

	if (profiles.s && profiles.len != 0)
		read_dialog_profiles(profiles.s, profiles.len, dlg, 1, 1);

	unref_dlg(dlg, 1);
	return 0;

error:
	dlg_unlock(d_table, d_entry);
	return -1;
}

/**
 * replicates the remote deletion of a dialog locally
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_delete(bin_packet_t *packet)
{
	str call_id, from_tag, to_tag;
	unsigned int dir, dst_leg;
	struct dlg_cell *dlg;
	int old_state, new_state, unref, ret;

	DLG_BIN_POP(str, packet, call_id, malformed);
	DLG_BIN_POP(str, packet, from_tag, malformed);
	DLG_BIN_POP(str, packet, to_tag, malformed);

	LM_DBG("Deleting dialog with callid: %.*s\n", call_id.len, call_id.s);

	dlg = get_dlg(&call_id, &from_tag, &to_tag, &dir, &dst_leg);
	if (!dlg) {
		/* may be already deleted due to timeout */
		LM_DBG("dialog not found (callid: |%.*s| ftag: |%.*s|\n",
			call_id.len, call_id.s, from_tag.len, from_tag.s);
		return 0;
	}

	destroy_linkers(dlg);
	remove_dlg_prof_table(dlg, 0);

	/* simulate BYE received from caller */
	next_state_dlg(dlg, DLG_EVENT_REQBYE, DLG_DIR_DOWNSTREAM, &old_state,
		&new_state, &unref, dlg->legs_no[DLG_LEG_200OK], 0);

	if (old_state == new_state) {
		LM_ERR("duplicate dialog delete request (callid: |%.*s|"
			"ftag: |%.*s|\n", call_id.len, call_id.s, from_tag.len, from_tag.s);
		return -1;
	}

	ret = remove_dlg_timer(&dlg->tl);
	if (ret < 0) {
		LM_CRIT("unable to unlink the timer on dlg %p [%u:%u] "
			"with clid '%.*s' and tags '%.*s' '%.*s'\n",
			dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg->legs[DLG_CALLER_LEG].tag.len,
			dlg->legs[DLG_CALLER_LEG].tag.s,
			dlg->legs[callee_idx(dlg)].tag.len,
			ZSW(dlg->legs[callee_idx(dlg)].tag.s));
	} else if (ret > 0) {
		LM_DBG("dlg expired (not in timer list) on dlg %p [%u:%u] "
			"with clid '%.*s' and tags '%.*s' '%.*s'\n",
			dlg, dlg->h_entry, dlg->h_id,
			dlg->callid.len, dlg->callid.s,
			dlg->legs[DLG_CALLER_LEG].tag.len,
			dlg->legs[DLG_CALLER_LEG].tag.s,
			dlg->legs[callee_idx(dlg)].tag.len,
			ZSW(dlg->legs[callee_idx(dlg)].tag.s));
	} else {
		/* dialog successfully removed from timer -> unref */
		unref++;
	}

	unref_dlg(dlg, 1 + unref);
	if_update_stat(dlg_enable_stats, active_dlgs, -1);

	return 0;
malformed:
	return -1;
}


/**
 * replicates the remote update of a cseq of a dialog locally
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_cseq_updated(bin_packet_t *packet)
{
	str call_id, from_tag, to_tag;
	unsigned int dir, dst_leg;
	unsigned int cseq;
	struct dlg_cell *dlg;

	DLG_BIN_POP(str, packet, call_id, malformed);
	DLG_BIN_POP(str, packet, from_tag, malformed);
	DLG_BIN_POP(str, packet, to_tag, malformed);

	LM_DBG("Updating cseq for dialog with callid: %.*s\n", call_id.len, call_id.s);

	dst_leg = -1;
	dlg = get_dlg(&call_id, &from_tag, &to_tag, &dir, &dst_leg);
	if (!dlg) {
		/* may be already deleted due to timeout */
		LM_DBG("dialog not found (callid: |%.*s| ftag: |%.*s|\n",
			call_id.len, call_id.s, from_tag.len, from_tag.s);
		return 0;
	}
	DLG_BIN_POP(int, packet, cseq, malformed);
	dlg->legs[dst_leg].last_gen_cseq = cseq;
	unref_dlg(dlg, 1);

	return 0;
malformed:
	LM_ERR("malformed cseq update packet for %.*s\n", call_id.len, call_id.s);
	return -1;
}
#undef DLG_BIN_POP


#define DLG_BIN_PUSH_ROUTE(_packet, _dlg, _type) \
do { \
	str __s; \
	if (_dlg->rt_ ## _type>0) { \
		__s.s = sroutes->request[_dlg->rt_ ## _type].name; \
		__s.len = strlen(__s.s); \
		bin_push_str(_packet, &__s); \
	} else { \
		bin_push_str(_packet, NULL); \
	} \
} while(0)

void bin_push_dlg(bin_packet_t *packet, struct dlg_cell *dlg)
{
	int callee_leg;
	str *vars, *profiles;

	callee_leg = callee_idx(dlg);

	bin_push_str(packet, &dlg->callid);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(packet, &dlg->legs[callee_leg].tag);

	bin_push_str(packet, &dlg->from_uri);
	bin_push_str(packet, &dlg->to_uri);

	bin_push_int(packet, dlg->h_id);
	bin_push_int(packet, dlg->start_ts);
	bin_push_int(packet, dlg->state);

	bin_push_str(packet,
		get_socket_internal_name(dlg->legs[DLG_CALLER_LEG].bind_addr));
	if (dlg->legs[callee_leg].bind_addr)
		bin_push_str(packet,
			get_socket_internal_name(dlg->legs[callee_leg].bind_addr));
	else
		bin_push_str(packet, NULL);

	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].r_cseq);
	bin_push_str(packet, &dlg->legs[callee_leg].r_cseq);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].route_set);
	bin_push_str(packet, &dlg->legs[callee_leg].route_set);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].contact);
	bin_push_str(packet, &dlg->legs[callee_leg].contact);
	bin_push_str(packet, &dlg->legs[callee_leg].from_uri);
	bin_push_str(packet, &dlg->legs[callee_leg].to_uri);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].in_sdp);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].out_sdp);
	bin_push_str(packet, &dlg->legs[callee_leg].in_sdp);
	bin_push_str(packet, &dlg->legs[callee_leg].out_sdp);
	bin_push_str(packet, &dlg->legs[DLG_CALLER_LEG].adv_contact);
	bin_push_str(packet, &dlg->legs[callee_leg].adv_contact);

	/* give modules the chance to write values/profiles before replicating */
	run_dlg_callbacks(DLGCB_WRITE_VP, dlg, NULL, DLG_DIR_NONE, NULL, 1, 1);

   /* save sharing tag name as dlg val */
	if (dlg->shtag.s && store_dlg_value_unsafe(dlg, &shtag_dlg_val, &dlg->shtag) < 0)
		LM_ERR("Failed to store sharing tag name as dlg val\n");

	vars = write_dialog_vars(dlg->vals);
	profiles = write_dialog_profiles(dlg->profile_links);

	bin_push_str(packet, vars);
	bin_push_str(packet, profiles);
	bin_push_int(packet, dlg->user_flags);
	bin_push_int(packet, dlg->mod_flags);
	bin_push_int(packet, dlg->flags &
			     ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED|DLG_FLAG_FROM_DB));
	bin_push_int(packet, (unsigned int)time(0) + dlg->tl.timeout - get_ticks());
	bin_push_int(packet, dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_push_int(packet, dlg->legs[callee_leg].last_gen_cseq);

	DLG_BIN_PUSH_ROUTE( packet, dlg, on_answer);
	DLG_BIN_PUSH_ROUTE( packet, dlg, on_timeout);
	DLG_BIN_PUSH_ROUTE( packet, dlg, on_hangup);
}

/*  Binary Packet sending functions   */


/**
 * replicates a locally created dialog to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_created(struct dlg_cell *dlg)
{
	int rc;
	bin_packet_t packet;

	dlg_lock_dlg(dlg);

	if (dlg->state != DLG_STATE_CONFIRMED_NA && dlg->state != DLG_STATE_CONFIRMED) {
		/* we don't need to replicate when in deleted state */
		LM_WARN("not replicating dlg create message due to bad state %d (%.*s)\n",
			dlg->state, dlg->callid.len, dlg->callid.s);
		goto no_send;
	}

	if (dlg->replicated) {
		/* already created - must be a retransmission */
		LM_DBG("not replicating retransmission for %p (%.*s)\n",
			dlg, dlg->callid.len, dlg->callid.s);
		goto no_send;
	}

	if (bin_init(&packet, &dlg_repl_cap, REPLICATION_DLG_CREATED, BIN_VERSION, 0) != 0)
		goto init_error;

	if (dlg_has_reinvite_pinging(dlg) && persist_reinvite_pinging(dlg))
		LM_ERR("failed to persist Re-INVITE pinging info\n");

	bin_push_dlg(&packet, dlg);

	dlg->replicated = 1;

	dlg_unlock_dlg(dlg);

	rc = clusterer_api.send_all(&packet, dialog_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dialog_repl_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			dialog_repl_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dialog_repl_cluster);
		goto error;
	}

	if_update_stat(dlg_enable_stats,create_sent,1);
	bin_free_packet(&packet);
	return;

error:
	bin_free_packet(&packet);
	LM_ERR("Failed to replicate created dialog\n");
	return;

init_error:
	LM_ERR("Failed to replicate created dialog\n");
no_send:
	dlg_unlock_dlg(dlg);
	return;
}

/**
 * replicates a local dialog update in the cluster
 */
void replicate_dialog_updated(struct dlg_cell *dlg)
{
	int rc;
	bin_packet_t packet;


	dlg_lock_dlg(dlg);
	if (dlg->state < DLG_STATE_CONFIRMED_NA) {
		LM_DBG("not replicating update in state %d (%.*s)\n", dlg->state,
				dlg->callid.len, dlg->callid.s);
		goto end;
	}
	if (dlg->state == DLG_STATE_DELETED) {
		/* we no longer need to update anything */
		LM_WARN("not replicating dlg update message due to bad state %d (%.*s)\n",
			dlg->state, dlg->callid.len, dlg->callid.s);
		goto end;
	}

	if (bin_init(&packet, &dlg_repl_cap, REPLICATION_DLG_UPDATED, BIN_VERSION, 0) != 0)
		goto init_error;

	if (dlg_has_reinvite_pinging(dlg) && persist_reinvite_pinging(dlg))
		LM_ERR("failed to persist Re-INVITE pinging info\n");

	bin_push_dlg(&packet, dlg);

	dlg->replicated = 1;

	dlg_unlock_dlg(dlg);

	rc = clusterer_api.send_all(&packet, dialog_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dialog_repl_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_ERR("All destinations in cluster: %d are down or probing\n",
			dialog_repl_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dialog_repl_cluster);
		goto error;
	}

	if_update_stat(dlg_enable_stats,update_sent,1);
	bin_free_packet(&packet);
	return;

error:
	LM_ERR("Failed to replicate updated dialog\n");
	bin_free_packet(&packet);
	return;

init_error:
	LM_ERR("Failed to replicate updated dialog\n");
end:
	dlg_unlock_dlg(dlg);
}

/**
 * replicates a local dialog delete event to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_deleted(struct dlg_cell *dlg)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &dlg_repl_cap, REPLICATION_DLG_DELETED, BIN_VERSION, 1024) != 0)
		goto error;

	bin_push_str(&packet, &dlg->callid);
	bin_push_str(&packet, &dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(&packet, &dlg->legs[callee_idx(dlg)].tag);

	rc = clusterer_api.send_all(&packet, dialog_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dialog_repl_cluster);
		goto error_free;
	case CLUSTERER_DEST_DOWN:
		LM_ERR("All destinations in cluster: %d are down or probing\n",
			dialog_repl_cluster);
		goto error_free;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dialog_repl_cluster);
		goto error_free;
	}

	if_update_stat(dlg_enable_stats, delete_sent, 1);
	bin_free_packet(&packet);
	return;
error_free:
	bin_free_packet(&packet);
error:
	LM_ERR("Failed to replicate deleted dialog\n");
}


/**
 * replicates a local dialog cseq increased for a specific leg
 */
void replicate_dialog_cseq_updated(struct dlg_cell *dlg, int leg)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &dlg_repl_cap, REPLICATION_DLG_CSEQ,
			BIN_VERSION, 512) != 0)
		goto error;

	bin_push_str(&packet, &dlg->callid);
	bin_push_str(&packet,
			&dlg->legs[leg == DLG_CALLER_LEG?callee_idx(dlg):DLG_CALLER_LEG].tag);
	bin_push_str(&packet, &dlg->legs[leg].tag);
	bin_push_int(&packet, dlg->legs[leg].last_gen_cseq);

	rc = clusterer_api.send_all(&packet, dialog_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", dialog_repl_cluster);
		goto error_free;
	case CLUSTERER_DEST_DOWN:
		LM_ERR("All destinations in cluster: %d are down or probing\n",
			dialog_repl_cluster);
		goto error_free;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", dialog_repl_cluster);
		goto error_free;
	}

	bin_free_packet(&packet);
	return;
error_free:
	bin_free_packet(&packet);
error:
	LM_ERR("Failed to replicate dialog cseq update\n");
}

void receive_dlg_repl(bin_packet_t *packet)
{
	int rc = 0;
	bin_packet_t *pkt;

	for (pkt = packet; pkt; pkt = pkt->next) {
		switch (pkt->type) {
		case REPLICATION_DLG_CREATED:
			ensure_bin_version(pkt, BIN_VERSION);

			rc = dlg_replicated_create(pkt, NULL, NULL, NULL, 1);
			if_update_stat(dlg_enable_stats, create_recv, 1);
			break;
		case REPLICATION_DLG_UPDATED:
			ensure_bin_version(pkt, BIN_VERSION);

			rc = dlg_replicated_update(pkt);
			if_update_stat(dlg_enable_stats, update_recv, 1);
			break;
		case REPLICATION_DLG_DELETED:
			ensure_bin_version(pkt, BIN_VERSION);

			rc = dlg_replicated_delete(pkt);
			if_update_stat(dlg_enable_stats, delete_recv, 1);
			break;
		case REPLICATION_DLG_CSEQ:
			rc = dlg_replicated_cseq_updated(pkt);
			break;
		case SYNC_PACKET_TYPE:
			ensure_bin_version(pkt, BIN_VERSION);

			while (clusterer_api.sync_chunk_iter(pkt))
				if (dlg_replicated_create(pkt, NULL, NULL, NULL, 1) < 0) {
					LM_ERR("Failed to process sync packet\n");
					return;
				}
			break;
		default:
			rc = -1;
			LM_WARN("Invalid dialog binary packet command: %d "
				"(from node: %d in cluster: %d)\n", pkt->type, pkt->src_id,
				dialog_repl_cluster);
		}

		if (rc != 0)
			LM_ERR("Failed to process a binary packet!\n");
	}
}

static int receive_sync_request(int node_id)
{
	int i;
	struct dlg_cell *dlg;
	bin_packet_t *sync_packet;

	for (i = 0; i < d_table->size; i++) {
		dlg_lock(d_table, &(d_table->entries[i]));
		for (dlg = d_table->entries[i].first; dlg; dlg = dlg->next) {
			if (dlg->state != DLG_STATE_CONFIRMED_NA &&
			        dlg->state != DLG_STATE_CONFIRMED)
				continue;

			sync_packet = clusterer_api.sync_chunk_start(&dlg_repl_cap,
			                   dialog_repl_cluster, node_id, BIN_VERSION);
			if (!sync_packet)
				goto error;

			bin_push_dlg(sync_packet, dlg);
		}
		dlg_unlock(d_table, &(d_table->entries[i]));
	}

	return 0;

error:
	dlg_unlock(d_table, &(d_table->entries[i]));
	return -1;
}

void rcv_cluster_event(enum clusterer_event ev, int node_id)
{
	struct dlg_cell *dlg, *next_dlg;
	int i, ret, unref, old_state, new_state;

	if (ev == SYNC_REQ_RCV && receive_sync_request(node_id) < 0)
		LM_ERR("Failed to reply to sync request from node: %d\n", node_id);
	else if (ev == SYNC_DONE) {
		if (dlg_db_mode == DB_MODE_NONE)
			return;
		/* drop dialogs loaded from DB which have not been reconfirmed
		 * through syncing or SIP(updates) */
		for (i = 0; i < d_table->size; i++) {
			dlg_lock(d_table, &d_table->entries[i]);
			dlg = d_table->entries[i].first;
			while (dlg) {
				if (!(dlg->flags & DLG_FLAG_FROM_DB)) {
					dlg = dlg->next;
					continue;
				}

				/* make sure dialog is not freed while we don't hold the lock */
				ref_dlg_unsafe(dlg, 1);
				dlg_unlock(d_table, &d_table->entries[i]);

				LM_DBG("Drop DB loaded dialog ID=%llu\n", dlg_get_db_id(dlg));

				/* simulate BYE received from caller */
				next_state_dlg(dlg, DLG_EVENT_REQBYE, DLG_DIR_UPSTREAM, &old_state,
				        &new_state, &unref, dlg->legs_no[DLG_LEG_200OK], 0);

				if (new_state != DLG_STATE_DELETED) {
					unref_dlg(dlg, 1 + unref);
					dlg = dlg->next;
					continue;
				}
				unref++; /* the extra added ref */
				dlg_lock(d_table, &d_table->entries[i]);

				destroy_linkers_unsafe(dlg);

				dlg_unlock(d_table, &d_table->entries[i]);

				remove_dlg_prof_table(dlg, 1);

				dlg_lock(d_table, &d_table->entries[i]);

				/* remove from timer, even though it may be done already */
				ret = remove_dlg_timer(&dlg->tl);
				if (ret < 0) {
					LM_ERR("unable to unlink the timer on dlg %p [%u:%u] "
						"with clid '%.*s' and tags '%.*s' '%.*s'\n",
						dlg, dlg->h_entry, dlg->h_id,
						dlg->callid.len, dlg->callid.s,
						dlg_leg_print_info(dlg, DLG_CALLER_LEG, tag),
						dlg_leg_print_info(dlg, callee_idx(dlg), tag));
				} else if (ret == 0)
					/* successfully removed from timer list */
					unref++;

				if (dlg_db_mode != DB_MODE_SHUTDOWN) {
					dlg->flags &= ~DLG_FLAG_NEW;
					remove_dialog_from_db(dlg);
					dlg->flags |= DLG_FLAG_DB_DELETED;
				}

				if (dlg_db_mode == DB_MODE_DELAYED)
					unref++;

				if (old_state != DLG_STATE_DELETED)
					if_update_stat(dlg_enable_stats, active_dlgs, -1);

				next_dlg = dlg->next;
				unref_dlg_unsafe(dlg, unref, &d_table->entries[i]);
				dlg = next_dlg;
			}
			dlg_unlock(d_table, &d_table->entries[i]);
		}
	}
}

int repl_prof_buffer_th = DLG_REPL_PROF_BUF_THRESHOLD;
int repl_prof_utimer = DLG_REPL_PROF_TIMER;
int repl_prof_timer_check = DLG_REPL_PROF_TIMER;
int repl_prof_timer_expire = DLG_REPL_PROF_EXPIRE_TIMER;

static void broadcast_profiles(utime_t ticks, void *param);
static void clean_profiles(unsigned int ticks, void *param);

int repl_prof_init(void)
{
	if (!profile_repl_cluster)
		return 0;

	if (repl_prof_timer_check < 0) {
		LM_ERR("negative replicate timer for profiles check %d\n",
			repl_prof_timer_check);
		return -1;
	}

	if (repl_prof_timer_expire < 0) {
		LM_ERR("negative replicate expire timer for profiles %d\n",
			repl_prof_timer_expire);
		return -1;
	}

	if (register_timer("dialog-repl-profiles-timer", clean_profiles, NULL,
		repl_prof_timer_check, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register profiles utimer\n");
		return -1;
	}

	if (repl_prof_utimer < 0) {
		LM_ERR("negative replicate timer for profiles %d\n", repl_prof_utimer);
		return -1;
	}

	if (repl_prof_buffer_th < 0) {
		LM_ERR("negative replicate buffer threshold for profiles %d\n",
			repl_prof_buffer_th);
		return -1;
	}

	if (register_utimer("dialog-repl-profiles-utimer", broadcast_profiles, NULL,
		repl_prof_utimer * 1000, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register profiles utimer\n");
		return -1;
	}


	if (repl_prof_buffer_th > (BUF_SIZE * 0.9)) {
		LM_WARN("Buffer size too big %d - profiles information might get lost",
			repl_prof_buffer_th);
		return -1;
	}

	return 0;
}

/* profiles replication */
static inline void dlg_replicate_profiles(bin_packet_t *packet)
{
	int rc;

	rc = clusterer_api.send_all(packet, profile_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", profile_repl_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_ERR("All destinations in cluster: %d are down or probing\n",
			profile_repl_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster %d\n", profile_repl_cluster);
		goto error;
	}

	return;
error:
	LM_ERR("Failed to replicate dialog profile\n");
}

static repl_prof_count_t* find_destination(prof_rcv_count_t *noval, int node_id)
{
	repl_prof_count_t *head;

	head = noval->dsts;
	while(head != NULL){
		if( head->node_id ==  node_id )
			break;
		head=head->next;
	}

	if(head == NULL){
		head = shm_malloc(sizeof(repl_prof_count_t));
		if(head == NULL){
			LM_ERR("no more shm memory\n");
			goto error;
		}
		head->node_id = node_id;
		head->next = noval->dsts;
		noval->dsts = head;
	}
	return head;

error:
	return NULL;
}


void receive_prof_repl(bin_packet_t *packet)
{
	time_t now;
	str name;
	str value = str_init("");
	unsigned int counter;
	struct dlg_profile_table *profile;
	int has_value;
	int i;
	void **dst;
	prof_value_info_t *rp;
	repl_prof_count_t *destination;

	/* optimize profile search */
	struct dlg_profile_table *old_profile = NULL;
	str old_name = {NULL,0};

	if (!profile_repl_cluster)
		return;

	if (packet->type != REPLICATION_DLG_PROFILE) {
		LM_WARN("Invalid dialog binary packet command: %d (from node: %d in cluster: %d)\n",
			packet->type, packet->src_id, profile_repl_cluster);
		return;
	}

	now = time(0);
	//*repl_prof_dests[index].last_msg = now;

	for (;;) {
		if (bin_pop_str(packet ,&name) == 1)
			break; /* pop'ed all pipes */

		/* check if the same profile was sent */
		if (!old_profile || old_name.len != name.len ||
			memcmp(name.s, old_name.s, name.len) != 0) {
			old_profile = get_dlg_profile(&name);
			if (!old_profile) {
				LM_WARN("received unknown profile <%.*s> from node %d\n",
					name.len, name.s, packet->src_id);

				if (bin_pop_int(packet, &has_value) < 0) {
					LM_ERR("cannot pop profile's has_value int\n");
					return;
				}
				if (has_value)
					bin_skip_str(packet, 1);
				bin_skip_int(packet, 1);

				continue;
			}
			old_name = name;
		}
		profile = old_profile;

		if (profile->repl_type != REPL_PROTOBIN) {
			LM_WARN("Received a replication packet for a local profile\n");
			return;
		}

		if (bin_pop_int(packet, &has_value) < 0) {
			LM_ERR("cannot pop profile's has_value int\n");
			return;
		}

		if (has_value) {
			if (!profile->has_value) {
				LM_WARN("The other end does not have a value for this profile:"
					"<%.*s> [node: %d]\n", profile->name.len, profile->name.s,
					packet->src_id);
				profile = NULL;
			}
			if (bin_pop_str(packet, &value)) {
				LM_ERR("cannot pop the value of the profile\n");
				return;
			}
		}

		if (bin_pop_int(packet, &counter) < 0) {
			LM_ERR("cannot pop profile's counter\n");
			return;
		}

		if (profile) {
			if (!profile->has_value) {
				lock_get(&profile->noval_rcv_counters->lock);
				destination = find_destination(profile->noval_rcv_counters, packet->src_id);
				if(destination == NULL){
					lock_release(&profile->noval_rcv_counters->lock);
					return;
				}
				destination->counter = counter;
				destination->update = now;
				lock_release(&profile->noval_rcv_counters->lock);
			} else {
				/* XXX: hack to make sure we find the proper index */
				i = core_hash(&value, NULL, profile->size);
				lock_set_get(profile->locks, i);
				/* if counter is 0 and we don't have it, don't try to create */
				if (!counter) {
					dst = map_find(profile->entries[i], value);
					if (!dst)
						goto release;
				} else {
					dst = map_get(profile->entries[i], value);
				}
				if (!*dst) {
					rp = shm_malloc(sizeof(prof_value_info_t));
					if (!rp) {
						LM_ERR("no more shm memory to allocate repl_prof_value\n");
						goto release;
					}
					memset(rp, 0, sizeof(prof_value_info_t));
					*dst = rp;
				} else {
					rp = (prof_value_info_t *) * dst;
				}
				if (!rp->rcv_counters)
					rp->rcv_counters = repl_prof_allocate();
				if (rp->rcv_counters) {
					lock_get(&rp->rcv_counters->lock);
					destination = find_destination(rp->rcv_counters, packet->src_id);
					if (destination == NULL) {
						lock_release(&rp->rcv_counters->lock);
						lock_set_release(profile->locks, i);
						return;
					}
					destination->counter = counter;
					destination ->update = now;
					lock_release(&rp->rcv_counters->lock);
				}
release:
				lock_set_release(profile->locks, i);
			}
		}
	}
	return;
}

static int repl_prof_add(bin_packet_t *packet, str *name, int has_value, str *value,
													unsigned int count)
{
	int ret = 0;

	if (bin_push_str(packet, name) < 0)
		return -1;
	/* extra size to add the value indication but it's good
	 * for servers profiles consistency checks */
	if (bin_push_int(packet, has_value) < 0)
		return -1;
	/* the other end should already know if the profile has a value or not */
	if (value && bin_push_str(packet, value) < 0)
		return -1;
	if ((ret = bin_push_int(packet, count)) < 0)
		return -1;

	return ret;
}

int repl_prof_remove(str *name, str *value)
{
	bin_packet_t packet;

	if (profile_repl_cluster <= 0)
		return 0;
	if (bin_init(&packet, &prof_repl_cap, REPLICATION_DLG_PROFILE, BIN_VERSION, 1024) < 0) {
		LM_ERR("cannot initiate bin buffer\n");
		return -1;
	}

	if (repl_prof_add(&packet, name, value?1:0, value, 0) < 0) {
		bin_free_packet(&packet);
		return -1;
	}
	dlg_replicate_profiles(&packet);
	bin_free_packet(&packet);

	return 0;
}


int replicate_profiles_count(prof_rcv_count_t *rp)
{
	int counter = 0;
	time_t now = time(0);
	repl_prof_count_t *head;

	if (!rp)
		return 0;

	lock_get(&rp->lock);
	head = rp->dsts;
	while (head != NULL) {
		/* if the replication expired, reset its counter */
		if ((head->update + repl_prof_timer_expire) < now)
			head->counter = 0;
		counter += head->counter;
		head = head->next;
	}
	lock_release(&rp->lock);
	return counter;
}

static void clean_profiles(unsigned int ticks, void *param)
{
	map_iterator_t it, del;
	unsigned int count;
	struct dlg_profile_table *profile;
	prof_value_info_t *rp;
	void **dst;
	int i;

	for (profile = profiles; profile; profile = profile->next) {
		if (!profile->has_value || profile->repl_type != REPL_PROTOBIN)
			continue;
		for (i = 0; i < profile->size; i++) {
			lock_set_get(profile->locks, i);
			if (map_first(profile->entries[i], &it) < 0) {
				LM_ERR("map does not exist\n");
				goto next_entry;
			}
			while (iterator_is_valid(&it)) {
				dst = iterator_val(&it);
				if (!dst || !*dst) {
					LM_ERR("[BUG] bogus map[%d] state\n", i);
					goto next_val;
				}
				count = prof_val_get_count(dst, 1, 1);
				if (!count) {
					del = it;
					if (iterator_next(&it) < 0)
						LM_DBG("cannot find next iterator\n");
					rp = (prof_value_info_t *) iterator_delete(&del);
					if (rp)
						free_profile_val_t(rp);

					continue;
				}
next_val:
				if (iterator_next(&it) < 0)
					break;
			}
next_entry:
			lock_set_release(profile->locks, i);
		}
	}
}

static void broadcast_profiles(utime_t ticks, void *param)
{
#define REPL_PROF_TRYSEND() \
	do { \
		if (ret > repl_prof_buffer_th) { \
			/* send the buffer */ \
			if (nr) \
				dlg_replicate_profiles(&packet); \
			bin_reset_back_pointer(&packet); \
			nr = 0; \
		} \
	} while (0)

	struct dlg_profile_table *profile;
	map_iterator_t it;
	unsigned int count;
	int i;
	int nr = 0;
	int ret = 0;
	void **dst;
	str *value;
	bin_packet_t packet;

	if (bin_init(&packet, &prof_repl_cap, REPLICATION_DLG_PROFILE, BIN_VERSION, 0) < 0) {
		LM_ERR("cannot initiate bin buffer\n");
		return;
	}

	for (profile = profiles; profile; profile = profile->next) {
		if (profile->repl_type != REPL_PROTOBIN)
			continue;

		count = 0;
		if (!profile->has_value) {
			count = noval_get_local_count(profile);

			if ((ret = repl_prof_add(&packet, &profile->name, 0, NULL, count)) < 0)
				goto error;
			/* check if the profile should be sent */
			nr++;
			REPL_PROF_TRYSEND();
		} else {
			for (i = 0; i < profile->size; i++) {
				lock_set_get(profile->locks, i);
				if (map_first(profile->entries[i], &it) < 0) {
					LM_ERR("map does not exist\n");
					goto next_entry;
				}
				while (iterator_is_valid(&it)) {
					dst = iterator_val(&it);
					if (!dst || !*dst) {
						LM_ERR("[BUG] bogus map[%d] state\n", i);
						goto next_val;
					}
					value = iterator_key(&it);
					if (!value) {
						LM_ERR("cannot retrieve profile's key\n");
						goto next_val;
					}
					count = prof_val_get_local_count(dst, 0);
					if ((ret = repl_prof_add(&packet, &profile->name, 1, value, count)) < 0) {
						lock_set_release(profile->locks, i);
						goto error;
					}
					nr++;

next_val:
					if (iterator_next(&it) < 0)
						break;
				}
next_entry:
				lock_set_release(profile->locks, i);
				/* check if the profile should be sent */
				REPL_PROF_TRYSEND();
			}
		}
	}

	goto done;

error:
	LM_ERR("cannot add any more profiles in buffer\n");
done:
	/* check if there is anything else left to replicate */
	if (nr)
		dlg_replicate_profiles(&packet);
	bin_free_packet(&packet);
#undef REPL_PROF_TRYSEND
}

mi_response_t *mi_sync_cl_dlg(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (!dialog_repl_cluster)
		return init_mi_error(400, MI_SSTR("Dialog replication disabled"));

	if (clusterer_api.request_sync(&dlg_repl_cap, dialog_repl_cluster) < 0)
		return init_mi_error(400, MI_SSTR("Failed to send sync request"));
	else
		return init_mi_result_ok();
}

int set_dlg_shtag(struct dlg_cell *dlg, str *tag_name)
{
	if (clusterer_api.shtag_get(tag_name, dialog_repl_cluster) < 0) {
		LM_ERR("Failed to fetch sharing tag: <%.*s>\n", tag_name->len,
			tag_name->s);
		return -1;
	}

	if (shm_str_dup(&dlg->shtag, tag_name) < 0) {
		LM_ERR("No more shm memory\n");
		return -1;
	}

	return 0;
}

/* @return:
 *	0 - backup
 *	1 - active
 * -1 - error
 * -2 - tag not found
 */
int get_shtag_state(struct dlg_cell *dlg)
{
	int rc;

	if (!dlg)
		return -1;

	if (!dlg->shtag.s || dlg->shtag.len == 0) {
		LM_DBG("Sharing tag not set\n");
		return -2;
	}

	if ((rc = clusterer_api.shtag_get(&dlg->shtag, dialog_repl_cluster)) < 0) {
		LM_ERR("Failed to get state for sharing tag: <%.*s>\n",
			dlg->shtag.len, dlg->shtag.s);
		return -1;
	}

	return rc;
}
