/*
 * dialog module - basic support for dialog tracking
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2013-04-12 initial version (Liviu)
 */

#include "dlg_hash.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"

#include "dlg_replication.h"

extern int active_dlgs_cnt;
extern int early_dlgs_cnt;

extern int last_dst_leg;

extern int dlg_enable_stats;

extern stat_var *active_dlgs;
extern stat_var *processed_dlgs;

extern stat_var *create_sent;
extern stat_var *update_sent;
extern stat_var *delete_sent;
extern stat_var *create_recv;
extern stat_var *update_recv;
extern stat_var *delete_recv;

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

	sock = grep_sock_info(&host, (unsigned short)port, (unsigned short)proto);
	if (!sock) {
		LM_WARN("non-local socket <%.*s>...ignoring\n", addr->len, addr->s);
	}

	return sock;
}

/*  Binary Packet receiving functions   */


/**
 * replicates a confirmed dialog from another OpenSIPS instance
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_create(struct dlg_cell *cell, str *ftag, str *ttag, int safe)
{
	int next_id, h_entry;
	unsigned int dir, dst_leg;
	str callid, from_uri, to_uri, from_tag, to_tag;
	str cseq1,cseq2,contact1,contact2,rroute1,rroute2,mangled_fu,mangled_tu;
	str sock, vars, profiles;
	struct dlg_cell *dlg = NULL;
	struct socket_info *caller_sock, *callee_sock;
	struct dlg_entry *d_entry;

	if_update_stat(dlg_enable_stats, processed_dlgs, 1);

	LM_DBG("Received replicated dialog!\n");
	if (!cell) {
		bin_pop_str(&callid);
		bin_pop_str(&from_tag);
		bin_pop_str(&to_tag);
		bin_pop_str(&from_uri);
		bin_pop_str(&to_uri);

		dlg = get_dlg(&callid, &from_tag, &to_tag, &dir, &dst_leg);

		h_entry = dlg_hash(&callid);
		d_entry = &d_table->entries[h_entry];

		if (safe)
			dlg_lock(d_table, d_entry);

		if (dlg) {
			LM_DBG("Dialog with ci '%.*s' is already created\n",
			       callid.len, callid.s);
			unref_dlg_unsafe(dlg, 1, d_entry);
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

	bin_pop_int(&dlg->h_id);
	bin_pop_int(&dlg->start_ts);
	bin_pop_int(&dlg->state);

	next_id = d_table->entries[dlg->h_entry].next_id;

	d_table->entries[dlg->h_entry].next_id =
		(next_id <= dlg->h_id) ? (dlg->h_id + 1) : next_id;

	if (bin_pop_str(&sock))
		goto pre_linking_error;

	caller_sock = fetch_socket_info(&sock);

	if (bin_pop_str(&sock))
		goto pre_linking_error;

	callee_sock = fetch_socket_info(&sock);

	if (!caller_sock || !callee_sock) {
		LM_ERR("Dialog in DB doesn't match any listening sockets\n");
		goto pre_linking_error;
	}

	bin_pop_str(&cseq1);
	bin_pop_str(&cseq2);
	bin_pop_str(&rroute1);
	bin_pop_str(&rroute2);
	bin_pop_str(&contact1);
	bin_pop_str(&contact2);
	bin_pop_str(&mangled_fu);
	bin_pop_str(&mangled_tu);

	/* add the 2 legs */
	if (dlg_add_leg_info(dlg, &from_tag, &rroute1, &contact1,
				&cseq1, caller_sock, 0, 0) != 0 ||
		dlg_add_leg_info(dlg, &to_tag, &rroute2, &contact2,
				&cseq2, callee_sock, &mangled_fu, &mangled_tu) != 0) {
		LM_ERR("dlg_set_leg_info failed\n");
		goto pre_linking_error;
	}

	dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

	/* link the dialog into the hash */
	dlg->h_id = d_entry->next_id++;
	if (!d_entry->first)
		d_entry->first = d_entry->last = dlg;
	else {
		d_entry->last->next = dlg;
		dlg->prev = d_entry->last;
		d_entry->last = dlg;
	}
	dlg->ref++;
	d_entry->cnt++;

	bin_pop_str(&vars);
	bin_pop_str(&profiles);
	bin_pop_int(&dlg->user_flags);
	bin_pop_int(&dlg->flags);
	bin_pop_int((void *)&dlg->tl.timeout);
	bin_pop_int(&dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_pop_int(&dlg->legs[callee_idx(dlg)].last_gen_cseq);

	if (dlg->tl.timeout <= (unsigned int)time(0))
		dlg->tl.timeout = 0;
	else
		dlg->tl.timeout -= (unsigned int)time(0);

	/* restore the timer values */
	if (insert_dlg_timer(&dlg->tl, (int)dlg->tl.timeout) != 0) {
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

	if (dlg->state == DLG_STATE_CONFIRMED_NA ||
	    dlg->state == DLG_STATE_CONFIRMED)
		active_dlgs_cnt++;

	/* reference the dialog as kept in the timer list */
	ref_dlg_unsafe(dlg, 1);

	LM_DBG("Received initial timeout of %d for dialog %.*s, safe = %d\n",dlg->tl.timeout,callid.len,callid.s,safe);

	dlg->lifetime = 0;

	/*
	Do not replicate the pinging - we might terminate dialogs badly when running
	as backup 
	if (dlg->flags & DLG_FLAG_PING_CALLER || dlg->flags & DLG_FLAG_PING_CALLEE) {
		if (insert_ping_timer(dlg) != 0)
			LM_CRIT("Unable to insert dlg %p into ping timer\n",dlg);
		else {
			ref_dlg_unsafe(dlg, 1);
		}
	}
	*/

	if (dlg_db_mode == DB_MODE_DELAYED) {
		/* to be later removed by timer */
		ref_dlg_unsafe(dlg, 1);
	}

	if (vars.s && vars.len != 0)
		read_dialog_vars(vars.s, vars.len, dlg);

	dlg_unlock(d_table, d_entry);

	if (profiles.s && profiles.len != 0)
		read_dialog_profiles(profiles.s, profiles.len, dlg, 0, 1);

	if_update_stat(dlg_enable_stats, active_dlgs, 1);

	run_load_callback_per_dlg(dlg);

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

	return -1;
}

/**
 * replicates the remote update of an ongoing dialog locally
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_update(void)
{
	struct dlg_cell *dlg;
	str call_id, from_tag, to_tag, from_uri, to_uri, vars, profiles;
	unsigned int dir, dst_leg;
	int timeout, h_entry;
	str st;
	struct dlg_entry *d_entry;

	bin_pop_str(&call_id);
	bin_pop_str(&from_tag);
	bin_pop_str(&to_tag);
	bin_pop_str(&from_uri);
	bin_pop_str(&to_uri);

	LM_DBG("replicated update for ['%.*s' '%.*s' '%.*s' '%.*s' '%.*s']\n",
	call_id.len, call_id.s, from_tag.len, from_tag.s, to_tag.len, to_tag.s,
	from_uri.len, from_uri.s, to_uri.len, to_uri.s);

	dlg = get_dlg(&call_id, &from_tag, &to_tag, &dir, &dst_leg);

	h_entry = dlg_hash(&call_id);
	d_entry = &d_table->entries[h_entry];

	dlg_lock(d_table, d_entry);

	if (!dlg) {
		/* TODO: change to LM_DBG */
		LM_ERR("dialog not found, building new\n");

		dlg = build_new_dlg(&call_id, &from_uri, &to_uri, &from_tag);
		if (!dlg) {
			LM_ERR("Failed to create replicated dialog!\n");
			goto error;
		}

		return dlg_replicated_create(dlg, &from_tag, &to_tag, 0);
	}

	bin_skip_int(2);
	bin_pop_int(&dlg->state);

	bin_skip_str(2);

	bin_pop_str(&st);
	if (dlg_update_cseq(dlg, DLG_CALLER_LEG, &st, 0) != 0) {
		LM_ERR("failed to update caller cseq\n");
		goto error;
	}

	bin_pop_str(&st);
	if (dlg_update_cseq(dlg, callee_idx(dlg), &st, 0) != 0) {
		LM_ERR("failed to update callee cseq\n");
		goto error;
	}

	bin_skip_str(6);
	bin_pop_str(&vars);
	bin_pop_str(&profiles);
	bin_pop_int(&dlg->user_flags);
	bin_pop_int(&dlg->flags);

	bin_pop_int(&timeout);
	bin_skip_int(2);

	timeout -= time(0);
	LM_DBG("Received updated timeout of %d for dialog %.*s\n",timeout,call_id.len,call_id.s);

	if (dlg->lifetime != timeout) {
		dlg->lifetime = timeout;
		if (update_dlg_timer(&dlg->tl, dlg->lifetime) == -1)
			LM_ERR("failed to update dialog lifetime!\n");
	}

	unref_dlg_unsafe(dlg, 1, d_entry);

	if (vars.s && vars.len != 0)
		read_dialog_vars(vars.s, vars.len, dlg);

	dlg_unlock(d_table, d_entry);

	if (profiles.s && profiles.len != 0)
		read_dialog_profiles(profiles.s, profiles.len, dlg, 1, 1);

	return 0;

error:
	dlg_unlock(d_table, d_entry);
	return -1;
}

/**
 * replicates the remote deletion of a dialog locally
 * by reading the relevant information using the Binary Packet Interface
 */
int dlg_replicated_delete(void)
{
	str call_id, from_tag, to_tag;
	unsigned int dir, dst_leg;
	struct dlg_cell *dlg;
	int old_state, new_state, unref, ret;

	bin_pop_str(&call_id);
	bin_pop_str(&from_tag);
	bin_pop_str(&to_tag);

	LM_DBG("Deleting dialog with callid: %.*s\n", call_id.len, call_id.s);

	dlg = get_dlg(&call_id, &from_tag, &to_tag, &dir, &dst_leg);
	if (!dlg) {
	        LM_ERR("dialog not found (callid: |%.*s| ftag: |%.*s|\n",
	                call_id.len, call_id.s, from_tag.len, from_tag.s);
	        return -1;
	}

	dlg_lock_dlg(dlg);
	destroy_linkers(dlg->profile_links, 1);
	dlg->profile_links = NULL;
	dlg_unlock_dlg(dlg);

	/* simulate BYE received from caller */
	last_dst_leg = dlg->legs_no[DLG_LEG_200OK];
	next_state_dlg(dlg, DLG_EVENT_REQBYE, DLG_DIR_DOWNSTREAM, &old_state,
	               &new_state, &unref, 1);

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
		/* dialog sucessfully removed from timer -> unref */
		unref++;
	}

	unref_dlg(dlg, 1 + unref);
	if_update_stat(dlg_enable_stats, active_dlgs, -1);

	return 0;
}

/*  Binary Packet sending functions   */


/**
 * replicates a locally created dialog to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_created(struct dlg_cell *dlg)
{
	struct replication_dest *d;
	static str module_name = str_init("dialog");
	int callee_leg;
	str *vars, *profiles;

	if (bin_init(&module_name, REPLICATION_DLG_CREATED) != 0)
		goto error;

	callee_leg = callee_idx(dlg);

	bin_push_str(&dlg->callid);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(&dlg->legs[callee_leg].tag);

	bin_push_str(&dlg->from_uri);
	bin_push_str(&dlg->to_uri);

	bin_push_int(dlg->h_id);
	bin_push_int(dlg->start_ts);
	bin_push_int(dlg->state);

	bin_push_str(&dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str);
	if (dlg->legs[callee_leg].bind_addr)
		bin_push_str(&dlg->legs[callee_leg].bind_addr->sock_str);
	else
		bin_push_str(NULL);

	bin_push_str(&dlg->legs[DLG_CALLER_LEG].r_cseq);
	bin_push_str(&dlg->legs[callee_leg].r_cseq);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].route_set);
	bin_push_str(&dlg->legs[callee_leg].route_set);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].contact);
	bin_push_str(&dlg->legs[callee_leg].contact);
	bin_push_str(&dlg->legs[callee_leg].from_uri);
	bin_push_str(&dlg->legs[callee_leg].to_uri);

	/* XXX: on shutdown only? */
	vars = write_dialog_vars(dlg->vals);
	profiles = write_dialog_profiles(dlg->profile_links);

	bin_push_str(vars);
	bin_push_str(profiles);
	bin_push_int(dlg->user_flags);
	bin_push_int(dlg->flags &
			     ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED));
	bin_push_int((unsigned int)time(0) + dlg->tl.timeout - get_ticks());
	bin_push_int(dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_push_int(dlg->legs[callee_leg].last_gen_cseq);

	for (d = replication_dests; d; d = d->next)
		bin_send(&d->to);

	if_update_stat(dlg_enable_stats,create_sent,1);
	return;

error:
	LM_ERR("Failed to replicate created dialog\n");
}

/**
 * replicates a local dialog update to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_updated(struct dlg_cell *dlg)
{
	struct replication_dest *d;
	static str module_name = str_init("dialog");
	int callee_leg;
	str *vars, *profiles;

	if (bin_init(&module_name, REPLICATION_DLG_UPDATED) != 0)
		goto error;

	callee_leg = callee_idx(dlg);

	bin_push_str(&dlg->callid);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(&dlg->legs[callee_leg].tag);

	bin_push_str(&dlg->from_uri);
	bin_push_str(&dlg->to_uri);

	bin_push_int(dlg->h_id);
	bin_push_int(dlg->start_ts);
	bin_push_int(dlg->state);

	bin_push_str(&dlg->legs[DLG_CALLER_LEG].bind_addr->sock_str);
	if (dlg->legs[callee_leg].bind_addr)
		bin_push_str(&dlg->legs[callee_leg].bind_addr->sock_str);
	else
		bin_push_str(NULL);

	bin_push_str(&dlg->legs[DLG_CALLER_LEG].r_cseq);
	bin_push_str(&dlg->legs[callee_leg].r_cseq);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].route_set);
	bin_push_str(&dlg->legs[callee_leg].route_set);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].contact);
	bin_push_str(&dlg->legs[callee_leg].contact);
	bin_push_str(&dlg->legs[callee_leg].from_uri);
	bin_push_str(&dlg->legs[callee_leg].to_uri);

	/* XXX: on shutdown only? */
	vars = write_dialog_vars(dlg->vals);
	profiles = write_dialog_profiles(dlg->profile_links);

	bin_push_str(vars);
	bin_push_str(profiles);
	bin_push_int(dlg->user_flags);
	bin_push_int(dlg->flags &
			     ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED));
	bin_push_int((unsigned int)time(0) + dlg->tl.timeout - get_ticks());
	bin_push_int(dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_push_int(dlg->legs[callee_leg].last_gen_cseq);

	for (d = replication_dests; d; d = d->next)
		bin_send(&d->to);

	if_update_stat(dlg_enable_stats,update_sent,1);
	return;

error:
	LM_ERR("Failed to replicate updated dialog\n");
}

/**
 * replicates a local dialog delete event to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_deleted(struct dlg_cell *dlg)
{
	struct replication_dest *d;
	static str module_name = str_init("dialog");

	if (bin_init(&module_name, REPLICATION_DLG_DELETED) != 0)
		goto error;

	bin_push_str(&dlg->callid);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(&dlg->legs[callee_idx(dlg)].tag);

	for (d = replication_dests; d; d = d->next)
		bin_send(&d->to);

	if_update_stat(dlg_enable_stats,delete_sent,1);
	return;
error:
	LM_ERR("Failed to replicate deleted dialog\n");
}

/**
 * receive_binary_packet (callback) - receives a cmd_type, specifying the
 * purpose of the data encoded in the received UDP packet
 */
void receive_binary_packet(int info_type)
{
	int rc;

	LM_DBG("Received a binary packet!\n");

	switch (info_type) {
	case REPLICATION_DLG_CREATED:
		rc = dlg_replicated_create(NULL, NULL, NULL, 1);
		if_update_stat(dlg_enable_stats, create_recv, 1);
		break;

	case REPLICATION_DLG_UPDATED:
		rc = dlg_replicated_update();
		if_update_stat(dlg_enable_stats, update_recv, 1);
		break;

	case REPLICATION_DLG_DELETED:
		rc = dlg_replicated_delete();
		if_update_stat(dlg_enable_stats, delete_recv, 1);
		break;

	default:
		rc = -1;
		LM_ERR("Invalid dialog binary packet command: %d\n", info_type);
	}

	if (rc != 0)
		LM_ERR("Failed to process a binary packet!\n");
}

