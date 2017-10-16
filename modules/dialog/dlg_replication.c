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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2013-04-12 initial version (Liviu)
 */

#include "dlg_hash.h"
#include "dlg_db_handler.h"
#include "dlg_profile.h"

#include "dlg_replication.h"
#include "dlg_repl_profile.h"

#include "../../resolve.h"
#include "../../forward.h"

extern int active_dlgs_cnt;
extern int early_dlgs_cnt;

extern int dlg_enable_stats;

extern stat_var *active_dlgs;
extern stat_var *processed_dlgs;

extern stat_var *create_sent;
extern stat_var *update_sent;
extern stat_var *delete_sent;
extern stat_var *create_recv;
extern stat_var *update_recv;
extern stat_var *delete_recv;

struct clusterer_binds clusterer_api;

static void dlg_replicated_profiles(struct receive_info *ri, int server_id);

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

	sock = grep_sock_info(&host, (unsigned short) port, (unsigned short) proto);
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
	int h_entry;
	unsigned int dir, dst_leg;
	str callid, from_uri, to_uri, from_tag, to_tag;
	str cseq1, cseq2, contact1, contact2, rroute1, rroute2, mangled_fu, mangled_tu;
	str sock, vars, profiles;
	struct dlg_cell *dlg = NULL;
	struct socket_info *caller_sock, *callee_sock;
	struct dlg_entry *d_entry;

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
	if_update_stat(dlg_enable_stats, processed_dlgs, 1);

	bin_pop_int(&dlg->h_id);
	bin_pop_int(&dlg->start_ts);
	bin_pop_int(&dlg->state);

	/* next_id follows the max value of all replicated ids */
	if (d_table->entries[dlg->h_entry].next_id <= dlg->h_id)
		d_table->entries[dlg->h_entry].next_id = dlg->h_id + 1;

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
	/* TODO - sdp here */
	if (dlg_add_leg_info(dlg, &from_tag, &rroute1, &contact1,
		&cseq1, caller_sock, 0, 0,0) != 0 ||
		dlg_add_leg_info(dlg, &to_tag, &rroute2, &contact2,
		&cseq2, callee_sock, &mangled_fu, &mangled_tu,0) != 0) {
		LM_ERR("dlg_set_leg_info failed\n");
		goto pre_linking_error;
	}

	dlg->legs_no[DLG_LEG_200OK] = DLG_FIRST_CALLEE_LEG;

	/* link the dialog into the hash */
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
	bin_pop_int(&dlg->mod_flags);
	bin_pop_int(&dlg->flags);
	bin_pop_int((void *) &dlg->tl.timeout);
	bin_pop_int(&dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_pop_int(&dlg->legs[callee_idx(dlg)].last_gen_cseq);

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

	if (dlg->state == DLG_STATE_CONFIRMED_NA ||
		dlg->state == DLG_STATE_CONFIRMED)
		active_dlgs_cnt++;

	/* reference the dialog as kept in the timer list */
	ref_dlg_unsafe(dlg, 1);

	LM_DBG("Received initial timeout of %d for dialog %.*s, safe = %d\n", dlg->tl.timeout, callid.len, callid.s, safe);

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
		LM_DBG("dialog not found, building new\n");

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
	bin_pop_int(&dlg->mod_flags);
	bin_pop_int(&dlg->flags);

	bin_pop_int(&timeout);
	bin_skip_int(2);

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
			ref_dlg(dlg,1);
		}
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
	next_state_dlg(dlg, DLG_EVENT_REQBYE, DLG_DIR_DOWNSTREAM, &old_state,
		&new_state, &unref, dlg->legs_no[DLG_LEG_200OK], 1);

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
	static str module_name = str_init("dialog");
	int callee_leg;
	str *vars, *profiles;

	if (bin_init(&module_name, REPLICATION_DLG_CREATED, BIN_VERSION) != 0)
		goto error;

	bin_push_int(clusterer_api.get_my_id());

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
	bin_push_int(dlg->mod_flags);
	bin_push_int(dlg->flags &
			     ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED));
	bin_push_int((unsigned int)time(0) + dlg->tl.timeout - get_ticks());
	bin_push_int(dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_push_int(dlg->legs[callee_leg].last_gen_cseq);
	dlg->replicated = 1;
	dlg_unlock_dlg(dlg);

	if (clusterer_api.send_to(dialog_replicate_cluster, PROTO_BIN) < 0)
 		goto error;

	if_update_stat(dlg_enable_stats,create_sent,1);
	return;

error:
	LM_ERR("Failed to replicate created dialog\n");
	return;

no_send:
	dlg_unlock_dlg(dlg);
	return;
}

/**
 * replicates a local dialog update to all the destinations
 * specified with the 'replicate_dialogs' modparam
 */
void replicate_dialog_updated(struct dlg_cell *dlg)
{
	static str module_name = str_init("dialog");
	int callee_leg;
	str *vars, *profiles;

	if (bin_init(&module_name, REPLICATION_DLG_UPDATED, BIN_VERSION) != 0)
		goto error;
	bin_push_int(clusterer_api.get_my_id());

	dlg_lock_dlg(dlg);
	if (dlg->state == DLG_STATE_DELETED) {
		/* we no longer need to update anything */
		LM_WARN("not replicating dlg update message due to bad state %d (%.*s)\n",
			dlg->state, dlg->callid.len, dlg->callid.s);
		dlg_unlock_dlg(dlg);
		return;
	}


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
	bin_push_int(dlg->mod_flags);
	bin_push_int(dlg->flags &
			     ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED|DLG_FLAG_VP_CHANGED));
	bin_push_int((unsigned int)time(0) + dlg->tl.timeout - get_ticks());
	bin_push_int(dlg->legs[DLG_CALLER_LEG].last_gen_cseq);
	bin_push_int(dlg->legs[callee_leg].last_gen_cseq);
	dlg->replicated = 1;
	dlg_unlock_dlg(dlg);

	if (clusterer_api.send_to(dialog_replicate_cluster, PROTO_BIN) < 0) {
		LM_ERR("replicate dialog updated failed\n");
		return;
 	}

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
	static str module_name = str_init("dialog");

	if (bin_init(&module_name, REPLICATION_DLG_DELETED, BIN_VERSION) != 0)
		goto error;

	bin_push_int(clusterer_api.get_my_id());
	bin_push_str(&dlg->callid);
	bin_push_str(&dlg->legs[DLG_CALLER_LEG].tag);
	bin_push_str(&dlg->legs[callee_idx(dlg)].tag);

	if (clusterer_api.send_to(dialog_replicate_cluster, PROTO_BIN) < 0) {
		goto error;
 	}

	if_update_stat(dlg_enable_stats, delete_sent, 1);
	return;
error:
	LM_ERR("Failed to replicate deleted dialog\n");
}

/**
 * receive_binary_packet (callback) - receives a cmd_type, specifying the
 * purpose of the data encoded in the received UDP packet
 */
void receive_prof_binary_packet(int packet_type, struct receive_info *ri,
																int server_id)
{
	char *ip;
	unsigned short port;

	if (packet_type == SERVER_TEMP_DISABLED) {
		get_su_info(&ri->src_su.s, ip, port);
		LM_INFO("server: %s:%hu temporary disabled\n", ip, port);
		return;
	}

	if (packet_type == SERVER_TIMEOUT) {
		LM_INFO("server with clusterer id %d timeout\n", server_id);
		return;
	}

	if (packet_type != REPLICATION_DLG_PROFILE) {
		LM_WARN("bad packet type\n");
		return;
	}
	dlg_replicated_profiles(ri, server_id);
}

void receive_dlg_binary_packet(int packet_type, struct receive_info *ri, void *att)
{
	int rc;
	char *ip;
	unsigned short port;
	int server_id;

	rc = bin_pop_int(&server_id);
	if (rc < 0)
		return;

	LM_DBG("Received a binary packet!\n");

	if(get_bin_pkg_version() != BIN_VERSION){
		LM_ERR("incompatible bin protocol version\n");
		return;
	}

	if (!accept_replicated_dlg) {
		get_su_info(&ri->src_su.s, ip, port);
		LM_WARN("Unwanted dialog packet received from %s:%hu (type=%d)\n",
				ip, port, packet_type);
		return;
	}

	if(!clusterer_api.check(accept_replicated_dlg, &ri->src_su, server_id, ri->proto))
		return;

	switch (packet_type) {
	case REPLICATION_DLG_CREATED:
		LM_DBG("AAAA dlg_replicated_create\n");
		rc = dlg_replicated_create(NULL, NULL, NULL, 1);
		if_update_stat(dlg_enable_stats, create_recv, 1);
		break;

	case REPLICATION_DLG_UPDATED:
		LM_DBG("AAAA dlg_replicated_update\n");
		rc = dlg_replicated_update();
		if_update_stat(dlg_enable_stats, update_recv, 1);
		break;

	case REPLICATION_DLG_DELETED:
		LM_DBG("AAAA dlg_replicated_deleted\n");
		rc = dlg_replicated_delete();
		if_update_stat(dlg_enable_stats, delete_recv, 1);
		break;

	default:
		rc = -1;
		get_su_info(&ri->src_su.s, ip, port);
		LM_WARN("Invalid dialog binary packet command: %d (from %s:%hu)\n",
			packet_type, ip, port);
	}

	if (rc != 0)
		LM_ERR("Failed to process a binary packet!\n");
}

/**
 * From now on, we only have replication for dialog profiles
 */

typedef struct repl_prof_repl_dst {
	int id;
	str dst;
	time_t *last_msg;
	union sockaddr_union to;
} repl_prof_repl_dst_t;

typedef struct repl_prof_repl_dst_new {
	int id;
	str dst;
	time_t *last_msg;
} repl_prof_repl_dst_new_t;



int repl_prof_buffer_th = DLG_REPL_PROF_BUF_THRESHOLD;
int repl_prof_utimer = DLG_REPL_PROF_TIMER;
int repl_prof_timer_check = DLG_REPL_PROF_TIMER;
int repl_prof_timer_expire = DLG_REPL_PROF_EXPIRE_TIMER;

static void repl_prof_utimer_f(utime_t ticks, void *param);
static void repl_prof_timer_f(unsigned int ticks, void *param);

int repl_prof_init(void)
{
	if (!profile_replicate_cluster && !accept_repl_profiles)
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

	if (register_timer("dialog-repl-profiles-timer", repl_prof_timer_f, NULL,
		repl_prof_timer_check, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register profiles utimer\n");
		return -1;
	}

	if (!profile_replicate_cluster)
		return 0;

	if (repl_prof_utimer < 0) {
		LM_ERR("negative replicate timer for profiles %d\n", repl_prof_utimer);
		return -1;
	}

	if (repl_prof_buffer_th < 0) {
		LM_ERR("negative replicate buffer threshold for profiles %d\n",
			repl_prof_buffer_th);
		return -1;
	}

	if (register_utimer("dialog-repl-profiles-utimer", repl_prof_utimer_f, NULL,
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
static inline void dlg_replicate_profiles(void)
{
	if (clusterer_api.send_to(profile_replicate_cluster, PROTO_BIN) < 0) {
 		goto error;
	}

	return;
error:
	LM_ERR("Failed to replicate profile dialog\n");
}

static repl_prof_count_t* find_destination(repl_prof_novalue_t *noval, int machine_id)
{
	repl_prof_count_t *head;

	head = noval->dsts;
	while(head != NULL){
		if( head->machine_id ==  machine_id )
			break;
		head=head->next;
	}

	if(head == NULL){
		head = shm_malloc(sizeof(repl_prof_count_t));
		if(head == NULL){
			LM_ERR("no more shm memory\n");
			goto error;
		}
		head->machine_id = machine_id;
		head->next = noval->dsts;
		noval->dsts = head;
	}
	return head;

error:
	return NULL;
}


static void dlg_replicated_profiles(struct receive_info *ri, int server_id)
{
	time_t now;
	str name;
	str value;
	char *ip;
	unsigned short port;
	unsigned int counter;
	struct dlg_profile_table *profile;
	int has_value;
	int i;
	void **dst;
	repl_prof_value_t *rp;
	repl_prof_count_t *destination;


	/* optimize profile search */
	struct dlg_profile_table *old_profile = NULL;
	str old_name = {NULL,0};

	now = time(0);
	//*repl_prof_dests[index].last_msg = now;

	for (;;) {
		if (bin_pop_str(&name) == 1)
			break; /* pop'ed all pipes */

		/* check if the same profile was sent */
		if (!old_profile || old_name.len != name.len ||
			memcmp(name.s, old_name.s, name.len) != 0) {
			old_profile = get_dlg_profile(&name);
			if (!old_profile) {
				get_su_info(&ri->src_su.s, ip, port);
				LM_WARN("received unknown profile <%.*s> from %s:%hu\n",
					name.len, name.s, ip, port);
			}
			old_name = name;
		}
		profile = old_profile;

		if (bin_pop_int(&has_value) < 0) {
			LM_ERR("cannot pop profile's has_value int\n");
			return;
		}

		if (has_value) {
			if (!profile->has_value) {
				get_su_info(&ri->src_su.s, ip, port);
				LM_WARN("The other end does not have a value for this profile:"
					"<%.*s> [%s:%hu]\n", profile->name.len, profile->name.s, ip, port);
				profile = NULL;
			}
			if (bin_pop_str(&value)) {
				LM_ERR("cannot pop the value of the profile\n");
				return;
			}
		}

		if (bin_pop_int(&counter) < 0) {
			LM_ERR("cannot pop profile's counter\n");
			return;
		}

		if (profile) {
			if (!profile->has_value) {
				lock_get(&profile->repl->lock);
				destination = find_destination(profile->repl, server_id);
				if(destination == NULL){
					lock_release(&profile->repl->lock);
					return;
				}
				destination->counter = counter;
				destination->update = now;
				lock_release(&profile->repl->lock);
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
					rp = shm_malloc(sizeof(repl_prof_value_t));
					if (!rp) {
						LM_ERR("no more shm memory to allocate repl_prof_value\n");
						goto release;
					}
					memset(rp, 0, sizeof(repl_prof_value_t));
					*dst = rp;
				} else {
					rp = (repl_prof_value_t *) * dst;
				}
				if (!rp->noval)
					rp->noval = repl_prof_allocate();
				if (rp->noval) {
					lock_release(&rp->noval->lock);
					destination = find_destination(rp->noval, server_id);
					if (destination == NULL) {
						lock_release(&rp->noval->lock);
						lock_set_release(profile->locks, i);
						return;
					}
					destination->counter = counter;
					destination ->update = now;
					lock_release(&rp->noval->lock);
				}
release:
				lock_set_release(profile->locks, i);
			}
		}
	}
	return;
}

static int repl_prof_add(str *name, int has_value, str *value,
													unsigned int count)
{
	int ret = 0;

	if (bin_push_str(name) < 0)
		return -1;
	/* extra size to add the value indication but it's good
	 * for servers profiles consistency checks */
	if (bin_push_int(has_value) < 0)
		return -1;
	/* the other end should already know if the profile has a value or not */
	if (value && bin_push_str(value) < 0)
		return -1;
	if ((ret = bin_push_int(count)) < 0)
		return -1;

	return ret;
}

int repl_prof_remove(str *name, str *value)
{
	static str module_name = str_init("dialog");
	if (profile_replicate_cluster <= 0)
		return 0;
	if (bin_init(&module_name, REPLICATION_DLG_PROFILE, BIN_VERSION) < 0) {
		LM_ERR("cannot initiate bin buffer\n");
		return -1;
	}

	bin_push_int(clusterer_api.get_my_id());

	if (repl_prof_add(name, value?1:0, value, 0) < 0)
		return -1;
	dlg_replicate_profiles();
	return 0;
}


int replicate_profiles_count(repl_prof_novalue_t *rp)
{
	int counter = 0;
	time_t now = time(0);
	repl_prof_count_t *head;

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

static void repl_prof_timer_f(unsigned int ticks, void *param)
{
	map_iterator_t it, del;
	unsigned int count;
	struct dlg_profile_table *profile;
	repl_prof_value_t *rp;
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
				count = repl_prof_get_all(dst);
				if (!count) {
					del = it;
					if (iterator_next(&it) < 0)
						LM_DBG("cannot find next iterator\n");
					rp = (repl_prof_value_t *) iterator_delete(&del);
					if (rp) {
						free_profile_val_t(rp);
						/*if (rp->noval)
							shm_free(rp->noval);
						shm_free(rp);*/
					}
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

static void repl_prof_utimer_f(utime_t ticks, void *param)
{
#define REPL_PROF_TRYSEND() \
	do { \
		if (ret > repl_prof_buffer_th) { \
			/* send the buffer */ \
			dlg_replicate_profiles(); \
			replicated = 1; \
			if (bin_init(&module_name, REPLICATION_DLG_PROFILE, BIN_VERSION) < 0) { \
				LM_ERR("cannot initiate bin buffer\n"); \
				return; \
			} \
			bin_push_int(clusterer_api.get_my_id()); \
		} \
	} while (0)

	struct dlg_profile_table *profile;
	static str module_name = str_init("dialog");
	map_iterator_t it;
	unsigned int count;
	int replicated = 0;
	int i;
	int ret;
	void **dst;
	str *value;

	if (bin_init(&module_name, REPLICATION_DLG_PROFILE, BIN_VERSION) < 0) {
		LM_ERR("cannot initiate bin buffer\n");
		return;
	}
	bin_push_int(clusterer_api.get_my_id());

	for (profile = profiles; profile; profile = profile->next) {
		if (!(profile->repl_type&REPL_PROTOBIN))
			continue;

		count = 0;
		if (!profile->has_value) {
			for (i = 0; i < profile->size; i++) {
				lock_set_get(profile->locks, i);
				count += profile->counts[i];
				lock_set_release(profile->locks, i);
			}

			if ((ret = repl_prof_add(&profile->name, 0, NULL, count)) < 0)
				goto error;
			/* check if the profile should be sent */
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
					count = repl_prof_get(dst);
					if ((ret = repl_prof_add(&profile->name, 1, value, count)) < 0)
						goto error;
					/* check if the profile should be sent */
					REPL_PROF_TRYSEND();

next_val:
					if (iterator_next(&it) < 0)
						break;
				}
next_entry:
				lock_set_release(profile->locks, i);
			}
		}
	}

	goto done;

error:
	LM_ERR("cannot add any more profiles in buffer\n");

done:
	/* check if there is anything else left to replicate */
	if (!replicated)
		dlg_replicate_profiles();
#undef REPL_PROF_TRYSEND
}
