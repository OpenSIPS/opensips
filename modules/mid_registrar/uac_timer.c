/*
 * timer routine which periodically generates outbound registrations
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-07-06 initial version (liviu)
 */

#include "../../locking.h"

#include "../tm/dlg.h"

#include "uac_timer.h"

static struct list_head *uac_timer_queue;
static gen_lock_t *queue_lock;

struct usrloc_api ul_api;
struct tm_binds tm_api;
struct sig_binds sig_api;

static str register_method = str_init("REGISTER");
static str contact_hdr = str_init("Contact: ");
static str expires_hdr = str_init("Expires: ");
static str expires_param = str_init(";expires=");

/* typically used to send out De-REGISTER requests */
str mid_reg_from_uri   = { "sip:registrar@localhost", 23 };

static void print_queue_entry(struct mid_reg_queue_entry *entry)
{
	LM_INFO("\n"
			"-- AoR: '%.*s', ruri: '%.*s', ct_uri: '%.*s'\n"
			"-- mc %d, fl %d\n"
			"-- e: %d, e_out: %d\n"
			"-- NOW: %ld\n"
			"-- ncheck: %d, last_reg_out: %d\n",
			entry->aor.len, entry->aor.s, entry->ruri.len, entry->ruri.s, entry->ct_uri.len, entry->ct_uri.s, entry->max_contacts, entry->flags, entry->expires, entry->expires_out, act_time, entry->next_check_ts, entry->last_register_out_ts);
}

int timer_queue_init(void)
{
	uac_timer_queue = shm_malloc(sizeof *uac_timer_queue);
	if (!uac_timer_queue) {
		LM_ERR("out of shm\n");
		return -1;
	}
	INIT_LIST_HEAD(uac_timer_queue);

	queue_lock = lock_alloc();
	lock_init(queue_lock);

	return 0;
}

void __timer_queue_add(struct mid_reg_queue_entry *te)
{
	struct list_head *it;
	struct mid_reg_queue_entry *entry;
	int found = 0;

	print_queue_entry(te);

	list_for_each(it, uac_timer_queue) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		if (te->next_check_ts <= entry->next_check_ts) {
			list_add(&te->queue, it->prev);
			found = 1;
			break;
		}
	}

	if (!found)
		list_add_tail(&te->queue, uac_timer_queue);
}

void timer_queue_add(struct mid_reg_queue_entry *te)
{
	if (!te)
		return;

	lock_get(queue_lock);
	__timer_queue_add(te);
	lock_release(queue_lock);
}

int __timer_queue_update_by_ct(ucontact_t *con, unsigned int expires)
{
	struct list_head *it;
	struct mid_reg_queue_entry *entry;

	list_for_each(it, uac_timer_queue) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		if (con == entry->con) {
			if (entry->expires != expires ||
			    entry->next_check_ts < expires + act_time) {

				print_queue_entry(entry);

				list_del(it);
				entry->expires = expires;
				entry->next_check_ts = expires + act_time;
				__timer_queue_add(entry);

				/*
				 * check if the outbound registration will
				 * expire before we're triggered again
				 *
				 * if yes, then we will have to forward this REGISTER
				 */
				if (act_time - entry->last_register_out_ts >=
				    entry->expires_out - expires) {
					entry->last_register_out_ts = act_time;
					return 1;
				}
			}

			return 0;
		}
	}

	return 1;
}

int should_relay_register(ucontact_t *con, unsigned int expires)
{
	struct list_head *it;
	struct mid_reg_queue_entry *entry;

	lock_get(queue_lock);
	list_for_each(it, uac_timer_queue) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		if (con == entry->con) {
			LM_INFO("ct match!\n");
			if (entry->expires != expires ||
	//		    entry->next_check_ts < expires + act_time)
			    entry->expires_out + entry->last_register_out_ts - act_time <= expires) {
				LM_INFO("[%d - %d], [%d - %d - %d]\n", entry->expires, expires, entry->expires_out, entry->last_register_out_ts, expires);
				lock_release(queue_lock);
				return 1;
			}

			lock_release(queue_lock);
			return 0;
		}
	}

	LM_INFO("no match for [%d - %d, %d - %d]\n", entry->expires, entry->expires_out, entry->last_register_out_ts, expires);

	lock_release(queue_lock);
	return 1;
}

int timer_queue_update_by_ct(ucontact_t *con, unsigned int expires)
{
	int rc;

	lock_get(queue_lock);
	rc = __timer_queue_update_by_ct(con, expires);
	lock_release(queue_lock);

	return rc;
}

void __timer_queue_del_contact(ucontact_t *ct)
{
	struct list_head *it;
	struct mid_reg_queue_entry *entry;

	list_for_each(it, uac_timer_queue) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		if (entry->con == ct) {
			list_del(it);
			shm_free(entry);
			return;
		}
	}
}

void timer_queue_del_contact(ucontact_t *ct)
{
	LM_INFO("----- DEL CONTACT\n");
	lock_get(queue_lock);
	__timer_queue_del_contact(ct);
	lock_release(queue_lock);
}

static inline void __print_list(struct list_head *list)
{
	struct list_head *it;
	struct mid_reg_queue_entry *entry = NULL;

	list_for_each(it, list) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		LM_INFO("  %d\n", entry->next_check_ts);
	}
}

/* for debugging purposes */
void print_timer_queue(void)
{
	lock_get(queue_lock);
	__print_list(uac_timer_queue);
	lock_release(queue_lock);
}

char extra_hdrs_buf[512];
static str extra_hdrs={extra_hdrs_buf, 512};

void build_unregister_hdrs(struct mid_reg_queue_entry *entry)
{
	char *p;

	p = extra_hdrs.s;
	memcpy(p, contact_hdr.s, contact_hdr.len);
	p += contact_hdr.len;

	/* TODO FIXME - proper handling */
	*p = '<'; p++;
	memcpy(p, entry->ct_uri.s, entry->ct_uri.len);
	p += entry->ct_uri.len;
	if (1) {
		/* adding exiration time as a parameter */
		memcpy(p, expires_param.s, expires_param.len);
		p += expires_param.len;
	} else {
		/* adding exiration time as a header */
		memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;
		memcpy(p, expires_hdr.s, expires_hdr.len);
		p += expires_hdr.len;
	}

	*p++ = '0';
	memcpy(p, CRLF, CRLF_LEN); p += CRLF_LEN;

	extra_hdrs.len = (int)(p - extra_hdrs.s);
}

void reg_tm_cback(struct cell *t, int type, struct tmcb_params *ps)
{
	LM_INFO(">> [REPLY] UNREGISTER !\n");
}

void unregister_contact(struct mid_reg_queue_entry *entry)
{
	dlg_t *dlg;
	int result;

	/* create a mystical dialog in preparation for our De-REGISTER */
	if (tm_api.new_auto_dlg_uac(&entry->from, entry->to.s ? &entry->to : &entry->ruri, &entry->callid, NULL, &dlg)) {
		LM_ERR("failed to create new TM dlg\n");
		return;
	}
	dlg->state = DLG_CONFIRMED;

	build_unregister_hdrs(entry);

	result = tm_api.t_request_within(
		&register_method,	/* method */
		&extra_hdrs,		/* extra headers*/
		NULL,			/* body */
		dlg,		/* dialog structure*/
		reg_tm_cback,		/* callback function */
		NULL,	/* callback param */
		NULL);	/* function to release the parameter */
	LM_DBG("result=[%d]\n", result);
}

void mid_reg_uac(unsigned int ticks, void *attr)
{
	struct list_head *it, *next, unreg = LIST_HEAD_INIT(unreg);
	struct mid_reg_queue_entry *entry;
	time_t now;

	/**
	 * TODO
	 *
	 * - write_lock(pending_reg)
	 * - for each entry <= "ticks" in global "pending_reg" list:
	 *		*	detach entry from list
	 *		*	if contacts(urec) == 0:
	 *				free(entry)
	 *				unref(urecord_t)
	 *			else:
	 *				Re-REGISTER w/ tm_binds
	 *				update(entry->next_check_ts)
	 *				insert_prio_queue(entry)
	 * - write_unlock(pending_reg)
	 */
	now = time(NULL);

	LM_INFO("++++++++++++ BEFORE +++++++++++++++\n");

	print_timer_queue();

	/*
	 * detach and process all expired contacts which have not been properly
	 * De-REGISTERED by their end-user devices
	 */
	lock_get(queue_lock);
	if (list_is_singular(uac_timer_queue)) {
		entry = list_entry(uac_timer_queue->next,
		                   struct mid_reg_queue_entry, queue);
		if (now >= entry->next_check_ts) {
			list_add(uac_timer_queue->next, &unreg);
			INIT_LIST_HEAD(uac_timer_queue);
		}
	} else {
		list_for_each(it, uac_timer_queue) {
			entry = list_entry(it, struct mid_reg_queue_entry, queue);
			if (now < entry->next_check_ts) {
				list_cut_position(&unreg, uac_timer_queue, it->prev);
				break;
			}
		}
	}
	lock_release(queue_lock);

	LM_INFO("++++++++++++ AFTER QUEUE +++++++++++++++\n");
	print_timer_queue();
	LM_INFO("++++++++++++ AFTER DETACH +++++++++++++++\n");
	__print_list(&unreg);

	/* properly De-REGISTER all these contacts from the final registrar */
	list_for_each_safe(it, next, &unreg) {
		LM_INFO("sending De-REGISTER ...\n");
		entry = list_entry(it, struct mid_reg_queue_entry, queue);

		/* TODO: send REGISTER with "tm"
		 * question: is multi-registering from 1 x process enough?!
		 */
		unregister_contact(entry);

		list_del(it);
		shm_free(it);
	}

	LM_INFO("++++++++++++ FINAL QUEUE +++++++++++++++\n");
	print_timer_queue();

	return;
}
