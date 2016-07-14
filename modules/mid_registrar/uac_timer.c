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

	list_for_each(it, uac_timer_queue) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);
		if (te->reg_tick <= entry->reg_tick) {
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
		LM_INFO("  %d\n", entry->reg_tick);
	}
}

/* for debugging purposes */
void print_timer_queue(void)
{
	LM_INFO("----- timer list dump:\n");

	lock_get(queue_lock);
	__print_list(uac_timer_queue);
	lock_release(queue_lock);
}

//void unregister_contact(ucontact_t *con)
//{
//	dlg_t *dlg;
//
//	/* create a mystical dialog in preparation for our De-REGISTER */
//	if (tm_api.new_auto_dlg_uac(&mid_reg_from_uri, &list->dlist[j].uri,
//	list->dlist[j].sock?list->dlist[j].sock:probing_sock,
//	&dlg) != 0 ) {
//		LM_ERR("failed to create new TM dlg\n");
//		continue;
//	}
//	dlg->state = DLG_CONFIRMED;
//
//	result = tm_api.t_request_within(
//		&register_method,	/* method */
//		&extra_hdrs,		/* extra headers*/
//		NULL,			/* body */
//		&rec->td,		/* dialog structure*/
//		reg_tm_cback,		/* callback function */
//		(void *)cb_param,	/* callback param */
//		shm_free_param);	/* function to release the parameter */
//	LM_DBG("result=[%d]\n", result);
//	return result;
//}

void mid_reg_uac(unsigned int ticks, void *attr)
{
	struct list_head *it, *next, unreg = LIST_HEAD_INIT(unreg);
	struct mid_reg_queue_entry *entry;
	time_t now;

	LM_INFO("I AM CALLED: %d\n", ticks);
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
	 *				update(entry->reg_tick)
	 *				insert_prio_queue(entry)
	 * - write_unlock(pending_reg)
	 */
	now = time(NULL);

	LM_INFO("++++++++++++ BEFORE +++++++++++++++\n");

	print_timer_queue();

	/* detach the expired contacts asap */
	lock_get(queue_lock);
	if (list_is_singular(uac_timer_queue)) {
		entry = list_entry(uac_timer_queue->next,
		                   struct mid_reg_queue_entry, queue);
		if (now >= entry->reg_tick) {
			list_add(uac_timer_queue->next, &unreg);
			INIT_LIST_HEAD(uac_timer_queue);
		}
	} else {
		list_for_each(it, uac_timer_queue) {
			entry = list_entry(it, struct mid_reg_queue_entry, queue);
			if (now < entry->reg_tick) {
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

	LM_INFO("sending REGISTERs ...\n");

	/* De-REGISTER all due contacts */
	list_for_each_safe(it, next, &unreg) {
		entry = list_entry(it, struct mid_reg_queue_entry, queue);

		/* TODO: send REGISTER with "tm"
		 * question: is multi-registering from 1 x process enough?!
		 */
		//unregister_contact(entry->con);

		list_del(it);
		shm_free(it);
	}

	LM_INFO("++++++++++++ FINAL QUEUE +++++++++++++++\n");
	print_timer_queue();

	return;
}
