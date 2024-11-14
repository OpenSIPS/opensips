/*
 * Copyright (C) 2023 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#ifndef _B2B_UA_API_
#define _B2B_UA_API_

#define UA_FL_IS_UA_ENTITY     (1<<0)
#define UA_FL_REPORT_ACK       (1<<1)
#define UA_FL_REPORT_REPLIES   (1<<2)
#define UA_FL_DISABLE_AUTO_ACK (1<<3)
#define UA_FL_PROVIDE_HDRS     (1<<4)
#define UA_FL_PROVIDE_BODY     (1<<5)
#define UA_FL_SUPPRESS_NEW     (1<<6)

#define UA_SESSION_DEFAULT_TIMEOUT (60 * 60 * 12)

enum ua_sess_event_type {
	UA_SESS_EV_NEW,
	UA_SESS_EV_EARLY,
	UA_SESS_EV_ANSWERED,
	UA_SESS_EV_REJECTED,
	UA_SESS_EV_UPDATED,
	UA_SESS_EV_TERMINATED
};

struct ua_sess_init_params {
	unsigned int flags;
	unsigned int timeout;
};

struct ua_sess_t_list {
	str b2b_key;
	volatile unsigned int timeout;
	struct ua_sess_t_list *next;
	struct ua_sess_t_list *prev;
};

struct ua_sess_timer {
	gen_lock_t *lock;
	struct ua_sess_t_list *first;
	struct ua_sess_t_list *last;
};

extern str adv_contact;
extern int ua_default_timeout;

int init_ua_sess_timer(void);
void destroy_ua_sess_timer(void);
void ua_dlg_timer_routine(unsigned int ticks, void* param);
struct ua_sess_t_list *insert_ua_sess_tl(str *b2b_key, unsigned int timeout);
void remove_ua_sess_tl(struct ua_sess_t_list *tl);

int ua_entity_delete(int et, str* b2b_key, int db_del, int remove_tl);
int ua_send_reply(int et, str *b2b_key, int method, int code, str *reason,
	str *body, str *content_type, str *extra_headers);
int ua_send_request(int et, str *b2b_key, str *method, str *body,
	str *content_type, str *extra_headers, unsigned int no_cb);

int fixup_ua_flags(void** param);
int fixup_free_ua_flags(void** param);

int b2b_ua_server_init(struct sip_msg *msg, pv_spec_t *key_spec,
	struct ua_sess_init_params *init_params, str *extra);
int b2b_ua_update(struct sip_msg *msg, str *key, str *method, str *body,
	str *extra_headers, str *content_type);
int b2b_ua_reply(struct sip_msg *msg, str *key, str *method, int *code,
	str *reason, str *body, str *extra_headers, str *content_type);
int b2b_ua_terminate(struct sip_msg *msg, str *key, str *extra_headers);

mi_response_t *b2b_ua_session_client_start(const mi_params_t *params,
	struct mi_handler *_);
mi_response_t *b2b_ua_mi_update(const mi_params_t *params,
	struct mi_handler *_);
mi_response_t *b2b_ua_mi_reply(const mi_params_t *params,
	struct mi_handler *_);
mi_response_t *b2b_ua_mi_terminate(const mi_params_t *params,
	struct mi_handler *_);
mi_response_t *b2b_ua_session_list(const mi_params_t *params,
	struct mi_handler *_);

int ua_evi_init(void);
int raise_ua_sess_event(str *key, enum b2b_entity_type ent_type,
	enum ua_sess_event_type ev_type, unsigned int flags, struct sip_msg *msg, str *extra);

#endif
