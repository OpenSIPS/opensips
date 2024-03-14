/*
 * AKA Authentication - generic Authentication Manager support
 *
 * Copyright (C) 2024 Razvan Crainea
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
 */

#ifndef AUTH_AKA_H
#define AUTH_AKA_H

#include "../../lib/cond.h"
#include "../../lib/list.h"
#include "../../parser/digest/digest_parser.h"
#include "../../lib/digest_auth/digest_auth.h"
#include "aka_av_mgm.h"

enum aka_user_state {
	AKA_USER_STATE_INIT = 0,
};

enum aka_av_state {
	AKA_AV_NEW = 0,
	AKA_AV_USING,
	AKA_AV_USED,
	AKA_AV_INVALID,
};

struct aka_av {
	enum aka_av_state state;
	str authenticate;
	str authorize;
	str ck;
	str ik;
	alg_t alg;    /* algorithm that this AV is being challenged for */
	int algmask;  /* algorithms this AV is suitable for */
	time_t ts;
	struct list_head list;
	char buf[0];
};

struct aka_user_pub {
	str impu;
	struct list_head privates;
	char buf[0];
};

struct aka_user {
	enum aka_user_state state;
	unsigned int ref;
	str impi;
	int error_count;
	struct aka_user_pub *public;
	struct list_head avs;
	struct list_head list;
	struct list_head async;
	gen_cond_t cond;
	char buf[0];
};

struct aka_av_mgm {
	str name;
	struct aka_av_binds binds;
	struct list_head list;
	char buf[0];
};



int aka_init_mgm(int hash_size);

struct aka_av_mgm *aka_get_mgm(str *name);
struct aka_av_mgm *aka_load_mgm(str *name);

/* returns a user structure identified by user IMPU and IMPI */
struct aka_user *aka_user_get(str *public_id, str *private_id);
struct aka_user *aka_user_find(str *public_id, str *private_id);
void aka_user_release(struct aka_user *user);

/* gets an AV for a specific user */
void aka_av_set_new(struct aka_user *user, struct aka_av *av);
int aka_av_get_new(struct aka_user *user, int algmask, struct aka_av **av);
int aka_av_get_new_wait(struct aka_user *user, int algmask,
		long milliseconds, struct aka_av **av);
struct aka_av *aka_av_get_nonce(struct aka_user *user, int algmask, str *nonce);

int aka_av_add(str *pub_id, str *priv_id, int algmask, str *authenticate,
		str *authorize, str *ck, str *ik);
int aka_av_drop(str *pub_id, str *priv_id, str *nonce);
int aka_av_fail(str *pub_id, str *priv_id, int no);
int aka_av_drop_all(str *pub_id, str *priv_id);
int aka_av_drop_all_user(struct aka_user *user);

void aka_push_async(struct aka_user *user, struct  list_head *subs);
void aka_pop_async(struct aka_user *user, struct  list_head *subs);
void aka_pop_unsafe_async(struct aka_user *user, struct  list_head *subs);
void aka_signal_async(struct aka_user *user, struct  list_head *subs);
void aka_check_expire_async(unsigned int ticks, struct list_head *subs);
void aka_check_expire_av(unsigned int ticks, struct aka_av *av);
void aka_av_free(struct aka_av *av);

void aka_async_expire(unsigned int ticks, void* param);

#endif /* AUTH_AKA_H */
