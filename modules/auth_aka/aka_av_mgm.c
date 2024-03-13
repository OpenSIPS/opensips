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

#include "../../ut.h"
#include "../../lib/hash.h"
#include "aka_av_mgm.h"
#include "auth_aka.h"
#include <math.h>

static gen_hash_t *aka_users;
OSIPS_LIST_HEAD(aka_av_managers);


int aka_init_mgm(int hash_size)
{
	aka_users = hash_init(hash_size);
	if (!aka_users) {
		LM_ERR("cannot create AKA users hash\n");
		return -1;
	}
	return 0;
}


struct aka_av_mgm *aka_get_mgm(str *name)
{
	struct list_head *it;
	struct aka_av_mgm *mgm;
	list_for_each(it, &aka_av_managers) {
		mgm = list_entry(it, struct aka_av_mgm, list);
		if (str_casematch(&mgm->name, name))
			return mgm;
	}
	return 0;
}

typedef int (*load_aka_av_mgm_f)(struct aka_av_binds *binds);

struct aka_av_mgm *aka_load_mgm(str *name)
{
	char *aka_av_name;
	struct aka_av_mgm *mgm = NULL;
	load_aka_av_mgm_f load_aka_av_mgm;

	aka_av_name = pkg_malloc(sizeof(AKA_AV_MGM_PREFIX) + name->len);
	if (!aka_av_name) {
		LM_ERR("oom for AKA AV name\n");
		return NULL;
	}
	memcpy(aka_av_name, AKA_AV_MGM_PREFIX, sizeof(AKA_AV_MGM_PREFIX) - 1);
	memcpy(aka_av_name + sizeof(AKA_AV_MGM_PREFIX) - 1, name->s, name->len);
	aka_av_name[sizeof(AKA_AV_MGM_PREFIX) - 1 + name->len] = '\0';

	load_aka_av_mgm = (load_aka_av_mgm_f)find_export(aka_av_name, 0);
	if (!load_aka_av_mgm) {
		LM_DBG("could not find binds for AV mgm <%.*s>(%s)\n",
				name->len, name->s, aka_av_name);
		pkg_free(aka_av_name);
		return NULL;
	}
	pkg_free(aka_av_name);
	/* found it - let's create it */
	mgm = pkg_malloc(sizeof *mgm + name->len);
	if (!mgm) {
		LM_ERR("oom for AV mgm\n");
		return NULL;
	}
	memset(mgm, 0, sizeof *mgm);
	mgm->name.s = mgm->buf;
	memcpy(mgm->name.s, name->s, name->len);
	mgm->name.len = name->len;
	if (load_aka_av_mgm(&mgm->binds) < 0) {
		LM_ERR("could not load %.*s AV bindings\n",
				name->len, name->s);
		pkg_free(mgm);
		return NULL;
	}

	return mgm;
}

static struct aka_user_pub *aka_user_pub_new(str *public_id)
{
	struct aka_user_pub *pub = shm_malloc(sizeof *pub + public_id->len);
	if (!pub) {
		LM_ERR("oom for user public identity!\n");
		return NULL;
	}
	pub->impu.s = pub->buf;
	pub->impu.len = public_id->len;
	memcpy(pub->impu.s, public_id->s, public_id->len);
	INIT_LIST_HEAD(&pub->privates);
	return pub;
}

static struct aka_user *aka_user_new(struct aka_user_pub *pub, str *private_id)
{
	struct aka_user *user = shm_malloc(sizeof *user + private_id->len);
	if (!user) {
		LM_ERR("oom for user public identity!\n");
		return NULL;
	}
	memset(user, 0, sizeof *user);
	if (cond_init(&user->cond) != 0) {
		LM_ERR("could not initialize user cond\n");
		shm_free(user);
		return NULL;
	}
	user->public = pub;
	user->impi.s = user->buf;
	user->impi.len = private_id->len;
	memcpy(user->impi.s, private_id->s, private_id->len);
	INIT_LIST_HEAD(&user->list);
	INIT_LIST_HEAD(&user->avs);
	INIT_LIST_HEAD(&user->async);
	list_add(&user->list, &pub->privates);
	return user;
}

static void aka_user_pub_release(struct aka_user_pub *pub)
{
	if (!list_empty(&pub->privates))
		return;
	/* no more privates pointing to us - remove and release */
	hash_remove_key(aka_users, pub->impu);
	shm_free(pub);
}

static struct aka_user *aka_user_pub_find(struct aka_user_pub *pub, str *private_id)
{
	struct aka_user *user;
	struct list_head *it;

	list_for_each(it, &pub->privates) {
		user = list_entry(it, struct aka_user, list);
		if (str_match(private_id, &user->impi))
			return user;
	}
	return NULL;
}

struct aka_user *aka_user_find(str *public_id, str *private_id)
{
	struct aka_user *user = NULL;
	struct aka_user_pub **pub;
	unsigned int hentry = hash_entry(aka_users, *public_id);

	hash_lock(aka_users, hentry);
	pub = (struct aka_user_pub **)hash_find(aka_users, hentry, *public_id);
	if (pub && *pub) {
		user = aka_user_pub_find(*pub, private_id);
		if (user)
			user->ref++;
	}
	hash_unlock(aka_users, hentry);
	return user;
}

struct aka_user *aka_user_get(str *public_id, str *private_id)
{
	unsigned int hentry;
	struct aka_user_pub **pub;
	struct aka_user *user = NULL;

	hentry = hash_entry(aka_users, *public_id);
	hash_lock(aka_users, hentry);
	pub = (struct aka_user_pub **)hash_get(aka_users, hentry, *public_id);
	if (!pub)
		goto end;
	if (*pub) {
		user = aka_user_pub_find(*pub, private_id);
		if (user)
			goto ref;
	} else {
		*pub = aka_user_pub_new(public_id);
		if (*pub == NULL) {
			LM_ERR("cannot create user public identity!\n");
			goto end;
		}
	}
	user = aka_user_new(*pub, private_id);
	if (!user) {
		LM_ERR("cannot create user public identity!\n");
		aka_user_pub_release(*pub);
		goto end;
	}
ref:
	user->ref++;
end:
	hash_unlock(aka_users, hentry);
	return user;
}

static void aka_user_try_free(struct aka_user *user)
{
	struct aka_user_pub *pub = user->public;
	cond_lock(&user->cond);
	if (!list_empty(&user->avs) || !list_empty(&user->async)) {
		cond_unlock(&user->cond);
		return;
	}
	cond_unlock(&user->cond);
	list_del(&user->list);
	cond_destroy(&user->cond);
	shm_free(user);
	/* release pub if not used anymore */
	aka_user_pub_release(pub);
}

void aka_user_release(struct aka_user *user)
{
	unsigned int hentry;
	hentry = hash_entry(aka_users, user->public->impu);
	hash_lock(aka_users, hentry);
	user->ref--;
	if (user->ref == 0)
		aka_user_try_free(user);
	hash_unlock(aka_users, hentry);
}

static struct aka_av *aka_av_get_state(struct aka_user *user, int algmask, enum aka_av_state state)
{
	struct list_head *it;
	struct aka_av *av = NULL;

	/* find the first free AV */
	list_for_each(it, &user->avs) {
		av = list_entry(it, struct aka_av, list);
		/* check if AV algorithm is suitable */
		if (algmask >= -1 && av->algmask >= 0 && !(algmask & av->algmask)) {
			av = NULL;
			continue;
		}
		if (av->state == state)
			break;
		av = NULL;
	}
	return av;
}

static struct aka_av *aka_av_match(struct aka_user *user, int algmask, str *nonce)
{
	struct list_head *it;
	struct aka_av *av = NULL;

	list_for_each(it, &user->avs) {
		av = list_entry(it, struct aka_av, list);
		if (av->state == AKA_AV_INVALID)
			continue;
		/* check if AV algorithm is suitable */
		if (algmask >= 0 && av->algmask >= 0 && !(algmask & av->algmask))
			continue;
		if (str_match(nonce, &av->authenticate))
			return av;
	}
	return NULL;
}

struct aka_av *aka_av_get_nonce(struct aka_user *user, int algmask, str *nonce)
{
	struct aka_av *av = NULL;

	cond_lock(&user->cond);
	av = aka_av_match(user, algmask, nonce);
	if (av) {
		if (av->state != AKA_AV_USING && av->state != AKA_AV_USED)
			av = NULL;
		else
			av->state = AKA_AV_USED;
	}
	cond_unlock(&user->cond);
	return av;
}

static inline int aka_av_first_bit_mask(int algmask)
{
	int c;
	for (c = 0; c < sizeof(algmask) * 8; c++)
		if (algmask & (1<<c))
			return c;
	return 0;
}

static void aka_av_mark_using(struct aka_av *av, int algmask)
{
	av->state = AKA_AV_USING;
	/*
	 * an algorithm can only be used for one algorithm, so we mark
	 * it as being used only for the first algorithm in the mask
	 */
	av->alg = aka_av_first_bit_mask(algmask);
}

int aka_av_get_new_wait(struct aka_user *user, int algmask,
		long milliseconds, struct aka_av **av)
{
	int ret = -1;
	struct timespec spec, end, begin;

	cond_lock(&user->cond);
	if (user->error_count) {
		user->error_count--;
		goto end;
	}
	*av = aka_av_get_state(user, algmask, AKA_AV_NEW);
	if (*av == NULL) {
		switch (milliseconds) {
			case 0: /* just peaking */
				break;
			case -1: /* blocking pop */
				do {
					if (user->error_count) {
						user->error_count--;
						goto end;
					}
					cond_wait(&user->cond);
				} while ((*av = aka_av_get_state(user, algmask, AKA_AV_NEW)) == NULL);
				break;
			default:
				do {
					timespec_get(&begin, TIME_UTC);
					spec = begin;
					spec.tv_sec += milliseconds / 1000;
					spec.tv_nsec += (milliseconds % 1000) * 1000000;
					errno = 0;
					cond_timedwait(&user->cond, &spec);
					if (user->error_count) {
						user->error_count--;
						goto end;
					}
					*av = aka_av_get_state(user, algmask, AKA_AV_NEW); /* one last time */
					if (cond_has_timedout(&user->cond))
						break;
					if (!av) {
						/* compute the drift/reminder */
						timespec_get(&end, TIME_UTC);
						milliseconds -= (end.tv_sec - begin.tv_sec) * 1000 +
							(end.tv_nsec - begin.tv_nsec) / 1000000;
					}
				} while (*av == NULL && milliseconds > 0);
				break;
		}
	}
	if (*av) {
		aka_av_mark_using(*av, algmask);
		ret = 1;
	} else {
		ret = 0;
	}
end:
	cond_unlock(&user->cond);
	return ret;
}

int aka_av_get_new(struct aka_user *user, int algmask, struct aka_av **av)
{
	int ret;
	cond_lock(&user->cond);
	if (!user->error_count) {
		ret = 0;
		*av = aka_av_get_state(user, algmask, AKA_AV_NEW);
		if (*av) {
			aka_av_mark_using(*av, algmask);
			ret = 1;
		}
	} else {
		/* account for one error */
		ret = -1;
		user->error_count--;
	}
	cond_unlock(&user->cond);
	return ret;
}

static inline int aka_check_algmask(int algmask, int flags,
		int len, int check_len, const char *debug)
{
	if (algmask & flags) {
		if (len != check_len) {
			LM_WARN("invalid authorize length %d, expected %d for MD5 hashing\n",
					len, check_len);
			algmask &= ~(flags);
		}
	}
	return algmask;
}

static struct aka_av *aka_av_new(int algmask, str *authenticate, str *authorize, str *ck, str *ik)
{
	char *p;
	unsigned char *hex, *b64;
	struct aka_av *av = NULL;
	int b64len;

	b64len = calc_base64_encode_len(authenticate->len / 2);
	hex = pkg_malloc((authenticate->len / 2) + b64len);
	if (!hex) {
		LM_ERR("oom for authenticate encoding\n");
		goto end;
	}
	b64 = hex + (authenticate->len / 2);
	if (hex2string(authenticate->s, authenticate->len, (char *)hex) < 0) {
		LM_ERR("could not hexa decode %.*s\n", authenticate->len, authenticate->s);
		goto end;
	}
	base64encode(b64, hex, (authenticate->len / 2));
	av = shm_malloc(sizeof(*av) + b64len + (authorize->len / 2) + ck->len + ik->len);
	if (!av)
		goto end;
	memset(av, 0, sizeof *av);
	av->algmask = algmask;
	p = av->buf;
	av->authenticate.s = p;
	av->authenticate.len = b64len;
	memcpy(p, b64, b64len);
	p += b64len;

	av->authorize.s = p;
	if (hex2string(authorize->s, authorize->len, av->authorize.s) < 0) {
		LM_ERR("could not hexa decode %.*s\n", authorize->len, authorize->s);
		shm_free(av);
		av = NULL;
		goto end;
	}
	av->authorize.len = authorize->len / 2;
	p += av->authorize.len;

	av->ck.s = p;
	av->ck.len = ck->len;
	memcpy(p, ck->s, ck->len);
	p += ck->len;

	av->ik.s = p;
	av->ik.len = ik->len;
	memcpy(p, ik->s, ik->len);
	p += ik->len;
	INIT_LIST_HEAD(&av->list);

end:
	pkg_free(hex);
	return av;
}

#if 0
static void aka_av_free(struct aka_av *av)
{
	shm_free(av);
}
#endif

static void aka_av_insert(struct aka_user *user, struct aka_av *av)
{
	list_add_tail(&av->list, &user->avs);
}


int aka_av_add(str *pub_id, str *priv_id, int algmask,
		str *authenticate, str *authorize, str *ck, str *ik)
{
	int ret = -1;
	struct aka_av *av;
	struct aka_user *user = aka_user_get(pub_id, priv_id);
	if (!user) {
		LM_INFO("cannot find or create user %.*s/%.*s\n",
				pub_id->len, pub_id->s, priv_id->len, priv_id->s);
		return -1;
	}
	av = aka_av_new(algmask, authenticate, authorize, ck, ik);
	if (!av) {
		LM_ERR("could not create new AV\n");
		goto end;
	}
	cond_lock(&user->cond);
	aka_av_insert(user, av);
	/* we also need to inform users we have an AV */
	if (!list_empty(&user->async))
		aka_signal_async(user, user->async.next);
	cond_signal(&user->cond);
	cond_unlock(&user->cond);
	ret = 1;
end:
	aka_user_release(user);
	return ret;
}

int aka_av_drop_all_user(struct aka_user *user)
{
	int count = 0;
	struct aka_av *av;
	struct list_head *it;

	cond_lock(&user->cond);
	list_for_each(it, &user->avs) {
		av = list_entry(it, struct aka_av, list);
		if (av->state != AKA_AV_INVALID) {
			count++;
			av->state = AKA_AV_INVALID;
		}
	}
	cond_unlock(&user->cond);
	return count;
}

int aka_av_drop_all(str *pub_id, str *priv_id)
{
	int count = 0;
	struct aka_user *user = aka_user_find(pub_id, priv_id);

	if (!user) {
		LM_DBG("cannot find user %.*s/%.*s\n",
				pub_id->len, pub_id->s, priv_id->len, priv_id->s);
		return 0;
	}
	count = aka_av_drop_all_user(user);
	aka_user_release(user);
	return count;
}

int aka_av_drop(str *pub_id, str *priv_id, str *nonce)
{
	struct aka_av *av;
	struct aka_user *user = aka_user_find(pub_id, priv_id);

	if (!user) {
		LM_DBG("cannot find user %.*s/%.*s\n",
				pub_id->len, pub_id->s, priv_id->len, priv_id->s);
		return -1;
	}
	cond_lock(&user->cond);
	av = aka_av_match(user, -1, nonce);
	if (av && av->state != AKA_AV_INVALID)
		av->state = AKA_AV_INVALID;
	else
		av = NULL;
	cond_unlock(&user->cond);
	aka_user_release(user);
	return (av?1:0);
}

int aka_av_fail(str *pub_id, str *priv_id, int count)
{
	struct aka_user *user = aka_user_find(pub_id, priv_id);

	if (!user) {
		LM_DBG("cannot find user %.*s/%.*s\n",
				pub_id->len, pub_id->s, priv_id->len, priv_id->s);
		return -1;
	}
	cond_lock(&user->cond);
	user->error_count += count;
	if (!list_empty(&user->async))
		aka_signal_async(user, user->async.next);
	cond_signal(&user->cond);
	cond_unlock(&user->cond);
	aka_user_release(user);
	return 0;
}

void aka_av_set_new(struct aka_user *user, struct aka_av *av)
{
	cond_lock(&user->cond);
	av->state = AKA_AV_NEW;
	cond_unlock(&user->cond);
}

void aka_push_async(struct aka_user *user, struct list_head *subs)
{
	cond_lock(&user->cond);
	list_add_tail(subs, &user->async);
	cond_unlock(&user->cond);
}

void aka_pop_unsafe_async(struct aka_user *user, struct list_head *subs)
{
	list_del(subs);
}

void aka_pop_async(struct aka_user *user, struct list_head *subs)
{
	cond_lock(&user->cond);
	aka_pop_unsafe_async(user, subs);
	cond_unlock(&user->cond);
}

static int aka_async_hash_iterator(void *param, str key, void *value)
{
	struct list_head *it, *safe, *uit;
	unsigned int ticks = *(unsigned int*)param;
	struct aka_user *user;
	struct aka_user_pub *pub = (struct aka_user_pub *)value;

	list_for_each(uit, &pub->privates) {
		user = list_entry(uit, struct aka_user, list);
		cond_lock(&user->cond);
		list_for_each_safe(it, safe, &user->async) {
			aka_check_expire_async(ticks, it);
		}
		cond_unlock(&user->cond);
	}
	return 0;
}

void aka_async_expire(unsigned int ticks, void* param)
{
	hash_for_each_locked(aka_users, aka_async_hash_iterator, &ticks);
}
