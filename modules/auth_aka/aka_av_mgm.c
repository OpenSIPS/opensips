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

/* CacheDB AV TTL (set from pending_timeout) */
static int aka_cdb_av_ttl = 30;

/* CacheDB key prefix */
#define AKA_CDB_KEY_PREFIX "aka_av:"
#define AKA_CDB_KEY_PREFIX_LEN (sizeof(AKA_CDB_KEY_PREFIX) - 1)

/* Serialization delimiter */
#define AKA_CDB_DELIM '|'


int aka_init_mgm(int hash_size, int pending_timeout)
{
	aka_users = hash_init(hash_size);
	if (!aka_users) {
		LM_ERR("cannot create AKA users hash\n");
		return -1;
	}
	/* Add some margin to TTL for race conditions */
	aka_cdb_av_ttl = pending_timeout + 5;
	return 0;
}

/*
 * Build CacheDB key: aka_av:<impu>:<impi>:<nonce>
 * Returns allocated pkg memory that must be freed by caller
 */
static int aka_cdb_build_key(str *impu, str *impi, str *nonce, str *key)
{
	key->len = AKA_CDB_KEY_PREFIX_LEN + impu->len + 1 + impi->len + 1 + nonce->len;
	key->s = pkg_malloc(key->len + 1);
	if (!key->s) {
		LM_ERR("oom for cachedb key\n");
		return -1;
	}
	memcpy(key->s, AKA_CDB_KEY_PREFIX, AKA_CDB_KEY_PREFIX_LEN);
	memcpy(key->s + AKA_CDB_KEY_PREFIX_LEN, impu->s, impu->len);
	key->s[AKA_CDB_KEY_PREFIX_LEN + impu->len] = ':';
	memcpy(key->s + AKA_CDB_KEY_PREFIX_LEN + impu->len + 1, impi->s, impi->len);
	key->s[AKA_CDB_KEY_PREFIX_LEN + impu->len + 1 + impi->len] = ':';
	memcpy(key->s + AKA_CDB_KEY_PREFIX_LEN + impu->len + 1 + impi->len + 1,
		nonce->s, nonce->len);
	key->s[key->len] = '\0';
	return 0;
}

/*
 * Serialize AV to string: state|algmask|alg|authenticate|authorize|ck|ik
 * Returns allocated pkg memory that must be freed by caller
 */
static int aka_cdb_serialize_av(struct aka_av *av, str *value)
{
	char state_buf[16], algmask_buf[16], alg_buf[16];
	int state_len, algmask_len, alg_len;

	state_len = snprintf(state_buf, sizeof(state_buf), "%d", av->state);
	algmask_len = snprintf(algmask_buf, sizeof(algmask_buf), "%d", av->algmask);
	alg_len = snprintf(alg_buf, sizeof(alg_buf), "%d", av->alg);

	value->len = state_len + 1 + algmask_len + 1 + alg_len + 1 +
		av->authenticate.len + 1 + av->authorize.len + 1 +
		av->ck.len + 1 + av->ik.len;
	value->s = pkg_malloc(value->len + 1);
	if (!value->s) {
		LM_ERR("oom for cachedb value\n");
		return -1;
	}

	snprintf(value->s, value->len + 1, "%s%c%s%c%s%c%.*s%c%.*s%c%.*s%c%.*s",
		state_buf, AKA_CDB_DELIM,
		algmask_buf, AKA_CDB_DELIM,
		alg_buf, AKA_CDB_DELIM,
		av->authenticate.len, av->authenticate.s, AKA_CDB_DELIM,
		av->authorize.len, av->authorize.s, AKA_CDB_DELIM,
		av->ck.len, av->ck.s, AKA_CDB_DELIM,
		av->ik.len, av->ik.s);
	return 0;
}

/*
 * Parse a field from serialized string
 * Updates pos to point after the delimiter
 */
static int aka_cdb_parse_field(char *start, char *end, str *field, char **next)
{
	char *delim = memchr(start, AKA_CDB_DELIM, end - start);
	if (delim) {
		field->s = start;
		field->len = delim - start;
		*next = delim + 1;
	} else {
		/* Last field */
		field->s = start;
		field->len = end - start;
		*next = end;
	}
	return 0;
}

/*
 * Deserialize AV from string: state|algmask|alg|authenticate|authorize|ck|ik
 * Creates a new aka_av in shared memory
 */
static struct aka_av *aka_cdb_deserialize_av(str *value)
{
	struct aka_av *av;
	str field;
	char *pos, *end;
	int state, algmask, alg;
	str authenticate, authorize, ck, ik;
	char *p;

	pos = value->s;
	end = value->s + value->len;

	/* Parse state */
	aka_cdb_parse_field(pos, end, &field, &pos);
	if (str2sint(&field, &state) < 0) {
		LM_ERR("invalid state in cached AV\n");
		return NULL;
	}

	/* Parse algmask */
	aka_cdb_parse_field(pos, end, &field, &pos);
	if (str2sint(&field, &algmask) < 0) {
		LM_ERR("invalid algmask in cached AV\n");
		return NULL;
	}

	/* Parse alg */
	aka_cdb_parse_field(pos, end, &field, &pos);
	if (str2sint(&field, &alg) < 0) {
		LM_ERR("invalid alg in cached AV\n");
		return NULL;
	}

	/* Parse authenticate */
	aka_cdb_parse_field(pos, end, &authenticate, &pos);

	/* Parse authorize */
	aka_cdb_parse_field(pos, end, &authorize, &pos);

	/* Parse ck */
	aka_cdb_parse_field(pos, end, &ck, &pos);

	/* Parse ik */
	aka_cdb_parse_field(pos, end, &ik, &pos);

	/* Allocate AV structure */
	av = shm_malloc(sizeof(*av) + authenticate.len + authorize.len + ck.len + ik.len);
	if (!av) {
		LM_ERR("oom for cached AV\n");
		return NULL;
	}
	memset(av, 0, sizeof(*av));
	av->state = state;
	av->algmask = algmask;
	av->alg = alg;

	p = av->buf;
	av->authenticate.s = p;
	av->authenticate.len = authenticate.len;
	memcpy(p, authenticate.s, authenticate.len);
	p += authenticate.len;

	av->authorize.s = p;
	av->authorize.len = authorize.len;
	memcpy(p, authorize.s, authorize.len);
	p += authorize.len;

	av->ck.s = p;
	av->ck.len = ck.len;
	memcpy(p, ck.s, ck.len);
	p += ck.len;

	av->ik.s = p;
	av->ik.len = ik.len;
	memcpy(p, ik.s, ik.len);

	INIT_LIST_HEAD(&av->list);
	av->ts = av->new_ts = get_ticks();

	LM_DBG("deserialized AV state=%d algmask=%d alg=%d nonce=%.*s\n",
		av->state, av->algmask, av->alg, av->authenticate.len, av->authenticate.s);
	return av;
}

/*
 * Store AV in CacheDB
 */
int aka_cdb_store_av(str *impu, str *impi, struct aka_av *av)
{
	str key, value;
	int ret = -1;

	if (!aka_cdb) {
		return 0; /* CacheDB not configured, silently succeed */
	}

	if (aka_cdb_build_key(impu, impi, &av->authenticate, &key) < 0)
		return -1;

	if (aka_cdb_serialize_av(av, &value) < 0) {
		pkg_free(key.s);
		return -1;
	}

	LM_DBG("storing AV key=%.*s ttl=%d\n", key.len, key.s, aka_cdb_av_ttl);
	if (aka_cdbf.set(aka_cdb, &key, &value, aka_cdb_av_ttl) < 0) {
		LM_ERR("failed to store AV in cachedb\n");
	} else {
		ret = 0;
	}

	pkg_free(key.s);
	pkg_free(value.s);
	return ret;
}

/*
 * Fetch AV from CacheDB
 * Returns new AV allocated in shm memory, or NULL if not found
 */
struct aka_av *aka_cdb_fetch_av(str *impu, str *impi, str *nonce)
{
	str key, value;
	struct aka_av *av = NULL;

	if (!aka_cdb) {
		return NULL; /* CacheDB not configured */
	}

	if (aka_cdb_build_key(impu, impi, nonce, &key) < 0)
		return NULL;

	value.s = NULL;
	value.len = 0;

	LM_DBG("fetching AV key=%.*s\n", key.len, key.s);
	if (aka_cdbf.get(aka_cdb, &key, &value) <= 0 || value.s == NULL) {
		LM_DBG("AV not found in cachedb for key=%.*s\n", key.len, key.s);
		pkg_free(key.s);
		return NULL;
	}

	av = aka_cdb_deserialize_av(&value);
	if (av) {
		LM_DBG("fetched AV from cachedb key=%.*s state=%d\n",
			key.len, key.s, av->state);
	}

	pkg_free(key.s);
	pkg_free(value.s);
	return av;
}

/*
 * Remove AV from CacheDB
 */
int aka_cdb_remove_av(str *impu, str *impi, str *nonce)
{
	str key;
	int ret = -1;

	if (!aka_cdb) {
		return 0; /* CacheDB not configured, silently succeed */
	}

	if (aka_cdb_build_key(impu, impi, nonce, &key) < 0)
		return -1;

	LM_DBG("removing AV key=%.*s\n", key.len, key.s);
	if (aka_cdbf.remove(aka_cdb, &key) < 0) {
		LM_DBG("failed to remove AV from cachedb (may not exist)\n");
	} else {
		ret = 0;
	}

	pkg_free(key.s);
	return ret;
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

static struct aka_user_impi *aka_user_impi_new(str *private_id)
{
	struct aka_user_impi *impi = shm_malloc(sizeof *impi + private_id->len);
	if (!impi) {
		LM_ERR("oom for user public identity!\n");
		return NULL;
	}
	impi->impi.s = impi->buf;
	impi->impi.len = private_id->len;
	memcpy(impi->impi.s, private_id->s, private_id->len);
	INIT_LIST_HEAD(&impi->impus);
	return impi;
}

static struct aka_user *aka_user_new(struct aka_user_impi *impi, str *public_id)
{
	struct aka_user *user = shm_malloc(sizeof *user + public_id->len);
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
	user->impi = impi;
	user->impu.s = user->buf;
	user->impu.len = public_id->len;
	memcpy(user->impu.s, public_id->s, public_id->len);
	INIT_LIST_HEAD(&user->list);
	INIT_LIST_HEAD(&user->avs);
	INIT_LIST_HEAD(&user->async);
	list_add(&user->list, &impi->impus);
	return user;
}

static void aka_user_impi_release(struct aka_user_impi *impi)
{
	if (!list_empty(&impi->impus))
		return;
	/* no more privates pointing to us - remove and release */
	hash_remove_key(aka_users, impi->impi);
	shm_free(impi);
}

static struct aka_user *aka_user_impi_find(struct aka_user_impi *impi, str *public_id)
{
	struct aka_user *user;
	struct list_head *it;

	list_for_each(it, &impi->impus) {
		user = list_entry(it, struct aka_user, list);
		if (str_match(public_id, &user->impu))
			return user;
	}
	return NULL;
}

struct aka_user *aka_user_find(str *public_id, str *private_id)
{
	struct aka_user *user = NULL;
	struct aka_user_impi **impi;
	unsigned int hentry = hash_entry(aka_users, *private_id);

	hash_lock(aka_users, hentry);
	impi = (struct aka_user_impi **)hash_find(aka_users, hentry, *private_id);
	if (impi && *impi) {
		user = aka_user_impi_find(*impi, public_id);
		if (user)
			user->ref++;
	}
	hash_unlock(aka_users, hentry);
	return user;
}

struct aka_user *aka_user_get(str *public_id, str *private_id)
{
	unsigned int hentry;
	struct aka_user_impi **impi;
	struct aka_user *user = NULL;

	hentry = hash_entry(aka_users, *private_id);
	hash_lock(aka_users, hentry);
	impi = (struct aka_user_impi **)hash_get(aka_users, hentry, *private_id);
	if (!impi)
		goto end;
	if (*impi) {
		user = aka_user_impi_find(*impi, public_id);
		if (user)
			goto ref;
	} else {
		*impi = aka_user_impi_new(private_id);
		if (*impi == NULL) {
			LM_ERR("cannot create user private identity!\n");
			goto end;
		}
	}
	user = aka_user_new(*impi, public_id);
	if (!user) {
		LM_ERR("cannot create user privte identity!\n");
		aka_user_impi_release(*impi);
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
	struct aka_user_impi *impi = user->impi;
	cond_lock(&user->cond);
	if (user->ref != 0 || !list_empty(&user->avs) || !list_empty(&user->async)) {
		cond_unlock(&user->cond);
		return;
	}
	cond_unlock(&user->cond);
	list_del(&user->list);
	cond_destroy(&user->cond);
	shm_free(user);
	/* release pub if not used anymore */
	aka_user_impi_release(impi);
}

void aka_user_release(struct aka_user *user)
{
	unsigned int hentry;
	hentry = hash_entry(aka_users, user->impi->impi);
	hash_lock(aka_users, hentry);
	user->ref--;
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

	/* If not found locally, try CacheDB */
	if (!av && aka_cdb) {
		LM_DBG("AV not found locally, checking CacheDB for nonce=%.*s\n",
			nonce->len, nonce->s);
		av = aka_cdb_fetch_av(&user->impu, &user->impi->impi, nonce);
		if (av) {
			/* Check algorithm compatibility */
			if (algmask >= 0 && av->algmask >= 0 && !(algmask & av->algmask)) {
				LM_DBG("AV found in CacheDB but algorithm mismatch\n");
				shm_free(av);
				return NULL;
			}
			/* Check state - only USING or USED states are valid for authorization */
			if (av->state != AKA_AV_USING && av->state != AKA_AV_USED) {
				LM_DBG("AV found in CacheDB but invalid state %d\n", av->state);
				shm_free(av);
				return NULL;
			}
			/* Insert into local user's AV list */
			cond_lock(&user->cond);
			av->state = AKA_AV_USED;
			aka_av_insert(user, av);
			cond_unlock(&user->cond);
			LM_DBG("AV fetched from CacheDB and inserted locally\n");
		}
	}

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
	av->ts = get_ticks();
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
					clock_gettime(CLOCK_REALTIME, &begin);
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
					if (*av == NULL) {
						/* compute the drift/reminder */
						clock_gettime(CLOCK_REALTIME, &end);
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
	/* Update CacheDB with USING state after releasing lock */
	if (ret == 1 && *av) {
		aka_cdb_store_av(&user->impu, &user->impi->impi, *av);
	}
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
	/* Update CacheDB with USING state after releasing lock */
	if (ret == 1 && *av) {
		aka_cdb_store_av(&user->impu, &user->impi->impi, *av);
	}
	return ret;
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

void aka_av_free(struct aka_av *av, str *impu, str *impi)
{
	/* Remove from CacheDB if configured */
	if (impu && impi) {
		aka_cdb_remove_av(impu, impi, &av->authenticate);
	}
	list_del(&av->list);
	shm_free(av);
}

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
	av->ts = av->new_ts = get_ticks();
	ret = 1;
	LM_DBG("adding av %p\n", av);

	/* Store AV in CacheDB for cross-node synchronization */
	if (aka_cdb_store_av(pub_id, priv_id, av) < 0) {
		LM_WARN("failed to store AV in cachedb, cross-node auth may fail\n");
	}
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
	av->ts = av->new_ts; /* restore the new timestamp */
	cond_unlock(&user->cond);

	/* Update state in CacheDB */
	aka_cdb_store_av(&user->impu, &user->impi->impi, av);
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
	struct list_head *it, *safe, *uit, *usafe;
	unsigned int ticks = *(unsigned int*)param;
	struct aka_user *user;
	struct aka_user_impi *impi = (struct aka_user_impi *)value;

	list_for_each_safe(uit, usafe, &impi->impus) {
		user = list_entry(uit, struct aka_user, list);
		cond_lock(&user->cond);
		list_for_each_safe(it, safe, &user->async) {
			aka_check_expire_async(ticks, it);
		}
		list_for_each_safe(it, safe, &user->avs) {
			aka_check_expire_av(ticks, list_entry(it, struct aka_av, list),
				&user->impu, &user->impi->impi);
		}
		cond_unlock(&user->cond);
		aka_user_try_free(user);
	}
	return 0;
}

void aka_async_expire(unsigned int ticks, void* param)
{
	hash_for_each_locked(aka_users, aka_async_hash_iterator, &ticks);
}
