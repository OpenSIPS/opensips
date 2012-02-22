/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-26  created (razvancrainea)
 */

#include "../../sr_module.h"
#include "../../ut.h"
#include "../../locking.h"
#include "../../mod_fix.h"
#include "../../timer.h"
#include "../../socket_info.h"

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ratelimit.h"

/* parameters */
int rl_expire_time = RL_DEFAULT_EXPIRE;
int rl_hash_size = RL_HASHSIZE;

str rl_default_algo_s = str_init("TAILDROP");
static rl_algo_t rl_default_algo = PIPE_ALGO_NOP;

/* other functions */
static rl_algo_t get_rl_algo(str);

/* big hash table */
rl_big_htable rl_htable;

/* feedback algorithm */
static int *rl_feedback_limit;

static cachedb_funcs cdbf;
static cachedb_con *cdbc = 0;

/* returnes the idex of the pipe in our hash */
#define RL_GET_INDEX(_n)		core_hash(&(_n), NULL, rl_htable.size);

/* gets the lock associated with the hash index */
#define RL_GET_LOCK(_l) \
	lock_set_get(rl_htable.locks, ((_l) % rl_htable.locks_no))

/* releases the lock associated with the hash index */
#define RL_RELEASE_LOCK(_l) \
	lock_set_release(rl_htable.locks, ((_l) % rl_htable.locks_no))

/* retrieves the structure associated with the index and key */
#define RL_GET_PIPE(_i, _k) \
	(rl_pipe_t **)map_get(rl_htable.maps[(_i)], _k)

#define RL_FIND_PIPE(_i, _k) \
	(rl_pipe_t **)map_find(rl_htable.maps[(_i)], _k)

/* returns true if the pipe should use cachedb interface */
#define RL_USE_CDB(_p) \
	(cdbc && (_p)->algo!=PIPE_ALGO_NETWORK && (_p)->algo!=PIPE_ALGO_FEEDBACK)

/* sets the pending flag for a pipe */
#define RL_SET_PENDING(_p) ((_p)->pending++)
/* resets the pending flag for a pipe */
#define RL_RESET_PENDING(_p) ((_p)->pending--)
/* returns true if the pipe has pending state */
#define RL_IS_PENDING(_p) ((_p)->pending)



static str rl_name_buffer = {0, 0};
static inline int rl_set_name(str * name)
{
	if (name->len + db_prefix.len > rl_name_buffer.len) {
		rl_name_buffer.len = name->len + db_prefix.len;
		rl_name_buffer.s = pkg_realloc(rl_name_buffer.s,
				rl_name_buffer.len);
		if (!rl_name_buffer.s) {
			LM_ERR("cannot realloc buffer\n");
			rl_name_buffer.len = 0;
			return -1;
		}
	}
	memcpy(rl_name_buffer.s + db_prefix.len, name->s, name->len);
	rl_name_buffer.len = name->len + db_prefix.len;
	return 0;
}


/* NOTE: assumes that the pipe has been locked. If fails, releases the lock */
static int rl_change_counter(str *name, rl_pipe_t *pipe, int c)
{
	unsigned int hid = RL_GET_INDEX(*name);
	int new_counter;

	RL_SET_PENDING(pipe);
	RL_RELEASE_LOCK(hid);
	if (rl_set_name(name) < 0)
		return -1;

	/* if the command should be reset */
	/* XXX: This is not needed since add takes also negative numbers 
	if (c > 0) {
		if (cdbf.add(cdbc, &rl_name_buffer, c, rl_expire_time, &new_counter)<0){
			LM_ERR("cannot increase buffer for pipe %.*s\n",
					name->len, name->s);
			return -1;
		}
	} else {
		if (cdbf.sub(cdbc, &rl_name_buffer, c ? c : pipe->my_counter,
					rl_expire_time, &new_counter) < 0){
			LM_ERR("cannot change counter for pipe %.*s with %d\n",
					name->len, name->s, c);
			return -1;
		}
	}
	*/
	if (cdbf.add(cdbc, &rl_name_buffer, c ? c : -(pipe->my_counter),
				rl_expire_time, &new_counter) < 0){
		LM_ERR("cannot change counter for pipe %.*s with %d\n",
				name->len, name->s, c);
		return -1;
	}

	RL_GET_LOCK(hid);
	RL_RESET_PENDING(pipe);
	pipe->my_counter = c ? pipe->my_counter + c : 0;
	pipe->counter = new_counter;
	LM_DBG("changed with %d; my_counter: %d; counter: %d\n",
			c, pipe->my_counter, new_counter);

	return 0;
}

/* NOTE: assumes that the pipe has been locked. If fails, releases the lock */
static int rl_get_counter(str *name, rl_pipe_t * pipe)
{
	str res;
	unsigned int hid = RL_GET_INDEX(*name);
	int new_counter;

	RL_SET_PENDING(pipe);
	RL_RELEASE_LOCK(hid);

	if (rl_set_name(name) < 0)
		return -1;
	if (cdbf.get(cdbc, &rl_name_buffer, &res) < 0) {
		LM_ERR("cannot retrieve key\n");
		return -1;
	}
	if (str2sint(&res, &new_counter) < 0) {
		LM_ERR("invalid value %.*s - should be integer\n", res.len, res.s);
		return -1;
	}
	if (res.s)
		pkg_free(res.s);
	RL_GET_LOCK(hid);
	RL_RESET_PENDING(pipe);
	pipe->counter = new_counter;
	return 0;
}

int init_cachedb(str * db_url)
{
	if (cachedb_bind_mod(db_url, &cdbf) < 0) {
		LM_ERR("cannot bind functions for db_url %.*s\n",
				db_url->len, db_url->s);
		return -1;
	}
	if (!CACHEDB_CAPABILITY(&cdbf,
				CACHEDB_CAP_GET|CACHEDB_CAP_ADD|CACHEDB_CAP_SUB)) {
		LM_ERR("not enough capabilities\n");
		return -1;
	}
	cdbc = cdbf.init(db_url);
	if (!cdbc) {
		LM_ERR("cannot connect to db_url %.*s\n", db_url->len, db_url->s);
		return -1;
	}
	/* guessing that the name is not larger than 32 */
	rl_name_buffer.len = db_prefix.len + 32;
	rl_name_buffer.s = pkg_malloc(rl_name_buffer.len);
	if (!rl_name_buffer.s) {
		LM_ERR("no more pkg memory\n");
		rl_name_buffer.len = 0;
		return -1;
	}
	/* copy prefix - this is constant*/
	memcpy(rl_name_buffer.s, db_prefix.s, db_prefix.len);

	return 0;
}

void destroy_cachedb(void)
{
	if (cdbc)
		cdbf.destroy(cdbc);
	if (rl_name_buffer.s)
		pkg_free(rl_name_buffer.s);
}

int init_rl_table(unsigned int size)
{
	unsigned int i;

	rl_htable.maps = shm_malloc(sizeof(map_t) * size);
	if (!rl_htable.maps) {
		LM_ERR("no more shm memory\n");
		return -1;
	}

	memset(rl_htable.maps, 0, sizeof(map_t) * size);
	for (i = 0; i < size; i++) {
		rl_htable.maps[i] = map_create(AVLMAP_SHARED);
		if (!rl_htable.maps[i]) {
			LM_ERR("cannot create map index %d\n", i);
			goto error;
		}
		rl_htable.size++;
	}

	if (!rl_default_algo_s.s) {
		LM_ERR("Default algorithm was not specified\n");
		return -1;
	}
	/* resolve the default algorithm */
	rl_default_algo = get_rl_algo(rl_default_algo_s);
	if (rl_default_algo < 0) {
		LM_ERR("unknown algoritm <%.*s>\n", rl_default_algo_s.len,
				rl_default_algo_s.s);
		return -1;
	}
	LM_DBG("default algorithm is %.*s [ %d ]\n",
			rl_default_algo_s.len, rl_default_algo_s.s, rl_default_algo);

	/* if at least 25% of the size locks can't be alocated
	 * we return an error */
	for ( i = size; i > size / 4; i--) {
		rl_htable.locks = lock_set_alloc(i);
		if (!rl_htable.locks)
			continue;
		if (!lock_set_init(rl_htable.locks)) {
			lock_set_dealloc(rl_htable.locks);
			rl_htable.locks = 0;
			continue;
		}
		break;
	}

	if (!rl_htable.locks) {
		LM_ERR("unable to allocted at least %d locks for the hash table\n",
				size/4);
		goto error;
	}
	rl_htable.locks_no = i;

	LM_DBG("%d locks allocated for %d hashsize\n",
			rl_htable.locks_no, rl_htable.size);

	return 0;
error:
	mod_destroy();
	return -1;
}

/* the map between names and algorithms */
struct {
	str name;
	rl_algo_t algo;
} rl_algo_names[] = {
	{ str_init("NOP"),		PIPE_ALGO_NOP},
	{ str_init("RED"),		PIPE_ALGO_RED},
	{ str_init("TAILDROP"),	PIPE_ALGO_TAILDROP},
	{ str_init("FEEDBACK"),	PIPE_ALGO_FEEDBACK},
	{ str_init("NETWORK"),	PIPE_ALGO_NETWORK},
	{ { 0, 0 },				0},
};

static rl_algo_t get_rl_algo(str name)
{
	int i;
	if (!name.s || !name.len)
		return -1;

	for ( i = 0 ; rl_algo_names[i].name.s ; i++) {
		if (rl_algo_names[i].name.len == name.len &&
				strncasecmp(rl_algo_names[i].name.s, name.s, name.len) == 0)
			return rl_algo_names[i].algo;
	}
	return -1;
}

static str * get_rl_algo_name(rl_algo_t algo)
{
	int i;
	for (i = 0; rl_algo_names[i].name.s ; i++)
		if (rl_algo_names[i].algo == algo)
			return &rl_algo_names[i].name;
	return NULL;
}


int w_rl_check_2(struct sip_msg *_m, char *_n, char *_l)
{
	return w_rl_check_3(_m, _n, _l, NULL);
}

int w_rl_check_3(struct sip_msg *_m, char *_n, char *_l, char *_a)
{
	str name;
	int limit = 0, ret = 1, should_update = 0;
	str algorithm;
	unsigned int hash_idx;
	rl_pipe_t **pipe;

	rl_algo_t algo = -1;

	/* retrieve and check parameters */
	if (!_n || !_l) {
		LM_ERR("invalid parameters\n");
		goto end;
	}
	if (fixup_get_svalue(_m, (gparam_p)_n, &name) < 0) {
		LM_ERR("cannot retrieve identifier\n");
		goto end;
	}
	if (fixup_get_ivalue(_m, (gparam_p)_l, &limit) < 0) {
		LM_ERR("cannot retrieve limit\n");
		goto end;
	}
	algorithm.s = 0;
	if (!_a || fixup_get_svalue(_m, (gparam_p)_a, &algorithm) < 0 ||
			(algo = get_rl_algo(algorithm)) < 0) {
		algo = PIPE_ALGO_NOP;
	}

	/* get limit for FEEDBACK algorithm */
	if (algo == PIPE_ALGO_FEEDBACK) {
		lock_get(rl_lock);
		if (*rl_feedback_limit) {
			if (*rl_feedback_limit != limit) {
				LM_WARN("FEEDBACK limit should be the same for all pipes, but"
						" new limit %d differs - setting to %d\n",
						limit, *rl_feedback_limit);
				limit = *rl_feedback_limit;
			}
		} else {
			if (limit <= 0 || limit >= 100) {
				LM_ERR("invalid limit for FEEDBACK algorithm "
					"(must be between 0 and 100)\n");
				lock_release(rl_lock);
				goto end;
			}
			*rl_feedback_limit = limit;
			pid_setpoint_limit(limit);
		}
		lock_release(rl_lock);
	}

	hash_idx = RL_GET_INDEX(name);
	RL_GET_LOCK(hash_idx);

	/* try to get the value */
	pipe = RL_GET_PIPE(hash_idx, name);
	if (!pipe) {
		LM_ERR("cannot get the index\n");
		goto release;
	}

	if (!*pipe) {
		/* allocate new pipe */
		*pipe = shm_malloc(sizeof(rl_pipe_t));
		if (!*pipe) {
			LM_ERR("no more shm memory\n");
			goto release;
		}
		memset(*pipe, 0, sizeof(rl_pipe_t));
		LM_DBG("Pipe %.*s doens't exist, but was created %p\n",
				name.len, name.s, *pipe);
		if (algo == PIPE_ALGO_NETWORK)
			should_update = 1;
		(*pipe)->algo = (algo == PIPE_ALGO_NOP) ? rl_default_algo : algo;
	} else {
		LM_DBG("Pipe %.*s found: %p - last used %lu\n",
				name.len, name.s, *pipe, (*pipe)->last_used);
		if (algo != PIPE_ALGO_NOP && (*pipe)->algo != algo) {
			LM_WARN("algorithm %d different from the initial one %d for pipe "
					"%.*s", algo, (*pipe)->algo, name.len, name.s);
		}
	}

	/* set/update the limit */
	(*pipe)->limit = limit;

	/* set the last used time */
	(*pipe)->last_used = time(0);
	if (RL_USE_CDB(*pipe)) {
		/* release the counter for a while */
		if (rl_change_counter(&name, *pipe, 1) < 0) {
			LM_ERR("cannot increase counter\n");
			goto end;
		}
	} else {
		(*pipe)->counter++;
	}

	ret = rl_pipe_check(*pipe);
	LM_DBG("Pipe %.*s counter:%d load:%d limit:%d should %sbe blocked (%p)\n",
			name.len, name.s, (*pipe)->counter, (*pipe)->load,
			(*pipe)->limit, ret == 1? "NOT " : "", *pipe);

release:
	RL_RELEASE_LOCK(hash_idx);
	if (should_update) {
		lock_get(rl_lock);
		(*rl_network_count)++;
		lock_release(rl_lock);
	}
end:
	return ret;
}

/* timer housekeeping, invoked each timer interval to reset counters */
void rl_timer(unsigned int ticks, void *param)
{
	unsigned int i = 0;
	map_iterator_t it, del;
	rl_pipe_t **pipe;
	str *key;
	unsigned long now = time(0);

	/* get CPU load */
	if (get_cpuload() < 0) {
		LM_ERR("cannot update CPU load\n");
		i = 1;
	}

	lock_get(rl_lock);
	/* if CPU was successfully loaded */
	if (!i)
		do_update_load();


	/* update network if needed */
	if (*rl_network_count)
		*rl_network_load = get_total_bytes_waiting(PROTO_NONE);
	lock_release(rl_lock);

	/* iterate through each map */
	for (i = 0; i < rl_htable.size; i++) {
		RL_GET_LOCK(i);
		/* iterate through all the entries */
		if (map_first(rl_htable.maps[i], &it) < 0) {
			LM_ERR("map doesn't exist\n");
			goto next_map;
		}
		for (; iterator_is_valid(&it);) {
			pipe = (rl_pipe_t **)iterator_val(&it);
			if (!pipe || !*pipe) {
				LM_ERR("[BUG] bogus map[%d] state\n", i);
				goto next_pipe;
			}
			key = iterator_key(&it);
			if (!key) {
				LM_ERR("cannot retrieve pipe key\n");
				goto next_pipe;
			}
			/* check to see if it is expired */
			if ((*pipe)->last_used + rl_expire_time < now) {
				/* this pipe is engaged in a transaction */
				if (RL_USE_CDB(*pipe) && RL_IS_PENDING(*pipe))
					goto next_pipe;
				del = it;
				if (iterator_prev(&it) < 0) {
					LM_DBG("cannot find previous iterator\n");
					goto next_pipe;
				}
				if ((*pipe)->algo == PIPE_ALGO_NETWORK) {
					lock_get(rl_lock);
					(*rl_network_count)--;
					lock_release(rl_lock);
				}
				LM_DBG("Deleting ratelimit pipe key \"%.*s\"\n",
						key->len, key->s);
				if (*pipe != iterator_delete(&del)) {
					LM_ERR("error while deleting key\n");
				}
				/* free resources */
				shm_free(*pipe);
			} else {
				/* leave the lock if a cachedb query should be done*/
				if (RL_USE_CDB(*pipe)) {
					if (rl_get_counter(key, *pipe) < 0) {
						LM_ERR("cannot get pipe counter\n");
						RL_GET_LOCK(i);
						goto next_pipe;
					}
				}
				switch ((*pipe)->algo) {
					case PIPE_ALGO_NETWORK:
						/* handle network algo */
						(*pipe)->load =
							(*rl_network_load > (*pipe)->limit) ? -1 : 1;
						break;
				
					case PIPE_ALGO_RED:
						if ((*pipe)->limit && rl_timer_interval)
							(*pipe)->load = (*pipe)->counter /
								((*pipe)->limit * rl_timer_interval);
						break;
					default:
						break;
				}
				(*pipe)->last_counter = (*pipe)->counter;
				if (RL_USE_CDB(*pipe)) {
					if (rl_change_counter(key, *pipe, 0) < 0) {
						LM_ERR("cannot reset counter\n");
						RL_GET_LOCK(i);
					}
				} else {
					(*pipe)->counter = 0;
				}
				/* TODO delete this */
				LM_DBG("Pipe \"%.*s\" load updated to %d\n",
						key->len, key->s, (*pipe)->load);
			}
next_pipe:
			if (iterator_next(&it) < 0)
				break;
			}
next_map:
		RL_RELEASE_LOCK(i);
	}

}

struct rl_map_param {
	int limit;
	rl_algo_t algo;
};

static int rl_map_print(void *param, str key, void *value)
{
	struct mi_attr* attr;
	char* p;
	int len;
	rl_pipe_t *pipe = (rl_pipe_t *)value;
	struct mi_node * rpl = (struct mi_node *)param;
	struct mi_node * node;
	str *alg;

	if (!pipe) {
		LM_ERR("invalid pipe value\n");
		return -1;
	}

	if (!rpl) {
		LM_ERR("no reply node\n");
		return -1;
	}

	if (!key.len || !key.s) {
		LM_ERR("no key found\n");
		return -1;
	}
	LM_DBG("Algorithm is %d (%p)\n", pipe->algo, pipe);

	/* skip if no algo */
	if (pipe->algo == PIPE_ALGO_NOP)
		return 0;

	if (!(node = add_mi_node_child(rpl, 0, "PIPE", 4, 0, 0)))
		return -1;

	if (!(attr = add_mi_attr(node, MI_DUP_VALUE, "id", 2, key.s, key.len)))
		return -1;

	if (!(alg = get_rl_algo_name(pipe->algo))) {
		LM_ERR("[BUG] unknown algorithm %d\n", pipe->algo);
		return -1;
	}

	if (!(attr = add_mi_attr(node, MI_DUP_VALUE, "algorithm", 9,
					alg->s, alg->len)))
		return -1;


	p = int2str((unsigned long)(pipe->limit), &len);
	if (!(attr = add_mi_attr(node, MI_DUP_VALUE, "limit", 5, p, len)))
		return -1;

	p = int2str((unsigned long)(pipe->last_counter), &len);
	if (!(attr = add_mi_attr(node, MI_DUP_VALUE, "counter", 7, p, len)))
		return -1;

	return 0;
}

int rl_stats(struct mi_node *rpl, str * value)
{
	rl_pipe_t **pipe;
	int i;

	if (value && value->s && value->len) {
		i = RL_GET_INDEX(*value);
		RL_GET_LOCK(i);
		pipe = RL_FIND_PIPE(i, *value);
		if (!pipe || !*pipe) {
			LM_DBG("pipe %.*s not found\n", value->len, value->s);
			goto error;
		}
		if (rl_map_print(rpl, *value, *pipe)) {
			LM_ERR("cannot print value for key %.*s\n",
					value->len, value->s);
			goto error;
		}
		RL_RELEASE_LOCK(i);
	} else {
		/* iterate through each map */
		for (i = 0; i < rl_htable.size; i++) {
			RL_GET_LOCK(i);
			if (map_for_each(rl_htable.maps[i], rl_map_print, rpl)) {
				LM_ERR("cannot print values\n");
				goto error;
			}
			RL_RELEASE_LOCK(i);
		}
	}
	return 0;
error:
	RL_RELEASE_LOCK(i);
	return -1;
}


int w_rl_set_count(str key, int val)
{
	unsigned int hash_idx;
	int ret = -1;
	rl_pipe_t **pipe;

	hash_idx = RL_GET_INDEX(key);
	RL_GET_LOCK(hash_idx);

	/* try to get the value */
	pipe = RL_FIND_PIPE(hash_idx, key);
	if (!pipe || !*pipe) {
		LM_DBG("cannot find any pipe named %.*s\n", key.len, key.s);
		goto release;
	}

	if (RL_USE_CDB(*pipe)) {
		if (rl_change_counter(&key, *pipe, val) < 0) {
			LM_ERR("cannot decrease counter\n");
			return -1;
		}
	} else {
		if (val && val < (*pipe)->counter) {
			(*pipe)->counter -= val;
		} else {
			(*pipe)->counter = 0;
		}
	}

	LM_DBG("new counter for key %.*s is %d\n",
			key.len, key.s, (*pipe)->counter);

	ret = 0;

release:
	RL_RELEASE_LOCK(hash_idx);
	return ret;
}

static inline int w_rl_change_counter(struct sip_msg *_m, char *_n, int  dec)
{
	str name;

	if (!_n || fixup_get_svalue(_m, (gparam_p)_n, &name) < 0) {
		LM_ERR("cannot retrieve identifier\n");
		return -1;
	}
	if (w_rl_set_count(name, dec)) {
		LM_ERR("cannot find any pipe named %.*s\n", name.len, name.s);
		return -1;
	}
	return 1;
}

int w_rl_dec(struct sip_msg *_m, char *_n)
{
	return w_rl_change_counter(_m, _n, -1);
}

int w_rl_reset(struct sip_msg *_m, char *_n)
{
	return w_rl_change_counter(_m, _n, 0);
}

