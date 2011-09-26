/*
 * Copyright (C) 2011 OpenSIPS Project
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

#include <stdio.h>
#include <stdlib.h>

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
	(*pipe)->counter++;

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

	/* iterate through each map */
	for (i = 0; i < rl_htable.size; i++) {
		RL_GET_LOCK(i);
		/* iterate through all the entries */
		if (map_first(rl_htable.maps[i], &it) < 0) {
			LM_ERR("map doesn't exist\n");
			goto next;
		}
		for (; iterator_is_valid(&it);) {
			pipe = (rl_pipe_t **)iterator_val(&it);
			if (!pipe || !*pipe) {
				LM_ERR("[BUG] bogus map[%d] state\n", i);
				goto next;
			}
			/* check to see if it is expired */
			if ((*pipe)->last_used + rl_expire_time < now) {
				key = iterator_key(&it);
				if (!key) {
					LM_ERR("cannot retrieve pipe key\n");
					goto next;
				}
				del = it;
				if (iterator_prev(&it) < 0) {
					LM_DBG("cannot find previous iterator\n");
					goto next;
				}
				if ((*pipe)->algo == PIPE_ALGO_NETWORK)
					(*rl_network_count)--;
				LM_DBG("Deleting ratelimit pipe key \"%.*s\"\n",
						key->len, key->s);
				if (*pipe != iterator_delete(&del)) {
					LM_ERR("error while deleting key\n");
				}
				/* free resources */
				shm_free(*pipe);
			} else {
				switch ((*pipe)->algo) {
					case PIPE_ALGO_NETWORK:
						/* TODO handle network algo */
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
				(*pipe)->counter = 0;
				/* TODO delete this */
				LM_DBG("Pipe \"%.*s\" load updated to %d and counter reseted\n",
						iterator_key(&it)->len, iterator_key(&it)->s,
						(*pipe)->load);
			}
			if (iterator_next(&it) < 0)
				break;
		}
next:
		RL_RELEASE_LOCK(i);
	}

	lock_release(rl_lock);
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


int w_rl_set_count(str key, int dec)
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

	if (dec && dec < (*pipe)->counter) {
		(*pipe)->counter -= dec;
	} else {
		(*pipe)->counter = 0;
	}
	LM_DBG("new counter for key %.*s is %d\n",
			key.len, key.s, (*pipe)->counter);

	ret = 0;

release:
	RL_RELEASE_LOCK(hash_idx);
	return ret;
}

static inline int w_rl_change_counter(struct sip_msg *_m, char *_n, int dec)
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
	return w_rl_change_counter(_m, _n, 1);
}

int w_rl_reset(struct sip_msg *_m, char *_n)
{
	return w_rl_change_counter(_m, _n, 0);
}

