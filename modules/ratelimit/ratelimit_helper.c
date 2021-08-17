/*:
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
#include "../../resolve.h"
#include "../../bin_interface.h"

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"
#include "../../forward.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ratelimit.h"

/* parameters */
int rl_expire_time = RL_DEFAULT_EXPIRE;
unsigned int rl_hash_size = RL_HASHSIZE;

str rl_default_algo_s = str_init("TAILDROP");
static rl_algo_t rl_default_algo = PIPE_ALGO_NOP;

/* other functions */
static rl_algo_t get_rl_algo(str);

/* big hash table */
rl_big_htable rl_htable;

static cachedb_funcs cdbf;
static cachedb_con *cdbc = 0;

int rl_buffer_th = RL_BUF_THRESHOLD;

static str pipe_repl_cap = str_init("ratelimit-pipe-repl");

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
	int new_counter;
	int ret;

	if (rl_set_name(name) < 0)
		return -1;

	if (pipe->my_counter + c < 0) {
		LM_DBG("Counter going negative\n");
		return 1;
	}

	if (c) {
		if (c < 0)
			ret = cdbf.sub(cdbc, &rl_name_buffer, -c, rl_expire_time, &new_counter);
		else
			ret = cdbf.add(cdbc, &rl_name_buffer, c, rl_expire_time, &new_counter);
	} else {
		if (pipe->my_counter) {
			ret = cdbf.sub(cdbc, &rl_name_buffer, pipe->my_counter, rl_expire_time,
				&new_counter);
		} else {
			ret = cdbf.get_counter(cdbc, &rl_name_buffer, &new_counter);
		}
	}

	if (ret < 0) {
		LM_ERR("cannot change counter for pipe %.*s with %d\n",
			name->len, name->s, c);
		return -1;
	}

	pipe->my_counter = c ? pipe->my_counter + c : 0;
	pipe->counter = new_counter;
	LM_DBG("changed with %d; my_counter: %d; counter: %d\n",
		c, pipe->my_counter, new_counter);

	return 0;
}

/* NOTE: assumes that the pipe has been locked */
static int rl_get_counter(str *name, rl_pipe_t * pipe)
{
	int new_counter;

	if (rl_set_name(name) < 0)
		return -1;
	if (cdbf.get_counter(cdbc, &rl_name_buffer, &new_counter) < 0) {
		LM_ERR("cannot retrieve key\n");
		return -1;
	}

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
		CACHEDB_CAP_GET | CACHEDB_CAP_ADD | CACHEDB_CAP_SUB)) {
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
	rl_default_algo_s.len = strlen(rl_default_algo_s.s);
	/* resolve the default algorithm */
	rl_default_algo = get_rl_algo(rl_default_algo_s);
	if (rl_default_algo == PIPE_ALGO_NOP) {
		LM_ERR("unknown algorithm <%.*s>\n", rl_default_algo_s.len,
			rl_default_algo_s.s);
		return -1;
	}
	LM_DBG("default algorithm is %.*s [ %d ]\n",
		rl_default_algo_s.len, rl_default_algo_s.s, rl_default_algo);

	/* if at least 25% of the size locks can't be allocated
	 * we return an error */
	for (i = size; i > size / 4; i--) {
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
			size / 4);
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
	{ str_init("NOP"), PIPE_ALGO_NOP},
	{ str_init("RED"), PIPE_ALGO_RED},
	{ str_init("TAILDROP"), PIPE_ALGO_TAILDROP},
	{ str_init("FEEDBACK"), PIPE_ALGO_FEEDBACK},
	{ str_init("NETWORK"), PIPE_ALGO_NETWORK},
	{ str_init("SBT"), PIPE_ALGO_HISTORY},
	{
		{ 0, 0}, 0
	},
};

static rl_algo_t get_rl_algo(str name)
{
	int i;
	if (!name.s || !name.len)
		return PIPE_ALGO_NOP;

	for (i = 0; rl_algo_names[i].name.s; i++) {
		if (rl_algo_names[i].name.len == name.len &&
			strncasecmp(rl_algo_names[i].name.s, name.s, name.len) == 0)
			return rl_algo_names[i].algo;
	}
	return PIPE_ALGO_NOP;
}

static str * get_rl_algo_name(rl_algo_t algo)
{
	int i;
	for (i = 0; rl_algo_names[i].name.s; i++)
		if (rl_algo_names[i].algo == algo)
			return &rl_algo_names[i].name;
	return NULL;
}

rl_pipe_t *rl_create_pipe(int limit, rl_algo_t algo)
{
	rl_pipe_t *pipe;
	int size = sizeof(rl_pipe_t);

	if (algo == PIPE_ALGO_NOP)
		algo = rl_default_algo;

	if (algo == PIPE_ALGO_HISTORY)
		size += (rl_window_size * 1000) / rl_slot_period * sizeof(long int);

	pipe = shm_malloc(size);
	if (!pipe) {
		LM_ERR("no more shm memory!\n");
		return NULL;
	}
	memset(pipe, 0, size);

	pipe->algo = algo;
	pipe->limit = limit;

	if (algo == PIPE_ALGO_HISTORY) {
		pipe->rwin.window = (long int *)(pipe + 1);
		pipe->rwin.window_size = (rl_window_size * 1000) / rl_slot_period;
		/* everything else is already cleared */
	}
	return pipe;
}

int w_rl_check(struct sip_msg *_m, str *name, int *limit, str *algorithm)
{
	int ret = 1, should_update = 0;
	unsigned int hash_idx;
	rl_pipe_t **pipe;

	rl_algo_t algo = -1;

	if (!algorithm || (algo = get_rl_algo(*algorithm)) == PIPE_ALGO_NOP) {
		algo = PIPE_ALGO_NOP;
	}

	/* get limit for FEEDBACK algorithm */
	if (algo == PIPE_ALGO_FEEDBACK) {
		lock_get(rl_lock);
		if (*rl_feedback_limit) {
			if (*rl_feedback_limit != *limit) {
				LM_WARN("FEEDBACK limit should be the same for all pipes, but"
					" new limit %d differs - setting to %d\n",
					*limit, *rl_feedback_limit);
				*limit = *rl_feedback_limit;
			}
		} else {
			if (*limit <= 0 || *limit >= 100) {
				LM_ERR("invalid limit for FEEDBACK algorithm "
					"(must be between 0 and 100)\n");
				lock_release(rl_lock);
				goto end;
			}
			*rl_feedback_limit = *limit;
			pid_setpoint_limit(*limit);
		}
		lock_release(rl_lock);
	}

	hash_idx = RL_GET_INDEX(*name);
	RL_GET_LOCK(hash_idx);

	/* try to get the value */
	pipe = RL_GET_PIPE(hash_idx, *name);
	if (!pipe) {
		LM_ERR("cannot get the index\n");
		goto release;
	}

	if (!*pipe) {
		/* allocate new pipe */
		if (!(*pipe = rl_create_pipe(*limit, algo)))
			goto release;

		LM_DBG("Pipe %.*s doesn't exist, but was created %p\n",
				name->len, name->s, *pipe);
		if ((*pipe)->algo == PIPE_ALGO_NETWORK)
			should_update = 1;
		(*pipe)->last_local_used = time(0);
	} else {
		LM_DBG("Pipe %.*s found: %p - last used %lu\n",
			name->len, name->s, *pipe, (*pipe)->last_used);
		if (algo != PIPE_ALGO_NOP && (*pipe)->algo != algo) {
			LM_WARN("algorithm %d different from the initial one %d for pipe "
				"%.*s", algo, (*pipe)->algo, name->len, name->s);
		}
		/* update the limit */
		(*pipe)->limit = *limit;
	}

	/* set the last used time */
	(*pipe)->last_used = time(0);
	if (RL_USE_CDB(*pipe)) {
		/* release the counter for a while */
		if (rl_change_counter(name, *pipe, 1) < 0) {
			LM_ERR("cannot increase counter\n");
			goto release;
		}
	} else {
		(*pipe)->counter++;
	}

	ret = rl_pipe_check(*pipe);
	LM_DBG("Pipe %.*s counter:%d load:%d limit:%d should %sbe blocked (%p)\n",
		name->len, name->s, (*pipe)->counter, (*pipe)->load,
		(*pipe)->limit, ret == 1 ? "NOT " : "", *pipe);


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
	void *value;
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
			pipe = (rl_pipe_t **) iterator_val(&it);
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
			if (((*pipe)->last_local_used + rl_expire_time < now) &&
				((*pipe)->last_used + rl_expire_time + rl_timer_interval < now)) {
				/* this pipe is engaged in a transaction */
				del = it;
				if (iterator_next(&it) < 0)
					LM_DBG("cannot find next iterator\n");
				if ((*pipe)->algo == PIPE_ALGO_NETWORK) {
					lock_get(rl_lock);
					(*rl_network_count)--;
					lock_release(rl_lock);
				}
				LM_DBG("Deleting ratelimit pipe key \"%.*s\"\n",
					key->len, key->s);
				value = iterator_delete(&del);
				/* free resources */
				if (value)
					shm_free(value);
				continue;
			} else {
				/* leave the lock if a cachedb query should be done*/
				if (RL_USE_CDB(*pipe)) {
					if (rl_get_counter(key, *pipe) < 0) {
						LM_ERR("cannot get pipe counter\n");
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
						((*pipe)->limit *
							(rl_limit_per_interval ? 1 : rl_timer_interval));
					break;
				default:
					break;
				}
				(*pipe)->my_last_counter = (*pipe)->counter;
				(*pipe)->last_counter = rl_get_all_counters(*pipe);
				if (RL_USE_CDB(*pipe)) {
					if (rl_change_counter(key, *pipe, 0) < 0) {
						LM_ERR("cannot reset counter\n");
					}
				} else {
					(*pipe)->counter = 0;
				}
			}
next_pipe:
			if (iterator_next(&it) < 0)
				break;
		}
next_map:
		RL_RELEASE_LOCK(i);
	}
}

static int rl_map_print(void *param, str key, void *value)
{
	rl_pipe_t *pipe = (rl_pipe_t *) value;
	str *alg;
	mi_item_t *pipe_item = (mi_item_t *)param;

	if (!pipe) {
		LM_ERR("invalid pipe value\n");
		return -1;
	}
	if (!pipe_item) {
		LM_ERR("no mi item\n");
		return -1;
	}
	if (!key.len || !key.s) {
		LM_ERR("no key found\n");
		return -1;
	}

	/* skip if no algo */
	if (pipe->algo == PIPE_ALGO_NOP)
		return 0;

	if (add_mi_string(pipe_item, MI_SSTR("id"), key.s, key.len) < 0)
		return -1;

	if (!(alg = get_rl_algo_name(pipe->algo))) {
		LM_ERR("[BUG] unknown algorithm %d\n", pipe->algo);
		return -1;
	}

	if (add_mi_string(pipe_item, MI_SSTR("algorithm"), alg->s, alg->len) < 0)
		return -1;

	if (add_mi_number(pipe_item, MI_SSTR("limit"), pipe->limit) < 0)
		return -1;

	if (add_mi_number(pipe_item, MI_SSTR("counter"), pipe->last_counter) < 0)
		return -1;

	return 0;
}

static int rl_map_print_array(void *param, str key, void *value)
{
	mi_item_t *pipe_item = add_mi_object((mi_item_t *)param, NULL, 0);
	if (!pipe_item)
		return -1;
	return rl_map_print(pipe_item, key, value);
}

int rl_stats(mi_item_t *resp_obj, str * value)
{
	mi_item_t *pipe_item, *pipe_arr;
	rl_pipe_t **pipe;
	int i;

	if (value && value->s && value->len) {
		i = RL_GET_INDEX(*value);
		RL_GET_LOCK(i);
		pipe = RL_FIND_PIPE(i, *value);
		if (!pipe || !*pipe) {
			LM_DBG("pipe %.*s not found\n", value->len, value->s);
			RL_RELEASE_LOCK(i);
			return 1;
		}
		pipe_item = add_mi_object(resp_obj, MI_SSTR("Pipe"));
		if (!pipe_item)
			goto error;
		if (rl_map_print(pipe_item, *value, *pipe)) {
			LM_ERR("cannot print value for key %.*s\n",
				value->len, value->s);
			goto error;
		}
		RL_RELEASE_LOCK(i);
	} else {
		/* iterate through each map */
		pipe_arr = add_mi_array(resp_obj, MI_SSTR("Pipes"));
		if (!pipe_arr)
			return -1;
		for (i = 0; i < rl_htable.size; i++) {
			if (map_size(rl_htable.maps[i]) == 0)
				continue;
			RL_GET_LOCK(i);
			if (map_for_each(rl_htable.maps[i], rl_map_print_array, pipe_arr)) {
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
			goto release;
		}
	} else if ((*pipe)->algo == PIPE_ALGO_HISTORY) {
		hist_set_count(*pipe, val);
	} else {
		if (val && (val + (*pipe)->counter >= 0)) {
			(*pipe)->counter += val;
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

static inline int w_rl_change_counter(struct sip_msg *_m, str *name, int dec)
{
	if (w_rl_set_count(*name, dec)) {
		LM_ERR("cannot find any pipe named %.*s\n", name->len, name->s);
		return -1;
	}
	return 1;
}

int w_rl_dec(struct sip_msg *_m, str *_n)
{
	return w_rl_change_counter(_m, _n, -1);
}

int w_rl_reset(struct sip_msg *_m, str *_n)
{
	return w_rl_change_counter(_m, _n, 0);
}

static rl_repl_counter_t* find_destination(rl_pipe_t *pipe, int machine_id)
{
	rl_repl_counter_t *head;

	head = pipe->dsts;
	while(head != NULL){
		if( head->machine_id ==  machine_id )
			break;
		head=head->next;
	}

	if(head == NULL){
		head = shm_malloc(sizeof(rl_repl_counter_t));
		if(head == NULL){
			LM_ERR("no more shm memory\n");
			goto error;
		}
		head->machine_id = machine_id;
		head->next = pipe->dsts;
		pipe->dsts = head;
	}

	return head;

error:
	return NULL;
}




void rl_rcv_bin(bin_packet_t *packet)
{
	rl_algo_t algo;
	int limit;
	int counter;
	str name;
	rl_pipe_t **pipe;
	unsigned int hash_idx;
	time_t now;
	rl_repl_counter_t *destination;

	if (packet->type != RL_PIPE_COUNTER) {
		LM_WARN("Invalid binary packet command: %d (from node: %d in cluster: %d)\n",
			packet->type, packet->src_id, rl_repl_cluster);
		return;
	}

	now = time(0);

	for (;;) {
		if (bin_pop_str(packet, &name) == 1)
			break; /* pop'ed all pipes */

		if (bin_pop_int(packet, &algo) < 0) {
			LM_ERR("cannot pop pipe's algorithm\n");
			return;
		}

		if (bin_pop_int(packet, &limit) < 0) {
			LM_ERR("cannot pop pipe's limit\n");
			return;
		}

		if (bin_pop_int(packet, &counter) < 0) {
			LM_ERR("cannot pop pipe's counter\n");
			return;
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
			/* if the pipe does not exist, allocate it in case we need it later */
			if (!(*pipe = rl_create_pipe(limit, algo)))
				goto release;
			LM_DBG("Pipe %.*s doesn't exist, but was created %p\n",
				name.len, name.s, *pipe);

		} else {
			LM_DBG("Pipe %.*s found: %p - last used %lu\n",
				name.len, name.s, *pipe, (*pipe)->last_used);
			if ((*pipe)->algo != algo)
				LM_WARN("algorithm %d different from the initial one %d for "
				"pipe %.*s", algo, (*pipe)->algo, name.len, name.s);
			/*
			 * XXX: do not output these warnings since they can be triggered
			 * when a custom limit is used
			if ((*pipe)->limit != limit)
				LM_WARN("limit %d different from the initial one %d for "
				"pipe %.*s", limit, (*pipe)->limit, name.len, name.s);
			 */
		}
		/* set the last used time */
		(*pipe)->last_used = time(0);
		/* set the destination's counter */
		destination = find_destination(*pipe, packet->src_id);
		if (!destination)
			goto release;
		destination->counter = counter;
		destination->update = now;
		RL_RELEASE_LOCK(hash_idx);
	}
	return;

release:
	RL_RELEASE_LOCK(hash_idx);
}

/*
 * same as hist_check() in ratelimit.c but this one
 * only counts, no updates on the window ==> faster
 */
static inline int ALLOW_UNUSED hist_count(rl_pipe_t *pipe)
{
	/* Window ELement*/
	#define U2MILI(__usec__) (__usec__/1000)
	#define S2MILI(__sec__)  (__sec__ *1000)
	int i;
	int first_good_index;
	int rl_win_ms = rl_window_size * 1000;

	int count=0;

	unsigned long long now_total, start_total;

	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (pipe->rwin.start_time.tv_sec == 0) {
		return 0;
	} else {
		start_total = S2MILI(pipe->rwin.start_time.tv_sec)
							+ U2MILI(pipe->rwin.start_time.tv_usec);
		now_total = S2MILI(tv.tv_sec) + U2MILI(tv.tv_usec);

		if (now_total - start_total >= 2*rl_win_ms) {
			/* nothing here; window is expired */
		} else if (now_total - start_total >= rl_win_ms) {
			first_good_index = ((((now_total - rl_win_ms) - start_total)
						/rl_slot_period + 1) + pipe->rwin.start_index) %
						pipe->rwin.window_size;

			count = 0;
			for (i=first_good_index; i != pipe->rwin.start_index;
											i=(i+1)%pipe->rwin.window_size)
				count += pipe->rwin.window[i];

		} else {
			/* count all of them; valid window */
			for (i=0; i < pipe->rwin.window_size; i++)
				count += pipe->rwin.window[i];
		}
	}
	return count;

	#undef U2MILI
	#undef S2MILI
}

int rl_repl_init(void)
{
	if (rl_repl_cluster && clusterer_api.register_capability(&pipe_repl_cap,
		rl_rcv_bin, NULL, rl_repl_cluster, 0, NODE_CMP_ANY) < 0) {
		LM_ERR("Cannot register clusterer callback!\n");
		return -1;
	}

	return 0;
}

static inline void rl_replicate(bin_packet_t *packet)
{
	int rc;

	rc = clusterer_api.send_all(packet, rl_repl_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", rl_repl_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			rl_repl_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", rl_repl_cluster);
		goto error;
	}

	return;

error:
	LM_ERR("Failed to replicate ratelimit pipes\n");
}

void rl_timer_repl(utime_t ticks, void *param)
{
	unsigned int i = 0;
	map_iterator_t it;
	rl_pipe_t **pipe;
	str *key;
	int nr = 0;
	int ret = 0;
	bin_packet_t packet;
	time_t now = time(0);

	if (bin_init(&packet, &pipe_repl_cap, RL_PIPE_COUNTER, BIN_VERSION, 0) < 0) {
		LM_ERR("cannot initiate bin buffer\n");
		return;
	}

	/* iterate through each map */
	for (i = 0; i < rl_htable.size; i++) {
		RL_GET_LOCK(i);
		/* iterate through all the entries */
		if (map_first(rl_htable.maps[i], &it) < 0) {
			LM_ERR("map doesn't exist\n");
			goto next_map;
		}
		for (; iterator_is_valid(&it);) {
			pipe = (rl_pipe_t **) iterator_val(&it);
			if (!pipe || !*pipe) {
				LM_ERR("[BUG] bogus map[%d] state\n", i);
				goto next_pipe;
			}
			/* ignore cachedb replicated stuff */
			if (RL_USE_CDB(*pipe))
				goto next_pipe;

			/* do not replicate if about to expire */
			if ((*pipe)->last_local_used + rl_expire_time < now)
				goto next_pipe;

			key = iterator_key(&it);
			if (!key) {
				LM_ERR("cannot retrieve pipe key\n");
				goto next_pipe;
			}

			if (bin_push_str(&packet, key) < 0)
				goto error;

			if (bin_push_int(&packet, (*pipe)->algo) < 0)
				goto error;

			if (bin_push_int(&packet, (*pipe)->limit) < 0)
				goto error;

			/*
			 * for the SBT algorithm it is safe to replicate the current
			 * counter, since it is always updating according to the window
			 */
			if ((ret = bin_push_int(&packet,
						((*pipe)->algo == PIPE_ALGO_HISTORY ?
						 (*pipe)->counter : (*pipe)->my_last_counter))) < 0)
				goto error;
			nr++;

next_pipe:
			if (iterator_next(&it) < 0)
				break;
		}
next_map:
		RL_RELEASE_LOCK(i);
		if (ret > rl_buffer_th) {
			/* send the buffer */
			if (nr)
				rl_replicate(&packet);
			bin_reset_back_pointer(&packet);
			nr = 0;
		}
	}
	/* if there is anything else to send, do it now */
	if (nr)
		rl_replicate(&packet);
	bin_free_packet(&packet);
	return;
error:
	LM_ERR("cannot add pipe info in buffer\n");
	RL_RELEASE_LOCK(i);
	if (nr)
		rl_replicate(&packet);
	bin_free_packet(&packet);
}

int rl_get_all_counters(rl_pipe_t *pipe)
{
	unsigned counter = 0;
	time_t now = time(0);
	rl_repl_counter_t *nodes = pipe->dsts;
	rl_repl_counter_t *d;

	for (d = nodes; d; d = d->next) {
		/* if the replication expired, reset its counter */
		if ((d->update + rl_repl_timer_expire) < now)
			d->counter = 0;
		counter += d->counter;
	}
	return counter + pipe->counter;
}

int rl_get_counter_value(str *key)
{
	unsigned int hash_idx;
	rl_pipe_t **pipe;
	int ret = -1;

	hash_idx = RL_GET_INDEX(*key);
	RL_GET_LOCK(hash_idx);

	/* try to get the value */
	pipe = RL_FIND_PIPE(hash_idx, *key);
	if (!pipe || !*pipe) {
		LM_DBG("cannot find any pipe named %.*s\n", key->len, key->s);
		goto release;
	}

	if (RL_USE_CDB(*pipe)) {
		if (rl_get_counter(key, *pipe) < 0) {
			LM_ERR("cannot get the counter's value\n");
			goto release;
		}
	} else if ((*pipe)->algo == PIPE_ALGO_HISTORY)
		ret = hist_get_count(*pipe);
	else
		ret = rl_get_all_counters(*pipe);

release:
	RL_RELEASE_LOCK(hash_idx);
	return ret;
}
