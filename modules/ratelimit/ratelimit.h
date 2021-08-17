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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2011-09-26  created (razvancrainea)
 */

#ifndef _RATELIMIT_H_
#define _RATELIMIT_H_

#define RL_DEFAULT_EXPIRE	3600
#define RL_HASHSIZE			1024
#define RL_TIMER_INTERVAL	10
#define RL_PIPE_PENDING		(1<<0)
#define BIN_VERSION         1


#include "../../map.h"
#include "../clusterer/api.h"
#include "../../forward.h"

/* copied from old ratelimit module */
typedef enum {
	PIPE_ALGO_NOP = 0,
	PIPE_ALGO_TAILDROP,
	PIPE_ALGO_RED,
	PIPE_ALGO_FEEDBACK,
	PIPE_ALGO_NETWORK,
	PIPE_ALGO_HISTORY
} rl_algo_t;

typedef struct rl_repl_counter {
	int counter;
	time_t update;
        int machine_id;
        struct rl_repl_counter *next;
} rl_repl_counter_t;


typedef struct rl_window {
	int window_size;   /* how big the window array is */
	int start_index;   /* where the window starts; the window uses
						* a circular buffer so we will need to know
						* where is the start of the buffer */
	struct timeval start_time; /* time from where the window starts */

	long int *window;  /* actual array of messages */
} rl_window_t;

typedef struct rl_pipe {
	int limit;					/* limit used by algorithm */
	int counter;				/* countes the accesses */
	int my_counter;				/* countes the accesses of this instance */
	int my_last_counter;		/* countes the last accesses of this instance */
	int last_counter;			/* last counter */
	int load;					/* countes the accesses */
	rl_algo_t algo;				/* the algorithm used */
	time_t last_used;			/* timestamp when the pipe was last accessed */
	time_t last_local_used;		/* timestamp when the pipe was last locally accessed */
	rl_repl_counter_t *dsts;	/* counters per destination */
	rl_window_t rwin;			/* window of requests */
} rl_pipe_t;

typedef struct rl_repl_dst {
	int id;
	str dst;
	time_t *last_msg;
	union sockaddr_union to;
} rl_repl_dst_t;

/* big hashtable */
typedef struct {
	unsigned int size;
	map_t * maps;
	gen_lock_set_t *locks;
	unsigned int locks_no;
} rl_big_htable;

extern gen_lock_t * rl_lock;
extern rl_big_htable rl_htable;
extern int rl_timer_interval;
extern int rl_limit_per_interval;
extern int rl_expire_time;
extern unsigned int rl_hash_size;
extern int *rl_feedback_limit;
extern int *rl_network_count;
extern int *rl_network_load;
extern str rl_default_algo_s;
extern str db_prefix;
extern int rl_repl_cluster;
extern int rl_window_size;
extern int rl_slot_period;

extern struct clusterer_binds clusterer_api;

/* helper funcs */
void mod_destroy(void);
int init_rl_table(unsigned int size);

/* exported functions */
int w_rl_check(struct sip_msg*, str *, int *, str *);
int w_rl_dec(struct sip_msg*, str *);
int w_rl_reset(struct sip_msg*, str *);
int w_rl_set_count(str, int);
int rl_stats(mi_item_t *, str *);
int rl_pipe_check(rl_pipe_t *);
int rl_get_counter_value(str *);
/* update load */
int get_cpuload(void);
void do_update_load(void);
void pid_setpoint_limit(int);

/* timer */
void rl_timer(unsigned int, void *);
void rl_timer_repl(utime_t, void *);

/* cachedb functions */
int init_cachedb(str*);
void destroy_cachedb(void);

/* bin functions */
extern int rl_buffer_th;
extern unsigned int rl_repl_timer_expire;
int rl_repl_init(void);
int rl_get_all_counters(rl_pipe_t *pipe);
int rl_add_repl_dst(modparam_t type, void *val);

void hist_set_count(rl_pipe_t *pipe, long int value);
int hist_get_count(rl_pipe_t *pipe);

#define RL_PIPE_COUNTER		0
#define RL_EXPIRE_TIMER		10
#define RL_BUF_THRESHOLD	32767

#endif /* _RATELIMIT_H_ */
