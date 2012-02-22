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

#ifndef _RATELIMIT_H_
#define _RATELIMIT_H_

#define RL_DEFAULT_EXPIRE	3600
#define RL_HASHSIZE			1024
#define RL_TIMER_INTERVAL	10
#define RL_PIPE_PENDING		(1<<0)

#include "../../map.h"

/* copied from old ratelimit module */
typedef enum {
	PIPE_ALGO_NOP = 0,
	PIPE_ALGO_TAILDROP,
	PIPE_ALGO_RED,
	PIPE_ALGO_FEEDBACK,
	PIPE_ALGO_NETWORK
} rl_algo_t;

typedef struct rl_pipe {
	int limit;					/* limit used by algorithm */
	int counter;				/* countes the accesses */
	int my_counter;				/* contes the accesses of this instance */
	int last_counter;			/* last counter */
	int load;					/* countes the accesses */
	rl_algo_t algo;				/* the algorithm used */
	unsigned long last_used;	/* timestamp when the pipe was last accessed */
	int pending;					/* pending refs */
} rl_pipe_t;

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
extern int rl_expire_time;
extern int rl_hash_size;
extern int *rl_network_count;
extern int *rl_network_load;
extern str rl_default_algo_s;
extern str db_prefix;

/* helper funcs */
void mod_destroy(void);
int init_rl_table(unsigned int size);

/* exported functions */
int w_rl_check_2(struct sip_msg*, char *, char *);
int w_rl_check_3(struct sip_msg*, char *, char *, char *);
int w_rl_dec(struct sip_msg*, char *);
int w_rl_reset(struct sip_msg*, char *);
int w_rl_set_count(str, int);
int rl_stats(struct mi_node *, str *);
int rl_pipe_check(rl_pipe_t *);
/* update load */
int get_cpuload(void);
void do_update_load(void);
void pid_setpoint_limit(int);

/* timer */
void rl_timer(unsigned int, void *);

/* cachedb functions */
int init_cachedb(str*);
void destroy_cachedb(void);
#endif /* _RATELIMIT_H_ */
