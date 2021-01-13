/*
 * ratelimit module
 *
 * Copyright (C) 2006 Hendrik Scholz <hscholz@raisdorf.net>
 * Copyright (C) 2008 Ovidiu Sas <osas@voipembedded.com>
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
 * ---------
 *
 * 2008-01-10 ported from SER project (osas)
 * 2008-01-16 ported enhancements from openims project (osas)
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include <math.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../timer.h"
#include "../../ut.h"
#include "../../locking.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../socket_info.h"
#include "../../bin_interface.h"
#include "../signaling/signaling.h"
#include "ratelimit.h"


/* === these change after startup */
gen_lock_t * rl_lock;

static double * rl_load_value;     /* actual load, used by PIPE_ALGO_FEEDBACK */
static double * pid_kp, * pid_ki, * pid_kd, * pid_setpoint; /* PID tuning params */
static int * drop_rate;         /* updated by PIPE_ALGO_FEEDBACK */
int *rl_feedback_limit;

int * rl_network_load;	/* network load */
int * rl_network_count;	/* flag for counting network algo users */

/* these only change in the mod_init() process -- no locking needed */
int rl_timer_interval = RL_TIMER_INTERVAL;

/* specify limit per second by defualt */
int rl_limit_per_interval = 0;

int rl_repl_cluster = 0;
struct clusterer_binds clusterer_api;

int rl_window_size=10;   /* how many seconds the window shall hold*/
int rl_slot_period=200;  /* how many milisecs a slot from the window has  */

static str db_url = {0,0};
str db_prefix = str_init("rl_pipe_");

unsigned int rl_repl_timer_expire = RL_TIMER_INTERVAL;
static unsigned int rl_repl_timer_interval = RL_TIMER_INTERVAL;

/* === */

#ifndef RL_DEBUG_LOCKS
# define LOCK_GET lock_get
# define LOCK_RELEASE lock_release
#else
# define LOCK_GET(l) do { \
	LM_INFO("%d: + get\n", __LINE__); \
	lock_get(l); \
	LM_INFO("%d: - get\n", __LINE__); \
} while (0)

# define LOCK_RELEASE(l) do { \
	LM_INFO("%d: + release\n", __LINE__); \
	lock_release(l); \
	LM_INFO("%d: - release\n", __LINE__); \
} while (0)
#endif

/* module functions */
static int mod_init(void);
static int mod_child(int);

mi_response_t *mi_stats(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_stats_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_reset_pipe(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_set_pid(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_pid(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int pv_get_rl_count(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);
static int pv_parse_rl_count(pv_spec_p sp, str *in);

static cmd_export_t cmds[] = {
	{"rl_check", (cmd_function)w_rl_check, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_INT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rl_dec_count", (cmd_function)w_rl_dec, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rl_reset_count", (cmd_function)w_rl_reset, {
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|ERROR_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[] = {
	{ "timer_interval",		INT_PARAM,	&rl_timer_interval		},
	{ "expire_time",		INT_PARAM,	&rl_expire_time			},
	{ "hash_size",			INT_PARAM,	&rl_hash_size			},
	{ "default_algorithm",		STR_PARAM,	&rl_default_algo_s.s		},
	{ "cachedb_url",		STR_PARAM,	&db_url.s			},
	{ "db_prefix",			STR_PARAM,	&db_prefix.s			},
	{ "repl_buffer_threshold",	INT_PARAM,	&rl_buffer_th			},
	{ "repl_timer_interval",	INT_PARAM,	&rl_repl_timer_interval		},
	{ "repl_timer_expire",		INT_PARAM,	&rl_repl_timer_expire		},
	{ "pipe_replication_cluster",	INT_PARAM,	&rl_repl_cluster		},
	{ "window_size",            INT_PARAM,  &rl_window_size},
	{ "slot_period",            INT_PARAM,  &rl_slot_period},
	{ "limit_per_interval",     INT_PARAM,  &rl_limit_per_interval},
	{ 0, 0, 0}
};

#define RLH1 "Params: [pipe] ; Lists the parameters and variabiles in the " \
	"ratelimit module; If no pipe is specified, all existing pipes are listed."
#define RLH2 "Params: pipe ; Resets the counter of a specified pipe."
#define RLH3 "Params: ki kp kd ; Sets the PID Controller parameters for the " \
	"Feedback Algorithm."
#define RLH4 "Params: none ; Gets the list of in use PID Controller parameters."
#define RLH5 "Params: none ; Shows the status of the other SIP instances."

static mi_export_t mi_cmds [] = {
	{"rl_list", RLH1, 0, 0, {
		{mi_stats, {0}},
		{mi_stats_1, {"pipe", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"rl_reset_pipe", RLH2, 0, 0, {
		{mi_reset_pipe, {"pipe", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"rl_set_pid", RLH3, 0, 0, {
		{mi_set_pid, {"ki", "kp", "kd", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{"rl_get_pid", RLH4, 0, 0, {
		{mi_get_pid, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static pv_export_t mod_items[] = {
	{ {"rl_count", sizeof("rl_count")-1}, 1010, pv_get_rl_count, 0,
		 pv_parse_rl_count, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "pipe_replication_cluster",	get_deps_clusterer	},
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"ratelimit",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	&deps,				/* OpenSIPS module dependencies */
	cmds,
	NULL,
	params,
	0,					/* exported statistics */
	mi_cmds,			/* exported MI functions */
	mod_items,			/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	0,
	mod_destroy,		/* module exit function */
	mod_child,			/* per-child init function */
	0					/* reload confirm function */
};


/* not using /proc/loadavg because it only works when our_timer_interval == theirs */
int get_cpuload(void)
{
	static
	long long o_user, o_nice, o_sys, o_idle, o_iow, o_irq, o_sirq, o_stl;
	long long n_user, n_nice, n_sys, n_idle, n_iow, n_irq, n_sirq, n_stl;
	static int first_time = 1;
	int scan_res;
	FILE * f = fopen("/proc/stat", "r");

	if (! f)
		return -1;
	scan_res = fscanf(f, "cpu  %lld%lld%lld%lld%lld%lld%lld%lld",
			&n_user, &n_nice, &n_sys, &n_idle, &n_iow, &n_irq, &n_sirq, &n_stl);
	fclose(f);

	if (scan_res <= 0) {
		LM_ERR("/proc/stat didn't contain expected values\n");
		return -1;
	}

	if (first_time) {
		first_time = 0;
		*rl_load_value = 0;
	} else {
		long long d_total =	(n_user - o_user)	+
					(n_nice	- o_nice)	+
					(n_sys	- o_sys)	+
					(n_idle	- o_idle)	+
					(n_iow	- o_iow)	+
					(n_irq	- o_irq)	+
					(n_sirq	- o_sirq)	+
					(n_stl	- o_stl);
		long long d_idle =	(n_idle - o_idle);

		*rl_load_value = 1.0 - ((double)d_idle) / (double)d_total;
	}

	o_user	= n_user;
	o_nice	= n_nice;
	o_sys	= n_sys;
	o_idle	= n_idle;
	o_iow	= n_iow;
	o_irq	= n_irq;
	o_sirq	= n_sirq;
	o_stl	= n_stl;

	return 0;
}

static double int_err = 0.0;
static double last_err = 0.0;

void pid_setpoint_limit(int limit)
{
	*pid_setpoint = 0.01 * (double)limit;
}

/* (*load_value) is expected to be in the 0.0 - 1.0 range
 * (expects rl_lock to be taken)
 */
void do_update_load(void)
{
	double err, dif_err, output;

	/* PID update */
	err = *pid_setpoint - *rl_load_value;

	dif_err = err - last_err;

	/*
	 * TODO?: the 'if' is needed so low cpu loads for
	 * long periods (which can't be compensated by
	 * negative drop rates) don't confuse the controller
	 *
	 * NB: - "err < 0" means "desired_cpuload < actual_cpuload"
	 *     - int_err is integral(err) over time
	 */
	if (int_err < 0 || err < 0)
		int_err += err;

	output =	(*pid_kp) * err +
				(*pid_ki) * int_err +
				(*pid_kd) * dif_err;
	last_err = err;

	*drop_rate = (output > 0) ? output  : 0;
}

#define RL_SHM_MALLOC(_p, _s) \
	do { \
		_p = shm_malloc((_s)); \
		if (!_p) { \
			LM_ERR("no more shm memory\n"); \
			return -1; \
		} \
		memset(_p, 0, (_s)); \
	} while (0)

#define RL_SHM_FREE(_p) \
	do { \
		if (_p) { \
			shm_free(_p); \
			_p = 0; \
		} \
	} while (0)

/* initialize ratelimit module */
static int mod_init(void)
{
	unsigned int n;

	LM_INFO("Ratelimit module - initializing ...\n");

	if (rl_timer_interval < 0) {
		LM_ERR("invalid timer interval\n");
		return -1;
	}
	if (rl_expire_time < 0) {
		LM_ERR("invalid expire time\n");
		return -1;
	}

	if (rl_repl_cluster < 0) {
		LM_ERR("Invalid replication_cluster, must be 0 or a positive cluster id\n");
		return -1;
	}

	if (rl_repl_cluster && load_clusterer_api(&clusterer_api) != 0 ){
		LM_DBG("failed to find clusterer API - is clusterer module loaded?\n");
		return -1;
	}

	if (db_url.s) {
		db_url.len = strlen(db_url.s);
		db_prefix.len = strlen(db_prefix.s);
		LM_DBG("using CacheDB url: %s\n", db_url.s);
	}

	RL_SHM_MALLOC(rl_network_count, sizeof(int));
	RL_SHM_MALLOC(rl_network_load, sizeof(int));
	RL_SHM_MALLOC(rl_load_value, sizeof(double));
	RL_SHM_MALLOC(pid_kp, sizeof(double));
	RL_SHM_MALLOC(pid_ki, sizeof(double));
	RL_SHM_MALLOC(pid_kd, sizeof(double));
	RL_SHM_MALLOC(pid_setpoint, sizeof(double));
	RL_SHM_MALLOC(drop_rate, sizeof(int));
	RL_SHM_MALLOC(rl_feedback_limit, sizeof(int));

	/* init ki value for feedback algo */
	*pid_ki = -25.0;

	rl_lock = lock_alloc();
	if (!rl_lock) {
		LM_ERR("cannot alloc lock\n");
		return -1;
	}

	if (!lock_init(rl_lock)) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	/* register timer to reset counters */
	if (register_timer("rl-timer", rl_timer, NULL,
	rl_timer_interval, TIMER_FLAG_DELAY_ON_DELAY) < 0 ) {
		LM_ERR("could not register timer function\n");
		return -1;
	}
	if(rl_repl_cluster)
	if (register_utimer("rl-utimer", rl_timer_repl, NULL,
			rl_repl_timer_interval * 1000, TIMER_FLAG_DELAY_ON_DELAY) < 0) {
		LM_ERR("failed to register utimer\n");
		return -1;
	}

	if (rl_hash_size <= 0) {
		LM_ERR("Hash size must be a positive integer, power of 2!\n");
		return -1;
	}
	if (rl_hash_size != 1) {
		for( n=1 ; n < (8 * sizeof(unsigned int)) ; n++) {
			if (rl_hash_size==(1<<n))
				break;
			if (rl_hash_size<(1<<n)) {
				LM_WARN("hash_size is not a power "
						"of 2 as it should be -> rounding from %d to %d\n",
						rl_hash_size, 1<<(n-1));
				rl_hash_size = 1<<(n-1);
				break;
			}
		}
	}

	if (init_rl_table(rl_hash_size) < 0) {
		LM_ERR("cannot allocate the table\n");
		return -1;
	}

	if (rl_repl_init() < 0) {
		LM_ERR("cannot init bin replication\n");
		return -1;
	}



	return 0;
}

static int mod_child(int rank)
{
	/* init the cachedb */
	if (db_url.s && db_url.len)
		return init_cachedb(&db_url);
	LM_DBG("db_url not set - using standard behaviour\n");
	return 0;
}

void mod_destroy(void)
{
	unsigned int i;
	if (rl_htable.maps) {
		for (i = 0; i < rl_htable.size; i++)
			map_destroy(rl_htable.maps[i], 0);
		shm_free(rl_htable.maps);
		rl_htable.maps = 0;
		rl_htable.size = 0;
	}
	if (rl_htable.locks) {
		lock_set_destroy(rl_htable.locks);
		lock_set_dealloc(rl_htable.locks);
		rl_htable.locks = 0;
		rl_htable.locks_no = 0;
	}
	if (rl_lock) {
		lock_destroy(rl_lock);
		lock_dealloc(rl_lock);
	}
	RL_SHM_FREE(rl_network_count);
	RL_SHM_FREE(rl_network_load);
	RL_SHM_FREE(rl_load_value);
	RL_SHM_FREE(pid_kp);
	RL_SHM_FREE(pid_ki);
	RL_SHM_FREE(pid_kd);
	RL_SHM_FREE(pid_setpoint);
	RL_SHM_FREE(drop_rate);
	RL_SHM_FREE(rl_feedback_limit);
}


/* this is here to avoid using rand() ... which doesn't _always_ return
 * exactly what we want (see NOTES section in 'man 3 rand')
 */
int hash[100] = {18, 50, 51, 39, 49, 68, 8, 78, 61, 75, 53, 32, 45, 77, 31,
	12, 26, 10, 37, 99, 29, 0, 52, 82, 91, 22, 7, 42, 87, 43, 73, 86, 70,
	69, 13, 60, 24, 25, 6, 93, 96, 97, 84, 47, 79, 64, 90, 81, 4, 15, 63,
	44, 57, 40, 21, 28, 46, 94, 35, 58, 11, 30, 3, 20, 41, 74, 34, 88, 62,
	54, 33, 92, 76, 85, 5, 72, 9, 83, 56, 17, 95, 55, 80, 98, 66, 14, 16,
	38, 71, 23, 2, 67, 36, 65, 27, 1, 19, 59, 89, 48};

/**
 * the algorithm keeps a circular window of requests in a fixed size buffer
 *
 * @param pipe   containing the window
 * @param update whether or not to inc call number
 * @return number of calls in the window
 */
static inline unsigned hist_update(rl_pipe_t *pipe, int update)
{
	#define U2MILI(__usec__) (__usec__/1000)
	#define S2MILI(__sec__)  (__sec__ *1000)
	int i;
	int now_index;
	int rl_win_ms = rl_window_size * 1000;
	unsigned long long now_time, start_time;

	struct timeval tv;

	gettimeofday(&tv, NULL);
	now_time = S2MILI(tv.tv_sec) + U2MILI(tv.tv_usec);
	now_index = (now_time%rl_win_ms) / rl_slot_period;

	start_time = S2MILI(pipe->rwin.start_time.tv_sec)
		+ U2MILI(pipe->rwin.start_time.tv_usec);

	if ( (pipe->rwin.start_time.tv_sec == 0) ||   /* first run*/
	(now_time - start_time >= rl_win_ms) ) {      /* or more than one window */
		//LM_DBG("case 1 - start=%lld/%d, now=%lld/%d, diff=%lld\n",
		//	start_time, pipe->rwin.start_index, now_time, now_index,
		//	now_time-start_time);
		memset(pipe->rwin.window, 0,
			pipe->rwin.window_size * sizeof(long int));
		pipe->rwin.start_time = tv;
		pipe->rwin.start_index = now_index;
		pipe->rwin.window[now_index] = update;

	} else
	if (now_time - start_time >= rl_slot_period) {
		/* different slot */
		//LM_DBG("case 2 - start=%lld/%d, now=%lld/%d, diff=%lld\n",
		//	start_time, pipe->rwin.start_index, now_time, now_index,
		//	now_time-start_time);
		/* zero the gap between old/start index and current/now index */
		for ( i=(pipe->rwin.start_index+1)%pipe->rwin.window_size;
			i != now_index;
			i=(i+1)%pipe->rwin.window_size)
				pipe->rwin.window[i] = 0;
		/* update the time/index of the last counting */
		pipe->rwin.start_time = tv;
		pipe->rwin.start_index = now_index;

		/* count current call; it will be the last element in the window */
		pipe->rwin.window[now_index] = update;

	} else {
		/* index the same slot */
		/* we just need to increment the number of calls for
		 * the current slot*/
		//LM_DBG("case 3 - start=%lld/%d, now=%lld/%d, diff=%lld\n",
		//	start_time, pipe->rwin.start_index, now_time, now_index,
		//	now_time-start_time);
		pipe->rwin.window[pipe->rwin.start_index] += update;
	}

	pipe->counter = 0;
	/* count the total number of calls in the window */
	for (i=0; i < pipe->rwin.window_size; i++)
		pipe->counter += pipe->rwin.window[i];

	return rl_get_all_counters(pipe);

	#undef U2MILI
	#undef S2MILI
}

int hist_get_count(rl_pipe_t *pipe)
{
	/* do a NOP to validate the interval, then return the unchanged counter */
	return hist_update(pipe, 0);
}

void hist_set_count(rl_pipe_t *pipe, long int value)
{
	if (value == 0) {
		/* if 0, we need to clear all counters */
		memset(pipe->rwin.window, 0,
				pipe->rwin.window_size * sizeof(long int));
		pipe->rwin.start_time.tv_sec = 0; /* force init */
	} else
		hist_update(pipe, value);
}


/**
 * runs the pipe's algorithm
 * (expects rl_lock to be taken)
 * \return	-1 if drop needed, 1 if allowed
 */
int rl_pipe_check(rl_pipe_t *pipe)
{
	unsigned counter;

	if (pipe->algo == PIPE_ALGO_HISTORY)
		return (hist_update(pipe, 1) > pipe->limit ? -1 : 1);

	counter = rl_get_all_counters(pipe);

	switch (pipe->algo) {
		case PIPE_ALGO_NOP:
			LM_ERR("no algorithm defined for this pipe\n");
			return 1;
		case PIPE_ALGO_TAILDROP:
			return (counter <= pipe->limit *
				(rl_limit_per_interval ? 1 : rl_timer_interval)) ? 1 : -1;
		case PIPE_ALGO_RED:
			if (!pipe->load)
				return 1;
			return (counter % pipe->load ? -1 : 1);
		case PIPE_ALGO_NETWORK:
			return (pipe->load ? pipe->load : 1);
		case PIPE_ALGO_FEEDBACK:
			return (hash[counter % 100] < *drop_rate) ? -1 : 1;
		default:
			LM_ERR("ratelimit algorithm %d not implemented\n", pipe->algo);
	}
	return 1;
}

/*
 * MI functions
 *
 * mi_stats() dumps the current config/statistics
 */

/* mi function implementations */
mi_response_t *mi_stats(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (rl_stats(resp_obj, NULL) < 0) {
		LM_ERR("cannot mi print values\n");
		goto free;
	}

	LOCK_GET(rl_lock);
	if (add_mi_number(resp_obj, MI_SSTR("drop_rate"), *drop_rate) < 0) {
		LOCK_RELEASE(rl_lock);
		goto free;
	}
	LOCK_RELEASE(rl_lock);

	return resp;

free:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_stats_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	str pipe_name;
	int rc;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (get_mi_string_param(params, "pipe", &pipe_name.s, &pipe_name.len) < 0)
		return init_mi_param_error();

	rc = rl_stats(resp_obj, &pipe_name);
	if (rc < 0) {
		LM_ERR("cannot mi print values\n");
		goto free;
	} else if (rc == 1) {
		return init_mi_error(404, MI_SSTR("Pipe Not Found"));
	}

	LOCK_GET(rl_lock);
	if (add_mi_number(resp_obj, MI_SSTR("drop_rate"), *drop_rate) < 0) {
		LOCK_RELEASE(rl_lock);
		goto free;
	}
	LOCK_RELEASE(rl_lock);

	return resp;

free:
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_set_pid(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	char buf[5];
	int rl_ki, rl_kp, rl_kd;
	str ki_s, kp_s, kd_s;

	if (get_mi_string_param(params, "ki", &ki_s.s, &ki_s.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "kp", &kp_s.s, &kp_s.len) < 0)
		return init_mi_param_error();
	if (get_mi_string_param(params, "kd", &kd_s.s, &kd_s.len) < 0)
		return init_mi_param_error();

	if ( !ki_s.s || !ki_s.len || ki_s.len >= 5)
		goto bad_syntax;
	memcpy(buf, ki_s.s, ki_s.len);
	buf[ki_s.len] = '\0';
	rl_ki = strtod(buf, NULL);

	if ( !kp_s.s || !kp_s.len || kp_s.len >= 5)
		goto bad_syntax;
	memcpy(buf, kp_s.s, kp_s.len);
	buf[kp_s.len] = '\0';
	rl_kp = strtod(buf, NULL);

	if ( !kd_s.s || !kd_s.len || kd_s.len >= 5)
		goto bad_syntax;
	memcpy(buf, kd_s.s, kd_s.len);
	buf[kd_s.len] = '\0';
	rl_kd = strtod(buf, NULL);

	LOCK_GET(rl_lock);
	*pid_ki = rl_ki;
	*pid_kp = rl_kp;
	*pid_kd = rl_kd;
	LOCK_RELEASE(rl_lock);

	return init_mi_result_ok();

bad_syntax:
	return init_mi_error(400, MI_SSTR("Bad parameter value"));
}

mi_response_t *mi_get_pid(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *pid_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	pid_obj = add_mi_object(resp_obj, MI_SSTR("PID"));
	if (!pid_obj)
		goto error;

	LOCK_GET(rl_lock);
	if (add_mi_string_fmt(pid_obj, MI_SSTR("ki"), "%0.3f", *pid_ki) < 0)
		goto error;
	if (add_mi_string_fmt(pid_obj, MI_SSTR("kp"), "%0.3f", *pid_kp) < 0)
		goto error;
	if (add_mi_string_fmt(pid_obj, MI_SSTR("kd"), "%0.3f", *pid_kd) < 0)
		goto error;
	LOCK_RELEASE(rl_lock);

	return resp;

error:
	LOCK_RELEASE(rl_lock);
	LM_ERR("Unable to create reply\n");
	free_mi_response(resp);
	return 0;
}

mi_response_t *mi_reset_pipe(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str pipe_name;

	if (get_mi_string_param(params, "pipe", &pipe_name.s, &pipe_name.len) < 0)
		return init_mi_param_error();

	if (w_rl_set_count(pipe_name, 0))
		return init_mi_error(500, MI_SSTR("Internal error"));

	return init_mi_result_ok();
}

/* pseudo-variable functions */
static int pv_get_rl_count(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int counter;

	if (!param)
		return pv_get_null(msg, param, res);

	if(pv_get_spec_name(msg, param, res)!=0 || (!(res->flags&PV_VAL_STR))) {
		LM_ERR("invalid name\n");
		return -1;
	}

	counter = rl_get_counter_value(&res->rs);
	if (counter < 0) {
		return pv_get_null(msg, param, res);
	}

	return pv_get_uintval(msg, param, res, counter);
}

static int pv_parse_rl_count(pv_spec_p sp, str *in)
{
	char *p;
	char *s;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.name.s = *in;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	return 0;

}
