/*
 * Benchmarking module for OpenSIPS
 *
 * Copyright (C) 2007 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
 * Copyright (C) 2007 Voice Sistem SRL
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

#define _GNU_SOURCE
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../locking.h"
#include "../../mi/mi.h"
#include "../../mem/mem.h"
#include "../../ut.h"

#include "benchmark.h"

#include "../../mem/shm_mem.h"

#define MI_CALL_INVALID_S              "Call not valid for granularity!=0"
#define MI_CALL_INVALID_LEN            (sizeof(MI_CALL_INVALID_S)-1)

#define STARTING_MIN_VALUE 0xffffffff

/* Exported functions */
static int bm_start_timer(struct sip_msg* _msg, void* timer);
static int bm_log_timer(struct sip_msg* _msg, void* timer);

/*
 * Module destroy function prototype
 */
static void destroy(void);

/*
 * Module child-init function prototype
 */
static int child_init(int rank);

/*
 * Module initialization function prototype
 */
static int mod_init(void);


/*
 * Exported parameters
 * Copied to mycfg on module initialization
 */
static int bm_enable_global = 0;
static int bm_granularity = 100;
static int bm_loglevel = L_INFO;

static int _bm_last_time_diff = 0;

/*
 * Module setup
 */

typedef struct bm_cfg {
	int enable_global;
	int granularity;
	int loglevel;
	/* The internal timers */
	int nrtimers;
	benchmark_timer_t *timers;
	benchmark_timer_t **tindex;
} bm_cfg_t;

/*
 * The setup is located in shared memory so that
 * all instances can access this variable
 */

bm_cfg_t *bm_mycfg = 0;

static inline int fixup_bm_timer(void** param);

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"bm_start_timer", (cmd_function)bm_start_timer, {
		{CMD_PARAM_STR, fixup_bm_timer, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"bm_log_timer",   (cmd_function)bm_log_timer, {
		{CMD_PARAM_STR, fixup_bm_timer, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"load_bm",        (cmd_function)load_bm, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"enable",      INT_PARAM, &bm_enable_global},
	{"granularity", INT_PARAM, &bm_granularity},
	{"loglevel",    INT_PARAM, &bm_loglevel},
	{ 0, 0, 0 }
};


/*
 * Exported MI functions
 */
mi_response_t *mi_bm_enable_global(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_bm_enable_timer(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_bm_granularity(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_bm_loglevel(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_bm_poll_results(const mi_params_t *params,
								struct mi_handler *async_hdl);

static mi_export_t mi_cmds[] = {
	{ "bm_enable_global", 0,0,0, {
		{mi_bm_enable_global, {"enable", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "bm_enable_timer", 0,0,0, {
		{mi_bm_enable_timer, {"timer", "enable", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "bm_granularity", 0,0,0, {
		{mi_bm_granularity, {"granularity", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "bm_loglevel", 0,0,0, {
		{mi_bm_loglevel, {"log_level", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "bm_poll_results", 0,0,0, {
		{mi_bm_poll_results, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static int bm_get_time_diff(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static pv_export_t mod_items[] = {
	{ {"BM_time_diff", sizeof("BM_time_diff")-1}, 1000, bm_get_time_diff, 0,
		0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

/*
 * Module interface
 */
struct module_exports exports = {
	"benchmark",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,          /* load function */
	NULL,       /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	mod_items,  /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* child initialization function */
	0           /* reload confirm function */
};


/****************/


/*
 * mod_init
 * Called by opensips at init time
 */
static int mod_init(void) {

	int ret = 0;

	LM_INFO("benchmark: initializing\n");

	bm_mycfg = (bm_cfg_t*)shm_malloc(sizeof(bm_cfg_t));
	memset(bm_mycfg, 0, sizeof(bm_cfg_t));
	bm_mycfg->enable_global = bm_enable_global;
	if (bm_granularity<0) {
		LM_ERR("benchmark granularity cannot be negative\n");
		return -1;
	}
	bm_mycfg->granularity   = bm_granularity;
	bm_mycfg->loglevel      = bm_loglevel;

	return ret;
}

static int child_init(int rank)
{
	LM_INFO("initing child...\n");
	return 0;
}

/*
 * destroy
 * called by opensips at exit time
 */
static void destroy(void)
{
	benchmark_timer_t *bmt = 0;
	benchmark_timer_t *bmp = 0;

	if(bm_mycfg!=NULL)
	{
		/* free timers list */
		bmt = bm_mycfg->timers;
		while(bmt)
		{
			bmp = bmt;
			bmt = bmt->next;
			shm_free(bmp);
		}
		if(bm_mycfg->tindex)
			shm_free(bm_mycfg->tindex);
		shm_free(bm_mycfg);
	}
}

/* timer should be locked when calling this function */
static void soft_reset_timer(benchmark_timer_t *timer) {
	timer->calls = 0;
	timer->last_sum = 0;
	timer->last_max = 0;
	timer->last_min = STARTING_MIN_VALUE;
}

static void reset_timer(int i)
{
	benchmark_timer_t *timer;

	if(bm_mycfg==NULL || (timer = bm_mycfg->tindex[i])==NULL)
		return;

	lock_get(timer->lock);

	timer->calls = 0;
	timer->sum = 0;
	timer->last_max = 0;
	timer->last_min = STARTING_MIN_VALUE;
	timer->last_sum = 0;
	timer->global_calls = 0;
	timer->global_max = 0;
	timer->global_min = STARTING_MIN_VALUE;

	lock_release(timer->lock);
}

/*
 * timer_active().
 * Global enable mode can be:
 * -1 - All timing disabled
 *  0 - Timing enabled, watch for single timers enabled (default: off)
 *  1 - Timing enabled for all timers
 */

static inline int timer_active(unsigned int id)
{
	if (bm_mycfg->enable_global > 0 || bm_mycfg->timers[id].enabled > 0)
		return 1;
	else
		return 0;
}


/*
 * start_timer()
 */

static int _bm_start_timer(unsigned int id)
{
	if (timer_active(id))
	{
		if(bm_get_time(bm_mycfg->tindex[id]->start)!=0)
		{
			LM_ERR("error getting current time\n");
			return -1;
		}
	}

	return 1;
}

static int bm_start_timer(struct sip_msg* _msg, void* timer)
{
	return _bm_start_timer((unsigned int)(unsigned long)timer);
}


/*
 * log_timer()
 */

static int _bm_log_timer(unsigned int id)
{
	/* BM_CLOCK_REALTIME */
	bm_timeval_t now;
	unsigned long long tdiff;
	benchmark_timer_t *timer;

	if (!timer_active(id))
		return 1;

	if(bm_get_time(&now)<0)
	{
		LM_ERR("error getting current time\n");
		return -1;
	}

	timer = bm_mycfg->tindex[id];
	tdiff = bm_diff_time(timer->start, &now);
	_bm_last_time_diff = (int)tdiff;

	/* What to do
	 * - update min, max, sum
	 * - if granularity hit: Log, reset min/max
	 */

	lock_get(timer->lock);

	timer->sum += tdiff;
	timer->last_sum += tdiff;
	timer->calls++;
	timer->global_calls++;

	if (tdiff < timer->last_min)
		timer->last_min = tdiff;

	if (tdiff > timer->last_max)
		timer->last_max = tdiff;

	if (tdiff < timer->global_min)
		timer->global_min = tdiff;

	if (tdiff > timer->global_max)
		timer->global_max = tdiff;


	if (bm_mycfg->granularity > 0 && timer->calls >= bm_mycfg->granularity)
	{
		LM_GEN1(bm_mycfg->loglevel, "benchmark (timer %s [%d]): %llu ["
			" msgs/total/min/max/avg - LR:"
			" %i/%lld/%lld/%lld/%f | GB: %lld/%lld/%lld/%lld/%f]\n",
			timer->name,
			id,
			tdiff,
			timer->calls,
			timer->last_sum,
			timer->last_min,
			timer->last_max,
			((double)timer->last_sum)/bm_mycfg->granularity,
			timer->global_calls,
			timer->sum,
			timer->global_min,
			timer->global_max,
			((double)timer->sum)/timer->global_calls);

		soft_reset_timer(timer);
	}

	lock_release(timer->lock);

	return 1;
}

static int bm_log_timer(struct sip_msg* _msg, void* timer)
{
	return _bm_log_timer((unsigned int)(unsigned long)timer);
}

static int _bm_register_timer(char *tname, int mode, unsigned int *id)
{
	benchmark_timer_t *bmt = 0;
	benchmark_timer_t **tidx = 0;

	if(tname==NULL || id==NULL || bm_mycfg==NULL || strlen(tname)==0
			|| strlen(tname)>BM_NAME_LEN-1)
		return -1;

	bmt = bm_mycfg->timers;
	while(bmt)
	{
		if(strcmp(bmt->name, tname)==0)
		{
			*id = bmt->id;
			return 0;
		}
		bmt = bmt->next;
	}
	if(mode==0)
		return -1;

	bmt = (benchmark_timer_t*)shm_malloc(sizeof(benchmark_timer_t));

	if(bmt==0)
	{
		LM_ERR("no more shm\n");
		return -1;
	}
	memset(bmt, 0, sizeof(benchmark_timer_t));

	bmt->lock = lock_alloc();
	if(bmt->lock == NULL) {
		shm_free(bmt);
		LM_ERR("no more shm\n");
		return -1;
	}

	if (!lock_init(bmt->lock)) {
		lock_dealloc(bmt->lock);
		shm_free(bmt);
		LM_ERR("failed to init lock\n");
		return -1;
	}

	/* private memory, otherwise we have races */
	bmt->start = (bm_timeval_t*)pkg_malloc(sizeof(bm_timeval_t));
	if(bmt->start == NULL)
	{
		lock_dealloc(bmt->lock);
		shm_free(bmt);
		LM_ERR("no more pkg\n");
		return -1;
	}
	memset(bmt->start, 0, sizeof(bm_timeval_t));

	strcpy(bmt->name, tname);
	if(bm_mycfg->timers==0)
	{
		bmt->id = 0;
		bm_mycfg->timers = bmt;
	} else {
		bmt->id = bm_mycfg->timers->id+1;
		bmt->next = bm_mycfg->timers;
		bm_mycfg->timers = bmt;
	}

	/* do the indexing */
	if(bmt->id%10==0)
	{
		if(bm_mycfg->tindex!=NULL)
			tidx = bm_mycfg->tindex;
		bm_mycfg->tindex = (benchmark_timer_t**)shm_malloc((10+bmt->id)*
								sizeof(benchmark_timer_t*));
		if(bm_mycfg->tindex==0)
		{
			LM_ERR("no more share memory\n");
			if(tidx!=0)
				shm_free(tidx);
			return -1;
		}
		memset(bm_mycfg->tindex, 0, (10+bmt->id)*sizeof(benchmark_timer_t*));
		if(tidx!=0)
		{
			memcpy(bm_mycfg->tindex, tidx, bmt->id*sizeof(benchmark_timer_t*));
			shm_free(tidx);
		}
	}
	bm_mycfg->tindex[bmt->id] = bmt;
	bm_mycfg->nrtimers = bmt->id + 1;
	reset_timer(bmt->id);
	*id = bmt->id;
	LM_DBG("timer [%s] added with index <%u>\n", bmt->name, bmt->id);

	return 0;
}

/* API Binding */

int load_bm( struct bm_binds *bmb)
{
	if(bmb==NULL)
		return -1;

	bmb->bm_register = _bm_register_timer;
	bmb->bm_start    = _bm_start_timer;
	bmb->bm_log	     = _bm_log_timer;

	return 1;
}


static inline char * pkg_strndup( char* _p, int _len)
{
	char *s;

	s = (char*)pkg_malloc(_len+1);
	if (s==NULL)
		return NULL;
	memcpy(s,_p,_len);
	s[_len] = 0;
	return s;
}


/* MI functions */

/*
 * Expects 1 node: 0 for disable, 1 for enable
 */
mi_response_t *mi_bm_enable_global(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int v1;

	if (get_mi_int_param(params, "enable", &v1) < 0)
		init_mi_param_error();

	if ((v1 < -1) || (v1 > 1))
		return init_mi_error(400, MI_SSTR("Bad parameter value"));

	bm_mycfg->enable_global = v1;

	return init_mi_result_ok();
}

mi_response_t *mi_bm_enable_timer(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	char *p1;
	int v2;
	unsigned int id;
	str timer;

	if (get_mi_string_param(params, "timer", &timer.s, &timer.len) < 0)
		return init_mi_param_error();

	p1 = pkg_strndup(timer.s, timer.len);

	if(_bm_register_timer(p1, 0, &id)!=0)
	{
		pkg_free(p1);
		return init_mi_error(400, MI_SSTR("Failed to register timer"));
	}

	pkg_free(p1);

	if (get_mi_int_param(params, "enable", &v2) < 0)
		init_mi_param_error();	

	if ((v2 < 0) || (v2 > 1))
		return init_mi_error(400, MI_SSTR("Bad parameter value"));

	bm_mycfg->timers[id].enabled = v2;

	return init_mi_result_ok();
}

mi_response_t *mi_bm_granularity(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int v1;

	if (get_mi_int_param(params, "granularity", &v1) < 0)
		init_mi_param_error();

	if (v1 < 0)
		return init_mi_error(400, MI_SSTR("Bad value for parameter"));

	bm_mycfg->granularity = v1;

	return init_mi_result_ok();
}

mi_response_t *mi_bm_loglevel(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int v1;

	if (get_mi_int_param(params, "log_level", &v1) < 0)
		init_mi_param_error();	

	if ((v1 < -3) || (v1 > 4)) /* Maximum log levels */
		return init_mi_error(400, MI_SSTR("Bad value for parameter"));

	bm_mycfg->enable_global = v1;

	return init_mi_result_ok();
}

static int add_results_item(mi_item_t *timer_item, benchmark_timer_t *timer)
{
	if (add_mi_string(timer_item, MI_SSTR("name"),
		timer->name, strlen(timer->name)) < 0)
		return -1;

	if (add_mi_string_fmt(timer_item, MI_SSTR("global"), "%i/%lld/%lld/%lld/%f",
		timer->calls,
		timer->last_sum,
		timer->last_min==STARTING_MIN_VALUE?0:timer->last_min,
		timer->last_max,
		timer->calls?((double)timer->last_sum)/timer->calls:0.) < 0)
		return -1;

	if (add_mi_string_fmt(timer_item, MI_SSTR("local"), "%lld/%lld/%lld/%lld/%f",
		timer->global_calls,
			timer->sum,
			timer->global_min==STARTING_MIN_VALUE?0:timer->global_min,
			timer->global_max,
			timer->global_calls?((double)timer->sum)/timer->global_calls:0.) < 0)
		return -1;

	return 0;
}

mi_response_t *mi_bm_poll_results(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *timers_arr, *timer_item;
	benchmark_timer_t *bmt;
	int rc;

	if (bm_mycfg->granularity!=0)
		return init_mi_error(400, MI_CALL_INVALID_S, MI_CALL_INVALID_LEN);

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	timers_arr = add_mi_array(resp_obj, MI_SSTR("Timers"));
	if (!timers_arr)
		goto error;

	for(bmt = bm_mycfg->timers; bmt!=NULL; bmt=bmt->next) {
		timer_item = add_mi_object(timers_arr, NULL, 0);
		if (!timer_item)
			goto error;

		lock_get(bmt->lock);

		rc = add_results_item(timer_item, bmt);
		soft_reset_timer(bmt);

		lock_release(bmt->lock);

		if (rc < 0)
			goto error;
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

/* item functions */
static int bm_get_time_diff(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;
	return pv_get_sintval(msg, param, res, _bm_last_time_diff);
}


static inline int fixup_bm_timer(void** param)
{
	unsigned int tid = 0;
	str tname;

	if (pkg_nt_str_dup(&tname, (str*)*param) < 0)
		return E_UNSPEC;
	
	if((_bm_register_timer(tname.s, 1, &tid))!=0)
	{
		LM_ERR("cannot register timer [%s]\n", (char*)(*param));
		pkg_free(tname.s);
		return E_UNSPEC;
	}

	*param = (void*)(unsigned long)tid;

	pkg_free(tname.s);
	return 0;
}

/* End of file */
