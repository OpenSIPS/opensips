/*
 * Copyright (C) 2007 1&1 Internet AG
 * Copyright (C) 2007 BASIS AudioNet GmbH
 *
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
 * --------
 *  2007-03-22  initial module created (Henning Westerholt)
 *  2007-03-29  adaption to opensips 1.2 and some cleanups
 *  2007-04-20  rename to cfgutils, use pseudovariable for get_random_val
 *              add "rand_" prefix, add sleep and usleep functions
 *  2008-12-26  pseudovar argument for sleep and usleep functions (saguti).
 *  2012-11-21  added script locks (Liviu)
 *
 * cfgutils module: random probability functions for opensips;
 * it provide functions to make a decision in the script
 * of the server based on a probability function.
 * The benefit of this module is the value of the probability function
 * can be manipulated by external applications such as web interface
 * or command line tools.
 * Furthermore it provides some functions to let the server wait a
 * specific time interval.
 *
 */
#include <stdlib.h>
#ifdef __OS_linux
#include <features.h>     /* for GLIBC version testing */
#endif

#include "../../sr_module.h"
#include "../../error.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../mod_fix.h"
#include "../../md5utils.h"
#include "../../globals.h"
#include "../../time_rec.h"
#include "../../timer.h"
#include "shvar.h"
#include "env_var.h"
#include "script_locks.h"

#include "../../lib/timerfd.h"
#ifndef HAVE_TIMER_FD
#ifdef __OS_linux
	#warning Your GLIB is too old, disabling async sleep functions!!!
#endif
#endif

/* FIFO action protocol names */
#define FIFO_SET_PROB   "rand_set_prob"
#define FIFO_RESET_PROB "rand_reset_prob"
#define FIFO_GET_PROB   "rand_get_prob"
#define FIFO_GET_HASH   "get_config_hash"
#define FIFO_CHECK_HASH "check_config_hash"

static int fixup_check_pv_setf(void **param);
static int fixup_str(void **param);
static int fixup_free_str(void **param);

static int set_prob(struct sip_msg *bar, int *percent_par);
static int reset_prob(struct sip_msg*);
static int get_prob(struct sip_msg*);
static int rand_event(struct sip_msg *bar, int *prob_param);
static int m_sleep(struct sip_msg *msg, int *seconds);
static int m_usleep(struct sip_msg*, int *);
static int dbg_abort(struct sip_msg*);
static int dbg_pkg_status(struct sip_msg*);
static int dbg_shm_status(struct sip_msg*);
static int get_accurate_time(struct sip_msg* msg,
			pv_spec_t *pv_sec, pv_spec_t *pv_usec, pv_spec_t *pv_sec_usec);
static int pv_set_count(struct sip_msg* msg,
					pv_spec_t *pv_name, pv_spec_t *pv_result);
static int pv_sel_weight(struct sip_msg* msg, pv_spec_t *pv_name);

mi_response_t *mi_set_prob(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_reset_prob(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_prob(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_hash(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_check_hash(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int pv_get_random_val(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static int ts_usec_delta(struct sip_msg *msg, int *t1s,
		int *t1u, int *t2s, int *t2u, pv_spec_t *_res);
int check_time_rec(struct sip_msg *msg, str *time_str, unsigned int *ptime);

#ifdef HAVE_TIMER_FD
static int async_sleep(struct sip_msg* msg,
		async_ctx *ctx, int *seconds);

static int async_usleep(struct sip_msg* msg,
		async_ctx *ctx, int *duration);
#endif

static int mod_init(void);
static void mod_destroy(void);

static int initial = 10;
static int *probability;

static char config_hash[MD5_LEN];
static char* hash_file = NULL;

int lock_pool_size = 32;


static cmd_export_t cmds[]={
	{"rand_set_prob", (cmd_function)set_prob, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_reset_prob", (cmd_function)reset_prob, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_get_prob", (cmd_function)get_prob, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_event", (cmd_function)rand_event, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"sleep", (cmd_function)m_sleep, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"usleep", (cmd_function)m_usleep, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"abort", (cmd_function)dbg_abort, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"pkg_status", (cmd_function)dbg_pkg_status, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"shm_status", (cmd_function)dbg_shm_status, {{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"set_count",  (cmd_function)pv_set_count, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"set_select_weight",(cmd_function)pv_sel_weight, {
		{CMD_PARAM_VAR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"get_accurate_time",  (cmd_function)get_accurate_time, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ts_usec_delta", (cmd_function)ts_usec_delta, {
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_INT, 0, 0},
		{CMD_PARAM_VAR, fixup_check_pv_setf, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"get_static_lock",(cmd_function)get_static_lock, {
		{CMD_PARAM_STR, fixup_static_lock, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"check_time_rec", (cmd_function)check_time_rec, {
		{CMD_PARAM_STR, fixup_str, fixup_free_str},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},{0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"release_static_lock",(cmd_function)release_static_lock, {
		{CMD_PARAM_STR, fixup_static_lock, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"get_dynamic_lock",(cmd_function)get_dynamic_lock, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"release_dynamic_lock",(cmd_function)release_dynamic_lock, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"strings_share_lock",(cmd_function)strings_share_lock, {
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0,0,{{0,0,0}},0}
};

static acmd_export_t acmds[] = {
#ifdef HAVE_TIMER_FD
	{"sleep", (acmd_function)async_sleep, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}}},
	{"usleep", (acmd_function)async_usleep, {
		{CMD_PARAM_INT, 0, 0}, {0,0,0}}},
#endif
	{0,0,{{0,0,0}}}
};


static param_export_t params[]={
	{"initial_probability", INT_PARAM, &initial},
	{"hash_file",           STR_PARAM, &hash_file        },
	{"shvset",              STR_PARAM|USE_FUNC_PARAM, (void*)param_set_shvar },
	{"varset",              STR_PARAM|USE_FUNC_PARAM, (void*)param_set_var },
	{"lock_pool_size",      INT_PARAM, &lock_pool_size},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ FIFO_SET_PROB, 0, 0, 0, {
		{mi_set_prob, {"prob_proc", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_RESET_PROB, 0, 0, 0, {
		{mi_reset_prob, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_GET_PROB, 0, 0, 0, {
		{mi_get_prob, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_GET_HASH, 0, 0, 0, {
		{mi_get_hash, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_CHECK_HASH, 0, 0, 0, {
		{mi_check_hash, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "shv_get", 0, 0, 0, {
		{mi_shvar_get, {0}},
		{mi_shvar_get_1, {"name", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "shv_set", 0, 0, 0, {
		{mi_shvar_set, {"name", "type", "value", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static pv_export_t mod_items[] = {
	{ {"RANDOM", sizeof("RANDOM")-1}, 1000, pv_get_random_val, 0,
		0, 0, 0, 0 },
	{ {"shv", (sizeof("shv")-1)}, 1001, pv_get_shvar,
		pv_set_shvar, pv_parse_shvar_name, 0, 0, 0},
	{ {"ctime", (sizeof("ctime")-1)}, 1002, pv_get_time,
		0, pv_parse_time_name, 0, 0, 0},
	{ {"env", (sizeof("env")-1)}, 1002, pv_get_env,
		0, pv_parse_env_name, 0, 0, 0},

	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
	"cfgutils",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,        /* exported functions */
	acmds,       /* exported async functions */
	params,      /* exported parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_items,   /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,           /* extra processes */
	0,           /* module pre-initialization function */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	0,           /* per-child init function */
	0            /* reload confirm function */
};


/**************************** fixup functions ******************************/

static int fixup_check_pv_setf(void **param)
{
	if (((pv_spec_t*)*param)->setf == 0) {
		LM_ERR("invalid pvar\n");
		return E_SCRIPT;
	}

	return 0;
}

static int fixup_str(void **param)
{
	str *s;

	s = pkg_malloc(sizeof *s);
	if (!s) {
		LM_ERR("no more pkg mem\n");
		return E_OUT_OF_MEM;
	}

	if (pkg_nt_str_dup(s, (str*)*param) < 0)
		return E_OUT_OF_MEM;

	*param = s;

	return 0;
}

static int fixup_free_str(void **param)
{
	pkg_free(*param);

	return 0;
}

/************************** module functions **********************************/

mi_response_t *mi_set_prob(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int percent;

	if (get_mi_int_param(params, "prob_proc", &percent) < 0)
		return init_mi_param_error();

	if (percent > 100) {
		LM_ERR("incorrect probability <%u>\n", percent);
		return init_mi_error(400, MI_SSTR("Bad parameter value"));
	}

	*probability = percent;

	return init_mi_result_ok();
}

mi_response_t *mi_reset_prob(const mi_params_t *params,
								struct mi_handler *async_hdl)
{

	*probability = initial;
	return init_mi_result_ok();
}

mi_response_t *mi_get_prob(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
	if (add_mi_number(resp_obj, MI_SSTR("actual probability percent"),
		*probability) < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

mi_response_t *mi_get_hash(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (!hash_file) {
		LM_INFO("no hash_file given, disable hash functionality\n");
		return init_mi_error(404, MI_SSTR("Functionality disabled"));
	} else {
		return init_mi_result_string(config_hash, MD5_LEN);
	}
}

mi_response_t *mi_check_hash(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	char tmp[MD5_LEN];
	memset(tmp, 0, MD5_LEN);

	if (!hash_file) {
		LM_INFO("no hash_file given, disable hash functionality\n");
		return init_mi_error(404, MI_SSTR("Functionality disabled"));
	} else {
		if (MD5File(tmp, hash_file) != 0) {
			LM_ERR("could not hash the config file\n");
			return init_mi_error(500, MI_SSTR("Internal error"));
		}

		if (strncmp(config_hash, tmp, MD5_LEN) == 0)
			return init_mi_result_string(MI_SSTR("The actual config file hash "
				"is identical to the stored one."));
		else
			return init_mi_error(400, MI_SSTR("The actual config file hash is not "
				"identical to the stored one.")); 
	}
}

static int set_prob(struct sip_msg *bar, int *percent_par)
{
	*probability=*percent_par;
	return 1;
}

static int reset_prob(struct sip_msg *bar)
{
	*probability=initial;
	return 1;
}

static int get_prob(struct sip_msg *bar)
{
	return *probability;
}


static int rand_event(struct sip_msg *bar, int *prob_param)
{
	double tmp = ((double) rand() / RAND_MAX);
	int prob = *probability;

	LM_DBG("generated random %f\n", tmp);
	LM_DBG("my pid is %d\n", getpid());

	if (prob_param) {
		prob = *prob_param;
		LM_DBG("new probability is %d\n", prob);
	}

	if (tmp < ((double) (prob) / 100)) {
		LM_DBG("return true\n");
		return 1;
	}
	else {
		LM_DBG("return false\n");
		return -1;
	}
}

static int pv_get_random_val(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int n;
	int l = 0;
	char *ch;

	if(msg==NULL || res==NULL)
		return -1;
	n = rand();

	ch = int2str(n , &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->ri = n;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

static int m_sleep(struct sip_msg *msg, int *seconds)
{
	LM_DBG("sleep %d\n", *(unsigned int*)seconds);

	sleep(*(unsigned int*)seconds);

	return 1;
}

static int m_usleep(struct sip_msg *msg, int *useconds)
{
	LM_DBG("sleep %d\n", *(unsigned int*)useconds);

	sleep_us(*(unsigned int*)useconds);

	return 1;
}


#ifdef HAVE_TIMER_FD
int resume_async_sleep(int fd, struct sip_msg *msg, void *param)
{
	unsigned long now = (unsigned long)
		(((unsigned long)-1) & get_uticks());

	/* apply a sync correction if (for whatever reasons) the sleep
	 * did not cover the whole interval so far */
	if ( ((unsigned long)param) > (now+UTIMER_TICK) )
		sleep_us((unsigned int)((unsigned long)param - now));

	close (fd);
	async_status = ASYNC_DONE;

	return 1;
}


static int async_sleep(struct sip_msg* msg, async_ctx *ctx, int *seconds)
{
	struct itimerspec its;
	int fd;

	LM_DBG("sleep %d seconds\n", *(unsigned int*)seconds);

	/* create the timer fd */
	if ( (fd=timerfd_create( CLOCK_REALTIME, 0))<0 ) {
		LM_ERR("failed to create new timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* set the time */
	its.it_value.tv_sec = *(unsigned int*)seconds;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timerfd_settime( fd, 0, &its, NULL)<0) {
		LM_ERR("failed to set timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* start the async wait */
	ctx->resume_param = (void*)(unsigned long)
		(((unsigned long)-1) & (get_uticks()+1000000*(*(unsigned int*)seconds)));
	ctx->resume_f = resume_async_sleep;
	async_status = fd;

	return 1;
}


static int async_usleep(struct sip_msg* msg, async_ctx *ctx, int *useconds)
{
	struct itimerspec its;
	int fd;

	LM_DBG("sleep %d useconds\n", *(unsigned int *)useconds);

	/* create the timer fd */
	if ( (fd=timerfd_create( CLOCK_REALTIME, 0))<0 ) {
		LM_ERR("failed to create new timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* set the time */
	its.it_value.tv_sec = (*(unsigned int *)useconds / 1000000);
	its.it_value.tv_nsec = (*(unsigned int *)useconds % 1000000) * 1000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timerfd_settime( fd, 0, &its, NULL)<0) {
		LM_ERR("failed to set timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* start the async wait */
	ctx->resume_param = (void*)(unsigned long)
		(((unsigned long)-1) & (get_uticks()+*(unsigned int *)useconds));
	ctx->resume_f = resume_async_sleep;
	async_status = fd;

	return 1;
}
#endif


static int dbg_abort(struct sip_msg* msg)
{
	LM_CRIT("abort called\n");
	abort();
	return 0;
}

static int dbg_pkg_status(struct sip_msg* msg)
{
	pkg_status();
	return 1;
}

static int dbg_shm_status(struct sip_msg* msg)
{
	shm_status();
	return 1;
}

static int mod_init(void)
{
	if (!hash_file) {
		LM_INFO("no hash_file given, disable hash functionality\n");
	} else {
		if (MD5File(config_hash, hash_file) != 0) {
			LM_ERR("could not hash the config file\n");
			return -1;
		}
		LM_DBG("config file hash is %.*s", MD5_LEN, config_hash);
	}

	if (initial > 100) {
		LM_ERR("invalid probability <%d>\n", initial);
		return -1;
	}
	LM_DBG("initial probability %d percent\n", initial);

	probability=(int *) shm_malloc(sizeof(int));

	if (!probability) {
		LM_ERR("no shmem available\n");
		return -1;
	}
	*probability = initial;

	if (lock_pool_size < 1) {
		LM_ERR("Invalid lock size parameter (%d)!\n", lock_pool_size);
		return -1;
	}

	if (create_dynamic_locks() != 0) {
		LM_ERR("Failed to create dynamic locks\n");
		return -1;
	}

	LM_INFO("module initialized, pid [%d]\n", getpid());

	return 0;
}


static void mod_destroy(void)
{
	if (probability)
		shm_free(probability);
	shvar_destroy_locks();
	destroy_shvars();

	destroy_script_locks();
}


static int get_accurate_time(struct sip_msg* msg,
			pv_spec_t *pv_sec, pv_spec_t *pv_usec, pv_spec_t *pv_sec_usec)
{
	struct timeval tv;
	pv_value_t val;
	char sec_usec_buf[20 + 1 + 20 + 1];

	if (gettimeofday(&tv, NULL) != 0)
		return -1;

	memset(&val, 0, sizeof val);

	val.flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	val.ri = tv.tv_sec;
	val.rs.s = int2str(tv.tv_sec, &val.rs.len);
	if (pv_set_value(msg, pv_sec, 0, &val) != 0) {
		LM_ERR("failed to set 'pv_sec'\n");
		return -1;
	}

	val.flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	val.ri = tv.tv_usec;
	val.rs.s = int2str(tv.tv_usec, &val.rs.len);
	if (pv_set_value(msg, pv_usec, 0, &val) != 0) {
		LM_ERR("failed to set 'pv_usec'\n");
		return -1;
	}

	if (pv_sec_usec) {
		memset(&val, 0, sizeof val);

		val.flags = PV_VAL_STR;
		val.rs.s = sec_usec_buf;
		val.rs.len = sprintf(sec_usec_buf, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
		if (pv_set_value(msg, pv_sec_usec, 0, &val) != 0) {
			LM_ERR("failed to set 'pv_sec_usec'\n");
			return -1;
		}
	}

	return 1;
}


static int pv_set_count(struct sip_msg* msg, pv_spec_t *pv_name, pv_spec_t *pv_result)
{
	pv_value_t pv_val;

	memset(&pv_val, 0, sizeof(pv_value_t));

	pv_name->pvp.pvi.type = PV_IDX_INT;
	pv_name->pvp.pvi.u.ival = 0;

	while(pv_val.flags != PV_VAL_NULL)
	{
		if(pv_get_spec_value(msg, pv_name, &pv_val) < 0)
		{
			LM_ERR("PV get function failed\n");
			return -1;
		}
		pv_name->pvp.pvi.u.ival++;
	}

	pv_val.flags = PV_TYPE_INT;
	pv_val.ri = pv_name->pvp.pvi.u.ival-1;

	if (pv_set_value( msg, pv_result, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	LM_DBG("Set count = %d\n", pv_val.ri);
	return 1;
}

/* This function does selection based on the
 * fitness proportionate selection also known as roulette-wheel selection*/
static int pv_sel_weight(struct sip_msg* msg, pv_spec_t *pv_name)
{
	int size;
	int *vals = NULL;
	int sum = 0;
	int rnd_val;
	int prev_val;
	pv_value_t pv_val;
	int i;

	memset(&pv_val, 0, sizeof(pv_value_t));

	pv_name->pvp.pvi.type = PV_IDX_INT;
	pv_name->pvp.pvi.u.ival = 0;

	while(pv_val.flags != PV_VAL_NULL)
	{
		if(pv_get_spec_value(msg, pv_name, &pv_val) < 0)
		{
			LM_ERR("PV get function failed\n");
			return -1;
		}
		if((!(pv_val.flags & PV_VAL_INT)) && (pv_val.flags != PV_VAL_NULL))
		{
			LM_ERR("Applied select weight algorithm for a varible set"
					" containing not only integer values\n");
			return -1;
		}

		pv_name->pvp.pvi.u.ival++;
	}
	size = pv_name->pvp.pvi.u.ival - 1;

	if(size <= 0)
		return -1;

	if(size == 1)
		return 0;

	vals = (int*)pkg_malloc(size* sizeof(int));
	if(vals == NULL)
	{
		LM_ERR("No more private memory\n");
		return -1;
	}
	memset(vals, 0, size*sizeof(int));

	for(i= 0; i< size; i++)
	{
		pv_name->pvp.pvi.u.ival = i;
		if(pv_get_spec_value(msg, pv_name, &pv_val) < 0)
		{
			LM_ERR("PV get function failed\n");
			goto error;
		}
		vals[i]= sum + pv_val.ri;
		sum = vals[i];
	}

	/* generate a random value */
	rnd_val = random() % sum;

	/* find out which segment it belongs to */
	prev_val = 0;
	for(i = 0; i< size; i++)
	{
		if(rnd_val >= prev_val && rnd_val < vals[i])
			break;
		prev_val = vals[i];
	}
	LM_DBG("The interval is %d - %d\n", prev_val, vals[i]);
	pkg_free(vals);

	return i;

error:
	if(vals)
		pkg_free(vals);
	return -1;
}

static int ts_usec_delta(struct sip_msg *msg, int *t1s,
		int *t1u, int *t2s, int *t2u, pv_spec_t *_res)
{
	pv_value_t res;

	res.ri = abs(1000000 * (*t1s - *t2s) + *t1u - *t2u);
	res.flags = PV_TYPE_INT;

	if (pv_set_value(msg, _res, 0, &res)) {
		LM_ERR("cannot store result value\n");
		return -1;
	}
	return 1;
}

/**
 *
 * return values:
			1 - match
			-1 - otherwise
 */
int check_time_rec(struct sip_msg *msg, str *time_str, unsigned int *ptime)
{
	tmrec_p time_rec = 0;
	char *p, *s;
	ac_tm_t att;

	p = time_str->s;

	LM_DBG("Parsing : %.*s\n", time_str->len, time_str->s);

	time_rec = tmrec_new(PKG_ALLOC);
	if (time_rec==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}

	load_TR_value( p, s, time_rec, tr_parse_dtstart, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_dtend, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_duration, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_freq, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_until, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_interval, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byyday, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_byweekno, parse_error, done);
	load_TR_value( p, s, time_rec, tr_parse_bymonth, parse_error, done);

	/* success */

	LM_DBG("Time rec created\n");

done:
	/* shortcut: if there is no dstart, timerec is valid */
	if (time_rec->dtstart==0)
		goto success;

	memset( &att, 0, sizeof(att));

	/* set current time */
	if ( ac_tm_set_time( &att, ptime?(time_t)*ptime:time(0) ) )
		goto error;

	/* does the recv_time match the specified interval?  */
	if (check_tmrec( time_rec, &att, 0)!=0)
		goto error;

success:
	tmrec_free(time_rec);

	return 1;

parse_error:
	LM_ERR("parse error in <%s> around position %i\n",
		time_str->s, (int)(long)(p-time_str->s));
error:
	if (time_rec)
		tmrec_free( time_rec );
	return -1;
}
