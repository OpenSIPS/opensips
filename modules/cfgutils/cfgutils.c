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


static int set_prob(struct sip_msg*, char *, char *);
static int reset_prob(struct sip_msg*, char *, char *);
static int get_prob(struct sip_msg*, char *, char *);
static int rand_event(struct sip_msg*, char *, char *);
static int m_sleep(struct sip_msg*, char *, char *);
static int m_usleep(struct sip_msg*, char *, char *);
static int dbg_abort(struct sip_msg*, char*,char*);
static int dbg_pkg_status(struct sip_msg*, char*,char*);
static int dbg_shm_status(struct sip_msg*, char*,char*);
static int pv_set_count(struct sip_msg*, char*,char*);
static int pv_sel_weight(struct sip_msg*, char*,char*);

static struct mi_root* mi_set_prob(struct mi_root* cmd, void* param );
static struct mi_root* mi_reset_prob(struct mi_root* cmd, void* param );
static struct mi_root* mi_get_prob(struct mi_root* cmd, void* param );
static struct mi_root* mi_get_hash(struct mi_root* cmd, void* param );
static struct mi_root* mi_check_hash(struct mi_root* cmd, void* param );

static int pv_get_random_val(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

static int ts_usec_delta(struct sip_msg *msg, char *_t1s,
		char *_t1u, char *_t2s, char *_t2u, char *_res);
static int check_time_rec(struct sip_msg*, char *);

#ifdef HAVE_TIMER_FD
static int async_sleep(struct sip_msg* msg,
		async_resume_module **resume_f, void **resume_param,
		char *duration);

static int async_usleep(struct sip_msg* msg,
		async_resume_module **resume_f, void **resume_param,
		char *duration);
#endif

static int fixup_prob( void** param, int param_no);
static int fixup_pv_set(void** param, int param_no);
static int fixup_rand_event(void** param, int param_no);
static int fixup_delta(void** param, int param_no);

static int mod_init(void);
static void mod_destroy(void);

static int initial = 10;
static int *probability;

static char config_hash[MD5_LEN];
static char* hash_file = NULL;

int lock_pool_size = 32;

static cmd_export_t cmds[]={
	{"rand_set_prob", /* action name as in scripts */
		(cmd_function)set_prob,  /* C function name */
		1,          /* number of parameters */
		fixup_prob, 0,         /* */
		/* can be applied to original/failed requests and replies */
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_reset_prob", (cmd_function)reset_prob, 0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_get_prob",   (cmd_function)get_prob,   0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_event",      (cmd_function)rand_event, 0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"rand_event",      (cmd_function)rand_event, 1, fixup_rand_event, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"sleep",  (cmd_function)m_sleep,  1, fixup_spve_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"usleep", (cmd_function)m_usleep, 1, fixup_spve_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"abort",      (cmd_function)dbg_abort,        0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"pkg_status", (cmd_function)dbg_pkg_status,   0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"shm_status", (cmd_function)dbg_shm_status,   0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"set_count",  (cmd_function)pv_set_count,       2, fixup_pv_set, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"set_select_weight",(cmd_function)pv_sel_weight,1, fixup_pv_set, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"ts_usec_delta", (cmd_function)ts_usec_delta, 5, fixup_delta, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"get_static_lock",(cmd_function)get_static_lock, 1, fixup_static_lock, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"check_time_rec", (cmd_function)check_time_rec, 1, fixup_sgp_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"release_static_lock",(cmd_function)release_static_lock, 1,
		fixup_static_lock, 0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"get_dynamic_lock",(cmd_function)get_dynamic_lock, 1, fixup_sgp_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"release_dynamic_lock",(cmd_function)release_dynamic_lock, 1,
		fixup_sgp_null, 0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"strings_share_lock",(cmd_function)strings_share_lock, 2,
		fixup_sgp_sgp, 0, REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		BRANCH_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static acmd_export_t acmds[] = {
#ifdef HAVE_TIMER_FD
	{"sleep",  (acmd_function)async_sleep,  1, fixup_spve_null },
	{"usleep", (acmd_function)async_usleep, 1, fixup_spve_null },
#endif
	{0, 0, 0, 0}
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
	{ FIFO_SET_PROB,   0, mi_set_prob,   0,                 0,  0 },
	{ FIFO_RESET_PROB, 0, mi_reset_prob, MI_NO_INPUT_FLAG,  0,  0 },
	{ FIFO_GET_PROB,   0, mi_get_prob,   MI_NO_INPUT_FLAG,  0,  0 },
	{ FIFO_GET_HASH,   0, mi_get_hash,   MI_NO_INPUT_FLAG,  0,  0 },
	{ FIFO_CHECK_HASH, 0, mi_check_hash, MI_NO_INPUT_FLAG,  0,  0 },
	{ "shv_get",       0, mi_shvar_get,  0,                 0,  0 },
	{ "shv_set" ,      0, mi_shvar_set,  0,                 0,  0 },
	{ 0, 0, 0, 0, 0, 0}
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
	NULL,            /* OpenSIPS module dependencies */
	cmds,        /* exported functions */
	acmds,       /* exported async functions */
	params,      /* exported parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_items,   /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	0            /* per-child init function */
};


/**************************** fixup functions ******************************/
static int fixup_prob( void** param, int param_no)
{
	unsigned int myint = 0;
	str param_str;

	/* we only fix the parameter #1 */
	if (param_no!=1)
		return 0;

	param_str.s=(char*) *param;
	param_str.len=strlen(param_str.s);
	if (str2int(&param_str, &myint) < 0 || myint > 100) {
		LM_ERR("invalid probability <%d>\n", myint);
		return E_CFG;
	}

	pkg_free(*param);
	*param=(void *)(long)myint;
	return 0;
}

static int fixup_delta( void **param, int param_no)
{
	if (param_no < 5) {
		return fixup_igp(param);
	} else if (param_no == 5) {
		if (fixup_pvar(param) < 0 && ((pv_spec_p)*param)->setf == 0) {
			LM_ERR("invalid pvar\n");
			return E_SCRIPT;
		}
		return 0;
	 } else {
		 return E_UNSPEC;
	 }
}


/************************** module functions **********************************/

static struct mi_root* mi_set_prob(struct mi_root* cmd, void* param )
{
	unsigned int percent;
	struct mi_node* node;

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if( str2int( &node->value, &percent) <0)
		goto error;
	if (percent > 100) {
		LM_ERR("incorrect probability <%u>\n", percent);
		goto error;
	}
	*probability = percent;
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}

static struct mi_root* mi_reset_prob(struct mi_root* cmd, void* param )
{

	*probability = initial;
	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN );
}

static struct mi_root* mi_get_prob(struct mi_root* cmd, void* param )
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* node= NULL;
	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN );
	if(rpl_tree == NULL)
		return 0;
	node = addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "actual probability: %u percent\n",(*probability));
	if(node == NULL)
		goto error;

	return rpl_tree;

error:
	free_mi_tree(rpl_tree);
	return 0;
}

static struct mi_root* mi_get_hash(struct mi_root* cmd, void* param )
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* node= NULL;

	if (!hash_file) {
		LM_INFO("no hash_file given, disable hash functionality\n");
		rpl_tree = init_mi_tree(404, "Functionality disabled\n", 23);
	} else {
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN );
		if(rpl_tree == NULL)
			return 0;
		node = addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "%.*s\n", MD5_LEN, config_hash);
		if(node == NULL)
			goto error;
	}
	return rpl_tree;

error:
	free_mi_tree(rpl_tree);
	return 0;
}

static struct mi_root* mi_check_hash(struct mi_root* cmd, void* param )
{
	struct mi_root* rpl_tree= NULL;
	struct mi_node* node= NULL;
	char tmp[MD5_LEN];
	memset(tmp, 0, MD5_LEN);

	if (!hash_file) {
		LM_INFO("no hash_file given, disable hash functionality\n");
		rpl_tree = init_mi_tree(404, "Functionality disabled\n", 23);
	} else {
		if (MD5File(tmp, hash_file) != 0) {
			LM_ERR("could not hash the config file");
			rpl_tree = init_mi_tree( 500, MI_INTERNAL_ERR_S, MI_INTERNAL_ERR_LEN );
		}

		if (strncmp(config_hash, tmp, MD5_LEN) == 0) {
			rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN );
			if(rpl_tree == NULL)
				return 0;
			node = addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "The actual config file hash is identical to the stored one.\n");
		} else {
			rpl_tree = init_mi_tree( 400, "Error", 5 );
			if(rpl_tree == NULL)
				return 0;
			node = addf_mi_node_child( &rpl_tree->node, 0, 0, 0, "The actual config file hash is not identical to the stored one.\n");
		}
		if(node == NULL)
			goto error;
	}

	return rpl_tree;

error:
	free_mi_tree(rpl_tree);
	return 0;
}

static int set_prob(struct sip_msg *bar, char *percent_par, char *foo)
{
	*probability=(int)(long)percent_par;
	return 1;
}

static int reset_prob(struct sip_msg *bar, char *percent_par, char *foo)
{
	*probability=initial;
	return 1;
}

static int get_prob(struct sip_msg *bar, char *foo1, char *foo2)
{
	return *probability;
}

static int fixup_rand_event(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	if(param_no== 0)
		return 0;

	if(*param)
	{
		s.s = (char*)(*param); s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR( "wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}
		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
}

static int rand_event(struct sip_msg *bar, char *prob_param, char *foo2)
{
	double tmp = ((double) rand() / RAND_MAX);
	int prob = *probability;
	str pr;

	LM_DBG("generated random %f\n", tmp);
	LM_DBG("my pid is %d\n", getpid());

	if (prob_param) {
		if (((pv_elem_p)prob_param)->spec.getf!=NULL) {
			if(pv_printf_s(bar, (pv_elem_p)prob_param, &pr)!=0 || pr.len <=0)
				return -1;
		} else {
			pr = ((pv_elem_p)prob_param)->text;
		}
		if (str2sint(&pr, &prob) < 0) {
			LM_ERR("invalid probability <%.*s>\n", pr.len, pr.s);
			return -1;
		}
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

static int m_sleep(struct sip_msg *msg, char *time, char *str2)
{
	str time_s={NULL,0};
	long seconds;

	if(time == NULL || fixup_get_svalue(msg, (gparam_p)time, &time_s)!=0) {
		LM_ERR("Invalid time argument\n");
		return -1;
	}

	seconds = atol(time_s.s);
	LM_DBG("sleep %d\n", (unsigned int)seconds);

	sleep((unsigned int)seconds);

	return 1;
}

static int m_usleep(struct sip_msg *msg, char *time, char *str2)
{
	str time_s= { NULL, 0 };
	long useconds;

	if(time == NULL || fixup_get_svalue(msg, (gparam_p)time, &time_s) != 0) {
		LM_ERR("Invalid useconds argument.\n");
		return -1;
	}

	useconds = atol(time_s.s);
	LM_DBG("sleep %d\n", (unsigned int)useconds);

	sleep_us((unsigned int)useconds);

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


static int async_sleep(struct sip_msg* msg, async_resume_module **resume_f,
										void **resume_param, char *time)
{
	str time_s={NULL,0};
	unsigned int seconds;
	struct itimerspec its;
	int fd;

	if(time == NULL || fixup_get_svalue(msg, (gparam_p)time, &time_s)!=0) {
		LM_ERR("Invalid time argument\n");
		return -1;
	}

	if ( str2int( &time_s, &seconds) != 0 ) {
		LM_ERR("time to sleep <%.*s> is not integer\n",
			time_s.len,time_s.s);
		return -1;
	}
	LM_DBG("sleep %d seconds\n", seconds);

	/* create the timer fd */
	if ( (fd=timerfd_create( CLOCK_REALTIME, 0))<0 ) {
		LM_ERR("failed to create new timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* set the time */
	its.it_value.tv_sec = seconds;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timerfd_settime( fd, 0, &its, NULL)<0) {
		LM_ERR("failed to set timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* start the async wait */
	*resume_param = (void*)(unsigned long)
		(((unsigned long)-1) & (get_uticks()+1000000*seconds));
	*resume_f = resume_async_sleep;
	async_status = fd;

	return 1;
}


static int async_usleep(struct sip_msg* msg, async_resume_module **resume_f,
										void **resume_param, char *time)
{
	str time_s={NULL,0};
	unsigned int useconds;
	struct itimerspec its;
	int fd;

	if(time == NULL || fixup_get_svalue(msg, (gparam_p)time, &time_s)!=0) {
		LM_ERR("Invalid time argument\n");
		return -1;
	}

	if ( str2int( &time_s, &useconds) != 0 ) {
		LM_ERR("time to sleep <%.*s> is not integer\n",
			time_s.len,time_s.s);
		return -1;
	}
	LM_DBG("sleep %d useconds\n", useconds);

	/* create the timer fd */
	if ( (fd=timerfd_create( CLOCK_REALTIME, 0))<0 ) {
		LM_ERR("failed to create new timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* set the time */
	its.it_value.tv_sec = (useconds / 1000000);
	its.it_value.tv_nsec = (useconds % 1000000) * 1000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timerfd_settime( fd, 0, &its, NULL)<0) {
		LM_ERR("failed to set timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return -1;
	}

	/* start the async wait */
	*resume_param = (void*)(unsigned long)
		(((unsigned long)-1) & (get_uticks()+useconds));
	*resume_f = resume_async_sleep;
	async_status = fd;

	return 1;
}
#endif


static int dbg_abort(struct sip_msg* msg, char* foo, char* bar)
{
	LM_CRIT("abort called\n");
	abort();
	return 0;
}

static int dbg_pkg_status(struct sip_msg* msg, char* foo, char* bar)
{
	pkg_status();
	return 1;
}

static int dbg_shm_status(struct sip_msg* msg, char* foo, char* bar)
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
			LM_ERR("could not hash the config file");
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

static int fixup_pv_set(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	if((*param == 0) || (param_no!=1 && param_no!=2))
	{
		LM_ERR( "NULL format\n");
		return E_UNSPEC;
	}

	s.s = (char*)(*param); s.len = strlen(s.s);
	if(pv_parse_format(&s, &model)<0)
	{
		LM_ERR( "wrong format[%s]\n",(char*)(*param));
		return E_UNSPEC;
	}

	*param = (void*)model;

	return 0;
}


static int pv_set_count(struct sip_msg* msg, char* pv_name, char* pv_result)
{
	pv_elem_t* pv_elem = (pv_elem_t*)pv_name;
	pv_elem_t* pv_res = (pv_elem_t*)pv_result;
	pv_value_t pv_val;

	if(pv_elem == NULL || pv_res == NULL)
	{
		LM_ERR("NULL parameter\n");
		return -1;
	}
	memset(&pv_val, 0, sizeof(pv_value_t));

	pv_elem->spec.pvp.pvi.type = PV_IDX_INT;
	pv_elem->spec.pvp.pvi.u.ival = 0;

	while(pv_val.flags != PV_VAL_NULL)
	{
		if(pv_get_spec_value(msg, &pv_elem->spec, &pv_val) < 0)
		{
			LM_ERR("PV get function failed\n");
			return -1;
		}
		pv_elem->spec.pvp.pvi.u.ival++;
	}

	pv_val.flags = PV_TYPE_INT;
	pv_val.ri = pv_elem->spec.pvp.pvi.u.ival-1;

	if (pv_set_value( msg, &pv_res->spec, 0, &pv_val) != 0)
	{
		LM_ERR("SET output value failed.\n");
		return -1;
	}

	LM_DBG("Set count = %d\n", pv_val.ri);
	return 1;
}

/* This function does selection based on the
 * fitness proportionate selection also known as roulette-wheel selection*/
static int pv_sel_weight(struct sip_msg* msg, char* pv_name,char* str2)
{
	int size;
	int *vals = NULL;
	int sum = 0;
	int rnd_val;
	int prev_val;
	pv_elem_t* pv_elem = (pv_elem_t*)pv_name;
	pv_value_t pv_val;
	int i;

	/* check the value type - it must be int */
	if(pv_elem == NULL)
	{
		LM_ERR("NULL parameter\n");
		return -1;
	}
	memset(&pv_val, 0, sizeof(pv_value_t));

	pv_elem->spec.pvp.pvi.type = PV_IDX_INT;
	pv_elem->spec.pvp.pvi.u.ival = 0;

	while(pv_val.flags != PV_VAL_NULL)
	{
		if(pv_get_spec_value(msg, &pv_elem->spec, &pv_val) < 0)
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

		pv_elem->spec.pvp.pvi.u.ival++;
	}
	size = pv_elem->spec.pvp.pvi.u.ival - 1;

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
		pv_elem->spec.pvp.pvi.u.ival = i;
		if(pv_get_spec_value(msg, &pv_elem->spec, &pv_val) < 0)
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

#define GET_INT(_msg, _p, _v) \
	do { \
		if (!(_p) || fixup_get_ivalue((_msg), ((gparam_p)(_p)), &(_v))< 0) { \
			LM_ERR("cannot retrieve int value\n"); \
			return -1; \
		} \
	} while (0)

static int ts_usec_delta(struct sip_msg *msg, char *_t1s,
		char *_t1u, char *_t2s, char *_t2u, char *_res)
{
	int t1s, t2s, t1u, t2u;
	pv_value_t res;

	GET_INT(msg, _t1s, t1s);
	GET_INT(msg, _t1u, t1u);
	GET_INT(msg, _t2s, t2s);
	GET_INT(msg, _t2u, t2u);

	res.ri = abs(1000000 * (t1s - t2s) + t1u - t2u);
	res.flags = PV_TYPE_INT;

	if (pv_set_value(msg, (pv_spec_p)_res, 0, &res)) {
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
int check_time_rec(struct sip_msg *msg, char *time_str)
{
	tmrec_p time_rec = 0;
	char *p, *s;
	str ret;
	ac_tm_t att;

	if (fixup_get_svalue(msg, (gparam_p)time_str, &ret) != 0) {
		LM_ERR("Get fixup value failed!\n");
		return E_CFG;
	}

	p = ret.s;

	LM_INFO("Parsing : %.*s\n", ret.len, ret.s);

	time_rec = tmrec_new(SHM_ALLOC);
	if (time_rec==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}

	/* empty definition? */
	if ( time_str==0 || *time_str==0 )
		return -1;

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
		return 1;

	memset( &att, 0, sizeof(att));

	/* set current time */
	if ( ac_tm_set_time( &att, time(0) ) )
		return -1;

	/* does the recv_time match the specified interval?  */
	if (check_tmrec( time_rec, &att, 0)!=0)
		return -1;

	return 1;

parse_error:
	LM_ERR("parse error in <%s> around position %i\n",
		time_str, (int)(long)(p-time_str));
error:
	if (time_rec)
		tmrec_free( time_rec );
	return -1;
}
