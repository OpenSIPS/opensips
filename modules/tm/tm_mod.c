/*
 * $Id$
 *
 * TM module
 *
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../fifo_server.h"

#include "sip_msg.h"
#include "h_table.h"
#include "t_funcs.h"
#include "t_hooks.h"
#include "tm_load.h"
#include "ut.h"
#include "t_reply.h"
#include "uac.h"
#include "t_fwd.h"
#include "t_lookup.h"
#include "t_stats.h"



inline static int w_t_check(struct sip_msg* msg, char* str, char* str2);
inline static int w_t_reply(struct sip_msg* msg, char* str, char* str2);
inline static int w_t_reply_unsafe(struct sip_msg* msg, char* str, char* str2);
inline static int w_t_release(struct sip_msg* msg, char* str, char* str2);
inline static int fixup_t_send_reply(void** param, int param_no);
inline static int fixup_str2int( void** param, int param_no);
inline static int w_t_retransmit_reply(struct sip_msg* p_msg, char* foo, char* bar );
inline static int w_t_newtran(struct sip_msg* p_msg, char* foo, char* bar );
inline static int w_t_newdlg( struct sip_msg* p_msg, char* foo, char* bar );
inline static int w_t_relay( struct sip_msg  *p_msg , char *_foo, char *_bar);
inline static int w_t_relay_to( struct sip_msg  *p_msg , char *proxy, char *);
inline static int w_t_replicate( struct sip_msg  *p_msg , 
	char *proxy, /* struct proxy_l *proxy expected */
	char *_foo       /* nothing expected */ );
inline static int w_t_forward_nonack(struct sip_msg* msg, char* str, char* );
inline static int fixup_hostport2proxy(void** param, int param_no);
inline static int w_t_on_negative( struct sip_msg* msg, char *go_to, char *foo );


static int mod_init(void);

static int child_init(int rank);


#ifdef STATIC_TM
struct module_exports tm_exports = {
#else
struct module_exports exports= {
#endif
	"tm",
	/* -------- exported functions ----------- */
	(char*[]){			
				"t_newtran",
				"t_lookup_request",
				T_REPLY,
				T_REPLY_UNSAFE,
				"t_retransmit_reply",
				"t_release",
				T_RELAY_TO,
				"t_replicate",
				T_RELAY,
				T_FORWARD_NONACK,
				"t_on_negative",

				/* not applicable from script ... */

				"register_tmcb",
				T_UAC,
				"load_tm",
				"t_newdlg"
			},
	(cmd_function[]){
					w_t_newtran,
					w_t_check,
					w_t_reply,
					w_t_reply_unsafe,
					w_t_retransmit_reply,
					w_t_release,
					w_t_relay_to,
					w_t_replicate,
					w_t_relay,
					w_t_forward_nonack,
					w_t_on_negative,

					(cmd_function) register_tmcb,
					(cmd_function) t_uac,
					(cmd_function) load_tm,
					w_t_newdlg,
					},
	(int[]){
				0, /* t_newtran */
				0, /* t_lookup_request */
				2, /* t_reply */
				2, /* t_reply_unsafe */
				0, /* t_retransmit_reply */
				0, /* t_release */
				2, /* t_relay_to */
				2, /* t_replicate */
				0, /* t_relay */
				2, /* t_forward_nonack */
				1, /* t_on_negative */
				NO_SCRIPT /* register_tmcb */,
				NO_SCRIPT /* t_uac */,
				NO_SCRIPT /* load_tm */,
				0 /* t_newdlg */
			},
	(fixup_function[]){
				0,						/* t_newtran */
				0,						/* t_lookup_request */
				fixup_t_send_reply,		/* t_reply */
				fixup_t_send_reply,		/* t_reply_unsafe */
				0,						/* t_retransmit_reply */
				0,						/* t_release */
				fixup_hostport2proxy,	/* t_relay_to */
				fixup_hostport2proxy,	/* t_replicate */
				0,						/* t_relay */
				fixup_hostport2proxy,	/* t_forward_nonack */
				fixup_str2int,			/* t_on_negative */
				0,						/* register_tmcb */
				0,						/* t_uac */
				0,						/* load_tm */
				0						/* t_newdlg */
	
		},
	15,

	/* ------------ exported variables ---------- */
	(char *[]) { /* Module parameter names */
		"fr_timer",
		"fr_inv_timer",
		"wt_timer",
		"delete_timer",
		"retr_timer1p1",
		"retr_timer1p2",
		"retr_timer1p3",
		"retr_timer2",
		"noisy_ctimer",
		"uac_from"
	},
	(modparam_t[]) { /* variable types */
		INT_PARAM, /* fr_timer */
		INT_PARAM, /* fr_inv_timer */
		INT_PARAM, /* wt_timer */
		INT_PARAM, /* delete_timer */
		INT_PARAM,/* retr_timer1p1 */
		INT_PARAM, /* retr_timer1p2 */
		INT_PARAM, /* retr_timer1p3 */
		INT_PARAM, /* retr_timer2 */
		INT_PARAM, /* noisy_ctimer */
		STR_PARAM, /* uac_from */
	},
	(void *[]) { /* variable pointers */
		&(timer_id2timeout[FR_TIMER_LIST]),
		&(timer_id2timeout[FR_INV_TIMER_LIST]),
		&(timer_id2timeout[WT_TIMER_LIST]),
		&(timer_id2timeout[DELETE_LIST]),
		&(timer_id2timeout[RT_T1_TO_1]),
		&(timer_id2timeout[RT_T1_TO_2]),
		&(timer_id2timeout[RT_T1_TO_3]),
		&(timer_id2timeout[RT_T2]),
		&noisy_ctimer,
		&uac_from
	},
	11,      /* Number of module paramers */

	mod_init, /* module initialization function */
	(response_function) t_on_reply,
	(destroy_function) tm_shutdown,
	0, /* w_onbreak, */
	child_init /* per-child init function */
};

inline static int fixup_str2int( void** param, int param_no)
{
	unsigned int go_to;
	int err;

	if (param_no==1) {
		go_to=str2s(*param, strlen(*param), &err );
		if (err==0) {
			free(*param);
			*param=(void *)go_to;
			return 0;
		} else {
			LOG(L_ERR, "ERROR: fixup_str2int: bad number <%s>\n",
				(char *)(*param));
			return E_CFG;
		}
	}
	return 0;
}

static int w_t_unref( struct sip_msg *foo, void *bar)
{
	return t_unref(foo);
}

static int script_init( struct sip_msg *foo, void *bar)
{   
	/* we primarily reset all private memory here to make sure
	   private values left over from previous message will
	   not be used again
    */

	/* make sure the new message will not inherit previous
	   message's t_on_negative value
	*/
	t_on_negative( 0 );

	return 1;
}

static int mod_init(void)
{

	DBG( "TM - initializing...\n");
	/* checking if we have sufficient bitmap capacity for given
	   maximum number of  branches */
	if (1<<(MAX_BRANCHES+1)>UINT_MAX) {
		LOG(L_CRIT, "Too many max UACs for UAC branch_bm_t bitmap: %d\n",
			MAX_BRANCHES );
		return -1;
	}
	if (register_fifo_cmd(fifo_uac, "t_uac", 0)<0) {
		LOG(L_CRIT, "cannot register fifo uac\n");
		return -1;
	}
	
	if (init_stats()<0) {
		LOG(L_CRIT, "ERROR: mod_init: failed to init stats\n");
		return -1;
	}

	if (tm_startup()==-1) return -1;
	uac_init();
	register_tmcb( TMCB_ON_NEGATIVE, on_negative_reply, 0 /* empty param */);
    /* register the timer function */
    register_timer( timer_routine , hash_table , 1 );
    /* register post-script clean-up function */
    register_script_cb( w_t_unref, POST_SCRIPT_CB, 0 /* empty param */ );
    register_script_cb( script_init, PRE_SCRIPT_CB , 0 /* empty param */ );
	return 0;
}

static int child_init(int rank) {
	uac_child_init(rank);
	return 1;
}


/* (char *hostname, char *port_nr) ==> (struct proxy_l *, -)  */

inline static int fixup_hostport2proxy(void** param, int param_no)
{
	unsigned int port;
	char *host;
	int err;
	struct proxy_l *proxy;
	
	DBG("TM module: fixup_t_forward(%s, %d)\n", (char*)*param, param_no);
	if (param_no==1){
		DBG("TM module: fixup_t_forward: param 1.. do nothing, wait for #2\n");
		return 0;
	} else if (param_no==2) {

		host=(char *) (*(param-1)); 
		port=str2s(*param, strlen(*param), &err);
		if (err!=0) {
			LOG(L_ERR, "TM module:fixup_t_forward: bad port number <%s>\n",
				(char*)(*param));
			 return E_UNSPEC;
		}
		proxy=mk_proxy(host, port);
		if (proxy==0) {
			LOG(L_ERR, "ERROR: fixup_t_forwardv6: bad host name in URI <%s>\n",
				host );
			return E_BAD_ADDRESS;
		}
		/* success -- fix the first parameter to proxy now ! */
		free( *(param-1));
		*(param-1)=proxy;
		return 0;
	} else {
		LOG(L_ERR, "ERROR: fixup_t_forwardv6 called with parameter #<>{1,2}\n");
		return E_BUG;
	}
}


/* (char *code, char *reason_phrase)==>(int code, r_p as is) */
inline static int fixup_t_send_reply(void** param, int param_no)
{
	unsigned int code;
	int err;

	if (param_no==1){
		code=str2s(*param, strlen(*param), &err);
		if (err==0){
			free(*param);
			*param=(void*)code;
			return 0;
		}else{
			LOG(L_ERR, "TM module:fixup_t_send_reply: bad  number <%s>\n",
					(char*)(*param));
			return E_UNSPEC;
		}
	}
	/* second param => no conversion*/
	return 0;
}




inline static int w_t_check(struct sip_msg* msg, char* str, char* str2)
{
	return t_check( msg , 0  ) ? 1 : -1;
}



inline static int w_t_forward_nonack(struct sip_msg* msg, char* proxy, char* _foo)
{
	struct cell *t;
	if (t_check( msg , 0 )==-1) return -1;
	t=get_t();
	if ( t && t!=T_UNDEFINED ) {
		if (msg->REQ_METHOD==METHOD_ACK) {
			LOG(L_WARN,"WARNING: you don't really want to fwd hbh ACK\n");
			return -1;
		}
		return t_forward_nonack(t, msg, ( struct proxy_l *) proxy );
	} else {
		DBG("DEBUG: t_forward_nonack: no transaction found\n");
		return -1;
	}
}



inline static int w_t_reply(struct sip_msg* msg, char* str, char* str2)
{
	struct cell *t;

	if (msg->REQ_METHOD==METHOD_ACK) {
		LOG(L_WARN, "WARNING: t_reply: ACKs are not replied\n");
		return -1;
	}
	if (t_check( msg , 0 )==-1) return -1;
	t=get_t();
	if (!t) {
		LOG(L_ERR, "ERROR: t_reply: cannot send a t_reply to a message "
			"for which no T-state has been established\n");
		return -1;
	}
	return t_reply( t, msg, (unsigned int) str, str2);
}


inline static int w_t_reply_unsafe(struct sip_msg* msg, char* str, char* str2)
{
	struct cell *t;

	if (msg->REQ_METHOD==METHOD_ACK) {
		LOG(L_WARN, "WARNING: t_reply: ACKs are not replied\n");
		return -1;
	}
	if (t_check( msg , 0 )==-1) return -1;
	t=get_t();
	if (!t) {
		LOG(L_ERR, "ERROR: t_reply: cannot send a t_reply to a message "
			"for which no T-state has been established\n");
		return -1;
	}
	return t_reply_unsafe(t, msg, (unsigned int) str, str2);
}


inline static int w_t_release(struct sip_msg* msg, char* str, char* str2)
{
	struct cell *t;
	if (t_check( msg  , 0  )==-1) return -1;
	t=get_t();
	if ( t && t!=T_UNDEFINED ) 
		return t_release_transaction( t );
	return 1;
}




inline static int w_t_retransmit_reply( struct sip_msg* p_msg, char* foo, char* bar)
{
	struct cell *t;


	if (t_check( p_msg  , 0 )==-1) 
		return 1;
	t=get_t();
	if (t) {
		if (p_msg->REQ_METHOD==METHOD_ACK) {
			LOG(L_WARN, "WARNING: : ACKs ansmit_replies not replied\n");
			return -1;
		}
		return t_retransmit_reply( t );
	} else 
		return -1;
	return 1;
}





inline static int w_t_newdlg( struct sip_msg* p_msg, char* foo, char* bar ) 
{
	return t_newdlg( p_msg );
}

inline static int w_t_newtran( struct sip_msg* p_msg, char* foo, char* bar ) 
{
	/* t_newtran returns 0 on error (negative value means
	   'transaction exists'
	*/
	return t_newtran( p_msg );
}


inline static int w_t_on_negative( struct sip_msg* msg, char *go_to, char *foo )
{
	return t_on_negative( (unsigned int ) go_to );
}

inline static int w_t_relay_to( struct sip_msg  *p_msg , 
	char *proxy, /* struct proxy_l *proxy expected */
	char *_foo       /* nothing expected */ )
{
	return t_relay_to( p_msg, ( struct proxy_l *) proxy,
	0 /* no replication */ );
}

inline static int w_t_replicate( struct sip_msg  *p_msg , 
	char *proxy, /* struct proxy_l *proxy expected */
	char *_foo       /* nothing expected */ )
{
	return t_replicate(p_msg, ( struct proxy_l *) proxy );
}

inline static int w_t_relay( struct sip_msg  *p_msg , 
						char *_foo, char *_bar)
{
	return t_relay_to( p_msg, 
		(struct proxy_l *) 0 /* no proxy */,
		0 /* no replication */ );
}


