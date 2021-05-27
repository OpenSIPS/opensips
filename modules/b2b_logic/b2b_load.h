#ifndef B2BUA_LOGIC_LOAD_
#define B2BUA_LOGIC_LOAD_

#include "../../sr_module.h"
#include "../b2b_entities/b2b_common.h"
#include "../b2b_entities/b2be_load.h"

#define B2B_BYE_CB        (1<<0)
#define B2B_REJECT_CB     (1<<1)
#define B2B_DESTROY_CB    (1<<2)
#define B2B_RE_INVITE_CB  (1<<3)
#define B2B_CONFIRMED_CB  (1<<4)

#define B2B_ERROR_CB_RET          -1
#define B2B_DROP_MSG_CB_RET        0
#define B2B_SEND_MSG_CB_RET        1
#define B2B_FOLLOW_SCENARIO_CB_RET 2

typedef struct b2bl_dlg_stat
{
	str key;
	int start_time;
	int setup_time;
	int call_time;
}b2bl_dlg_stat_t;

typedef struct b2bl_cb_params
{
	void *param;            /* parameter passed at callback registration */
	b2bl_dlg_stat_t *stat;  /* b2bl_dlg statistics */
	struct sip_msg* msg;    /* the message being processed */
	unsigned int entity;    /* the entity for which the callback is invoked */
} b2bl_cb_params_t;

typedef int (*b2bl_cback_f)(b2bl_cb_params_t *params, unsigned int b2b_event);
/*
 * event    - B2B_BYE_CB,       bye received from an entity
 *            B2B_REJECT_CB,    negative reply for invite when bridging
 *            B2B_DESTROY_CB,   destroy the tuple
 *            B2B_RE_INVITE_CB, re-invite received from an entity
 * Return:
 *     B2B_ERROR_CB_RET           - error
 *     B2B_DROP_MSG_CB_RET        - drop the request
 *     B2B_SEND_MSG_CB_RET        - send the request on the other side
 *     B2B_FOLLOW_SCENARIO_CB_RET - do what the scenario tells,
 *               if no rule defined send the request on the other side
 **/


typedef struct b2bl_init_params {
	enum b2b_entity_type e1_type;
	enum b2b_entity_type e2_type;
	str e1_to;
	str e2_to;
	str e1_from_dname;
	str e2_from_dname;
} b2bl_init_params_t;


typedef str* (*b2bl_init_f)(struct sip_msg* msg, str *scenario_name,
	b2bl_init_params_t *scenario_params, b2bl_cback_f, void* param,
	unsigned int cb_mask, str* custom_hdrs);


typedef int (*b2bl_bridge_f)(str* key, str* new_uri, str *new_proxy,
	str* new_from_dname,int entity_type);
/* key - the string returned by b2bl_init_f
 * entity_type - 0, the server entity
 *               1, the client entity
 */

int b2bl_terminate_call(str* key);
typedef int (*b2bl_terminate_call_t)(str* key);

int b2bl_bridge(str* key,str* new_uri, str *new_proxy, str* new_from_dname,
	int entity_no);
int b2bl_set_state(str* key, int state);

int b2bl_bridge_2calls(str* key1, str* key2);
typedef int (*b2bl_bridge_2calls_t)(str* key1, str* key2);

int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no, str *adv_ct);
int b2bl_get_tuple_key(str *key, unsigned int *hash_index,
		unsigned int *local_index);
typedef int (*b2bl_bridge_msg_t)(struct sip_msg* msg, str* key, int entity_no);

int b2bl_get_stats(str* key, b2bl_dlg_stat_t* stat);
typedef int (*b2bl_get_stats_f)(str* key, b2bl_dlg_stat_t* stat);

int b2bl_register_cb(str* key, b2bl_cback_f, void* param, unsigned int cb_mask);
typedef int (*b2bl_register_cb_f)(str* key, b2bl_cback_f, void* param, unsigned int cb_mask);

typedef struct b2b_tracer* (*b2bl_set_tracer_f)(void);
typedef int (*b2bl_register_set_tracer_cb_f)(b2bl_set_tracer_f cb, unsigned int msg_flag_filter);

int b2bl_restore_upper_info(str* b2bl_key, b2bl_cback_f, void* param, unsigned int cb_mask);
typedef int (*b2bl_restore_upper_info_f)(str* b2bl_key, b2bl_cback_f, void* param, unsigned int cb_mask);

typedef struct b2bl_api
{
	b2bl_init_f init;
	b2bl_bridge_f bridge;
	b2bl_bridge_2calls_t bridge_2calls;
	b2bl_terminate_call_t terminate_call;
	b2bl_bridge_msg_t bridge_msg;
	b2bl_get_stats_f get_stats;
	b2bl_register_cb_f register_cb;
	b2bl_register_set_tracer_cb_f register_set_tracer_cb;
	b2bl_restore_upper_info_f restore_upper_info;
}b2bl_api_t;

str* internal_init_scenario(struct sip_msg* msg, str *scen_name,
	b2bl_init_params_t *scen_params, b2bl_cback_f cbf, void* param,
	unsigned int cb_mask, str* custom_hdrs);

typedef int(*load_b2bl_f)( b2bl_api_t *api );
int b2b_logic_bind(b2bl_api_t* api);

static inline int load_b2b_logic_api( b2bl_api_t *api)
{
	load_b2bl_f load_b2b;

	/* import the b2b logic auto-loading function */
	if ( !(load_b2b=(load_b2bl_f)find_export("b2b_logic_bind", 0))) {
		return -1;
	}
	/* let the auto-loading function load all B2B stuff */
	if (load_b2b( api )==-1)
		return -1;

	return 0;
}


#endif

