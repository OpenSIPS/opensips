
#ifndef B2BUA_LOGIC_LOAD_
#define B2BUA_LOGIC_LOAD_

#include "../../sr_module.h"
#include "../b2b_entities/dlg.h"

#define B2B_BYE_E1     (1<<0)
#define B2B_BYE_E2     (1<<1)
#define B2B_REJECT_E1  (1<<2)
#define B2B_REJECT_E2  (1<<3)
#define B2B_DESTROY    (1<<4)

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
} b2bl_cb_params_t;

typedef int (*b2bl_cback_f)(b2bl_cb_params_t *params, unsigned int b2b_event);
/*
 * event    - B2B_BYE_E1,  bye from entity 1
 *            B2B_BYE_E2,  bye from entity 2
 *            B2B_REJECT,  negative reply for Invite when bridging
 *            B2B_DESTROY, destroy the tuple
 * Return: -1 - error
 *           0 - drop the BYE
 *           1 - send the BYE on the other side 
 *           2 - do what the scenario tells, if no rule defined send the BYE on the other side
 **/


typedef str* (*b2bl_init_f)(struct sip_msg* msg, str* name, str* args[5],
		b2bl_cback_f, void* param);

typedef int (*b2bl_bridge_f)(str* key, str* new_uri, str* new_from_dname,int entity_type);
/* key - the string returned by b2bl_init_f 
 * entity_type - 0, the server entity
 *               1, the client entity
 */
typedef int (*b2bl_set_state_f)(str* key, int state);

typedef str* (*b2bl_bridge_extern_f)(str* scenario_name, str* args[5],
		b2bl_cback_f cbf, void* cb_param);

int b2bl_terminate_call(str* key);
typedef int (*b2bl_terminate_call_t)(str* key);

int b2bl_bridge(str* key,str* new_uri,str* new_from_dname,int entity_no);
int b2bl_set_state(str* key, int state);

int b2bl_bridge_2calls(str* key1, str* key2);
typedef int (*b2bl_bridge_2calls_t)(str* key1, str* key2);

int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no);
typedef int (*b2bl_bridge_msg_t)(struct sip_msg* msg, str* key, int entity_no);

typedef struct b2bl_api
{
	b2bl_init_f init;
	b2bl_bridge_f bridge;
	b2bl_bridge_extern_f bridge_extern;
	b2bl_bridge_2calls_t bridge_2calls;
	b2bl_terminate_call_t terminate_call;
	b2bl_set_state_f set_state;
	b2bl_bridge_msg_t bridge_msg;
}b2bl_api_t;

str* internal_init_scenario(struct sip_msg* msg, str* name, str* args[5],
		b2bl_cback_f, void* param);

typedef int(*load_b2bl_f)( b2bl_api_t *api );
int b2b_logic_bind(b2bl_api_t* api);

str* b2bl_bridge_extern(str* scenario_name, str* args[5], b2bl_cback_f cbf, void* cb_param);

static inline int load_b2b_logic_api( b2bl_api_t *api)
{
	load_b2bl_f load_b2b;

	/* import the b2b logic auto-loading function */
	if ( !(load_b2b=(load_b2bl_f)find_export("b2b_logic_bind", 1, 0))) {
		LM_ERR("failed to import b2b_logic_bind\n");
		return -1;
	}
	/* let the auto-loading function load all B2B stuff */
	if (load_b2b( api )==-1)
		return -1;

	return 0;
}


#endif

