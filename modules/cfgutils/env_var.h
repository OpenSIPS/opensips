#ifndef _ENV_VAR_H_
#define _ENV_VAR_H_

#include "../../script_var.h"
#include "../../usr_avp.h"

typedef struct env_var {
	str name;
	str value;
	struct env_var *next;
} env_var_t, *env_var_p;

int pv_parse_env_name(pv_spec_p sp, str *in);
int pv_get_env(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
void destroy_env_list(void);

#endif
