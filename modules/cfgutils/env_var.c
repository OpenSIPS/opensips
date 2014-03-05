#include <stdlib.h>

#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "env_var.h"

static env_var_t *env_vars = 0;

int pv_parse_env_name(pv_spec_p sp, str *in)
{
	env_var_p it;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	for (it=env_vars; it; it=it->next) {
		if (in->len == it->name.len && !strncmp(it->name.s, in->s, in->len))
			goto end;
	}
	it = (env_var_p)pkg_malloc(sizeof(env_var_t));
	if (!it) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(it, 0, sizeof(env_var_t));

	it->name.s = (char*)pkg_malloc(in->len + 1);
	if (!it->name.s) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	memcpy(it->name.s, in->s, in->len);
	it->name.s[in->len] = 0;
	it->name.len = in->len;

	it->next = env_vars;
	env_vars = it->next;

end:
	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void*)it;
	return 0;
}


int pv_get_env(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	env_var_p env_v = NULL;
	char *env_val;
	int len;

	if (!res)
		return -1;

	if (!param || !param->pvn.u.dname)
		return pv_get_null(msg, param, res);

	env_v = (env_var_p)param->pvn.u.dname;

	env_val = getenv(env_v->name.s);
	if (!env_val) {
		LM_DBG("env variable <%s> could not be found\n", env_v->name.s);
		return pv_get_null(msg, param, res);
	}
	len = strlen(env_val);

	if (len > env_v->value.len) {
		env_v->value.s = (char*)pkg_realloc(env_v->value.s, len);
		if (!env_v->value.s) {
			LM_ERR("no more pkg mem\n");
			return pv_get_null(msg, param, res);
		}
	}

	memcpy(env_v->value.s, env_val, len);
	env_v->value.len = len;

	res->rs = env_v->value;
	res->flags = PV_VAL_STR;

	return 0;
}

void destroy_env_list(void)
{
	env_var_p env_it;

	while (env_vars) {
		env_it = env_vars;
		env_vars = env_vars->next;

		pkg_free(env_it->name.s);
		if (env_it->value.s)
			pkg_free(env_it->value.s);
		pkg_free(env_it);
	}
}
