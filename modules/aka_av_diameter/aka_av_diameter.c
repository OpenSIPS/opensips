/*
 * AKA Authentication - Diameter support
 *
 * Copyright (C) 2024 Razvan Crainea
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../sr_module.h"
#include "../../pt.h"
#include "../../error.h"
#include "../../config.h"
#include "../../mod_fix.h"
#include "../../map.h"
#include "../../lib/cond.h"
#include "../../str_list.h"
#include "../../parser/digest/digest_parser.h"

#include "../auth_aka/aka_av_mgm.h"
#include "diameter_mar.h"

#include "../aaa_diameter/diameter_api.h"

static diameter_api dm_api;
static aka_av_api aka_api;
static diameter_conn *dm_conn;
static str dm_aaa_url = {NULL, 0};
static str aka_av_dm_realm = {"diameter.test", 0};

static int aka_av_diameter_fetch(str *realm, str *impu, str *impi,
		str *resync, int algmask, int no, int async);

static int mod_init(void);         /* Module initialization function */
static void mod_destroy(void);      /* Module destroy function */

/*
 * Module parameter variables
 */

/*
 * Exported functions
 */

int load_aka_av_event(struct aka_av_binds *binds)
{
	binds->fetch = aka_av_diameter_fetch;
	return 0;
};

static const cmd_export_t cmds[] = {
	{AKA_AV_MGM_PREFIX"diameter", (cmd_function)load_aka_av_event, {
		{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "auth_aka", DEP_ABORT },
		{ MOD_TYPE_AAA, "aaa_diameter", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};


/*
 * Exported parameters
 */
static const param_export_t params[] = {
	{ "aaa_url", STR_PARAM, &dm_aaa_url.s },
	{ "realm", STR_PARAM,   &aka_av_dm_realm.s },
	{0, 0, 0}
};

/*
 * Module interface
 */
struct module_exports exports = {
	"aka_av_diameter",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	0,          /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* child initialization function */
	0           /* reload confirm function */
};


/*
 * Module initialization function
 */
static int mod_init(void)
{
	LM_INFO("initializing...\n");

	/* handling the event */
	if (!dm_aaa_url.s) {
		LM_ERR("Diameter URL not provided!\n");
		return -1;
	}

	dm_aaa_url.len = strlen(dm_aaa_url.s);
	aka_av_dm_realm.len = strlen(aka_av_dm_realm.s);

	if (diameter_bind_api(&dm_api) < 0)
		return -1;

	dm_conn = dm_api.init(&dm_aaa_url);
	if (!dm_conn) {
		LM_ERR("Diameter protocol initialization failure\n");
		return -1;
	}
	if (!dm_api.find_cmd(dm_conn, AKA_AV_DM_MAR_CODE)) {
		LM_ERR("could not find Multimedia-Auth-Request command!\n");
		return -1;
	}

	if (aka_av_bind_api(&aka_api) < 0) {
		LM_ERR("could not bind AKA AV API\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void)
{
}

static inline char *aka_av_diameter_get_session(void)
{
	int l;
	char *sess, *p, *t;
	static int seq = 0;

	if (seq == 0)
		seq = rand();
	else
		seq++;

	sess = pkg_malloc(aka_av_dm_realm.len + 3 * INT2STR_MAX_LEN + 5 /* separators */ +
			1 /* iteration id */ + 1 /* '\0' */);
	if (!sess) {
		LM_ERR("oom for session\n");
		return NULL;
	}
	p = sess;
	memcpy(p, aka_av_dm_realm.s, aka_av_dm_realm.len);
	p += aka_av_dm_realm.len;
	*p++ = ';';
	t = int2str(time(NULL), &l);
	memcpy(p, t, l);
	p += l;
	*p++ = ';';
	t = int2str(process_no, &l);
	memcpy(p, t, l);
	p += l;
	*p++ = ';';
	t = int2str(seq, &l);
	memcpy(p, t, l);
	p += l;
	*p++ = ';';
	*p++ = '0'; /* XXX: start from 0 up to 'Z' */
	*p++ = '\0';
	return sess;
}

static inline void aka_av_diameter_update_session(cJSON *sess, alg_t alg)
{
	/* hack to make the Session id unique */
	int len = strlen(sess->valuestring);
	sess->valuestring[len - 1] = '0' + alg;
}

#define cJSON_SWITCH(_el, _str, _type, _block) \
	do { \
		if (strcmp(_el->string, _str) == 0) { \
			if (_el->type != _type) { \
				LM_ERR("invalid type %d (expected %d) for %s\n", \
						_el->type, _type, _str); \
				goto end; \
			} \
			LM_DBG("found %s JSON node\n", _str); \
			_block; \
		} \
	} while (0)

struct aka_av_dm {
	int index;
	alg_t alg;
	str authenticate;
	str authorize;
	str confidentiality;
	str integrity;
};

static int aka_av_diameter_sort(const void *d1, const void *d2)
{
	const struct aka_av_dm *av1 = d1;
	const struct aka_av_dm *av2 = d2;

	if (av1->index == av2->index)
		return 0;
	return av2->index - av1->index; /* reverse order to push them accordingly */
}

static alg_t aka_av_parse_scheme(char *algorithm)
{
	str algs;
	algs.s = algorithm;
	algs.len = strlen(algorithm);
	if (algs.len > 7 && memcmp(algs.s, "Digest-", 7) == 0) {
		algs.s += 7;
		algs.len -= 7;
	}
	return parse_digest_algorithm(&algs);
}


static int aka_av_diameter_handle_reply(cJSON *rpl, str *impu, str *impi)
{
	cJSON *it, *el, *it2;
	struct aka_av_dm *arr = NULL;
	int ret = -1;
	int nr = 0, nr2 = 0;
	str pub_id, priv_id;

	/* we've got the response in rpl - start parsing it */
	if (!rpl) {
		LM_ERR("bad diameter reply\n");
		goto end;
	}
	if (rpl->type != cJSON_Array) {
		LM_ERR("bad json type %d\n", rpl->type);
		goto end;
	}
	pub_id.s = priv_id.s = NULL;

	/* first, search for the number of AVs and identities */
	for (it = rpl->child; it; it = it->next) {
		if (it->type != cJSON_Object) {
			LM_ERR("bad json type %d in array\n", it->type);
			continue;
		}
		el = it->child;
		cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEMS, cJSON_Number,
			nr = el->valueint;
		);
		cJSON_SWITCH(el, AKA_AV_DM_PUBLIC_ID, cJSON_String,
			pub_id.s = el->valuestring;
			pub_id.len = strlen(el->valuestring);
		);
		cJSON_SWITCH(el, AKA_AV_DM_USER_NAME, cJSON_String,
			priv_id.s = el->valuestring;
			priv_id.len = strlen(el->valuestring);
		);
		cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM, cJSON_Array,
			if (cJSON_GetArraySize(el) != 0)
				nr2++;
		);
	}
	/* TODO: should we check if these match with the request? */
	if (pub_id.s == NULL) {
		LM_ERR(AKA_AV_DM_PUBLIC_ID "not present in response\n");
		goto end;
	}
	if (priv_id.s == NULL) {
		LM_ERR(AKA_AV_DM_USER_NAME "not present in response\n");
		goto end;
	}
	if (nr == 0 || nr2 == 0) {
		LM_DBG("no AVs present in reply\n");
		goto end;
	}
	if (nr != nr2) {
		LM_WARN("invalid response says contains %d AV, but has %d\n", nr, nr2);
		nr = nr2; /* we store all that we have */
	}
	arr = pkg_malloc(nr * sizeof *arr);
	if (!arr) {
		LM_ERR("oom for tmp array\n");
		goto end;
	}
	memset(arr, 0, nr * sizeof *arr);
	ret = 0;
	for (it = rpl->child; it; it = it->next) {
		if (strcmp(it->child->string, AKA_AV_DM_AUTH_ITEM) != 0)
			continue;
		arr[ret].index = -1;
		el = cJSON_GetObjectItem(it, AKA_AV_DM_AUTH_ITEM);
		if (!el) {
			LM_ERR("invalid data item in JSON\n");
			continue;
		}
		for (it2 = el->child; it2; it2 = it2->next) {
			el = it2->child;
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM_NO, cJSON_Number,
					arr[ret].index = el->valueint;
					);
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_SCHEME, cJSON_String,
					arr[ret].alg = aka_av_parse_scheme(el->valuestring);
					if (arr[ret].alg == ALG_OTHER) {
						LM_ERR("bad item scheme %s for item %d/%d\n", el->valuestring,
								arr[ret].index, ret);
						arr[ret].alg = ALG_UNSPEC;
						break;
					}
					);
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM_AUTHENTICATE, cJSON_String,
					arr[ret].authenticate.s = el->valuestring;
					arr[ret].authenticate.len = strlen(el->valuestring);
					);
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM_AUTHORIZE, cJSON_String,
					arr[ret].authorize.s = el->valuestring;
					arr[ret].authorize.len = strlen(el->valuestring);
					);
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM_CK, cJSON_String,
					arr[ret].confidentiality.s = el->valuestring;
					arr[ret].confidentiality.len = strlen(el->valuestring);
					);
			cJSON_SWITCH(el, AKA_AV_DM_AUTH_ITEM_IK, cJSON_String,
					arr[ret].integrity.s = el->valuestring;
					arr[ret].integrity.len = strlen(el->valuestring);
					);
		}
		if (arr[ret].index == -1) {
			LM_ERR("no item number for entry %d\n", ret);
			continue;
		}
		if (arr[ret].alg == ALG_UNSPEC) {
			LM_ERR("no item scheme for item %d/%d\n", arr[ret].index, ret);
			continue;
		}
		if (!arr[ret].authenticate.s) {
			LM_ERR("no item authenticate for item %d/%d\n", arr[ret].index, ret);
			continue;
		}
		if (!arr[ret].authorize.s) {
			LM_ERR("no item authorize for item %d/%d\n", arr[ret].index, ret);
			continue;
		}
		if (!arr[ret].confidentiality.s) {
			LM_ERR("no item confidentiality for item %d/%d\n", arr[ret].index, ret);
			continue;
		}
		if (!arr[ret].integrity.s) {
			LM_ERR("no item itegrity for item %d/%d\n", arr[ret].index, ret);
			continue;
		}
		ret++;
	}
	nr = ret;
	qsort(arr, ret, sizeof *arr, aka_av_diameter_sort);
	while (nr-- > 0) {
		if (aka_api.add(&pub_id, &priv_id, ALG2ALGFLG(arr[nr].alg),
				&arr[nr].authenticate, &arr[nr].authorize,
				&arr[nr].confidentiality, &arr[nr].integrity) < 0) {
			ret--;
		}
	}

	LM_DBG("found %d AVs in reply\n", ret);
end:
	if (arr)
		pkg_free(arr);
	return ret;
}

#define cJSON_ADD_OBJ(_a, _n, _b) \
	do { \
		cJSON *_t, *_o; \
		_o = cJSON_CreateObject(); \
		if (_o == NULL) { \
			LM_ERR("oom for object\n"); \
			goto end; \
		} \
		_t = (_b); \
		if (_t == NULL) { \
			cJSON_Delete(_o); \
			LM_ERR("oom for "#_b"\n"); \
			goto end; \
		} \
		cJSON_AddItemToObject(_o, _n, _t); \
		cJSON_AddItemToArray(_a, _o); \
	} while (0);

static int aka_av_diameter_print_alg(cJSON *alg_arr, alg_t alg)
{
	const str *algs = print_digest_algorithm(alg);
	char *p;
	int ret;

	if (!algs)
		return -1;
	/* append Digest at the end */
	p = pkg_malloc(algs->len + 7 /* 'Digest-' */ + 1 /* '\0' */);
	if (!p) {
		LM_ERR("oom for Digest algorithm\n");
		return -1;
	}
	memcpy(p, "Digest-", 7);
	memcpy(p + 7, algs->s, algs->len);
	p[algs->len + 7] = '\0';
	cJSON_DeleteItemFromArray(alg_arr, 0); /* remove whatever was there */
	cJSON_ADD_OBJ(alg_arr, AKA_AV_DM_AUTH_SCHEME, cJSON_CreateString(p));
	ret = 0;
end:
	pkg_free(p);
	
	return ret;
}


struct aka_av_param {
	str impu;
	str impi;
	int count;
	char _buf[0];
};

static struct aka_av_param *aka_av_param_new(str *impu, str *impi, int count)
{
	struct aka_av_param *param = shm_malloc(sizeof(*param) + impu->len + impi->len);
	if (!param) {
		LM_ERR("oom for impi/impu\n");
		return NULL;
	}
	param->impu.s = param->_buf;
	memcpy(param->impu.s, impu->s, impu->len);
	param->impu.len = impu->len;
	param->impi.s = param->impu.s + impu->len;
	memcpy(param->impi.s, impi->s, impi->len);
	param->impi.len = impi->len;
	param->count = count;
	return param;
}

static void aka_av_param_free(struct aka_av_param *param)
{
	shm_free(param);
}


static int aka_av_dm_reply(diameter_conn *conn, diameter_reply *reply, void *param)
{
	int ret;
	struct aka_av_param *p = (struct aka_av_param *)param;
	if (dm_api.get_reply_status(reply)) {
		ret = aka_av_diameter_handle_reply(dm_api.get_reply(reply), &p->impu, &p->impi);
		if (ret != p->count)
			ret = 0;
		aka_api.fail(&p->impu, &p->impi, p->count - ret);
	} else {
		aka_api.fail(&p->impu, &p->impi, p->count); /* mark all as failed */
	}
	dm_api.free_reply(reply);
	return -1;
}

static int aka_av_diameter_fetch(str *realm, str *impu, str *impi,
		str *resync, int algmask, int count, int async)
{
	diameter_reply reply;
	cJSON *req = NULL, *tmp = NULL, *alg_arr, *sess_obj;
	int ret = -2;
	char *sess = NULL;
	alg_t alg;
	struct aka_av_param *param = NULL;

	sess = aka_av_diameter_get_session();
	if (!sess)
		goto end;

	/* create a session */
	req = cJSON_CreateArray();
	if (!req) {
		LM_ERR("oom for array\n");
		goto end;
	}

	cJSON_ADD_OBJ(req, AKA_AV_DM_SESSION, cJSON_CreateString(sess));
	sess_obj = cJSON_GetArrayItem(req, 0)->child; /* the session is the first */
	cJSON_ADD_OBJ(req, AKA_AV_DM_ORIGIN_HOST, cJSON_CreateString(aka_av_dm_realm.s));
	cJSON_ADD_OBJ(req, AKA_AV_DM_ORIGIN_REALM, cJSON_CreateStr(realm->s, realm->len));
	cJSON_ADD_OBJ(req, AKA_AV_DM_DST_REALM, cJSON_CreateStr(realm->s, realm->len));

	tmp = cJSON_CreateArray();
	if (!tmp) {
		LM_ERR("oom for vendor id\n");
		goto end;
	}
	cJSON_ADD_OBJ(tmp, AKA_AV_DM_VENDOR_ID_S, cJSON_CreateNumber(AKA_AV_DM_VENDOR_ID));
	cJSON_ADD_OBJ(tmp, AKA_AV_DM_AUTH_APP_ID, cJSON_CreateNumber(AKA_AV_DM_APP_ID));
	cJSON_ADD_OBJ(req, AKA_AV_DM_VENDOR_APP_ID, tmp);
	tmp = NULL;
	cJSON_ADD_OBJ(req, AKA_AV_DM_AUTH_SESS, cJSON_CreateNumber(1)); /* NO_STATE_MAINTAINED */
	cJSON_ADD_OBJ(req, AKA_AV_DM_USER_NAME, cJSON_CreateStr(impi->s, impi->len));
	cJSON_ADD_OBJ(req, AKA_AV_DM_PUBLIC_ID, cJSON_CreateStr(impu->s, impu->len));
	cJSON_ADD_OBJ(req, AKA_AV_DM_SERVER_NAME, cJSON_CreateStr(realm->s, realm->len)); /* TODO */
	cJSON_ADD_OBJ(req, AKA_AV_DM_AUTH_ITEMS, cJSON_CreateNumber(count));
	tmp = cJSON_CreateArray();
	if (!tmp) {
		LM_ERR("oom for auth data id\n");
		goto end;
	}
	cJSON_ADD_OBJ(req, AKA_AV_DM_AUTH_ITEM, tmp);
	/* we need to store the Scheme separately because it changes between
	 * different requests */
	alg_arr = tmp;
	tmp = NULL;

	if (resync)
		cJSON_ADD_OBJ(req, AKA_AV_DM_AUTH_ITEM_AUTHORIZE, cJSON_CreateStr(resync->s, resync->len));

	ret = -1;
	/* we send a diameter request for each algorithm used */
	for (alg = ALG_MD5; alg < ALG_OTHER; alg++) {
		if ((algmask & ALG2ALGFLG(alg)) == 0)
			continue;
		if (aka_av_diameter_print_alg(alg_arr, alg) < 0)
			continue;
		aka_av_diameter_update_session(sess_obj, alg);
		if (!async) {
			if (dm_api.send_request(dm_conn, AKA_AV_DM_APP_ID,
					AKA_AV_DM_MAR_CODE, req, &reply) < 0) {
				LM_ERR("could not send diameter request\n");
				goto end;
			}
			if (!dm_api.get_reply_status(&reply)) {
				dm_api.free_reply(&reply);
				continue;
			}
			if (aka_av_diameter_handle_reply(dm_api.get_reply(&reply), impu, impi) < 0) {
				LM_ERR("could not parse json reply\n");
				dm_api.free_reply(&reply);
				continue;
			}
			dm_api.free_reply(&reply);
		} else {
			param = aka_av_param_new(impu, impi, count);
			if (!param)
				goto end;
			if (dm_api.send_request_async(dm_conn, AKA_AV_DM_APP_ID,
					AKA_AV_DM_MAR_CODE, req, aka_av_dm_reply, param) < 0) {
				LM_ERR("could not send diameter request\n");
				aka_av_param_free(param);
				goto end;
			}
		}
	}

	ret = 0;
end:
	if (sess)
		pkg_free(sess);
	if (req)
		cJSON_Delete(req);
	if (tmp)
		cJSON_Delete(tmp);
	return ret;
}
#undef cJSON_CREATE_OBJ
