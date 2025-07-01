/**
 * Copyright (C) 2021 OpenSIPS Solutions
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
 */

#include <freeDiameter/extension.h>

#include "../../ut.h"
#include "../../lib/list.h"
#include "../../lib/csv.h"
#include "../../lib/hash.h"

#include "aaa_impl.h"
#include "peer.h"
#include "app_opensips/avps.h"

struct local_rules_definition {
	char *avp_name;
	enum rule_position position;
	int min;
	int max;
};

struct _dm_dict dm_dict;

/* Workaround until we find a way of looking up a single enum val in fD */
static gen_hash_t *osips_enumvals;

/* helps locate a SIP worker awaiting a Diameter reply when receiving
 * that async Diameter reply on some freeDiameter peer thread */
static gen_hash_t *pending_replies;

/* the condition variable used by a SIP worker to wait for a Diameter reply */
static struct dm_cond *my_reply_cond;

#define RULE_ORDER( _position ) ((((_position) == RULE_FIXED_HEAD) || ((_position) == RULE_FIXED_TAIL)) ? 1 : 0 )
#define PARSE_loc_rules( _rulearray, _parent) {								\
	int __ar;											\
	for (__ar=0; __ar < sizeof(_rulearray) / sizeof((_rulearray)[0]); __ar++) {			\
		struct dict_rule_data __data = { NULL, 							\
			(_rulearray)[__ar].position,							\
			0, 										\
			(_rulearray)[__ar].min,								\
			(_rulearray)[__ar].max};							\
		__data.rule_order = RULE_ORDER(__data.rule_position);					\
		FD_CHECK(fd_dict_search( 								\
			fd_g_config->cnf_dict,								\
			DICT_AVP, 									\
			AVP_BY_NAME, 									\
			(_rulearray)[__ar].avp_name, 							\
			&__data.rule_avp, 0 ) );							\
		if ( !__data.rule_avp ) {								\
			LM_ERR("AVP not found: '%s'\n", (_rulearray)[__ar].avp_name );		\
			return -1;									\
		}											\
		FD_CHECK_dict_new(DICT_RULE, &__data, _parent, NULL);	\
	} \
}


// index this using fD's (enum dict_avp_basetype)
static int dm_avp_inttype[] = {
	AAA_TYPE_INT32,
	AAA_TYPE_INT32,
	AAA_TYPE_INT32,
	AAA_TYPE_INT64,
	AAA_TYPE_UINT32,
	AAA_TYPE_UINT64,
	AAA_TYPE_FLOAT32,
	AAA_TYPE_FLOAT64,
};


int dm_init_reply_cond(int proc_rank)
{
	my_reply_cond = shm_malloc(sizeof *my_reply_cond);
	if (!my_reply_cond) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(my_reply_cond, 0, sizeof *my_reply_cond);

	init_mutex_cond(&my_reply_cond->mutex, &my_reply_cond->cond);
	return 0;
}


int init_mutex_cond(pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	pthread_mutexattr_t mattr;
	FD_CHECK(pthread_mutexattr_init(&mattr));
	FD_CHECK(pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED));
	FD_CHECK(pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST));
	FD_CHECK(pthread_mutex_init(mutex, &mattr));
	pthread_mutexattr_destroy(&mattr);

	pthread_condattr_t cattr;
	FD_CHECK(pthread_condattr_init(&cattr));
	FD_CHECK(pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED));
	FD_CHECK(pthread_cond_init(cond, &cattr));
	pthread_condattr_destroy(&cattr);

	return 0;
}


static int dm_acc_reply(struct msg ** msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	struct avp *a = NULL;
	struct avp_hdr * h = NULL;
	struct msg_hdr *hdr = NULL;
	int rc;

	FD_CHECK(fd_msg_hdr(*msg, &hdr));

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		LM_INFO("received ACR request?! discarding...\n");
		goto out;
	}

	FD_CHECK(fd_msg_search_avp(*msg, dm_dict.Result_Code, &a));
	FD_CHECK(fd_msg_avp_hdr(a, &h));
	rc = h->avp_value->u32;

	FD_CHECK(fd_msg_search_avp(*msg, dm_dict.Error_Message, &a));
	if (a) {
		FD_CHECK(fd_msg_avp_hdr(a, &h));
		LM_ERR("server failed to process ACR request, rc: %d (%.*s)\n",
			rc, (int)h->avp_value->os.len, h->avp_value->os.data);
	}

	if (hdr->msg_flags & CMD_FLAG_ERROR)
		LM_ERR("protocol failure for ACR request (rc: %d, 'E' bit set)\n", rc);

out:
	FD_CHECK(fd_msg_free(*msg));
	*msg = NULL;
	return 0;
}


static int dm_auth_reply(struct msg **_msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	struct msg_hdr *hdr = NULL;
	struct msg *msg = *_msg;
	struct avp *a = NULL;
	struct avp_hdr * h = NULL;
	int rc;
	str callid;
	struct dm_cond **prpl_cond, *rpl_cond;

	FD_CHECK(fd_msg_hdr(msg, &hdr));

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		LM_INFO("received MAR request?! discarding...\n");
		goto out;
	}

	FD_CHECK(fd_msg_search_avp(msg, dm_dict.Result_Code, &a));
	FD_CHECK(fd_msg_avp_hdr(a, &h));
	rc = h->avp_value->u32;

	FD_CHECK(fd_msg_search_avp(msg, dm_dict.Acct_Session_Id, &a));
	FD_CHECK(fd_msg_avp_hdr(a, &h));
	callid.s = (char *)h->avp_value->os.data;
	callid.len = (int)h->avp_value->os.len;

	LM_DBG("MAA reply %d, Acct-Session-Id: %.*s\n", rc, callid.len, callid.s);

	prpl_cond = (struct dm_cond **)hash_find_key(pending_replies, callid);
	if (!prpl_cond) {
		LM_ERR("failed to match Call-ID %.*s to a pending request\n",
		       callid.len, callid.s);
		goto out;
	}
	rpl_cond = *prpl_cond;
	rpl_cond->rc = rc;

	hash_remove_key(pending_replies, callid);

	FD_CHECK(fd_msg_search_avp(msg, dm_dict.Error_Message, &a));
	if (a) {
		rpl_cond->is_error = 1;
		FD_CHECK(fd_msg_avp_hdr(a, &h));
		LM_DBG("auth failure, rc: %d (%.*s)\n",
			rc, (int)h->avp_value->os.len, h->avp_value->os.data);
	} else {
		rpl_cond->is_error = 0;
	}

	/* signal the blocked SIP worker that the auth result is available! */
	pthread_mutex_lock(&rpl_cond->mutex);
	pthread_cond_signal(&rpl_cond->cond);
	pthread_mutex_unlock(&rpl_cond->mutex);

out:
	FD_CHECK(fd_msg_free(msg));
	*_msg = NULL;
	return 0;
}


static int dm_avps2json(void *root, cJSON *avps)
{
	cJSON *item = NULL;
	struct avp *it = NULL;
	struct avp_hdr *h = NULL;
	int i = 0;

	FD_CHECK_GT(fd_msg_browse(root, MSG_BRW_FIRST_CHILD, &it, NULL));

	LM_DBG("------------ AVP iteration ----------------\n");

	while (it) {
		cJSON *val;
		struct dict_object *obj;
		struct dict_avp_data dm_avp;
		int int_type = 1;
		double num_val = 0;

		FD_CHECK_GT(fd_msg_avp_hdr(it, &h));

		if (h->avp_flags & AVP_FLAG_VENDOR) {
			struct dict_avp_request ar;
			memset(&ar, 0, sizeof ar);
			ar.avp_code = h->avp_code;
			ar.avp_vendor = h->avp_vendor;
			__FD_CHECK_GT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE_AND_VENDOR,
					&ar, &obj, ENOENT), 0, skip);
		} else {
			__FD_CHECK_GT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE,
					&h->avp_code, &obj, ENOENT), 0, skip);
		}
		FD_CHECK_GT(fd_dict_getval(obj, &dm_avp));

		item = cJSON_CreateObject();
		if (!item) {
			LM_ERR("oom 2\n");
			goto out;
		}

		switch (dm_avp.avp_basetype) {
		case AVP_TYPE_GROUPED:
			LM_DBG("%d. got grouped AVP %s, code: %u\n", i, dm_avp.avp_name, dm_avp.avp_code);
			int_type = 0;

			val = cJSON_CreateArray();
			if (!val) {
				LM_ERR("oom 3\n");
				goto out;
			}

			if (dm_avps2json(it, val) != 0) {
				cJSON_Delete(val);
				LM_ERR("failed to encode Grouped AVP as JSON string (AVP: %s, code: %u)\n",
				       dm_avp.avp_name, dm_avp.avp_code);
				goto out;
			}

			break;

		case AVP_TYPE_OCTETSTRING:
			LM_DBG("%d. got string AVP %u, len: %d, value: %.*s\n", i, h->avp_code, (int)h->avp_value->os.len, (int)h->avp_value->os.len, h->avp_value->os.data);
			int_type = 0;

			val = cJSON_CreateStr((const char *)h->avp_value->os.data, (int)h->avp_value->os.len);
			if (!val) {
				LM_ERR("oom 4\n");
				goto out;
			}
			break;

		case AVP_TYPE_INTEGER32:
			LM_DBG("%d. got int32 AVP %u, value: %d\n", i, h->avp_code, h->avp_value->i32);
			num_val = (double)h->avp_value->i32;
			break;

		case AVP_TYPE_INTEGER64:
			LM_DBG("%d. got int64 AVP %u, value: %ld\n", i, h->avp_code, h->avp_value->i64);
			num_val = (double)h->avp_value->i64;
			break;

		case AVP_TYPE_UNSIGNED32:
			LM_DBG("%d. got uint32 AVP %u, value: %u\n", i, h->avp_code, h->avp_value->u32);
			num_val = (double)h->avp_value->u32;
			break;

		case AVP_TYPE_UNSIGNED64:
			LM_DBG("%d. got uint64 AVP %u, value: %lu\n", i, h->avp_code, h->avp_value->u64);
			num_val = (double)h->avp_value->u64;
			break;

		case AVP_TYPE_FLOAT32:
			LM_DBG("%d. got float32 AVP %u, value: %f\n", i, h->avp_code, h->avp_value->f32);
			num_val = (double)h->avp_value->f32;
			break;

		case AVP_TYPE_FLOAT64:
			LM_DBG("%d. got float64 AVP %u, value: %lf\n", i, h->avp_code, h->avp_value->f64);
			num_val = h->avp_value->f64;
			break;
		}

		if (int_type) {
			/* Integer Type AVP */

			val = cJSON_CreateNumber(num_val);
			if (!val) {
				LM_ERR("oom 5\n");
				goto out;
			}
		}

		cJSON_AddItemToObject(item, dm_avp.avp_name, val);
		cJSON_AddItemToArray(avps, item);

skip:
		FD_CHECK_GT(fd_msg_browse(it, MSG_BRW_NEXT, &it, NULL));
		i++;
	}

	LM_DBG("------------ END AVP iteration ----------------\n");
	return 0;

out:
	cJSON_Delete(item);

	LM_DBG("------------ END AVP iteration (failure) ----------------\n");
	return -1;
}


static int dm_custom_cmd_reply(struct msg **_msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	cJSON *avps = NULL;
	struct msg_hdr *hdr = NULL;
	struct msg *msg = *_msg;
	struct avp *a = NULL;
	struct avp_hdr * h = NULL;
	int rc;
	str tid;
	struct dm_cond **prpl_cond, *rpl_cond;

	FD_CHECK(fd_msg_hdr(msg, &hdr));

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		LM_INFO("received a request?! discarding...\n");
		goto out;
	}

	cJSON_InitHooks(&shm_mem_hooks);
	avps = cJSON_CreateArray();
	if (!avps) {
		LM_ERR("oom 1\n");
		goto out;
	}

	if (dm_avps2json(msg, avps) != 0) {
		LM_ERR("failed to pack Message AVPs as JSON string\n");
		goto out;
	}

	rc = fd_msg_search_avp(msg, dm_dict.Session_Id, &a);
	if (rc != 0) {
		LM_DBG("Missing Session-Id AVP in Diameter Answer %d/%d, looking for Transaction-Id\n",
		       hdr->msg_appl, hdr->msg_code);
		rc = fd_msg_search_avp(msg, dm_dict.Transaction_Id, &a);
		if (rc != 0) {
			LM_WARN("Missing Transaction-Id AVP in Diameter Answer %d/%d\n",
				   hdr->msg_appl, hdr->msg_code);
			goto out;
		}

		FD_CHECK_GT(fd_msg_avp_hdr(a, &h));
		tid.s = (char *)h->avp_value->os.data;
		tid.len = (int)h->avp_value->os.len;

		LM_DBG("%d/%d reply %d, Transaction-Id: %.*s\n", hdr->msg_appl,
			   hdr->msg_code, rc, tid.len, tid.s);
	} else {
		FD_CHECK_GT(fd_msg_avp_hdr(a, &h));
		tid.s = (char *)h->avp_value->os.data;
		tid.len = (int)h->avp_value->os.len;

		LM_DBG("%d/%d reply %d, Session-Id: %.*s\n", hdr->msg_appl,
			   hdr->msg_code, rc, tid.len, tid.s);
	}

	prpl_cond = (struct dm_cond **)hash_find_key(pending_replies, tid);
	if (!prpl_cond) {
		LM_ERR("failed to match Transaction_Id %.*s to a pending request\n",
		       tid.len, tid.s);
		goto out;
	}
	rpl_cond = *prpl_cond;

	pthread_mutex_lock(&rpl_cond->mutex);
	if (!hash_find_key(pending_replies, tid)) {
		pthread_mutex_unlock(&rpl_cond->mutex);
		LM_ERR("Transaction_Id %.*s already processed!\n", tid.len, tid.s);
		goto out;
	}

	if (rpl_cond->rpl_avps_json)
		shm_free(rpl_cond->rpl_avps_json);
	rpl_cond->rpl_avps_json = cJSON_PrintUnformatted(avps);

	hash_remove_key(pending_replies, tid);

	fd_msg_search_avp(msg, dm_dict.Error_Message, &a);
	if (a) {
		rpl_cond->is_error = 1;
		rc = fd_msg_avp_hdr(a, &h);
		if (rc != 0) {
			pthread_mutex_unlock(&rpl_cond->mutex);
			goto out;
		}

		LM_DBG("transaction failed (%.*s)\n",
			(int)h->avp_value->os.len, h->avp_value->os.data);
	} else {
		rpl_cond->is_error = 0;
	}

	/* signal the blocked SIP worker that the auth result is available! */
	pthread_cond_signal(&rpl_cond->cond);
	pthread_mutex_unlock(&rpl_cond->mutex);

out:
	cJSON_Delete(avps);
	cJSON_InitHooks(NULL);

	FD_CHECK(fd_msg_free(msg));
	*_msg = NULL;
	return 0;
}


int dm_register_callbacks(void)
{
	struct disp_when data;
	struct dict_object *vendor_dict;

	/* accounting */
	{
		memset(&data, 0, sizeof data);

		/* Initialize the dictionary objects we use */
		FD_CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_NAME,
				"Diameter Base Accounting", &data.app);

		/* Register the dispatch callback */
		FD_CHECK(fd_disp_register(dm_acc_reply,
				DISP_HOW_APPID, &data, NULL, NULL));

		/* Advertise support for the Diameter Base Accounting app */
		FD_CHECK(fd_disp_app_support(data.app, NULL, 0, 1 ));
	}

	/* auth */
	{
		memset(&data, 0, sizeof data);

		/* Initialize the dictionary objects we use */
		FD_CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_NAME,
			"Diameter Session Initiation Protocol (SIP) Application", &data.app);

		/* Register the dispatch callback */
		FD_CHECK(fd_disp_register(dm_auth_reply,
				DISP_HOW_APPID, &data, NULL, NULL));

		/* Advertise support for the Diameter SIP Application app */
		FD_CHECK(fd_disp_app_support(data.app, NULL, 0, 1 ));
	}

	/* custom commands */
	{
		int i;

		memset(&data, 0, sizeof data);

		for (i = 0; i < n_app_ids; i++) {
			/* Initialize the dictionary objects we use */
			FD_CHECK_dict_search(DICT_APPLICATION, APPLICATION_BY_ID,
				&app_defs[i].id, &data.app);

			/* Register the dispatch callback */
			FD_CHECK(fd_disp_register(dm_custom_cmd_reply,
					DISP_HOW_APPID, &data, NULL, NULL));

			if (app_defs[i].vendor != (unsigned int)-1) {
				FD_CHECK_dict_search(DICT_VENDOR, VENDOR_BY_ID,
						&app_defs[i].vendor, &vendor_dict);
			} else {
				vendor_dict = NULL;
			}

			/* Advertise support for the respective app */
			FD_CHECK(fd_disp_app_support(data.app,
						vendor_dict,
						(app_defs[i].auth?1:0),
						(app_defs[i].auth?0:1)));

			LM_DBG("registered a reply callback for App ID %d ...\n", app_defs[i].id);
		}
	}

	return 0;
}


int dm_store_enumval(const char *name, int value)
{
	int *val_holder;
	const str *_name = _str(name);

	val_holder = (int *)hash_get_key(osips_enumvals, *_name);
	if (!val_holder) {
		LM_ERR("oom\n");
		return -1;
	}

	*val_holder = value;
	return 0;
}


int dm_add_pending_reply(const str *callid, struct dm_cond *reply_cond)
{
	struct dm_cond **cond_holder;
	unsigned int hentry;

	hentry = hash_entry(pending_replies, *callid);
	hash_lock(pending_replies, hentry);

	cond_holder = (struct dm_cond **)hash_get(pending_replies, hentry, *callid);
	if (!cond_holder) {
		hash_unlock(pending_replies, hentry);
		LM_ERR("oom\n");
		return -1;
	}

	*cond_holder = reply_cond;
	hash_unlock(pending_replies, hentry);

	return 0;
}



/* all of these AVPs are part of "RADIUS Extension for Digest Auth" RFC 5090 */
static int dm_register_digest_avps(void)
{
	struct dict_object *UTF8String_type;

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* Digest-Response */
	{
		struct dict_avp_data data = {
				103, 				/* Code */
				0, 					/* Vendor */
				"Digest-Response", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Realm */
	{
		struct dict_avp_data data = {
				104, 				/* Code */
				0, 					/* Vendor */
				"Digest-Realm", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 	/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nonce */
	{
		struct dict_avp_data data = {
				105, 				/* Code */
				0, 					/* Vendor */
				"Digest-Nonce", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Response-Auth */
	{
		struct dict_avp_data data = {
				106,					/* Code */
				0, 						/* Vendor */
				"Digest-Response-Auth",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nextnonce */
	{
		struct dict_avp_data data = {
				107, 				/* Code */
				0, 					/* Vendor */
				"Digest-Nextnonce", /* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Method */
	{
		struct dict_avp_data data = {
				108, 				/* Code */
				0, 					/* Vendor */
				"Digest-Method", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-URI */
	{
		struct dict_avp_data data = {
				109, 				/* Code */
				0, 					/* Vendor */
				"Digest-URI", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-QoP */
	{
		struct dict_avp_data data = {
				110,				/* Code */
				0, 					/* Vendor */
				"Digest-QoP", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Algorithm */
	{
		struct dict_avp_data data = {
				111, 				/* Code */
				0, 					/* Vendor */
				"Digest-Algorithm",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Entity-Body-Hash */
	{
		struct dict_avp_data data = {
				112,						/* Code */
				0, 							/* Vendor */
				"Digest-Entity-Body-Hash", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-CNonce */
	{
		struct dict_avp_data data = {
				113, 					/* Code */
				0, 					/* Vendor */
				"Digest-CNonce", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 			/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Nonce-Count */
	{
		struct dict_avp_data data = {
				114, 					/* Code */
				0,						/* Vendor */
				"Digest-Nonce-Count", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Username */
	{
		struct dict_avp_data data = {
				115, 				/* Code */
				0, 					/* Vendor */
				"Digest-Username", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Opaque */
	{
		struct dict_avp_data data = {
				116, 				/* Code */
				0, 					/* Vendor */
				"Digest-Opaque", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Auth-Param */
	{
		struct dict_avp_data data = {
				117,					/* Code */
				0, 						/* Vendor */
				"Digest-Auth-Param", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-AKA-Auts */
	{
		struct dict_avp_data data = {
				118, 				/* Code */
				0, 					/* Vendor */
				"Digest-AKA-Auts", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Domain */
	{
		struct dict_avp_data data = {
				119, 				/* Code */
				0, 					/* Vendor */
				"Digest-Domain", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-Stale */
	{
		struct dict_avp_data data = {
				120, 				/* Code */
				0, 					/* Vendor */
				"Digest-Stale", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* Digest-HA1 */
	{
		struct dict_avp_data data = {
				121, 				/* Code */
				0, 					/* Vendor */
				"Digest-HA1", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-AOR */
	{
		struct dict_avp_data data = {
				122, 			/* Code */
				0, 				/* Vendor */
				"SIP-AOR", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	return 0;
}




/* Register the Diameter SIP Application (RFC 4740) commands, AVPs, etc. */
int dm_init_sip_application(void)
{
	struct dict_object *sip;
	struct dict_object * UTF8String_type;

	struct dict_application_data data =
		{ 	6, "Diameter Session Initiation Protocol (SIP) Application"	};
	FD_CHECK_dict_new(DICT_APPLICATION, &data, NULL, &sip);

	FD_CHECK_dict_search(DICT_TYPE, TYPE_BY_NAME, "UTF8String", &UTF8String_type);

	/* SIP-Server-URI */
	{
		/*
			The SIP-Server-URI AVP (AVP Code 371) is of type UTF8String.  This
			AVP contains a SIP or SIPS URI (as defined in RFC 3261 [RFC3261])
			that identifies a SIP server.
		*/
		struct dict_avp_data data = {
				371,				/* Code */
				0, 					/* Vendor */
				"SIP-Server-URI", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-Method */
	{
		/*
			The SIP-Method-AVP (AVP Code 393) is of type UTF8String and contains
			the method of the SIP request that triggered the Diameter message.
			The Diameter server MUST use this AVP solely for authorization of SIP
			requests, and MUST NOT use it to compute the Digest authentication.
			To compute the Digest authentication, the Diameter server MUST use
			the Digest-Method AVP instead.
		*/
		struct dict_avp_data data = {
				393, 			/* Code */
				0, 				/* Vendor */
				"SIP-Method", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_OCTETSTRING 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, UTF8String_type, NULL);
	}

	/* SIP-Number-Auth-Items */
	{
		/*
			The SIP-Number-Auth-Items AVP (AVP Code 382) is of type Unsigned32
			and indicates the number of authentication and/or authorization
			credentials that the Diameter server included in a Diameter message.

			When the AVP is present in a request, it indicates the number of
			SIP-Auth-Data-Items the Diameter client is requesting.  This can be
			used, for instance, when the SIP server is requesting several
			pre-calculated authentication credentials.  In the answer message,
			the SIP-Number-Auth-Items AVP indicates the actual number of items
			that the Diameter server included.
		*/
		struct dict_avp_data data = {
				382,						/* Code */
				0, 							/* Vendor */
				"SIP-Number-Auth-Items",	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 		/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* SIP-Authentication-Scheme */
	{
		/*
			The SIP-Authentication-Scheme AVP (AVP Code 377) is of type
			Enumerated and indicates the authentication scheme used in the
			authentication of SIP services.  RFC 2617 identifies this value as an
			"auth-scheme" (see Section 1.2 of RFC 2617 [RFC2617]).  The only
			currently defined value is:

			o  DIGEST (0) to indicate HTTP Digest authentication as specified in
			RFC 2617 [RFC2617] Section 3.2.1.  Derivative work is also
			considered Digest authentication scheme, as long as the
			"auth-scheme" is identified as Digest in the SIP headers carrying
			the HTTP authentication.  This includes, e.g., the HTTP Digest
			authentication using AKA [RFC3310].

			Each HTTP Digest directive (parameter) is transported in a
			corresponding AVP, whose name follows the pattern Digest-*.  The
			Digest-* AVPs are RADIUS attributes imported from the RADIUS
			Extension for Digest Authentication [RFC4590] namespace, allowing a
			smooth transition between RADIUS and Diameter applications supporting
			SIP.  The Diameter SIP application goes a step further by grouping
			the Digest-* AVPs into the SIP-Authenticate, SIP-Authorization, and
			SIP-Authentication-Info grouped AVPs that correspond to the SIP WWW-
			Authenticate/Proxy-Authentication, Authorization/Proxy-Authorization,
			and Authentication-Info headers fields, respectively.

			Note: Due to the fact that HTTP Digest authentication [RFC2617] is
			the only mandatory authentication mechanism in SIP, this memo only
			provides support for HTTP Digest authentication and derivative
			work such as HTTP Digest authentication using AKA [RFC3310].
			Extensions to this memo can register new values and new AVPs to
			provide support for other authentication schemes or extensions to
			HTTP Digest authentication.

			Note: Although RFC 2617 [RFC2617] defines the Basic and Digest
			schemes for authenticating HTTP requests, RFC 3261 [RFC3261] only
			imports HTTP Digest as a mechanism to provide authentication in
			SIP.

			Due to syntactic requirements, HTTP Digest authentication has to
			escape quote characters in contents of HTTP Digest directives.  When
			translating directives into Digest-* AVPs, the Diameter client or
			server removes the surrounding quotes where present, as required by
			the syntax of the Digest-* attributes defined in the "RADIUS
			Extension for Digest Authentication" [RFC4590].

		*/
		#define enumval_def_u32( _val_, _str_ ) \
				{ _str_, 		{ .u32 = _val_ }}

		struct dict_object 	*type;
		struct dict_type_data 	 tdata = {
			AVP_TYPE_UNSIGNED32,	"Enumerated(SIP-Authentication-Scheme)",
				NULL, NULL, NULL, NULL, NULL};
		struct dict_enumval_data tvals[] = {
			enumval_def_u32( 0, "DIGEST")
		};
		struct dict_avp_data data = {
				377,							/* Code */
				0, 								/* Vendor */
				"SIP-Authentication-Scheme", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32			/* base type of data */
		};
		int i;
		/* Create the Enumerated type, enumerated values, and the AVP */
		FD_CHECK_dict_new(DICT_TYPE, &tdata, NULL, &type);
		for (i = 0; i < sizeof(tvals) / sizeof(tvals[0]); i++) {
			FD_CHECK_dict_new(DICT_ENUMVAL, &tvals[i], type, NULL);
		}
		FD_CHECK_dict_new(DICT_AVP, &data, type, NULL);
	}

	/* SIP-Item-Number */
	{
		/*
			The SIP-Item-Number (AVP Code 378) is of type Unsigned32 and is
			included in a SIP-Auth-Data-Item grouped AVP in circumstances where
			there are multiple occurrences of SIP-Auth-Data-Item AVPs and the
			order of processing is relevant.  The AVP indicates the order in
			which the Grouped SIP-Auth-Data-Item should be processed.  Lower
			values of the SIP-Item-Number AVP indicate that the whole
			SIP-Auth-Data-Item SHOULD be processed before other
			SIP-Auth-Data-Item AVPs that contain higher values in the
			SIP-Item-Number AVP.
		*/
		struct dict_avp_data data = {
				378, 					/* Code */
				0, 					/* Vendor */
				"SIP-Item-Number", 		/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_UNSIGNED32 			/* base type of data */
				};
		FD_CHECK_dict_new(DICT_AVP, &data, NULL, NULL);
	}

	/* SIP-Authorization */
	{
		/*
			The SIP-Authorization AVP (AVP Code 380) is of type Grouped and
			contains a reconstruction of either the SIP Authorization or
			Proxy-Authorization header fields specified in RFC 2617 [RFC2617] for
			the HTTP Digest authentication scheme.

			The SIP-Authorization AVP is defined as follows (per the
			grouped-avp-def of RFC 3588 [RFC3588]):

			SIP-Authorization ::= < AVP Header: 380 >
					    { Digest-Username }
					    { Digest-Realm }
					    { Digest-Nonce }
					    { Digest-URI }
					    { Digest-Response }
					    [ Digest-Algorithm ]
					    [ Digest-CNonce ]
					    [ Digest-Opaque ]
					    [ Digest-QoP ]
					    [ Digest-Nonce-Count ]
					    [ Digest-Method]
					    [ Digest-Entity-Body-Hash ]
					  * [ Digest-Auth-Param ]
					  * [ AVP ]
		*/
		struct dict_object *avp;
		struct dict_avp_data data = {
				380, 					/* Code */
				0,						/* Vendor */
				"SIP-Authorization", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_GROUPED 			/* base type of data */
				};
		struct local_rules_definition rules[] = {
			{ "Digest-Username",	RULE_REQUIRED, -1, 1 },
			{ "Digest-Realm",		RULE_REQUIRED, -1, 1 },
			{ "Digest-Nonce",		RULE_REQUIRED, -1, 1 },
			{ "Digest-URI",			RULE_REQUIRED, -1, 1 },
			{ "Digest-Response",	RULE_REQUIRED, -1, 1 },
			{ "Digest-Algorithm",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-CNonce",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-Opaque",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-QoP",			RULE_OPTIONAL, -1, 1 },
			{ "Digest-Nonce-Count",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-Method",		RULE_OPTIONAL, -1, 1 },
			{ "Digest-Entity-Body-Hash",	RULE_OPTIONAL, -1, 1 },
			{ "Digest-Auth-Param",	RULE_OPTIONAL, -1, -1 },
		};

		FD_CHECK_dict_new(DICT_AVP, &data, NULL, &avp);
		PARSE_loc_rules(rules, avp);
	}

	/* SIP-Auth-Data-Item */
	{
		/*
			The SIP-Auth-Data-Item (AVP Code 376) is of type Grouped and contains
			the authentication and/or authorization information pertaining to a
			user.

			When the Diameter server uses the grouped SIP-Auth-Data-Item AVP to
			include a SIP-Authenticate AVP, the Diameter server MUST send a
			maximum of one authentication data item (e.g., in case the SIP
			request contained several credentials).  Section 11 contains a
			detailed discussion and normative text of the case when a SIP request
			contains several credentials.

			The SIP-Auth-Data-Item AVP is defined as follows (per the
			grouped-avp-def of RFC 3588 [RFC3588]):

			SIP-Auth-Data-Item ::= < AVP Header: 376 >
			{ SIP-Authentication-Scheme }
				[ SIP-Item-Number ]
				[ SIP-Authenticate ]
				[ SIP-Authorization ]
				[ SIP-Authentication-Info ]
				* [ AVP ]
		*/
		struct dict_object * avp;
		struct dict_avp_data data = {
				376, 					/* Code */
				0,						/* Vendor */
				"SIP-Auth-Data-Item", 	/* Name */
				AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY, 	/* Fixed flags */
				AVP_FLAG_MANDATORY,		 	/* Fixed flag values */
				AVP_TYPE_GROUPED 			/* base type of data */
				};
		struct local_rules_definition rules[] = {
			{ "SIP-Authentication-Scheme",	RULE_REQUIRED, -1, 1 },
			{ "SIP-Item-Number",			RULE_OPTIONAL, -1, 1 },
			//{ "SIP-Authenticate",			RULE_OPTIONAL, -1, 1 },
			{ "SIP-Authorization",			RULE_OPTIONAL, -1, 1 },
			//{ "SIP-Authentication-Info",	RULE_OPTIONAL, -1, 1 },
		};

		FD_CHECK_dict_new(DICT_AVP, &data, NULL, &avp);
		PARSE_loc_rules(rules, avp);
	}

	/* Multimedia-Auth-Request (MAR) Command */
	{
		struct dict_object *cmd;
		struct dict_cmd_data data = {
				286,						/* Code */
				"Multimedia-Auth-Request", 	/* Name */
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR,
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE
				};
		struct local_rules_definition rules[] =  {
			{ "Session-Id",				RULE_FIXED_HEAD, -1, 1 },
			{ "Auth-Application-Id",	RULE_REQUIRED,   -1, 1 },
			{ "Auth-Session-State", 	RULE_REQUIRED,   -1, 1 },
			{ "Origin-Host",			RULE_REQUIRED,   -1, 1 },
			{ "Origin-Realm", 			RULE_REQUIRED,   -1, 1 },
			{ "Destination-Realm",		RULE_REQUIRED,   -1, 1 },
			{ "SIP-AOR", 				RULE_REQUIRED,   -1, 1 },
			{ "SIP-Method", 			RULE_REQUIRED,   -1, 1 },
			{ "Destination-Host", 		RULE_OPTIONAL,   -1, 1 },
			{ "User-Name",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Server-URI", 		RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Number-Auth-Items",	RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Auth-Data-Item", 	RULE_OPTIONAL,   -1, 1 },
			{ "Proxy-Info",				RULE_OPTIONAL,   -1, -1 },
			{ "Route-Record", 			RULE_OPTIONAL,   -1, -1 },
		};

		FD_CHECK_dict_new(DICT_COMMAND, &data, sip, &cmd);
		PARSE_loc_rules(rules, cmd);
	}

	/* Multimedia-Auth-Answer (MAA) Command */
	{
		struct dict_object *cmd;
		struct dict_cmd_data data = {
				286,						/* Code */
				"Multimedia-Auth-Answer", 	/* Name */
				CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR, 	/* Fixed flags */
				CMD_FLAG_PROXIABLE 			/* Fixed flag values */
				};
		struct local_rules_definition rules[] = {
			{ "Session-Id",				RULE_FIXED_HEAD, -1, 1 },
			{ "Auth-Application-Id",	RULE_REQUIRED,   -1, 1 },
			{ "Result-Code",			RULE_REQUIRED,   -1, 1 },
			{ "Auth-Session-State",		RULE_REQUIRED,   -1, 1 },
			{ "Origin-Host",			RULE_REQUIRED,   -1, 1 },
			{ "Origin-Realm",			RULE_REQUIRED,   -1, 1 },
			{ "User-Name",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-AOR",				RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Number-Auth-Items",	RULE_OPTIONAL,   -1, 1 },
			{ "SIP-Auth-Data-Item",		RULE_OPTIONAL,   -1, -1 },
			{ "Authorization-Lifetime",	RULE_OPTIONAL,   -1, 1 },
			{ "Auth-Grace-Period",		RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Host",			RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Host-Usage",	RULE_OPTIONAL,   -1, 1 },
			{ "Redirect-Max-Cache-Time",	RULE_OPTIONAL,   -1, 1 },
			{ "Proxy-Info",				RULE_OPTIONAL,   -1, -1 },
			{ "Route-Record",			RULE_OPTIONAL,   -1, -1 },
		};

		FD_CHECK_dict_new(DICT_COMMAND, &data, sip, &cmd);
		PARSE_loc_rules(rules, cmd);
	}

	return 0;
}


/*
 * Register a series of AVPs needed by OpenSIPS (some dating back from RADIUS,
 * and some purely custom / non-standardized).
 *
 * Note that these AVPs may be overridden in the freeDiameter-client.conf file
 */
int dm_register_osips_avps(void)
{
	FD_CHECK(register_osips_avps());
	FD_CHECK(dm_register_digest_avps());
	return 0;
}


int dm_init_minimal(void)
{
	/* these functions are not immediately available via the
	 * libfdcore .h files, but who said we cannot use them? >:) */
	extern int fd_conf_init(void);
	extern int fd_dict_base_protocol(struct dictionary * dict);

	static struct fd_config g_conf;
	static char min_init_done;

	if (min_init_done)
		return 0;

	if (!(osips_enumvals = hash_init(8))) {
		LM_ERR("oom\n");
		return -1;
	}

	if (!(pending_replies = hash_init(64))) {
		LM_ERR("oom\n");
		return -1;
	}

	LM_INFO("initializing the Diameter object dictionary...\n");

	fd_g_config = &g_conf;

	FD_CHECK(fd_conf_init());
	FD_CHECK(fd_dict_base_protocol(fd_g_config->cnf_dict));
	FD_CHECK(dm_register_osips_avps());
	FD_CHECK(dm_init_sip_application());

	min_init_done = 1;
	return 0;
}


void dm_destroy(void)
{
	hash_destroy(osips_enumvals, NULL);
	osips_enumvals = NULL;

	hash_destroy(pending_replies, NULL);
	pending_replies = NULL;
}


static int parse_config_string(const char *cfgstr,
        char **cfg_filename, char **extra_avps_file)
{
	csv_record *items, *it;
	int have_conf = 0;

	items = __parse_csv_record(_str(cfgstr), 0, ';');
	for (it = items; it; it = it->next) {
		str dup;

		if (!have_conf) {
			if (pkg_nt_str_dup(&dup, &it->s) != 0) {
				LM_ERR("oom\n");
				return -1;
			}

			*cfg_filename = dup.s;
			have_conf = 1;
		} else {
			csv_record *kv;

			kv = __parse_csv_record(&it->s, 0, ':');
			if (str_casematch(&kv->s, const_str("extra-avps-file"))) {
				if (pkg_nt_str_dup(&dup, &kv->next->s) != 0) {
					LM_ERR("oom\n");
					return -1;
				}

				*extra_avps_file = dup.s;
			}

			free_csv_record(kv);
		}
	}

	LM_DBG("freeDiameter cfg file: '%s'\n", *cfg_filename);
	LM_DBG("freeDiameter extra-avps-file: '%s'\n", *extra_avps_file);

	free_csv_record(items);
	return 0;
}


aaa_conn *dm_init_prot(str *aaa_url)
{
	static str previous_url;
	aaa_prot_config parsed;

	if (previous_url.s && !str_match(&previous_url, aaa_url)) {
		LM_ERR("please use the same Diameter URL for all modules\n");
		return NULL;
	}

	if (!previous_url.s && pkg_str_dup(&previous_url, aaa_url) != 0) {
		LM_ERR("oom\n");
		return NULL;
	}

	if (aaa_parse_url(aaa_url, &parsed) != 0) {
		LM_ERR("bad AAA URL\n");
		return NULL;
	}

	if (strlen((char *)parsed.rest)) {
		if (parse_config_string((char *)parsed.rest,
		        &dm_conf_filename, &extra_avps_file) != 0) {
			LM_ERR("failed to parse config string\n");
			return NULL;
		}
	}

	if (dm_init_minimal() != 0) {
		LM_ERR("failed to init freeDiameter global dictionary\n");
		return NULL;
	}

	if (parse_extra_avps(extra_avps_file) != 0) {
		LM_ERR("failed to load the 'extra-avps-file'\n");
		return NULL;
	}

	return DM_DUMMY_HANDLE;
}


int freeDiameter_init(void)
{
	extern int fd_conf_deinit(void);

	extern int fd_log_level;

	if (fd_log_level < FD_LOG_ANNOYING)
		fd_log_level = FD_LOG_ANNOYING;

	if (fd_log_level > FD_LOG_FATAL)
		fd_log_level = FD_LOG_FATAL;

	/* free the "minimal initialization" we've done at mod_init() */
	FD_CHECK(fd_conf_deinit());

	/* ... and now fully init the entire freeDiameter library
	 *	(parse freeDiameter-client.conf file, fork all threads, etc.) */
	FD_CHECK(fd_core_initialize());

	fd_g_debug_lvl = fd_log_level;

	FD_CHECK(fd_core_parseconf(dm_conf_filename));

	return 0;
}


int dm_find(aaa_conn *_, aaa_map *map, int op)
{
	struct dict_object *obj;

	if (!map) {
		LM_ERR("NULL map argument\n");
		return -1;
	}

	switch (op) {
	case AAA_DICT_FIND_ATTR: {
		struct dict_avp_data avp;

		if (map->type == 0) {
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME,
			      map->name, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &avp));
		} else {
			struct dict_avp_request_ex req;

			memset(&req, 0, sizeof req);
			req.avp_data.avp_name = map->name;
			req.avp_vendor.vendor_id = map->type;

			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_STRUCT,
			      &req, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &avp));
		}

		map->value = avp.avp_code;
		return 0;
	}
	case AAA_DICT_FIND_VAL: {
		unsigned int entry;
		int *value;

		entry = hash_entry(osips_enumvals, *_str(map->name));
		value = (int *)hash_find(osips_enumvals, entry, *_str(map->name));
		if (!value) {
			LM_ERR("enum '%s' not found\n", map->name);
			return -1;
		}

		map->value = *value;
		return 0;
	}
	case AAA_DICT_FIND_VEND: {
		struct dict_vendor_data vendor;

		FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_VENDOR, VENDOR_BY_NAME,
		      map->name, &obj, ENOENT));
		FD_CHECK(fd_dict_getval(obj, &vendor));

		map->value = vendor.vendor_id;
		LM_DBG("found vendor '%s', id: %d\n", map->name, map->value);
		return 0;
	}}

	LM_ERR("failed to locate Diameter object: '%s'\n", map->name);
	return -1;
}


aaa_message *_dm_create_message(aaa_conn *_, int msg_type,
        unsigned int app_id, unsigned int cmd_code)
{
	aaa_message *m;
	struct dm_message *dm;

	m = shm_malloc(sizeof *m);
	if (!m) {
		LM_ERR("oom\n");
		return NULL;
	}

	dm = shm_malloc(sizeof *dm);
	if (!dm) {
		shm_free(m);
		LM_ERR("oom\n");
		return NULL;
	}

	memset(m, 0, sizeof *m);
	m->type = msg_type;
	m->avpair = (void *)dm;

	memset(dm, 0, sizeof *dm);
	INIT_LIST_HEAD(&dm->avps);
	dm->am = m;
	dm->app_id = app_id;
	dm->cmd_code = cmd_code;

	return m;
}


aaa_message *dm_create_message(aaa_conn *_, int msg_type)
{
	return _dm_create_message(_, msg_type, 0, 0);
}


int _dm_avp_add(aaa_conn *_, struct list_head *avp_arr, aaa_map *avp, void *val,
               int val_length, int vendor)
{
	struct {
		struct dm_avp davp;
		char buf[0];
	} *wrap;
	int len;

	if (!avp || !avp->name || val_length < AAA_TYPE_GROUPED)
		return -1;
	len = strlen(avp->name);

	wrap = shm_malloc(sizeof *wrap + len + 1 +
				(val_length < 0 ? 0 : val_length) + 1);
	if (!wrap) {
		LM_ERR("oom\n");
		return -1;
	}

	memset(&wrap->davp, 0, sizeof wrap->davp);
	INIT_LIST_HEAD(&wrap->davp.subavps);

	wrap->davp.name.s = wrap->buf;
	wrap->davp.name.len = len;
	strcpy(wrap->buf, avp->name);
	wrap->davp.vendor_id = vendor;

	if (val_length >= 0) {
		wrap->davp.value_type = AAA_TYPE_OCTETSTRING;

		wrap->davp.value.os.data = (uint8_t *)(wrap->buf + len + 1);
		wrap->davp.value.os.len = val_length;
		memcpy(wrap->davp.value.os.data, val, val_length);
		wrap->davp.value.os.data[val_length] = '\0';
	} else if (val_length == AAA_TYPE_GROUPED) {
		wrap->davp.value_type = val_length;

		if (dm_build_avps(&wrap->davp.subavps, (cJSON *)val) != 0) {
			LM_ERR("failed to build sub-AVP list\n");
			shm_free(wrap);
			return -1;
		}
	} else {
		wrap->davp.value_type = val_length;

		switch (val_length) {
		case AAA_TYPE_INT32:
			wrap->davp.value.i32 = (int32_t)*(double *)val;
			break;

		case AAA_TYPE_INT64:
			wrap->davp.value.i64 = (int64_t)*(double *)val;
			break;

		case AAA_TYPE_UINT32:
			wrap->davp.value.u32 = (uint32_t)*(double *)val;
			break;

		case AAA_TYPE_UINT64:
			wrap->davp.value.u64 = (uint64_t)*(double *)val;
			break;

		case AAA_TYPE_FLOAT32:
			wrap->davp.value.f32 = (float)*(double *)val;
			break;

		case AAA_TYPE_FLOAT64:
			wrap->davp.value.f64 = *(double *)val;
			break;
		}
	}

	list_add_tail(&wrap->davp.list, avp_arr);
	return 0;
}


int dm_avp_add(aaa_conn *_, aaa_message *msg, aaa_map *avp, void *val,
               int val_length, int vendor)
{
	return _dm_avp_add(_, &((struct dm_message *)(msg->avpair))->avps,
	                   avp, val, val_length, vendor);
}


int dm_build_avps(struct list_head *subavps, cJSON *array)
{
	cJSON *_avp;
	struct dict_avp_data dm_avp;
	struct dict_object *obj;
	char *name;
	unsigned int code;
	str st;

	for (_avp = array; _avp; _avp = _avp->next) {
		if (_avp->type != cJSON_Object) {
			LM_ERR("bad JSON type in Grouped AVP: sub-AVPs must be Objects\n");
			return -1;
		}

		cJSON *avp = _avp->child;

		// TODO: allow dict too, e.g. maybe for setting a non-zero VendorId?!
		if (!(avp->type & (cJSON_String|cJSON_Number|cJSON_Array))) {
			LM_ERR("bad AVP value: only String allowed (AVP name: %s)\n", avp->string);
			goto error;
		}

		init_str(&st, avp->string);
		if (str2int(&st, &code) == 0) {

			LM_DBG("AVP:: searching AVP by int: %d\n", code);
			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_CODE,
				&code, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &dm_avp));

			name = dm_avp.avp_name;
		} else {
			LM_DBG("AVP:: searching AVP by string: %s\n", avp->string);

			FD_CHECK(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME_ALL_VENDORS,
				avp->string, &obj, ENOENT));
			FD_CHECK(fd_dict_getval(obj, &dm_avp));

			name = avp->string;
			code = dm_avp.avp_code;
		}

		aaa_map my_avp = {.name = name};

		if (avp->type & cJSON_String) {
			LM_DBG("dbg::: AVP %d (name: '%s', str-val: %s)\n", code, name, avp->valuestring);
			if (_dm_avp_add(NULL, subavps, &my_avp, avp->valuestring,
			        strlen(avp->valuestring), 0) != 0) {
				LM_ERR("failed to add AVP %d, aborting request\n", code);
				goto error;
			}
		} else if (avp->type & cJSON_Number) {
			LM_DBG("dbg::: AVP %d (name: '%s', int-val: %d)\n", code, name, avp->valueint);
			if (_dm_avp_add(NULL, subavps, &my_avp, &avp->valuedouble,
							dm_avp_inttype[dm_avp.avp_basetype], 0) != 0) {
				LM_ERR("failed to add AVP %d, aborting request\n", code);
				goto error;
			}
		} else if (avp->type & cJSON_Array) {
			LM_DBG("dbg::: AVP %d (name: '%s', grouped)\n", code, name);
			if (_dm_avp_add(NULL, subavps, &my_avp, avp->child, AAA_TYPE_GROUPED, 0) != 0) {
				LM_ERR("failed to add grouped AVP %d, aborting request\n", code);
				goto error;
			}
		} else {
			LM_ERR("bad AVP value type (%d), must be string/int/array\n", avp->type);
			goto error;
		}
	}

	return 0;

error:
	return -1;
}


int _dm_send_message(aaa_conn *_, aaa_message *req, aaa_message **reply,
               char **rpl_avps)
{
	struct dm_message *dm;

	if (!req || !my_reply_cond)
		return -1;

	dm = (struct dm_message *)(req->avpair);
	dm->reply_cond = my_reply_cond;

	/* never provide the reply, just grab the result code, if any */
	if (reply)
		*reply = NULL;

	req->last_found = DM_MSG_SENT;

	pthread_mutex_lock(msg_send_lk);

	list_add_tail(&dm->list, msg_send_queue);
	pthread_cond_signal(msg_send_cond);

	pthread_mutex_unlock(msg_send_lk);

	LM_DBG("message queued for sending\n");

	if (req->type == AAA_AUTH || req->type == AAA_CUSTOM) {
		struct timespec wait_until;
		struct timeval now, wait_time, res;
		int rc;

		gettimeofday(&now, NULL);
		wait_time.tv_sec = dm_answer_timeout / 1000;
		wait_time.tv_usec = dm_answer_timeout % 1000 * 1000UL;
		LM_DBG("awaiting auth reply (%ld s, %ld us)...\n", wait_time.tv_sec, wait_time.tv_usec);

		timeradd(&now, &wait_time, &res);

		wait_until.tv_sec = res.tv_sec;
		wait_until.tv_nsec = res.tv_usec * 1000UL;

		pthread_mutex_lock(&my_reply_cond->mutex);
		rc = pthread_cond_timedwait(&my_reply_cond->cond,
					&my_reply_cond->mutex, &wait_until);
		if (rc != 0) {
			LM_ERR("timeout (errno: %d '%s') while awaiting Diameter "
			       "reply\n", rc, strerror(rc));
			pthread_mutex_unlock(&my_reply_cond->mutex);

			if (rpl_avps)
				*rpl_avps = NULL;
			return -2;
		}

		pthread_mutex_unlock(&my_reply_cond->mutex);

		LM_DBG("reply received, Result-Code: %d (%s)\n", my_reply_cond->rc,
				my_reply_cond->is_error ? "FAILURE" : "SUCCESS");
		LM_DBG("AVPs: %s\n", my_reply_cond->rpl_avps_json);

		if (rpl_avps)
			*rpl_avps = my_reply_cond->rpl_avps_json;

		if (my_reply_cond->is_error)
			return -1;
	}

	return 0;
}


int dm_send_message(aaa_conn *_, aaa_message *req, aaa_message **reply)
{
	return _dm_send_message(_, req, reply, NULL);
}


/* recursively free all AVPs, including grouped ones */
static void dm_free_avps(struct list_head *avps)
{
	struct list_head *it, *aux;
	struct dm_avp *avp;

	list_for_each_safe (it, aux, avps) {
		avp = list_entry(it, struct dm_avp, list);

		if (avp->value_type == AAA_TYPE_GROUPED)
			dm_free_avps(&avp->subavps);

		shm_free(avp);
	}
}


void _dm_destroy_message(aaa_message *msg)
{
	if (!msg)
		return;

	dm_free_avps(&((struct dm_message *)(msg->avpair))->avps);

	shm_free(msg->avpair);
	shm_free(msg);
}

int dm_destroy_message(aaa_conn *_, aaa_message *msg)
{
	if (!msg)
		return 0;

	/* let the peer process be the one who cleans it up */
	if (msg->last_found == DM_MSG_SENT)
		return 0;

	_dm_destroy_message(msg);
	return 0;
}
