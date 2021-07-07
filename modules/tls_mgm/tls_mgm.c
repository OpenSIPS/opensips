 /*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2015 OpenSIPS Foundation
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
 *
 */

#ifdef __OS_linux
#define _GNU_SOURCE /* we need this for gettid() */
#endif

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <dirent.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../timer.h"
#include "../../receive.h"
#include "../../pt.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"
#include "../../db/db.h"
#include "../../str_list.h"

#include "../../net/proto_tcp/tcp_common_defs.h"
#include "tls_conn_server.h"
#include "tls_config.h"
#include "tls_domain.h"
#include "tls_params.h"
#include "tls_select.h"
#include "tls.h"
#include "api.h"

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && defined __OS_linux)
#include <features.h>
#if defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 2)
#define __OPENSSL_ON_EXIT
#endif
#endif
#endif

#define DB_CAP DB_CAP_QUERY | DB_CAP_UPDATE
#define len(s)	s == NULL?0:strlen(s)

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %.*s has a bad type\n", _col.len, _col.s); \
			continue;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			continue;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			continue;\
		} \
		if ((_val)->type == DB_INT && (_val)->nul) { \
			(_val)->val.int_val = -1;\
		} \
	}while(0)

static char *tls_domain_avp = NULL;
static char *sip_domain_avp = NULL;

#ifndef NO_SSL_GLOBAL_LOCK
gen_lock_t *tls_global_lock;
#endif

static int  mod_init(void);
static int  child_init(int rank);
static int  mod_load(void);
static void mod_destroy(void);
static int load_tls_mgm(struct tls_mgm_binds *binds);
static mi_response_t *tls_reload(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *tls_list(const mi_params_t *params,
								struct mi_handler *async_hdl);
static int list_domain(mi_item_t *domains_arr, struct tls_domain *d);

/* DB handler */
static db_con_t *db_hdl = 0;
/* DB functions */
static db_func_t dr_dbf;

static param_export_t params[] = {
	{ "client_tls_domain_avp",     STR_PARAM,         &tls_domain_avp        },
	{ "client_sip_domain_avp",     STR_PARAM,         &sip_domain_avp        },
	{ "server_domain", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_add_srv_domain },
	{ "client_domain", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_add_cli_domain },
	{ "match_ip_address", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_match_addr },
	{ "match_sip_domain",  STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_match_dom  },
	{ "tls_method",    STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_method     },
	{ "verify_cert",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_verify     },
	{ "require_cert",  STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_require    },
	{ "certificate",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_certificate},
	{ "private_key",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_pk         },
	{ "crl_check_all", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_crl_check  },
	{ "crl_dir",       STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_crldir     },
	{ "ca_list",       STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_calist     },
	{ "ca_dir",        STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_cadir      },
	{ "ciphers_list",  STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_cplist     },
	{ "dh_params",     STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_dhparams   },
	{ "ec_curve",      STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_eccurve    },
	{ "db_url",		STR_PARAM,  &tls_db_url.s	},
	{ "db_table",		STR_PARAM,  &tls_db_table.s	},
	{ "domain_col",		STR_PARAM,  &domain_col.s		},
	{ "match_ip_address_col",	STR_PARAM,  &match_address_col.s	},
	{ "match_sip_domain_col",	STR_PARAM,  &match_domain_col.s	},
	{ "tls_method_col",	STR_PARAM,  &method_col.s	},
	{ "verify_cert_col",	STR_PARAM,  &verify_cert_col.s	},
	{ "require_cert_col",	STR_PARAM,  &require_cert_col.s	},
	{ "certificate_col",	STR_PARAM,  &certificate_col.s	},
	{ "private_key_col",	STR_PARAM,  &pk_col.s		},
	{ "crl_check_all_col",	STR_PARAM,  &crl_check_col.s	},
	{ "crl_dir_col",	STR_PARAM,  &crl_dir_col.s	},
	{ "ca_list_col",	STR_PARAM,  &calist_col.s	},
	{ "ca_dir_col",		STR_PARAM,  &cadir_col.s	},
	{ "ciphers_list_col",	STR_PARAM,  &cplist_col.s	},
	{ "dh_params_col",	STR_PARAM,  &dhparams_col.s	},
	{ "ec_curve_col",	STR_PARAM,  &eccurve_col.s	},
	{0, 0, 0}
};

static cmd_export_t cmds[] = {
	{"is_peer_verified", (cmd_function)tls_is_peer_verified, {{0,0,0}},
		REQUEST_ROUTE},
	{"load_tls_mgm", (cmd_function)load_tls_mgm,
		{{0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported MI functions
 */
static mi_export_t mi_cmds[] = {
	{ "tls_reload", "reloads stored data from the database", 0, 0, {
		{tls_reload, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{ "tls_list", "lists all domains", 0, 0, {
		{tls_list, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

/*
 *  pseudo variables
 */
static pv_export_t mod_items[] = {
	/* TLS session parameters */
	{{"tls_version", sizeof("tls_version")-1},
		850, tlsops_version, 0,
		0, 0, 0, 0 },
	{{"tls_description", sizeof("tls_description")-1},
		850, tlsops_desc, 0,
		0, 0, 0, 0 },
	{{"tls_cipher_info", sizeof("tls_cipher_info")-1},
		850, tlsops_cipher, 0,
		0, 0, 0, 0 },
	{{"tls_cipher_bits", sizeof("tls_cipher_bits")-1},
		850,  tlsops_bits, 0,
		0, 0, 0, 0 },
	/* general certificate parameters for peer and local */
	{{"tls_peer_version", sizeof("tls_peer_version")-1},
		850, tlsops_cert_version, 0,
		0, 0, pv_init_iname, CERT_PEER  },
	{{"tls_my_version", sizeof("tls_my_version")-1},
		850, tlsops_cert_version, 0,
		0, 0, pv_init_iname, CERT_LOCAL },
	{{"tls_peer_serial", sizeof("tls_peer_serial")-1},
		850, tlsops_sn, 0,
		0, 0, pv_init_iname, CERT_PEER  },
	{{"tls_my_serial", sizeof("tls_my_serial")-1},
		850, tlsops_sn,0,
		0, 0, pv_init_iname, CERT_LOCAL },
	/* certificate parameters for peer and local, for subject and issuer*/
	{{"tls_peer_subject", sizeof("tls_peer_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT },
	{{"tls_peer_issuer", sizeof("tls_peer_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  },
	{{"tls_my_subject", sizeof("tls_my_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT },
	{{"tls_my_issuer", sizeof("tls_my_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  },
	{{"tls_peer_subject_cn", sizeof("tls_peer_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_CN },
	{{"tls_peer_issuer_cn", sizeof("tls_peer_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_CN },
	{{"tls_my_subject_cn", sizeof("tls_my_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_CN },
	{{"tls_my_issuer_cn", sizeof("tls_my_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_CN },
	{{"tls_peer_subject_locality", sizeof("tls_peer_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_L },
	{{"tls_peer_issuer_locality", sizeof("tls_peer_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_L },
	{{"tls_my_subject_locality", sizeof("tls_my_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_L },
	{{"tls_my_issuer_locality", sizeof("tls_my_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_L },
	{{"tls_peer_subject_country", sizeof("tls_peer_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_C },
	{{"tls_peer_issuer_country", sizeof("tls_peer_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_C },
	{{"tls_my_subject_country", sizeof("tls_my_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_C },
	{{"tls_my_issuer_country", sizeof("tls_my_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_C },
	{{"tls_peer_subject_state", sizeof("tls_peer_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_ST },
	{{"tls_peer_issuer_state", sizeof("tls_peer_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_ST },
	{{"tls_my_subject_state", sizeof("tls_my_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_ST },
	{{"tls_my_issuer_state", sizeof("tls_my_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_ST },
	{{"tls_peer_subject_organization", sizeof("tls_peer_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_O },
	{{"tls_peer_issuer_organization", sizeof("tls_peer_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_O },
	{{"tls_my_subject_organization", sizeof("tls_my_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_O },
	{{"tls_my_issuer_organization", sizeof("tls_my_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_O },
	{{"tls_peer_subject_unit", sizeof("tls_peer_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_OU },
	{{"tls_peer_issuer_unit", sizeof("tls_peer_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_OU },
	{{"tls_my_subject_unit", sizeof("tls_my_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_OU },
	{{"tls_my_subject_serial", sizeof("tls_my_subject_serial")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_SUBJECT_SERIAL },
	{{"tls_peer_subject_serial", sizeof("tls_peer_subject_serial")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER | CERT_SUBJECT | COMP_SUBJECT_SERIAL },
	{{"tls_my_issuer_unit", sizeof("tls_my_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_OU },
	/* subject alternative name parameters for peer and local */
	{{"tls_peer_san_email", sizeof("tls_peer_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_E },
	{{"tls_my_san_email", sizeof("tls_my_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_E },
	{{"tls_peer_san_hostname", sizeof("tls_peer_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_HOST },
	{{"tls_my_san_hostname", sizeof("tls_my_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_HOST },
	{{"tls_peer_san_uri", sizeof("tls_peer_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_URI },
	{{"tls_my_san_uri", sizeof("tls_my_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_URI },
	{{"tls_peer_san_ip", sizeof("tls_peer_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_IP },
	{{"tls_my_san_ip", sizeof("tls_my_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_IP },
	/* peer certificate validation parameters */
	{{"tls_peer_verified", sizeof("tls_peer_verified")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_VERIFIED },
	{{"tls_peer_revoked", sizeof("tls_peer_revoked")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_REVOKED },
	{{"tls_peer_expired", sizeof("tls_peer_expired")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_EXPIRED },
	{{"tls_peer_selfsigned", sizeof("tls_peer_selfsigned")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_SELFSIGNED },
	{{"tls_peer_notBefore", sizeof("tls_peer_notBefore")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, CERT_NOTBEFORE },
	{{"tls_peer_notAfter", sizeof("tls_peer_notAfter")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, CERT_NOTAFTER },

	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }

};

struct module_exports exports = {
	"tls_mgm",  /* module name*/
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	mod_load,   /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,          /* exported MI functions */
	mod_items,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	child_init, /* per-child init function */
	0           /* reload confirm function */
};

#ifndef NO_SSL_GLOBAL_LOCK
void tls_global_lock_get(void)
{
	lock_get(tls_global_lock);
}

void tls_global_lock_release(void)
{
	lock_release(tls_global_lock);
}
#endif

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
/*
 * Load and set DH params to be used in ephemeral key exchange from a file.
 */
static int
set_dh_params(SSL_CTX * ctx, char *filename)
{
	BIO *bio = BIO_new_file(filename, "r");
	if (!bio) {
		LM_ERR("unable to open dh params file '%s'\n", filename);
		return -1;
	}

	DH *dh = PEM_read_bio_DHparams(bio, 0, 0, 0);
	BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from '%s'\n", filename);
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to set dh params\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	DH_free(dh);
	LM_DBG("DH params from '%s' successfully set\n", filename);
	return 0;
}

static int set_dh_params_db(SSL_CTX * ctx, str *blob)
{
	BIO *bio;
	DH *dh;

	bio = BIO_new_mem_buf((void*)blob->s,blob->len);
	if (!bio) {
		LM_ERR("unable to create bio \n");
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, 0, 0, 0);
	BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from bio\n");
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to set dh params\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	DH_free(dh);
	LM_DBG("DH params from successfully set\n");
	return 0;
}

/*
 * Set elliptic curve.
 */
static int set_ec_params(SSL_CTX * ctx, const char* curve_name)
{
	int curve = 0;
	if (curve_name) {
		curve = OBJ_txt2nid(curve_name);
	}
	if (curve > 0) {
		EC_KEY *ecdh = EC_KEY_new_by_curve_name (curve);
		if (! ecdh) {
			LM_ERR("unable to create EC curve\n");
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_get();
		#endif
		if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh)) {
			#ifndef NO_SSL_GLOBAL_LOCK
			tls_global_lock_release();
			#endif
			LM_ERR("unable to set tmp_ecdh\n");
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		EC_KEY_free (ecdh);
	}
	else {
		LM_ERR("unable to find the EC curve\n");
		return -1;
	}
	return 0;
}
#endif

/* loads data from the db */
int load_info(struct tls_domain **serv_dom, struct tls_domain **cli_dom,
				struct tls_domain *script_srv_doms, struct tls_domain *script_cli_doms)
{
	int int_vals[NO_INT_VALS];
	char *str_vals[NO_STR_VALS];
	str blob_vals[NO_BLOB_VALS];
	int i, n;
	int no_rows = 5;
	int db_cols = NO_DB_COLS;

	/* the columns from the db table */
	db_key_t columns[NO_DB_COLS];
	/* result from a db query */
	db_res_t* res;
	/* a row from the db table */
	db_row_t* row;

	res = 0;

	columns[0] = &id_col;
	columns[1] = &domain_col;
	columns[2] = &match_address_col;
	columns[3] = &match_domain_col;
	columns[4] = &type_col;
	columns[5] = &method_col;
	columns[6] = &verify_cert_col;
	columns[7] = &require_cert_col;
	columns[8] = &certificate_col;
	columns[9] = &pk_col;
	columns[10] = &crl_check_col;
	columns[11] = &crl_dir_col;
	columns[12] = &calist_col;
	columns[13] = &cadir_col;
	columns[14] = &cplist_col;
	columns[15] = &dhparams_col;
	columns[16] = &eccurve_col;

	/* checking if the table version is up to date*/
	if (db_check_table_version(&dr_dbf, db_hdl, &tls_db_table, TLS_TABLE_VERSION) != 0)
		goto error;

	/* table to use*/
	if (dr_dbf.use_table(db_hdl, &tls_db_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", tls_db_table.len, tls_db_table.s);
		goto error;
	}

	if (DB_CAPABILITY(dr_dbf, DB_CAP_FETCH)) {

		if (dr_dbf.query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0) < 0) {
			LM_ERR("DB query failed - retrieve valid connections \n");
			goto error;
		}
		no_rows = estimate_available_rows(4 + 45 + 4 + 45 + 4 + 4 + 45 +
			45 + 4 + 45 + 45 + 4 * 4096, db_cols);
		if (no_rows == 0) no_rows = 5;
		if (dr_dbf.fetch_result(db_hdl, &res, no_rows) < 0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (dr_dbf.query(db_hdl, 0, 0, 0, columns, 0, db_cols, 0, &res) < 0) {
			LM_ERR("DB query failed - retrieve valid connections\n");
			goto error;
		}
	}

	LM_DBG("%d rows found in %.*s\n",
		RES_ROW_N(res), tls_db_table.len, tls_db_table.s);

	n = 0;
	do {
		for (i = 0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			n++;

			check_val(id_col, ROW_VALUES(row), DB_INT, 1, 0);
			int_vals[INT_VALS_ID_COL] = VAL_INT(ROW_VALUES(row));

			check_val(domain_col, ROW_VALUES(row) + 1, DB_STRING, 0, 0);
			if (VAL_NULL(ROW_VALUES(row) + 1))
				str_vals[STR_VALS_DOMAIN_COL] = 0;
			else
				str_vals[STR_VALS_DOMAIN_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 1);

			check_val(match_address_col, ROW_VALUES(row) + 2, DB_STRING, 0, 1);
			if (VAL_NULL(ROW_VALUES(row) + 2))
				str_vals[STR_VALS_MATCH_ADDRESS_COL] = 0;
			else
				str_vals[STR_VALS_MATCH_ADDRESS_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 2);

			check_val(match_domain_col, ROW_VALUES(row) + 3, DB_STRING, 0, 1);
			if (VAL_NULL(ROW_VALUES(row) + 3))
				str_vals[STR_VALS_MATCH_DOMAIN_COL] = 0;
			else
				str_vals[STR_VALS_MATCH_DOMAIN_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 3);

			check_val(type_col, ROW_VALUES(row) + 4, DB_INT, 1, 0);
			int_vals[INT_VALS_TYPE_COL] = VAL_INT(ROW_VALUES(row) + 4);

			check_val(method_col, ROW_VALUES(row) + 5, DB_STRING, 0, 0);
			str_vals[STR_VALS_METHOD_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 5);

			check_val(verify_cert_col, ROW_VALUES(row) + 6, DB_INT, 0, 0);
			int_vals[INT_VALS_VERIFY_CERT_COL] = VAL_INT(ROW_VALUES(row) + 6);

			check_val(require_cert_col, ROW_VALUES(row) + 7, DB_INT, 0, 0);
			int_vals[INT_VALS_REQUIRE_CERT_COL] = VAL_INT(ROW_VALUES(row) + 7);

			check_val(certificate_col, ROW_VALUES(row) + 8, DB_BLOB, 0, 0);
			blob_vals[BLOB_VALS_CERTIFICATE_COL] = VAL_BLOB(ROW_VALUES(row) + 8);

			check_val(pk_col, ROW_VALUES(row) + 9, DB_BLOB, 0, 0);
			blob_vals[BLOB_VALS_PK_COL] = VAL_BLOB(ROW_VALUES(row) + 9);

			check_val(crl_check_col, ROW_VALUES(row) + 10, DB_INT, 0, 0);
			int_vals[INT_VALS_CRL_CHECK_COL] = VAL_INT(ROW_VALUES(row) + 10);

			check_val(crl_dir_col, ROW_VALUES(row) + 11, DB_STRING, 0, 0);
			str_vals[STR_VALS_CRL_DIR_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 11);

			check_val(calist_col, ROW_VALUES(row) + 12, DB_BLOB, 0, 0);
			blob_vals[BLOB_VALS_CALIST_COL] = VAL_BLOB(ROW_VALUES(row) + 12);

			check_val(cadir_col, ROW_VALUES(row) + 13, DB_STRING, 0, 0);
			str_vals[STR_VALS_CADIR_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 13);

			check_val(cplist_col, ROW_VALUES(row) + 14, DB_STRING, 0, 0);
			str_vals[STR_VALS_CPLIST_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 14);

			check_val(dhparams_col, ROW_VALUES(row) + 15, DB_BLOB, 0, 0);
			blob_vals[BLOB_VALS_DHPARAMS_COL] = VAL_BLOB(ROW_VALUES(row) + 15);

			check_val(eccurve_col, ROW_VALUES(row) + 16, DB_STRING, 0, 0);
			str_vals[STR_VALS_ECCURVE_COL] = (char *) VAL_STRING(ROW_VALUES(row) + 16);

			if (db_add_domain(str_vals, int_vals, blob_vals, serv_dom, cli_dom,
								script_srv_doms, script_cli_doms) < 0) {
				if (str_vals[STR_VALS_DOMAIN_COL])
					LM_ERR("failed to add TLS domain '%s' id: %d, skipping... \n",
						str_vals[STR_VALS_DOMAIN_COL], int_vals[INT_VALS_ID_COL]);
				else
					LM_ERR("failed to add TLS domain id: %d, skipping... \n",
						int_vals[INT_VALS_ID_COL]);
			}
		}

		if (DB_CAPABILITY(dr_dbf, DB_CAP_FETCH)) {
			if (dr_dbf.fetch_result(db_hdl, &res, no_rows) < 0) {
				LM_ERR("fetching rows\n");
				goto error;
			}
		} else {
			break;
		}

	} while (RES_ROW_N(res) > 0);

	LM_DBG("%d records found in %.*s\n",
		n, tls_db_table.len, tls_db_table.s);

	dr_dbf.free_result(db_hdl, res);
	res = 0;

	return 0;
error:
	LM_ERR("Unable to load domains info from DB\n");
	return -1;
}


/* This callback is called during each verification process,
   at each step during the chain of certificates (this function
   is not the certificate_verification one!). */
int verify_callback(int pre_verify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *cert;
	int depth, err;

	depth = X509_STORE_CTX_get_error_depth(ctx);

	if (pre_verify_ok) {
		LM_NOTICE("depth = %d, verify success\n", depth);
	} else {
		LM_NOTICE("depth = %d, verify failure\n", depth);

		cert = X509_STORE_CTX_get_current_cert(ctx);
		err = X509_STORE_CTX_get_error(ctx);

		X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof buf);
		LM_NOTICE("subject = %s\n", buf);

		X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof buf);
		LM_NOTICE("issuer  = %s\n", buf);

		LM_NOTICE("verify error: %s [error=%d]\n", X509_verify_cert_error_string(err), err);
	}

	return pre_verify_ok;
}

/* This callback is called during Client Hello processing in order to
 * inspect if a servername extension is present. If the client
 * indicated which hostname is attempting to connect to, we should present
 * the appropriate certificate for that domain.
 */
int ssl_servername_cb(SSL *ssl, int *ad, void *arg)
{
	str srvname = {NULL, 0};
	struct tls_domain *dom, *new_dom;
	struct tcp_connection *c;
	str match_no_sni = str_init(MATCH_NO_SNI_VAL);
	str *match_val;

	if (!ssl || !arg) {
		LM_ERR("Bad parameters in servername callback\n");
		return SSL_TLSEXT_ERR_NOACK;
	}

	dom = (struct tls_domain *)arg;

	srvname.s = (char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!srvname.s)
		match_val = &match_no_sni;
	else {
		srvname.len = strlen(srvname.s);
		if (!srvname.len) {
			LM_ERR("Empty Servername extension in Client Hello\n");
			return SSL_TLSEXT_ERR_NOACK;
		}
		match_val = &srvname;
	}

	c = (struct tcp_connection *)SSL_get_ex_data(ssl, SSL_EX_CONN_IDX);
	if (!c) {
		LM_ERR("Failed to get tcp_connection pointer from SSL struct\n");
		return SSL_TLSEXT_ERR_NOACK;
	}
	new_dom = tls_find_domain_by_filters(&c->rcv.dst_ip, c->rcv.dst_port,
										match_val, DOM_FLAG_SRV);
	if (!new_dom) {
		LM_INFO("No domain found matching host: %.*s in servername extension\n",
			srvname.len, srvname.s);
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	} else if (new_dom && new_dom != dom) {
		/* switch SSL context to the one with the proper certificate
		 * for the indicated hostname */
		SSL_set_SSL_CTX(ssl, new_dom->ctx[process_no]);

		if (!SSL_set_ex_data(ssl, SSL_EX_DOM_IDX, new_dom)) {
			LM_ERR("Failed to store tls_domain pointer in SSL struct\n");
			tls_release_domain(dom);
			return SSL_TLSEXT_ERR_NOACK;
		}
		tls_release_domain(dom);

		LM_DBG("Switched to TLS server domain: %.*s due to SNI\n",
			new_dom->name.len, new_dom->name.s);
		return SSL_TLSEXT_ERR_OK;
	} else {
		/* the originally matched domain is the correct one */
		tls_release_domain(new_dom);
		return SSL_TLSEXT_ERR_OK;
	}
}


static void get_ssl_ctx_verify_mode(struct tls_domain *d, int *verify_mode)
{
	/* Set verification procedure
	 * The verification can be made null with SSL_VERIFY_NONE, or
	 * at least easier with SSL_VERIFY_CLIENT_ONCE instead of
	 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 * For extra control, instead of 0, we can specify a callback function:
	 *           int (*verify_callback)(int, X509_STORE_CTX *)
	 * Also, depth 2 may be not enough in some scenarios ... though no need
	 * to increase it much further */

	if (d->flags & DOM_FLAG_SRV) {
		/* Server mode:
		 * SSL_VERIFY_NONE
		 *   the server will not send a client certificate request to the
		 *   client, so the client  will not send a certificate.
		 * SSL_VERIFY_PEER
		 *   the server sends a client certificate request to the client.
		 *   The certificate returned (if any) is checked. If the verification
		 *   process fails, the TLS/SSL handshake is immediately terminated
		 *   with an alert message containing the reason for the verification
		 *   failure. The behaviour can be controlled by the additional
		 *   SSL_VERIFY_FAIL_IF_NO_PEER_CERT and SSL_VERIFY_CLIENT_ONCE flags.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   if the client did not return a certificate, the TLS/SSL handshake
		 *   is immediately terminated with a ``handshake failure'' alert.
		 *   This flag must be used together with SSL_VERIFY_PEER.
		 * SSL_VERIFY_CLIENT_ONCE
		 *   only request a client certificate on the initial TLS/SSL
		 *   handshake. Do not ask for a client certificate again in case of
		 *   a renegotiation. This flag must be used together with
		 *   SSL_VERIFY_PEER.
		 */

		if( d->verify_cert ) {
			*verify_mode = SSL_VERIFY_PEER;
			if( d->require_client_cert ) {
				LM_INFO("client verification activated. Client "
						"certificates are mandatory.\n");
				*verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else
				LM_INFO("client verification activated. Client "
						"certificates are NOT mandatory.\n");
		} else {
			*verify_mode = SSL_VERIFY_NONE;
			LM_INFO("client verification NOT activated. Weaker security.\n");
		}
	} else {
		/* Client mode:
		 * SSL_VERIFY_NONE
		 *   if not using an anonymous cipher (by default disabled), the
		 *   server will send a certificate which will be checked. The result
		 *   of the certificate verification process can be checked after the
		 *   TLS/SSL handshake using the SSL_get_verify_result(3) function.
		 *   The handshake will be continued regardless of the verification
		 *   result.
		 * SSL_VERIFY_PEER
		 *   the server certificate is verified. If the verification process
		 *   fails, the TLS/SSL handshake is immediately terminated with an
		 *   alert message containing the reason for the verification failure.
		 *   If no server certificate is sent, because an anonymous cipher is
		 *   used, SSL_VERIFY_PEER is ignored.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   ignored
		 * SSL_VERIFY_CLIENT_ONCE
		 *   ignored
		 */

		if( d->verify_cert ) {
			*verify_mode = SSL_VERIFY_PEER;
			LM_INFO("server verification activated.\n");
		} else {
			*verify_mode = SSL_VERIFY_NONE;
			LM_INFO("server verification NOT activated. Weaker security.\n");
		}
	}
}

/*
 * load a certificate from a file
 * (certificate file can be a chain, starting by the user cert,
 * and ending in the root CA; if not all needed certs are in this
 * file, they are looked up in the caFile or caPATH (see verify
 * function).
 */
static int load_certificate(SSL_CTX * ctx, char *filename)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (!SSL_CTX_use_certificate_chain_file(ctx, filename)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		tls_print_errstack();
		LM_ERR("unable to load certificate file '%s'\n",
				filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	LM_DBG("'%s' successfully loaded\n", filename);
	return 0;
}

static int load_certificate_db(SSL_CTX * ctx, str *blob)
{
	X509 *cert = NULL;
	BIO *cbio;

	cbio = BIO_new_mem_buf((void*)blob->s,blob->len);
	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
	if (!cert) {
		LM_ERR("Unable to load certificate from buffer\n");
		BIO_free(cbio);
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (! SSL_CTX_use_certificate(ctx, cert)) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("Unable to use certificate\n");
		X509_free(cert);
		BIO_free(cbio);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif
	tls_dump_cert_info("Certificate loaded: ", cert);
	X509_free(cert);

	while ((cert = PEM_read_bio_X509(cbio, NULL, 0, NULL)) != NULL) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_get();
		#endif
		if (!SSL_CTX_add_extra_chain_cert(ctx, cert)){
			tls_print_errstack();
			#ifndef NO_SSL_GLOBAL_LOCK
			tls_global_lock_release();
			#endif
			tls_dump_cert_info("Unable to add chain cert: ", cert);
			X509_free(cert);
			BIO_free(cbio);
			return -1;
		}
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		/* The x509 certificate provided to SSL_CTX_add_extra_chain_cert()
		*	will be freed by the library when the SSL_CTX is destroyed.
		*	An application should not free the x509 object.a*/
		tls_dump_cert_info("Chain certificate loaded: ", cert);
	}

	BIO_free(cbio);
	LM_DBG("Successfully loaded\n");
	return 0;
}

static int load_crl(SSL_CTX * ctx, char *crl_directory, int crl_check_all)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	DIR *d;
	struct dirent *dir;
	int crl_added = 0;
	LM_DBG("Loading CRL from directory\n");

	/*Get X509 store from SSL context*/
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	if(!store) {
		LM_ERR("Unable to get X509 store from ssl context\n");
		return -1;
	}

	/*Parse directory*/
	d = opendir(crl_directory);
	if(!d) {
		LM_ERR("Unable to open crl directory '%s'\n", crl_directory);
		return -1;
	}

	while ((dir = readdir(d)) != NULL) {
		/*Skip if not regular file*/
		if (dir->d_type != DT_REG)
			continue;

		/*Create filename*/
		char* filename = (char*) pkg_malloc(sizeof(char)*(strlen(crl_directory)+strlen(dir->d_name)+2));
		if (!filename) {
			LM_ERR("Unable to allocate crl filename\n");
			closedir(d);
			return -1;
		}
		strcpy(filename,crl_directory);
		if(filename[strlen(filename)-1] != '/')
			strcat(filename,"/");
		strcat(filename,dir->d_name);

		/*Get CRL content*/
		FILE *fp = fopen(filename,"r");
		pkg_free(filename);
		if(!fp)
			continue;

		X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
		fclose(fp);
		if(!crl)
			continue;

		/*Add CRL to X509 store*/
		if (X509_STORE_add_crl(store, crl) == 1)
			crl_added++;
		else
			LM_ERR("Unable to add crl to ssl context\n");

		X509_CRL_free(crl);
	}
	closedir(d);

	if (!crl_added) {
		LM_ERR("No suitable CRL files found in directory %s\n", crl_directory);
		return 0;
	}

	/*Enable CRL checking*/
	X509_VERIFY_PARAM *param;
	param = X509_VERIFY_PARAM_new();

	int flags =  X509_V_FLAG_CRL_CHECK;
	if(crl_check_all)
		flags |= X509_V_FLAG_CRL_CHECK_ALL;

	X509_VERIFY_PARAM_set_flags(param, flags);

	SSL_CTX_set1_param(ctx, param);
	X509_VERIFY_PARAM_free(param);

	return 0;
#else
	static int already_warned = 0;
	if (!already_warned) {
		LM_WARN("CRL not supported in %s\n", OPENSSL_VERSION_TEXT);
		already_warned = 1;
	}
	return 0;
#endif
}

/*
 * Load a caList, to be used to verify the client's certificate.
 * The list is to be stored in a single file, containing all
 * the acceptable root certificates.
 */
static int load_ca(SSL_CTX * ctx, char *filename)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (!SSL_CTX_load_verify_locations(ctx, filename, 0)) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to load ca '%s'\n", filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	LM_DBG("CA '%s' successfully loaded\n", filename);
	return 0;
}

static int load_ca_db(SSL_CTX * ctx, str *blob)
{
	X509_STORE *store;
	X509 *cert = NULL;
	BIO *cbio;

	cbio = BIO_new_mem_buf((void*)blob->s,blob->len);

	if (!cbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	store =  SSL_CTX_get_cert_store(ctx);
	if(!store) {
		BIO_free(cbio);
		LM_ERR("Unable to get X509 store from ssl context\n");
		return -1;
	}

	while ((cert = PEM_read_bio_X509_AUX(cbio, NULL, 0, NULL)) != NULL) {
		tls_dump_cert_info("CA loaded: ", cert);
		if (!X509_STORE_add_cert(store, cert)){
			tls_dump_cert_info("Unable to add ca: ", cert);
			X509_free(cert);
			BIO_free(cbio);
			return -1;
		}
		X509_free(cert);
	}

	BIO_free(cbio);
	LM_DBG("CA successfully loaded\n");
	return 0;
}

/*
 * Load a caList from a directory instead of a single file.
 */
static int load_ca_dir(SSL_CTX * ctx, char *directory)
{
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	if (!SSL_CTX_load_verify_locations(ctx, 0 , directory)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to load ca directory '%s'\n", directory);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	LM_DBG("CA '%s' successfully loaded from directory\n", directory);
	return 0;
}

static int passwd_cb(char *buf, int size, int rwflag, void *filename)
{
	UI             *ui;
	const char     *prompt;

	ui = UI_new();
	if (ui == NULL)
		goto err;

	prompt = UI_construct_prompt(ui, "passphrase", filename);
	UI_add_input_string(ui, prompt, 0, buf, 0, size - 1);
	UI_process(ui);
	UI_free(ui);
	return strlen(buf);

err:
	LM_ERR("passwd_cb failed\n");
	if (ui)
		UI_free(ui);
	return 0;
}


/*
 * load a private key from a file
 */
static int load_private_key(SSL_CTX * ctx, char *filename)
{
#define NUM_RETRIES 3
	int idx, ret_pwd;

	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, filename);

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	for(idx = 0, ret_pwd = 0; idx < NUM_RETRIES; idx++ ) {
		ret_pwd = SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM);
		if ( ret_pwd ) {
			break;
		} else {
			LM_ERR("unable to load private key file '%s'. \n"
					"Retry (%d left) (check password case)\n",
					filename, (NUM_RETRIES - idx -1) );
			continue;
		}
	}

	if( ! ret_pwd ) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to load private key file '%s'\n",
				filename);
		return -1;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("key '%s' does not match the public key of the certificate\n",
				filename);
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	LM_DBG("key '%s' successfully loaded\n", filename);
	return 0;
}

static int load_private_key_db(SSL_CTX * ctx, str *blob)
{
#define NUM_RETRIES 3
	int idx;
	BIO *kbio;
	EVP_PKEY *key;

	kbio = BIO_new_mem_buf((void*)blob->s, blob->len);

	if (!kbio) {
		LM_ERR("Unable to create BIO buf\n");
		return -1;
	}

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_get();
	#endif
	for(idx = 0; idx < NUM_RETRIES; idx++ ) {
		key = PEM_read_bio_PrivateKey(kbio,NULL, passwd_cb, "database");
		if ( key ) {
			break;
		} else {
			LM_ERR("unable to load private key. \n"
				   "Retry (%d left) (check password case)\n",  (NUM_RETRIES - idx -1) );
			continue;
		}
	}

	BIO_free(kbio);
	if(!key) {
		tls_print_errstack();
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		LM_ERR("unable to load private key from buffer\n");
		return -1;
	}

	if (!SSL_CTX_use_PrivateKey(ctx, key)) {
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		EVP_PKEY_free(key);
		LM_ERR("key does not match the public key of the certificate\n");
		return -1;
	}
	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock_release();
	#endif

	EVP_PKEY_free(key);
	LM_DBG("key successfully loaded\n");
	return 0;
}

static void destroy_tls_dom(struct tls_domain *d)
{
	int i;
	if (d->ctx) {
		for (i = 0; i < d->ctx_no; i++)
			if (d->ctx[i])
				SSL_CTX_free(d->ctx[i]);
		shm_free(d->ctx);
	}
	lock_destroy(d->lock);
	lock_dealloc(d->lock);
	shm_free(d);
}

static int init_tls_dom(struct tls_domain *d)
{
	int cert_from_file = 0;
	int ca_from_file = 0;
	int verify_mode = 0;
	unsigned i, tcp_procs;
	char *ciphers_list = NULL;
#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
	int dh_from_file = 0;
#endif

	LM_INFO("Processing TLS domain '%.*s'\n",
			d->name.len, ZSW(d->name.s));

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
	/*
	 * set dh params
	 */
	if (!d->dh_param.s) {
		dh_from_file = 1;
		LM_DBG("no DH params file for tls domain '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_tmp_dh_file);
		d->dh_param.s = tls_tmp_dh_file;
		d->dh_param.len = len(tls_tmp_dh_file);
	}
	if (!d->tls_ec_curve)
		LM_NOTICE("No EC curve defined\n");
#else
	if (d->tmp_dh_file  || tls_tmp_dh_file)
		LM_INFO("DH params file discarded as not supported by your "
			"openSSL version\n");
	if (d->tls_ec_curve)
		LM_INFO("EC params file discarded as not supported by your "
			"openSSL version\n");
#endif

	if( d->ciphers_list != 0 ) {
		ciphers_list = d->ciphers_list;
		LM_NOTICE("setting cipher list to %s\n", ciphers_list);
	} else {
		LM_DBG( "cipher list null ... setting default\n");
	}

	get_ssl_ctx_verify_mode(d, &verify_mode);

	/*
	 * set method
	 */
	if (d->method == TLS_METHOD_UNSPEC) {
		LM_DBG("no method for tls domain '%.*s', using default\n",
				d->name.len, ZSW(d->name.s));
		d->method = tls_default_method;
		d->method_max = tls_default_method;
	}

	if (!d->cert.s) {
		cert_from_file = 1;
		LM_NOTICE("no certificate for tls domain '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_cert_file);
		d->cert.s = tls_cert_file;
		d->cert.len = len(tls_cert_file);
	}

	if (!d->ca.s) {
		ca_from_file = 1;
		LM_NOTICE("no CA list for tls domain '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_ca_file);
		d->ca.s = tls_ca_file;
		d->ca.len = len(tls_ca_file);
	}

	/*
	 * load ca from directory
	 */
	if (!d->ca_directory) {
		LM_NOTICE("no CA dir for tls '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_ca_dir);
		d->ca_directory = tls_ca_dir;
	}

	if (!d->crl_directory)
		LM_NOTICE("no crl for tls, using none\n");

	tcp_procs = count_child_processes();

	d->ctx = shm_malloc(tcp_procs * sizeof(SSL_CTX *));
	if (!d->ctx) {
		LM_ERR("cannot allocate ssl ctx per process!\n");
		return 0;
	}
	memset(d->ctx, 0, tcp_procs * sizeof(SSL_CTX *));

	d->ctx_no = tcp_procs;

	for (i = 0; i < tcp_procs; i++) {
		/*
		 * create context
		 */
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_get();
		#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		d->ctx[i] = SSL_CTX_new(TLS_method());
#else
		d->ctx[i] = SSL_CTX_new(ssl_methods[d->method - 1]);
#endif
		#ifndef NO_SSL_GLOBAL_LOCK
		tls_global_lock_release();
		#endif
		if (d->ctx[i] == NULL) {
			LM_ERR("cannot create ssl context for tls domain '%.*s'\n",
				d->name.len, ZSW(d->name.s));
			return -1;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (d->method != TLS_USE_SSLv23) {
			if (!SSL_CTX_set_min_proto_version(d->ctx[i],
					ssl_versions[d->method - 1]) ||
				!SSL_CTX_set_max_proto_version(d->ctx[i],
					ssl_versions[d->method_max - 1])) {
				LM_ERR("cannot enforce ssl version for tls domain '%.*s'\n",
						d->name.len, ZSW(d->name.s));
				return -1;
			}
		}
#endif

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
		if (!(d->flags & DOM_FLAG_DB) || dh_from_file) {
			if (d->dh_param.s && set_dh_params(d->ctx[i], d->dh_param.s) < 0)
				return -1;
		} else {
			set_dh_params_db(d->ctx[i], &d->dh_param);
		}
		if (d->tls_ec_curve && set_ec_params(d->ctx[i], d->tls_ec_curve) < 0)
			return -1;
#endif

		if (ciphers_list != 0 && SSL_CTX_set_cipher_list(d->ctx[i], d->ciphers_list) == 0 ) {
			LM_ERR("failure to set SSL context "
					"cipher list '%s'\n", d->ciphers_list);
			return -1;
		}

		/* Set a bunch of options:
		 *     do not accept SSLv2 / SSLv3
		 *     no session resumption
		 *     choose cipher according to server's preference's*/

		SSL_CTX_set_options(d->ctx[i],
				SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
				SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
				SSL_OP_CIPHER_SERVER_PREFERENCE);


		SSL_CTX_set_verify(d->ctx[i], verify_mode, verify_callback);
		SSL_CTX_set_verify_depth(d->ctx[i], VERIFY_DEPTH_S);

		//SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER );
		SSL_CTX_set_session_cache_mode(d->ctx[i], SSL_SESS_CACHE_OFF );
		SSL_CTX_set_session_id_context(d->ctx[i], (unsigned char*)OS_SSL_SESS_ID,
				OS_SSL_SESS_ID_LEN );

		/* install callback for SNI */
		if (d->flags & DOM_FLAG_SRV) {
			SSL_CTX_set_tlsext_servername_callback(d->ctx[i], ssl_servername_cb);
			SSL_CTX_set_tlsext_servername_arg(d->ctx[i], d);
		}

		/*
		 * load certificate
		 */
		if (!(d->flags & DOM_FLAG_DB) || cert_from_file) {
			if (load_certificate(d->ctx[i], d->cert.s) < 0)
				return -1;
		} else
			if (load_certificate_db(d->ctx[i], &d->cert) < 0)
				return -1;

		/**
		 * load crl from directory
		 */
		if (d->crl_directory && load_crl(d->ctx[i], d->crl_directory, d->crl_check_all) < 0)
			return -1;

		/*
		 * load ca
		 */
		if (!(d->flags & DOM_FLAG_DB) || ca_from_file) {
			if (d->ca.s && load_ca(d->ctx[i], d->ca.s) < 0)
				return -1;
		} else {
			if (load_ca_db(d->ctx[i], &d->ca) < 0)
				return -1;
		}

		if (d->ca_directory && load_ca_dir(d->ctx[i], d->ca_directory) < 0)
			return -1;
	}

	return 0;
}

/*
 * initialize tls virtual domains
 */
static int init_tls_domains(struct tls_domain **dom)
{
	struct tls_domain *d, *tmp, *prev = NULL;
	int from_file = 0;
	int rc;
	int i;
	int db = 0;

	d = *dom;
	while (d) {
		if (init_tls_dom(d) < 0) {
			db = d->flags & DOM_FLAG_DB;
			if (!db)
				LM_ERR("Failed to init TLS domain '%.*s'\n", d->name.len, ZSW(d->name.s));
			else
				LM_WARN("Failed to init TLS domain '%.*s', skipping...\n",
					d->name.len, ZSW(d->name.s));

			if (d == *dom)
				*dom = d->next;

			if (prev)
				prev->next = d->next;

			tmp = d;
			d = d->next;
			destroy_tls_dom(tmp);

			if (!db)
				return -1;
		} else {
			prev = d;
			d = d->next;
		}
	}

	/*
	 * load all private keys as the last step (may prompt for password)
	 */
	d = *dom;
	prev = NULL;
	while (d) {
		if (!d->pkey.s) {
			LM_NOTICE("no private key for tls domain '%.*s' defined, using default '%s'\n",
					d->name.len, ZSW(d->name.s), tls_pkey_file);
			d->pkey.s = tls_pkey_file;
			d->pkey.len = len(tls_pkey_file);
			from_file = 1;
		}

		rc = 0;
		for (i = 0; i < d->ctx_no; i++) {
			if (!(d->flags & DOM_FLAG_DB) || from_file)
				rc = load_private_key(d->ctx[i], d->pkey.s);
			else
				rc = load_private_key_db(d->ctx[i], &d->pkey);
			if (rc < 0)
				break;
		}

		if (rc < 0) {
			db = d->flags & DOM_FLAG_DB;
			if (!db)
				LM_ERR("Failed to init TLS domain '%.*s'\n", d->name.len, ZSW(d->name.s));
			else
				LM_WARN("Failed to init TLS domain '%.*s', skipping...\n",
					d->name.len, ZSW(d->name.s));

			if (d == *dom)
				*dom = d->next;

			if (prev)
				prev->next = d->next;

			tmp = d;
			d = d->next;
			destroy_tls_dom(tmp);

			if (!db)
				return -1;
		} else {
			prev = d;
			d = d->next;
		}
	}

	return 0;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int check_for_krb(void)
{
	SSL_CTX *xx;

	int j;

	xx = SSL_CTX_new(ssl_methods[tls_default_method - 1]);
	if (xx==NULL)
		return -1;

	for( j=0 ; j<sk_SSL_CIPHER_num(xx->cipher_list) ; j++) {
		SSL_CIPHER *yy = sk_SSL_CIPHER_value(xx->cipher_list,j);
		if ( yy->id>=SSL3_CK_KRB5_DES_64_CBC_SHA &&
			yy->id<=SSL3_CK_KRB5_RC4_40_MD5 ) {
			LM_INFO("KRB5 cipher %s found\n", yy->name);
			SSL_CTX_free(xx);
			return 1;
		}
	}

	SSL_CTX_free(xx);
	return 0;
}
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int tls_static_locks_no=0;
static gen_lock_set_t* tls_static_locks=NULL;

static void tls_static_locks_ops(int mode, int n, const char* file, int line)
{
	if (n<0 || n>tls_static_locks_no) {
		LM_ERR("BUG - SSL Lib attempting to acquire bogus lock\n");
		abort();
	}

	if (mode & CRYPTO_LOCK) {
		lock_set_get(tls_static_locks,n);
	} else {
		lock_set_release(tls_static_locks,n);
	}
}



static int tls_init_multithread(void)
{
	/* init static locks support */
	tls_static_locks_no = CRYPTO_num_locks();

	if (tls_static_locks_no>0) {
		/* init a lock set & pass locking function to SSL */
		tls_static_locks = lock_set_alloc(tls_static_locks_no);
		if (tls_static_locks == NULL) {
			LM_ERR("Failed to alloc static locks\n");
			return -1;
		}
		if (lock_set_init(tls_static_locks)==0) {
				LM_ERR("Failed to init static locks\n");
				lock_set_dealloc(tls_static_locks);
				return -1;
		}
		CRYPTO_set_locking_callback(tls_static_locks_ops);
	}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
	CRYPTO_set_id_callback(tls_get_id);
#else /* between 1.0.0 and 1.1.0 */
	CRYPTO_THREADID_set_callback(tls_get_thread_id);
#endif /* OPENSSL_VERSION_NUMBER */

	/* dynamic locks support*/
	CRYPTO_set_dynlock_create_callback(tls_dyn_lock_create);
	CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_ops);
	CRYPTO_set_dynlock_destroy_callback(tls_dyn_lock_destroy);

	return 0;
}
#endif

/*
 * initialize ssl methods
 */
static void
init_ssl_methods(void)
{

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ssl_methods[TLS_USE_TLSv1-1] = (SSL_METHOD*)TLSv1_method();
	ssl_methods[TLS_USE_SSLv23-1] = (SSL_METHOD*)SSLv23_method();

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	ssl_methods[TLS_USE_TLSv1_2-1] = (SSL_METHOD*)TLSv1_2_method();
#endif
#else
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	ssl_versions[TLS_USE_TLSv1_3-1] = TLS1_3_VERSION;
#endif
	ssl_versions[TLS_USE_TLSv1_2-1] = TLS1_2_VERSION;
	ssl_versions[TLS_USE_TLSv1-1] = TLS1_VERSION;
#endif
}

static struct {
	char *name;
	char *alias;
	enum tls_method method;
} ssl_versions_struct[] = {
	{ "SSLv23",  "TLSany", TLS_USE_SSLv23  },
	{ "TLSv1",   NULL,     TLS_USE_TLSv1   },
	{ "TLSv1_2", NULL,     TLS_USE_TLSv1_2 },
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	{ "TLSv1_3", NULL,     TLS_USE_TLSv1_3 },
#endif
};

#define SSL_VERSIONS_SIZE (sizeof(ssl_versions_struct)/sizeof(ssl_versions_struct[0]))

#define MATCH(name, field) ((field) && strncasecmp(field, (name)->s, (name)->len) == 0)


static inline char *get_ssl_method_name(enum tls_method method)
{
	if (method < 1 || method > SSL_VERSIONS_SIZE)
		return "UNKNOWN";
	return ssl_versions_struct[method-1].name;
}

enum tls_method get_ssl_min_method(void)
{
	return ssl_versions_struct[1].method;  // skip SSLv23/TLSany
}

enum tls_method get_ssl_max_method(void)
{
	return ssl_versions_struct[SSL_VERSIONS_SIZE-1].method;
}

int parse_ssl_method(str *name)
{
	int index;
	for (index = 0; index < SSL_VERSIONS_SIZE; index++)
		if (MATCH(name, ssl_versions_struct[index].name) || MATCH(name, ssl_versions_struct[index].alias))
			return ssl_versions_struct[index].method;
	return -1;
}

int tls_get_method(str *method_str,
	enum tls_method *method, enum tls_method *method_max)
{
	str val = *method_str;
	str val_max;
	int m;
	char *s;

	/* search for a '-' to denote an interval */
	s = q_memchr(val.s, '-', val.len);
	if (s) {
		val_max.s = s + 1;
		val_max.len = val.len - (s - val.s) - 1;
		val.len = s - val.s;
		trim(&val_max);
	}
	trim(&val);
	if (val.len == 0)
		m = get_ssl_min_method();
	else
		m = parse_ssl_method(&val);
	if (m < 0) {
		LM_ERR("unsupported method [%s]\n",val.s);
		return -1;
	}

	*method = m;

	if (s) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (m == TLS_USE_SSLv23)
			LM_WARN("Using SSLv23/TLSany as the lower value for the method range makes no sense\n");

		if (val_max.len == 0)
			m = get_ssl_max_method();
		else
			m = parse_ssl_method(&val_max);
		if (m < 0) {
			LM_ERR("unsupported method [%s]\n",val_max.s);
			return -1;
		}

		if (m == TLS_USE_SSLv23)
			LM_WARN("Using SSLv23/TLSany as the higher value for the method range makes no sense\n");
#else
		LM_WARN("TLS method range not supported for versions lower than 1.1.0\n");
#endif
	}

	*method_max = m;

	return 0;
}

/* reloads data from the db */
static int reload_data(void)
{
	struct tls_domain *tls_client_domains_tmp = NULL;
	struct tls_domain *tls_server_domains_tmp = NULL;
	struct tls_domain *script_cli_doms, *script_srv_doms, *dom;

	script_srv_doms = find_first_script_dom(*tls_server_domains);
	script_cli_doms = find_first_script_dom(*tls_client_domains);

	/* load new domains from db */
	if (load_info(&tls_server_domains_tmp, &tls_client_domains_tmp,
					script_srv_doms, script_cli_doms) < 0)
		return -1;

	/*
	 * initialize new domains
	 */
	init_tls_domains(&tls_server_domains_tmp);
	init_tls_domains(&tls_client_domains_tmp);

	lock_start_write(dom_lock);

	tls_free_db_domains(*tls_server_domains);

	/* link the new DB domains with the existing script domains */
	if (script_srv_doms) {
		for (dom = tls_server_domains_tmp; dom; dom = dom->next)
			if (!dom->next)
				break;
		if (dom)
			dom->next = script_srv_doms;
	}

	if (tls_server_domains_tmp)
		*tls_server_domains = tls_server_domains_tmp;
	else
		*tls_server_domains = script_srv_doms;

	tls_free_db_domains(*tls_client_domains);

	if (script_cli_doms) {
		for (dom = tls_client_domains_tmp; dom; dom = dom->next)
			if (!dom->next)
				break;
		if (dom)
			dom->next = script_cli_doms;
	}

	if (tls_client_domains_tmp)
		*tls_client_domains = tls_client_domains_tmp;
	else
		*tls_client_domains = script_cli_doms;

	for (dom = *tls_server_domains; dom; dom = dom->next)
		if (update_matching_map(dom) < 0) {
			LM_ERR("Unable to update domain matching map\n");
			return -1;
		}
	for (dom = *tls_client_domains; dom; dom = dom->next)
		if (update_matching_map(dom) < 0) {
			LM_ERR("Unable to update domain matching map\n");
			return -1;
		}

	/* sort arrays of domain filters in order to be able to select the
	 * most specific domain first in case of definitions with wildcard patterns */
	if (*tls_server_domains)
		sort_map_dom_arrays(server_dom_matching);
	if (*tls_client_domains)
		sort_map_dom_arrays(client_dom_matching);

	lock_stop_write(dom_lock);

	return 0;
}

/* reloads data from the db */
static mi_response_t *tls_reload(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	LM_INFO("reload data MI command received!\n");

	if (!tls_db_url.s)
		return init_mi_error(500, MI_SSTR("DB url not set"));

	if (reload_data() < 0) {
		LM_ERR("failed to load tls data\n");
		return init_mi_error(500, MI_SSTR("Failed to reload"));
	}

	return init_mi_result_ok();
}

#ifdef __OPENSSL_ON_EXIT
/* This is used to exit _without_ running the remaining onexit callbacks,
 * we do this because openssl 1.1.x does not properly support multi-process
 * applications, and it tries to release an existing connection from each
 * process, resulting in multiple frees of the same chunk.
 *
 * We are sure that this callback is called _before_ the openssl onexit()
 * because glibc guarantees that the callbacks are called in the reversed
 * order they are armed, and since we are only registering this function in
 * the child init code, we are the last ones that register it.
 */
static void openssl_on_exit(int status, void *param)
{
	_exit(status);
}
#endif


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define SSL_LOCK_REENTRANT(_cmd) \
	do { \
		int __ssl_lock_unlock; \
		if (ssl_lock_pid != process_no) { \
			lock_get(ssl_lock); \
			ssl_lock_pid = process_no; \
			__ssl_lock_unlock = 1; \
		} else { \
			__ssl_lock_unlock = 0; \
		} \
		_cmd; \
		if (__ssl_lock_unlock) { \
			ssl_lock_pid = -1; \
			lock_release(ssl_lock); \
		} \
	} while (0)

static gen_lock_t *ssl_lock;
static int ssl_lock_pid = -1;
static const RAND_METHOD *os_ssl_method;

static int os_ssl_seed(const void *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->seed)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->seed(buf, num));
	return ret;
}

static int os_ssl_bytes(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->bytes)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->bytes(buf, num));
	return ret;
}

static void os_ssl_cleanup(void)
{
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->cleanup)
		return;
	SSL_LOCK_REENTRANT(os_ssl_method->cleanup());
}

static int os_ssl_add(const void *buf, int num, double entropy)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->add)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->add(buf, num, entropy));
	return ret;
}

static int os_ssl_pseudorand(unsigned char *buf, int num)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->pseudorand)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->pseudorand(buf, num));
	return ret;
}

static int os_ssl_status(void)
{
	int ret;
	if (!os_ssl_method || !ssl_lock || !os_ssl_method->status)
		return 0;
	SSL_LOCK_REENTRANT(ret = os_ssl_method->status());
	return ret;
}

static RAND_METHOD opensips_ssl_method = {
	os_ssl_seed,
	os_ssl_bytes,
	os_ssl_cleanup,
	os_ssl_add,
	os_ssl_pseudorand,
	os_ssl_status
};
#endif

static int mod_load(void)
{
	/*
	 * this has to be called before any function calling CRYPTO_malloc,
	 * CRYPTO_malloc will set allow_customize in openssl to 0
	 */

	LM_INFO("openssl version: %s\n", SSLeay_version(SSLEAY_VERSION));
	if (!CRYPTO_set_mem_functions(os_malloc, os_realloc, os_free)) {
		LM_ERR("unable to set the memory allocation functions\n");
		LM_ERR("NOTE: please make sure you are loading tls_mgm module at the"
			"very beginning of your script, before any other module!\n");
		return -1;
	}

	return 0;
}


static int mod_init(void) {
	str s;
	str tls_db_param = str_init(DB_TLS_DOMAIN_PARAM_EQ);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	int n;
#endif
	struct tls_domain *tls_client_domains_tmp = NULL;
	struct tls_domain *tls_server_domains_tmp = NULL;
	struct tls_domain *dom;

	LM_INFO("initializing TLS management\n");

	if (tls_db_url.s) {

		/* create & init lock */
		if ((dom_lock = lock_init_rw()) == NULL) {
			LM_CRIT("failed to init lock\n");
			return -1;
		}

		init_db_url(tls_db_url, 0 /*cannot be null*/);

		if (str_strstr(&tls_db_url, &tls_db_param)) {
			/* this would cause a circular dependency between the DB module and tls_mgm */
			LM_CRIT("Cannot use a TLS connection to DB for the tls_mgm module itself\n");
			return -1;
		}

		tls_db_table.len = strlen(tls_db_table.s);

		if (tls_db_table.len == 0) {
			LM_ERR("db table not specified\n");
			return -1;
		}

		id_col.len = strlen(id_col.s);
		domain_col.len = strlen(domain_col.s);
		match_address_col.len = strlen(match_address_col.s);
		match_domain_col.len = strlen(match_domain_col.s);
		type_col.len = strlen(type_col.s);
		method_col.len = strlen(method_col.s);
		verify_cert_col.len = strlen(verify_cert_col.s);
		require_cert_col.len = strlen(require_cert_col.s);
		certificate_col.len = strlen(certificate_col.s);
		pk_col.len = strlen(pk_col.s);
		crl_check_col.len = strlen(crl_check_col.s);
		calist_col.len = strlen(calist_col.s);
		cadir_col.len = strlen(cadir_col.s);
		cplist_col.len = strlen(cplist_col.s);
		dhparams_col.len = strlen(dhparams_col.s);
		eccurve_col.len = strlen(eccurve_col.s);

		if (db_bind_mod(&tls_db_url, &dr_dbf)) {
			LM_CRIT("cannot bind to database module! "
				"Did you forget to load a database module ?\n");
			return -1;
		}
		/* init DB connection */
		if ((db_hdl = dr_dbf.init(&tls_db_url)) == 0) {
			LM_CRIT("cannot initialize database connection\n");
			return -1;
		}

		if (dr_dbf.use_table(db_hdl, &tls_db_table) < 0) {
			LM_ERR("cannot select table \"%.*s\"\n",
				tls_db_table.len, tls_db_table.s);
			return -1;
		}
	}

	if (tls_server_domains == NULL) {
		tls_server_domains = shm_malloc(sizeof *tls_server_domains);
		if (!tls_server_domains) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_server_domains = NULL;
	}

	if (tls_client_domains == NULL) {
		tls_client_domains = shm_malloc(sizeof *tls_client_domains);
		if (!tls_client_domains) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_client_domains = NULL;
	}

	server_dom_matching = map_create(AVLMAP_SHARED);
	if (!server_dom_matching) {
		LM_ERR("No more shm memory!\n");
		return -1;
	}
	client_dom_matching = map_create(AVLMAP_SHARED);
	if (!client_dom_matching) {
		LM_ERR("No more shm memory!\n");
		return -1;
	}

	if (tls_domain_avp) {
		s.s = tls_domain_avp;
		s.len = strlen(s.s);
		if (parse_avp_spec( &s, &tls_client_domain_avp)) {
			LM_ERR("cannot parse client_tls_domain_avp\n");
			return -1;
		}
	}

	if (sip_domain_avp) {
		s.s = sip_domain_avp;
		s.len = strlen(s.s);
		if (parse_avp_spec(&s, &sip_client_domain_avp)) {
			LM_ERR("cannot parse client_sip_domain_avp\n");
			return -1;
		}
	}

#if !defined(OPENSSL_NO_COMP)
	STACK_OF(SSL_COMP)* comp_methods;
	/* disabling compression */
	LM_INFO("disabling compression due ZLIB problems\n");
	comp_methods = SSL_COMP_get_compression_methods();
	if (comp_methods==0) {
		LM_INFO("openssl compression already disabled\n");
	} else {
		sk_SSL_COMP_zero(comp_methods);
	}
#endif
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	if (tls_init_multithread() < 0) {
		LM_ERR("failed to init multi-threading support\n");
		return -1;
	}
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	SSL_library_init();
	SSL_load_error_strings();
#else
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT
#if (OPENSSL_VERSION_NUMBER >= 0x1010102fL)
			|OPENSSL_INIT_NO_ATEXIT
#endif
			, NULL);
#endif

	#ifndef NO_SSL_GLOBAL_LOCK
	tls_global_lock = lock_alloc();
	if (!tls_global_lock || !lock_init(tls_global_lock)) {
		LM_ERR("could not initialize global openssl lock!\n");
		return -1;
	}
	#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	ssl_lock = lock_alloc();
	if (!ssl_lock || !lock_init(ssl_lock)) {
		LM_ERR("could not initialize ssl lock!\n");
		return -1;
	}
	os_ssl_method = RAND_get_rand_method();
	if (!os_ssl_method) {
		LM_ERR("could not get the default ssl rand method!\n");
		return -1;
	}
	RAND_set_rand_method(&opensips_ssl_method);
#endif

	init_ssl_methods();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	n = check_for_krb();
	if (n==-1) {
		LM_ERR("kerberos check failed\n");
		return -1;
	}

	if ( ( n ^
#ifndef OPENSSL_NO_KRB5
			1
#else
			0
#endif
		 )!=0 ) {
		LM_ERR("compiled agaist an openssl with %s"
				"kerberos, but run with one with %skerberos\n",
				(n!=1)?"":"no ",(n!=1)?"no ":"");
		return -1;
	}
#endif

	if (tls_db_url.s) {
		if (load_info(&tls_server_domains_tmp, &tls_client_domains_tmp,
						*tls_server_domains, *tls_client_domains))
			return -1;

		dr_dbf.close(db_hdl);
		db_hdl = NULL;

		/* link the DB domains with the existing script domains */

		if (*tls_server_domains && tls_server_domains_tmp) {
			for (dom = tls_server_domains_tmp; dom; dom = dom->next)
				if (!dom->next)
					break;
			dom->next = *tls_server_domains;
		}
		if (tls_server_domains_tmp)
			*tls_server_domains = tls_server_domains_tmp;

		if (*tls_client_domains && tls_client_domains_tmp) {
			for (dom = tls_client_domains_tmp; dom; dom = dom->next)
				if (!dom->next)
					break;
			dom->next = *tls_client_domains;
		}
		if (tls_client_domains_tmp)
			*tls_client_domains = tls_client_domains_tmp;
	}

	for (dom = *tls_server_domains; dom; dom = dom->next) {
		/* for script defined domains, if match_address/domain parameters
		 * are not defined, match any value */
		s.s = NULL;
		if (!dom->match_domains && parse_match_domains(dom, &s) < 0) {
			LM_ERR("Failed to parse domain matching filters for domain [%.*s]\n",
				dom->name.len, dom->name.s);
			return -1;
		}
		if (!dom->match_addresses && parse_match_addresses(dom, &s) < 0) {
			LM_ERR("Failed to parse address matching filters for domain [%.*s]\n",
				dom->name.len, dom->name.s);
			return -1;
		}

		if (update_matching_map(dom) < 0) {
			LM_ERR("Unable to update domain matching map\n");
			return -1;
		}
	}

	for (dom = *tls_client_domains; dom; dom = dom->next) {
		/* for script defined domains, if match_address/domain parameters
		 * are not defined, match any value */
		s.s = NULL;
		if (!dom->match_domains && parse_match_domains(dom, &s) < 0) {
			LM_ERR("Failed to parse domain matching filters for domain [%.*s]\n",
				dom->name.len, dom->name.s);
			return -1;
		}
		if (!dom->match_addresses && parse_match_addresses(dom, &s) < 0) {
			LM_ERR("Failed to parse address matching filters for domain [%.*s]\n",
				dom->name.len, dom->name.s);
			return -1;
		}

		if (update_matching_map(dom) < 0) {
			LM_ERR("Unable to update domain matching map\n");
			return -1;
		}
	}

	/* sort arrays of domain filters in order to be able to select the
	 * most specific domain first in case of definitions with wildcard patterns */
	if (*tls_server_domains)
		sort_map_dom_arrays(server_dom_matching);
	if (*tls_client_domains)
		sort_map_dom_arrays(client_dom_matching);

	/* initialize tls virtual domains */
	if (init_tls_domains(tls_server_domains) < 0)
		return -1;
	if (init_tls_domains(tls_client_domains) < 0)
		return -1;

#ifdef __OPENSSL_ON_EXIT
	on_exit(openssl_on_exit, NULL);
#endif

	return 0;
}

static int child_init(int rank)
{
	if (!tls_db_url.s || !(rank >= 1 || rank == PROC_MODULE))
		return 0;

	/* init DB connection */
	if (!(db_hdl = dr_dbf.init(&tls_db_url))) {
		LM_CRIT("failed to initialize database connection\n");
		return -1;
	}

	return 0;
}

static void mod_destroy(void)
{
	struct tls_domain *d, *d_tmp;

	if (dom_lock)
		lock_destroy_rw(dom_lock);

	d = *tls_server_domains;
	while (d) {
		d_tmp = d;
		d = d->next;
		tls_free_domain(d_tmp);
	}
	d = *tls_client_domains;
	while (d) {
		d_tmp = d;
		d = d->next;
		tls_free_domain(d_tmp);
	}

	shm_free(tls_server_domains);
	shm_free(tls_client_domains);

	map_destroy(server_dom_matching, map_free_node);
	map_destroy(client_dom_matching, map_free_node);

	#ifndef NO_SSL_GLOBAL_LOCK
	lock_destroy(tls_global_lock);
	lock_dealloc(tls_global_lock);
	#endif

	/* TODO - destroy static locks */

	/* library destroy */
	ERR_free_strings();
	/*SSL_free_comp_methods(); - this function is not on std. openssl*/
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return;
}

static int list_domain(mi_item_t *domains_arr, struct tls_domain *d)
{
	mi_item_t *domain_item, *addrf_arr, *domf_arr;
	str_list *filt;
	char *method;

	while (d) {
		domain_item = add_mi_object(domains_arr, NULL, 0);
		if (!domain_item)
			goto error;

		if (add_mi_string(domain_item, MI_SSTR("name"),
			d->name.s, d->name.len) < 0)
			goto error;

		if (d->flags & DOM_FLAG_SRV) {
			if (add_mi_string(domain_item, MI_SSTR("type"),
				MI_SSTR("TLS_DOMAIN_SRV")) < 0)
				goto error;
		} else
			if (add_mi_string(domain_item, MI_SSTR("type"),
				MI_SSTR("TLS_DOMAIN_CLI")) < 0)
				goto error;

		addrf_arr = add_mi_array(domain_item, MI_SSTR("IP ADDRESS FILTERS"));
		if (!addrf_arr)
			goto error;

		for (filt = d->match_addresses; filt; filt = filt->next)
			if (add_mi_string(addrf_arr, 0, 0, filt->s.s, filt->s.len) < 0)
				goto error;

		domf_arr = add_mi_array(domain_item, MI_SSTR("SIP DOMAIN FILTERS"));
		if (!domf_arr)
			goto error;

		for (filt = d->match_domains; filt; filt = filt->next)
			if (add_mi_string(domf_arr, 0, 0, filt->s.s, filt->s.len) < 0)
				goto error;

		if (d->method == d->method_max) {
			method = get_ssl_method_name(d->method);
			if (add_mi_string(domain_item, MI_SSTR("METHOD"),
					method, strlen(method)) < 0)
						goto error;
		} else {
			if (add_mi_string_fmt(domain_item, MI_SSTR("METHOD"),
					"%s-%s", get_ssl_method_name(d->method), get_ssl_method_name(d->method_max)) < 0)
						goto error;
		}

		if (add_mi_bool(domain_item, MI_SSTR("VERIFY_CERT"), d->verify_cert) < 0)
			goto error;

		if (add_mi_bool(domain_item, MI_SSTR("REQ_CLI_CERT"), d->require_client_cert) < 0)
			goto error;

		if (add_mi_bool(domain_item, MI_SSTR("CRL_CHECKALL"), d->crl_check_all) < 0)
			goto error;

		if (!(d->flags & DOM_FLAG_DB))
			if (add_mi_string(domain_item, MI_SSTR("CERT_FILE"),
				d->cert.s, d->cert.len) < 0)
				goto error;

		if (add_mi_string(domain_item, MI_SSTR("CRL_DIR"),
			d->crl_directory, len(d->crl_directory)) < 0)
			goto error;

		if (!(d->flags & DOM_FLAG_DB))
			if (add_mi_string(domain_item, MI_SSTR("CA_FILE"),
				d->ca.s, d->ca.len) < 0)
				goto error;

		if (add_mi_string(domain_item, MI_SSTR("CA_DIR"),
			d->ca_directory, len(d->ca_directory)) < 0)
			goto error;

		if (!(d->flags & DOM_FLAG_DB))
			if (add_mi_string(domain_item, MI_SSTR("PKEY_FILE"),
				d->pkey.s, d->pkey.len) < 0)
				goto error;

		if (add_mi_string(domain_item, MI_SSTR("CIPHER_LIST"),
			d->ciphers_list, len(d->ciphers_list)) < 0)
			goto error;

		if (!(d->flags & DOM_FLAG_DB))
			if (add_mi_string(domain_item, MI_SSTR("DH_PARAMS_FILE"),
				d->dh_param.s, d->dh_param.len) < 0)
				goto error;

		if (add_mi_string(domain_item, MI_SSTR("EC_CURVE"),
			d->tls_ec_curve, len(d->tls_ec_curve)) < 0)
			goto error;

		d = d->next;
	}

	return 0;

error:
	LM_ERR("Failed to add mi item\n");
	return -1;
}

/* lists all domains */
static mi_response_t *tls_list(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj, *domains_arr;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (dom_lock)
		lock_start_read(dom_lock);

	domains_arr = add_mi_array(resp_obj, MI_SSTR("Domains"));
	if (!domains_arr)
		goto error;

	if (list_domain(domains_arr, *tls_client_domains) < 0)
		goto error;

	if (list_domain(domains_arr, *tls_server_domains) < 0)
		goto error;

	if (dom_lock)
		lock_stop_read(dom_lock);

	return resp;

error:
	if (dom_lock)
		lock_stop_read(dom_lock);
	free_mi_response(resp);
	return NULL;
}

static int load_tls_mgm(struct tls_mgm_binds *binds)
{
	binds->find_server_domain = tls_find_server_domain;
	binds->find_client_domain = tls_find_client_domain;
	binds->find_client_domain_name = tls_find_client_domain_name;
	binds->release_domain = tls_release_domain;
	#ifndef NO_SSL_GLOBAL_LOCK
	binds->global_lock_get = tls_global_lock_get;
	binds->global_lock_release = tls_global_lock_release;
	#endif
	return 1;
}

