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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

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

#include "../tls_openssl/openssl_api.h"
#include "../tls_wolfssl/wolfssl_api.h"

#include "../../net/proto_tcp/tcp_common_defs.h"
#include "tls_config.h"
#include "tls_domain.h"
#include "tls_params.h"
#include "tls_select.h"
#include "api.h"

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

struct openssl_binds openssl_api;
struct wolfssl_binds wolfssl_api;

enum os_tls_library tls_library;

static char *tls_domain_avp = NULL;
static char *sip_domain_avp = NULL;

static int  mod_init(void);
static int  child_init(int rank);
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
	{ "tls_library",	STR_PARAM,  &tls_library_param.s },
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
		0, 0, pv_init_iname, VAR_CERT_PEER  },
	{{"tls_my_version", sizeof("tls_my_version")-1},
		850, tlsops_cert_version, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL },
	{{"tls_peer_serial", sizeof("tls_peer_serial")-1},
		850, tlsops_sn, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  },
	{{"tls_my_serial", sizeof("tls_my_serial")-1},
		850, tlsops_sn,0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL },
	/* certificate parameters for peer and local, for subject and issuer*/
	{{"tls_peer_subject", sizeof("tls_peer_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT },
	{{"tls_peer_issuer", sizeof("tls_peer_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  },
	{{"tls_my_subject", sizeof("tls_my_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT },
	{{"tls_my_issuer", sizeof("tls_my_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  },
	{{"tls_peer_subject_cn", sizeof("tls_peer_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_CN },
	{{"tls_peer_issuer_cn", sizeof("tls_peer_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_CN },
	{{"tls_my_subject_cn", sizeof("tls_my_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_CN },
	{{"tls_my_issuer_cn", sizeof("tls_my_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_CN },
	{{"tls_peer_subject_locality", sizeof("tls_peer_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_L },
	{{"tls_peer_issuer_locality", sizeof("tls_peer_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_L },
	{{"tls_my_subject_locality", sizeof("tls_my_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_L },
	{{"tls_my_issuer_locality", sizeof("tls_my_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_L },
	{{"tls_peer_subject_country", sizeof("tls_peer_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_C },
	{{"tls_peer_issuer_country", sizeof("tls_peer_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_C },
	{{"tls_my_subject_country", sizeof("tls_my_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_C },
	{{"tls_my_issuer_country", sizeof("tls_my_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_C },
	{{"tls_peer_subject_state", sizeof("tls_peer_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_ST },
	{{"tls_peer_issuer_state", sizeof("tls_peer_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_ST },
	{{"tls_my_subject_state", sizeof("tls_my_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_ST },
	{{"tls_my_issuer_state", sizeof("tls_my_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_ST },
	{{"tls_peer_subject_organization", sizeof("tls_peer_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_O },
	{{"tls_peer_issuer_organization", sizeof("tls_peer_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_O },
	{{"tls_my_subject_organization", sizeof("tls_my_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_O },
	{{"tls_my_issuer_organization", sizeof("tls_my_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_O },
	{{"tls_peer_subject_unit", sizeof("tls_peer_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_SUBJECT | VAR_COMP_OU },
	{{"tls_peer_issuer_unit", sizeof("tls_peer_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_CERT_ISSUER  | VAR_COMP_OU },
	{{"tls_my_subject_unit", sizeof("tls_my_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_OU },
	{{"tls_my_subject_serial", sizeof("tls_my_subject_serial")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_SUBJECT | VAR_COMP_SUBJECT_SERIAL },
	{{"tls_peer_subject_serial", sizeof("tls_peer_subject_serial")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER | VAR_CERT_SUBJECT | VAR_COMP_SUBJECT_SERIAL },
	{{"tls_my_issuer_unit", sizeof("tls_my_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_CERT_ISSUER  | VAR_COMP_OU },
	/* subject alternative name parameters for peer and local */
	{{"tls_peer_san_email", sizeof("tls_peer_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_COMP_E },
	{{"tls_my_san_email", sizeof("tls_my_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_COMP_E },
	{{"tls_peer_san_hostname", sizeof("tls_peer_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_COMP_HOST },
	{{"tls_my_san_hostname", sizeof("tls_my_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_COMP_HOST },
	{{"tls_peer_san_uri", sizeof("tls_peer_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_COMP_URI },
	{{"tls_my_san_uri", sizeof("tls_my_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_COMP_URI },
	{{"tls_peer_san_ip", sizeof("tls_peer_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_PEER  | VAR_COMP_IP },
	{{"tls_my_san_ip", sizeof("tls_my_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, VAR_CERT_LOCAL | VAR_COMP_IP },
	/* peer certificate validation parameters */
	{{"tls_peer_verified", sizeof("tls_peer_verified")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, VAR_CERT_VERIFIED },
	{{"tls_peer_revoked", sizeof("tls_peer_revoked")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, VAR_CERT_REVOKED },
	{{"tls_peer_expired", sizeof("tls_peer_expired")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, VAR_CERT_EXPIRED },
	{{"tls_peer_selfsigned", sizeof("tls_peer_selfsigned")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, VAR_CERT_SELFSIGNED },
	{{"tls_peer_notBefore", sizeof("tls_peer_notBefore")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, VAR_CERT_NOTBEFORE },
	{{"tls_peer_notAfter", sizeof("tls_peer_notAfter")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, VAR_CERT_NOTAFTER },

	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }

};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tls_openssl", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "tls_wolfssl", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"tls_mgm",  /* module name*/
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,          /* load function */
	&deps,       /* OpenSIPS module dependencies */
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

int tls_sni_cb(struct tls_domain *dom, struct tcp_connection *c,
	void *ssl_ctx, char *servername)
{
	str srvname = {NULL, 0};
	struct tls_domain *new_dom;
	str match_no_sni = str_init(MATCH_NO_SNI_VAL);
	str *match_val;
	int rc;

	srvname.s = servername;
	if (!srvname.s)
		match_val = &match_no_sni;
	else {
		srvname.len = strlen(servername);
		match_val = &srvname;
	}

	new_dom = tls_find_domain_by_filters(&c->rcv.dst_ip, c->rcv.dst_port,
										match_val, DOM_FLAG_SRV);
	if (!new_dom) {
		LM_INFO("No domain found matching host: %.*s in servername extension\n",
			srvname.len, srvname.s);
		return -2;
	} else if (new_dom && new_dom != dom) {
		/* switch SSL context to the one with the proper certificate
		 * for the indicated hostname */
		if (tls_library == TLS_LIB_OPENSSL) {
			rc = openssl_api.switch_ssl_ctx(new_dom, ssl_ctx);
		} else if (tls_library == TLS_LIB_WOLFSSL) {
			rc = wolfssl_api.switch_ssl_ctx(new_dom, ssl_ctx);
		} else {
			LM_CRIT("No TLS library module loaded\n");
			tls_release_domain(dom);
			return -1;
		}
		if (rc < 0) {
			tls_release_domain(dom);
			return -1;
		}

		tls_release_domain(dom);

		LM_DBG("Switched to TLS server domain: %.*s due to SNI\n",
			new_dom->name.len, new_dom->name.s);
		return 0;
	} else {
		/* the originally matched domain is the correct one */
		tls_release_domain(new_dom);
		return 0;
	}
}

void destroy_tls_dom(struct tls_domain *d)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.destroy_tls_dom(d);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.destroy_tls_dom(d);

	lock_destroy(d->lock);
	lock_dealloc(d->lock);
	shm_free(d);
}

static int init_tls_dom(struct tls_domain *d)
{
	int init_flags = 0;

	LM_INFO("Processing TLS domain '%.*s'\n",
			d->name.len, ZSW(d->name.s));

	if (!d->dh_param.s) {
		init_flags |= TLS_DOM_DH_FILE_FL;
		LM_DBG("no DH params file for tls domain '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_tmp_dh_file);
		d->dh_param.s = tls_tmp_dh_file;
		d->dh_param.len = len(tls_tmp_dh_file);
	}

	if( d->ciphers_list != 0 )
		LM_NOTICE("setting cipher list to %s\n", d->ciphers_list);
	else
		LM_DBG( "cipher list null ... setting default\n");

	/*
	 * set method
	 */
	if (!d->method_str.s) {
		LM_DBG("no method for tls domain '%.*s', using default\n",
				d->name.len, ZSW(d->name.s));
		d->method = tls_default_method;
		d->method_max = tls_default_method;
	}

	if (!d->cert.s) {
		init_flags |= TLS_DOM_CERT_FILE_FL;
		LM_NOTICE("no certificate for tls domain '%.*s' defined, using default '%s'\n",
				d->name.len, ZSW(d->name.s), tls_cert_file);
		d->cert.s = tls_cert_file;
		d->cert.len = len(tls_cert_file);
	}

	if (!d->ca.s) {
		init_flags |= TLS_DOM_CA_FILE_FL;
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

	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.init_tls_dom(d, init_flags);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.init_tls_dom(d, init_flags);
	else
		return 0;
}

/*
 * initialize tls virtual domains
 */
static int init_tls_domains(struct tls_domain **dom)
{
	struct tls_domain *d, *tmp, *prev = NULL;
	int from_file = 0;
	int db = 0;
	int rc;

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

		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.load_priv_key(d, from_file);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.load_priv_key(d, from_file);
		else {
			prev = d;
			d = d->next;
			continue;
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

static struct {
	char *name;
	enum tls_method method;
} ssl_versions_struct[] = {
	{ "SSLv23",  TLS_USE_SSLv23  },
	{ "TLSv1",   TLS_USE_TLSv1   },
	{ "TLSv1_2", TLS_USE_TLSv1_2 },
	{ "TLSv1_3", TLS_USE_TLSv1_3 },
};

#define SSL_VERSIONS_SIZE (sizeof(ssl_versions_struct)/sizeof(ssl_versions_struct[0]))

static inline char *get_ssl_method_name(enum tls_method method)
{
	if (method < 1 || method > SSL_VERSIONS_SIZE)
		return "UNKNOWN";
	return ssl_versions_struct[method-1].name;
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

static int load_tls_library(void)
{
	int wolfssl_loaded, openssl_loaded;

	tls_library = TLS_LIB_NONE;

	openssl_loaded = module_loaded("tls_openssl");
	wolfssl_loaded = module_loaded("tls_wolfssl");

	tls_library_param.len = strlen(tls_library_param.s);

	if (!str_strcmp(&tls_library_param, _str(TLS_LIB_AUTO_STR))) {
		if (openssl_loaded)
			tls_library = TLS_LIB_OPENSSL;

		if (wolfssl_loaded) {
			if (openssl_loaded) {
				LM_ERR("Multiple TLS library modules loaded\n");
				return -1;
			}

			tls_library = TLS_LIB_WOLFSSL;	
		}

		if (tls_library == TLS_LIB_NONE) {
			LM_ERR("No TLS library module loaded\n");
			return -1;
		}
	} else if (!str_strcmp(&tls_library_param, _str(TLS_LIB_NONE_STR))) {
		LM_INFO("No TLS library configured\n");
	} else if (!str_strcmp(&tls_library_param, _str(TLS_LIB_OPENSSL_STR))) {
		if (!openssl_loaded) {
			LM_ERR("Configured to use openssl library but 'tls_openssl' "
				"module not loaded!\n");
			return -1;
		}

		tls_library = TLS_LIB_OPENSSL;
	} else if (!str_strcmp(&tls_library_param, _str(TLS_LIB_WOLFSSL_STR))) {
		if (!wolfssl_loaded) {
			LM_ERR("Configured to use wolfSSL library but 'tls_wolfssl' "
				"module not loaded!\n");
			return -1;
		}

		tls_library = TLS_LIB_WOLFSSL;
	} else {
		LM_ERR("Bad value for tls_library module parameter\n");
		return -1;
	}

	if (tls_library == TLS_LIB_OPENSSL) {
		if (load_tls_openssl_api(&openssl_api)) {
			LM_DBG("Failed to load openssl API\n");
			return -1;
		}

		openssl_api.reg_tls_sni_cb(tls_sni_cb);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		if (load_tls_wolfssl_api(&wolfssl_api)) {
			LM_DBG("Failed to load wolfSSL API\n");
			return -1;
		}

		wolfssl_api.reg_tls_sni_cb(tls_sni_cb);
	}

	return 0;
}

static int mod_init(void) {
	str s;
	str tls_db_param = str_init(DB_TLS_DOMAIN_PARAM_EQ);
	struct tls_domain *tls_client_domains_tmp = NULL;
	struct tls_domain *tls_server_domains_tmp = NULL;
	struct tls_domain *dom;

	LM_INFO("initializing TLS management\n");

	if (load_tls_library() < 0)
		return -1;

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

int tls_conn_init(struct tcp_connection *c, struct tls_domain *tls_dom)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_conn_init(c, tls_dom);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_conn_init(c, tls_dom);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

void tls_conn_clean(struct tcp_connection* c, struct tls_domain **tls_dom)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_conn_clean(c, tls_dom);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_conn_clean(c, tls_dom);
	else
		LM_CRIT("No TLS library module loaded\n");
}

int tls_update_fd(struct tcp_connection* c, int fd)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_update_fd(c, fd);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_update_fd(c, fd);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_async_connect(struct tcp_connection *con, int fd,
    int timeout, trace_dest t_dst)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_async_connect(con, fd, timeout, t_dst);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_async_connect(con, fd, timeout, t_dst);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_write(struct tcp_connection *c, int fd, const void *buf,
    size_t len, short *poll_events)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_write(c, fd, buf, len, poll_events);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_write(c, fd, buf, len, poll_events);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_blocking_write(struct tcp_connection *c, int fd,
    const char *buf, size_t len, int handshake_timeout, int send_timeout,
    trace_dest t_dst)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_blocking_write(c, fd, buf, len,
			handshake_timeout, send_timeout, t_dst);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_blocking_write(c, fd, buf, len,
			handshake_timeout, send_timeout, t_dst);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_fix_read_conn(struct tcp_connection *c, int fd,
    int async_timeout, trace_dest t_dst, int lock)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_fix_read_conn(c, fd, async_timeout, t_dst, lock);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_fix_read_conn(c, fd, async_timeout, t_dst, lock);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_read(struct tcp_connection * c,struct tcp_req *r)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_read(c, r);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_read(c, r);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int tls_conn_extra_match(struct tcp_connection *c, void *id)
{
	if (tls_library == TLS_LIB_OPENSSL)
		return openssl_api.tls_conn_extra_match(c, id);
	else if (tls_library == TLS_LIB_WOLFSSL)
		return wolfssl_api.tls_conn_extra_match(c, id);
	else {
		LM_CRIT("No TLS library module loaded\n");
		return -1;
	}
}

int get_tls_library_used(void)
{
	return tls_library;
}

static int load_tls_mgm(struct tls_mgm_binds *binds)
{
	binds->find_server_domain = tls_find_server_domain;
	binds->find_client_domain = tls_find_client_domain;
	binds->find_client_domain_name = tls_find_client_domain_name;
	binds->release_domain = tls_release_domain;

	binds->tls_conn_init = tls_conn_init;
	binds->tls_conn_clean = tls_conn_clean;
	binds->tls_update_fd = tls_update_fd;
	binds->tls_async_connect = tls_async_connect;
	binds->tls_write = tls_write;
	binds->tls_blocking_write = tls_blocking_write;
	binds->tls_fix_read_conn = tls_fix_read_conn;
	binds->tls_read = tls_read;
	binds->tls_conn_extra_match = tls_conn_extra_match;

	binds->get_tls_library_used = get_tls_library_used;

	return 1;
}
