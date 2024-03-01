/*
 * Copyright (C) 2008-2024 OpenSIPS Solutions
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 *
 */



#ifndef _DB_OPS_IMPL_H_
#define _DB_OPS_IMPL_H_

#include "../../str.h"
#include "../../usr_avp.h"
#include "../../pvar.h"
#include "../../re.h"
#include "../../parser/msg_parser.h"

#include "dbops_db.h"



/* flags used inside avps */
/* IMPORTANT: flagss 0-4 are reserved by core; 8-15 by script */
#define AVP_IS_IN_DB    (1<<7)

/* DB flags */
#define AVPOPS_DB_NAME_INT   (1<<1)
#define AVPOPS_DB_VAL_INT    (1<<0)

/* operand flags */
#define AVPOPS_VAL_NONE      (1<<0)
#define AVPOPS_VAL_INT       (1<<1)
#define AVPOPS_VAL_STR       (1<<2)
#define AVPOPS_VAL_PVAR      (1<<3)

/* flags for operation flags    24..31 */
#define AVPOPS_FLAG_USER0    (1<<24)
#define AVPOPS_FLAG_DOMAIN0  (1<<25)
#define AVPOPS_FLAG_URI0     (1<<26)
#define AVPOPS_FLAG_UUID0    (1<<27)

/* container structer for Flag+Int_Spec_value parameter */
struct fis_param
{
	int     ops;       /* operation flags */
	int     opd;       /* operand flags */
	int     type;
	union {
		pv_spec_t sval;    /* values int or str */
		int n;
		str s;
	} u;
};

struct db_param
{
	struct fis_param a;        /* attribute */
	str              sa;       /* attribute as str (for db queries) */
	str              table;    /* DB table/scheme name */
	struct db_scheme *scheme;  /* DB scheme */
};

typedef struct _query_async_param
{
	pvname_list_t *output_avps;
	db_con_t      *hdl;
	db_func_t     *dbf;
	void		  *db_param;
	int one_row;
} query_async_param;

void init_store_avps(str **db_columns);

int ops_db_avp_load (struct sip_msg* msg, struct fis_param *sp,
		struct db_param *dbp,  struct db_url *url, int use_domain, str *prefix);

int ops_db_avp_delete(struct sip_msg* msg, struct fis_param *sp,
		struct db_param *dbp,  struct db_url *url, int use_domain);

int ops_db_avp_store(struct sip_msg* msg, struct fis_param *sp,
		struct db_param *dbp,  struct db_url *url, int use_domain);

int ops_db_query(struct sip_msg* msg, str* query,
		struct db_url *url, pvname_list_t* dest, int one_row);

int ops_async_db_query(struct sip_msg* msg, async_ctx *ctx,
		str *query, struct db_url *url, pvname_list_t *dest, int one_row);

int resume_async_dbquery(int fd, struct sip_msg *msg, void *_param);
int timeout_async_dbquery(int fd, struct sip_msg *msg, void *_param);

#endif

