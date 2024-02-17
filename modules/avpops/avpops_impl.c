/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2004-10-04  first version (ramona)
 *  2005-01-30  "fm" (fast match) operator added (ramona)
 *  2005-01-30  avp_copy (copy/move operation) added (ramona)
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <fnmatch.h>

#include "../../ut.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "../../action.h"
#include "../../ip_addr.h"
#include "../../config.h"
#include "../../dset.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../pvar.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../mem/mem.h"
#include "avpops_impl.h"
#include "avpops_db.h"


#define avpops_str2int_str(a, b) \
	do { \
		if(a.s==0) \
			b.n = a.len; \
		else \
			b.s = a; \
	} while(0)


static db_key_t  store_keys[6];
static db_val_t  store_vals[6];
static str      empty={"",0};

void init_store_avps(str **db_columns)
{
	/* unique user id */
	store_keys[0] = db_columns[0]; /*uuid*/
	store_vals[0].type = DB_STR;
	store_vals[0].nul  = 0;
	/* attribute */
	store_keys[1] = db_columns[1]; /*attribute*/
	store_vals[1].type = DB_STR;
	store_vals[1].nul  = 0;
	/* value */
	store_keys[2] = db_columns[2]; /*value*/
	store_vals[2].type = DB_STR;
	store_vals[2].nul  = 0;
	/* type */
	store_keys[3] = db_columns[3]; /*type*/
	store_vals[3].type = DB_INT;
	store_vals[3].nul  = 0;
	/* user name */
	store_keys[4] = db_columns[4]; /*username*/
	store_vals[4].type = DB_STR;
	store_vals[4].nul  = 0;
	/* domain */
	store_keys[5] = db_columns[5]; /*domain*/
	store_vals[5].type = DB_STR;
	store_vals[5].nul  = 0;
}

#define AVPOPS_ATTR_LEN	64
static char avpops_attr_buf[AVPOPS_ATTR_LEN];

/* value 0 - attr value
 * value 1 - attr name
 * value 2 - attr type
 */
static int dbrow2avp(struct db_row *row, struct db_param *dbp, int attr,
					int attr_type, int just_val_flags, str *prefix)
{
	unsigned int uint;
	int  db_flags;
	str  atmp;
	str  vtmp;
	int avp_attr;
	int_str avp_val;
	int flags;

	flags = dbp->a.opd;

	if (just_val_flags==-1)
	{
		/* check for null fields into the row */
		if (row->values[0].nul || row->values[1].nul || row->values[2].nul )
		{
			LM_ERR("dbrow contains NULL fields\n");
			return -1;
		}

		/* check the value types */
		if ( (row->values[0].type!=DB_STRING && row->values[0].type!=DB_STR)
			||  (row->values[1].type!=DB_STRING && row->values[1].type!=DB_STR)
			|| row->values[2].type!=DB_INT )
		{
			LM_ERR("wrong field types in dbrow\n");
			return -1;
		}

		/* check the content of flag field */
		uint = (unsigned int)row->values[2].val.int_val;
		db_flags = ((uint&AVPOPS_DB_NAME_INT)?0:AVP_NAME_STR) |
			((uint&AVPOPS_DB_VAL_INT)?0:AVP_VAL_STR);
	} else {
		/* check the validity of value column */
		if (row->values[0].nul || (row->values[0].type!=DB_STRING &&
		row->values[0].type!=DB_STR && row->values[0].type!=DB_INT) )
		{
			LM_ERR("empty or wrong type for 'value' using scheme\n");
			return -1;
		}
		db_flags = just_val_flags;
	}

	/* is the avp name already known? */
	if ( (flags&AVPOPS_VAL_NONE)==0 )
	{
		/* use the name  */
		avp_attr = attr;
		db_flags |= attr_type;
	} else {
		/* take the name from db response */
		if (row->values[1].type==DB_STRING)
		{
			atmp.s = (char*)row->values[1].val.string_val;
			atmp.len = strlen(atmp.s);
		} else {
			atmp = row->values[1].val.str_val;
		}

		if (prefix)
		{
			if (atmp.len + prefix->len > AVPOPS_ATTR_LEN)
			{
				LM_ERR("name too long [%d/%.*s...]\n",
								prefix->len + atmp.len, 16, prefix->s);
				return -1;
			}

			memcpy(avpops_attr_buf, prefix->s, prefix->len);
			memcpy(avpops_attr_buf + prefix->len, atmp.s, atmp.len);
			atmp.s = avpops_attr_buf;
			atmp.len += prefix->len;
		}

		/* there is always a name here - get the ID */
		avp_attr = get_avp_id(&atmp);
		if (avp_attr < 0)
			return -2;
	}

	/* now get the value as correct type */
	if (row->values[0].type==DB_STRING)
	{
		vtmp.s = (char*)row->values[0].val.string_val;
		vtmp.len = strlen(vtmp.s);
	} else if (row->values[0].type==DB_STR){
		vtmp = row->values[0].val.str_val;
	} else {
		vtmp.s = 0;
		vtmp.len = 0;
	}
	if (db_flags&AVP_VAL_STR) {
		/* value must be saved as string */
		if (row->values[0].type==DB_INT) {
			vtmp.s = int2str( (unsigned long)row->values[0].val.int_val,
				&vtmp.len);
		}
		avp_val.s = vtmp;
	} else {
		/* value must be saved as integer */
		if (row->values[0].type!=DB_INT) {
			if (vtmp.len==0 || vtmp.s==0 || str2int(&vtmp, &uint)==-1) {
				LM_ERR("value is not int as flags say <%s>\n", vtmp.s);
				return -1;
			}
			avp_val.n = (int)uint;
		} else {
			avp_val.n = row->values[0].val.int_val;
		}
	}

	/* added the avp */
	db_flags |= AVP_IS_IN_DB;
	/* set script flags */
	db_flags |= dbp->a.u.sval.pvp.pvn.u.isname.type&0xff00;
	return add_avp( (unsigned short)db_flags, avp_attr, avp_val);
}


static inline void int_str2db_val( int_str is_val, str *val, int is_s)
{
	if (is_s)
	{
		/* val is string */
		*val = is_val.s;
	} else {
		/* val is integer */
		val->s =
			int2str((unsigned long)is_val.n, &val->len);
	}
}


int ops_dbload_avps (struct sip_msg* msg, struct fis_param *sp,
		struct db_param *dbp, struct db_url *url, int use_domain, str *prefix)
{
	struct sip_uri   uri;
	db_res_t         *res = NULL;
	str              uuid;
	int  i, n, sh_flg;
	str *s0, *s1, *s2;
	int avp_name;
	int avp_type = 0;
	pv_value_t xvalue;

	s0 = s1 = s2 = NULL;
	if (!((sp->opd&AVPOPS_VAL_PVAR)||(sp->opd&AVPOPS_VAL_STR))) {
		LM_CRIT("invalid flag combination (%d/%d)\n", sp->opd, sp->ops);
		goto error;
	}

	/* get uuid from avp */
	if (sp->opd&AVPOPS_VAL_PVAR)
	{
		if(pv_get_spec_value(msg, &(sp->u.sval), &xvalue)!=0)
		{
			LM_CRIT("failed to get PVAR value (%d/%d)\n", sp->opd, sp->ops);
			goto error;
		}
		if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
		{
			LM_ERR("no value for first param\n");
			goto error;
		}
		uuid = xvalue.rs;
	} else {
		uuid.s   = sp->u.s.s;
		uuid.len = sp->u.s.len;
	}

	if(sp->opd&AVPOPS_FLAG_UUID0)
	{
		s0 = &uuid;
	} else {
		/* parse uri */
		if (parse_uri(uuid.s, uuid.len, &uri)<0)
		{
			LM_ERR("failed to parse uri\n");
			goto error;
		}

                if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_USER0))
                {
			/* check that uri contains user part */
			if(!uri.user.s|| !uri.user.len)
			{
				LM_ERR("incomplet uri <%.*s> missing user\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s1 = &uri.user;
			}
                }
		if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_DOMAIN0))
		{
			/* check that uri contains host part */
			if(!uri.host.len|| !uri.host.s)
			{
				LM_ERR("incomplet uri <%.*s> missing host\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s2 = &uri.host;
			}
		}
	}

	/* is dynamic avp name ? */
	if(dbp->a.type==AVPOPS_VAL_PVAR)
	{
		if(pv_has_dname(&(dbp->a.u.sval)))
		{
			if(pv_get_spec_name(msg, &(dbp->a.u.sval.pvp), &xvalue)!=0)
			{
				LM_CRIT("failed to get value for P2\n");
				goto error;
			}
			if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
			{
				LM_ERR("no value for p2\n");
				goto error;
			}
			if(xvalue.flags&PV_VAL_STR)
			{
				if(xvalue.rs.len>=AVPOPS_ATTR_LEN)
				{
					LM_ERR("name too long [%d/%.*s...]\n",
						xvalue.rs.len, 16, xvalue.rs.s);
					goto error;
				}
				dbp->sa.s = avpops_attr_buf;
				memcpy(dbp->sa.s, xvalue.rs.s, xvalue.rs.len);
				dbp->sa.len = xvalue.rs.len;
				dbp->sa.s[dbp->sa.len] = '\0';
			} else {
				LM_INFO("no string value for p2\n");
				goto error;
			}
		}
	}

	/* do DB query */
	res = db_load_avp( url, s0, s1,
			((use_domain)||(sp->opd&AVPOPS_FLAG_DOMAIN0))?s2:0,
			dbp->sa.s, &dbp->table, dbp->scheme);

	/* res query ?  */
	if (res==0)
	{
		LM_ERR("db_load failed\n");
		goto error;
	}

	sh_flg = (dbp->scheme)?dbp->scheme->db_flags:-1;

	/* validate row */
	avp_name = -1;
	if(dbp->a.type==AVPOPS_VAL_PVAR)
	{
		if(pv_has_dname(&dbp->a.u.sval))
		{
			if(xvalue.flags&PV_TYPE_INT)
			{
				avp_name = xvalue.ri;
			} else {

				if (prefix)
				{
					if (xvalue.rs.len + prefix->len > AVPOPS_ATTR_LEN)
					{
						LM_ERR("name too long [%d/%.*s...]\n",
							prefix->len + xvalue.rs.len, 16, prefix->s);
						goto error;
					}

					memcpy(avpops_attr_buf, prefix->s, prefix->len);
					memcpy(avpops_attr_buf + prefix->len, xvalue.rs.s,
																xvalue.rs.len);
					xvalue.rs.s = avpops_attr_buf;
					xvalue.rs.len = prefix->len + xvalue.rs.len;
				}

				avp_name = get_avp_id(&xvalue.rs);
				if (avp_name < 0) {
					LM_ERR("cannot get avp id\n");
					return -1;
				}
			}
		} else {
			avp_name = dbp->a.u.sval.pvp.pvn.u.isname.name.n;
			avp_type = dbp->a.u.sval.pvp.pvn.u.isname.type;
		}
	}

	/* process the results */
	for( n=0,i=0 ; i<res->n ; i++)
	{
		if (dbrow2avp(&res->rows[i], dbp, avp_name, avp_type, sh_flg, prefix) < 0)
			continue;
		n++;
	}

	db_close_query( url, res );

	LM_DBG("loaded avps = %d\n",n);

	return n?1:-1;
error:
	return -1;
}


int ops_dbdelete_avps (struct sip_msg* msg, struct fis_param *sp,
		struct db_param *dbp, struct db_url *url, int use_domain)
{
	struct sip_uri  uri;
	int             res;
	str             uuid;
	pv_value_t xvalue;
	str *s0, *s1, *s2;

	s0 = s1 = s2 = NULL;
	if (!((sp->opd&AVPOPS_VAL_PVAR)||(sp->opd&AVPOPS_VAL_STR))) {
		LM_CRIT("invalid flag combination (%d/%d)\n", sp->opd, sp->ops);
		goto error;
	}

	/* get uuid from avp */
	if (sp->opd&AVPOPS_VAL_PVAR)
	{
		if(pv_get_spec_value(msg, &(sp->u.sval), &xvalue)!=0)
		{
			LM_CRIT("failed to get PVAR value (%d/%d)\n", sp->opd, sp->ops);
			goto error;
		}
		if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
		{
			LM_ERR("no value for first param\n");
			goto error;
		}
		uuid = xvalue.rs;
	} else {
		uuid.s   = sp->u.s.s;
		uuid.len = sp->u.s.len;
	}

	if(sp->opd&AVPOPS_FLAG_UUID0)
	{
		s0 = &uuid;
	} else {
		/* parse uri */
		if (parse_uri(uuid.s, uuid.len, &uri)<0)
		{
			LM_ERR("failed to parse uri\n");
			goto error;
		}

		if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_USER0))
		{
			/* check that uri contains user part */
			if(!uri.user.s|| !uri.user.len)
			{
				LM_ERR("incomplet uri <%.*s> missing user\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s1 = &uri.user;
			}
		}
		if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_DOMAIN0))
		{
			/* check tah uri contains host part */
			if(!uri.host.len|| !uri.host.s)
			{
				LM_ERR("incomplet uri <%.*s> missing host\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s2 = &uri.host;
			}
		}
	}

	/* is dynamic avp name ? */
	if(dbp->a.type==AVPOPS_VAL_PVAR)
	{
		if(pv_has_dname(&dbp->a.u.sval))
		{
			if(pv_get_spec_name(msg, &(dbp->a.u.sval.pvp), &xvalue)!=0)
			{
				LM_CRIT("failed to get value for P2\n");
				goto error;
			}
			if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
			{
				LM_INFO("no value for p2\n");
				goto error;
			}
			if(xvalue.flags&PV_VAL_STR)
			{
				if(xvalue.rs.len>=AVPOPS_ATTR_LEN)
				{
					LM_ERR("name too long [%d/%.*s...]\n",
						xvalue.rs.len, 16, xvalue.rs.s);
					goto error;
				}
				dbp->sa.s = avpops_attr_buf;
				memcpy(dbp->sa.s, xvalue.rs.s, xvalue.rs.len);
				dbp->sa.len = xvalue.rs.len;
				dbp->sa.s[dbp->sa.len] = '\0';
			} else {
				LM_INFO("no string value for p2\n");
				goto error;
			}
		}
	}

	/* do DB delete */
	res = db_delete_avp( url, s0, s1,
			(use_domain||(sp->opd&AVPOPS_FLAG_DOMAIN0))?s2:0,
			dbp->sa.s, &dbp->table);

	/* res ?  */
	if (res<0)
	{
		LM_ERR("db_delete failed\n");
		goto error;
	}

	return 1;
error:
	return -1;
}


int ops_dbstore_avps (struct sip_msg* msg, struct fis_param *sp,
					struct db_param *dbp, struct db_url *url, int use_domain)
{
	struct sip_uri   uri;
	struct usr_avp   **avp_list;
	struct usr_avp   *avp;
	int              avp_name;
	int_str          i_s;
	str              uuid;
	int              keys_nr;
	int              n;
	pv_value_t xvalue;
	str *s0, *s1, *s2;
	str *sn;

	s0 = s1 = s2 = NULL;
	if (!((sp->opd&AVPOPS_VAL_PVAR)||(sp->opd&AVPOPS_VAL_STR))) {
		LM_CRIT("invalid flag combination (%d/%d)\n", sp->opd, sp->ops);
		goto error;
	}

	keys_nr = 6; /* uuid, avp name, avp val, avp type, user, domain */

	/* get uuid from avp */
	if (sp->opd&AVPOPS_VAL_PVAR)
	{
		if(pv_get_spec_value(msg, &(sp->u.sval), &xvalue)!=0)
		{
			LM_CRIT("failed to get PVAR value (%d/%d)\n", sp->opd, sp->ops);
			goto error;
		}
		if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
		{
			LM_ERR("no value for first param\n");
			goto error;
		}
		uuid = xvalue.rs;
	} else {
		uuid.s   = sp->u.s.s;
		uuid.len = sp->u.s.len;
	}

	if(sp->opd&AVPOPS_FLAG_UUID0)
	{
		s0 = &uuid;
	} else {
		/* parse uri */
		if (parse_uri(uuid.s, uuid.len, &uri)<0)
		{
			LM_ERR("failed to parse uri\n");
			goto error;
		}

		if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_USER0))
		{
			/* check tha uri contains user part */
			if(!uri.user.s|| !uri.user.len)
			{
				LM_ERR("incomplet uri <%.*s> missing user\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s1 = &uri.user;
			}
		}
		if((sp->opd&AVPOPS_FLAG_URI0)||(sp->opd&AVPOPS_FLAG_DOMAIN0))
		{
			/* check that uri contains host part */
			if(!uri.host.len|| !uri.host.s)
			{
				LM_ERR("incomplet uri <%.*s> missing host\n", uuid.len, uuid.s);
				goto error;
			}
			else
			{
				s2 = &uri.host;
			}
		}
	}

	/* set values for keys  */
	store_vals[0].val.str_val = (s0)?*s0:empty;
	store_vals[4].val.str_val = (s1)?*s1:empty;
	if (use_domain || sp->opd&AVPOPS_FLAG_DOMAIN0)
		store_vals[5].val.str_val = (s2)?*s2:empty;
	avp_name = -1;

	/* is dynamic avp name ? */
	if(dbp->a.type==AVPOPS_VAL_PVAR)
	{
		if(pv_has_dname(&dbp->a.u.sval))
		{
			/* TODO change here to be aware of the int name */
			if(pv_get_spec_name(msg, &(dbp->a.u.sval.pvp), &xvalue)!=0)
			{
				LM_CRIT("failed to get value for P2\n");
				goto error;
			}
			if(xvalue.flags&(PV_VAL_NULL|PV_VAL_EMPTY))
			{
				LM_INFO("no value for P2\n");
				goto error;
			}
			if(xvalue.flags&PV_TYPE_INT)
			{
				avp_name = xvalue.ri;
			} else {
				avp_name = -1;
			}
			if(xvalue.flags&PV_VAL_STR)
			{
				if(xvalue.rs.len>=AVPOPS_ATTR_LEN)
				{
					LM_ERR("name too long [%d/%.*s...]\n",
						xvalue.rs.len, 16, xvalue.rs.s);
					goto error;
				}
				dbp->sa.s = avpops_attr_buf;
				memcpy(dbp->sa.s, xvalue.rs.s, xvalue.rs.len);
				dbp->sa.len = xvalue.rs.len;
				dbp->sa.s[dbp->sa.len] = '\0';
				avp_name = get_avp_id(&dbp->sa);
				/* search for the id only once */
				if (avp_name < 0) {
					LM_ERR("cannot find avp\n");
					goto error;
				}
			} else {
				LM_INFO("no string value for p2\n");
				goto error;
			}
		} else {
			avp_name = dbp->a.u.sval.pvp.pvn.u.isname.name.n;
		}
	} else {
		LM_WARN("TODO: avp is not a dynamic name <%.*s> name is %d\n", dbp->sa.len, dbp->sa.s, avp_name);
		avp_name = -1;
	}

	/* set uuid/(username and domain) fields */

	n =0 ;
	if ((dbp->a.opd&AVPOPS_VAL_NONE)==0)
	{
		/* if avp wasn't found yet */
		if (avp_name < 0) {
			avp_name = get_avp_id(&dbp->sa);
			/* search for the id only once */
			if (avp_name < 0) {
				LM_ERR("cannot find avp\n");
				goto error;
			}
		}
		/* avp name is known ->set it and its type */
		store_vals[1].val.str_val = dbp->sa; /*attr name*/
		avp = search_first_avp( 0, avp_name, &i_s, 0);
		for( ; avp; avp=search_first_avp( 0, avp_name, &i_s, avp))
		{
			/* don't insert avps which were loaded */
			if (avp->flags&AVP_IS_IN_DB)
				continue;
			/* set type */
			store_vals[3].val.int_val =
				(avp->flags&AVP_NAME_STR?0:AVPOPS_DB_NAME_INT)|
				(avp->flags&AVP_VAL_STR?0:AVPOPS_DB_VAL_INT);
			/* set value */
			int_str2db_val( i_s, &store_vals[2].val.str_val,
				avp->flags&AVP_VAL_STR);
			/* save avp */
			if (db_store_avp( url, store_keys, store_vals,
					keys_nr, &dbp->table)==0 )
			{
				avp->flags |= AVP_IS_IN_DB;
				n++;
			}
		}
	} else {
		/* avp name is unknown -> go through all list */
		avp_list = get_avp_list();
		avp = *avp_list;

		for ( ; avp ; avp=avp->next )
		{
			/* don't insert avps which were loaded */
			if (avp->flags&AVP_IS_IN_DB)
				continue;

			/* set attribute name and type */
			if ( (sn=get_avp_name(avp))==0 )
				i_s.n = avp->id;
			else
				i_s.s = *sn;
			int_str2db_val( i_s, &store_vals[1].val.str_val, AVP_NAME_STR);
			store_vals[3].val.int_val =
				(avp->flags&AVP_NAME_STR?0:AVPOPS_DB_NAME_INT)|
				(avp->flags&AVP_VAL_STR?0:AVPOPS_DB_VAL_INT);
			/* set avp value */
			get_avp_val( avp, &i_s);
			int_str2db_val( i_s, &store_vals[2].val.str_val,
				avp->flags&AVP_VAL_STR);
			/* save avp */
			if (db_store_avp( url, store_keys, store_vals,
			keys_nr, &dbp->table)==0)
			{
				avp->flags |= AVP_IS_IN_DB;
				n++;
			}
		}
	}

	LM_DBG(" %d avps were stored\n",n);

	return n==0?-1:1;
error:
	return -1;
}



/* @return : non-zero */
int ops_dbquery_avps(struct sip_msg* msg, str* query,
                     struct db_url *url, pvname_list_t* dest)
{
	int ret;

	if(msg==NULL || query==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	LM_DBG("query [%.*s]\n", query->len, query->s);
	ret = db_query_avp(url, msg, query, dest);

	//Empty return set
	if(ret==1)
		return -2;

	//All other failures
	if(ret!=0)
		return -1;

	//Have a return set
	return 1;
}

int ops_async_dbquery(struct sip_msg* msg, async_ctx *ctx,
		str *query, struct db_url *url, pvname_list_t *dest)
{
	int rc, read_fd;
	query_async_param *param;

	void *_priv;

	if (!msg || !query)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	LM_DBG("query [%.*s]\n", query->len, query->s);

	/* No async capabilities - just run it in blocking mode */
	if (!DB_CAPABILITY(url->dbf, DB_CAP_ASYNC_RAW_QUERY))
	{
		rc = db_query_avp(url, msg, query, dest);
		LM_DBG("sync query \"%.*s\" returned: %d\n", query->len, query->s, rc);

		ctx->resume_param = NULL;
		ctx->resume_f = NULL;
		async_status = ASYNC_NO_IO;

		/* Empty_set / Other_errors / Success */
		return rc == 1 ? -2 : (rc != 0 ? -1 : 1);
	}

	read_fd = url->dbf.async_raw_query(url->hdl, query, &_priv);
	if (read_fd < 0)
	{
		ctx->resume_param = NULL;
		ctx->resume_f = NULL;
		return -1;
	}

	param = pkg_malloc(sizeof *param);
	if (!param)
	{
		LM_ERR("no more pkg mem\n");
		return E_OUT_OF_MEM;
	}
	memset(param, '\0', sizeof *param);

	ctx->resume_param = param;
	ctx->resume_f = resume_async_dbquery;
	/* if supported in the backend */
	if (url->dbf.async_timeout != NULL)
		ctx->timeout_f = timeout_async_dbquery;

	param->output_avps = dest;
	param->hdl = url->hdl;
	param->dbf = &url->dbf;
	param->db_param = _priv;

	async_status = read_fd;
	return 1;
}

int timeout_async_dbquery(int fd, struct sip_msg *msg, void *_param)
{
	query_async_param *param = (query_async_param *)_param;

	param->dbf->async_timeout(param->hdl, fd, param->db_param);

	/* this in an error case */
	return -1;
}

int resume_async_dbquery(int fd, struct sip_msg *msg, void *_param)
{
	db_res_t *res = NULL;
	query_async_param *param = (query_async_param *)_param;
	int rc, ret;

	rc = param->dbf->async_resume(param->hdl, fd, &res, param->db_param);
	if (async_status == ASYNC_CONTINUE || async_status == ASYNC_CHANGE_FD) {
		return rc;
	}

	if (rc != 0) {
		LM_ERR("async query returned error\n");
		ret = -1;
		goto err_free;
	}

	if (!res || RES_ROW_N(res) <= 0 || RES_COL_N(res) <= 0) {
		LM_DBG("query returned no results\n");
		ret = -2;
		goto err_free;
	}

	if (db_query_avp_print_results(msg, res, param->output_avps) != 0) {
		LM_ERR("failed to print results\n");
		ret = -1;
		goto err_free;
	}

	async_status = ASYNC_DONE;

	param->dbf->async_free_result(param->hdl, res, param->db_param);
	pkg_free(param);
	return 1;

err_free:
	param->dbf->async_free_result(param->hdl, res, param->db_param);
	pkg_free(param);
	return ret;
}

