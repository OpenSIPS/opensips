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

static int avpops_get_aname(struct sip_msg* msg, struct fis_param *ap,
		int *avp_name, unsigned short *name_type)
{
	if(ap==NULL || avp_name==NULL || name_type==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	return pv_get_avp_name(msg, &ap->u.sval.pvp, avp_name, name_type);
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
	unsigned short   name_type;
	int              avp_name;
	int_str          i_s;
	str              uuid;
	int              keys_nr;
	int              n;
	pv_value_t xvalue;
	str *s0, *s1, *s2;
	str *sn;

	s0 = s1 = s2 = NULL;
	name_type = 0;
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
				name_type = 0;
				avp_name = xvalue.ri;
			} else {
				name_type = AVP_NAME_STR;
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
			name_type = dbp->a.u.sval.pvp.pvn.u.isname.type;
			avp_name = dbp->a.u.sval.pvp.pvn.u.isname.name.n;
		}
	} else {
		LM_WARN("TODO: avp is not a dynamic name <%.*s> name is %d\n", dbp->sa.len, dbp->sa.s, avp_name);
		avp_name = -1;
	}

	/* set the script flags */
	if(dbp->a.type==AVPOPS_VAL_PVAR)
		name_type |= dbp->a.u.sval.pvp.pvn.u.isname.type&0xff00;

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

	param->output_avps = dest;
	param->hdl = url->hdl;
	param->dbf = &url->dbf;
	param->db_param = _priv;

	async_status = read_fd;
	return 1;
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



int ops_delete_avp(struct sip_msg* msg, struct fis_param *ap)
{
	struct usr_avp **avp_list;
	struct usr_avp *avp;
	struct usr_avp *avp_next;
	unsigned short name_type;
	int avp_name;
	int n;

	n = 0;

	if ((ap->opd&AVPOPS_VAL_NONE)==0)
	{
		/* avp name is known ->search by name */
		/* get avp name */
		if(avpops_get_aname(msg, ap, &avp_name, &name_type)!=0)
		{
			LM_ERR("failed to get dst AVP name\n");
			return -1;
		}
		n = destroy_avps( name_type, avp_name, ap->ops&AVPOPS_FLAG_ALL );
	} else {
		/* avp name is not given - we have just flags */
		/* -> go through all list */
		avp_list = get_avp_list();
		avp = *avp_list;

		for ( ; avp ; avp=avp_next )
		{
			avp_next = avp->next;
			/* check if type match */
			if ( !( (ap->opd&(AVPOPS_VAL_INT|AVPOPS_VAL_STR))==0 ||
			((ap->opd&AVPOPS_VAL_INT)&&((avp->flags&AVP_NAME_STR))==0) ||
			((ap->opd&AVPOPS_VAL_STR)&&(avp->flags&AVP_NAME_STR)) )  )
				continue;
			if((ap->u.sval.pvp.pvn.u.isname.type&AVP_SCRIPT_MASK)!=0
					&& ((ap->u.sval.pvp.pvn.u.isname.type&AVP_SCRIPT_MASK)
								&avp->flags)==0)
				continue;
			/* remove avp */
			destroy_avp( avp );
			n++;
			if ( !(ap->ops&AVPOPS_FLAG_ALL) )
				break;
		}
	}

	LM_DBG("%d avps were removed\n",n);

	return n?1:-1;
}

int ops_copy_avp( struct sip_msg* msg, struct fis_param* src,
													struct fis_param* dst)
{
	struct usr_avp *avp;
	struct usr_avp *prev_avp;
	int_str         avp_val;
	int_str         avp_val2;
	unsigned short name_type1;
	unsigned short name_type2;
	int avp_name1;
	int avp_name2;
	int n;

	n = 0;
	prev_avp = 0;

	/* get avp src name */
	if(avpops_get_aname(msg, src, &avp_name1, &name_type1)!=0)
	{
		LM_ERR("failed to get src AVP name\n");
		goto error;
	}
	/* get avp dst name */
	if(avpops_get_aname(msg, dst, &avp_name2, &name_type2)!=0)
	{
		LM_ERR("failed to get dst AVP name\n");
		goto error;
	}

	avp = search_first_avp( name_type1, avp_name1, &avp_val, 0);
	while ( avp )
	{
		/* build a new avp with new name, but old value */
		/* do we need cast conversion ?!?! */
		if((avp->flags&AVP_VAL_STR) && (dst->ops&AVPOPS_FLAG_CASTN)) {
			if(str2int(&avp_val.s, (unsigned int*)&avp_val2.n)!=0)
			{
				LM_ERR("cannot convert str to int\n");
				goto error;
			}
			if ( add_avp( name_type2, avp_name2, avp_val2)==-1 ) {
				LM_ERR("failed to create new avp!\n");
				goto error;
			}
		} else if(!(avp->flags&AVP_VAL_STR)&&(dst->ops&AVPOPS_FLAG_CASTS)) {
			avp_val2.s.s = int2str(avp_val.n, &avp_val2.s.len);
			if ( add_avp( name_type2|AVP_VAL_STR, avp_name2, avp_val2)==-1 ) {
				LM_ERR("failed to create new avp.\n");
				goto error;
			}
		} else {
			if ( add_avp( name_type2|(avp->flags&AVP_VAL_STR), avp_name2,
					avp_val)==-1 ) {
				LM_ERR("failed to create new avp\n");
				goto error;
			}
		}
		n++;
		/* copy all avps? */
		if ( !(dst->ops&AVPOPS_FLAG_ALL) ) {
			/* delete the old one? */
			if (dst->ops&AVPOPS_FLAG_DELETE)
				destroy_avp( avp );
			break;
		} else {
			prev_avp = avp;
			avp = search_first_avp( name_type1, avp_name1, &avp_val, prev_avp);
			/* delete the old one? */
			if (dst->ops&AVPOPS_FLAG_DELETE)
				destroy_avp( prev_avp );
		}
	}

	return n?1:-1;
error:
	return -1;
}


#define STR_BUF_SIZE  1024
static char str_buf[STR_BUF_SIZE];

inline static int append_0(str *in, str *out)
{
	if (in->len+1>STR_BUF_SIZE)
		return -1;
	memcpy( str_buf, in->s, in->len);
	str_buf[in->len] = 0;
	out->len = in->len;
	out->s = str_buf;
	return 0;
}


int ops_pushto_avp (struct sip_msg* msg, struct fis_param* dst,
													struct fis_param* src)
{
	struct usr_avp *avp;
	unsigned short name_type;
	int_str        avp_val;
	int        avp_name;
	str            val;
	int            act_type;
	int            n;
	int            flags;
	pv_value_t     xvalue;

	avp = NULL;
	flags = 0;
	if(src->u.sval.type==PVT_AVP)
	{
		/* search for the avp */
		if(avpops_get_aname(msg, src, &avp_name, &name_type)!=0)
		{
			LM_ERR("failed to get src AVP name\n");
			goto error;
		}
		avp = search_first_avp( name_type, avp_name, &avp_val, 0);
		if (avp==0)
		{
			LM_DBG(" no src avp found\n");
			goto error;
		}
		flags = avp->flags;
	} else {
		if(pv_get_spec_value(msg, &(src->u.sval), &xvalue)!=0)
		{
			LM_ERR("cannot get src value\n");
			goto error;
		}
		if(xvalue.flags&PV_TYPE_INT)
		{
			avp_val.n = xvalue.ri;
		} else {
			flags = AVP_VAL_STR;
			avp_val.s = xvalue.rs;
		}
	}

	n = 0;
	do {
		/* the avp val will be used all the time as str */
		if (flags&AVP_VAL_STR) {
			val = avp_val.s;
		} else {
			val.s = int2str((unsigned long)avp_val.n, &val.len);
		}

		act_type = -1;
		/* push the value into right position */
		if (dst->opd&AVPOPS_USE_RURI)
		{
			if (dst->opd&AVPOPS_FLAG_USER0)
				act_type = RW_RURI_USER;
			else if (dst->opd&AVPOPS_FLAG_DOMAIN0)
				act_type = RW_RURI_HOST;
			else
				act_type = 0; /* entire RURI */
			if ( flags&AVP_VAL_STR && append_0( &val, &val)!=0 ) {
				LM_ERR("failed to make 0 term.\n");
				goto error;
			}
		} else if (dst->opd&AVPOPS_USE_DURI) {
			if (!(flags&AVP_VAL_STR)) {
				goto error;
			}
		} else if (dst->opd&AVPOPS_USE_BRANCH) {
			if (!(flags&AVP_VAL_STR)) {
				goto error;
			}
		} else {
			LM_CRIT("destination unknown (%d/%d)\n", dst->opd, dst->ops);
			goto error;
		}

		if ( act_type != -1 )
		{
			/* rewrite part of ruri */
			if (n)
			{
				/* if is not the first modification, push the current uri as
				 * branch */
				if (append_branch( msg, 0, 0, 0, Q_UNSPECIFIED, 0, 0)!=1 )
				{
					LM_ERR("append_branch action failed\n");
					goto error;
				}
			}
			if (act_type == 0) {
				if (set_ruri(msg, &val) < 0) {
					LM_ERR("Failed to set RURI\n");
					goto error;
				}
			} else {
				if (rewrite_ruri(msg, &val, 0, act_type) < 0) {
					LM_ERR("Failed to set user or host\n");
					goto error;
				}
			}
		} else if (dst->opd&AVPOPS_USE_DURI) {
			if(set_dst_uri(msg, &val)!=0)
			{
				LM_ERR("changing dst uri failed\n");
				goto error;
			}
		} else if (dst->opd&AVPOPS_USE_BRANCH) {
			if (append_branch( msg, &val, 0, 0, Q_UNSPECIFIED, 0,
			msg->force_send_socket)!=1 )
			{
				LM_ERR("append_branch action failed\n");
				goto error;
			}
		} else {
			LM_ERR("unknown destination\n");
			goto error;
		}

		n++;
		if ( !(src->ops&AVPOPS_FLAG_ALL) )
			break;
		if(avp==NULL)
			break;
		if((avp = search_first_avp( name_type, avp_name, &avp_val, avp))!=NULL)
			flags = avp->flags;
	} while (avp);/* end while */

	LM_DBG("%d avps were processed\n",n);
	return 1;
error:
	return -1;
}

int ops_check_avp( struct sip_msg* msg, struct fis_param* src,
													struct fis_param* val)
{
	unsigned short    name_type1;
	unsigned short    name_type2;
	struct usr_avp    *avp1;
	struct usr_avp    *avp2;
	regmatch_t        pmatch;
	int               avp_name1;
	int               avp_name2;
	int_str           avp_val;
	int_str           check_val;
	int               check_flags;
	int               n, rt;
	int            flags;
	pv_value_t     xvalue;
	char           backup;

	/* look if the required avp(s) is/are present */
	if(src->u.sval.type==PVT_AVP)
	{
		/* search for the avp */
		if(avpops_get_aname(msg, src, &avp_name1, &name_type1)!=0)
		{
			LM_ERR("failed to get src AVP name\n");
			goto error;
		}
		avp1 = search_first_avp( name_type1, avp_name1, &avp_val, 0);
		if (avp1==0)
		{
			LM_DBG("no src avp found\n");
			goto error;
		}
		flags = avp1->flags;
	} else {
		avp1 = 0;
		flags = 0;
		if(pv_get_spec_value(msg, &(src->u.sval), &xvalue)!=0)
		{
			LM_ERR("cannot get src value\n");
			goto error;
		}
		if(xvalue.flags&PV_TYPE_INT)
		{
			avp_val.n = xvalue.ri;
		} else {
			flags = AVP_VAL_STR;
			avp_val.s = xvalue.rs;
		}
	}

cycle1:
	/* copy string since pseudo-variables uses static buffer */
	if(flags&AVP_VAL_STR)
	{
		if(avp_val.s.len>=STR_BUF_SIZE)
		{
			LM_ERR("src value too long\n");
			goto error;
		}
		strncpy(str_buf, avp_val.s.s, avp_val.s.len);
		str_buf[avp_val.s.len] = '\0';
		avp_val.s.s = str_buf;
	}

	if (val->opd&AVPOPS_VAL_PVAR)
	{
		/* the 2nd operator is variable -> get avp value */
		check_flags = 0;
		if(val->u.sval.type==PVT_AVP)
		{
			/* search for the avp */
			if(avpops_get_aname(msg, val, &avp_name2, &name_type2)!=0)
			{
				LM_ERR("failed to get dst AVP name\n");
				goto error;
			}
			avp2 = search_first_avp( name_type2, avp_name2, &check_val, 0);
			if (avp2==0)
			{
				LM_DBG("no dst avp found\n");
				goto error;
			}
			check_flags = avp2->flags;
		} else {
			avp2 = 0;
			if(pv_get_spec_value(msg, &(val->u.sval), &xvalue)!=0)
			{
				LM_ERR("cannot get dst value\n");
				goto error;
			}
			if(xvalue.flags&PV_TYPE_INT)
			{
				check_val.n = xvalue.ri;
			} else {
				check_flags = AVP_VAL_STR;
				check_val.s = xvalue.rs;
			}
		}
	} else {
		check_flags = 0;
		if(val->type == AVPOPS_VAL_INT)
		{
			check_val.n = val->u.n;
		} else {
			check_val.s = val->u.s;
			check_flags = AVP_VAL_STR;
		}
		avp2 = 0;
	}

cycle2:
	/* are both values of the same type? */
	if ((flags&AVP_VAL_STR)^(check_flags&AVP_VAL_STR))
	{
		LM_ERR("value types don't match\n");
		goto next;
	}

	if (flags&AVP_VAL_STR)
	{
		/* string values to check */
		LM_DBG("check <%.*s> against <%.*s> as str /%d\n",
			avp_val.s.len,avp_val.s.s,
			(val->ops&AVPOPS_OP_RE)?6:check_val.s.len,
			(val->ops&AVPOPS_OP_RE)?"REGEXP":check_val.s.s,
			val->ops);
		/* do check */
		if (val->ops&AVPOPS_OP_EQ)
		{
			if (avp_val.s.len==check_val.s.len)
			{
				if (val->ops&AVPOPS_FLAG_CI)
				{
					if (strncasecmp(avp_val.s.s,check_val.s.s,
								check_val.s.len)==0)
						return 1;
				} else {
					if (strncmp(avp_val.s.s,check_val.s.s,check_val.s.len)==0 )
						return 1;
				}
			}
		} else if (val->ops&AVPOPS_OP_NE) {
			if (avp_val.s.len!=check_val.s.len)
				return 1;
			if (val->ops&AVPOPS_FLAG_CI)
			{
				if (strncasecmp(avp_val.s.s,check_val.s.s,check_val.s.len)!=0)
					return 1;
			} else {
				if (strncmp(avp_val.s.s,check_val.s.s,check_val.s.len)!=0 )
					return 1;
			}
		} else if (val->ops&AVPOPS_OP_LT) {
			n = (avp_val.s.len>=check_val.s.len)?avp_val.s.len:check_val.s.len;
			rt = strncasecmp(avp_val.s.s,check_val.s.s,n);
			if (rt<0)
				return 1;
			if(rt==0 && avp_val.s.len<check_val.s.len)
				return 1;
		} else if (val->ops&AVPOPS_OP_LE) {
			n = (avp_val.s.len>=check_val.s.len)?avp_val.s.len:check_val.s.len;
			if (strncasecmp(avp_val.s.s,check_val.s.s,n)<=0)
				return 1;
		} else if (val->ops&AVPOPS_OP_GT) {
			n = (avp_val.s.len>=check_val.s.len)?avp_val.s.len:check_val.s.len;
			rt = strncasecmp(avp_val.s.s,check_val.s.s,n);
			if (rt>0)
				return 1;
			if(rt==0 && avp_val.s.len>check_val.s.len)
				return 1;
		} else if (val->ops&AVPOPS_OP_GE) {
			n = (avp_val.s.len>=check_val.s.len)?avp_val.s.len:check_val.s.len;
			if (strncasecmp(avp_val.s.s,check_val.s.s,n)>=0)
				return 1;
		} else if (val->ops&AVPOPS_OP_RE) {
			backup  = avp_val.s.s[avp_val.s.len];
			avp_val.s.s[avp_val.s.len] = '\0';
			if (regexec((regex_t*)check_val.s.s, avp_val.s.s, 1, &pmatch,0)==0)
			{
				avp_val.s.s[avp_val.s.len] = backup;
				return 1;
			}
			avp_val.s.s[avp_val.s.len] = backup;
		} else if (val->ops&AVPOPS_OP_FM){
			backup  = avp_val.s.s[avp_val.s.len];
			avp_val.s.s[avp_val.s.len] = '\0';
			if (fnmatch( check_val.s.s, avp_val.s.s,
			#ifdef FNM_CASEFOLD
			(val->ops&AVPOPS_FLAG_CI)?FNM_CASEFOLD:
			#endif
			0 )==0)
			{
				avp_val.s.s[avp_val.s.len] = backup;
				return 1;
			}
			avp_val.s.s[avp_val.s.len] = backup;
		} else {
			LM_CRIT("unknown operation (flg=%d/%d)\n",val->opd, val->ops);
		}
	} else {
		/* int values to check -> do check */
		LM_DBG("check <%d> against <%d> as int /%d\n",
				avp_val.n, check_val.n, val->ops);
		if (val->ops&AVPOPS_OP_EQ)
		{
			if ( avp_val.n==check_val.n)
				return 1;
		} else 	if (val->ops&AVPOPS_OP_NE) {
			if ( avp_val.n!=check_val.n)
				return 1;
		} else  if (val->ops&AVPOPS_OP_LT) {
			if ( avp_val.n<check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_LE) {
			if ( avp_val.n<=check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_GT) {
			if ( avp_val.n>check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_GE) {
			if ( avp_val.n>=check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_BAND) {
			if ( avp_val.n&check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_BOR) {
			if ( avp_val.n|check_val.n)
				return 1;
		} else if (val->ops&AVPOPS_OP_BXOR) {
			if ( avp_val.n^check_val.n)
				return 1;
		} else {
			LM_CRIT("unknown operation (flg=%d)\n",val->ops);
		}
	}

next:
	/* cycle for the second value (only if avp can have multiple vals) */
	if ((avp2!=NULL)
		&& (avp2=search_first_avp( name_type2, avp_name2, &check_val, avp2))!=NULL)
	{
		check_flags = avp2->flags;
		goto cycle2;
	/* cycle for the first value -> next avp */
	} else {
		if(avp1 && val->ops&AVPOPS_FLAG_ALL)
		{
			avp1=search_first_avp(name_type1, avp_name1, &avp_val, avp1);
			if (avp1)
				goto cycle1;
		}
	}

	LM_DBG("no match\n");
	return -1; /* check failed */
error:
	return -1;
}


int ops_print_avp(void)
{
	struct usr_avp **avp_list;
	struct usr_avp *avp;
	int_str         val;
	str            *name;

	/* go through all list */
	avp_list = get_avp_list();
	avp = *avp_list;

	LM_INFO("----------- All AVPs in this context --------\n");
	LM_INFO("  (SIP txn, script event, timer route, etc.)\n");
	for ( ; avp ; avp=avp->next)
	{
		LM_INFO("p=%p, flags=0x%04X\n",avp, avp->flags);
		name = get_avp_name(avp);
		LM_INFO("    name=<%.*s>\n",name->len,name->s);
		LM_INFO("    id=<%d>\n",avp->id);
		get_avp_val( avp, &val);
		if (avp->flags&AVP_VAL_STR)
		{
			LM_INFO("    val_str=<%.*s / %d>\n",val.s.len,val.s.s,
					val.s.len);
		} else {
			LM_INFO("    val_int=<%d>\n",val.n);
		}
	}
	LM_INFO("---------------- END ALL AVPs ---------------\n");

	return 1;
}

int ops_subst(struct sip_msg* msg, struct fis_param** src,
		struct subst_expr* se)
{
	struct usr_avp *avp;
	struct usr_avp *prev_avp;
	int_str         avp_val;
	unsigned short name_type1;
	unsigned short name_type2;
	int            avp_name1;
	int            avp_name2;
	int n;
	int nmatches;
	str* result;

	n = 0;
	prev_avp = 0;

	/* avp name is known ->search by name */
	/* get src avp name */
	if(avpops_get_aname(msg, src[0], &avp_name1, &name_type1)!=0)
	{
		LM_ERR("failed to get src AVP name\n");
		return -1;
	}

	avp = search_first_avp(name_type1, avp_name1, &avp_val, 0);

	if(avp==NULL)
		return -1;

	if(src[1]!=0)
	{
		/* get dst avp name */
		if(avpops_get_aname(msg, src[1], &avp_name2, &name_type2)!=0)
		{
			LM_ERR("failed to get dst AVP name\n");
			return -1;
		}
	} else {
		name_type2 = name_type1;
		avp_name2 = avp_name1;
	}
/* TODO: delete?
	if(name_type2&AVP_NAME_STR)
	{
		if(avp_name2.s.len>=STR_BUF_SIZE)
		{
			LM_ERR("dst name too long\n");
			goto error;
		}
		strncpy(str_buf, avp_name2.s.s, avp_name2.s.len);
		str_buf[avp_name2.s.len] = '\0';
		avp_name2.s.s = str_buf;
	}
*/
	while(avp)
	{
		if(!is_avp_str_val(avp))
		{
			prev_avp = avp;
			avp = search_first_avp(name_type1, avp_name1, &avp_val, prev_avp);
			continue;
		}

		result=subst_str(avp_val.s.s, msg, se, &nmatches);
		if(result!=NULL)
		{
			/* build a new avp with new name */
			avp_val.s = *result;
			if(add_avp(name_type2|AVP_VAL_STR, avp_name2, avp_val)==-1 ) {
				LM_ERR("failed to create new avp\n");
				if(result->s!=0)
					pkg_free(result->s);
				pkg_free(result);
				goto error;
			}
			if(result->s!=0)
				pkg_free(result->s);
			pkg_free(result);
			n++;
			/* copy all avps? */
			if (!(src[0]->ops&AVPOPS_FLAG_ALL) ) {
				/* delete the old one? */
				if (src[0]->ops&AVPOPS_FLAG_DELETE || src[1]==0)
					destroy_avp(avp);
				break;
			} else {
				prev_avp = avp;
				avp = search_first_avp(name_type1,avp_name1,&avp_val,prev_avp);
				/* delete the old one? */
				if (src[0]->ops&AVPOPS_FLAG_DELETE || src[1]==0)
					destroy_avp( prev_avp );
			}
		} else {
			prev_avp = avp;
			avp = search_first_avp(name_type1, avp_name1, &avp_val, prev_avp);
		}

	}
	LM_DBG("subst to %d avps\n", n);
	return n?1:-1;
error:
	return -1;
}

int ops_op_avp( struct sip_msg* msg, struct fis_param** av,
													struct fis_param* val)
{
	unsigned short    name_type1;
	unsigned short    name_type2;
	unsigned short    name_type3;
	struct fis_param* src;
	struct usr_avp    *avp1;
	struct usr_avp    *avp2;
	struct usr_avp    *prev_avp;
	int               avp_name1;
	int               avp_name2;
	int               avp_name3;
	int_str           avp_val;
	int_str           op_val;
	int               result;
	pv_value_t        xvalue;

	src = av[0];
	/* look if the required avp(s) is/are present */
			/* search for the avp */
	if(avpops_get_aname(msg, src, &avp_name1, &name_type1)!=0)
	{
		LM_ERR("failed to get src AVP name\n");
		goto error;
	}
	avp1 = search_first_avp(name_type1, avp_name1, &avp_val, 0);
	if (avp1==0)
	{
		LM_DBG(" no src avp found\n");
		goto error;
	}

	while(avp1!=0)
	{
		if(!(avp1->flags&AVP_VAL_STR))
			break;
		avp1 = search_first_avp(name_type1, avp_name1, &avp_val, avp1);
	}
	if (avp1==0 && !(val->ops&AVPOPS_OP_BNOT)) {
		LM_DBG("no proper avp found\n");
		goto error;
	}
	name_type3 = name_type1;
	avp_name3 = avp_name1;
	if(av[1]!=0)
	{
		if(avpops_get_aname(msg, av[1], &avp_name3, &name_type3)!=0)
		{
			LM_ERR("failed to get dst AVP name\n");
			goto error;
		}
	}
/* TODO: delete?
	if(name_type3&AVP_NAME_STR)
	{
		if(avp_name3.s.len>=STR_BUF_SIZE)
		{
			LM_ERR("failed to get dst name too long\n");
			goto error;
		}
		strncpy(str_buf, avp_name3.s.s, avp_name3.s.len);
		str_buf[avp_name3.s.len] = '\0';
		avp_name3.s.s = str_buf;
	}
*/
	prev_avp = 0;
	result = 0;

cycle1:
	if (val->opd&AVPOPS_VAL_PVAR)
	{
		/* the 2nd operator is variable -> get value */
		if(val->u.sval.type==PVT_AVP)
		{
			/* search for the avp */
			if(avpops_get_aname(msg, val, &avp_name2, &name_type2)!=0)
			{
				LM_ERR("failed to get dst AVP name\n");
				goto error;
			}
			avp2 = search_first_avp( name_type2, avp_name2, &op_val, 0);
			while(avp2!=0)
			{
				if(!(avp2->flags&AVP_VAL_STR))
					break;
				avp2 = search_first_avp( name_type2, avp_name2, &op_val, avp2);
			}
			if (avp2==0)
			{
				LM_DBG("no dst avp found\n");
				goto error;
			}
		} else {
			avp2 = 0;
			if(pv_get_spec_value(msg, &(val->u.sval), &xvalue)!=0)
			{
				LM_ERR("cannot get dst value\n");
				goto error;
			}
			if(xvalue.flags&PV_TYPE_INT)
			{
				op_val.n = xvalue.ri;
			} else {
				LM_ERR("dst value is str\n");
				goto error;
			}
		}
	} else {
		if(val->type == AVPOPS_VAL_INT)
			op_val.n = val->u.n;
		else
			op_val.s = val->u.s;
		avp2 = 0;
	}

cycle2:
	/* do operation */
	LM_DBG(" use <%d> and <%d>\n",
			avp_val.n, op_val.n);
	if (val->ops&AVPOPS_OP_ADD)
	{
		result = avp_val.n+op_val.n;
	} else 	if (val->ops&AVPOPS_OP_SUB) {
		result = avp_val.n-op_val.n;
	} else  if (val->ops&AVPOPS_OP_MUL) {
		result = avp_val.n*op_val.n;
	} else if (val->ops&AVPOPS_OP_DIV) {
		if(op_val.n!=0)
			result = (int)(avp_val.n/op_val.n);
		else
		{
			LM_ERR("division by 0\n");
			result = 0;
		}
	} else if (val->ops&AVPOPS_OP_MOD) {
		if(op_val.n!=0)
			result = avp_val.n%op_val.n;
		else
		{
			LM_ERR("modulo by 0\n");
			result = 0;
		}
	} else if (val->ops&AVPOPS_OP_BAND) {
		result = avp_val.n&op_val.n;
	} else if (val->ops&AVPOPS_OP_BOR) {
		result = avp_val.n|op_val.n;
	} else if (val->ops&AVPOPS_OP_BXOR) {
		result = avp_val.n^op_val.n;
	} else if (val->ops&AVPOPS_OP_BNOT) {
		result = ~op_val.n;
	} else {
		LM_CRIT("unknown operation (flg=%d)\n",val->ops);
		goto error;
	}

	/* add the new avp */
	avp_val.n = result;
	if(add_avp(name_type3, avp_name3, avp_val)==-1 ) {
		LM_ERR("failed to create new avp\n");
		goto error;
	}

	/* cycle for the second value (only if avp can have multiple vals) */
	while((avp2!=NULL)
		&&(avp2=search_first_avp( name_type2, avp_name2, &op_val, avp2))!=0)
	{
		if(!(avp2->flags&AVP_VAL_STR))
			goto cycle2;
	}
	prev_avp = avp1;
	/* cycle for the first value -> next avp */
	while((avp1!=NULL)
		&&(avp1=search_first_avp(name_type1, avp_name1, &avp_val, avp1))!=0)
	{
		if (!(avp1->flags&AVP_VAL_STR))
		{
			if(val->ops&AVPOPS_FLAG_DELETE && prev_avp!=0)
			{
				destroy_avp(prev_avp);
				prev_avp = 0;
			}
			goto cycle1;
		}
	}
	LM_DBG("done\n");
	if(val->ops&AVPOPS_FLAG_DELETE && prev_avp!=0)
	{
		destroy_avp(prev_avp);
		prev_avp = 0;
	}
	return 1;

error:
	return -1;
}

int ops_is_avp_set(struct sip_msg* msg, struct fis_param *ap)
{
	struct usr_avp *avp;
	unsigned short    name_type;
	int avp_name;
	int_str avp_value;
	int index;
	int findex;

	/* get avp name */
	if(avpops_get_aname(msg, ap, &avp_name, &name_type)!=0)
	{
		LM_ERR("failed to get AVP name\n");
		return -1;
	}

	/* get avp index */
	if(pv_get_spec_index(msg, &ap->u.sval.pvp, &index, &findex)!=0)
	{
		LM_ERR("failed to get AVP index\n");
		return -1;
	}

	avp=search_first_avp(name_type, avp_name, &avp_value, 0);
	if(avp==0)
		return -1;

	do {
		/* last index [-1] or all [*] go here as well */
		if(index<=0)
		{
			if(ap->ops&AVPOPS_FLAG_ALL)
				return 1;
			if((ap->ops&AVPOPS_FLAG_CASTS && !(avp->flags&AVP_VAL_STR))
					||(ap->ops&AVPOPS_FLAG_CASTN && avp->flags&AVP_VAL_STR))
				return -1;
			if(ap->ops&AVPOPS_FLAG_EMPTY)
			{
				if(avp->flags&AVP_VAL_STR)
				{
					if(avp_value.s.s==0 || avp_value.s.len==0)
						return 1;
					else
						return -1;
				} else {
					if(avp_value.n==0)
						return 1;
					else
						return -1;
				}
			}
			return 1;
		}
		index--;
	} while ((avp=search_first_avp(name_type, avp_name, &avp_value, avp))!=0);

	return -1;
}
