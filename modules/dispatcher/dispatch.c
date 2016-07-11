/*
 * dispatcher module
 *
 * Copyright (C) 2010-2015 OpenSIPS Solutions
 * Copyright (C) 2005-2010 Voice-System.ro
 * Copyright (C) 2004-2006 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 * 2004-07-31  first version, by daniel
 * 2005-04-22  added ruri  & to_uri hashing (andrei)
 * 2005-12-10  added failover support via avp (daniel)
 * 2006-08-15  added support for authorization username hashing (carsten)
 * 2007-01-11  Added a function to check if a specific gateway is in a
 *             group (carsten)
 * 2007-01-12  Added a threshhold for automatic deactivation (carsten)
 * 2007-02-09  Added active probing of failed destinations and automatic
 *             re-enabling of destinations (carsten)
 * 2007-05-08  Ported the changes to SVN-Trunk, renamed ds_is_domain to
 *             ds_is_from_list and modified the function to work with IPv6 adresses.
 * 2007-07-18  removed index stuff
 *             added DB support to load/reload data(ancuta)
 * 2007-09-17  added list-file support for reload data (carstenbock)
 * 2009-05-18  Added support for weights for the destinations;
 *             added support for custom "attrs" (opaque string) (bogdan)
 * 2013-12-02  Added support state persistency (restart and reload) (bogdan)
 * 2013-12-05  Added a safer reload mechanism based on locking read/writter (bogdan)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../ut.h"
#include "../../trim.h"
#include "../../dprint.h"
#include "../../action.h"
#include "../../route.h"
#include "../../dset.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../usr_avp.h"
#include "../../mi/mi.h"
#include "../../parser/digest/digest.h"
#include "../../resolve.h"
#include "../tm/tm_load.h"
#include "../../db/db.h"
#include "../../db/db_res.h"
#include "../../str.h"
#include "../../rw_locking.h"

#include "dispatch.h"
#include "ds_bl.h"

#define DS_TABLE_VERSION	6

extern struct socket_info *probing_sock;
extern event_id_t dispatch_evi_id;

extern int ds_force_dst;

static db_func_t ds_dbf;
static db_con_t* ds_db_handle=0;

/* dispatching data holder */
static ds_data_t **ds_data = NULL;
/* reader-writers lock for reloading the data */
static rw_lock_t *ds_lock = NULL;

#define dst_is_active(_dst) \
	(!((_dst).flags&(DS_INACTIVE_DST|DS_PROBING_DST)))

int init_ds_data(void)
{
	ds_data = (ds_data_t**)shm_malloc( sizeof(ds_data_t*) );
	if (ds_data==NULL) {
		LM_ERR("failed to allocate data holder in shm\n");
		return -1;
	}

	*ds_data = NULL;

	/* create & init lock */
	if ((ds_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init reader/writer lock\n");
		return -1;
	}

	return 0;
}


/* destroy entire dispatching data */
static void ds_destroy_data_set( ds_data_t *d)
{
	ds_set_p  sp;
	ds_set_p  sp_curr;
	ds_dest_p dest;

	/* free the list of sets */
	sp = d->sets;
	while(sp) {
		sp_curr = sp;
		sp = sp->next;

		dest = sp_curr->dlist;
		if (dest) {
			do {
				if(dest->uri.s!=NULL)
					shm_free(dest->uri.s);
				if(dest->param)
					shm_free(dest->param);
				dest = dest->next;
			}while(dest);
			shm_free(sp_curr->dlist);
		}
		shm_free(sp_curr);
	}

	/* free the data holder */
	shm_free(d);
}


/* destroy current dispatching data */
void ds_destroy_data(void)
{
	if (ds_data && *ds_data)
		ds_destroy_data_set( *ds_data );

	/* destroy rw lock */
	if (ds_lock) {
		lock_destroy_rw( ds_lock );
		ds_lock = 0;
	}
}


int add_dest2list(int id, str uri, struct socket_info *sock, int state,
							int weight, str attrs, ds_data_t *d_data)
{
	ds_dest_p dp = NULL;
	ds_set_p  sp = NULL;
	struct sip_uri puri;

	/* For DNS-Lookups */
	struct proxy_l *proxy;
	union sockaddr_union sau;

	/* check uri */
	if(parse_uri(uri.s, uri.len, &puri)!=0 || puri.host.len>254)
	{
		LM_ERR("bad uri [%.*s]\n", uri.len, uri.s);
		goto err;
	}

	/* get dest set */
	for( sp=d_data->sets ; sp ; sp=sp->next) {
		if(sp->id == id)
			break;
	}

	if(sp==NULL)
	{
		sp = (ds_set_p)shm_malloc(sizeof(ds_set_t));
		if(sp==NULL)
		{
			LM_ERR("no more memory.\n");
			goto err;
		}

		memset(sp, 0, sizeof(ds_set_t));
		sp->next = d_data->sets;
		d_data->sets = sp;
		d_data->sets_no++;
		sp->id = id;
	}

	dp = (ds_dest_p)shm_malloc(sizeof(ds_dest_t));
	if(dp==NULL)
	{
		LM_ERR("no more memory!\n");
		goto err;
	}
	memset(dp, 0, sizeof(ds_dest_t));

	/* store uri and attrs strings */
	dp->uri.s = (char*)shm_malloc( (uri.len+1+attrs.len+1)*sizeof(char));
	if(dp->uri.s==NULL)
	{
		LM_ERR("no more shm memory!\n");
		goto err;
	}
	memcpy(dp->uri.s, uri.s, uri.len);
	dp->uri.s[uri.len]='\0';
	dp->uri.len = uri.len;
	if (attrs.len) {
		dp->attrs.s = dp->uri.s + dp->uri.len + 1;
		memcpy(dp->attrs.s, attrs.s, attrs.len);
		dp->attrs.s[attrs.len]='\0';
		dp->attrs.len = attrs.len;
	}

	/* copy state, weight & socket */
	dp->sock = sock;
	dp->weight = weight;
	switch (state) {
		case 0:
			dp->flags = 0;
			break;
		case 1:
			dp->flags = DS_INACTIVE_DST;
			break;
		case 2:
			dp->flags = DS_PROBING_DST;
			break;
		default:
			LM_CRIT("BUG: unknown state %d for destination %.*s\n",
				state, uri.len, uri.s);
	}

	/* Do a DNS-Lookup for the Host-Name: */
	proxy = mk_proxy( &puri.host, puri.port_no, puri.proto,
		(puri.type==SIPS_URI_T));
	if (proxy==NULL) {
		LM_ERR("could not resolve %.*s, skipping it\n",
			puri.host.len, puri.host.s);
		goto err;
	}
	hostent2ip_addr( &dp->ips[0], &proxy->host, proxy->addr_idx);
	dp->ports[0] = proxy->port;
	dp->protos[0] = proxy->proto;
	dp->ips_cnt = 1;
	LM_DBG("first gw ip addr [%s]:%d\n",
		ip_addr2a(&dp->ips[0]), dp->ports[0]);
	/* get the next available IPs from DNS */
	while (dp->ips_cnt<DS_MAX_IPS && (get_next_su( proxy, &sau, 0)==0) ) {
		su2ip_addr( &dp->ips[dp->ips_cnt], &sau);
		dp->ports[dp->ips_cnt] = proxy->port;
		dp->protos[dp->ips_cnt] = proxy->proto;
		LM_DBG("additional gw ip addr [%s]:%d, proto %d\n",
			ip_addr2a(&dp->ips[dp->ips_cnt]),
			dp->ports[dp->ips_cnt], dp->protos[dp->ips_cnt]);
		/* one more IP found */
		dp->ips_cnt++;
	}
	/* free al the helper structures */
	free_proxy(proxy);
	pkg_free(proxy);

	dp->next = sp->dlist;
	sp->dlist = dp;
	sp->nr++;

	LM_DBG("dest [%d/%d] <%.*s> successfully loaded\n", sp->id, sp->nr, dp->uri.len, dp->uri.s);

	return 0;
err:
	/* free allocated memory */
	if(dp!=NULL)
	{
		if(dp->uri.s!=NULL)
			shm_free(dp->uri.s);
		shm_free(dp);
	}
	return -1;
}


/* iterates the whole set and calculates (1) the number of
   active destinations and (2) the running and total weight
   sum for the active destinations */
static inline void re_calculate_active_dsts(ds_set_p sp)
{
	int j,i;

	/* pre-calculate the running weights for each destination */
	for( j=0,i=-1,sp->active_nr=sp->nr ; j<sp->nr ; j++ ) {
		/* running weight is the current weight plus the running weight of
		 * the previous element */
		sp->dlist[j].running_weight = sp->dlist[j].weight
			+ ((j==0) ? 0 : sp->dlist[j-1].running_weight);
		/* now the running weight for the active destinations */
		if ( dst_is_active(sp->dlist[j]) ) {
			sp->dlist[j].active_running_weight = sp->dlist[j].weight
				+ ((i==-1) ? 0 : sp->dlist[i].active_running_weight);
			i = j; /* last active destination */
		} else {
			sp->dlist[j].active_running_weight =
				((i==-1) ? 0 : sp->dlist[i].active_running_weight);
			sp->active_nr --;
		}
		LM_DBG("destination i=%d, j=%d , weight=%d, sum=%d, active_sum=%d\n",i,j,
			sp->dlist[j].weight,
			sp->dlist[j].running_weight,sp->dlist[j].active_running_weight);
	}
}


/* compact destinations from sets for fast access */
int reindex_dests( ds_data_t *d_data)
{
	int j;
	ds_set_p  sp = NULL;
	ds_dest_p dp = NULL, dp0= NULL;

	for( sp=d_data->sets ; sp!= NULL ; sp=sp->next )
	{
		if (sp->nr == 0) {
			dp0 = NULL;
			continue;
		}

		dp0 = (ds_dest_p)shm_malloc(sp->nr*sizeof(ds_dest_t));
		if(dp0==NULL)
		{
			LM_ERR("no more memory!\n");
			goto err1;
		}
		memset(dp0, 0, sp->nr*sizeof(ds_dest_t));

		/*copy from the old pointer to destination, and then free it*/
		for(j=sp->nr-1; j>=0 && sp->dlist!= NULL; j--)
		{
			memcpy(&dp0[j], sp->dlist, sizeof(ds_dest_t));
			if(j==sp->nr-1)
				dp0[j].next = NULL;
			else
				dp0[j].next = &dp0[j+1];

			dp = sp->dlist;
			sp->dlist = dp->next;

			shm_free(dp);
			dp=NULL;
		}

		sp->dlist=dp0;

		re_calculate_active_dsts(sp);

	}

	LM_DBG("found [%d] dest sets\n", d_data->sets_no);
	return 0;

err1:
	return -1;
}


/* variables used to generate the pvar name */
static int ds_has_pattern = 0;
static str ds_pattern_suffix = str_init("");
static str ds_pattern_prefix = str_init("");

void ds_pvar_parse_pattern(str pattern)
{
	char *p, *end;

	ds_pattern_suffix = pattern;
	end = pattern.s + pattern.len - DS_PV_ALGO_MARKER_LEN + 1;

	/* first try to see if we have the marker */
	for (p = pattern.s; p < end &&
			memcmp(p, DS_PV_ALGO_MARKER, DS_PV_ALGO_MARKER_LEN); p++);

	/* if reached end - pattern not present => pure pvar */
	if (p == end) {
		LM_DBG("Pattern not found\n");
		return;
	}

	ds_has_pattern = 1;
	ds_pattern_suffix.len = p - pattern.s;

	/* skip marker */
	ds_pattern_prefix.s = p + DS_PV_ALGO_MARKER_LEN;
	ds_pattern_prefix.len = pattern.s + pattern.len - ds_pattern_prefix.s;
}


ds_pvar_param_p ds_get_pvar_param(str uri)
{
	str name;
	int len = ds_pattern_suffix.len + uri.len + ds_pattern_prefix.len;
	char buf[len]; /* XXX: check if this works for all compilers */
	ds_pvar_param_p param;

	if (ds_has_pattern) {
		name.len = 0;
		name.s = buf;
		memcpy(buf, ds_pattern_suffix.s, ds_pattern_suffix.len);
		name.len = ds_pattern_suffix.len;
		memcpy(name.s + name.len, uri.s, uri.len);
		name.len += uri.len;
		memcpy(name.s + name.len, ds_pattern_prefix.s, ds_pattern_prefix.len);
		name.len += ds_pattern_prefix.len;
	}

	param = shm_malloc(sizeof(ds_pvar_param_t));
	if (!param) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}

	if (!pv_parse_spec(ds_has_pattern ? &name : &ds_pattern_suffix, &param->pvar)) {
		LM_ERR("cannot parse pattern spec\n");
		shm_free(param);
		return NULL;
	}

	return param;
}


int ds_pvar_algo(struct sip_msg *msg, ds_set_p set, ds_dest_p **sorted_set)
{
	pv_value_t val;
	int i, j, k, end_idx, cnt;
	ds_dest_p *sset;
	ds_pvar_param_p param;

	if (!set) {
		LM_ERR("invalid set\n");
		return -1;
	}
	sset = shm_realloc(*sorted_set, set->nr * sizeof(ds_dest_p));
	if (!sset) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	*sorted_set = sset;

	end_idx = set->nr - 1;
	if (ds_use_default) {
		sset[end_idx] = &set->dlist[end_idx];
		end_idx--;
	}

	for (i = 0, cnt = 0; i < set->nr - (ds_use_default?1:0); i++) {
		if ( !dst_is_active(set->dlist[i]) ) {
			/* move to the end of the list */
			sset[end_idx--] = &set->dlist[i];
			continue;
		}

		/* if pvar not set - try to evaluate it */
		if (set->dlist[i].param == NULL) {
			param = ds_get_pvar_param(set->dlist[i].uri);
			if (param == NULL) {
				LM_ERR("cannot parse pvar for uri %.*s\n",
					   set->dlist[i].uri.len, set->dlist[i].uri.s);
				continue;
			}
			set->dlist[i].param = (void *)param;
		} else {
			param = (ds_pvar_param_p)set->dlist[i].param;
		}
		if (pv_get_spec_value(msg, &param->pvar, &val) < 0) {
			LM_ERR("cannot get spec value for spec %.*s\n",
				   set->dlist[i].uri.len, set->dlist[i].uri.s);
			continue;
		}
		if (!(val.flags & PV_VAL_NULL)) {
			if (!(val.flags & PV_VAL_INT)) {
				/* last attempt to retrieve value */
				if (!str2sint(&val.rs, &param->value)) {
					LM_ERR("invalid pvar value type - not int\n");
					continue;
				}
			} else {
				param->value = val.ri;
			}
		} else {
			param->value = 0;
		}
		/* search the proper position */
		j = 0;
		for (; j < cnt && ((ds_pvar_param_p)sset[j]->param)->value <= param->value; j++);
		/* make space for the new entry */
		for (k = cnt; k > j; k--)
			sset[k] = sset[k - 1];
		sset[j] = &set->dlist[i];
		cnt++;
	}

	return cnt;
}


int ds_connect_db(void)
{
	if(!ds_db_url.s)
		return -1;

	if (ds_db_handle)
	{
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}

	if ((ds_db_handle = ds_dbf.init(&ds_db_url)) == 0)
			return -1;

	return 0;
}


void ds_disconnect_db(void)
{
	if(ds_db_handle)
	{
		ds_dbf.close(ds_db_handle);
		ds_db_handle = 0;
	}
}


/*initialize and verify DB stuff*/
int init_ds_db(void)
{
	int _ds_table_version;

	if(ds_table_name.s == 0){
		LM_ERR("invalid database name\n");
		return -1;
	}

	/* Find a database module */
	if (db_bind_mod(&ds_db_url, &ds_dbf) < 0) {
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if(ds_connect_db()!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	_ds_table_version = db_table_version(&ds_dbf, ds_db_handle, &ds_table_name);
	if (_ds_table_version < 0) {
		LM_ERR("failed to query table version\n");
		return -1;
	} else if (_ds_table_version != DS_TABLE_VERSION) {
		LM_ERR("invalid table version (found %d , required %d)\n"
			"(use opensipsdbctl reinit)\n",
			_ds_table_version, DS_TABLE_VERSION );
		return -1;
	}

	return 0;
}


static void ds_inherit_state( ds_data_t *old_data , ds_data_t *new_data)
{
	ds_set_p new_set, old_set;
	ds_dest_p new_ds, old_ds;

	/* search the new sets through the old sets */
	for ( new_set=new_data->sets ; new_set ; new_set=new_set->next ) {
		for ( old_set=old_data->sets ; old_set ; old_set=old_set->next ) {
			if (new_set->id==old_set->id)
				break;
		}
		if (old_set==NULL) {
			LM_DBG("new set id %d not found in old sets\n",new_set->id);
			continue;
		}
		LM_DBG("set id %d found in old sets\n",new_set->id);

		/* sets are matching, try to match the destinations, one by one */
		for ( new_ds=new_set->dlist ; new_ds ; new_ds=new_ds->next ) {
			for ( old_ds=old_set->dlist ; old_ds ; old_ds=old_ds->next ) {
				if (new_ds->uri.len==old_ds->uri.len &&
				strncasecmp(new_ds->uri.s, old_ds->uri.s, old_ds->uri.len)==0 ) {
					LM_DBG("DST <%.*s> found in old set, copying state\n",
						new_ds->uri.len,new_ds->uri.s);
					new_ds->flags = old_ds->flags;
					break;
				}
			}
			if (old_ds==NULL)
				LM_DBG("DST <%.*s> not found in old set\n",
					new_ds->uri.len,new_ds->uri.s);
		}
	}
}


void ds_flusher_routine(unsigned int ticks, void* param)
{
	db_key_t key_cmp;
	db_val_t val_cmp;
	db_key_t key_set;
	db_val_t val_set;
	ds_set_p list;
	int j;

	if (ds_db_handle==NULL)
		return;

	val_cmp.type = DB_STR;
	val_cmp.nul  = 0;

	val_set.type = DB_INT;
	val_set.nul  = 0;

	/* update the gateways */
	if (ds_dbf.use_table(ds_db_handle, &ds_table_name) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n",
			ds_table_name.len, ds_table_name.s);
		return;
	}
	key_cmp = &ds_dest_uri_col;
	key_set = &ds_dest_state_col;

	if (*ds_data) {
		/* Iterate over the groups and the entries of each group */
		for(list = (*ds_data)->sets; list!= NULL; list= list->next) {
			for(j=0; j<list->nr; j++) {
				/* If the Flag of the entry is STATE_DIRTY -> flush do db */
				if ( (list->dlist[j].flags&DS_STATE_DIRTY_DST)==0 )
					/* nothing to do for this destination */
					continue;

				/* populate the update */
				val_cmp.val.str_val = list->dlist[j].uri;
				val_set.val.int_val =
					(list->dlist[j].flags&DS_INACTIVE_DST) ? 1 : ((list->dlist[j].flags&DS_PROBING_DST)?2:0);

				/* update the state of this gateway */
				LM_DBG("updating the state of destination <%.*s> to %d\n",
					list->dlist[j].uri.len, list->dlist[j].uri.s, val_set.val.int_val);

				if ( ds_dbf.update(ds_db_handle,&key_cmp,0,&val_cmp,&key_set,&val_set,1,1)<0 ) {
					LM_ERR("DB update failed\n");
				} else {
					list->dlist[j].flags &= ~DS_STATE_DIRTY_DST;
				}
			}
		}
	}

	return;
}


/*load groups of destinations from DB*/
static ds_data_t* ds_load_data(void)
{
	ds_data_t *d_data;
	int i, id, nr_rows, cnt;
	int state;
	int weight;
	struct socket_info *sock;
	str uri;
	str attrs;
	str host;
	int port, proto;
	db_res_t * res = NULL;
	db_val_t * values;
	db_row_t * rows;

	db_key_t query_cols[6] = {&ds_set_id_col, &ds_dest_uri_col,
			&ds_dest_sock_col, &ds_dest_state_col,
			&ds_dest_weight_col, &ds_dest_attrs_col};

	if(ds_db_handle == NULL){
			LM_ERR("invalid DB handler\n");
			return NULL;
	}

	if (ds_dbf.use_table(ds_db_handle, &ds_table_name) < 0) {
		LM_ERR("error in use_table\n");
		return NULL;
	}

	d_data = (ds_data_t*)shm_malloc( sizeof(ds_data_t) );
	if (d_data==NULL) {
		LM_ERR("failed to allocate new data structure in shm\n");
		return NULL;
	}
	memset( d_data, 0, sizeof(ds_data_t));

	/*select the whole table and all the columns*/
	if(ds_dbf.query(ds_db_handle,0,0,0,query_cols,0,6,0,&res) < 0) {
		LM_ERR("error while querying database\n");
		goto error;
	}

	nr_rows = RES_ROW_N(res);
	rows = RES_ROWS(res);
	if(nr_rows == 0) {
		LM_WARN("no dispatching data in the db -- empty destination set\n");
		goto load_done;
	}

	cnt = 0;

	for(i=0; i<nr_rows; i++) {

		values = ROW_VALUES(rows+i);

		/* id */
		if (VAL_NULL(values)) {
			LM_ERR("ds ID column cannot be NULL -> skipping\n");
			continue;
		}
		id = VAL_INT(values);

		/* uri */
		get_str_from_dbval( "URI", values+1,
			1/*not_null*/, 1/*not_empty*/, uri, error2);

		/* sock */
		get_str_from_dbval( "SOCKET", values+2,
			0/*not_null*/, 0/*not_empty*/, attrs, error2);
		if ( attrs.len ) {
			if (parse_phostport( attrs.s, attrs.len, &host.s, &host.len,
			&port, &proto)!=0){
				LM_ERR("socket description <%.*s> is not valid -> ignoring\n",
					attrs.len,attrs.s);
				sock = NULL;
			} else {
				sock = grep_sock_info( &host, port, proto);
				if (sock == NULL) {
					LM_ERR("socket <%.*s> is not local to opensips (we must "
						"listen on it) -> ignoring it\n", attrs.len, attrs.s);
				}
			}
		} else {
			sock = NULL;
		}

		/* state */
		if (VAL_NULL(values+3)) {
			state = 0;
		} else {
			state = VAL_INT(values+3);
		}

		/* weight */
		if (VAL_NULL(values+4)) {
			weight = 1;
		} else {
			weight = VAL_INT(values+4);
		}

		/* attrs */
		get_str_from_dbval( "ATTRIBUTES", values+5,
			0/*not_null*/, 0/*not_empty*/, attrs, error2);

		if (add_dest2list(id, uri, sock, state, weight, attrs, d_data) != 0) {
			LM_WARN("failed to add destination <%.*s> in group %d\n",uri.len,uri.s,id);
			continue;
		} else {
			cnt ++;
		}

	}

	if (cnt==0) {
		LM_WARN("No record loaded from db, running on empty set\n");
	} else {
		if(reindex_dests( d_data )!=0) {
			LM_ERR("error on reindex\n");
			goto error2;
		}
	}

load_done:
	ds_dbf.free_result(ds_db_handle, res);
	return d_data;

error:
	ds_destroy_data_set( d_data );
error2:
	ds_dbf.free_result(ds_db_handle, res);
	return NULL;
}


int ds_reload_db(void)
{
	ds_data_t *old_data;
	ds_data_t *new_data;

	new_data = ds_load_data();
	if (new_data==NULL) {
		LM_ERR("failed to load the new data, dropping the reload\n");
		return -1;
	}

	lock_start_write( ds_lock );

	/* no more activ readers -> do the swapping */
	old_data = *ds_data;
	*ds_data = new_data;

	lock_stop_write( ds_lock );

	/* destroy old data */
	if (old_data) {
		/* copy the state of the destinations from the old set
		 * (for the matching ids) */
		ds_inherit_state( old_data, new_data);
		ds_destroy_data_set( old_data );
	}

	/* update the Black Lists with the new gateways */
	populate_ds_bls( new_data->sets );

	return 0;
}


/**
 *
 */
unsigned int ds_get_hash(str *x, str *y)
{
	char* p;
	register unsigned v;
	register unsigned h;

	if(!x && !y)
		return 0;
	h=0;
	if(x)
	{
		p=x->s;
		if (x->len>=4)
		{
			for (; p<=(x->s+x->len-4); p+=4)
			{
				v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
				h+=v^(v>>3);
			}
		}
		v=0;
		for (;p<(x->s+x->len); p++)
		{
			v<<=8;
			v+=*p;
		}
		h+=v^(v>>3);
	}
	if(y)
	{
		p=y->s;
		if (y->len>=4)
		{
			for (; p<=(y->s+y->len-4); p+=4)
			{
				v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
				h+=v^(v>>3);
			}
		}

		v=0;
		for (;p<(y->s+y->len); p++)
		{
			v<<=8;
			v+=*p;
		}
		h+=v^(v>>3);
	}
	h=((h)+(h>>11))+((h>>13)+(h>>23));

	return (h)?h:1;
}


/*
 * gets the part of the uri we will use as a key for hashing
 * params:  key1       - will be filled with first part of the key
 *                       (uri user or "" if no user)
 *          key2       - will be filled with the second part of the key
 *                       (uri host:port)
 *          uri        - str with the whole uri
 *          parsed_uri - struct sip_uri pointer with the parsed uri
 *                       (it must point inside uri). It can be null
 *                       (in this case the uri will be parsed internally).
 *          flags  -    if & DS_HASH_USER_ONLY, only the user part of the uri
 *                      will be used
 * returns: -1 on error, 0 on success
 */
static inline int get_uri_hash_keys(str* key1, str* key2,
							str* uri, struct sip_uri* parsed_uri, int flags)
{
	struct sip_uri tmp_p_uri; /* used only if parsed_uri==0 */
	unsigned short proto;

	if (parsed_uri==0)
	{
		if (parse_uri(uri->s, uri->len, &tmp_p_uri)<0)
		{
			LM_ERR("invalid uri %.*s\n", uri->len, uri->len?uri->s:"");
			goto error;
		}
		parsed_uri=&tmp_p_uri;
	}
	/* uri sanity checks */
	if (parsed_uri->host.s==0)
	{
			LM_ERR("invalid uri, no host present: %.*s\n",
					uri->len, uri->len?uri->s:"");
			goto error;
	}

	/* we want: user@host:port if port is not the defaut one
	 *          user@host if port is the default one
	 *          user if the user flag is set*/
	*key1=parsed_uri->user;
	key2->s=0;
	key2->len=0;
	if (!(flags & DS_HASH_USER_ONLY))
	{	/* key2=host */
		*key2=parsed_uri->host;
		/* add port if needed */
		if (parsed_uri->port.s!=0)
		{ /* uri has a port */
			/* skip port if the default one ( first extract proto from URI) */
			if ( get_uri_port(parsed_uri, &proto) &&
			parsed_uri->port_no != (proto==PROTO_TLS)?SIPS_PORT:SIP_PORT )
				key2->len+=parsed_uri->port.len+1 /* ':' */;
		}
	}
	if (key1->s==0)
	{
		LM_WARN("empty username in: %.*s\n", uri->len, uri->len?uri->s:"");
	}
	return 0;
error:
	return -1;
}



/**
 *
 */
int ds_hash_fromuri(struct sip_msg *msg, unsigned int *hash)
{
	str from;
	str key1;
	str key2;

	if(msg==NULL || hash == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(parse_from_header(msg)<0)
	{
		LM_ERR("cannot parse From hdr\n");
		return -1;
	}

	if(msg->from==NULL || get_from(msg)==NULL)
	{
		LM_ERR("cannot get From uri\n");
		return -1;
	}

	from   = get_from(msg)->uri;
	trim(&from);
	if (get_uri_hash_keys(&key1, &key2, &from, 0, ds_flags)<0)
		return -1;
	*hash = ds_get_hash(&key1, &key2);

	return 0;
}



/**
 *
 */
int ds_hash_touri(struct sip_msg *msg, unsigned int *hash)
{
	str to;
	str key1;
	str key2;

	if(msg==NULL || hash == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}
	if ((msg->to==0) && ((parse_headers(msg, HDR_TO_F, 0)==-1) ||
				(msg->to==0)))
	{
		LM_ERR("cannot parse To hdr\n");
		return -1;
	}


	to   = get_to(msg)->uri;
	trim(&to);

	if (get_uri_hash_keys(&key1, &key2, &to, 0, ds_flags)<0)
		return -1;
	*hash = ds_get_hash(&key1, &key2);

	return 0;
}



/**
 *
 */
int ds_hash_callid(struct sip_msg *msg, unsigned int *hash)
{
	str cid;
	if(msg==NULL || hash == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
				(msg->callid==NULL)) )
	{
		LM_ERR("cannot parse Call-Id\n");
		return -1;
	}

	cid.s   = msg->callid->body.s;
	cid.len = msg->callid->body.len;
	trim(&cid);

	*hash = ds_get_hash(&cid, NULL);

	return 0;
}



int ds_hash_ruri(struct sip_msg *msg, unsigned int *hash)
{
	str* uri;
	str key1;
	str key2;


	if(msg==NULL || hash == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}
	if (parse_sip_msg_uri(msg)<0){
		LM_ERR("bad request uri\n");
		return -1;
	}

	uri=GET_RURI(msg);
	if (get_uri_hash_keys(&key1, &key2, uri, &msg->parsed_uri, ds_flags)<0)
		return -1;

	*hash = ds_get_hash(&key1, &key2);
	return 0;
}


int ds_hash_authusername(struct sip_msg *msg, unsigned int *hash)
{
	/* Header, which contains the authorization */
	struct hdr_field* h = 0;
	/* The Username */
	str username = {0, 0};
	/* The Credentials from this request */
	auth_body_t* cred;

	if(msg==NULL || hash == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}
	if (parse_headers(msg, HDR_PROXYAUTH_F, 0) == -1)
	{
		LM_ERR("error parsing headers!\n");
		return -1;
	}
	if (msg->proxy_auth && !msg->proxy_auth->parsed)
		parse_credentials(msg->proxy_auth);
	if (msg->proxy_auth && msg->proxy_auth->parsed) {
		h = msg->proxy_auth;
	}
	if (!h)
	{
		if (parse_headers(msg, HDR_AUTHORIZATION_F, 0) == -1)
		{
			LM_ERR("error parsing headers!\n");
			return -1;
		}
		if (msg->authorization && !msg->authorization->parsed)
			parse_credentials(msg->authorization);
		if (msg->authorization && msg->authorization->parsed) {
			h = msg->authorization;
		}
	}
	if (!h)
	{
		LM_DBG("No Authorization-Header!\n");
		return 1;
	}

	cred=(auth_body_t*)(h->parsed);
	if (!cred || !cred->digest.username.user.len)
	{
		LM_ERR("No Authorization-Username or Credentials!\n");
		return 1;
	}

	username.s = cred->digest.username.user.s;
	username.len = cred->digest.username.user.len;

	trim(&username);

	*hash = ds_get_hash(&username, NULL);

	return 0;
}


int ds_hash_pvar(struct sip_msg *msg, unsigned int *hash)
{
	/* The String to create the hash */
	str hash_str = {0, 0};

	if(msg==NULL || hash == NULL || hash_param_model == NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}
	if (pv_printf_s(msg, hash_param_model, &hash_str)<0) {
		LM_ERR("error - cannot print the format\n");
		return -1;
	}

	/* Remove empty spaces */
	trim(&hash_str);
	if (hash_str.len <= 0) {
		LM_ERR("String is empty!\n");
		return -1;
	}
	LM_DBG("Hashing %.*s!\n", hash_str.len, hash_str.s);

	*hash = ds_get_hash(&hash_str, NULL);

	return 0;
}


static inline int ds_get_index(int group, ds_set_p *index)
{
	ds_set_p si = NULL;

	if(index==NULL || group<0 || (*ds_data)->sets==NULL)
		return -1;

	/* get the index of the set */
	for ( si=(*ds_data)->sets ; si ; si = si->next ) {
		if(si->id == group) {
			*index = si;
			break;
		}
	}

	if(si==NULL) {
		LM_ERR("destination set [%d] not found\n", group);
		return -1;
	}

	return 0;
}


static inline int ds_update_dst(struct sip_msg *msg, str *uri,
										struct socket_info *sock, int mode)
{
	struct action act;

	switch(mode)
	{
		case 1:
			act.type = SET_HOSTPORT_T;
			act.elem[0].type = STR_ST;
			act.elem[0].u.s = *uri;
			if (uri->len>4 && strncasecmp(uri->s,"sip:",4)==0) {
				act.elem[0].u.s.s += 4;
				act.elem[0].u.s.len -= 4;
			}
			act.next = 0;

			if (do_action(&act, msg) < 0) {
				LM_ERR("error while setting host\n");
				return -1;
			}
			break;
		default:
			if (set_dst_uri(msg, uri) < 0) {
				LM_ERR("error while setting dst uri\n");
				return -1;
			}
		break;
	}
	if (sock)
		msg->force_send_socket = sock;
	return 0;
}

static int is_default_destination_entry(ds_set_p idx, int i) {
	return ds_use_default!=0 && i==(idx->nr-1);
}

static int count_inactive_destinations(ds_set_p idx) {
	int count = 0, i;

	for(i=0; i<idx->nr; i++)
		if( !dst_is_active(idx->dlist[i]) )
			/* only count inactive entries that are not default */
			if(!is_default_destination_entry(idx, i))
				count++;

	return count;
}


static inline int push_ds_2_avps( ds_dest_t *ds )
{
	char buf[2+16+1]; /* a hexa string */
	int_str avp_val;

	avp_val.s.len = 1 + sprintf( buf, "%p", ds->sock );
	avp_val.s.s = buf;
	if(add_avp(AVP_VAL_STR|sock_avp_type, sock_avp_name, avp_val)!=0) {
		LM_ERR("failed to add SOCK avp\n");
		return -1;
	}

	avp_val.s = ds->uri;
	if(add_avp(AVP_VAL_STR|dst_avp_type, dst_avp_name, avp_val)!=0) {
		LM_ERR("failed to add DST avp\n");
		return -1;
	}

	if (attrs_avp_name >= 0) {
		avp_val.s = ds->attrs;
		if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0) {
			LM_ERR("failed to add ATTR avp\n");
			return -1;
		}
	}
	return 0;
}


/**
 *
 */
int ds_select_dst(struct sip_msg *msg, ds_select_ctl_p ds_select_ctl)
{
	int i, j, cnt, i_unwrapped, set_size;
	unsigned int ds_hash, ds_rand;
	int_str avp_val;
	int ds_id;
	ds_set_p idx = NULL;
	int inactive_dst_count = 0;
	int destination_entries_to_skip = 0;
	/* used to sort the destinations for LB algo */
	ds_dest_p dest = NULL;
	ds_dest_p selected = NULL;
	static ds_dest_p *sorted_set = NULL;

	if(msg==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if ( (*ds_data)->sets==NULL) {
		LM_DBG("empty destination set\n");
		return -1;
	}

	if((ds_select_ctl->mode==0) && (ds_force_dst==0)
			&& (msg->dst_uri.s!=NULL || msg->dst_uri.len>0))
	{
		LM_ERR("destination already set [%.*s]\n", msg->dst_uri.len,
				msg->dst_uri.s);
		return -1;
	}

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	/* get the index of the set */
	if(ds_get_index(ds_select_ctl->set, &idx)!=0)
	{
		LM_ERR("destination set [%d] not found\n", ds_select_ctl->set);
		goto error;
	}

	if (idx->nr == 0) {
		LM_DBG("destination set [%d] is empty!\n", idx->id);
		goto error;
	}

	if (idx->active_nr == 0) {
		LM_DBG("no active destinations in set [%d] !\n", idx->id);
		goto error;
	}

	/* calculate the real size of the set, depending on the USE_DEFAULT value
	 * This size will be all the time higher than 0 (>=1) */
	set_size =  (ds_flags&DS_USE_DEFAULT && idx->nr>1) ? idx->nr-1 : idx->nr ;

	/* at this point we know for sure that we have
	 * at least one  active destination */

	LM_DBG("set [%d], using alg [%d], size [%d], used size [%d], "
		"active size [%d]\n", ds_select_ctl->set, ds_select_ctl->alg, idx->nr,
		set_size, idx->active_nr);

	/* hash value used for picking the destination */
	ds_hash = 0;
	/* id of the destination candidate (still to check if active) */
	ds_id = -1;
	/* final selected destination */
	selected = NULL;

	switch(ds_select_ctl->alg)
	{
		case 0:
			if(ds_hash_callid(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get callid hash\n");
				goto error;
			}
		break;
		case 1:
			if(ds_hash_fromuri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get From uri hash\n");
				goto error;
			}
		break;
		case 2:
			if(ds_hash_touri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get To uri hash\n");
				goto error;
			}
		break;
		case 3:
			if (ds_hash_ruri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get ruri hash\n");
				goto error;
			}
		break;
		case 4:
			/* round robin */
			ds_id = (idx->last+1) % set_size;
		break;
		case 5:
			i = ds_hash_authusername(msg, &ds_hash);
			switch (i)
			{
				case 0:
					/* Authorization-Header found: Nothing to be done here */
				break;
				case 1:
					/* No Authorization found: Use round robin */
					ds_id = idx->last;
					idx->last = (idx->last+1) % set_size;
				break;
				default:
					LM_ERR("can't get authorization hash\n");
					goto error;
				break;
			}
		break;
		case 6:
			ds_hash = rand();
		break;
		case 7:
			if (ds_hash_pvar(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get PV hash\n");
				goto error;
			}
		break;
		case 8:
			ds_id = 0;
		break;
		case 9:
			if (!ds_has_pattern && ds_pattern_suffix.len == 0 ) {
				LM_WARN("no pattern specified - using first entry...\n");
				ds_select_ctl->alg = 8;
				break;
			}
			if ((ds_id = ds_pvar_algo(msg, idx, &sorted_set)) <= 0)
			{
				LM_ERR("can't get destination index\n");
				goto error;
			}
			selected = sorted_set[0];
		break;
		default:
			LM_WARN("dispatching via [%d] with unknown algo [%d]"
					": defaulting to 0 - first entry\n",
					ds_select_ctl->set, ds_select_ctl->alg);
			ds_id = 0;
	}

	/* any destination selected yet? */
	if (selected==NULL) {

		LM_DBG("hash [%u], candidate [%d], weight sum [%u]\n",
			ds_hash, ds_id, idx->dlist[set_size-1].running_weight);

		/* any candidate selected yet */
		if (ds_id==-1) {
			/* no candidate yet -> do it based on hash and weights */
			if (idx->dlist[set_size-1].running_weight) {
				ds_rand = ds_hash % idx->dlist[set_size-1].running_weight;
				/* get the ds id based on weights */
				for( ds_id=0 ; ds_id<set_size ; ds_id++ )
					if (ds_rand<idx->dlist[ds_id].running_weight)
						break;
			} else {
				/* get a candidate simply based on hash */
				ds_id = ds_hash % set_size;
			}
		}

		LM_DBG("candidate is [%u]\n",ds_id);

		/* now we have a candidate, so we need to check if active or not */
		i=ds_id;
		while ( idx->dlist[i].flags&(DS_INACTIVE_DST|DS_PROBING_DST) ) {
			if (ds_hash==0) {
				/* for algs with no hash, simple get the next in the list */
				i = (i+1) % set_size;
			} else {
				/* use the hash and weights over active destinations only ;
				 * if USE_DEFAULT is set, do a -1 if the default (last)
				 * destination is active (we want to skip it) */
				cnt = idx->active_nr - (ds_flags&DS_USE_DEFAULT &&
					dst_is_active(idx->dlist[idx->nr-1]))?1:0 ;
				if (cnt) {
					/* weights or not ? */
					if (idx->dlist[set_size-1].active_running_weight) {
						ds_rand = ds_hash %
							idx->dlist[set_size-1].active_running_weight;
						/* get the ds id based on active weights */
						for( i=0 ; i<set_size ; i++ )
							if ( dst_is_active(idx->dlist[i]) &&
							(ds_rand<idx->dlist[i].active_running_weight) )
								break;
					} else {
						j = ds_hash % cnt;
						/* translate this index to the full set of dsts */
						for ( i=0 ; i<set_size ; i++ ) {
							if ( dst_is_active(idx->dlist[i]) ) j--;
							if (j<0) break;
						}
					}
				}
				/* i reflects the new candidate */
			}
			if(i==ds_id)
			{
				if(ds_use_default!=0)
				{
					i = idx->nr-1;
					if (!dst_is_active(idx->dlist[i]))
						goto error;
					break;
				} else {
					goto error;
				}
			}
		}
		LM_DBG("using destination [%u]\n",i);
		ds_id = i;
		selected = &idx->dlist[ds_id];
	}

	/* remember the last used destination */
	idx->last = ds_id;

	/* start pushing the destinations to SIP level */
	cnt = 0;

	if(ds_select_ctl->set_destination
		&& ds_update_dst(msg, &selected->uri, selected->sock, ds_select_ctl->mode)!=0)
	{
		LM_ERR("cannot set dst addr\n");
		goto error;
	}

	LM_DBG("selected [%d-%d/%d] <%.*s>\n", ds_select_ctl->alg, ds_select_ctl->set, ds_id,
			selected->uri.len, selected->uri.s);

	if(!(ds_flags&DS_FAILOVER_ON))
		goto done;

	if(ds_select_ctl->reset_AVP)
	{
		/* do some AVP cleanup before start populating new ones */
		destroy_avps( 0 /*all types*/, dst_avp_name, 1 /*all*/);
		destroy_avps( 0 /*all types*/, grp_avp_name, 1 /*all*/);
		destroy_avps( 0 /*all types*/, cnt_avp_name, 1 /*all*/);
		destroy_avps( 0 /*all types*/,sock_avp_name, 1 /*all*/);
		if (attrs_avp_name>0)
			destroy_avps( 0 /*all types*/,attrs_avp_name, 1 /*all*/);
		ds_select_ctl->reset_AVP = 0;
	}


	if(ds_use_default!=0 && ds_id!=idx->nr-1)
	{
		if (push_ds_2_avps( &idx->dlist[idx->nr-1] ) != 0 )
			goto error;
		cnt++;
	}

	inactive_dst_count = count_inactive_destinations(idx);
	/* don't count inactive and default entries into total */
	destination_entries_to_skip = idx->nr - inactive_dst_count - (ds_use_default!=0);
	destination_entries_to_skip -= ds_select_ctl->max_results;

	/* add to avp */

	for(i_unwrapped = ds_id-1+idx->nr; i_unwrapped>ds_id; i_unwrapped--) {
		i = i_unwrapped % idx->nr;
		dest = (ds_select_ctl->alg == 9 ? sorted_set[i] : &idx->dlist[i]);

		if ( !dst_is_active(*dest) ||
		(ds_use_default!=0 && i==(idx->nr-1)) )
			continue;
		if(destination_entries_to_skip > 0) {
			LM_DBG("skipped entry [%d/%d] (would create more than %i results)\n",
				ds_select_ctl->set, i, ds_select_ctl->max_results);
			destination_entries_to_skip--;
			continue;
		}

		LM_DBG("using entry [%d/%d]\n", ds_select_ctl->set, i);
		if (push_ds_2_avps( dest ) != 0 )
			goto error;
		cnt++;
	}

	/* add to avp the first used dst */
	avp_val.s = selected->uri;
	if(add_avp(AVP_VAL_STR|dst_avp_type, dst_avp_name, avp_val)!=0)
		goto error;
	cnt++;

done:
	if (attrs_avp_name>0) {
		avp_val.s = selected->attrs;
		if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0)
			goto error;
	}

	/* add to avp the group id */
	avp_val.n = ds_select_ctl->set;
	if(add_avp(grp_avp_type, grp_avp_name, avp_val)!=0)
		goto error;

	/* add to avp the number of dst */
	avp_val.n = cnt;
	if(add_avp(cnt_avp_type, cnt_avp_name, avp_val)!=0)
		goto error;

	lock_stop_read( ds_lock );
	return 1;

error:
	lock_stop_read( ds_lock );
	return -1;
}


int ds_next_dst(struct sip_msg *msg, int mode)
{
	struct socket_info *sock;
	struct usr_avp *avp;
	struct usr_avp *tmp_avp;
	struct usr_avp *attr_avp;
	int_str avp_value;
	int_str sock_avp_value;

	if(!(ds_flags&DS_FAILOVER_ON) || dst_avp_name < 0)
	{
		LM_WARN("failover support disabled\n");
		return -1;
	}

	tmp_avp = search_first_avp(dst_avp_type, dst_avp_name, NULL, 0);
	if(tmp_avp==NULL)
		return -1; /* used avp deleted -- strange */

	/* get AVP with next destination URI */
	avp = search_next_avp(tmp_avp, &avp_value);
	destroy_avp(tmp_avp);

	/* remove old attribute AVP (from prev destination) */
	if (attrs_avp_name >= 0) {
		attr_avp = search_first_avp(attrs_avp_type, attrs_avp_name, NULL, 0);
		if (attr_avp)
			destroy_avp(attr_avp);
	}

	if(avp==NULL || !(avp->flags&AVP_VAL_STR))
		return -1; /* no more avps or value is int */

	/* get AVP with next destination socket */
	tmp_avp = search_first_avp(sock_avp_type, sock_avp_name,
	&sock_avp_value, 0);
	if (!tmp_avp) {
		/* this shuold not happen, it is a bogus state */
		sock = NULL;
	} else {
		if (sscanf( sock_avp_value.s.s, "%p", (void**)&sock ) != 1)
			sock = NULL;
		destroy_avp(tmp_avp);
	}

	if(ds_update_dst(msg, &avp_value.s, sock, mode)!=0)
	{
		LM_ERR("cannot set dst addr\n");
		return -1;
	}
	LM_DBG("using [%.*s]\n", avp_value.s.len, avp_value.s.s);

	return 1;
}


int ds_mark_dst(struct sip_msg *msg, int mode)
{
	int group, ret;
	struct usr_avp *prev_avp;
	int_str avp_value;

	if(!(ds_flags&DS_FAILOVER_ON))
	{
		LM_WARN("failover support disabled\n");
		return -1;
	}

	prev_avp = search_first_avp(grp_avp_type, grp_avp_name, &avp_value, 0);

	if(prev_avp==NULL || prev_avp->flags&AVP_VAL_STR)
		return -1; /* grp avp deleted -- strange */
	group = avp_value.n;

	prev_avp = search_first_avp(dst_avp_type, dst_avp_name, &avp_value, 0);

	if(prev_avp==NULL || !(prev_avp->flags&AVP_VAL_STR))
		return -1; /* dst avp deleted -- strange */

	if(mode==1) {
		/* set as "active" */
		ret = ds_set_state(group, &avp_value.s,
				DS_INACTIVE_DST|DS_PROBING_DST, 0);
	} else if(mode==2) {
		ret = ds_set_state(group, &avp_value.s, DS_PROBING_DST, 1);
		if (ret == 0) ret = ds_set_state(group, &avp_value.s,
				DS_INACTIVE_DST, 0);
	} else {
		ret = ds_set_state(group, &avp_value.s, DS_INACTIVE_DST, 1);
		if (ret == 0) ret = ds_set_state(group, &avp_value.s,
				DS_PROBING_DST, 0);
	}

	LM_DBG("mode [%d] grp [%d] dst [%.*s]\n", mode, group, avp_value.s.len,
			avp_value.s.s);

	return (ret==0)?1:-1;
}

/* event parameters */
static str group_str = str_init("group");
static str address_str = str_init("address");
static str status_str = str_init("status");
static str inactive_str = str_init("inactive");
static str active_str = str_init("active");

int ds_set_state(int group, str *address, int state, int type)
{
	int i=0;
	ds_set_p idx = NULL;
	evi_params_p list = NULL;
	int old_flags;

	if ( (*ds_data)->sets==NULL ){
		LM_DBG("empty destination set\n");
		return -1;
	}

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	/* get the index of the set */
	if(ds_get_index(group, &idx)!=0) {
		LM_ERR("destination set [%d] not found\n", group);
		lock_stop_read( ds_lock );
		return -1;
	}

	while(i<idx->nr)
	{
		if(idx->dlist[i].uri.len==address->len
				&& strncasecmp(idx->dlist[i].uri.s, address->s,
					address->len)==0)
		{

			/* remove the Probing/Inactive-State? Set the fail-count to 0. */
			if (state == DS_PROBING_DST) {
				if (type) {
					if (idx->dlist[i].flags & DS_INACTIVE_DST) {
						LM_INFO("Ignoring the request to set this destination"
								" to probing: It is already inactive!\n");
						lock_stop_read( ds_lock );
						return 0;
					}

					idx->dlist[i].failure_count++;
					/* Fire only, if the Threshold is reached. */
					if (idx->dlist[i].failure_count
							< probing_threshhold) {
						lock_stop_read( ds_lock );
						return 0;
					}
					if (idx->dlist[i].failure_count
							> probing_threshhold)
						idx->dlist[i].failure_count
							= probing_threshhold;
				}
			}
			/* Reset the Failure-Counter */
			if ((state & DS_RESET_FAIL_DST) > 0) {
				idx->dlist[i].failure_count = 0;
				state &= ~DS_RESET_FAIL_DST;
			}

			/* set the new state of the destination */
			old_flags = idx->dlist[i].flags;
			if(type)
				idx->dlist[i].flags |= state;
			else
				idx->dlist[i].flags &= ~state;
			if ( idx->dlist[i].flags != old_flags) {
				/* state actually changed -> do all updates */
				idx->dlist[i].flags |= DS_STATE_DIRTY_DST;
				/* update info on active destinations */
				if ( ((old_flags&(DS_PROBING_DST|DS_INACTIVE_DST))?0:1) !=
				((idx->dlist[i].flags&(DS_PROBING_DST|DS_INACTIVE_DST))?0:1) )
					/* this destination switched state between disabled <> enabled
					   -> update active info */
					re_calculate_active_dsts( idx );
			}

			if (dispatch_evi_id == EVI_ERROR) {
				LM_ERR("event not registered %d\n", dispatch_evi_id);
			} else if (evi_probe_event(dispatch_evi_id)) {
				if (!(list = evi_get_params())) {
					lock_stop_read( ds_lock );
					return 0;
				}
				if (evi_param_add_int(list, &group_str, &group)) {
					LM_ERR("unable to add group parameter\n");
					evi_free_params(list);
					lock_stop_read( ds_lock );
					return 0;
				}
				if (evi_param_add_str(list, &address_str, address)) {
					LM_ERR("unable to add address parameter\n");
					evi_free_params(list);
					lock_stop_read( ds_lock );
					return 0;
				}
				if (evi_param_add_str(list, &status_str,
							type ? &inactive_str : &active_str)) {
					LM_ERR("unable to add status parameter\n");
					evi_free_params(list);
					lock_stop_read( ds_lock );
					return 0;
				}

				if (evi_raise_event(dispatch_evi_id, list)) {
					LM_ERR("unable to send event\n");
				}
			} else {
				LM_DBG("no event sent\n");
			}
			lock_stop_read( ds_lock );
			return 0;
		}
		i++;
	}

	lock_stop_read( ds_lock );
	return -1;
}


/* Checks, if the request (sip_msg *_m) comes from a host in a set
 * (set-id or -1 for all sets)
 */
int ds_is_in_list(struct sip_msg *_m, pv_spec_t *pv_ip, pv_spec_t *pv_port,
													int set, int active_only)
{
	pv_value_t val;
	ds_set_p list;
	struct ip_addr *ip;
	int_str avp_val;
	int port;
	int j,k;

	/* get the address to test */
	if (pv_get_spec_value( _m, pv_ip, &val)!=0) {
		LM_ERR("failed to get IP value from PV\n");
		return -1;
	}
	if ( (val.flags&PV_VAL_STR)==0 ) {
		LM_ERR("IP PV val is not string\n");
		return -1;
	}
	if ( (ip=str2ip( &val.rs ))==NULL ) {
		LM_ERR("IP val is not IP <%.*s>\n",val.rs.len,val.rs.s);
		return -1;
	}

	/* get the port to test */
	if (pv_port) {
		if (pv_get_spec_value( _m, pv_port, &val)!=0) {
			LM_ERR("failed to get PORT value from PV\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_INT)==0 ) {
			LM_ERR("PORT PV val is not integer\n");
			return -1;
		}
		port = val.ri;
	} else {
		port = 0;
	}

	memset(&val, 0, sizeof(pv_value_t));
	val.flags = PV_VAL_INT|PV_TYPE_INT;

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	for(list = (*ds_data)->sets ; list!= NULL; list= list->next) {
		if ((set == -1) || (set == list->id)) {
			/* interate through all elements/destinations in the list */
			for(j=0; j<list->nr; j++) {
				/* interate through all IPs of each destination */
				for(k=0 ; k<list->dlist[j].ips_cnt ; k++ ) {
					if ( (list->dlist[j].ports[k]==0 || port==0
					|| port==list->dlist[j].ports[k]) &&
					ip_addr_cmp( ip, &list->dlist[j].ips[k]) ) {
						/* matching destination */
						if (active_only && !dst_is_active(list->dlist[j]) )
							continue;
						if(set==-1 && ds_setid_pvname.s!=0) {
							val.ri = list->id;
							if(pv_set_value(_m, &ds_setid_pv,
									(int)EQ_T, &val)<0)
							{
								LM_ERR("setting PV failed\n");
								goto error;
							}
						}
						if (attrs_avp_name>= 0) {
							avp_val.s = list->dlist[j].attrs;
							if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0)
								goto error;
						}

						lock_stop_read( ds_lock );
						return 1;
					}
				}
			}
		}
	}

error:
	lock_stop_read( ds_lock );
	return -1;
}


int ds_print_mi_list(struct mi_node* rpl)
{
	int len, j;
	char* p;
	ds_set_p list;
	struct mi_node* node = NULL;
	struct mi_node* node1;
	struct mi_node* set_node = NULL;
	struct mi_attr* attr = NULL;

	if ( (*ds_data)->sets==NULL ) {
		LM_DBG("empty destination sets\n");
		return  0;
	}

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	for(list = (*ds_data)->sets ; list!= NULL; list= list->next) {
		p = int2str(list->id, &len);
		set_node= add_mi_node_child(rpl, MI_IS_ARRAY|MI_DUP_VALUE,
			"SET", 3, p, len);
		if(set_node == NULL)
			goto error;

		for(j=0; j<list->nr; j++)
		{
			node= add_mi_node_child(set_node, MI_DUP_VALUE, "URI", 3,
					list->dlist[j].uri.s, list->dlist[j].uri.len);
			if(node == NULL)
				goto error;

			if (list->dlist[j].flags & DS_INACTIVE_DST)
				attr = add_mi_attr (node, 0, "state",5, "Inactive", 8);
			else if (list->dlist[j].flags & DS_PROBING_DST)
				attr = add_mi_attr (node, 0, "state",5, "Probing", 7);
			else
				attr = add_mi_attr (node, 0, "state",5, "Active", 6);

			if(attr == NULL)
				goto error;

			if (list->dlist[j].sock)
			{
				p = socket2str(list->dlist[j].sock, NULL, &len, 0);
				if (p)
				{
					node1= add_mi_node_child(node, MI_DUP_VALUE,
						"socket", 6, p, len);
					if(node1 == NULL)
						goto error;
				}
			}

			if (list->dlist[j].attrs.s)
			{
				node1= add_mi_node_child(node, MI_DUP_VALUE, "attr", 4,
					list->dlist[j].attrs.s, list->dlist[j].attrs.len);
				if(node1 == NULL)
					goto error;
			}
		}
	}

	lock_stop_read( ds_lock );
	return 0;
error:
	lock_stop_read( ds_lock );
	return -1;
}


/**
 * Callback-Function for the OPTIONS-Request
 * This Function is called, as soon as the Transaction is finished
 * (e. g. a Response came in, the timeout was hit, ...)
 *
 */
static void ds_options_callback( struct cell *t, int type,
		struct tmcb_params *ps )
{
	int group = 0;
	str uri = {0, 0};

	/* The Param does contain the group, in which the failed host
	 * can be found.*/
	if (!ps->param) {
		LM_DBG("No parameter provided, OPTIONS-Request was finished"
				" with code %d\n", ps->code);
		return;
	}

	/* The param is a (void*) Pointer, so we need to dereference it and
	 *  cast it to an int. */
	group = (int)(long)(*ps->param);

	/* The SIP-URI is taken from the Transaction.
	 * Remove the "To: " (s+4) and the trailing new-line (s - 4 (To: )
	 * - 2 (\r\n)). */
	uri.s = t->to.s + 4;
	uri.len = t->to.len - 6;
	LM_DBG("OPTIONS-Request was finished with code %d (to %.*s, group %d)\n",
			ps->code, uri.len, uri.s, group);

	/* ps->code contains the result-code of the request;
	 * We accept "200 OK" by default and the custom codes
	 * defined in options_reply_codes parameter*/
	if ((ps->code == 200) || check_options_rplcode(ps->code)) {
		/* Set the according entry back to "Active":
		 *  remove the Probing/Inactive Flag and reset the failure counter. */
		if (ds_set_state(group, &uri,
					DS_INACTIVE_DST|DS_PROBING_DST|DS_RESET_FAIL_DST, 0) != 0)
		{
			LM_ERR("Setting the state failed (%.*s, group %d)\n", uri.len,
					uri.s, group);
		}
	}
	/* if we always probe, and we get a timeout
	 * or a reponse that is not within the allowed
	 * reply codes, then disable*/
	if(ds_probing_mode==1 && ps->code != 200 &&
	(ps->code == 408 || !check_options_rplcode(ps->code)))
	{
		if (ds_set_state(group, &uri, DS_PROBING_DST, 1) != 0)
		{
			LM_ERR("Setting the probing state failed (%.*s, group %d)\n",
					uri.len, uri.s, group);
		}
	}

	return;
}

/*
 * Timer for checking inactive destinations
 *
 * This timer is regularly fired.
 */
void ds_check_timer(unsigned int ticks, void* param)
{
	dlg_t *dlg;
	ds_set_p list;
	int j;

	/* Check for the list. */
	if ( (*ds_data)->sets==NULL )
		return;

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	/* Iterate over the groups and the entries of each group: */
	for( list=(*ds_data)->sets ; list!= NULL ; list= list->next)
	{
		for(j=0; j<list->nr; j++)
		{
			/* If the Flag of the entry has "Probing set, send a probe:	*/
			if ( ((list->dlist[j].flags&DS_INACTIVE_DST)==0) &&
			(ds_probing_mode==1 || (list->dlist[j].flags&DS_PROBING_DST)!=0) )
			{
				LM_DBG("probing set #%d, URI %.*s\n", list->id,
						list->dlist[j].uri.len, list->dlist[j].uri.s);

				/* Execute the Dialog using the "request"-Method of the
				 * TM-Module.*/
				if (tmb.new_auto_dlg_uac(&ds_ping_from,
						&list->dlist[j].uri,
						list->dlist[j].sock?list->dlist[j].sock:probing_sock,
						&dlg) != 0 ) {
					LM_ERR("failed to create new TM dlg\n");
					continue;
				}
				dlg->state = DLG_CONFIRMED;
				if (tmb.t_request_within(&ds_ping_method,
						NULL,
						NULL,
						dlg,
						ds_options_callback,
						(void*)(long)list->id,
						NULL) < 0) {
					LM_ERR("unable to execute dialog\n");
				}
				tmb.free_dlg(dlg);
			}
		}
	}

	lock_stop_read( ds_lock );
}


int ds_count(struct sip_msg *msg, int set_id, const char *cmp, pv_spec_p ret)
{
	pv_value_t pv_val;
	ds_set_p set;
	ds_dest_p dst;
	int count, active = 0, inactive = 0, probing = 0;

	LM_DBG("Searching for set: %d, filtering: %d\n", set_id, *cmp);

	/* access ds data under reader's lock */
	lock_start_read( ds_lock );

	if ( ds_get_index( set_id, &set)!=0 ) {
		LM_ERR("INVALID SET %d (not found)!\n",set_id);
		lock_stop_read( ds_lock );
		return -1;
	}

	for (dst = set->dlist; dst; dst = dst->next)
	{
		if ( dst_is_active(*dst) )
		{
			active++;

		} else if (dst->flags & DS_INACTIVE_DST)
		{
			inactive++;

		} else if (dst->flags & DS_PROBING_DST)
		{
			probing++;
		}
	}

	lock_stop_read( ds_lock );

	switch (*cmp)
	{
		case DS_COUNT_ACTIVE:
			count = active;
			break;

		case DS_COUNT_ACTIVE|DS_COUNT_INACTIVE:
		case DS_COUNT_ACTIVE|DS_COUNT_PROBING:
			count = (*cmp & DS_COUNT_INACTIVE ? active + inactive :
												active + probing);
			break;

		case DS_COUNT_INACTIVE:
		case DS_COUNT_PROBING:
			count = (*cmp == DS_COUNT_INACTIVE ? inactive : probing);
			break;

		case DS_COUNT_INACTIVE|DS_COUNT_PROBING:
			count = inactive + probing;
			break;

		default:
			count = active + inactive + probing;
	}

	pv_val.flags = PV_TYPE_INT;
	pv_val.ri = count;

	if (pv_set_value(msg, ret, 0, &pv_val) != 0)
	{
		LM_ERR("SET OUTPUT value failed!\n");
		return -1;
	}

	return 1;
}

