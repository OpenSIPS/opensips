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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
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
#include "ds_fixups.h"
#include "ds_bl.h"
#include "ds_clustering.h"

#define DS_TABLE_VERSION	8

/**
 * in version 8, the "weight" column is given as a string, since it can contain
 * both integer (the weight) or URL definitions (dynamically calculated weight)
 *
 * OpenSIPS retains backwards-compatibility with the former integer column flavor
 */
#define supported_ds_version(_ver) \
	(DS_TABLE_VERSION == 8 ? (_ver == 8 || _ver == 7) : _ver == DS_TABLE_VERSION)

extern ds_partition_t *partitions;

extern struct socket_info *probing_sock;
extern event_id_t dispatch_evi_id;
extern ds_partition_t *default_partition;

struct tm_binds tmb;
struct fs_binds fs_api;

#define dst_is_active(_dst) \
	(!((_dst).flags&(DS_INACTIVE_DST|DS_PROBING_DST)))


int init_ds_data(ds_partition_t *partition)
{
	partition->data = (ds_data_t**)shm_malloc( sizeof(ds_data_t*) );
	if (partition->data==NULL) {
		LM_ERR("failed to allocate data holder in shm\n");
		return -1;
	}

	*partition->data = NULL;

	/* create & init lock */
	if ((partition->lock = lock_init_rw()) == NULL) {
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
	str ds_str = {MI_SSTR("dispatcher")};

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
				if (dest->fs_sock)
					fs_api.put_stats_evs(dest->fs_sock, &ds_str);
				if (dest->script_attrs.s)
					shm_free(dest->script_attrs.s);
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
void ds_destroy_data(ds_partition_t *partition)
{
	if (partition->data && *partition->data)
		ds_destroy_data_set( *partition->data );

	/* destroy rw lock */
	if (partition->lock) {
		lock_destroy_rw( partition->lock );
		partition->lock = 0;
	}
}


int add_dest2list(int id, str uri, struct socket_info *sock, str *comsock, int state,
							int weight, int prio, str attrs, str description, ds_data_t *d_data)
{
	ds_dest_p dp = NULL;
	ds_set_p  sp = NULL;
	short new_set = 0;
	ds_dest_p dp_it, dp_prev;
	struct sip_uri puri;
	str ds_str = {MI_SSTR("dispatcher")};

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
			return -1;
		}

		new_set = 1;
		memset(sp, 0, sizeof(ds_set_t));
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

	dp->uri.len = uri.len;
	if (puri.user.len == 0 && puri.passwd.len == 0 && puri.headers.len == 0) {

		/* The uri from db is good for ds_select_dst */
		dp->uri.s = shm_malloc(uri.len + 1 + attrs.len + 1 + description.len + 1);
		if(dp->uri.s==NULL){
			LM_ERR("no more shm memory!\n");
			goto err;
		}
		dp->dst_uri = dp->uri;
		dp->attrs.s = dp->uri.s + dp->uri.len + 1;
		dp->description.s = dp->uri.s + dp->uri.len + 1 + attrs.len + 1;
	}
	else {
		dp->dst_uri.len = uri_typestrlen(puri.type) + 1 + puri.host.len
						+ (puri.port.len ? puri.port.len + 1 : 0) + puri.params.len;
		dp->uri.s = shm_malloc(uri.len+1 + dp->dst_uri.len + 1 + attrs.len+1
								+ description.len + 1);
		if(dp->uri.s==NULL){
			LM_ERR("no more shm memory!\n");
			goto err;
		}

		dp->description.s = dp->uri.s + dp->uri.len + 1 + dp->dst_uri.len + 1 + attrs.len + 1;
		dp->attrs.s = dp->uri.s + dp->uri.len + 1 + dp->dst_uri.len + 1;
		dp->dst_uri.s = dp->uri.s + dp->uri.len + 1;
		char *p = uri_type2str(puri.type, dp->dst_uri.s);
		*(p++) = ':';

		memcpy(p, puri.host.s, puri.host.len);
		p += puri.host.len;

		if (puri.port.len) {
			*(p++) = ':';
			memcpy(p, puri.port.s, puri.port.len);
		}
		if (puri.params.len) {
			memcpy(p, puri.params.s, puri.params.len);
			p += puri.params.len;
		}
		dp->dst_uri.s[dp->dst_uri.len]='\0';
	}

	memcpy(dp->uri.s, uri.s, dp->uri.len);

	if (attrs.len) {
		memcpy(dp->attrs.s, attrs.s, attrs.len);
		dp->attrs.s[attrs.len]='\0';
		dp->attrs.len = attrs.len;
	}
	else dp->attrs.s = NULL;

	if(description.len){
		memcpy(dp->description.s, description.s, description.len);
		dp->description.s[description.len]='\0';
		dp->description.len = description.len;
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
	dp->priority = prio;
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

	if (fetch_freeswitch_stats) {
		if (comsock->s && comsock->len > 0) {
			dp->fs_sock = fs_api.get_stats_evs(comsock, &ds_str);
			if (!dp->fs_sock) {
				LM_ERR("failed to create FreeSWITCH stats socket!\n");
			} else {
				dp->weight = max_freeswitch_weight;
				if (sp->redo_weights == 0) {
					for (dp_it = sp->dlist; dp_it; dp_it = dp_it->next) {
						if (dp_it->weight > max_freeswitch_weight) {
							LM_WARN("(set %d) truncating static weight in "
						     "uri %.*s to 'max_freeswitch_weight'! (%d->%d)\n",
							 id, uri.len, uri.s, dp_it->weight, max_freeswitch_weight);
							dp_it->weight = max_freeswitch_weight;
						}
					}
					sp->redo_weights = 1;
				}
			}
		} else if (sp->redo_weights && dp->weight > max_freeswitch_weight) {
			LM_WARN("(set %d) truncating static weight in uri %.*s to"
			           "\"max_freeswitch_weight\"! (%d -> %d)\n", id,
			           uri.len, uri.s, weight, max_freeswitch_weight);
			dp->weight = max_freeswitch_weight;
		}
	}

	/*
	 * search the proper place based on priority
	 * put them in reverse order, since they will be reindexed
	 */
	for (dp_prev = NULL, dp_it = sp->dlist;
		 dp_it && dp_it->priority < prio;
		 dp_prev = dp_it, dp_it = dp_it->next);

	if (!dp_prev) {
		dp->next = sp->dlist;
		sp->dlist = dp;
	} else {
		dp->next = dp_prev->next;
		dp_prev->next = dp;
	}
	sp->nr++;

	if (new_set) {
		sp->next = d_data->sets;
		d_data->sets = sp;
		d_data->sets_no++;
	}

	LM_DBG("dest [%d/%d] <%.*s> <%.*s> successfully loaded\n", sp->id, sp->nr,
			dp->uri.len, dp->uri.s, dp->dst_uri.len, dp->dst_uri.s);

	return 0;
err:
	/* free allocated memory */
	if(dp!=NULL)
	{
		if(dp->uri.s!=NULL)
			shm_free(dp->uri.s);
		shm_free(dp);
	}

	if (sp != NULL && new_set)
		shm_free(sp);

	return -1;
}


/* iterates the whole set and calculates (1) the number of 
   active destinations and (2) the running and total weight
   sum for the active destinations */
static inline void re_calculate_active_dsts(ds_set_p sp)
{
	int j,i;
	ds_dest_p dst;
	int oldw;

	/* pre-calculate the running weights for each destination */
	for( j=0,i=-1,sp->active_nr=sp->nr ; j<sp->nr ; j++ ) {
		dst = &sp->dlist[j];
		if (dst->fs_sock && dst->fs_sock->stats.valid) {
			lock_start_read(dst->fs_sock->stats_lk);

			oldw = dst->weight;
			dst->weight = round(max_freeswitch_weight *
			(1 - dst->fs_sock->stats.sess /
			     (float)dst->fs_sock->stats.max_sess) *
			(dst->fs_sock->stats.id_cpu / (float)100));

			LM_DBG("weight update for %.*s: %d -> %d (%d %d %.3f)\n",
			       dst->uri.len, dst->uri.s, oldw, dst->weight,
				   dst->fs_sock->stats.sess, dst->fs_sock->stats.max_sess,
				   dst->fs_sock->stats.id_cpu);

			lock_stop_read(dst->fs_sock->stats_lk);
		}

		/* running weight is the current weight plus the running weight of
		 * the previous element */
		dst->running_weight = dst->weight
			+ ((j==0) ? 0 : sp->dlist[j-1].running_weight);
		/* now the running weight for the active destinations */
		if ( dst_is_active(*dst)) {
			dst->active_running_weight = dst->weight
				+ ((i==-1) ? 0 : sp->dlist[i].active_running_weight);
			i = j; /* last active destination */
		} else {
			dst->active_running_weight =
				((i==-1) ? 0 : sp->dlist[i].active_running_weight);
			sp->active_nr --;
		}
		LM_DBG("destination i=%d, j=%d, weight=%d, sum=%d, active_sum=%d\n",
			i,j, dst->weight, dst->running_weight, dst->active_running_weight);
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
static str ds_pattern_prefix = str_init("");
static str ds_pattern_suffix = str_init("");

void ds_pvar_parse_pattern(str pattern)
{
	char *p, *end;

	ds_pattern_prefix = pattern;
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
	ds_pattern_prefix.len = p - pattern.s;

	/* skip marker */
	ds_pattern_suffix.s = p + DS_PV_ALGO_MARKER_LEN;
	ds_pattern_suffix.len = pattern.s + pattern.len - ds_pattern_suffix.s;
}


ds_pvar_param_p ds_get_pvar_param(str uri)
{
	str name;
	int len = ds_pattern_prefix.len + uri.len + ds_pattern_suffix.len;
	char buf[len]; /* XXX: check if this works for all compilers */
	ds_pvar_param_p param;

	if (ds_has_pattern) {
		name.len = 0;
		name.s = buf;
		memcpy(buf, ds_pattern_prefix.s, ds_pattern_prefix.len);
		name.len = ds_pattern_prefix.len;
		memcpy(name.s + name.len, uri.s, uri.len);
		name.len += uri.len;
		memcpy(name.s + name.len, ds_pattern_suffix.s, ds_pattern_suffix.len);
		name.len += ds_pattern_suffix.len;
	}

	param = shm_malloc(sizeof(ds_pvar_param_t));
	if (!param) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}

	if (!pv_parse_spec(ds_has_pattern ? &name : &ds_pattern_prefix,
	&param->pvar)) {
		LM_ERR("cannot parse pattern spec\n");
		shm_free(param);
		return NULL;
	}

	return param;
}


int ds_pvar_algo(struct sip_msg *msg, ds_set_p set, ds_dest_p **sorted_set,
															int ds_use_default)
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

int ds_route_param_get(struct sip_msg *msg, pv_param_t *ip,
		pv_value_t *res, void *params, void *extra)
{
	pv_value_t tv;
	ds_dest_p entry = (ds_dest_p)params;
	
	if(ip->pvn.type==PV_NAME_INTSTR) {
		if (ip->pvn.u.isname.type != 0) {
			tv.rs =  ip->pvn.u.isname.name.s;
			tv.flags = PV_VAL_STR;
		} else {
			tv.ri = ip->pvn.u.isname.name.n;
			tv.flags = PV_VAL_INT|PV_TYPE_INT;
		}
	} else {
		/* pvar -> it might be another $param variable! */
		if(pv_get_spec_value(msg, (pv_spec_p)(ip->pvn.u.dname), &tv)!=0) {
			LM_ERR("cannot get spec value\n");
			return -1;
		}

		if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY) {
			LM_ERR("null or empty name\n");
			return -1;
		}
	}

	res->flags = PV_VAL_STR;
	/* search for the param we want top add, based on index */
	if (tv.flags & PV_VAL_INT) {
		if (tv.ri == 1) {
			res->rs.s = entry->dst_uri.s; 
			res->rs.len = entry->dst_uri.len;
		} else if (tv.ri == 2) {
			if (entry->attrs.s) {
				res->rs.s = entry->attrs.s; 
				res->rs.len = entry->attrs.len;
			} else
				return pv_get_null(msg, ip, res);
		} else if (tv.ri == 3) {
			if (entry->script_attrs.s) {
				res->rs.s = entry->script_attrs.s; 
				res->rs.len = entry->script_attrs.len;
			} else
				return pv_get_null(msg, ip, res);
		} else
			return pv_get_null(msg, ip, res);
	} else {
		if (tv.rs.len == 7 && 
		memcmp(tv.rs.s,"dst_uri",7) == 0) {
			res->rs.s = entry->dst_uri.s; 
			res->rs.len = entry->dst_uri.len;
		} else if (tv.rs.len == 5 && 
		memcmp(tv.rs.s,"attrs",5) == 0) {
			res->rs.s = entry->attrs.s; 
			res->rs.len = entry->attrs.len;
		} else if (tv.rs.len == 12 && 
		memcmp(tv.rs.s,"script_attrs",12) == 0) {
			res->rs.s = entry->script_attrs.s; 
			res->rs.len = entry->script_attrs.len;
		} else 
			return pv_get_null(msg, ip, res);
	}

	return 0;
}

int run_route_algo(struct sip_msg *msg, int rt_idx,ds_dest_p entry)
{
	int fret;

	route_params_push_level(entry, NULL, ds_route_param_get);
	run_top_route_get_code(sroutes->request[rt_idx].a, msg, &fret);
	route_params_pop_level();

	return fret;
}

int ds_route_algo(struct sip_msg *msg, ds_set_p set, 
		ds_dest_p **sorted_set,	int ds_use_default)
{
	int i, j, k, end_idx, cnt, rt_idx, fret;
	ds_dest_p *sset;

	if (!set) {
		LM_ERR("invalid set\n");
		return -1;
	}

	if ((rt_idx = get_script_route_ID_by_name(algo_route_param.s,
	sroutes->request, RT_NO)) == -1) {
		LM_ERR("Invalid route parameter \n");
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

		fret = run_route_algo(msg, rt_idx, &set->dlist[i]);
		set->dlist[i].route_algo_value = fret;

		/* search the proper position */
		j = 0;
		for (; j < cnt && sset[j]->route_algo_value <= fret; j++);
		/* make space for the new entry */
		for (k = cnt; k > j; k--)
			sset[k] = sset[k - 1];
		sset[j] = &set->dlist[i];
		cnt++;
	}

	return cnt;
}

int ds_connect_db(ds_partition_t *partition)
{
	if(!partition->db_url.s)
		return -1;

	if (*partition->db_handle)
	{
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}

	if ((*partition->db_handle = partition->dbf.init(&partition->db_url)) == 0)
			return -1;

	return 0;
}


void ds_disconnect_db(ds_partition_t *partition)
{
	if(*partition->db_handle)
	{
		partition->dbf.close(*partition->db_handle);
		*partition->db_handle = 0;
	}
}


/*initialize and verify DB stuff*/
int init_ds_db(ds_partition_t *partition)
{
	int _ds_table_version;

	if(partition->table_name.s == 0){
		LM_ERR("invalid database name\n");
		return -1;
	}

	/* Find a database module */
	if (db_bind_mod(&partition->db_url, &partition->dbf) < 0) {
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if(ds_connect_db(partition)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	_ds_table_version = db_table_version(&partition->dbf,*partition->db_handle,
											&partition->table_name);
	if (_ds_table_version < 0) {
		LM_ERR("failed to query table version\n");
		return -1;
	} else if (!supported_ds_version(_ds_table_version)) {
		LM_ERR("invalid version for table '%.*s' (found %d, required %d)\n"
		    "(use opensips-cli to migrate to latest schema)\n",
		    partition->table_name.len, partition->table_name.s,
		    _ds_table_version, DS_TABLE_VERSION );
		return -1;
	}

	return 0;
}


static void ds_inherit_state( ds_data_t *old_data , ds_data_t *new_data)
{
	ds_set_p new_set, old_set;
	ds_dest_p new_ds, old_ds;
	int changed;

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
		changed = 0;

		/* sets are matching, try to match the destinations, one by one */
		for ( new_ds=new_set->dlist ; new_ds ; new_ds=new_ds->next ) {
			for ( old_ds=old_set->dlist ; old_ds ; old_ds=old_ds->next ) {
				if (new_ds->uri.len==old_ds->uri.len &&
				strncasecmp(new_ds->uri.s, old_ds->uri.s, old_ds->uri.len)==0 ) {
					LM_DBG("DST <%.*s> found in old set, copying state\n",
						new_ds->uri.len,new_ds->uri.s);
					if (new_ds->flags != old_ds->flags) {
						new_ds->flags = old_ds->flags;
						changed = 1;
					}
					break;
				}
			}
			if (old_ds==NULL)
				LM_DBG("DST <%.*s> not found in old set\n",
					new_ds->uri.len,new_ds->uri.s);
		}
		if (changed)
			re_calculate_active_dsts(new_set);
	}
}


void ds_flusher_routine(unsigned int ticks, void* param)
{
	db_key_t key_cmp[2];
	db_val_t val_cmp[2];
	db_key_t key_set;
	db_val_t val_set;
	ds_set_p list;
	int j;

	ds_partition_t *partition;
	for (partition = partitions; partition; partition = partition->next){
		if (*partition->db_handle==NULL)
			continue;

		val_cmp[0].type = DB_INT;
		val_cmp[0].nul  = 0;
		val_cmp[1].type = DB_STR;
		val_cmp[1].nul  = 0;

		val_set.type = DB_INT;
		val_set.nul  = 0;

		/* access ds data under reader's lock */
		lock_start_read( partition->lock );

		/* update the gateways */
		if (partition->dbf.use_table(*partition->db_handle,
					&partition->table_name) < 0) {
			LM_ERR("cannot select table \"%.*s\"\n",
				partition->table_name.len, partition->table_name.s);
			lock_stop_read( partition->lock );
			continue;
		}
		key_cmp[0] = &ds_set_id_col;
		key_cmp[1] = &ds_dest_uri_col;
		key_set = &ds_dest_state_col;

		if (*partition->data) {
			/* Iterate over the groups and the entries of each group */
			for(list = (*partition->data)->sets; list!= NULL; list=list->next){
				for(j=0; j<list->nr; j++) {
					/* If the Flag of the entry is STATE_DIRTY -> flush do db*/
					if ( (list->dlist[j].flags&DS_STATE_DIRTY_DST)==0 )
						/* nothing to do for this destination */
						continue;

					/* populate the update */
					val_cmp[0].val.int_val = list->id;
					val_cmp[1].val.str_val = list->dlist[j].uri;
					val_set.val.int_val =
						(list->dlist[j].flags&DS_INACTIVE_DST) ? 1 :
							((list->dlist[j].flags&DS_PROBING_DST)?2:0);

					/* update the state of this destination */
					LM_DBG("updating the state of destination <%.*s> to %d\n",
						list->dlist[j].uri.len, list->dlist[j].uri.s,
							val_set.val.int_val);

					if (partition->dbf.update(*partition->db_handle,key_cmp,0,
					val_cmp,&key_set,&val_set,2,1)<0 ) {
						LM_ERR("DB update failed\n");
					} else {
						list->dlist[j].flags &= ~DS_STATE_DIRTY_DST;
					}
				}
			}
		}

		lock_stop_read( partition->lock );
	}

	return;
}


/*load groups of destinations from DB*/
static ds_data_t* ds_load_data(ds_partition_t *partition, int use_state_col)
{
	ds_data_t *d_data;
	int i, id, nr_rows, cnt, nr_cols = 8;
	int state;
	int weight;
	int prio;
	struct socket_info *sock;
	str uri;
	str attrs, weight_st;
	str host;
	str description;
	int port, proto;
	db_res_t * res = NULL;
	db_val_t * values;
	db_row_t * rows;

	db_key_t query_cols[8] = {&ds_set_id_col, &ds_dest_uri_col,
			&ds_dest_sock_col, &ds_dest_weight_col, &ds_dest_attrs_col,
			&ds_dest_prio_col, &ds_dest_description_col, &ds_dest_state_col};

	if (!use_state_col)
		nr_cols--;

	if(*partition->db_handle == NULL){
			LM_ERR("invalid DB handler\n");
			return NULL;
	}

	if (partition->dbf.use_table(*partition->db_handle, &partition->table_name)
	< 0) {
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
	if(partition->dbf.query(*partition->db_handle,0,0,0,query_cols,0,nr_cols,
	0,&res) < 0) {
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
				sock = grep_internal_sock_info( &host, port, proto);
				if (sock == NULL) {
					LM_ERR("socket <%.*s> is not local to opensips (we must "
						"listen on it) -> ignoring it\n", attrs.len, attrs.s);
				}
			}
		} else {
			sock = NULL;
		}

		weight = 1;

		/* weight */
		if (values[3].type == DB_INT) {
			weight = VAL_INT(values+3);
			memset(&weight_st, 0, sizeof weight_st);
		} else {
			/* dynamic weight, given as a communication socket string */
			get_str_from_dbval("WEIGHT", values+3,
			                   0/*not_null*/, 0/*not_empty*/, weight_st, error2);
			if (!is_fs_url(&weight_st)) {
				str2int(&weight_st, (unsigned int *)&weight);
				memset(&weight_st, 0, sizeof weight_st);
			}
		}

		/* attrs */
		get_str_from_dbval( "ATTRIBUTES", values+4,
			0/*not_null*/, 0/*not_empty*/, attrs, error2);

		/* priority */
		if (VAL_NULL(values+5))
			prio = 0;
		else
			prio = VAL_INT(values+5);

		/* state */
		if (!use_state_col || VAL_NULL(values+7))
			/* active state */
			state = 0;
		else
			state = VAL_INT(values+7);

		get_str_from_dbval( "DESCRIPTION", values+6,
			0/*not_null*/, 0/*not_empty*/, description, error2);

		if (add_dest2list(id, uri, sock, &weight_st, state, weight, prio, attrs, description, d_data)
		!= 0) {
			LM_WARN("failed to add destination <%.*s> in group %d\n",
				uri.len,uri.s,id);
			continue;
		} else {
			cnt++;
		}
	}

	if (cnt==0) {
		LM_WARN("No record loaded from db, running on empty sets\n");
	} else {
		if(reindex_dests( d_data )!=0) {
			LM_ERR("error on reindex\n");
			goto error2;
		}
	}

load_done:
	partition->dbf.free_result(*partition->db_handle, res);
	return d_data;

error:
	ds_destroy_data_set( d_data );
	return NULL;
error2:
	ds_destroy_data_set( d_data );
	partition->dbf.free_result(*partition->db_handle, res);
	return NULL;
}


int ds_reload_db(ds_partition_t *partition)
{
	ds_data_t *old_data;
	ds_data_t *new_data;

	new_data = ds_load_data(partition, ds_persistent_state);
	if (new_data==NULL) {
		LM_ERR("failed to load the new data, dropping the reload\n");
		return -1;
	}

	lock_start_write( partition->lock );

	/* no more activ readers -> do the swapping */
	old_data = *partition->data;
	*partition->data = new_data;

	lock_stop_write( partition->lock );

	/* destroy old data */
	if (old_data) {
		/* copy the state of the destinations from the old set
		 * (for the matching ids) */
		ds_inherit_state( old_data, new_data);
		ds_destroy_data_set( old_data );
	}

	/* update the Black Lists with the new gateways */
	populate_ds_bls( new_data->sets, partition->name);

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
			parsed_uri->port_no != protos[proto].default_port )
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
int ds_hash_fromuri(struct sip_msg *msg, unsigned int *hash, int ds_flags)
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
int ds_hash_touri(struct sip_msg *msg, unsigned int *hash, int ds_flags)
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



int ds_hash_ruri(struct sip_msg *msg, unsigned int *hash, int ds_flags)
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


static inline int ds_get_index(int group, ds_set_p *index,
													ds_partition_t *partition)
{
	ds_set_p si = NULL;

	if(index==NULL || group<0 || (*partition->data)->sets==NULL)
		return -1;

	/* get the index of the set */
	for ( si=(*partition->data)->sets ; si ; si = si->next ) {
		if(si->id == group) {
			*index = si;
			break;
		}
	}

	if(si==NULL) {
		LM_ERR("destination set [%d] not found in partition [%.*s]\n", group,
				partition->name.len, partition->name.s);
		return -1;
	}

	return 0;
}


int ds_update_dst(struct sip_msg *msg, str *uri, struct socket_info *sock,
																	int mode)
{
	uri_type utype;
	int typelen;
	str s;

	switch(mode)
	{
		case 1:
			utype = str2uri_type(uri->s);
			if (utype == ERROR_URI_T) {
				LM_ERR("Unknown uri type\n");
				return -1;
			}
			typelen = uri_typestrlen(utype);
			s.s = uri->s + typelen + 1;
			s.len = uri->len - typelen - 1;

			if (rewrite_ruri(msg, &s, 0, RW_RURI_HOSTPORT) < 0) {
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

static int is_default_destination_entry(ds_set_p idx,int i, int ds_use_default)
{
	return ds_use_default!=0 && i==(idx->nr-1);
}

static int count_inactive_destinations(ds_set_p idx, int ds_use_default) {
	int count = 0, i;

	for(i=0; i<idx->nr; i++)
		if( !dst_is_active(idx->dlist[i]) )
			/* only count inactive entries that are not default */
			if(!is_default_destination_entry(idx, i, ds_use_default))
				count++;

	return count;
}


static inline int push_ds_2_avps( ds_dest_t *ds, ds_partition_t *partition )
{
	char buf[PTR_STRING_SIZE]; /* a hexa string */
	int_str avp_val;

	avp_val.s.len = snprintf( buf, PTR_STR_SIZE, "%p", ds->sock );
	avp_val.s.s = buf;
	if(add_avp(AVP_VAL_STR| partition->sock_avp_type,
				partition->sock_avp_name, avp_val)!=0) {
		LM_ERR("failed to add SOCK avp\n");
		return -1;
	}

	avp_val.s = ds->dst_uri;
	if(add_avp(AVP_VAL_STR| partition->dst_avp_type,
				partition->dst_avp_name, avp_val)!=0) {
		LM_ERR("failed to add DST avp\n");
		return -1;
	}

	if (partition->attrs_avp_name >= 0) {
		avp_val.s = ds->attrs;
		if(add_avp(AVP_VAL_STR| partition->attrs_avp_type,
					partition->attrs_avp_name, avp_val)!=0) {
			LM_ERR("failed to add ATTR avp\n");
			return -1;
		}
	}

	if (partition->script_attrs_avp_name >= 0) {
		avp_val.s = ds->script_attrs;
		if(add_avp(AVP_VAL_STR| partition->script_attrs_avp_type,
		partition->script_attrs_avp_name, avp_val)!=0) {
			LM_ERR("failed to add Script ATTR avp\n");
			return -1;
		}
	}
	return 0;
}


/**
 *
 */
int ds_select_dst(struct sip_msg *msg, ds_select_ctl_p ds_select_ctl,
								ds_selected_dst_p selected_dst, int ds_flags)
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
	int rc;

	if(msg==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if ( (*ds_select_ctl->partition->data)->sets==NULL) {
		LM_DBG("empty destination set\n");
		return -1;
	}

	/* access ds data under reader's lock */
	lock_start_read( ds_select_ctl->partition->lock );

	/* get the index of the set */
	if(ds_get_index(ds_select_ctl->set, &idx, ds_select_ctl->partition)!=0)
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
			if(ds_hash_fromuri(msg, &ds_hash, ds_flags)!=0)
			{
				LM_ERR("can't get From uri hash\n");
				goto error;
			}
		break;
		case 2:
			if(ds_hash_touri(msg, &ds_hash, ds_flags)!=0)
			{
				LM_ERR("can't get To uri hash\n");
				goto error;
			}
		break;
		case 3:
			if (ds_hash_ruri(msg, &ds_hash, ds_flags)!=0)
			{
				LM_ERR("can't get ruri hash\n");
				goto error;
			}
		break;
		case 4:
			/* round robin
			   Each destination is selected a number of times equal to its weight before moving
			   to the next destination
			   the count is incremented after we verify that the destination is active
			*/
			if( idx->dlist[idx->last].rr_count < idx->dlist[idx->last].weight)
				ds_id = idx->last;
			else {
				idx->dlist[idx->last].rr_count = 0;
				ds_id = (idx->last+1) % set_size;
			}
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
			if (!ds_has_pattern && ds_pattern_prefix.len == 0 ) {
				LM_WARN("no pattern specified - using first entry...\n");
				ds_select_ctl->alg = 8;
				break;
			}
			if (ds_pvar_algo(msg, idx, &sorted_set, ds_flags&DS_USE_DEFAULT)
			<= 0)
			{
				LM_ERR("can't get destination index\n");
				goto error;
			}
			selected = sorted_set[0];
			ds_id = 0;
		break;
		case 10:
			if (algo_route_param.s == NULL || algo_route_param.len == 0) {
				LM_ERR("No hash_route param provided \n");
				goto error;
			}
			if (ds_route_algo(msg, idx, &sorted_set, ds_flags&DS_USE_DEFAULT)
			<= 0) {
				LM_ERR("can't route \n");
				goto error;
			}	
			selected = sorted_set[0];
			ds_id = 0;
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
				if (ds_id==set_size) {
					LM_CRIT("BUG - no node found with weight %d in set %d\n",
						ds_rand,idx->id);
					goto error;
				}
			} else {
				/* get a candidate simply based on hash */
				ds_id = ds_hash % set_size;
			}
		}

		LM_DBG("candidate is [%u]\n",ds_id);

		/* now we have a candidate, so we need to check if active or not */
		i=ds_id;
		while ( !dst_is_active(idx->dlist[i]) ) {
			/* get a next candidate */
			if (ds_hash==0) {
				/* for algs with no hash, simple get the next in the list */
				i = (i+1) % set_size;
			} else {
				/* use the hash and weights over active destinations only ;
				 * if USE_DEFAULT is set, do a -1 if the default (last)
				 * destination is active (we want to skip it) */
				cnt = idx->active_nr - ((ds_flags&DS_USE_DEFAULT &&
					dst_is_active(idx->dlist[idx->nr-1]))?1:0);
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
						if (i==set_size) {
							LM_CRIT("BUG - no active node found with "
								"weight %d in set %d\n",ds_rand,idx->id);
							goto error;
						}
					} else {
						j = ds_hash % cnt;
						/* translate this index to the full set of dsts */
						for ( i=0 ; i<set_size ; i++ ) {
							if ( dst_is_active(idx->dlist[i]) ) j--;
							if (j<0) break;
						}
						if (i==set_size) {
							LM_CRIT("BUG - no active node found with "
								"in set %d\n",idx->id);
							goto error;
						}
					}
				}
				/* i reflects the new candidate */
			}
			LM_DBG("new candidate is [%u]\n",i);
			if(i==ds_id) {
				if (ds_flags&DS_USE_DEFAULT) {
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

	/* increase  chosen count in round-robin algritm, now that we know the candidate is active*/
	if(ds_select_ctl->alg == 4)
		idx->dlist[ds_id].rr_count++;

	/* start pushing the destinations to SIP level */
	cnt = 0;
	rc = 1;
	if(ds_select_ctl->set_destination
		&& ((rc = ds_update_dst(msg, &selected->dst_uri, selected->sock, ds_select_ctl->mode)) != 0) )
	{
		LM_ERR("cannot set dst addr\n");
		goto error;
	}

	if(rc == 0){
		selected->chosen_count++;
	}


	/* Save the selected destination for multilist failover */
	if (selected_dst->uri.s != NULL) {
		pkg_free(selected_dst->uri.s);
		memset(&selected_dst->uri, 0, sizeof(str));
	}
	if (pkg_str_dup(&selected_dst->uri, &selected->dst_uri) != 0) {
		LM_ERR("cannot set selected_dst uri\n");
		goto error;
	}
	selected_dst->socket = selected->sock;

	LM_DBG("selected [%d-%d/%d] <%.*s>\n",
		ds_select_ctl->alg, ds_select_ctl->set, ds_id,
		selected->dst_uri.len, selected->dst_uri.s);

	if(!(ds_flags&DS_FAILOVER_ON))
		goto done;

	if (!(ds_select_ctl->ds_flags & DS_APPEND_MODE))
	{
		/* do some AVP cleanup before start populating new ones */
		destroy_avps(0/*all types*/, ds_select_ctl->partition->dst_avp_name,1);
		destroy_avps(0/*all types*/, ds_select_ctl->partition->grp_avp_name,1);
		destroy_avps(0/*all types*/, ds_select_ctl->partition->cnt_avp_name,1);
		destroy_avps(0/*all types*/,ds_select_ctl->partition->sock_avp_name,1);
		if (ds_select_ctl->partition->attrs_avp_name>0)
			destroy_avps( 0 /*all types*/,
			ds_select_ctl->partition->attrs_avp_name, 1 /*all*/);
		if (ds_select_ctl->partition->script_attrs_avp_name>0)
			destroy_avps( 0 /*all types*/,
			ds_select_ctl->partition->script_attrs_avp_name, 1 /*all*/);
	}

	if((ds_flags&DS_USE_DEFAULT) && ds_id!=idx->nr-1)
	{
		if (push_ds_2_avps( &idx->dlist[idx->nr-1], ds_select_ctl->partition )
		!= 0 )
			goto error;
		cnt++;
	}

	inactive_dst_count =
		count_inactive_destinations(idx, ds_flags&DS_USE_DEFAULT);
	/* don't count inactive and default entries into total */
	destination_entries_to_skip = idx->nr - inactive_dst_count
		- (ds_flags&DS_USE_DEFAULT?1:0);
	destination_entries_to_skip -= ds_select_ctl->max_results;

	/* add to avp */

	for(i_unwrapped = ds_id-1+idx->nr; i_unwrapped>ds_id; i_unwrapped--) {
		i = i_unwrapped % idx->nr;
		dest = ((ds_select_ctl->alg == 9 || ds_select_ctl->alg == 10) ? 
			sorted_set[i] : 
			&idx->dlist[i]);

		if ( !dst_is_active(*dest) ||
		((ds_flags&DS_USE_DEFAULT) && i==(idx->nr-1)) )
			continue;
		if(destination_entries_to_skip > 0) {
			LM_DBG("skipped entry [%d/%d] (would create more than %i "
				"results)\n",
				ds_select_ctl->set, i, ds_select_ctl->max_results);
			destination_entries_to_skip--;
			continue;
		}

		LM_DBG("using entry [%d/%d]\n", ds_select_ctl->set, i);
		if (push_ds_2_avps( dest, ds_select_ctl->partition ) != 0 )
			goto error;
		cnt++;
	}

	/* add to avp the first used dst */
	avp_val.s = selected->uri;
	if(add_avp(AVP_VAL_STR|ds_select_ctl->partition->dst_avp_type,
				ds_select_ctl->partition->dst_avp_name,
				avp_val)!=0)
		goto error;
	cnt++;

done:
	if (ds_select_ctl->partition->attrs_avp_name>0) {
		avp_val.s = selected->attrs;
		if(add_avp(AVP_VAL_STR | ds_select_ctl->partition->attrs_avp_type,
		ds_select_ctl->partition->attrs_avp_name,avp_val)!=0)
			goto error;
	}

	if (ds_select_ctl->partition->script_attrs_avp_name>0) {
		avp_val.s = selected->script_attrs;
		if(add_avp(AVP_VAL_STR | ds_select_ctl->partition->script_attrs_avp_type,
		ds_select_ctl->partition->script_attrs_avp_name,avp_val)!=0)
			goto error;
	}

	/* add to avp the group id */
	avp_val.n = ds_select_ctl->set;
	if(add_avp(ds_select_ctl->partition->grp_avp_type,
				ds_select_ctl->partition->grp_avp_name, avp_val)!=0)
		goto error;

	/* add to avp the number of dst */
	avp_val.n = cnt;
	if(add_avp(ds_select_ctl->partition->cnt_avp_type,
				ds_select_ctl->partition->cnt_avp_name, avp_val)!=0)
		goto error;

	lock_stop_read( ds_select_ctl->partition->lock );
	return 1;

error:
	lock_stop_read( ds_select_ctl->partition->lock );
	return -1;
}


int ds_next_dst(struct sip_msg *msg, int mode, ds_partition_t *partition)
{
	struct socket_info *sock;
	struct usr_avp *avp;
	struct usr_avp *tmp_avp;
	struct usr_avp *attr_avp;
	int_str avp_value;
	int_str sock_avp_value;

	tmp_avp = search_first_avp(partition->dst_avp_type,
		partition->dst_avp_name, NULL, 0);
	if(tmp_avp==NULL)
		return -1; /* used avp deleted -- strange */

	/* get AVP with next destination URI */
	avp = search_next_avp(tmp_avp, &avp_value);
	destroy_avp(tmp_avp);

	/* remove old attribute AVP (from prev destination) */
	if (partition->attrs_avp_name >= 0) {
		attr_avp = search_first_avp(partition->attrs_avp_type,
				partition->attrs_avp_name, NULL, 0);
		if (attr_avp)
			destroy_avp(attr_avp);
	}
	if (partition->script_attrs_avp_name >= 0) {
		attr_avp = search_first_avp(partition->script_attrs_avp_type,
				partition->script_attrs_avp_name, NULL, 0);
		if (attr_avp)
			destroy_avp(attr_avp);
	}

	if(avp==NULL || !(avp->flags&AVP_VAL_STR))
		return -1; /* no more avps or value is int */

	/* get AVP with next destination socket */
	tmp_avp = search_first_avp(partition->sock_avp_type,
		partition->sock_avp_name, &sock_avp_value, 0);
	if (!tmp_avp) {
		/* this shuold not happen, it is a bogus state */
		sock = NULL;
	} else {
		if (sscanf( sock_avp_value.s.s, "%p", (void**)&sock ) != 1)
			sock = NULL;
		destroy_avp(tmp_avp);
	}

	LM_DBG("using [%.*s]\n", avp_value.s.len, avp_value.s.s);
	if( ds_update_dst(msg, &avp_value.s, sock, mode) != 0)
	{
		LM_ERR("cannot set dst addr\n");
		return -1;
	}

	return 1;
}


int ds_mark_dst(struct sip_msg *msg, int mode, ds_partition_t *partition)
{
	int group, ret;
	struct usr_avp *prev_avp;
	int_str avp_value;

	prev_avp = search_first_avp(partition->grp_avp_type,
		partition->grp_avp_name, &avp_value, 0);

	if(prev_avp==NULL || prev_avp->flags&AVP_VAL_STR)
		return -1; /* grp avp deleted -- strange */
	group = avp_value.n;

	prev_avp = search_first_avp(partition->dst_avp_type,
		partition->dst_avp_name, &avp_value, 0);

	if(prev_avp==NULL || !(prev_avp->flags&AVP_VAL_STR))
		return -1; /* dst avp deleted -- strange */

	if(mode==1) {
		/* set as "active" */
		ret = ds_set_state(group, &avp_value.s,
				DS_INACTIVE_DST|DS_PROBING_DST, 0, partition);
	} else if(mode==2) {
		/* set as "probing" */
		ret = ds_set_state(group, &avp_value.s, DS_PROBING_DST, 1, partition);
		if (ret == 0) ret = ds_set_state(group, &avp_value.s,
				DS_INACTIVE_DST, 0, partition);
	} else {
		/* set as "inactive" */
		ret = ds_set_state(group, &avp_value.s, DS_INACTIVE_DST, 1, partition);
		if (ret == 0) ret = ds_set_state(group, &avp_value.s,
				DS_PROBING_DST, 0, partition);
	}

	LM_DBG("mode [%d] grp [%d] dst [%.*s]\n", mode, group, avp_value.s.len,
			avp_value.s.s);

	return (ret==0)?1:-1;
}

/* event parameters */
static str partition_str = str_init("partition");
static str group_str = str_init("group");
static str address_str = str_init("address");
static str status_str = str_init("status");
static str inactive_str = str_init("inactive");
static str active_str = str_init("active");

static void _ds_set_state(ds_set_p set, int idx, str *address, int state,
	int type, ds_partition_t *partition, int do_repl, int raise_event)
{
	evi_params_p list = NULL;
	int old_flags;

	/* remove the Probing/Inactive-State? Set the fail-count to 0. */
	if (state == DS_PROBING_DST) {
		if (type) {
			if (set->dlist[idx].flags & DS_INACTIVE_DST) {
				LM_INFO("Ignoring the request to set this destination"
						" to probing: It is already inactive!\n");
				return;
			}

			if (do_repl) {
				set->dlist[idx].failure_count++;
				/* Fire only, if the Threshold is reached. */
				if (set->dlist[idx].failure_count
						< probing_threshold)
					return;

				if (set->dlist[idx].failure_count
						> probing_threshold)
					set->dlist[idx].failure_count
						= probing_threshold;
			}
		}
	}
	/* Reset the Failure-Counter */
	if ((state & DS_RESET_FAIL_DST) > 0) {
		set->dlist[idx].failure_count = 0;
		state &= ~DS_RESET_FAIL_DST;
	}

	/* set the new state of the destination */
	old_flags = set->dlist[idx].flags;
	if(type)
		set->dlist[idx].flags |= state;
	else
		set->dlist[idx].flags &= ~state;

	if ( set->dlist[idx].flags != old_flags) {

		/* state actually changed -> do all updates */
		set->dlist[idx].flags |= DS_STATE_DIRTY_DST;

		/* replicate the change of status */
		if (do_repl) replicate_ds_status_event( &partition->name,
			set->id, address, state, type);

		/* update info on active destinations */
		if ( ((old_flags&(DS_PROBING_DST|DS_INACTIVE_DST))?0:1) !=
		((set->dlist[idx].flags&(DS_PROBING_DST|DS_INACTIVE_DST))?0:1) )
			/* this destination switched state between
			 * disabled <> enabled -> update active info */
			re_calculate_active_dsts( set );

		if (raise_event && evi_probe_event(dispatch_evi_id)) {
			if (!(list = evi_get_params()))
				return;

			if (partition != default_partition &&
			evi_param_add_str(list,&partition_str,&partition->name)){
				LM_ERR("unable to add partition parameter\n");
				evi_free_params(list);
				return;
			}
			if (evi_param_add_int(list, &group_str, &set->id)) {
				LM_ERR("unable to add group parameter\n");
				evi_free_params(list);
				return;
			}
			if (evi_param_add_str(list, &address_str, address)) {
				LM_ERR("unable to add address parameter\n");
				evi_free_params(list);
				return;
			}
			if (evi_param_add_str(list, &status_str,
						type ? &inactive_str : &active_str)) {
				LM_ERR("unable to add status parameter\n");
				evi_free_params(list);
				return;
			}
			if (evi_raise_event(dispatch_evi_id, list)) {
				LM_ERR("unable to send event\n");
			}
		} else {
			LM_DBG("no event sent\n");
		}

	} /* end 'if status changed' */
}

int ds_set_state_repl(int group, str *address, int state, int type,
		ds_partition_t *partition, int do_repl, int is_sync)
{
	int i=0;
	ds_set_p idx = NULL;

	if ( (*partition->data)->sets==NULL ){
		LM_DBG("empty destination set\n");
		return -1;
	}

	/* access ds data under reader's lock */
	lock_start_read( partition->lock );

	/* get the index of the set */
	if(ds_get_index(group, &idx, partition)!=0) {
		LM_ERR("destination set [%d] not found\n", group);
		lock_stop_read( partition->lock );
		return -1;
	}

	while(i<idx->nr)
	{
		if(idx->dlist[i].uri.len==address->len
				&& strncasecmp(idx->dlist[i].uri.s, address->s,
					address->len)==0)
		{
			if (is_sync) {
				if ((idx->dlist[i].flags & (DS_INACTIVE_DST|DS_PROBING_DST)) !=
					(state & (DS_INACTIVE_DST|DS_PROBING_DST))) {
					/* status has changed */
					if (state & DS_INACTIVE_DST) {
						_ds_set_state(idx, i, address, DS_INACTIVE_DST, 1,
							partition, 0, 0);
						_ds_set_state(idx, i, address, DS_PROBING_DST, 0,
							partition, 0, 0);
					} else if (state & DS_PROBING_DST) {
						_ds_set_state(idx, i, address, DS_PROBING_DST, 1,
							partition, 0, 0);
						_ds_set_state(idx, i, address, DS_INACTIVE_DST, 0,
							partition, 0, 0);
					} else {  /* set active */
						_ds_set_state(idx, i, address,
							DS_INACTIVE_DST|DS_PROBING_DST, 0, partition, 0, 0);
					}
				}
			} else
				_ds_set_state(idx, i, address, state, type, partition,
					do_repl, 1);

			lock_stop_read( partition->lock );
			return 0;
		}
		i++;
	}

	lock_stop_read( partition->lock );
	return -1;
}


/* Checks, if the request (sip_msg *_m) comes from a host in a set
 * (set-id or -1 for all sets)
 */
int ds_is_in_list(struct sip_msg *_m, str *_ip, int port, int set,
                  ds_partition_t *partition, int active_only)
{
	pv_value_t val;
	ds_set_p list;
	struct ip_addr *ip;
	int_str avp_val;
	int j,k;

	if (!(ip = str2ip(_ip)) && !(ip = str2ip6(_ip))) {
		LM_ERR("IP val is not IP <%.*s>\n",val.rs.len,val.rs.s);
		return -1;
	}

	memset(&val, 0, sizeof(pv_value_t));
	val.flags = PV_VAL_INT|PV_TYPE_INT;

	/* access ds data under reader's lock */
	lock_start_read( partition->lock );

	for(list = (*partition->data)->sets ; list!= NULL; list= list->next) {
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
						if (partition->attrs_avp_name>= 0) {
							avp_val.s = list->dlist[j].attrs;
							if(add_avp(AVP_VAL_STR|partition->attrs_avp_type,
										partition->attrs_avp_name,avp_val)!=0)
								goto error;
						}

						if (partition->script_attrs_avp_name>= 0) {
							avp_val.s = list->dlist[j].script_attrs;
							if(add_avp(AVP_VAL_STR|partition->script_attrs_avp_type,
										partition->script_attrs_avp_name,avp_val)!=0)
								goto error;
						}

						lock_stop_read( partition->lock );
						return 1;
					}
				}
			}
		}
	}

error:
	lock_stop_read( partition->lock );
	return -1;
}


int ds_print_mi_list(mi_item_t *part_item, ds_partition_t *partition, int full)
{
	int len, j;
	char* p;
	ds_set_p list;
	mi_item_t *sets_arr, *set_item, *dests_arr, *dest_item;

	if ( (*partition->data)->sets==NULL ) {
		LM_DBG("empty destination sets\n");
		return  0;
	}

	sets_arr = add_mi_array(part_item, MI_SSTR("SETS"));
	if (!sets_arr)
		return -1;

	/* access ds data under reader's lock */
	lock_start_read( partition->lock );

	for(list = (*partition->data)->sets ; list!= NULL; list= list->next) {
		set_item = add_mi_object(sets_arr, NULL, 0);
		if (!set_item)
			goto error;

		if (add_mi_number(set_item, MI_SSTR("id"), list->id) < 0)
			goto error;

		dests_arr = add_mi_array(set_item, MI_SSTR("Destinations"));
		if (!dests_arr)
			return -1;

		for(j=0; j<list->nr; j++)
		{
			dest_item = add_mi_object(dests_arr, NULL, 0);
			if (!dest_item)
				goto error;

			if (add_mi_string(dest_item, MI_SSTR("URI"),
				list->dlist[j].uri.s, list->dlist[j].uri.len) < 0)
				goto error;

			if (list->dlist[j].flags & DS_INACTIVE_DST) {
				if (add_mi_string(dest_item, MI_SSTR("state"),
					MI_SSTR("Inactive")) < 0)
					goto error;
			} else if (list->dlist[j].flags & DS_PROBING_DST) {
				if (add_mi_string(dest_item, MI_SSTR("state"),
					MI_SSTR("Probing")) < 0)
					goto error;
			} else
				if (add_mi_string(dest_item, MI_SSTR("state"),
					MI_SSTR("Active")) < 0)
					goto error;

			if (add_mi_number(dest_item, MI_SSTR("first_hit_counter"),
				list->dlist[j].chosen_count) < 0)
				goto error;

			if (list->dlist[j].sock)
			{
				p = socket2str(list->dlist[j].sock, NULL, &len, 0);
				if (p)
					if (add_mi_string(dest_item, MI_SSTR("socket"), p, len) < 0)
						goto error;
			}

			if (list->dlist[j].attrs.s)
				if (add_mi_string(dest_item, MI_SSTR("attr"),
					list->dlist[j].attrs.s, list->dlist[j].attrs.len) < 0)
					goto error;

			if (list->dlist[j].script_attrs.s)
				if (add_mi_string(dest_item, MI_SSTR("script_attr"),
					list->dlist[j].script_attrs.s, list->dlist[j].script_attrs.len) < 0)
					goto error;

			if (full) {
				if (add_mi_number(dest_item, MI_SSTR("weight"),
					list->dlist[j].weight) < 0)
					goto error;

				if (add_mi_number(dest_item, MI_SSTR("priority"),
					list->dlist[j].priority) < 0)
					goto error;

				if (list->dlist[j].description.len)
					if (add_mi_string(dest_item, MI_SSTR("description"),
						list->dlist[j].description.s,
						list->dlist[j].description.len) < 0)
						goto error;
			}
		}
	}

	lock_stop_read( partition->lock );
	return 0;

error:
	lock_stop_read( partition->lock );
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

	ds_options_callback_param_t *cb_param =
		(ds_options_callback_param_t*)(*ps->param);

	/* The SIP-URI is taken from the Transaction.
	 * Remove the "To: " (s+4) and the trailing new-line (s - 4 (To: )
	 * - 2 (\r\n)). */
	uri.s = t->to.s + 4;
	uri.len = t->to.len - 6;
	LM_DBG("OPTIONS-Request was finished with code %d (to %.*s, group %d)\n",
			ps->code, uri.len, uri.s, cb_param->set_id);

	/* ps->code contains the result-code of the request;
	 * We accept "200 OK" by default and the custom codes
	 * defined in options_reply_codes parameter*/
	if ((ps->code == 200) || check_options_rplcode(ps->code)) {
		/* Set the according entry back to "Active":
		 *  remove the Probing/Inactive Flag and reset the failure counter. */
		if (ds_set_state(cb_param->set_id, &uri,
					DS_INACTIVE_DST|DS_PROBING_DST|DS_RESET_FAIL_DST, 0,
					cb_param->partition) != 0)
		{
			LM_ERR("Setting the state failed (%.*s, group %d)\n", uri.len,
					uri.s, cb_param->set_id);
		}
	}
	/* if we always probe, and we get a timeout
	 * or a reponse that is not within the allowed
	 * reply codes, then disable*/
	if(ds_probing_mode==1 && ps->code != 200 &&
	(ps->code == 408 || !check_options_rplcode(ps->code)))
	{
		if (ds_set_state(cb_param->set_id, &uri, DS_PROBING_DST, 1,
					cb_param->partition) != 0)
		{
			LM_ERR("Setting the probing state failed (%.*s, group %d)\n",
					uri.len, uri.s, cb_param->set_id);
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
	ds_partition_t *partition;
	dlg_t *dlg;
	ds_set_p list;
	int j;

	if ( !ds_cluster_shtag_is_active() )
		return;

	for (partition = partitions; partition; partition = partition->next){
		/* Check for the list. */
		if ( (*partition->data)->sets==NULL )
			continue;

		/* access ds data under reader's lock */
		lock_start_read( partition->lock );

		/* Iterate over the groups and the entries of each group: */
		for( list=(*partition->data)->sets ; list!= NULL ; list= list->next)
		{
			for(j=0; j<list->nr; j++)
			{
				/* If list is probed by this proxy and the Flag of
				 * the entry has "Probing" set, send a probe: */
				if ( (!ds_probing_list || in_int_list(ds_probing_list, list->id)==0) &&
				((list->dlist[j].flags&DS_INACTIVE_DST)==0) &&
				(ds_probing_mode==1 || (list->dlist[j].flags&DS_PROBING_DST)!=0
				))
				{
					LM_DBG("probing set #%d, URI %.*s\n", list->id,
							list->dlist[j].uri.len, list->dlist[j].uri.s);

					/* Execute the Dialog using the "request"-Method of the
					 * TM-Module.*/
					if (tmb.new_auto_dlg_uac(&ds_ping_from,
					&list->dlist[j].uri, NULL, NULL,
					list->dlist[j].sock?list->dlist[j].sock:probing_sock,
					&dlg) != 0 ) {
						LM_ERR("failed to create new TM dlg\n");
						continue;
					}
					dlg->state = DLG_CONFIRMED;

					if (ds_ping_maxfwd>=0) {
						dlg->mf_enforced = 1;
						dlg->mf_value = (unsigned short)ds_ping_maxfwd;
					}

					ds_options_callback_param_t *cb_param =
								shm_malloc(sizeof(*cb_param));

					if (cb_param == NULL) {
						LM_CRIT("No more shared memory\n");
						continue;
					}
					cb_param->partition = partition;
					cb_param->set_id = list->id;
					if (tmb.t_request_within(&ds_ping_method,
							NULL,
							NULL,
							dlg,
							ds_options_callback,
							(void*)cb_param,
							osips_shm_free) < 0) {
						LM_ERR("unable to execute dialog\n");
						shm_free(cb_param);
					}
					tmb.free_dlg(dlg);
				}
			}
		}

		lock_stop_read( partition->lock );
	}
}

void ds_update_weights(unsigned int ticks, void *param)
{
	ds_partition_t *part;
	ds_set_p sp;

	for (part = partitions; part; part = part->next) {
		lock_start_write(part->lock);
		for (sp = (*part->data)->sets; sp; sp = sp->next) {
			if (sp->redo_weights) {
				re_calculate_active_dsts(sp);
			}
		}
		lock_stop_write(part->lock);
	}
}

int ds_count(struct sip_msg *msg, int set_id, void *_cmp, pv_spec_p ret,
				ds_partition_t *partition)
{
	pv_value_t pv_val;
	ds_set_p set;
	ds_dest_p dst;
	int count, active = 0, inactive = 0, probing = 0;
	int cmp = (int)(long)_cmp;

	LM_DBG("Searching for set: %d, filtering: %d\n", set_id, cmp);

	/* access ds data under reader's lock */
	lock_start_read( partition->lock );

	if ( ds_get_index( set_id, &set, partition)!=0 ) {
		LM_ERR("INVALID SET %d (not found)!\n",set_id);
		lock_stop_read( partition->lock );
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

	lock_stop_read( partition->lock );

	switch (cmp)
	{
		case DS_COUNT_ACTIVE:
			count = active;
			break;

		case DS_COUNT_ACTIVE|DS_COUNT_INACTIVE:
		case DS_COUNT_ACTIVE|DS_COUNT_PROBING:
			count = (cmp & DS_COUNT_INACTIVE ? active + inactive :
												active + probing);
			break;

		case DS_COUNT_INACTIVE:
		case DS_COUNT_PROBING:
			count = (cmp == DS_COUNT_INACTIVE ? inactive : probing);
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


/*
 * Find partition by name. Return null if no partition is matching the name
 */
ds_partition_t* find_partition_by_name (const str *partition_name)
{
	if (partition_name->len == 0)
		return default_partition;

	ds_partition_t *part_it;

	for (part_it = partitions; part_it; part_it = part_it->next)
		if (str_strcmp(&part_it->name, partition_name) == 0)
			break;

	return part_it; //and NULL if there's no partition matching the name
}

int ds_push_script_attrs(struct sip_msg *_m, str *script_attrs, 
		str *_ip, int port, int set, ds_partition_t *partition)
{
	ds_set_p list;
	struct ip_addr *ip;
	int j,k;

	if (!(ip = str2ip(_ip)) && !(ip = str2ip6(_ip))) {
		LM_ERR("IP val is not IP <%.*s>\n",_ip->len,_ip->s);
		return -1;
	}

	/* access ds data under reader's lock */
	lock_start_write( partition->lock );

	for(list = (*partition->data)->sets ; list!= NULL; list= list->next) {
		if ((set == -1) || (set == list->id)) {
			/* interate through all elements/destinations in the list */
			for(j=0; j<list->nr; j++) {
				/* interate through all IPs of each destination */
				for(k=0 ; k<list->dlist[j].ips_cnt ; k++ ) {
					if ( (list->dlist[j].ports[k]==0 || port==0
					|| port==list->dlist[j].ports[k]) &&
					ip_addr_cmp( ip, &list->dlist[j].ips[k]) ) {
						/* matching destination */
						
						list->dlist[j].script_attrs.s = shm_realloc(list->dlist[j].script_attrs.s,script_attrs->len);
						if (list->dlist[j].script_attrs.s == NULL) {
							LM_ERR("No more shm :( \n");
							goto error;
						}

						list->dlist[j].script_attrs.len = script_attrs->len;
						memcpy(list->dlist[j].script_attrs.s,script_attrs->s,script_attrs->len);
						
					}
				}
			}
		}
	}

	lock_stop_write( partition->lock );
	return 1;

error:
	lock_stop_write( partition->lock );
	return -1;

}

int ds_get_script_attrs(struct sip_msg *_m,str *uri,int set, 
	ds_partition_t *partition, pv_spec_t *attrs)
{
	pv_value_t val;
	ds_set_p list;
	int j;

	memset(&val, 0, sizeof(pv_value_t));
	val.flags = PV_VAL_STR;

	lock_start_read( partition->lock );

	for(list = (*partition->data)->sets ; list!= NULL; list= list->next) {
		if ((set == -1) || (set == list->id)) {
			/* interate through all elements/destinations in the list */
			for(j=0; j<list->nr; j++) {
				if (list->dlist[j].dst_uri.len == uri->len && 
				memcmp(list->dlist[j].dst_uri.s,uri->s,uri->len) == 0) {

					val.rs = list->dlist[j].script_attrs;	
					if (pv_set_value(_m,attrs,0,&val) != 0) {
						LM_ERR("Failed to set value for script attrs \n");
					}
					lock_stop_read( partition->lock );
					return 1;
				} 
			}
		}
	}

	lock_stop_read( partition->lock );
	return -1;
}
