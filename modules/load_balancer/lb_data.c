/*
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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



#include <stdio.h>
#include <stdlib.h>

#include "../../proxy.h"
#include "../../parser/parse_uri.h"
#include "../../mem/shm_mem.h"
#include "../../evi/evi.h"
#include "../../rw_locking.h"
#include "lb_parser.h"
#include "lb_data.h"
#include "lb_clustering.h"
#include "lb_db.h"

/* dialog stuff */
extern struct dlg_binds lb_dlg_binds;

extern int fetch_freeswitch_stats;
extern int initial_fs_load;
extern struct fs_binds fs_api;

/* reader-writers lock for data reloading */
rw_lock_t *ref_lock = NULL;


struct lb_data* load_lb_data(void)
{
	struct lb_data *data;

	data = (struct lb_data*) shm_malloc( sizeof(struct lb_data) );
	if (data==NULL) {
		LM_ERR("failed to allocate shm mem\n");
		return NULL;
	}
	memset( data, 0, sizeof(struct lb_data));

	if (lb_db_load_data(data)!=0) {
		LM_ERR("failed to load data from DB\n");
		free_lb_data(data);
		return NULL;
	}

	return data;
}


struct lb_resource *get_resource_by_name(struct lb_data *data, str *name)
{
	struct lb_resource *res;

	for( res=data->resources ; res ; res=res->next ) {
		if (name->len==res->name.len &&
		memcmp( name->s, res->name.s, name->len)==0) {
			LM_DBG("found resource [%.*s]\n",name->len,name->s);
			return res;
		}
	}

	return NULL;
}


static struct lb_resource *add_lb_resource(struct lb_data *data, str *name)
{
	#define PROFILE_MAX_NAME 256
	char buf[PROFILE_MAX_NAME];
	struct lb_resource *new_res;
	struct lb_resource *res;
	struct lb_resource *p_res;
	str profile_name;
	int o;

	LM_DBG(" new resource name=<%.*s>\n",name->len,name->s);

	new_res = (struct lb_resource*)shm_malloc
		( sizeof(struct lb_resource) + name->len );
	if (new_res==NULL) {
		LM_ERR("failed to allocate shm mem (%ld)\n",
			(unsigned long)(sizeof(struct lb_resource) + name->len) );
		return NULL;
	}
	memset( new_res , 0 , sizeof(struct lb_resource));

	new_res->name.s = (char*)(new_res+1);
	new_res->name.len = name->len;
	memcpy( new_res->name.s, name->s, name->len );

	/* create & init lock */
	if ( (new_res->lock=lock_alloc())==0) {
		LM_CRIT("failed to alloc lock\n");
		goto error;
	}
	if (lock_init(new_res->lock)==0 ) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}

	/* create and get new dialog profile */
	profile_name.len = snprintf( buf, PROFILE_MAX_NAME-1, "lbX%.*s",
		name->len,name->s);
	profile_name.s = buf;
	/* first check if the profile already exists */
	new_res->profile = lb_dlg_binds.search_profile( &profile_name );
	if (new_res->profile==NULL) {
		/* create a new one */
		LM_DBG("adding dialog profile <%.*s>\n",
			profile_name.len,profile_name.s);
		if (lb_dlg_binds.add_profiles( buf, 1 /*has value*/ )!=0) {
			LM_ERR("failed to add dialog profile <%s>\n",buf);
			goto error;
		}
		new_res->profile = lb_dlg_binds.search_profile( &profile_name );
		if (new_res->profile==NULL) {
			LM_CRIT("bug - cannot find just added profile\n");
			goto error;
		}
	} else {
		LM_DBG("dialog profile <%.*s> found created\n",
			profile_name.len,profile_name.s);
	}

	/* keep the list alphabetical ordered */
	p_res = NULL;
	res = data->resources;
	while (res) {
		o =  (name->len < res->name.len)?
			strncmp(name->s, res->name.s, name->len):
			strncmp(name->s, res->name.s, res->name.len);
		if (o>0)
			/* add between p_res and res */
			break;
		p_res = res;
		res = res->next;
	}
	if (p_res==NULL) {
		/* add at the beginning */
		new_res->next = data->resources;
		data->resources = new_res;
		LM_DBG("adding <%.*s> as head\n",name->len,name->s);
	} else if (res==NULL) {
		/* add at the end */
		p_res->next = new_res;
		LM_DBG("adding <%.*s> after <%.*s>\n",
			name->len,name->s,p_res->name.len,p_res->name.s);
	} else {
		/* add in the middle */
		new_res->next = res;
		p_res->next = new_res;
		LM_DBG("adding <%.*s> after <%.*s>\n",
			name->len,name->s,p_res->name.len,p_res->name.s);
	}

	data->res_no ++;

	return new_res;
error:
	if (new_res->lock) {
		lock_destroy( new_res->lock );
		lock_dealloc( new_res->lock );
		new_res->lock = 0;
	}
	shm_free(new_res);
	return NULL;
}


static int lb_set_resource_bitmask(struct lb_resource *res, unsigned int bit)
{
	#define BITMAP_UNIT 4
	unsigned int size;

	if ( bit >= res->bitmap_size*8*sizeof(unsigned int) ) {
		size = (bit / (8*sizeof(unsigned int)))+1;
		size = ((size+BITMAP_UNIT-1) / BITMAP_UNIT ) * BITMAP_UNIT;
		LM_DBG("realloc the bitmap for bit %u - old size=%u; new size=%u\n",
			bit, res->bitmap_size, size);
		res->dst_bitmap = (unsigned int*)shm_realloc( res ->dst_bitmap,
			size*sizeof(unsigned int));
		if (res->dst_bitmap==NULL) {
			LM_ERR("failed to realloc (shm) bitmap\n");
			return -1;
		}
		/* set to zero the new allocated bitmap part */
		memset( res->dst_bitmap+res->bitmap_size, 0,
			(size-res->bitmap_size)*sizeof(unsigned int) );
		res->bitmap_size = size;
	}
	/* set the bit */
	size = bit / (8*sizeof(unsigned int));
	LM_DBG("setting bit %u in unit %u , pos %d\n", bit, size,
		bit % ((unsigned int)(8*sizeof(unsigned int))));
	res->dst_bitmap[size] |= 1<<( bit % (8*sizeof(unsigned int)) );

	return 0;
}


int add_lb_dsturi( struct lb_data *data, int id, int group, char *uri,
						char* resource, char* attrs, unsigned int flags)
{
	struct lb_res_str_list *lb_rl;
	struct lb_res_str *r;
	struct lb_dst *dst;
	struct lb_resource *res;
	struct sip_uri puri;
	struct proxy_l *proxy;
	union sockaddr_union sau;
	int uri_len, attrs_len;
	int i;
	str fs_url = { NULL, 0 };
	str lb_str = { MI_SSTR("load_balancer") };

	LM_DBG("uri=<%s>, grp=%d, res=<%s>\n",uri, group, resource);

	/* check uri */
	uri_len = strlen(uri);
	if(parse_uri(uri, uri_len, &puri)!=0 ) {
		LM_ERR("bad uri [%.*s] for destination\n", uri_len, uri);
		return -1;
	}

	/* parse the resources string */
	lb_rl = parse_resources_list( resource, 1);
	if (lb_rl==NULL) {
		LM_ERR("failed to parse resourse string <%s>\n",resource);
		return -1;
	}

	attrs_len = attrs ? strlen(attrs) : 0;

	/*add new destination */
	dst = (struct lb_dst*)shm_malloc( sizeof(struct lb_dst)
		+ lb_rl->n*sizeof(struct lb_resource_map) + uri_len + attrs_len +
		(3+2*sizeof(struct lb_dst*)));
	if (dst==NULL) {
		LM_ERR("failed to get shmem\n");
		goto error;
	}
	memset( dst, 0, sizeof(struct lb_dst)+
		lb_rl->n*sizeof(struct lb_resource_map) + uri_len + attrs_len +
		(3+2*sizeof(struct lb_dst*)) );

	dst->rmap = (struct lb_resource_map*)(dst+1);

	dst->uri.s = (char*)(dst->rmap + lb_rl->n);
	dst->uri.len = uri_len;
	memcpy( dst->uri.s , uri, uri_len);

	dst->attrs.s = dst->uri.s + uri_len;
	dst->attrs.len = attrs_len;
	memcpy(dst->attrs.s, attrs, attrs_len);

	dst->profile_id.s = dst->attrs.s + attrs_len;
	dst->profile_id.len = snprintf(dst->profile_id.s,
		2+2*sizeof(struct lb_dst*), "%X", id);

	dst->id = id;
	dst->group = group;
	dst->rmap_no = lb_rl->n;
	dst->flags = flags;

	/* add or update resource list */
	for( i=0 ; i<lb_rl->n ; i++) {
		r = lb_rl->resources + i;
		LM_DBG(" setting for uri=<%s> (%d) resource=<%.*s>, val=%d, fs=%.*s\n",
			uri, data->dst_no+1, r->name.len, r->name.s, r->val,
		    r->fs_url.len, r->fs_url.s);
		res = get_resource_by_name( data, &r->name);
		if (res==NULL) {
			/* add new resource */
			res = add_lb_resource(data, &r->name);
			if (res==NULL) {
				LM_ERR("failed to create new resource\n");
				goto error;
			}
		}
		/* set the proper bit in the resource */
		if (lb_set_resource_bitmask( res, data->dst_no)==-1 ) {
			LM_ERR("failed to set destination bit\n");
			goto error;
		}
		/* set the pointer and the max load */
		dst->rmap[i].resource = res;
		if (fetch_freeswitch_stats && r->fs_url.s) {
			fs_url = r->fs_url;
			dst->rmap[i].max_load = initial_fs_load;
			dst->rmap[i].fs_enabled = 1;
		} else {
			dst->rmap[i].max_load = r->val;
		}
	}

	/* Do a SIP wise DNS-Lookup for the domain part */
	proxy = mk_proxy( &puri.host, puri.port_no, puri.proto,
		(puri.type==SIPS_URI_T));
	if (proxy==NULL) {
		LM_ERR("could not resolve %.*s\n", puri.host.len, puri.host.s);
		goto error;
	}
	hostent2ip_addr( &dst->ips[0], &proxy->host, proxy->addr_idx);
	dst->ports[0] = proxy->port;
	dst->protos[0] = proxy->proto;
	dst->ips_cnt = 1;
	LM_DBG("first dst ip addr [%s]:%d\n",
		ip_addr2a(&dst->ips[0]), dst->ports[0]);
	/* get the next available IPs from DNS */
	while (dst->ips_cnt<LB_MAX_IPS && (get_next_su( proxy, &sau, 0)==0) ) {
		su2ip_addr( &dst->ips[dst->ips_cnt], &sau);
		dst->ports[dst->ips_cnt] = proxy->port;
		dst->protos[dst->ips_cnt] = proxy->proto;
		LM_DBG("additional dst ip addr [%s]:%d, proto %d\n",
			ip_addr2a(&dst->ips[dst->ips_cnt]),
			dst->ports[dst->ips_cnt], dst->protos[dst->ips_cnt] );
		/* one more IP found */
		dst->ips_cnt++;
	}
	/* free al the helper structures */
	free_proxy(proxy);
	pkg_free(proxy);

	if (fetch_freeswitch_stats && fs_url.s && fs_url.len > 0) {
		dst->fs_sock = fs_api.get_stats_evs(&fs_url, &lb_str);
		if (!dst->fs_sock) {
			LM_ERR("failed to create FreeSWITCH stats socket!\n");
		}
	}

	/* link at the end */
	if (data->last_dst==NULL) {
		data->dsts = data->last_dst = dst;
	} else {
		data->last_dst->next = dst;
		data->last_dst = dst;
	}
	data->dst_no++;

	pkg_free(lb_rl);
	return 0;
error:
	shm_free(dst);
	pkg_free(lb_rl);
	return -1;
}


void free_lb_data(struct lb_data *data)
{
	struct lb_resource *lbr1, *lbr2;
	struct lb_dst *lbd1, *lbd2;
	str lb_str = { MI_SSTR("load_balancer") };

	if (data==NULL)
		return;

	/* free resources */
	for( lbr1=data->resources ; lbr1 ; ) {
		lbr2 = lbr1;
		lbr1 = lbr1->next;
		if (lbr2->dst_bitmap)
			shm_free(lbr2->dst_bitmap);
		if (lbr2->lock) {
			lock_destroy( lbr2->lock );
			lock_dealloc( lbr2->lock );
		}
		shm_free(lbr2);
	}

	/* free destinations */
	for( lbd1=data->dsts ; lbd1 ; ) {
		lbd2 = lbd1;
		lbd1 = lbd1->next;
		if (lbd2->fs_sock) {
			fs_api.put_stats_evs(lbd2->fs_sock, &lb_str);
		}
		shm_free(lbd2);
	}

	shm_free(data);

	return;
}


static int get_dst_load(struct lb_resource **res, unsigned int res_no,
							struct lb_dst *dst, unsigned int flags, int *load)
{
	unsigned int k, l;
	int av;

	/* iterate through requested resources */
	for( k=0 ; k<res_no ; k++ ) {
		for (l=0 ; l<dst->rmap_no ; l++ )
			if( res[k] == dst->rmap[l].resource )
				break;
		if( l == dst->rmap_no ) {
			LM_CRIT("bug - cannot find request resource in dst\n");
			return 0;
		}

		av = 0;
		if( flags & LB_FLAGS_RELATIVE ) {
			if( dst->rmap[l].max_load )
				av = 100 - (100 * lb_dlg_binds.get_profile_size(res[k]->profile, &dst->profile_id) / dst->rmap[l].max_load);
		} else {
			av = dst->rmap[l].max_load - lb_dlg_binds.get_profile_size(res[k]->profile, &dst->profile_id);
		}

		if( (k == 0/*first iteration*/) || (av < *load ) )
			*load = av;
		/*
		we possibly could have negative avaliability for any resource,
		because we could use LB_FLAGS_NEGATIVE or manually increment resource
		with lb_count_call()
		*/
	}
	return (k > 0); /* load initialized */
}


/* Performce the LB logic. It may return:
 *   0 - success
 *  -1 - generic error
 *  -2 - no capacity (destinations may exist)
 *  -3 - no destination at all
 *  -4 - bad resources
 */
int lb_route(struct sip_msg *req, int group, struct lb_res_str_list *rl,
					unsigned int flags, struct lb_data *data, int reuse, str *attrs)
{
	/* resources for previous iteration */
	static struct lb_resource **res_prev = NULL;
	static unsigned int res_prev_size = 0;
	/* resources for new iteration */
	static struct lb_resource **res_new = NULL;
	static unsigned int res_new_size = 0;
	/* probed destinations bitmap */
	static unsigned int *dst_bitmap = NULL;
	static unsigned int bitmap_size = 0;
	/* selected destinations buffer */
	static struct lb_dst **dsts = NULL;
	static unsigned int dsts_size = 0;

	/* control vars */
	struct lb_resource **res_cur;
	int res_prev_n, res_new_n, res_cur_n;
	struct lb_dst **dsts_cur;
	struct lb_dst *last_dst, *dst;
	unsigned int dsts_size_cur, dsts_size_max;
	unsigned int *dst_bitmap_cur;
	unsigned int bitmap_size_cur;
	struct dlg_cell *dlg;

	/* AVP related vars */
	struct usr_avp *group_avp;
	struct usr_avp *flags_avp;
	struct usr_avp *mask_avp;
	struct usr_avp *id_avp;
	struct usr_avp *res_avp;
	int_str group_val;
	int_str flags_val;
	int_str mask_val;
	int_str id_val;
	int_str res_val;

	/* iterators, e.t.c. */
	struct lb_dst *it_d;
	struct lb_resource *it_r;
	int load, it_l;
	int i, j, cond, cnt_aval_dst;


	/* init control vars state */
	res_cur = NULL;
	res_cur_n = res_prev_n = res_new_n = 0;
	last_dst = dst = NULL;
	dst_bitmap_cur = NULL;

	/* search and fill new resources references if we should not reuse
	   previous iteration data */
	if( !reuse ) {
		res_new_n = rl->n;
		/* adjust size of statically allocated buffer */
		if( res_new_n > res_new_size ) {
			res_new = (struct lb_resource **)pkg_realloc
				(res_new, (res_new_n * sizeof(struct lb_resource *)));
			if( res_new == NULL ) {
				res_new_size = 0;
				LM_ERR("no more pkg mem - resources ptr buffer realloc "
					"failure\n");
				return -1;
			}
			res_new_size = res_new_n;
		}
		/* fill resource references */
		for( it_r=data->resources,i=0 ; it_r ; it_r=it_r->next ) {
			if( search_resource_str(rl, &it_r->name) ) {
				res_new[i++] = it_r;
				LM_DBG("initial call of LB - found requested %d/%d "
					"resource [%.*s]\n", i, res_new_n,
					it_r->name.len, it_r->name.s);
			}
		}
		if( i != res_new_n ) {
			LM_ERR("initial call of LB - unknown resource found in "
				"input string\n");
			return -4;
		}

		/* set 'res_new' as current iteration buffer */
		res_cur = res_new;
		res_cur_n = res_new_n;
	}

	/* always search for previous iteration data,
	   no matter if we will reuse it or not */
	group_avp = search_first_avp(0, group_avp_name, &group_val, NULL);
	flags_avp = search_first_avp(0, flags_avp_name, &flags_val, NULL);
	mask_avp  = search_first_avp(0, mask_avp_name,  &mask_val,  NULL);
	id_avp    = search_first_avp(0, id_avp_name,    &id_val,    NULL);
	/* sanity checks for fetched AVPs */
	if( group_avp && !(is_avp_str_val(group_avp) == 0) )
		{ destroy_avp(group_avp); group_avp = NULL; }
	if( flags_avp && !(is_avp_str_val(flags_avp) == 0) )
		{ destroy_avp(flags_avp); flags_avp = NULL; }
	if( mask_avp  && !(is_avp_str_val(mask_avp)  != 0) )
		{ destroy_avp(mask_avp);  mask_avp  = NULL; }
	if( id_avp    && !(is_avp_str_val(id_avp)    == 0) )
		{ destroy_avp(id_avp);    id_avp    = NULL; }

	/* get previous iteration destination, if any */
	if( id_avp ) {
		for( it_d=data->dsts ; it_d ; it_d=it_d->next ) {
			if( it_d->id == id_val.n ) {
				last_dst = it_d;
				LM_DBG("%s call of LB - found previous dst %d [%.*s]\n",
					(reuse ? "sequential" : "initial"), last_dst->id,
					last_dst->profile_id.len, last_dst->profile_id.s);
				break;
			}
		}
	}
	/* search and fill previous iteration resources references only if... */
	if(
		/* we should reuse previous resources list */
		reuse ||
		/* we have 'last_dst', i.e. previous iteration was successful and
		 * we need to clean it up */
		(last_dst != NULL)
	) {
		do {
			cond = 0; /* use it here as a 'start loop again' flag */
			res_prev_n = 0;
			res_avp = search_first_avp(0, res_avp_name, &res_val, NULL);
			for( ; res_avp ; res_avp=search_next_avp(res_avp, &res_val) ) {
				/* ignore AVPs with invalid type */
				if( !(is_avp_str_val(res_avp) != 0) ) continue;

				if ( (it_r=get_resource_by_name( data, &res_val.s))==NULL ) {
					LM_WARN("%s call of LB - ignore unknown previous "
						"resource [%.*s]\n", (reuse?"sequential":"initial"),
						res_val.s.len, res_val.s.s);
					continue;
				}
				/* fill buffer only if buffer size not exeeded */
				if( res_prev_n < res_prev_size ) {
					res_prev[res_prev_n] = it_r;
					LM_DBG("%s call of LB - found previous resource [%.*s]\n",
						(reuse ? "sequential" : "initial"),
						it_r->name.len, it_r->name.s);
				}
				res_prev_n++;
			}
			/* adjust size of statically allocated buffer */
			if( res_prev_n > res_prev_size ) {
				/* small hack: if we need to adjust 'res_prev' buffer adjust
				 * it according to 'res_new' size to minimize 
				 * future pkg_realloc()'s */
				if( !reuse && (res_prev_n < res_new_n) )
					res_prev_n = res_new_n;

				res_prev = (struct lb_resource **)pkg_realloc
					(res_prev, (res_prev_n * sizeof(struct lb_resource *)));
				if( res_prev == NULL ) {
					res_prev_size = 0;
					LM_ERR("no more pkg mem - previous resources ptr "
						"buffer realloc failure\n");
					return -1;
				}
				res_prev_size = res_prev_n;
				cond = 1;
			}
		}
		while( cond );
	}

	/* reuse previous iteration resources, group and flags */
	if( reuse ) {
		/* set 'res_prev' as current iteration buffer */
		res_cur = res_prev;
		res_cur_n = res_prev_n;
		if( res_cur_n == 0 ) {
			LM_ERR("sequential call of LB - cannot find previous resources\n");
			return -1;
		}
		if( group_avp )
			group = group_val.n;
		else {
			LM_ERR("sequential call of LB - cannot find previous group\n");
			return -1;
		}
		if( flags_avp )
			flags = flags_val.n;
		else
			flags = LB_FLAGS_DEFAULT;

		LM_DBG("sequential call of LB - found previous group %d and "
			"flags 0x%x\n", group, flags);
	}

	/* sanity check - double check that we have a resource list to work with */
	if( (res_cur == NULL) || (res_cur_n == 0) ) {
		LM_ERR("%s call of LB - no resources list to work with\n",
			(reuse ? "sequential" : "initial"));
		return -1;
	}


	/* [re-]initialize/reuse destinations mask */

	/* sanity check - always calculate current iteration
	 * res_cur[]->bitmap_size */
	bitmap_size_cur=(unsigned int)(-1);
	for( i=0 ; i<res_cur_n ; i++ ) {
		if( bitmap_size_cur > res_cur[i]->bitmap_size )
			bitmap_size_cur = res_cur[i]->bitmap_size;
	}
	/* always try to reuse 'mask' buffer from AVP, even if we need 
	 * to reinitialize it to avoid un-neded AVP ops */
	if(mask_avp && (mask_val.s.len==(bitmap_size_cur*sizeof(unsigned int)))) {
		dst_bitmap_cur = (unsigned int *)mask_val.s.s;
	}
	/* ...or use our static buffer */
	if( dst_bitmap_cur == NULL ) {
		/* adjust size of statically allocated buffer */
		if( bitmap_size_cur > bitmap_size ) {
			dst_bitmap = (unsigned int *)pkg_realloc
				(dst_bitmap, (bitmap_size_cur * sizeof(unsigned int)));
			if( dst_bitmap == NULL ) {
				bitmap_size = 0;
				LM_ERR("no more pkg mem - dst bitmap buffer realloc failed\n");
				return -1;
			}
			bitmap_size = bitmap_size_cur;
		}
		dst_bitmap_cur = dst_bitmap;
	}
	/* reinitalize buffer if... */
	if(
		(dst_bitmap_cur == dst_bitmap) || /* it is our static buffer */
		!reuse /* should not reuse previous iteration data */
	) {
		if( reuse ) {
			LM_WARN("sequential call of LB - cannot %s previous mask, routing "
				"will be re-started", (mask_avp ? "reuse" : "find"));
		}

		memset(dst_bitmap_cur, 0xff, (bitmap_size_cur * sizeof(unsigned int)));
		for( i=0 ; i<res_cur_n ; i++ ) {
			for( j=0 ; j<bitmap_size_cur ; j++ )
				dst_bitmap_cur[j] &= res_cur[i]->dst_bitmap[j];
		}
	}

	/* init selected destinations buff */
	dsts_cur = NULL;
	dsts_size_max = (flags & LB_FLAGS_RANDOM) ? data->dst_no : 1;
	if( dsts_size_max > 1 ) {
		if( dsts_size_max > dsts_size ) {
			dsts = (struct lb_dst **)pkg_realloc
				(dsts, (dsts_size_max * sizeof(struct lb_dst *)));
			if( dsts == NULL ) {
				dsts_size_max = dsts_size = 0;
				LM_WARN("no more pkg mem - dsts buffer realloc failed\n");
			}
			else
				dsts_size = dsts_size_max;
		}
		dsts_cur = dsts;
	}
	if( dsts_cur == NULL ) {
		/* fallback to no-buffer / 'select first' scenario */
		dsts_cur = &dst;
		dsts_size_max = 1;
	}

	/* be sure the dialog is created */
	if ( (dlg=lb_dlg_binds.get_dlg())==NULL ) {
		if( lb_dlg_binds.create_dlg(req, 0) != 1 ) {
			LM_ERR("%s call of LB - failed to create dialog\n",
				(reuse ? "sequential" : "initial"));
			return -1;
		}
		/* get the dialog reference */
		dlg = lb_dlg_binds.get_dlg();
	}

	/* we're initialized from here and no errors could abort us */

	/* remove the dialog from previous profiles, if any */
	if ( (last_dst != NULL) && (res_prev_n > 0) ) {
		for( i=0 ; i<res_prev_n ; i++ ) {
			if( lb_dlg_binds.unset_profile(dlg, &last_dst->profile_id,
			res_prev[i]->profile) != 1 )
				LM_ERR("%s call of LB - failed to remove from profile [%.*s]"
					"->[%.*s]\n", (reuse ? "sequential" : "initial"),
					res_prev[i]->profile->name.len,
					res_prev[i]->profile->name.s, last_dst->profile_id.len,
					last_dst->profile_id.s );
		}
	}


	/* lock resources */
	for( i=0 ; i<res_cur_n ; i++ )
		lock_get(res_cur[i]->lock);

	/* do the load-balancing */

	/*  select destinations */
	cond = 0; /* use it here as a 'first iteration' flag */
	load = it_l = 0;
	dsts_size_cur = 0;
	cnt_aval_dst = 0;
	for( it_d=data->dsts,i=0,j=0 ; it_d ; it_d=it_d->next ) {
		if( it_d->group == group ) {
			if( (dst_bitmap_cur[i] & (1 << j)) &&
			((it_d->flags & LB_DST_STAT_DSBL_FLAG) == 0) ) {
				/* valid destination (group & resources & status) */
				cnt_aval_dst++;
				if( get_dst_load(res_cur, res_cur_n, it_d, flags, &it_l) ) {
					/* only valid load here */
					if( (it_l > 0) || (flags & LB_FLAGS_NEGATIVE) ) {
						/* only allowed load here */
						if( !cond/*first pass*/ || (it_l > load)/*new max*/ ) {
							cond = 1;
							/* restart buffer */
							dsts_size_cur = 0;
						} else if( it_l < load ) {
							/* lower availability -> new iteration */
							if( ++j == (8 * sizeof(unsigned int)) ) { i++; j=0; }
							continue;
						}

						/* add destination to to selected destinations buffer,
						 * if we have a room for it */
						if( dsts_size_cur < dsts_size_max ) {
							load = it_l;
							dsts_cur[dsts_size_cur++] = it_d;

							LM_DBG("%s call of LB - destination %d <%.*s> "
								"selected for LB set with free=%d\n",
								(reuse ? "sequential" : "initial"),
								it_d->id, it_d->uri.len, it_d->uri.s, it_l
							);
						}
					}
				} else {
					LM_WARN("%s call of LB - skipping destination %d <%.*s> - "
						"unable to calculate free resources\n",
						(reuse ? "sequential" : "initial"),
						it_d->id, it_d->uri.len, it_d->uri.s
					);
				}
			}
			else {
				LM_DBG("%s call of LB - skipping destination %d <%.*s> "
					"(filtered=%d , disabled=%d)\n",
					(reuse ? "sequential" : "initial"),
					it_d->id, it_d->uri.len, it_d->uri.s,
					((dst_bitmap_cur[i] & (1 << j)) ? 0 : 1),
					((it_d->flags & LB_DST_STAT_DSBL_FLAG) ? 1 : 0)
				);
			}
		}
		if( ++j == (8 * sizeof(unsigned int)) ) { i++; j=0; }
	}
	/* choose one destination among selected */
	if( dsts_size_cur > 0 ) {
		if( (dsts_size_cur > 1) && (flags & LB_FLAGS_RANDOM) ) {
			dst = dsts_cur[rand() % dsts_size_cur];
		} else {
			dst = dsts_cur[0];
		}
	}


	if( dst != NULL ) {
		LM_DBG("%s call of LB - winning destination %d <%.*s> selected "
			"for LB set with free=%d\n",
			(reuse ? "sequential" : "initial"),
			dst->id, dst->uri.len, dst->uri.s, load );

		/* add to the profiles */
		for( i=0 ; i<res_cur_n ; i++ ) {
			if( lb_dlg_binds.set_profile(dlg, &dst->profile_id,
			res_cur[i]->profile, 0) != 0 )
				LM_ERR("%s call of LB - failed to add to profile [%.*s]->"
					"[%.*s]\n", (reuse ? "sequential" : "initial"),
					res_cur[i]->profile->name.len, res_cur[i]->profile->name.s,
					dst->profile_id.len, dst->profile_id.s);
		}

		/* set dst as used (not selected) */
		for( it_d=data->dsts,i=0,j=0 ; it_d ; it_d=it_d->next ) {
			if( it_d == dst ) { dst_bitmap_cur[i] &= ~(1 << j); break; }
			if( ++j == (8 * sizeof(unsigned int)) ) { i++; j=0; }
		}
	} else {
		LM_DBG("%s call of LB - no destination found\n",
			(reuse ? "sequential" : "initial"));
	}

	/* unlock resources */
	for( i=0 ; i<res_cur_n ; i++ )
		lock_release(res_cur[i]->lock);

	/* we're done with load-balancing, now save state */

	/* save state - group */
	if( group_avp == NULL ) {
		group_val.n = group;
		if( add_avp(0, group_avp_name, group_val) != 0 ) {
			LM_ERR("failed to add GROUP AVP\n");
		}
	} else if( group_val.n != group ) {
		group_avp->data = (void *)(long)group;
	}
	/* save state - flags, save only if they are set */
	if( flags_avp == NULL ) {
		if( flags != LB_FLAGS_DEFAULT ) {
			flags_val.n = flags;
			if( add_avp(0, flags_avp_name, flags_val) != 0 ) {
				LM_ERR("failed to add FLAGS AVP\n");
			}
		}
	} else if( flags_val.n != flags ) {
		flags_avp->data = (void *)(long)flags;
	}
	/* save state - dst_bitmap mask */
	if( (mask_avp!=NULL) && (dst_bitmap_cur!=(unsigned int *)mask_val.s.s) ) {
		destroy_avp(mask_avp);
		mask_avp = NULL;
	}
	if( mask_avp == NULL ) {
		mask_val.s.s = (char *)dst_bitmap_cur;
		mask_val.s.len = bitmap_size_cur * sizeof(unsigned int);
		if( add_avp(AVP_VAL_STR, mask_avp_name, mask_val) != 0 ) {
			LM_ERR("failed to add MASK AVP\n");
		}
	}
	/* save state - dst, save only if we have one */
	if( id_avp == NULL ) {
		if( dst != NULL ) {
			id_val.n = dst->id;
			if( add_avp(0, id_avp_name, id_val) != 0 ) {
				LM_ERR("failed to add ID AVP\n");
			}
		}
	} else {
		if( dst != NULL ) {
			id_avp->data = (void *)(long)dst->id;
		} else {
			destroy_avp(id_avp);
			id_avp = NULL;
		}
	}
	/* save state - res */
	/* iterate AVPs once and delete old resources */
	destroy_avps(0, res_avp_name, 1 /*all*/);
	/* add new resources */
	for( i=0 ; i<res_cur_n ; i++ ) {
		res_val.s = res_cur[i]->name;
		if( add_avp_last(AVP_VAL_STR, res_avp_name, res_val) != 0 )
			LM_ERR("failed to add RES AVP\n");
	}

	/* outcome: set dst uri */
	if( (dst != NULL) && (set_dst_uri(req, &dst->uri) != 0) ) {
		LM_ERR("failed to set duri\n");
		return -1;
	}

	if (dst && attrs)
		*attrs = dst->attrs;

	return dst ? 0 : (cnt_aval_dst? -2 /*no capacity*/ : -3 /* no dests*/ );
}


int do_lb_start(struct sip_msg *req, int group, struct lb_res_str_list *rl,
						unsigned int flags, struct lb_data *data, str *attrs)
{
	return lb_route(req, group, rl, flags, data, 0/*no data reusage*/, attrs);
}


int do_lb_next(struct sip_msg *req, struct lb_data *data, str *attrs)
{
	return lb_route(req, -1, NULL, 0, data, 1/*reuse previous data*/, attrs);
}


int do_lb_reset(struct sip_msg *req, struct lb_data *data)
{
	struct usr_avp *id_avp;
	struct usr_avp *res_avp, *del_res_avp;
	int_str id_val;
	int_str res_val;

	struct dlg_cell *dlg;
	struct lb_dst *it_d, *last_dst;
	struct lb_resource *it_r;

	if ( (dlg=lb_dlg_binds.get_dlg())==NULL ) {
		LM_ERR("no dialog found for this call, LB not started\n");
		return -1;
	}

	/* remove any saved AVPs */
	destroy_avps(0, group_avp_name, 0);
	destroy_avps(0, flags_avp_name, 0);
	destroy_avps(0, mask_avp_name, 0);

	/* get previous iteration destination, if any */
	last_dst = NULL;
	id_avp = search_first_avp(0, id_avp_name, &id_val, NULL);
	if( id_avp && (is_avp_str_val(id_avp) == 0) ) {
		for( it_d=data->dsts ; it_d ; it_d=it_d->next ) {
			if( it_d->id == id_val.n ) {
				last_dst = it_d;
				LM_DBG("reset LB - found previous dst %d [%.*s]\n",
					last_dst->id,
					last_dst->profile_id.len, last_dst->profile_id.s);
				break;
			}
		}
	}
	destroy_avps(0, id_avp_name, 0);

	/* any valid previous iteration ? */
	if(last_dst == NULL) {
		/* simply delete all possible resources */
		destroy_avps(0, res_avp_name, 1);
	} else {
		/* search and clean up previous iteration resources, if any */
		res_avp = search_first_avp(0, res_avp_name, &res_val, NULL);
		while (res_avp) {
			if ( (it_r=get_resource_by_name( data, &res_val.s))!=NULL ) {
				if( lb_dlg_binds.unset_profile(dlg, &last_dst->profile_id,
				it_r->profile) != 1 )
					LM_ERR("reset LB - failed to remove from profile [%.*s]->"
						"[%.*s]\n", res_val.s.len, res_val.s.s,
						last_dst->profile_id.len, last_dst->profile_id.s );
			} else {
					LM_WARN("reset LB - ignore unknown previous resource "
						"[%.*s]\n", res_val.s.len, res_val.s.s);
			}

			del_res_avp = res_avp;
			res_avp = search_next_avp(del_res_avp, &res_val);
			destroy_avp(del_res_avp);
		}
	}

	return 0;
}


int do_lb_is_started(struct sip_msg *req)
{
	struct usr_avp *group_avp;
	struct usr_avp *mask_avp;
	struct usr_avp *res_avp;

	return (
		((group_avp=search_first_avp(0, group_avp_name, NULL, NULL))!=NULL) &&
			(is_avp_str_val(group_avp) == 0) &&
		((mask_avp =search_first_avp(0, mask_avp_name,  NULL, NULL))!=NULL) &&
			(is_avp_str_val(mask_avp)  != 0) &&
		((res_avp  =search_first_avp(0, res_avp_name,   NULL, NULL))!=NULL) &&
			(is_avp_str_val(res_avp)   != 0)
	) ? 1 : -1;
}


int do_lb_disable_dst(struct sip_msg *req, struct lb_data *data, unsigned int verbose)
{
	struct usr_avp *id_avp;
	int_str id_val;

	struct lb_dst *dst;
	int old_flags;

	id_avp = search_first_avp( 0, id_avp_name, &id_val, NULL);
	if( id_avp && (is_avp_str_val(id_avp) == 0) ) {
		for( dst=data->dsts ; dst ; dst=dst->next ) {
			if( dst->id == id_val.n ) {
				old_flags = dst->flags;
				dst->flags |= LB_DST_STAT_DSBL_FLAG;

				if( dst->flags != old_flags ) {
					lb_status_changed(dst);
					if( verbose )
						LM_INFO("manually disable destination %d <%.*s> "
							"from script\n",dst->id, dst->uri.len, dst->uri.s);
				}
				return 0;
			}
		}
	} else
		LM_DBG("no AVP ID -> nothing to disable\n");

	return -1;
}


/* Checks, if the IP PORT is a LB destination
 */
int lb_is_dst(struct lb_data *data, struct sip_msg *_m,
				str *ip_str, int port, int group, int active, str *attrs)
{
	struct ip_addr *ip;
	struct lb_dst *dst;
	int k;

	if ( (ip=str2ip(ip_str))==NULL  && (ip=str2ip6(ip_str))==NULL) {
		LM_ERR("IP val is not IP <%.*s>\n",ip_str->len,ip_str->s);
		return -1;
	}

	/* and now search !*/
	for( dst=data->dsts ; dst ; dst=dst->next) {
		if ( ((group==-1) || (dst->group==group)) &&  /*group matches*/
		( !active || (active && (dst->flags&LB_DST_STAT_DSBL_FLAG)==0 ) )
		) {
			/* check the IPs */
			for(k=0 ; k<dst->ips_cnt ; k++ ) {
				if ( (dst->ports[k]==0 || port==0 || port==dst->ports[k]) &&
				ip_addr_cmp( ip, &dst->ips[k]) ) {
					if (attrs)
						*attrs = dst->attrs;
					/* found */
					return 1;
				}
			}
		}
	}

	return -1;
}


int lb_count_call(struct lb_data *data, struct sip_msg *req,struct ip_addr *ip,
					int port, int group, struct lb_res_str_list *rl, int dir)
{
	static struct lb_resource **call_res = NULL;
	static unsigned int call_res_no = 0;
	struct dlg_cell *dlg;
	struct lb_resource *res;
	struct lb_dst *dst;
	int i,k;

	/* search for the destination we need to count for */
	for( dst=data->dsts ; dst ; dst=dst->next) {
		if ( (group==-1) || (dst->group==group) ) {
			/* check the IPs */
			for(k=0 ; k<dst->ips_cnt ; k++ ) {
				if ( (dst->ports[k]==0 || port==0 || port==dst->ports[k]) &&
				ip_addr_cmp( ip, &dst->ips[k]) ) {
					/* found */
					goto end_search;
				}
			}
		}
	}

end_search:
	if (dst==NULL) {
		LM_ERR("no destination to match the given IP and port (%s:%d)\n",
			ip_addr2a(ip), port);
		return -1;
	}

	/* get references to the resources */
	if (rl->n>call_res_no) {
		call_res = (struct lb_resource**)pkg_realloc
			(call_res, rl->n*sizeof(struct lb_resorce*));
		if (call_res==NULL) {
			call_res_no = 0;
			LM_ERR("no more pkg mem - res ptr realloc\n");
			return -1;
		}
		call_res_no = rl->n;
	}
	for( i=0,res=data->resources ; (i<rl->n)&&res ; res=res->next) {
		if (search_resource_str( rl, &res->name)) {
			call_res[i++] = res;
			LM_DBG("found requested (%d) resource %.*s\n",
				i-1, res->name.len,res->name.s);
		}
	}
	if (i!=rl->n) {
		LM_ERR("unknown resource in input string\n");
		return -1;
	}

	/* create dialog */
	if (lb_dlg_binds.create_dlg( req , 0)!=1 ) {
		LM_ERR("failed to create dialog\n");
		return -1;
	}

	if ( (dlg=lb_dlg_binds.get_dlg())==NULL ) {
		LM_CRIT("BUG - no dialog found at this stage :(\n");
		return -1;
	}

	/* lock the resources */
	for( i=0 ; i<rl->n ; i++)
		lock_get( call_res[i]->lock );

	/* add to the profiles */
	for( i=0 ; i<rl->n ; i++) {
		if( !dir ) {
			if (lb_dlg_binds.set_profile( dlg, &dst->profile_id,
			call_res[i]->profile, 0)!=0)
				LM_ERR("failed to add to profile\n");
		}
		else {
			if (lb_dlg_binds.unset_profile( dlg, &dst->profile_id,
			call_res[i]->profile)!=1)
				LM_ERR("failed to remove from profile\n");
		}
	}

	/* unlock the resources*/
	for( i=0 ; i<rl->n ; i++)
		lock_release( call_res[i]->lock );

	return 0;
}



/* events */
static event_id_t lb_evi_id;
static str lb_event = str_init("E_LOAD_BALANCER_STATUS");
static str lb_group_str = str_init("group");
static str lb_uri_str = str_init("uri");
static str lb_state_str = str_init("status");
static str lb_disabled_str = str_init("disabled");
static str lb_enabled_str = str_init("enabled");

int lb_init_event(void)
{
	lb_evi_id = evi_publish_event(lb_event);
	if (lb_evi_id == EVI_ERROR) {
		LM_ERR("cannot register %.*s event\n", lb_event.len, lb_event.s);
		return -1;
	}
	return 0;
}

void lb_raise_event(struct lb_dst *dst)
{
	evi_params_p list = NULL;

	if (lb_evi_id == EVI_ERROR || !evi_probe_event(lb_evi_id))
		return;

	list = evi_get_params();
	if (!list) {
		LM_ERR("cannot create event params\n");
		return;
	}

	if (evi_param_add_int(list, &lb_group_str, &dst->group) < 0) {
		LM_ERR("cannot add destination group\n");
		goto error;
	}

	if (evi_param_add_str(list, &lb_uri_str, &dst->uri) < 0) {
		LM_ERR("cannot add destination uri\n");
		goto error;
	}

	if (evi_param_add_str(list, &lb_state_str,
			dst->flags&LB_DST_STAT_DSBL_FLAG ? &lb_disabled_str : &lb_enabled_str) < 0) {
		LM_ERR("cannot add destination state\n");
		goto error;
	}

	if (evi_raise_event(lb_evi_id, list)) {
		LM_ERR("unable to send %.*s event\n", lb_event.len, lb_event.s);
	}
	return;

error:
	evi_free_params(list);
}


void lb_status_changed(struct lb_dst *dst)
{
	/* do BIN replication if configured */
	replicate_lb_status( dst );

	/* raise the event */
	lb_raise_event(dst);
}


