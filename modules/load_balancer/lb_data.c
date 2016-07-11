/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-02-01 initial version (bogdan)
 */



#include <stdio.h>

#include "../../proxy.h"
#include "../../parser/parse_uri.h"
#include "../../mem/shm_mem.h"
#include "lb_parser.h"
#include "lb_data.h"
#include "lb_db.h"

/* dialog stuff */
extern struct dlg_binds lb_dlg_binds;



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
											char* resource, unsigned int flags)
{
	struct lb_res_str_list *lb_rl;
	struct lb_res_str *r;
	struct lb_dst *dst;
	struct lb_resource *res;
	struct sip_uri puri;
	struct proxy_l *proxy;
	union sockaddr_union sau;
	int len;
	int i;

	LM_DBG("uri=<%s>, grp=%d, res=<%s>\n",uri, group, resource);

	/* check uri */
	len = strlen(uri);
	if(parse_uri(uri, len, &puri)!=0 ) {
		LM_ERR("bad uri [%.*s] for destination\n", len, uri);
		return -1;
	}

	/* parse the resources string */
	lb_rl = parse_resources_list( resource, 1);
	if (lb_rl==NULL) {
		LM_ERR("failed to parse resourse string <%s>\n",resource);
		return -1;
	}

	/*add new destination */
	dst = (struct lb_dst*)shm_malloc( sizeof(struct lb_dst)
		+ lb_rl->n*sizeof(struct lb_resource_map) + len +
		(3+2*sizeof(struct lb_dst*)));
	if (dst==NULL) {
		LM_ERR("failed to get shmem\n");
		goto error;
	}
	memset( dst, 0, sizeof(struct lb_dst)+
		lb_rl->n*sizeof(struct lb_resource_map) + len +
		(3+2*sizeof(struct lb_dst*)) );

	dst->rmap = (struct lb_resource_map*)(dst+1);

	dst->uri.s = (char*)(dst->rmap + lb_rl->n);
	dst->uri.len = len;
	memcpy( dst->uri.s , uri, len);

	dst->profile_id.s = dst->uri.s + len;
	dst->profile_id.len = snprintf(dst->profile_id.s,
		2+2*sizeof(struct lb_dst*), "%X", id);

	dst->id = id;
	dst->group = group;
	dst->rmap_no = lb_rl->n;
	dst->flags = flags;

	/* add or update resource list */
	for( i=0 ; i<lb_rl->n ; i++) {
		r = lb_rl->resources + i;
		LM_DBG(" setting for uri=<%s> (%d) resource=<%.*s>, val=%d\n",
			uri, data->dst_no+1, r->name.len, r->name.s, r->val);
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
		dst->rmap[i].max_load = r->val;
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
		shm_free(lbd2);
	}

	shm_free(data);

	return;
}


static unsigned int get_dst_load(struct lb_resource **res, unsigned int res_no,
										struct lb_dst *dst, unsigned int alg)
{
	int k,l;
	unsigned int available;
	int av;

	available = (unsigned int)(-1);
	/* iterate through requested resources */
	for( k=0 ; k<res_no ; k++ ) {
		for ( l=0 ; l<dst->rmap_no ; l++)
			if (res[k]==dst->rmap[l].resource)
				break;
		if (l==dst->rmap_no) {
			LM_CRIT("bug - cannot find request resource in dst\n");
			return 0;
		}

		if (alg==LB_RELATIVE_LOAD_ALG) {
			if (dst->rmap[l].max_load) {
				av = 100 - ( 100*lb_dlg_binds.get_profile_size(res[k]->profile, &dst->profile_id) / dst->rmap[l].max_load );
			} else {
				av = 0;
			}
		} else {
			/* LB_ABSOLUTE_LOAD_ALG */
			av = dst->rmap[l].max_load -
			lb_dlg_binds.get_profile_size(res[k]->profile, &dst->profile_id);
		}
		if (av < 0) {
			LM_WARN("negative availability for resource in dst\n");
			av = 0;
		}
		if (av < available) /* computing a minimum */
			available = av;
	}

	return available;
}


int do_load_balance(struct sip_msg *req, int grp, struct lb_res_str_list *rl,
										unsigned int alg, struct lb_data *data)
{
	static struct lb_resource **call_res = NULL;
	static unsigned int call_res_no = 0;
	static unsigned int *dst_bitmap = NULL;
	static unsigned int bitmap_size = 0;
	unsigned int * used_dst_bitmap;
	struct lb_resource *res;
	int size;
	int i,j;
	unsigned int load, ld;
	struct lb_dst *dst;
	struct lb_dst *it;
	struct lb_dst *last_dst;
	struct usr_avp *grp_avp;
	struct usr_avp *mask_avp;
	struct usr_avp *id_avp;
	int_str grp_val;
	int_str mask_val;
	int_str id_val;

	/* get references to the resources */
	if (rl->n>call_res_no) {
		call_res = (struct lb_resource**)pkg_realloc
			(call_res, rl->n*sizeof(struct lb_resorce*));
		if (call_res==NULL) {
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

	/* any previous iteration due failover ? */
	grp_avp = search_first_avp( 0, grp_avp_name, &grp_val, 0);
	mask_avp = search_first_avp( 0, mask_avp_name, &mask_val, 0);
	id_avp = search_first_avp( 0, id_avp_name, &id_val, 0);

	if ( grp_avp && mask_avp && id_avp && ((grp_avp->flags&AVP_VAL_STR)==0) &&
	(mask_avp->flags&AVP_VAL_STR) && ((id_avp->flags&AVP_VAL_STR)==0) ) {
		/* not the first iteration -> use data from AVPs */
		grp = grp_val.n ;
		used_dst_bitmap = (unsigned int*)mask_val.s.s;
		/* set the previous dst as used (not selected) */
		for(last_dst=data->dsts,i=0,j=0 ; last_dst ; last_dst=last_dst->next) {
			if (last_dst->id==id_val.n) {used_dst_bitmap[i] &= ~(1<<j);break;}
			j++;
			if (j==8*sizeof(unsigned int)) {i++;j=0;}
		}
		LM_DBG("sequential call of LB - previous selected dst is %d\n",id_val.n);
	} else {
		/* first iteration for this call */
		grp_avp = mask_avp = id_avp = NULL;
		last_dst = NULL;

		/* search destinations that fulfill the resources */
		for( size=(unsigned int)(-1),i=0 ; i<rl->n ; i++) {
			if (call_res[i]->bitmap_size<size)
				size = call_res[i]->bitmap_size;
		}
		if (size>bitmap_size) {
			dst_bitmap = (unsigned int*)pkg_realloc
				( dst_bitmap, size*sizeof(unsigned int) );
			if (dst_bitmap==NULL) {
				LM_ERR("no more pkg mem - bitmap realloc\n");
				return -1;
			}
			bitmap_size = size;
		}
		memset( dst_bitmap, 0xff , size*sizeof(unsigned int) );
		for( i=0 ; i<rl->n ; i++) {
			for( j=0 ; j<size ; j++)
				dst_bitmap[j] &= call_res[i]->dst_bitmap[j];
		}
		used_dst_bitmap = dst_bitmap;

		/* create dialog */
		if (lb_dlg_binds.create_dlg( req , 0)!=1 ) {
			LM_ERR("failed to create dialog\n");
			return -1;
		}
	} /* end - first LB run */


	/* lock the resources */
	for( i=0 ; i<rl->n ; i++)
		lock_get( call_res[i]->lock );

	/* do the load-balancing */
	load = 0;
	dst = NULL;
	for( it=data->dsts,i=0,j=0 ; it ; it=it->next) {
		if ( (used_dst_bitmap[i] & (1<<j)) && it->group==grp &&
		(it->flags&LB_DST_STAT_DSBL_FLAG)==0 ) {
			/* valid destination (resources & group & status) */
			if ( (ld = get_dst_load(call_res, rl->n, it, alg)) > load) {
				/* computing a max */
				load = ld;
				dst = it;
			}
			LM_DBG("destination <%.*s> selected for LB set with free=%d "
				"(max=%d)\n",it->uri.len, it->uri.s,ld, load);
		} else {
			if (it->group==grp)
				LM_DBG("skipping destination <%.*s> (used=%d , disabled=%d)\n",
					it->uri.len, it->uri.s,
					(used_dst_bitmap[i] & (1<<j))?0:1 , (it->flags&LB_DST_STAT_DSBL_FLAG)?1:0 );
		}
		j++;
		if (j==8*sizeof(unsigned int)) {i++;j=0;}
	}

	/* if re-trying, remove the dialog from previous profiles */
	if (last_dst) {
		for( i=0 ; i<rl->n ; i++) {
			if (lb_dlg_binds.unset_profile( req, &last_dst->profile_id,
			call_res[i]->profile)!=1)
				LM_ERR("failed to remove from profile\n");
		}
	}

	if (dst==NULL) {
		LM_DBG("no destination found\n");
	} else {
		/* add to the profiles */
		for( i=0 ; i<rl->n ; i++) {
			if (lb_dlg_binds.set_profile( req, &dst->profile_id,
			call_res[i]->profile, 0)!=0)
				LM_ERR("failed to add to profile\n");
		}
	}

	/* unlock the resources*/
	for( i=0 ; i<rl->n ; i++)
		lock_release( call_res[i]->lock );

	if (dst) {
		LM_DBG("winning destination <%.*s> selected for LB set with free=%d\n",
			dst->uri.len, dst->uri.s,load);
		/* change (add/edit) the AVPs for the next iteration */
		if (grp_avp==NULL && mask_avp==NULL) {
			grp_val.n = grp;
			if (add_avp( 0, grp_avp_name, grp_val)!=0) {
				LM_ERR("failed to add GRP AVP");
			}
			mask_val.s.s = (char*)used_dst_bitmap;
			mask_val.s.len = bitmap_size*sizeof(unsigned int);
			if (add_avp( AVP_VAL_STR, mask_avp_name, mask_val)!=0) {
				LM_ERR("failed to add MASK AVP");
			}
		}
		if (id_avp) {
			id_avp->data = (void*)(long)dst->id;
		} else {
			id_val.n = dst->id;
			if (add_avp( 0, id_avp_name, id_val)!=0) {
				LM_ERR("failed to add ID AVP");
			}
		}

		/* set dst uri */
		if (set_dst_uri( req, &dst->uri )!=0) {
			LM_ERR("failed to set duri\n");
			return -2;
		}
	}

	return dst?0:-2;
}


int do_lb_disable(struct sip_msg *req, struct lb_data *data)
{
	struct usr_avp *id_avp;
	int_str id_val;
	struct lb_dst *dst;

	id_avp = search_first_avp( 0, id_avp_name, &id_val, 0);
	if (id_avp==NULL) {
		LM_DBG(" no AVP ID ->nothing to disable\n");
		return -1;
	}

	for( dst=data->dsts ; dst ; dst=dst->next) {
		if (dst->id==id_val.n) {
			dst->flags |= LB_DST_STAT_DSBL_FLAG;
		}
	}

	return -1;
}


/* Checks, if the IP PORT is a LB destination
 */
int lb_is_dst(struct lb_data *data, struct sip_msg *_m,
					pv_spec_t *pv_ip, gparam_t *pv_port, int grp, int active)
{
	pv_value_t val;
	struct ip_addr *ip;
	int port;
	struct lb_dst *dst;
	int k;

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
		if (fixup_get_ivalue(_m, (gparam_p)pv_port, &port) != 0) {
			LM_ERR("failed to get PORT value from PV\n");
			return -1;
		}
	} else {
		port = 0;
	}

	/* and now search !*/
	for( dst=data->dsts ; dst ; dst=dst->next) {
		if ( ((grp==-1) || (dst->group==grp)) &&  /*group matches*/
		( !active || (active && (dst->flags&LB_DST_STAT_DSBL_FLAG)==0 ) )
		) {
			/* check the IPs */
			for(k=0 ; k<dst->ips_cnt ; k++ ) {
				if ( (dst->ports[k]==0 || port==0 || port==dst->ports[k]) &&
				ip_addr_cmp( ip, &dst->ips[k]) ) {
					/* found */
					return 1;
				}
			}
		}
	}

	return -1;
}


int lb_count_call(struct lb_data *data, struct sip_msg *req,
			struct ip_addr *ip, int port, int grp, struct lb_res_str_list *rl)
{
	static struct lb_resource **call_res = NULL;
	static unsigned int call_res_no = 0;
	struct lb_resource *res;
	struct lb_dst *dst;
	int i,k;

	/* search for the destination we need to count for */
	for( dst=data->dsts ; dst ; dst=dst->next) {
		if ( (grp==-1) || (dst->group==grp) ) {
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

	/* lock the resources */
	for( i=0 ; i<rl->n ; i++)
		lock_get( call_res[i]->lock );

	/* add to the profiles */
	for( i=0 ; i<rl->n ; i++) {
		if (lb_dlg_binds.set_profile( req, &dst->profile_id,
		call_res[i]->profile, 0)!=0)
			LM_ERR("failed to add to profile\n");
	}

	/* unlock the resources*/
	for( i=0 ; i<rl->n ; i++)
		lock_release( call_res[i]->lock );

	return 0;
}



