/*
 * Copyright (C) 2005-2008 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
 */


#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>

#include "../../str.h"
#include "../../resolve.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/parse_uri.h"
#include "../../time_rec.h"
#include "routing.h"
#include "prefix_tree.h"
#include "parse.h"


extern int dr_force_dns;

rt_data_t*
build_rt_data( void )
{
	rt_data_t *rdata=NULL;

	if( NULL==(rdata=shm_malloc(sizeof(rt_data_t)))) {
		LM_ERR("no more shm mem\n");
		goto err_exit;
	}
	memset(rdata, 0, sizeof(rt_data_t));

	INIT_PTREE_NODE(NULL, rdata->pt);

	rdata->pgw_tree = map_create( AVLMAP_SHARED );
	rdata->carriers_tree = map_create( AVLMAP_SHARED );

	if (rdata->pgw_tree == NULL || rdata->carriers_tree == NULL) {
		LM_ERR("Initializing avl failed!\n");
		if (rdata->pgw_tree)
			map_destroy(rdata->pgw_tree, 0);
		goto err_exit;

	}


	return rdata;
err_exit:
	if (rdata)
		shm_free(rdata);
	return 0;
}


int parse_destination_list(rt_data_t* rd, char *dstlist,
					pgw_list_t** pgwl_ret, unsigned short *len, int no_resize)
{
#define PGWL_SIZE 32
	pgw_list_t *pgwl=NULL, *p=NULL;
	unsigned int size, pgwl_size;
	long int t;
	char *tmp, *ep;
	str id;

	/* temporary list of gw while parsing */
	pgwl_size = PGWL_SIZE;
	pgwl = (pgw_list_t*)pkg_malloc(pgwl_size*sizeof(pgw_list_t));
	if (pgwl==NULL) {
		LM_ERR("no more shm mem\n");
		goto error;
	}
	memset(pgwl, 0, pgwl_size*sizeof(pgw_list_t));

	/* parset the destination list */
	tmp = dstlist;
	size = 0;
	/* parse the dstlst */
	while(tmp && (*tmp!=0)) {

		/* need a larger array ? */
		if(size>=pgwl_size){
			p=(pgw_list_t*)pkg_malloc((pgwl_size*2)*sizeof(pgw_list_t));
			if (p==NULL) {
				LM_ERR("not enough shm mem to resize\n");
				goto error;
			}
			memset( p+pgwl_size, 0, pgwl_size*sizeof(pgw_list_t));
			memcpy( p, pgwl, pgwl_size*sizeof(pgw_list_t));
			pkg_free(pgwl);
			pgwl_size*=2;
			pgwl=p;
		}

		/* go over spaces */
		EAT_SPACE(tmp);

		/* carrier id or GW id ? */
		if (*tmp==CARRIER_MARKER) {
			pgwl[size].is_carrier = 1;
			tmp++;
		}

		/* eat the destination ID (alphanumerical) */
		id.s = tmp;
		while( *tmp && (isalpha(*tmp) || isdigit(*tmp) || (*tmp)=='_' || (*tmp)=='-') )
			tmp++;
		if (id.s == tmp) {
			LM_ERR("bad id '%c' (%d)[%s]\n",
					*tmp, (int)(tmp-dstlist), dstlist);
			goto error;
		}
		id.len = tmp - id.s ;
		/* look for the destination */
		if (pgwl[size].is_carrier) {
			pgwl[size].dst.carrier = get_carrier_by_id(rd->carriers_tree, &id);
		} else {
			pgwl[size].dst.gw = get_gw_by_id(rd->pgw_tree, &id);
		}
		if (pgwl[size].dst.gw==NULL)
			LM_WARN("destination ID <%.*s> was not found\n",id.len,id.s);

		/* consume spaces */
		EAT_SPACE(tmp);

		/* any weight? */
		if (*tmp=='=') {
			tmp++;
			/* expect the weight value (int) */
			errno = 0;
			t = strtol(tmp, &ep, 10);
			if (ep == tmp) {
				LM_ERR("bad weight value '%c' (%d)[%s]\n",
					*ep, (int)(ep-dstlist), dstlist);
				goto error;
			}
			if (errno == ERANGE && (t== LONG_MAX || t== LONG_MIN)) {
				LM_ERR("weight value out of bounds\n");
				goto error;
			}
			tmp = ep;
			pgwl[size].weight = t;
			/* consume spaces */
			EAT_SPACE(tmp);
		}

		/* valid record ? */
		if (pgwl[size].dst.gw==NULL) {
			/* reset current record and do not count */
			memset( pgwl+size, 0, sizeof(pgw_list_t));
		} else {
			/* count record */
			size++;
		}

		/* separator */
		if ( (*tmp==SEP) || (*tmp==SEP1) ) {
			tmp++;
		} else if (*tmp!=0) {
			LM_ERR("bad char %c (%d) [%s]\n",
					*tmp, (int)(tmp-dstlist), dstlist);
			goto error;
		}
	}

	if (size==0) {
		LM_DBG("empty destination list\n");
		pkg_free(pgwl);
		*len = 0;
		*pgwl_ret = NULL;
		return 0;
	}

	/* done with parsing, build the final array and return */
	if (no_resize) {
		*len = size;
		*pgwl_ret = pgwl;
		return 0;
	}

	p=(pgw_list_t*)shm_malloc(size*sizeof(pgw_list_t));
	if (p==NULL) {
		LM_ERR("not enough shm mem for final build\n");
		goto error;
	}
	memcpy( p, pgwl, size*sizeof(pgw_list_t));
	pkg_free(pgwl);
	*len = size;
	*pgwl_ret = p;
	return 0;
error:
	if (pgwl)
		pkg_free(pgwl);
	*len = 0;
	*pgwl_ret = NULL;
	return -1;
}


int add_carrier(char *id, int flags, char *gwlist, char *attrs,
													int state, rt_data_t *rd)
{
	pcr_t *cr = NULL;
	unsigned int i;

	str key;

	/* allocate a new carrier structure */
	cr = (pcr_t*)shm_malloc(sizeof(pcr_t)+strlen(id)+(attrs?strlen(attrs):0));
	if (cr==NULL) {
		LM_ERR("no more shm mem for a new carrier\n");
		goto error;
	}
	memset(cr, 0, sizeof(pcr_t));

	if (gwlist && gwlist[0]!=0 ) {
		/* parse the list of gateways */
		if (parse_destination_list( rd, gwlist, &cr->pgwl,&cr->pgwa_len,0)!=0){
			LM_ERR("failed to parse the destinations\n");
			goto error;
		}
		/* check that all dest to be GW! */
		for( i=0 ; i<cr->pgwa_len ; i++ ) {
			if (cr->pgwl[i].is_carrier) {
				LM_ERR("invalid carrier <%s> definition as points to other "
					"carrier (%.*s) in destination list\n",id,
					cr->pgwl[i].dst.carrier->id.len,
					cr->pgwl[i].dst.carrier->id.s);
				goto error;
			}
		}
	}

	/* copy integer fields */
	cr->flags = flags;

	/* set state */
	if (state!=0)
		/* disabled */
		cr->flags |= DR_CR_FLAG_IS_OFF;
	else
		/* enabled */
		cr->flags &= ~DR_CR_FLAG_IS_OFF;

	/* copy id */
	cr->id.s = (char*)(cr+1);
	cr->id.len = strlen(id);
	memcpy(cr->id.s,id,cr->id.len);
	/* copy attributes */
	if (attrs && strlen(attrs)) {
		cr->attrs.s = cr->id.s + cr->id.len;
		cr->attrs.len = strlen(attrs);
		memcpy(cr->attrs.s,attrs,cr->attrs.len);
	}

	/* link it */
	key.s = id;
	key.len = strlen(id);
	map_put(rd->carriers_tree, key, cr);


	return 0;
error:
	if (cr) {
		shm_free(cr);
		if (cr->pgwl)
			shm_free(cr->pgwl);
	}
	return -1;
}


rt_info_t*
build_rt_info(
	int id,
	int priority,
	tmrec_t *trec,
	/* script routing table index */
	int route_idx,
	/* list of destinations indexes */
	char* dstlst,
	char* attrs,
	rt_data_t* rd
	)
{
	rt_info_t* rt = NULL;;

	rt = (rt_info_t*)shm_malloc(sizeof(rt_info_t)+(attrs?strlen(attrs):0));
	if (rt==NULL) {
		LM_ERR("no more shm mem(1)\n");
		goto err_exit;
	}
	memset(rt, 0, sizeof(rt_info_t));

	rt->id = id;
	rt->priority = priority;
	rt->time_rec = trec;
	rt->route_idx = route_idx;
	if (attrs && strlen(attrs)) {
		rt->attrs.s = (char*)(rt+1);
		rt->attrs.len = strlen(attrs);
		memcpy(rt->attrs.s,attrs,rt->attrs.len);
	}

	if ( dstlst && dstlst[0]!=0 ) {
		if (parse_destination_list(rd, dstlst, &rt->pgwl,&rt->pgwa_len,0)!=0){
			LM_ERR("failed to parse the destinations\n");
			goto err_exit;
		}
	}

	return rt;

err_exit:
	if ((NULL != rt) ) {
		if (NULL!=rt->pgwl)
			shm_free(rt->pgwl);
		shm_free(rt);
	}
	return NULL;
}


int add_rt_info(
	ptree_node_t *pn,
	rt_info_t* r,
	unsigned int rgid
	)
{
	rg_entry_t    *trg=NULL;
	rt_info_wrp_t *rtl_wrp=NULL;
	rt_info_wrp_t *rtlw=NULL;
	int i=0;

	if((NULL == pn) || (NULL == r))
		goto err_exit;

	if (NULL == (rtl_wrp = (rt_info_wrp_t*)shm_malloc(sizeof(rt_info_wrp_t)))) {
		LM_ERR("no more shm mem\n");
		goto err_exit;
	}
	memset( rtl_wrp, 0, sizeof(rt_info_wrp_t));
	rtl_wrp->rtl = r;

	if(NULL==pn->rg) {
		/* allocate the routing groups array */
		pn->rg_len = RG_INIT_LEN;
		if(NULL == (pn->rg = (rg_entry_t*)shm_malloc(
						pn->rg_len*sizeof(rg_entry_t)))) {
			/* recover the old pointer to be able to shm_free mem */
			goto err_exit;
		}
		memset( pn->rg, 0, pn->rg_len*sizeof(rg_entry_t));
		pn->rg_pos=0;
	}
	/* search for the rgid up to the rg_pos */
	for(i=0; (i<pn->rg_pos) && (pn->rg[i].rgid!=rgid); i++);
	if(i==pn->rg_len) {
		/* realloc & copy the old rg */
		trg = pn->rg;
		if(NULL == (pn->rg = (rg_entry_t*)shm_malloc(
				(pn->rg_len + RG_INIT_LEN)*sizeof(rg_entry_t)))) {
			/* recover the old pointer to be able to shm_free mem */
			pn->rg = trg;
			goto err_exit;
		}
		memset(pn->rg+pn->rg_len, 0, RG_INIT_LEN*sizeof(rg_entry_t));
		memcpy(pn->rg, trg, pn->rg_len*sizeof(rg_entry_t));
		pn->rg_len+=RG_INIT_LEN;
		shm_free( trg );
	}
	/* insert into list */
	r->ref_cnt++;
	if(NULL==pn->rg[i].rtlw){
		pn->rg[i].rtlw = rtl_wrp;
		pn->rg[i].rgid = rgid;
		pn->rg_pos++;
		goto ok_exit;
	}
	if( r->priority > pn->rg[i].rtlw->rtl->priority) {
		/* change the head of the list */
		rtl_wrp->next = pn->rg[i].rtlw;
		pn->rg[i].rtlw = rtl_wrp;
		goto ok_exit;
	}
	rtlw = pn->rg[i].rtlw;
	while( rtlw->next !=NULL) {
		if(r->priority > rtlw->next->rtl->priority) {
			rtl_wrp->next = rtlw->next;
			rtlw->next = rtl_wrp;
			goto ok_exit;
		}
		rtlw = rtlw->next;
	}
	/* the smallest priority is linked at the end */
	rtl_wrp->next=NULL;
	rtlw->next=rtl_wrp;
ok_exit:
	return 0;

err_exit:
	if (rtl_wrp) shm_free(rtl_wrp);
	return -1;
}

int
add_dst(
	rt_data_t *r,
	/* id */
	char *id,
	/* ip address */
	char* ip,
	/* strip len */
	int strip,
	/* pri prefix */
	char* pri,
	/* dst type*/
	int type,
	/* dst attrs*/
	char* attrs,
	/* probe_mode */
	int probing,
	/* socket */
	struct socket_info *sock,
	/* state */
	int state
	)
{
	static unsigned id_counter = 0;
	pgw_t *pgw=NULL;
	struct sip_uri uri;
	int l_ip,l_pri,l_attrs,l_id;
#define GWABUF_MAX_SIZE	512
	char gwabuf[GWABUF_MAX_SIZE];
	union sockaddr_union sau;
	struct proxy_l *proxy;
	unsigned int sip_prefix;
	str gwas;
	str key;

	if (NULL==r || NULL==ip) {
		LM_ERR("invalid parametres\n");
		goto err_exit;
	}

	l_id = strlen(id);
	l_ip = strlen(ip);
	l_pri = pri?strlen(pri):0;
	l_attrs = attrs?strlen(attrs):0;

	/* check if GW address starts with 'sip' or 'sips' */
	if (l_ip>5) {
		if ( strncasecmp("sip:", ip, 4)==0)
			sip_prefix = 4;
		else if ( strncasecmp("sips:", ip, 5)==0)
			sip_prefix = 5;
		else sip_prefix = 0;
	} else
		sip_prefix = 0;

	if( sip_prefix==0 ) {
		if(l_ip+4>=GWABUF_MAX_SIZE) {
			LM_ERR("GW address (%d) longer "
				"than %d\n",l_ip+4,GWABUF_MAX_SIZE);
			goto err_exit;
		}
		memcpy(gwabuf, "sip:", 4);
		memcpy(gwabuf+4, ip, l_ip);
		gwas.s = gwabuf;
		gwas.len = 4+l_ip;
	} else {
		gwas.s = ip;
		gwas.len = l_ip;
	}
	/* parse the normalized address as a SIP URI */
	memset(&uri, 0, sizeof(struct sip_uri));
	if(parse_uri(gwas.s, gwas.len, &uri)!=0) {
		LM_ERR("invalid uri <%.*s>\n",
			gwas.len, gwas.s);
		goto err_exit;
	}
	/* update the sip_prefix to skip to domain part */
	if (uri.user.len)
		sip_prefix += uri.host.s - uri.user.s;

	/* allocate new structure */
	pgw = (pgw_t*)shm_malloc(sizeof(pgw_t) + l_id + (l_ip-sip_prefix) +
		l_pri + l_attrs);
	if (NULL==pgw) {
		LM_ERR("no more shm mem (%u)\n",
			(unsigned int)(sizeof(pgw_t)+l_id+l_ip-sip_prefix+l_pri +l_attrs));
		goto err_exit;
	}
	memset(pgw,0,sizeof(pgw_t));

	/* set probing related flags  */
	switch(probing) {
		case 0:
			break;
		case 1:
			pgw->flags |=  DR_DST_PING_DSBL_FLAG;
			break;
		case 2:
			pgw->flags |=  DR_DST_PING_PERM_FLAG;
			break;
		default:
			goto err_exit;
	}

	/* set state related flags  */
	switch(state) {
		case 0:
			break;
		case 1:
			pgw->flags |=  DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG;
			break;
		case 2:
			pgw->flags |=  DR_DST_STAT_DSBL_FLAG;
			break;
		default:
			goto err_exit;
	}

	/* set outbound socket */
	pgw->sock = sock;

	pgw->_id = ++id_counter;

	pgw->id.len= l_id;
	pgw->id.s = (char*)(pgw+1);
	memcpy(pgw->id.s, id, l_id);

	pgw->ip_str.len= l_ip-sip_prefix;
	pgw->ip_str.s = (char*)(pgw+1)+l_id;
	memcpy(pgw->ip_str.s, ip+sip_prefix, l_ip-sip_prefix);

	if (pri) {
		pgw->pri.len = l_pri;
		pgw->pri.s = ((char*)(pgw+1))+l_id+l_ip-sip_prefix;
		memcpy(pgw->pri.s, pri, l_pri);
	}
	if (attrs) {
		pgw->attrs.len = l_attrs;
		pgw->attrs.s = ((char*)(pgw+1))+l_id+l_ip-sip_prefix+l_pri;
		memcpy(pgw->attrs.s, attrs, l_attrs);
	}
	pgw->strip = strip;
	pgw->type = type;

	/* add address in the global list of destinations/GWs */
	proxy = mk_proxy(&uri.host,uri.port_no,uri.proto,(uri.type==SIPS_URI_T));
	if (proxy==NULL) {
		if(dr_force_dns) {
			LM_ERR("cannot resolve <%.*s>\n",
				uri.host.len, uri.host.s);
			goto err_exit;
		} else {
			LM_DBG("cannot resolve <%.*s> - won't be used"
					" by is_from_gw()\n", uri.host.len, uri.host.s);
			goto done;
		}
	}
	hostent2ip_addr( &pgw->ips[0], &proxy->host, proxy->addr_idx);
	pgw->ports[0] = proxy->port;
	pgw->protos[0] = proxy->proto;
	LM_DBG("first gw ip addr [%s]\n", ip_addr2a(&pgw->ips[0]));

	pgw->ips_no = 1;

	while (pgw->ips_no<DR_MAX_IPS && (get_next_su( proxy, &sau, 0)==0) ) {
		su2ip_addr( &pgw->ips[pgw->ips_no], &sau);
		pgw->ports[pgw->ips_no] = proxy->port;
		pgw->protos[pgw->ips_no] = proxy->proto;
		LM_DBG("additional gw ip addr [%s]\n",
			ip_addr2a( &pgw->ips[pgw->ips_no] ) );
		pgw->ips_no++;
	}

	free_proxy(proxy);
	pkg_free(proxy);

done:
	key.s = id;
	key.len = strlen(id);

	if (map_put(r->pgw_tree, key, pgw)) {
		LM_ERR("Duplicate gateway!\n");
		return -1;
	}

	return 0;

err_exit:
	if(NULL!=pgw)
		shm_free(pgw);
	return -1;
}


void destroy_pgw(void *pgw_p)
{
	shm_free((pgw_t *)pgw_p);
}

void destroy_pcr(void *pcr_p)
{
	pcr_t* pcr = pcr_p;
	if (pcr->pgwl) shm_free(pcr->pgwl);
	shm_free(pcr);
}


/* FIXME FREE AVL HERE */
void
del_pgw_list(
		map_t pgw_tree
		)
{
	map_destroy(pgw_tree, destroy_pgw);
}

/* FIXME FREE AVL HERE */
void del_carriers_list(
		map_t carriers_tree
		)
{
	map_destroy(carriers_tree, destroy_pcr);
}

void
free_rt_data(
		rt_data_t* rt_data,
		int all
		)
{
	int j;
	if(NULL!=rt_data) {
		/* del GW list */
		del_pgw_list(rt_data->pgw_tree);
		rt_data->pgw_tree = 0 ;
		/* del prefix tree */
		del_tree(rt_data->pt);
		rt_data->pt = 0 ;
		/* del prefixless rules */
		if(NULL!=rt_data->noprefix.rg) {
			for(j=0;j<rt_data->noprefix.rg_pos;j++) {
				if(rt_data->noprefix.rg[j].rtlw !=NULL) {
					del_rt_list(rt_data->noprefix.rg[j].rtlw);
					rt_data->noprefix.rg[j].rtlw = 0;
				}
			}
			shm_free(rt_data->noprefix.rg);
			rt_data->noprefix.rg = 0;
		}
		/* del carriers */
		del_carriers_list(rt_data->carriers_tree);
		rt_data->carriers_tree=0;
		/* del top level */
		if (all) shm_free(rt_data);
	}
}
