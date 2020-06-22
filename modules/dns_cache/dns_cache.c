/*
 * Copyright (C) 2012 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *
 * History:
 * ---------
 *  2012-02-01  created (vlad)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../pt.h"
#include "../../resolve.h"
#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_cap.h"

static int mod_init(void);
static int child_init(int);
static void destroy(void);

int put_dnscache_value(char *name,int r_type,void *record,int rdata_len,
				int failure,int ttl);
void* get_dnscache_value(char *name,int r_type,int name_len);

static cachedb_funcs cdbf;
static cachedb_con *cdbc = 0;

static int blacklist_timeout=3600; /* seconds */
static str cachedb_url = {0,0};

static param_export_t params[]={
	{ "cachedb_url",                 STR_PARAM, &cachedb_url.s},
	{ "blacklist_timeout",           INT_PARAM, &blacklist_timeout},
	{0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_CACHEDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"dns_cache",				/* module name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	0,							/* load function */
	&deps,              /* OpenSIPS module dependencies */
	0,					/* exported functions */
	0,					/* exported async functions */
	params,					/* exported parameters */
	0,					/* exported statistics */
	0,					/* exported MI functions */
	0,					/* exported pseudo-variables */
	0,			 		/* exported transformations */
	0,					/* extra processes */
	0,						/* module pre-initialization function */
	mod_init,				/* module initialization function */
	(response_function) 0,      		/* response handling function */
	(destroy_function)destroy,		/* destroy function */
	child_init,			        /* per-child init function */
	0                           /* reload confirm function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	LM_NOTICE("initializing module dns_cache ...\n");

	if (cachedb_url.s == NULL) {
		LM_ERR("no cachedb_url set !\n");
		return -1;
	} else {
		cachedb_url.len = strlen(cachedb_url.s);
		LM_DBG("using CacheDB URL: %s\n", cachedb_url.s);
	}

	/* set pointers that resolver will use for caching */
	dnscache_fetch_func=get_dnscache_value;
	dnscache_put_func=put_dnscache_value;

	return 0;
}

static int child_init(int rank)
{
	if (cachedb_bind_mod(&cachedb_url, &cdbf) < 0) {
		LM_ERR("cannot bind functions for db_url %.*s\n",
				cachedb_url.len, cachedb_url.s);
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&cdbf,
				CACHEDB_CAP_GET|CACHEDB_CAP_SET)) {
		LM_ERR("not enough capabilities\n");
		return -1;
	}

	cdbc = cdbf.init(&cachedb_url);
	if (!cdbc) {
		LM_ERR("cannot connect to db_url %.*s\n", cachedb_url.len, cachedb_url.s);
		return -1;
	}

	return 0;
}

/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module dns_cache ...\n");
}

static int rdata_struct_len=sizeof(struct rdata)-sizeof(void *) -
		sizeof(struct rdata *);

static unsigned char *he_buf=NULL;
static int he_buf_len=0;
static char* serialize_he_rdata(struct hostent *he,int *buf_len,int do_encoding)
{
	unsigned char *p;
	int i,len=0,needed_len=0,base64_len=0,alias_no=0,addr_no=0;

	/* addr_type, name_len, alias_no, addr_no */
	len+=sizeof(int)*4;

	/* compute needed buffer length */
	if (he->h_name)
		len+=strlen(he->h_name)+1;

	if (he->h_aliases)
       		for (i=0;he->h_aliases[i];i++) {
			/* integer with len + len bytes of alias */
			len+=strlen(he->h_aliases[i])+1+sizeof(int);
			alias_no++;
		}


	i=0;
	if (he->h_addr_list)
       		for (i=0;he->h_addr_list[i];i++) {
			len+=he->h_length;
			addr_no++;
		}

	if (do_encoding) {
		/* backend does not support binary values - allocate continuous buffer
		for encoding */
		base64_len = calc_base64_encode_len(len);
		needed_len=len+base64_len;
	} else
		needed_len = len;

	if (he_buf == NULL || needed_len > he_buf_len) {
		/* realloc if not enough space */
		he_buf = pkg_realloc(he_buf,needed_len);
		if (he_buf == NULL) {
			LM_ERR("No more pkg\n");
			return NULL;
		}
		he_buf_len = needed_len;
	}

	p = he_buf;

	/* copy address type */
	memcpy(p,&he->h_addrtype,sizeof(int));
	p+=sizeof(int);

	/* copy h_name len */
	len=strlen(he->h_name)+1;
	memcpy(p,&len,sizeof(int));
	p+=sizeof(int);
	/* copy h_name */
	memcpy(p,he->h_name,len);
	p+=len;

	/* copy number of aliases */
	memcpy(p,&alias_no,sizeof(int));
	p+=sizeof(int);

	/* copy aliases, if any */
	if (he->h_aliases)
       		for (i=0;he->h_aliases[i];i++) {
			len=strlen(he->h_aliases[i])+1;
			/* copy alias length */
			memcpy(p,&len,sizeof(int));
			p+=sizeof(int);
			/* copy alias */
			memcpy(p,he->h_aliases[i],len);
			p+=len;
		}

	/* copy address no */
	memcpy(p,&addr_no,sizeof(int));
	p+=sizeof(int);

	/* copy addresses */
	if (he->h_addr_list)
       		for (i=0;he->h_addr_list[i];i++) {
			/* copy addreses. length will be known from the addrtype field */
			len=he->h_length;
			memcpy(p,he->h_addr_list[i],len);
			p+=len;
		}

	if (do_encoding) {
		len = needed_len - base64_len;

		if (buf_len)
			*buf_len=base64_len;

		/* do encoding, and return pointer after unencoded data */
		base64encode(p,he_buf,len);
		return (char *)p;
	} else {
		if (buf_len)
			*buf_len = needed_len;
		return (char *)he_buf;
	}
}

static unsigned char *dec_he_buf=NULL;
static int dec_he_buf_len=0;
static struct hostent dec_global_he;
#define MAXALIASES		36
#define MAXADDRS 		36
static char *h_addr_ptrs[MAXADDRS];
static char *host_aliases[MAXALIASES];
static struct hostent* deserialize_he_rdata(char *buff,int buf_len,int do_decoding)
{
	char **ap,**hap;
	unsigned char *p;
	int max_len=0;
	int i,alias_no=0,addr_no=0,len=0;

	/* max estimation of needed buffer */
	if (do_decoding) {
		max_len=calc_max_base64_decode_len(buf_len);
	} else {
		max_len = buf_len;
	}

	if (dec_he_buf == NULL || max_len > dec_he_buf_len) {
		/* realloc buff if not enough space */
		dec_he_buf = pkg_realloc(dec_he_buf,max_len);
		if (dec_he_buf == NULL) {
			LM_ERR("No more pkg\n");
			return NULL;
		}
		dec_he_buf_len = max_len;
	}

	/* set pointer in dec_global_he */
	ap = host_aliases;
	*ap = NULL;
	dec_global_he.h_aliases = host_aliases;
	hap = h_addr_ptrs;
	*hap = NULL;
	dec_global_he.h_addr_list = h_addr_ptrs;

	if (do_decoding) {
		/* decode base64 buf */
		base64decode(dec_he_buf,(unsigned char *)buff,buf_len);
		p = dec_he_buf;
	} else {
		memcpy(dec_he_buf,buff,buf_len);
		p = dec_he_buf;
	}

	/* set address type & length */
	memcpy(&dec_global_he.h_addrtype,p,sizeof(int));
	p+=sizeof(int);
	if (dec_global_he.h_addrtype == AF_INET)
		dec_global_he.h_length=4;
	else
		dec_global_he.h_length=16;

	/* set name */
	memcpy(&len,p,sizeof(int));
	p+=sizeof(int);
	dec_global_he.h_name = (char *)p;
	p+=len;

	/* get number of aliases */
	memcpy(&alias_no,p,sizeof(int));
	p+=sizeof(int);

	for (i=0;i<alias_no;i++) {
		/* get alias length, set pointer and skip over length */
		memcpy(&len,p,sizeof(int));
		p+=sizeof(int);
		*ap++ = (char *)p;
		p+=len;
	}

	/* get number of addresses */
	memcpy(&addr_no,p,sizeof(int));
	p+=sizeof(int);

	for (i=0;i<addr_no;i++) {
		/* set pointer and skip over length */
		*hap++ = (char *)p;
		p+=dec_global_he.h_length;
	}

	return &dec_global_he;
}

static unsigned char *rdata_buf=NULL;
static int rdata_buf_len=0;
static char* serialize_dns_rdata(struct rdata *head,int buf_len,int *len,int do_encoding)
{
	unsigned char *p;
	struct rdata *it;
	int needed_len;
	int entry_len,base64_len=0;
	struct cname_rdata *cname_rd;
	struct srv_rdata *srv_rd;
	struct naptr_rdata *naptr_rd;
	struct ebl_rdata *ebl_rd;
	struct txt_rdata *txt_rd;

	if (do_encoding) {
		base64_len = calc_base64_encode_len(buf_len);
		needed_len = buf_len + base64_len;
	} else {
		needed_len = buf_len;
	}

	if (rdata_buf == NULL || needed_len > rdata_buf_len) {
		rdata_buf = pkg_realloc(rdata_buf,needed_len);
		if (rdata_buf == NULL) {
			LM_ERR("No more pkg\n");
			return NULL;
		}
		rdata_buf_len = needed_len;
	}

	p = rdata_buf;

	for (it=head;it;it=it->next) {
		/* copy non-pointer fields of the struct */
		memcpy(p,it,rdata_struct_len);
		p+=rdata_struct_len;

		switch (it->type) {
			case T_A:
				/* copy all 4 bytes */
				memcpy(p,it->rdata,sizeof(struct a_rdata));
				p+=sizeof(struct a_rdata);
				break;
			case T_AAAA:
				/* copy all 16 bytes */
				memcpy(p,it->rdata,sizeof(struct aaaa_rdata));
				p+=sizeof(struct aaaa_rdata);
				break;
			case T_CNAME:
				cname_rd=(struct cname_rdata *)it->rdata;
				entry_len=strlen(cname_rd->name);
				/* copy len of alias */
				memcpy(p,&entry_len,sizeof(int));
				p+=sizeof(int);
				/* copy alias */
				memcpy(p,cname_rd->name,entry_len+1);
				p+=entry_len+1;
				break;
			case T_NAPTR:
				/* copy priority, etc */
				memcpy(p,it->rdata,2*sizeof(unsigned short) +
						sizeof(unsigned int));
				p+=2*sizeof(unsigned short) + sizeof(unsigned int);
				naptr_rd=it->rdata;
				/* copy flags, flags_len was copied above */
				memcpy(p,naptr_rd->flags,naptr_rd->flags_len+1);
				p+=naptr_rd->flags_len+1;
				/* copy services & len */
				memcpy(p,&naptr_rd->services_len,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(p,naptr_rd->services,naptr_rd->services_len+1);
				p+=naptr_rd->services_len+1;
				/* copy regexp & len */
				memcpy(p,&naptr_rd->regexp_len,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(p,naptr_rd->regexp,naptr_rd->regexp_len+1);
				p+=naptr_rd->regexp_len+1;
				/* copy repl & len */
				memcpy(p,&naptr_rd->repl_len,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(p,naptr_rd->repl,naptr_rd->repl_len+1);
				p+=naptr_rd->repl_len+1;
				break;
			case T_SRV:
				srv_rd=it->rdata;
				memcpy(p,srv_rd,4*sizeof(unsigned short) +
					sizeof(unsigned int));
				p+=4*sizeof(unsigned short) + sizeof(unsigned int);
				memcpy(p,srv_rd->name,srv_rd->name_len+1);
				p+=srv_rd->name_len+1;
				break;
			case T_TXT:
				txt_rd=it->rdata;
				entry_len=strlen(txt_rd->txt);
				memcpy(p,&entry_len,sizeof(int));
				p+=sizeof(int);
				memcpy(p,txt_rd->txt,entry_len+1);
				p+=entry_len+1;
				break;
			case T_EBL:
				ebl_rd=it->rdata;
				memcpy(p,ebl_rd,sizeof(unsigned char) +
					sizeof(unsigned int));
				p+=sizeof(unsigned char) + sizeof(unsigned int);
				memcpy(p,ebl_rd->separator,ebl_rd->separator_len+1);
				p+=ebl_rd->separator_len+1;
				memcpy(p,&ebl_rd->apex_len,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(p,ebl_rd->apex,ebl_rd->apex_len+1);
				p+=ebl_rd->apex_len+1;
				break;
			default:
				LM_ERR("Unexpected DNS record type\n");
				return NULL;
		}
	}

	if (do_encoding) {
		if (len)
			*len = base64_len;

		/* encode and return beggining of encoding */
		base64encode(p,rdata_buf,buf_len);
		return (char *)p;
	} else {
		if (len)
			*len = needed_len;
		return (char *)rdata_buf;
	}
}

static unsigned char *dec_rdata_buf=NULL;
static int dec_rdata_buf_len=0;
static struct rdata* deserialize_dns_rdata(char *buff,int buf_len,int do_decoding)
{
	unsigned char *p;
	int max_len=0,actual_len=0,entry_len=0;
	struct rdata *head,*it,**last;
	struct naptr_rdata *naptr_rd;
	struct srv_rdata *srv_rd;
	struct txt_rdata *txt_rd;
	struct ebl_rdata *ebl_rd;

	head=it=NULL;
	last=&head;

	if (do_decoding) {
		max_len = calc_max_base64_decode_len(buf_len);
	} else {
		max_len = buf_len;
	}

	if (dec_rdata_buf == NULL || max_len > dec_rdata_buf_len) {
		/* realloc buff if not enough space */
		dec_rdata_buf = pkg_realloc(dec_rdata_buf,max_len);
		if (dec_rdata_buf == NULL) {
			LM_ERR("No more pkg\n");
			return NULL;
		}
		dec_rdata_buf_len = max_len;
	}

	if (do_decoding) {
		/* decode base64 buf */
		actual_len = base64decode(dec_rdata_buf,(unsigned char *)buff,buf_len);
		p = dec_rdata_buf;
	} else {
		memcpy(dec_rdata_buf,buff,buf_len);
		actual_len = buf_len;
		p = dec_rdata_buf;
	}

	while ( p < dec_rdata_buf+actual_len) {
		it = pkg_malloc(sizeof(struct rdata));
		if (it == 0) {
			LM_ERR("no more pkg mem\n");
			goto it_alloc_error;
		}

		/* copy type, class & ttl */
		memcpy(it,p,rdata_struct_len);
		p+=rdata_struct_len;
		it->next=0;
		it->rdata=0;

		switch (it->type) {
			case T_A:
				it->rdata = pkg_malloc(sizeof(struct a_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				memcpy(p,it->rdata,sizeof(struct a_rdata));
				p+=sizeof(struct a_rdata);
				*last=it;
				last=&(it->next);
				break;
			case T_AAAA:
				it->rdata = pkg_malloc(sizeof(struct aaaa_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				memcpy(p,it->rdata,sizeof(struct aaaa_rdata));
				p+=sizeof(struct aaaa_rdata);
				*last=it;
				last=&(it->next);
				break;
			case T_CNAME:
				it->rdata = pkg_malloc(sizeof(struct cname_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				memcpy(&entry_len,p,sizeof(int));
				p+=sizeof(int);
				memcpy(((struct cname_rdata*)it->rdata)->name,
					p,entry_len+1);
				p+=entry_len+1;
				*last=it;
				last=&(it->next);
				break;
			case T_NAPTR:
				it->rdata = pkg_malloc(sizeof(struct naptr_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				naptr_rd = (struct naptr_rdata*)it->rdata;
				memcpy(naptr_rd,p,2*sizeof(unsigned short) +
					sizeof(unsigned int));
				p+=2*sizeof(unsigned short) + sizeof(unsigned int);
				memcpy(naptr_rd->flags,p,naptr_rd->flags_len+1);
				p+=naptr_rd->flags_len+1;
				memcpy(&naptr_rd->services_len,p,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(naptr_rd->services,p,naptr_rd->services_len+1);
				p+=naptr_rd->services_len+1;
				memcpy(&naptr_rd->regexp_len,p,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(naptr_rd->regexp,p,naptr_rd->regexp_len+1);
				p+=naptr_rd->regexp_len+1;
				memcpy(&naptr_rd->repl_len,p,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(naptr_rd->repl,p,naptr_rd->repl_len+1);
				p+=naptr_rd->repl_len+1;
				*last=it;
				last=&(it->next);
				break;
			case T_SRV:
				it->rdata = pkg_malloc(sizeof(struct srv_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				srv_rd = (struct srv_rdata*)it->rdata;
				memcpy(srv_rd,p,4*sizeof(unsigned short) +
					sizeof(unsigned int));
				p+=4*sizeof(unsigned short) + sizeof(unsigned int);
				memcpy(srv_rd->name,p,srv_rd->name_len+1);
				p+=srv_rd->name_len+1;
				*last=it;
				last=&(it->next);
				break;
			case T_TXT:
				it->rdata = pkg_malloc(sizeof(struct txt_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				txt_rd = (struct txt_rdata*)it->rdata;
				memcpy(&entry_len,p,sizeof(int));
				p+=sizeof(int);
				memcpy(txt_rd->txt,p,entry_len+1);
				p+=entry_len+1;
				*last=it;
				last=&(it->next);
				break;
			case T_EBL:
				it->rdata = pkg_malloc(sizeof(struct ebl_rdata));
				if (it->rdata == 0) {
					LM_ERR("no more pkg\n");
					goto rdata_alloc_error;
				}
				ebl_rd = (struct ebl_rdata*)it->rdata;
				memcpy(ebl_rd,p,sizeof(unsigned char) +
					sizeof(unsigned int));
				p+=sizeof(unsigned char)+sizeof(unsigned int);
				memcpy(ebl_rd->separator,p,ebl_rd->separator_len+1);
				p+=ebl_rd->separator_len+1;
				memcpy(&ebl_rd->apex_len,p,sizeof(unsigned int));
				p+=sizeof(unsigned int);
				memcpy(ebl_rd->apex,p,ebl_rd->apex_len+1);
				p+=ebl_rd->apex_len+1;
				*last=it;
				last=&(it->next);
				break;
		}
	}

	return head;

rdata_alloc_error:
	if (it)
		pkg_free(it);
it_alloc_error:
	if (head)
		free_rdata_list(head);
	return NULL;
}

static char keyname_buff[300]; /* TODO - size ?*/
char* create_keyname_for_record(char *name,int r_type,int name_len,int *res_len)
{
	char *p;
	int n,x;

	p=keyname_buff;
	*res_len = 0;

	memcpy(p,"dnscache_",9);
	*res_len += 9;
	p+=9;

	if (r_type != T_PTR) {
		/* query is plain text , go ahead and copy it */
		n=strlen(name);
		memcpy(p,name,n);
		*res_len += n;
		p+=n;
	} else {
		/* binary key, convert to str */
		inet_ntop(name_len==4?AF_INET:AF_INET6,name,p,name_len==4?
			INET_ADDRSTRLEN:INET6_ADDRSTRLEN);
		x=strlen(p);
		*res_len += x;
		p+=x;
	}

	switch (r_type) {
		case T_SRV:
			memcpy(p,"_srv",4);
			*res_len += 4;
			break;
		case T_A:
			memcpy(p,"_a",2);
			*res_len += 2;
			break;
		case T_AAAA:
			memcpy(p,"_aaaa",5);
			*res_len += 5;
			break;
		case T_CNAME:
			memcpy(p,"_cname",6);
			*res_len += 6;
			break;
		case T_NAPTR:
			memcpy(p,"_naptr",6);
			*res_len += 6;
			break;
		case T_TXT:
			memcpy(p,"_txt",4);
			*res_len += 4;
			break;
		case T_EBL:
			memcpy(p,"_ebl",4);
			*res_len += 4;
			break;
		case T_PTR:
			memcpy(p,"_ptr",4);
			*res_len +=4;
			p+=4;
			/* one can request PTR for IP and IPv6 */
			x = name_len==4?2:5;
			memcpy(p,name_len==4?"_a":"_aaaa",x);
			*res_len +=x;
			break;
		default:
			LM_ERR("invalid r_type %d\n",r_type);
			return NULL;
	}

	return keyname_buff;
}

/* gets value from cache for the corresponding entry
 * Params :
 * name - what is wished to be resolved - binary IP for PTR and strings for other queries
 * r_type - type of DNS query
 * name_len - only used in case of PTR
 */
int get_dnscache_strvalue(char *name,int r_type,int name_len,str *res)
{
	str key;

	/* generate key */
	key.s=create_keyname_for_record(name,r_type,name_len,&key.len);
	if (key.s == NULL) {
		LM_ERR("failed to create key\n");
		return -1;
	}

	LM_DBG("gen key [%.*s]\n",key.len,key.s);

	/* fetch from backend */
	if (cdbf.get(cdbc, &key, res) < 0) {
		LM_DBG("cannot retrieve key\n");
		return -1;
	}

	return 0;
}

#define FAILURE_MARKER_CHAR	'|'
#define FAILURE_MARKER		"|"
#define FAILURE_MARKER_LEN	1

/* Returns hostent or rdata struct, based on what callers needs */
void* get_dnscache_value(char *name,int r_type,int name_len)
{
	str value;
	struct hostent *he;
	struct rdata *head;

	if (cdbc == NULL) {
		/* assume dns request before forking - cache is not ready yet */
		return NULL;
	}

	if (get_dnscache_strvalue(name,r_type,name_len,&value) < 0) {
		LM_DBG("failed to fetch from cache\n");
		return NULL;
	}

	if (value.len == FAILURE_MARKER_LEN && value.s[0] == FAILURE_MARKER_CHAR) {
		LM_DBG("blacklisted value %s for type %d\n",name,r_type);
		pkg_free(value.s);
		return (void *)-1;
	}

	if (r_type == T_A || r_type == T_AAAA || r_type == T_PTR) {
		he = deserialize_he_rdata(value.s,value.len,
			CACHEDB_CAPABILITY(&cdbf,CACHEDB_CAP_BINARY_VALUE)?0:1);
		if (he == NULL) {
			LM_ERR("failed to deserialize he struct\n");
			pkg_free(value.s);
			return NULL;
		}
		pkg_free(value.s);
		return he;
	} else {
		head = deserialize_dns_rdata(value.s,value.len,
			CACHEDB_CAPABILITY(&cdbf,CACHEDB_CAP_BINARY_VALUE)?0:1);
		if (head == NULL) {
			LM_ERR("failed to deserialize rdata struct\n");
			pkg_free(value.s);
			return NULL;
		}
		pkg_free(value.s);
		return head;
	}
}

/* Pushes internal structure ( hostent or rdata ) to a cache backend
 *
 * Params:
 *	name - what query to be saved - binary IP for PTR and strings for other queries
 *	r_type - type of DNS query
 *	record - pointer to hostent or rdata
 *	rdata_len - If rdata record, rdata_len holds the actual length of rdata buf,
 *		in order to avoid double iterations on the rdata struct. If it's a
 *		PTR record, rdata_len is used to differentiate between IP and IPv6
 *	failure - should we blacklist or not
 *	ttl - seconds the key should be kept in cache
 *
 * Returns:
 *	0  - success
 *	1  - cache not initialized yet
 *	-1 - internal failure
 */
int put_dnscache_value(char *name,int r_type,void *record,int rdata_len,
				int failure,int ttl)
{
	str key,value;
	int key_ttl;

	if (cdbc == NULL) {
		/* assume dns request before forking - cache is not ready yet */
		return 1;
	}

	/* avoid caching records with TTL=0 */
	if (!failure && ttl==0) {
		/* RFC1035 states : "Zero TTL values are interpreted to mean that
		   the RR can only be used for the transaction in progress, and
		   should not be cached." */
		return 1;
	}

	/* generate key */
	key.s=create_keyname_for_record(name,r_type,rdata_len,&key.len);
	if (key.s == NULL) {
		LM_ERR("failed to create key\n");
		return -1;
	}
	value.len = 0;
	value.s = 0;

	if (failure) {
		/* just set value as failure marker, and push to back-end
		 * with the default timeout */
		value.s = FAILURE_MARKER;
		value.len= FAILURE_MARKER_LEN;
		key_ttl = blacklist_timeout;
	} else {
		if (r_type == T_A || r_type == T_AAAA || r_type == T_PTR) {
			value.s = serialize_he_rdata((struct hostent *)record,
		&value.len,CACHEDB_CAPABILITY(&cdbf,CACHEDB_CAP_BINARY_VALUE)?0:1);
			if (value.s == NULL) {
				LM_ERR("failed to serialize he rdata\n");
				return -1;
			}
		} else {
			value.s = serialize_dns_rdata((struct rdata *)record,
		rdata_len,&value.len,CACHEDB_CAPABILITY(&cdbf,CACHEDB_CAP_BINARY_VALUE)?0:1);
			if (value.s == NULL) {
				LM_ERR("failed to serialize rdata record\n");
				return -1;
			}
		}

		key_ttl = ttl;
	}

	LM_INFO("putting key [%.*s] with value [%.*s] ttl = %d\n",
		key.len,key.s,value.len,value.s,key_ttl);
	if (cdbf.set(cdbc,&key,&value,key_ttl) < 0) {
		LM_ERR("failed to set dns key\n");
		return -1;
	}

	return 0;
}

