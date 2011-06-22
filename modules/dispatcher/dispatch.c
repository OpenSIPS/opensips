/*
 * $Id$
 *
 * dispatcher module
 *
 * Copyright (C) 2004-2006 FhG Fokus
 * Copyright (C) 2005-2010 Voice-System.ro
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
 * group (carsten)
 * 2007-01-12  Added a threshhold for automatic deactivation (carsten)
 * 2007-02-09  Added active probing of failed destinations and automatic
 * re-enabling of destinations (carsten)
 * 2007-05-08  Ported the changes to SVN-Trunk, renamed ds_is_domain to
 * ds_is_from_list and modified the function to work with IPv6 adresses.
 * 2007-07-18  removed index stuff 
 * 			   added DB support to load/reload data(ancuta)
 * 2007-09-17  added list-file support for reload data (carstenbock)
 * 2009-05-18  Added support for weights for the destinations;
 *             added support for custom "attrs" (opaque string) (bogdan)

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

#include "dispatch.h"

#define DS_TABLE_VERSION_NEW	4
#define DS_TABLE_VERSION_OLD	3

extern struct socket_info *probing_sock;
static int _ds_table_version = DS_TABLE_VERSION_NEW;
extern event_id_t dispatch_evi_id;

typedef struct _ds_dest
{
	str uri;
	str attrs;
	int flags;
	int weight;
	struct ip_addr ip_address; /* IP-Address of the entry */
	unsigned short int port; /* Port of the request URI */
	int failure_count;
	struct _ds_dest *next;
} ds_dest_t, *ds_dest_p;

typedef struct _ds_set
{
	int id;				/* id of dst set */
	int nr;				/* number of items in dst set */
	int last;			/* last used item in dst set */
	int weight_sum;		/* sum of the weights from dst set */
	ds_dest_p dlist;
	struct _ds_set *next;
} ds_set_t, *ds_set_p;

extern int ds_force_dst;

static db_func_t ds_dbf;
static db_con_t* ds_db_handle=0;
ds_set_p *ds_lists=NULL;
int *ds_list_nr = NULL;
int *crt_idx    = NULL;
int *next_idx   = NULL;

#define _ds_list 	(ds_lists[*crt_idx])
#define _ds_list_nr (*ds_list_nr)

void destroy_list(int);

int init_data(void)
{
	int * p;

	ds_lists = (ds_set_p*)shm_malloc(2*sizeof(ds_set_p));
	if(!ds_lists)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}
	ds_lists[0] = ds_lists[1] = 0;

	
	p = (int*)shm_malloc(3*sizeof(int));
	if(!p)
	{
		LM_ERR("Out of memory\n");
		return -1;
	}

	crt_idx = p;
	next_idx = p+1;
	ds_list_nr = p+2;
	*crt_idx= *next_idx = 0;

	return 0;
}

int add_dest2list(int id, str uri, int flags, int weight, str attrs,
													int list_idx, int * setn)
{
	ds_dest_p dp = NULL;
	ds_set_p  sp = NULL;

	/* For DNS-Lookups */
	static char hn[256];
	struct hostent* he;
	struct sip_uri puri;

	/* check uri */
	if(parse_uri(uri.s, uri.len, &puri)!=0 || puri.host.len>254)
	{
		LM_ERR("bad uri [%.*s]\n", uri.len, uri.s);
		goto err;
	}

	/* get dest set */
	sp = ds_lists[list_idx];
	while(sp)
	{
		if(sp->id == id)
			break;
		sp = sp->next;
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
		sp->next = ds_lists[list_idx];
		ds_lists[list_idx] = sp;
		*setn = *setn+1;
	}
	sp->id = id;
	sp->nr++;

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

	/* copy flags and weight */
	dp->flags = flags;
	dp->weight = weight;

	/* The Hostname needs to be \0 terminated for resolvehost, so we
	 * make a copy here. */
	strncpy(hn, puri.host.s, puri.host.len);
	hn[puri.host.len]='\0';

	/* Do a DNS-Lookup for the Host-Name: */
	he=resolvehost(hn, 0);
	if (he==0)
	{
		LM_ERR("could not resolve %s\n", hn);
		goto err;
	}
	/* Free the hostname */
	hostent2ip_addr(&dp->ip_address, he, 0);
		
	/* Copy the Port out of the URI: */
	dp->port = puri.port_no;

	dp->next = sp->dlist;
	sp->dlist = dp;

	LM_DBG("dest [%d/%d] <%.*s>\n", sp->id, sp->nr, dp->uri.len, dp->uri.s);
	
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

/* compact destinations from sets for fast access */
int reindex_dests(int list_idx, int setn)
{
	int j;
	int weight;
	ds_set_p  sp = NULL;
	ds_dest_p dp = NULL, dp0= NULL;

	for( sp=ds_lists[list_idx] ; sp!= NULL ; sp->dlist=dp0, sp=sp->next )
	{
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

		/* updated the weights (pre-calculate the weight limits)*/
		for( j=0,weight=0 ; j<sp->nr ; j++ ) {
			if (ds_use_default && dp0[j].next==NULL)
				/* skip the last default record */
				break;
			dp0[j].weight += weight;
			weight = dp0[j].weight;
		}
		sp->weight_sum = weight;

	}

	LM_DBG("found [%d] dest sets\n", setn);
	return 0;

err1:
	return -1;
}

/*load groups of destinations from file */
int ds_load_list(char *lfile)
{
	char line[512], *p;
	FILE *f = NULL;
	int id, setn, flags, weight;
	str uri;
	str attrs;

	if( (*crt_idx) != (*next_idx)) {
		LM_WARN("load command already generated, aborting reload...\n");
		return 0;
	}

	if(lfile==NULL || strlen(lfile)<=0)
	{
		LM_ERR("bad list file\n");
		return -1;
	}

	f = fopen(lfile, "r");
	if(f==NULL)
	{
		LM_ERR("can't open list file [%s]\n", lfile);
		return -1;
		
	}

	id = setn = flags = 0;

	*next_idx = (*crt_idx + 1)%2;
	destroy_list(*next_idx);

	p = fgets(line, 512, f);
	while(p)
	{
		/* eat all white spaces */
		while(*p && (*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;
		if(*p=='\0' || *p=='#')
			goto next_line;

		/* get set id */
		id = 0;
		while(*p>='0' && *p<='9')
		{
			id = id*10+ (*p-'0');
			p++;
		}

		/* eat all white spaces */
		while(*p && (*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;
		if(*p=='\0' || *p=='#')
		{
			LM_ERR("bad line (missing uri) [%s]\n", line);
			goto error;
		}

		/* get uri */
		uri.s = p;
		while(*p && *p!=' ' && *p!='\t' && *p!='\r' && *p!='\n' && *p!='#')
			p++;
		uri.len = p-uri.s;

		weight = 1;
		attrs.s = NULL;
		attrs.len = 0;

		/* eat all white spaces */
		while(*p && (*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;
		if(*p=='\0' || *p=='#')
		{
			goto add_destination;
		}

		/* get flags */
		flags = 0;
		while(*p>='0' && *p<='9')
		{
			flags = flags*10+ (*p-'0');
			p++;
		}

		/* eat all white spaces */
		while(*p && (*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;
		if(*p=='\0' || *p=='#')
		{
			goto add_destination;
		}

		/* get weight */
		weight = 0;
		while(*p>='0' && *p<='9')
		{
			weight = weight*10+ (*p-'0');
			p++;
		}

		/* eat all white spaces */
		while(*p && (*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;

		/* get attrs */
		attrs.s = p;
		while (*p && !(*p==' ' || *p=='\t' || *p=='\r' || *p=='\n'))
			p++;
		attrs.len = p - attrs.s;
		if (attrs.len==0)
			attrs.s = NULL;

add_destination:
		if(add_dest2list(id, uri, flags, weight, attrs, *next_idx, &setn) != 0)
			goto error;
					
		
next_line:
		p = fgets(line, 512, f);
	}

	if(reindex_dests(*next_idx, setn)!=0){
		LM_ERR("error on reindex\n");
		goto error;
	}

	fclose(f);
	f = NULL;
	/* Update list */
	_ds_list_nr = setn;
	*crt_idx = *next_idx;
	return 0;

error:
	if(f!=NULL)
		fclose(f);
	destroy_list(*next_idx);
	*next_idx = *crt_idx; 
	return -1;
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

	if ((ds_db_handle = ds_dbf.init(&ds_db_url)) == 0){
		
			return -1;
	}
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
	int ret;

	if(ds_table_name.s == 0)
	{
		LM_ERR("invalid database name\n");
		return -1;
	}
	
	/* Find a database module */
	if (db_bind_mod(&ds_db_url, &ds_dbf) < 0)
	{
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}
	
	if(ds_connect_db()!=0){
		
		LM_ERR("unable to connect to the database\n");
		return -1;
	}
	
	_ds_table_version = db_table_version(&ds_dbf, ds_db_handle, &ds_table_name);
	if (_ds_table_version < 0) 
	{
		LM_ERR("failed to query table version\n");
		return -1;
	} else if (_ds_table_version != DS_TABLE_VERSION_NEW
			&& _ds_table_version != DS_TABLE_VERSION_OLD) {
		LM_ERR("invalid table version (found %d , required %d or %d)\n"
			"(use opensipsdbctl reinit)\n",
			_ds_table_version, DS_TABLE_VERSION_OLD, DS_TABLE_VERSION_NEW );
		return -1;
	}

	ret = ds_load_db();

	ds_disconnect_db();

	return ret;
}

/*load groups of destinations from DB*/
int ds_load_db(void)
{
	int i, id, nr_rows, setn;
	int flags;
	int weight;
	int nrcols;
	str uri;
	str attrs;
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;

	db_key_t query_cols[5] = {&ds_set_id_col, &ds_dest_uri_col,
			&ds_dest_flags_col, &ds_dest_weight_col, &ds_dest_attrs_col};

	nrcols = 3;
	if(_ds_table_version == DS_TABLE_VERSION_NEW)
		nrcols = 5;

	if( (*crt_idx) != (*next_idx))
	{
		LM_WARN("load command already generated, aborting reload...\n");
		return 0;
	}

	if(ds_db_handle == NULL){
			LM_ERR("invalid DB handler\n");
			return -1;
	}

	if (ds_dbf.use_table(ds_db_handle, &ds_table_name) < 0)
	{
		LM_ERR("error in use_table\n");
		return -1;
	}

	/*select the whole table and all the columns*/
	if(ds_dbf.query(ds_db_handle,0,0,0,query_cols,0,nrcols,0,&res) < 0)
	{
		LM_ERR("error while querying database\n");
		return -1;
	}

	nr_rows = RES_ROW_N(res);
	rows = RES_ROWS(res);
	if(nr_rows == 0)
	{
		LM_WARN("no dispatching data in the db -- empty destination set\n");
		ds_dbf.free_result(ds_db_handle, res);
		return 0;
	}

	setn = 0;
	*next_idx = (*crt_idx + 1)%2;
	destroy_list(*next_idx);

	for(i=0; i<nr_rows; i++)
	{
		values = ROW_VALUES(rows+i);

		/* id */
		if (VAL_NULL(values)) {
			LM_ERR("ds ID column cannot be NULL\n");
			goto err2;
		}
		id = VAL_INT(values);

		/* uri */
		if (VAL_NULL(values+1) || VAL_STR(values+1).s==NULL) {
			LM_ERR("ds URI column cannot be NULL or empty\n");
			goto err2;
		}
		uri.s = VAL_STR(values+1).s;
		uri.len = strlen(uri.s);

		/* flags */
		if (VAL_NULL(values+2)) {
			flags = 0;
		} else {
			flags = VAL_INT(values+2);
		}

		if (nrcols==5) {
			/* weight */
			if (VAL_NULL(values+3)) {
				weight = 1;
			} else {
				weight = VAL_INT(values+3);
			}

			/* attrs */
			if (VAL_NULL(values+4) || VAL_STR(values+4).s==NULL) {
				attrs.s = NULL;
				attrs.len = 0;
			} else {
				attrs.s = VAL_STR(values+4).s;
				attrs.len = strlen(attrs.s);
			}
		} else {
			weight = 1;
			attrs.s = NULL;
			attrs.len = 0;
		}

		if(add_dest2list(id, uri, flags, weight, attrs, *next_idx, &setn) != 0)
			goto err2;

	}

	if(reindex_dests(*next_idx, setn)!=0)
	{
		LM_ERR("error on reindex\n");
		goto err2;
	}

	/*update data*/
	_ds_list_nr = setn;
	*crt_idx = *next_idx;
	ds_dbf.free_result(ds_db_handle, res);

	return 0;

err2:
	destroy_list(*next_idx);
	ds_dbf.free_result(ds_db_handle, res);
	*next_idx = *crt_idx; 

	return -1;
}

/*called from dispatcher.c: free all*/
int ds_destroy_list(void)
{
	if (ds_lists) {
		destroy_list(0);
		destroy_list(1);
		shm_free(ds_lists);
	}

	if (crt_idx)
		shm_free(crt_idx);

	return 0;
}

void destroy_list(int list_id)
{
	ds_set_p  sp;
	ds_set_p  sp_curr;
	ds_dest_p dest;

	sp = ds_lists[list_id];

	while(sp) {
		sp_curr = sp;
		sp = sp->next;

		dest = sp_curr->dlist;
		if (dest) {
			do {
				if(dest->uri.s!=NULL)
					shm_free(dest->uri.s);
				dest = dest->next;
			}while(dest);
			shm_free(sp_curr->dlist);
		}
		shm_free(sp_curr);
	}
	
	ds_lists[list_id]  = NULL;
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
	
	/* we want: user@host:port if port !=5060
	 *          user@host if port==5060
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
			/* skip port if == 5060 or sips and == 5061 */
			if (parsed_uri->port_no !=
					((parsed_uri->type==SIPS_URI_T)?SIPS_PORT:SIP_PORT))
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
	
	if(index==NULL || group<0 || _ds_list==NULL)
		return -1;
	
	/* get the index of the set */
	si = _ds_list;
	while(si)
	{
		if(si->id == group)
		{
			*index = si;
			break;
		}
		si = si->next;
	}

	if(si==NULL)
	{
		LM_ERR("destination set [%d] not found\n", group);
		return -1;
	}

	return 0;
}

static inline int ds_update_dst(struct sip_msg *msg, str *uri, int mode)
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
	return 0;
}

static int is_default_destination_entry(ds_set_p idx, int i) {
	return ds_use_default!=0 && i==(idx->nr-1);
}

static int count_inactive_destinations(ds_set_p idx) {
	int count = 0, i;

	for(i=0; i<idx->nr; i++)
		if(idx->dlist[i].flags & DS_INACTIVE_DST)
			/* only count inactive entries that are not default */
			if(!is_default_destination_entry(idx, i))
				count++;

	return count;
}

/**
 *
 */
int ds_select_dst(struct sip_msg *msg, int set, int alg, int mode, int max_results)
{
	int i, cnt, i_unwrapped;
	unsigned int ds_hash;
	int ds_id;
	int_str avp_val;
	ds_set_p idx = NULL;
	int inactive_dst_count = 0;
	int destination_entries_to_skip = 0;

	if(msg==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}
	
	if(_ds_list==NULL || _ds_list_nr<=0)
	{
		LM_ERR("no destination sets\n");
		return -1;
	}

	if((mode==0) && (ds_force_dst==0)
			&& (msg->dst_uri.s!=NULL || msg->dst_uri.len>0))
	{
		LM_ERR("destination already set [%.*s]\n", msg->dst_uri.len,
				msg->dst_uri.s);
		return -1;
	}
	

	/* get the index of the set */
	if(ds_get_index(set, &idx)!=0)
	{
		LM_ERR("destination set [%d] not found\n", set);
		return -1;
	}
	
	LM_DBG("set [%d]\n", set);

	ds_hash = 0;
	ds_id = -1;
	switch(alg)
	{
		case 0:
			if(ds_hash_callid(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get callid hash\n");
				return -1;
			}
		break;
		case 1:
			if(ds_hash_fromuri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get From uri hash\n");
				return -1;
			}
		break;
		case 2:
			if(ds_hash_touri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get To uri hash\n");
				return -1;
			}
		break;
		case 3:
			if (ds_hash_ruri(msg, &ds_hash)!=0)
			{
				LM_ERR("can't get ruri hash\n");
				return -1;
			}
		break;
		case 4:
			ds_id = idx->last;
			idx->last = (idx->last+1) % idx->nr;
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
					idx->last = (idx->last+1) % idx->nr;
				break;
				default:
					LM_ERR("can't get authorization hash\n");
					return -1;
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
				return -1;
			}
		break;
		case 8:
			ds_id = 0;
		break;
		default:
			LM_WARN("algo %d not implemented - using first entry...\n", alg);
			ds_id = 0;
	}

	if (ds_id==-1) {
		/* no destination yet actually selected -> do it based on hash */
		if (idx->weight_sum==0) {
			ds_id = ds_hash % idx->nr;
		} else {
			ds_hash = ds_hash%idx->weight_sum;
			/* get the ds id based on weights */
			for( ds_id=0 ; ds_id<idx->nr ; ds_id++ )
				if (ds_hash<idx->dlist[ds_id].weight)
					break;
		}
	}

	LM_DBG("alg hash [%u], id [%u]\n", ds_hash, ds_id);
	cnt = 0;

	i=ds_id;
	while ( idx->dlist[i].flags&(DS_INACTIVE_DST|DS_PROBING_DST) )
	{
		if(ds_use_default!=0)
			i = (i+1)%(idx->nr-1);
		else
			i = (i+1)%idx->nr;
		if(i==ds_id)
		{
			if(ds_use_default!=0)
			{
				i = idx->nr-1;
				if (idx->dlist[i].flags&(DS_INACTIVE_DST|DS_PROBING_DST))
					return -1;
				break;
			} else {
				return -1;
			}
		}
	}
	ds_id = i;

	if(ds_update_dst(msg, &idx->dlist[ds_id].uri, mode)!=0)
	{
		LM_ERR("cannot set dst addr\n");
		return -1;
	}
	/* if alg is round-robin then update the shortcut to next to be used */
	if(alg==4)
		idx->last = (ds_id+1) % idx->nr;
	
	LM_DBG("selected [%d-%d/%d] <%.*s>\n", alg, set, ds_id,
			idx->dlist[ds_id].uri.len, idx->dlist[ds_id].uri.s);

	if(!(ds_flags&DS_FAILOVER_ON))
		goto done;

	if(dst_avp_name >= 0)
	{
		if(ds_use_default!=0 && ds_id!=idx->nr-1)
		{
			avp_val.s = idx->dlist[idx->nr-1].uri;
			if(add_avp(AVP_VAL_STR|dst_avp_type, dst_avp_name, avp_val)!=0)
				return -1;
			cnt++;
			if (attrs_avp_name >= 0) {
				avp_val.s = idx->dlist[idx->nr-1].attrs;
				if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0)
					return -1;
			}
		}
	
		inactive_dst_count = count_inactive_destinations(idx);
		/* don't count inactive and default entries into total */
		destination_entries_to_skip = idx->nr - inactive_dst_count - (ds_use_default!=0);
		destination_entries_to_skip -= max_results;

		/* add to avp */

		for(i_unwrapped = ds_id-1+idx->nr; i_unwrapped>ds_id; i_unwrapped--) {
			i = i_unwrapped % idx->nr;

			if((idx->dlist[i].flags & DS_INACTIVE_DST)
					|| (ds_use_default!=0 && i==(idx->nr-1)))
				continue;
			if(destination_entries_to_skip > 0) {
				LM_DBG("skipped entry [%d/%d] (would crete more than %i results)\n", set, i, max_results);
				destination_entries_to_skip--;
				continue;
			}

			LM_DBG("using entry [%d/%d]\n", set, i);
			avp_val.s = idx->dlist[i].uri;
			if(add_avp(AVP_VAL_STR|dst_avp_type, dst_avp_name, avp_val)!=0)
				return -1;
			cnt++;
			if (attrs_avp_name >= 0) {
				avp_val.s = idx->dlist[i].attrs;
				if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0)
					return -1;
			}
		}

		/* add to avp the first used dst */
		avp_val.s = idx->dlist[ds_id].uri;
		if(add_avp(AVP_VAL_STR|dst_avp_type, dst_avp_name, avp_val)!=0)
			return -1;
		cnt++;
	}

done:
	if (attrs_avp_name>= 0) {
		avp_val.s = idx->dlist[ds_id].attrs;
		if(add_avp(AVP_VAL_STR|attrs_avp_type,attrs_avp_name,avp_val)!=0)
			return -1;
	}

	if(grp_avp_name>=0) {
		/* add to avp the group id */
		avp_val.n = set;
		if(add_avp(grp_avp_type, grp_avp_name, avp_val)!=0)
			return -1;
	}

	if(cnt_avp_name>=0) {
		/* add to avp the number of dst */
		avp_val.n = cnt;
		if(add_avp(cnt_avp_type, cnt_avp_name, avp_val)!=0)
			return -1;
	}

	return 1;
}

int ds_next_dst(struct sip_msg *msg, int mode)
{
	struct usr_avp *avp;
	struct usr_avp *prev_avp;
	struct usr_avp *attr_avp;
	int_str avp_value;

	if(!(ds_flags&DS_FAILOVER_ON) || dst_avp_name < 0)
	{
		LM_WARN("failover support disabled\n");
		return -1;
	}

	prev_avp = search_first_avp(dst_avp_type, dst_avp_name, NULL, 0);
	if(prev_avp==NULL)
		return -1; /* used avp deleted -- strange */

	avp = search_next_avp(prev_avp, &avp_value);
	destroy_avp(prev_avp);

	if (attrs_avp_name >= 0) {
		attr_avp = search_first_avp(attrs_avp_type, attrs_avp_name, NULL, 0);
		if (attr_avp)
			destroy_avp(attr_avp);
	}

	if(avp==NULL || !(avp->flags&AVP_VAL_STR))
		return -1; /* no more avps or value is int */

	if(ds_update_dst(msg, &avp_value.s, mode)!=0)
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
static str address_str = str_init("address");
static str status_str = str_init("status");
static str inactive_str = str_init("inactive");
static str active_str = str_init("active");

int ds_set_state(int group, str *address, int state, int type)
{
	int i=0;
	ds_set_p idx = NULL;
	evi_params_p list = NULL;

	if(_ds_list==NULL || _ds_list_nr<=0)
	{
		LM_ERR("the list is null\n");
		return -1;
	}
	
	/* get the index of the set */
	if(ds_get_index(group, &idx)!=0)
	{
		LM_ERR("destination set [%d] not found\n", group);
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
						return 0;
					}
					
					idx->dlist[i].failure_count++;
					/* Fire only, if the Threshold is reached. */
					if (idx->dlist[i].failure_count 
							< probing_threshhold) return 0;
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
			
			if(type)
				idx->dlist[i].flags |= state;
			else
				idx->dlist[i].flags &= ~state;
			if (dispatch_evi_id == EVI_ERROR) {
				LM_ERR("event not registered %d\n", dispatch_evi_id);
			} else if (evi_probe_event(dispatch_evi_id)) {
				if (!(list = evi_get_params()))
					return 0;
				if (evi_param_add_str(list, &address_str, address)) {
					LM_ERR("unable to add address parameter\n");
					evi_free_params(list);
					return 0;
				}
				if (evi_param_add_str(list, &status_str,
							type ? &inactive_str : &active_str)) {
					LM_ERR("unable to add status parameter\n");
					evi_free_params(list);
					return 0;
				}

				if (evi_raise_event(dispatch_evi_id, list)) {
					LM_ERR("unable to send event\n");
				}
			} else {
				LM_DBG("no event sent\n");
			}
			return 0;
		}
		i++;
	}

	return -1;
}

int ds_print_list(FILE *fout)
{
	int j;
	ds_set_p list;
		
	if(_ds_list==NULL || _ds_list_nr<=0)
	{
		LM_ERR("no destination sets\n");
		return -1;
	}
	
	fprintf(fout, "\nnumber of destination sets: %d\n", _ds_list_nr);
	
	for(list = _ds_list; list!= NULL; list= list->next)
	{
		for(j=0; j<list->nr; j++)
		{
			fprintf(fout, "\n set #%d\n", list->id);
		
			if (list->dlist[j].flags&DS_INACTIVE_DST)
  				fprintf(fout, "    Disabled         ");
  			else if (list->dlist[j].flags&DS_PROBING_DST)
  				fprintf(fout, "    Probing          ");
  			else {
  				fprintf(fout, "    Active");
  				/* Optional: Print the tries for this host. */
  				if (list->dlist[j].failure_count > 0) {
  					fprintf(fout, " (Fail %d/%d)",
  							list->dlist[j].failure_count,
 							probing_threshhold);
  				} else {
  					fprintf(fout, "           ");
  				}
  			}
  
  			fprintf(fout, "   %.*s\n",
  				list->dlist[j].uri.len, list->dlist[j].uri.s);		
		}
	}
	return 0;
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
	int port;
	int j;

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

	for(list = _ds_list; list!= NULL; list= list->next) {
		if ((set == -1) || (set == list->id)) {
			for(j=0; j<list->nr; j++) {
				if ( (list->dlist[j].port==0 || port==0
				|| port==list->dlist[j].port) &&
				ip_addr_cmp( ip, &list->dlist[j].ip_address) ) {
					/* matching destination */
					if (active_only &&
					(list->dlist[j].flags&(DS_INACTIVE_DST|DS_PROBING_DST)) )
						continue;
					if(set==-1 && ds_setid_pvname.s!=0) {
						val.ri = list->id;
						if(pv_set_value(_m, &ds_setid_pv,
								(int)EQ_T, &val)<0)
						{
							LM_ERR("setting PV failed\n");
							return -2;
						}
					}
					return 1;
				}
			}
		}
	}
	return -1;
}


int ds_print_mi_list(struct mi_node* rpl)
{
	int len, j;
	char* p;
	char c;
	ds_set_p list;
	struct mi_node* node = NULL;
	struct mi_node* set_node = NULL;
	struct mi_attr* attr = NULL;
	
	if(_ds_list==NULL || _ds_list_nr<=0)
	{
		LM_ERR("no destination sets\n");
		return  0;
	}

	p= int2str(_ds_list_nr, &len); 
	node = add_mi_node_child(rpl, MI_DUP_VALUE, "SET_NO",6, p, len);
	if(node== NULL)
		return -1;

	for(list = _ds_list; list!= NULL; list= list->next)
	{
		p = int2str(list->id, &len);
		set_node= add_mi_node_child(rpl, MI_DUP_VALUE,"SET", 3, p, len);
		if(set_node == NULL)
			return -1;

		for(j=0; j<list->nr; j++)
  		{
  			node= add_mi_node_child(set_node, 0, "URI", 3,
  					list->dlist[j].uri.s, list->dlist[j].uri.len);
  			if(node == NULL)
  				return -1;
  
  			if (list->dlist[j].flags & DS_INACTIVE_DST) c = 'I';
  			else if (list->dlist[j].flags & DS_PROBING_DST) c = 'P';
  			else c = 'A';
  
  			attr = add_mi_attr (node, MI_DUP_VALUE, "flag",4, &c, 1);
  			if(attr == 0)
  				return -1;
  
 		}
	}

	return 0;
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
	if (!*ps->param)
	{
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
	/* ps->code contains the result-code of the request.
	 * 
	 * We accept "200 OK" by default and the custom codes
	 * defined in options_reply_codes parameter*/
	if ((ps->code == 200) || check_options_rplcode(ps->code))
	{
		/* Set the according entry back to "Active":
		 *  remove the Probing/Inactive Flag and reset the failure counter. */
		if (ds_set_state(group, &uri,
					DS_INACTIVE_DST|DS_PROBING_DST|DS_RESET_FAIL_DST, 0) != 0)
		{
			LM_ERR("Setting the state failed (%.*s, group %d)\n", uri.len,
					uri.s, group);
		}
	}
	if(ds_probing_mode==1 && ps->code == 408)
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
	if(_ds_list==NULL || _ds_list_nr<=0)
		return;

	/* Iterate over the groups and the entries of each group: */
	for(list = _ds_list; list!= NULL; list= list->next)
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
							probing_sock,
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
}
