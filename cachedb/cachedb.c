/*
 * Copyright (C) 2011-2019 OpenSIPS Solutions
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
 */

#include "cachedb.h"
#include "cachedb_cap.h"
#include "../dprint.h"
#include "../sr_module.h"
#include "../mem/mem.h"
#include "../mem/meminfo.h"
#include "../str.h"
#include "../ut.h"

#include <string.h>
#include <stdlib.h>

stat_var *cdb_total_queries;
stat_var *cdb_slow_queries;

struct cachedb_engine_t
{
	cachedb_engine cde;
	struct cachedb_engine_t* next;
};

int init_cdb_support(void)
{
	if (register_stat("cdb", "cdb_total_queries", &cdb_total_queries, 0) ||
	    register_stat("cdb", "cdb_slow_queries", &cdb_slow_queries, 0)) {
		LM_ERR("failed to register CacheDB stats\n");
		return -1;
	}

	return 0;
}

int cachedb_store_url(struct cachedb_url **list,char *val)
{
	struct cachedb_url *new,*it;
	int len;

	len = strlen(val);
	new = pkg_malloc(sizeof(struct cachedb_url) + len);
	if (new == NULL) {
		LM_ERR("no more pkg\n");
		return -1;
	}

	memset(new,0,sizeof(struct cachedb_url) + len);
	new->url.len = len;
	new->url.s = (char *)(new + 1);
	memcpy(new->url.s,val,len);

	if (*list == NULL)
		*list = new;
	else {
		for (it=*list;it->next;it=it->next);
		it->next = new;
	}

	return 0;
}

void cachedb_free_url(struct cachedb_url *list)
{
	struct cachedb_url *it=list,*aux;

	while (it){
		aux = it->next;
		pkg_free(it);
		it=aux;
	}
}

static struct cachedb_engine_t* cachedb_list = NULL;

cachedb_engine* lookup_cachedb(str *name)
{
	struct cachedb_engine_t* cde_node;

	cde_node = cachedb_list;

	while(cde_node)
	{
		if (name->len == cde_node->cde.name.len &&
				strncmp(name->s, cde_node->cde.name.s, name->len) == 0)
			return &cde_node->cde;

		cde_node = cde_node->next;
	}

	return 0;
}

int cachedb_bind_mod(str *url,cachedb_funcs *funcs)
{
	char *mod_name,*grp_name;
	int len;
	str cachedb_name;
	cachedb_engine *cde;


	if (url == NULL || url->s == NULL || funcs == NULL) {
		LM_ERR("NULL parameter provided\n");
		return -1;
	}

	memset(funcs,0,sizeof(cachedb_funcs));

	mod_name = memchr(url->s,':',url->len);
	if (mod_name == NULL) {
		LM_ERR("cannot extract cachedb type\n");
		return -1;
	}

	len = mod_name - url->s;
	cachedb_name.len = len;
	cachedb_name.s = url->s;

	/* no point in giving here the grp_name, but for the sake of uniform
	 * cachedb_urls in modules and for script, take in into account
	 * the presence of grp here too, and skip it */
	grp_name=memchr(cachedb_name.s,':',cachedb_name.len);
	if (grp_name)
		cachedb_name.len = grp_name - cachedb_name.s;

	cde = lookup_cachedb(&cachedb_name);
	if (cde == NULL) {
		LM_ERR("failed to bind to [%.*s] module. Is it loaded ?\n",
				cachedb_name.len,cachedb_name.s);
		return -1;
	}

	LM_DBG("Binded to mod %.*s\n",cachedb_name.len,cachedb_name.s);
	*funcs = cde->cdb_func;
	return 0;
}

int register_cachedb(cachedb_engine* cde_entry)
{
	struct cachedb_engine_t* cde_node;

	if(cde_entry == NULL)
	{
		LM_ERR("null argument\n");
		return -1;
	}

	if (lookup_cachedb( &cde_entry->name))
	{
		LM_ERR("cachedb system <%.*s> already registered\n",
				cde_entry->name.len, cde_entry->name.s);
		return -1;
	}

	cde_node = (struct cachedb_engine_t*)pkg_malloc(
		sizeof(struct cachedb_engine_t) + cde_entry->name.len);
	if (cde_node== NULL)
	{
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	cde_node->cde.name.s = (char*)cde_node + sizeof(struct cachedb_engine_t);
	memcpy(cde_node->cde.name.s, cde_entry->name.s, cde_entry->name.len);
	cde_node->cde.name.len = cde_entry->name.len;

	cde_node->cde.cdb_func = cde_entry->cdb_func;

	if (check_cachedb_api(&cde_node->cde) < 0) {
		LM_ERR("failed to meet api needs\n");
		pkg_free(cde_node);
		return -1;
	}

	cde_node->cde.default_connection = NULL;
	cde_node->cde.connections = NULL;

	cde_node->next = cachedb_list;
	cachedb_list = cde_node;

	LM_DBG("registered cachedb system [%.*s]\n", cde_node->cde.name.len,
			cde_node->cde.name.s);

	return 0;
}

int cachedb_insert_connection(cachedb_engine *cde,cachedb_con *conn)
{
	cachedb_con_list *new,*it;
	str grp;

	grp.s = ((cachedb_pool_con *)conn->data)->id->group_name;
	if (grp.s)
		grp.len = strlen(grp.s);

	if (grp.s == NULL || grp.len == 0) {
		LM_DBG("inserting default script connection\n");
		cde->default_connection = conn;
		return 0;
	}

	LM_DBG("inserting grp connection [%.*s]\n",grp.len,grp.s);

	new = pkg_malloc(sizeof(cachedb_con_list));
	if (new == NULL) {
		LM_ERR("no more pkg\n");
		return -1;
	}

	memset(new,0,sizeof(cachedb_con_list));
	new->connection = conn;
	new->grp = grp;

	if (cde->connections == NULL) {
		cde->connections = new;
	} else {
		for (it=cde->connections;it->next;it=it->next);
		it->next = new;
	}

	return 0;
}

int cachedb_put_connection(str *cachedb_name,cachedb_con *con)
{
	cachedb_engine *cde;

	cde = lookup_cachedb(cachedb_name);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cachedb_name->len,cachedb_name->s);
		return -1;
	}

	LM_DBG("in cachedb_put_connection %p\n",con);
	if (cachedb_insert_connection(cde,con) < 0) {
		LM_ERR("failed to insert new connection\n");
		return -1;
	}

	return 0;
}

cachedb_con *cachedb_get_connection(cachedb_engine *cde,str *group_name)
{
	cachedb_con_list *ret;

	if (cde == NULL) {
		LM_ERR("no such cachedb engine\n");
		return 0;
	}

	if (group_name == NULL || group_name->s == NULL || group_name->len == 0)
		return cde->default_connection;
	else {
		for (ret=cde->connections;ret;ret=ret->next) {
			if (ret->grp.len == group_name->len &&
				memcmp(ret->grp.s,group_name->s,group_name->len) == 0)
				return ret->connection;
		}
		return NULL;
	}
}

void cachedb_end_connections(str *cachedb_name)
{
	cachedb_engine *cde;
	cachedb_con_list *it;

	cde = lookup_cachedb(cachedb_name);
	if(cde == NULL) {
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cachedb_name->len,cachedb_name->s);
		return;
	}

	if (cde->default_connection)
		cde->cdb_func.destroy(cde->default_connection);

	for (it=cde->connections;it;it=it->next)
		cde->cdb_func.destroy(it->connection);
}


int cachedb_remove(str* cachedb_name, str* attr)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.remove(con,attr);
	if (ret == 0)
		ret++;

	return ret;
}

int cachedb_store(str* cachedb_name, str* attr, str* val,int expires)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL || val == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.set(con,attr,val,expires);
	if (ret ==0)
		ret++;

	return ret;
}

int cachedb_fetch(str* cachedb_name, str* attr, str* val)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL || val == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.get(con,attr,val);
	if (ret == 0)
		ret++;

	return ret;
}

int cachedb_counter_fetch(str* cachedb_name, str* attr, int* val)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL || val == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.get_counter(con,attr,val);
	if (ret == 0)
		ret++;

	return ret;
}

int cachedb_add(str* cachedb_name, str* attr, int val,int expires,int *new_val)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&cde->cdb_func,CACHEDB_CAP_ADD)) {
		LM_ERR("Engine %.*s does not support add ops\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.add(con,attr,val,expires,new_val);
	if (ret == 0)
		ret++;

	return ret;
}

int cachedb_sub(str* cachedb_name, str* attr, int val,int expires,int *new_val)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&cde->cdb_func,CACHEDB_CAP_SUB)) {
		LM_ERR("Engine %.*s does not support sub ops\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.sub(con,attr,val,expires,new_val);
	if (ret == 0)
		ret++;

	return ret;
}

cachedb_con* cachedb_do_init(str *url,void* (*new_connection)(struct cachedb_id *))
{
	struct cachedb_id* id;
	cachedb_con* res;
	void *con;

	if (url == NULL || url->s == NULL || new_connection == NULL) {
		LM_ERR("NULL parameter provided\n");
		return 0;
	}

	res = pkg_malloc(sizeof(cachedb_con) + url->len);
	if (res == NULL) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}

	id = NULL;

	memset(res,0,sizeof(cachedb_con) + url->len);
	res->url.s = (char *)res + sizeof(cachedb_con);
	res->url.len = url->len;
	memcpy(res->url.s,url->s,url->len);

	id = new_cachedb_id(url);
	if (!id) {
		LM_ERR("cannot parse url [%s]\n", db_url_escape(url));
		pkg_free(res);
		return 0;
	}

	con = cachedb_pool_get(id);
	if (con == NULL) {
		LM_DBG("opening new connection\n");
		con = new_connection(id);
		if (con == NULL) {
			LM_ERR("failed to open connection\n");
			goto err;
		}

		cachedb_pool_insert((cachedb_pool_con *)con);
	} else {
		LM_DBG("connection already in pool\n");
		free_cachedb_id(id);
	}

	res->data = con;
	return res;

err:
	if (res)
		pkg_free(res);
	if (id)
		free_cachedb_id(id);

	return 0;
}

void cachedb_do_close(cachedb_con *con, void (*free_connection)(cachedb_pool_con *))
{
	cachedb_pool_con *tmp;

	if (con == NULL) {
		LM_ERR("NULL parameter provided\n");
		return;
	}

	tmp = (cachedb_pool_con*)con->data;
	if (cachedb_pool_remove(tmp) == 1) {
		free_connection(tmp);
	}

	pkg_free(con);
}

int cachedb_raw_query(str* cachedb_name, str* attr, cdb_raw_entry*** reply,int expected_kv_no,int *rpl_no)
{
	cachedb_engine* cde;
	str cde_engine,grp_name;
	char *p;
	cachedb_con *con;
	int ret;

	if(cachedb_name == NULL || attr == NULL)
	{
		LM_ERR("null arguments\n");
		return -1;
	}

	p = memchr(cachedb_name->s,':',cachedb_name->len);
	if (p == NULL) {
		cde_engine = *cachedb_name;
		grp_name.s = NULL;
		grp_name.len = 0;
		LM_DBG("from script [%.*s] - no grp\n",cde_engine.len,cde_engine.s);
	} else {
		cde_engine.s = cachedb_name->s;
		cde_engine.len = p - cde_engine.s;
		grp_name.s = p+1;
		grp_name.len = cachedb_name->len - cde_engine.len -1;
		LM_DBG("from script [%.*s] - with grp [%.*s]\n",cde_engine.len,
				cde_engine.s,grp_name.len,grp_name.s);

	}

	cde = lookup_cachedb(&cde_engine);
	if(cde == NULL)
	{
		LM_ERR("Wrong argument <%.*s> - no cachedb system with"
				" this name registered\n",
				cde_engine.len,cde_engine.s);
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&cde->cdb_func,CACHEDB_CAP_RAW)) {
		LM_ERR("The backend does not support raw queries\n");
		return -1;
	}

	con = cachedb_get_connection(cde,&grp_name);
	if (con == NULL) {
		LM_ERR("failed to get connection for grp name [%.*s] : check db_url\n",
				grp_name.len,grp_name.s);
		return -1;
	}

	ret = cde->cdb_func.raw_query(con,attr,reply,expected_kv_no,rpl_no);
	if (ret == 0)
		ret++;

	return ret;
}

void free_raw_fetch(cdb_raw_entry **reply, int num_cols, int num_rows)
{
	int i,j;

	for (i=0;i<num_rows;i++) {
		for (j=0;j<num_cols;j++) {
			if (reply[i][j].type == CDB_STR)
				pkg_free(reply[i][j].val.s.s);
		}
		pkg_free(reply[i]);
	}

	pkg_free(reply);
}
