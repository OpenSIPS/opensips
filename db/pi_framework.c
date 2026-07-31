/* Core PI framework parser.  XML parsing is deliberately transport-independent. */
#include "../str.h"
#include "../ut.h"
#include "../db/db_ut.h"
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../config.h"
#include "../globals.h"
#include "../socket_info.h"
#include "../resolve.h"
#include "../parser/parse_uri.h"
#include "../sr_module.h"
#include "pi_xml.h"
#include "pi_framework.h"
#include "pi_framework_db.h"

#define PI_XML_FRAMEWORK_NODE "framework"
#define PI_XML_DB_URL_NODE "db_url"
#define PI_XML_DB_TABLE_NODE "db_table"
#define PI_XML_TABLE_NAME_NODE "table_name"
#define PI_XML_DB_URL_ID_NODE "db_url_id"
#define PI_XML_MOD_NODE "mod"
#define PI_XML_MOD_NAME_NODE "mod_name"
#define PI_XML_CMD_NODE "cmd"
#define PI_XML_DB_TABLE_ID_NODE "db_table_id"
#define PI_XML_CMD_NAME_NODE "cmd_name"
#define PI_XML_CMD_TYPE_NODE "cmd_type"
#define PI_XML_CLAUSE_COLS_NODE "clause_cols"
#define PI_XML_QUERY_COLS_NODE "query_cols"
#define PI_XML_ORDER_BY_COLS_NODE "order_by_cols"
#define PI_XML_COLUMN_NODE "column"
#define PI_XML_COL_NODE "col"
#define PI_XML_FIELD_NODE "field"
#define PI_XML_LINK_CMD_NODE "link_cmd"
#define PI_XML_TYPE_NODE "type"
#define PI_XML_OPERATOR_NODE "operator"
#define PI_XML_VALUE_NODE "value"
#define PI_XML_VALIDATE_NODE "validate"
#define PI_XML_ID_ATTR "id"

pi_framework_t *pi_framework_data = NULL;


xmlAttrPtr pi_xmlNodeGetAttrByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = node->properties;
	while (attr) {
		if(xmlStrcasecmp(attr->name, (const xmlChar*)name)==0)
			return attr;
		attr = attr->next;
	}
	return NULL;
}

char *pi_xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = pi_xmlNodeGetAttrByName(node, name);
	if (attr) return (char*)xmlNodeGetContent(attr->children);
	else return NULL;
}

xmlNodePtr pi_xmlNodeGetNodeByName(xmlNodePtr node, const char *name)
{
	xmlNodePtr cur = node;
	while (cur) {
		if(xmlStrcasecmp(cur->name, (const xmlChar*)name)==0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

char *pi_xmlNodeGetNodeContentByName(xmlNodePtr node, const char *name)
{
	xmlNodePtr node1 = pi_xmlNodeGetNodeByName(node, name);
	if (node1) return (char*)xmlNodeGetContent(node1);
	else return NULL;
}


int pi_getDbUrlNodes(pi_framework_t *_pi_framework_data, xmlNodePtr framework_node)
{
	int i;
	xmlNodePtr node;
	pi_db_url_t *db_urls;
	pi_db_url_t *pi_db_urls = NULL;
	str id, db_url;

	//_pi_framework_data->pi_db_urls_size=0;
	for(node=framework_node->children;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_DB_URL_NODE) == 0) {
			if(_pi_framework_data->pi_db_urls_size)
				db_urls = (pi_db_url_t*)
					shm_realloc(_pi_framework_data->pi_db_urls,
					(_pi_framework_data->pi_db_urls_size+1)*
					sizeof(pi_db_url_t));
			else
				db_urls = (pi_db_url_t*)
						shm_malloc(sizeof(pi_db_url_t));
			if(db_urls==NULL) {LM_ERR("oom\n");return -1;}
			_pi_framework_data->pi_db_urls = db_urls;

			pi_db_urls = _pi_framework_data->pi_db_urls;
			db_urls = &pi_db_urls[_pi_framework_data->pi_db_urls_size];
			memset(db_urls, 0, sizeof(pi_db_url_t));

			id.s = pi_xmlNodeGetAttrContentByName(node,
						PI_XML_ID_ATTR);
			if(id.s==NULL){
				LM_ERR("No attribute for node %d [%s]\n",
					_pi_framework_data->pi_db_urls_size,
					node->name);
				return -1;
			}
			id.len = strlen(id.s);
			if(id.len==0){
				LM_ERR("Empty attr for node %d [%s]\n",
					_pi_framework_data->pi_db_urls_size,
					node->name);
				return -1;
			}
			if(shm_str_dup(&db_urls->id, &id)!=0) return -1;
			xmlFree(id.s);id.s=NULL;id.len=0;

			db_url.s = (char*)xmlNodeGetContent(node);
			if(db_url.s==NULL){
				LM_ERR("No content for node [%.*s][%s]\n",
					db_urls->id.len, db_urls->id.s, node->name);
				return -1;
			}
			db_url.len = strlen(db_url.s);
			if(db_url.len==0){
				LM_ERR("Empty content for node [%.*s][%s]\n",
					db_urls->id.len, db_urls->id.s, node->name);
				return -1;
			}
			if(shm_str_dup(&db_urls->db_url, &db_url)!=0) return -1;
			xmlFree(db_url.s);db_url.s=NULL;db_url.len=0;

			for(i=0;i<_pi_framework_data->pi_db_urls_size;i++){
				if(db_urls->id.len==pi_db_urls[i].id.len &&
                                        strncmp(pi_db_urls[i].id.s,
                                                db_urls->id.s,
						db_urls->id.len)==0){
					LM_ERR("duplicated %s %s [%.*s]\n",
						PI_XML_DB_URL_NODE,
						PI_XML_ID_ATTR,
						db_urls->id.len,
						db_urls->id.s);
					return -1;
				}
				if(db_urls->db_url.len==pi_db_urls[i].db_url.len &&
                                        strncmp(pi_db_urls[i].db_url.s,
                                                db_urls->db_url.s,
						db_urls->db_url.len)==0){
					LM_ERR("duplicated %s [%.*s]\n",
						PI_XML_DB_URL_NODE,
						db_urls->db_url.len,
						db_urls->db_url.s);
					return -1;
				}
			}
			/* */
			LM_DBG("got node [%s]->[%.*s][%.*s]\n",
				node->name,
				db_urls->id.len, db_urls->id.s,
				db_urls->db_url.len, db_urls->db_url.s);
			/* */
			_pi_framework_data->pi_db_urls_size++;
		}
	}
	if(_pi_framework_data->pi_db_urls_size==0){
		LM_ERR("No [%s] node in config file\n", PI_XML_DB_URL_NODE);
		return -1;
	}
	/* */
	for(i=0;i<_pi_framework_data->pi_db_urls_size;i++){
		LM_DBG("got node %s [%d][%.*s][%.*s]\n", PI_XML_DB_URL_NODE,
			i, pi_db_urls[i].id.len, pi_db_urls[i].id.s,
			pi_db_urls[i].db_url.len, pi_db_urls[i].db_url.s);
	}
	/* */
	return 0;
}

int pi_getDbTableCols(pi_db_url_t *pi_db_urls, pi_db_table_t *db_tables,
			const xmlNodePtr table_node)
{
	int i;
	char *val;
	int val_len;
	xmlNodePtr node;
	pi_table_col_t *cols;
	str field;

	for(node=table_node->children,db_tables->cols_size=0;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_COLUMN_NODE) == 0) {
			if(db_tables->cols_size)
				cols = (pi_table_col_t*)shm_realloc(db_tables->cols,
						(db_tables->cols_size+1)*
						sizeof(pi_table_col_t));
			else
				cols = (pi_table_col_t*)
					shm_malloc(sizeof(pi_table_col_t));
			if(cols==NULL) {LM_ERR("oom\n");return -1;}
			db_tables->cols = cols;
			cols = &db_tables->cols[db_tables->cols_size];
			memset(cols, 0, sizeof(pi_table_col_t));
			cols->type=(db_type_t)-1;
			/* Populate the field */
			field.s =
				pi_xmlNodeGetNodeContentByName(node->children,
							PI_XML_FIELD_NODE);
			if(field.s==NULL){
				LM_ERR("missing node %s [%.*s] %s %s\n",
					table_node->name,
					db_tables->name.len, db_tables->name.s,
					node->name, PI_XML_FIELD_NODE);
				return -1;
			}
			field.len = strlen(field.s);
			if(field.len==0){
				LM_ERR("empty node %s [%.*s] %s %s \n",
					table_node->name,
					db_tables->name.len, db_tables->name.s,
					node->name, PI_XML_FIELD_NODE);
				return -1;
			}
			if(shm_str_dup(&cols->field, &field)!=0) return -1;
			xmlFree(field.s);field.s=NULL;field.len=0;
			/* Each field MUST be unique */
			for(i=0;i<db_tables->cols_size;i++){
				if(cols->field.len==db_tables->cols[i].field.len &&
					strncmp(db_tables->cols[i].field.s,
						cols->field.s,
						cols->field.len)==0){
					LM_ERR("duplicated %s %s [%.*s] in %s [%.*s]\n",
						node->name, PI_XML_FIELD_NODE,
						cols->field.len, cols->field.s,
						table_node->name,
						db_tables->name.len, db_tables->name.s);
					return -1;
				}
			}
			/* Populate the validation */
			val = pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_VALIDATE_NODE);
			if(val){
				val_len = strlen(val);
				switch(val_len){
				case 0:
					break;
				case 3:
					if(strncmp("URI",val,3)==0)
						cols->validation|=PI_FLAG_URI;
					break;
				case 11:
					if(strncmp("P_HOST_PORT",val,11)==0)
						cols->validation|=PI_FLAG_P_HOST_PORT;
					else
					if(strncmp("P_IPV4_PORT",val,11)==0)
						cols->validation|=PI_FLAG_P_IPV4_PORT;
					break;
				case 12:
					if(strncmp("URI_IPV4HOST",val,12)==0)
						cols->validation|=PI_FLAG_URI_IPV4HOST;
					break;
				default:
					LM_ERR("unexpected validation flag [%s] for "
						"%s %s %s\n",
						val, table_node->name, node->name,
						PI_XML_VALIDATE_NODE);
					xmlFree(val);
					return -1;
				}
				xmlFree(val);
			}
			/* Populate the type */
			val = pi_xmlNodeGetNodeContentByName(node->children,
							PI_XML_TYPE_NODE);
			if(val==NULL){
				LM_ERR("missing node %s %s %s\n",
					table_node->name, node->name,
					PI_XML_TYPE_NODE);
				return -1;
			}
			val_len = strlen(val);
			if(val_len==0){
				LM_ERR("empty node %s %s %s\n",
					table_node->name, node->name,
					PI_XML_TYPE_NODE);
				xmlFree(val);
				return -1;
			}else if(val_len==6){
				if(strncmp("DB_INT",val,6)==0)
					cols->type=DB_INT;
				else if(strncmp("DB_STR",val,6)==0)
					cols->type=DB_STR;
			}else if(val_len==7){
				if(strncmp("DB_BLOB",val,7)==0)
					cols->type=DB_BLOB;
			}else if(val_len==9){
				if(strncmp("DB_BIGINT",val,9)==0)
					cols->type=DB_BIGINT;
				else if(strncmp("DB_DOUBLE",val,9)==0)
					cols->type=DB_DOUBLE;
				else if(strncmp("DB_STRING",val,9)==0)
					cols->type=DB_STRING;
				else if(strncmp("DB_BITMAP",val,9)==0)
					cols->type=DB_BITMAP;
			}else if(val_len==11){
				if(strncmp("DB_DATETIME",val,11)==0)
					cols->type=DB_DATETIME;
			}
			if(cols->type== (db_type_t)-1){
				LM_ERR("unexpected type [%s] for %s %s %s\n",
					val, table_node->name, node->name,
					PI_XML_TYPE_NODE);
				xmlFree(val);
				return -1;
			}
			xmlFree(val);
			/* */
			LM_DBG("got node %s [%d][%.*s][%d]\n",
				PI_XML_COLUMN_NODE,
				db_tables->cols_size,
				db_tables->cols[db_tables->cols_size].field.len,
				db_tables->cols[db_tables->cols_size].field.s,
				db_tables->cols[db_tables->cols_size].type);
			/* */
			db_tables->cols_size++;
		}
	}
	if(db_tables->cols_size==0){
		LM_ERR("missing node: %s %s\n",
			table_node->name, PI_XML_COLUMN_NODE);
		return -1;
	}
	return 0;
}

int pi_getDbTables(pi_framework_t *_pi_framework_data, xmlNodePtr framework_node)
{
	int i;
	int j;
	char *val;
	int val_len;
	xmlNodePtr node;
	pi_db_table_t *db_tables;
	pi_db_table_t *pi_db_tables = NULL;
	str id, name;

	//_pi_framework_data->pi_db_tables_size=0;
	for(node=framework_node->children;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_DB_TABLE_NODE) == 0) {
			if(_pi_framework_data->pi_db_tables_size)
				db_tables = (pi_db_table_t*)
					shm_realloc(_pi_framework_data->pi_db_tables,
					(_pi_framework_data->pi_db_tables_size+1)*
					sizeof(pi_db_table_t));
			else
				db_tables = (pi_db_table_t*)
						shm_malloc(sizeof(pi_db_table_t));
			if(db_tables==NULL) {LM_ERR("oom\n"); return -1;}
			_pi_framework_data->pi_db_tables = db_tables;

			pi_db_tables = _pi_framework_data->pi_db_tables;
			db_tables = &pi_db_tables[_pi_framework_data->pi_db_tables_size];
			memset(db_tables, 0, sizeof(pi_db_table_t));

			/* Populate table ids */
			id.s = pi_xmlNodeGetAttrContentByName(node,
						PI_XML_ID_ATTR);
			if(id.s==NULL){
				LM_ERR("No attribute for node %d [%s]\n",
					_pi_framework_data->pi_db_tables_size,
					node->name);
				return -1;
			}
			id.len = strlen(id.s);
			if(id.len==0){
				LM_ERR("Empty attr for node %d [%s]\n",
					_pi_framework_data->pi_db_tables_size,
					node->name);
				return -1;
			}
			if(shm_str_dup(&db_tables->id, &id)!=0) return -1;
			xmlFree(id.s);id.s=NULL;id.len=0;
			/* Populate table name */
			name.s =
				pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_TABLE_NAME_NODE);
			if(name.s==NULL){
				LM_ERR("No content for node [%.*s][%s]\n",
					db_tables->id.len, db_tables->id.s,
					node->name);
				return -1;
			}
			name.len = strlen(name.s);
			if(name.len==0){
				LM_ERR("Empty content for node [%.*s][%s]\n",
					db_tables->id.len, db_tables->id.s,
					node->name);
				return -1;
			}
			if(shm_str_dup(&db_tables->name, &name)!=0) return -1;
			xmlFree(name.s);name.s=NULL;name.len=0;
			/* Each table_id MUST be unique */
			for(i=0;i<_pi_framework_data->pi_db_tables_size;i++){
				if(db_tables->id.len==pi_db_tables[i].id.len &&
                                        strncmp(pi_db_tables[i].id.s,
                                                db_tables->id.s,
						db_tables->id.len)==0){
					LM_ERR("duplicated id %s %s [%.*s]\n",
						PI_XML_DB_TABLE_NODE,
						PI_XML_ID_ATTR,
						db_tables->id.len, db_tables->id.s);
					return -1;
				}
			}
			/* Populate the optional db_url index.  If omitted, the
			 * owning module's db_url will be used during finalization. */
			val = pi_xmlNodeGetNodeContentByName(node->children,
							PI_XML_DB_URL_ID_NODE);
			if(val!=NULL)
				val_len = strlen(val);
			if(val && val_len==0){
				LM_ERR("empty %s for node %s [%.*s]\n",
					PI_XML_DB_URL_ID_NODE,
					PI_XML_DB_TABLE_NODE,
					db_tables->name.len, db_tables->name.s);
				return -1;
			}
			if (val) {
				str db_url_id = {val, val_len};
				if (shm_str_dup(&db_tables->db_url_id, &db_url_id) != 0)
					return -1;
				xmlFree(val);
			}

			if(pi_getDbTableCols(_pi_framework_data->pi_db_urls,
							db_tables, node)!=0)
				return -1;

			_pi_framework_data->pi_db_tables_size++;
			/*
			LM_DBG("got node [%s]->[%s][%s]\n",
				node->name, db_tables->id.s, db_tables->db_table.s);
			*/
		}
	}
	if(_pi_framework_data->pi_db_tables_size==0){
		LM_ERR("No [%s] node in config file\n", PI_XML_DB_TABLE_NODE);
		return -1;
	}
	/* */
	for(i=0;i<_pi_framework_data->pi_db_tables_size;i++){
		LM_DBG("got node %s [%d][%.*s]->[%.*s/%.*s]\n",
			PI_XML_DB_TABLE_NODE, i,
			pi_db_tables[i].id.len, pi_db_tables[i].id.s,
			pi_db_tables[i].db_url_id.len,
			pi_db_tables[i].db_url_id.s ? pi_db_tables[i].db_url_id.s : "(module)",
			pi_db_tables[i].name.len, pi_db_tables[i].name.s);
		db_tables = &pi_db_tables[i];
		for(j=0;j<db_tables->cols_size;j++){
			LM_DBG("got node %s [%.*s][%d]\n",
				PI_XML_COLUMN_NODE,
				db_tables->cols[j].field.len,
				db_tables->cols[j].field.s,
				db_tables->cols[j].type);
		}
	}
	/* */
	return 0;
}

int pi_getColVals(pi_mod_t *module, pi_cmd_t *cmd,
		pi_vals_t *cmd_col_vals, xmlNodePtr col_node)
{
	xmlNodePtr node;
	str *vals, *col_vals = NULL;
	str *ids, *col_ids = NULL;
	int size = 0;
	int i;
	str attr;
	str val;

	for(node=col_node->children;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_VALUE_NODE) == 0) {
			if(size){
				vals = (str*)shm_realloc(col_vals,
					(size+1)*sizeof(str));
				ids = (str*)shm_realloc(col_ids,
					(size+1)*sizeof(str));
			}else{
				vals = (str*)shm_malloc(sizeof(str));
				ids = (str*)shm_malloc(sizeof(str));
			}
			if(vals==NULL||ids==NULL) {LM_ERR("oom\n"); return -1;}
			col_vals = vals; col_ids = ids;
			vals = &col_vals[size]; ids = &col_ids[size];
			memset(vals, 0, sizeof *vals); memset(ids, 0, sizeof *ids);
			/* Retrieve the node attribute */
			attr.s = pi_xmlNodeGetAttrContentByName(node,
							PI_XML_ID_ATTR);
			if(attr.s==NULL){
				LM_ERR("No attribute for node\n");
				return -1;
			}
			attr.len = strlen(attr.s);
			if(attr.len==0){
				LM_ERR("No attribute for node\n");
				return -1;
			}
			if(shm_str_dup(ids, &attr)!=0) return -1;
			xmlFree(attr.s); attr.s = NULL; attr.len = 0;
			/* Retrieve the node value */
			val.s = (char*)xmlNodeGetContent(node);
			if(val.s==NULL){
				LM_ERR("No content for node\n");
				return -1;
			}
			val.len = strlen(val.s);
			if(val.len==0){
				LM_ERR("No content for node\n");
				return -1;
			}
			if(shm_str_dup(vals, &val)!=0) return -1;
			xmlFree(val.s); val.s = NULL; val.len = 0;
			/*
			LM_DBG(">  > [%d] [%p]->[%s] [%p]->[%s]\n",
					size, ids, ids->s, vals, vals->s);
			*/
			size++;
		}
	}
	if(size){
		cmd_col_vals->ids = col_ids;
		cmd_col_vals->vals = col_vals;
		cmd_col_vals->vals_size = size;
		/* */
		for(i=0;i<size;i++)
			LM_DBG(">>> [%d] [%p]->[%.*s] [%p]->[%.*s]\n", i,
				cmd_col_vals->ids[i].s,
				cmd_col_vals->ids[i].len, cmd_col_vals->ids[i].s,
				cmd_col_vals->vals[i].s,
				cmd_col_vals->vals[i].len, cmd_col_vals->vals[i].s);
		/* */
	}
	return 0;
}

int pi_getCols(pi_mod_t *module, pi_cmd_t *cmd,
		db_op_t **mod_cmd_ops, db_key_t **mod_cmd_keys,
		db_type_t **mod_cmd_types, pi_vals_t **mod_cmd_vals, str **mod_cmd_linkCmd,
		int *key_size, xmlNodePtr cmd_node)
{
	xmlNodePtr node;
	str *key;
	str field;
	db_key_t *keys;
	db_key_t *cmd_keys = NULL;
	int op_len;
	char *operator;
	char *_operator;
	db_op_t *ops;
	db_op_t *cmd_ops = NULL;
	db_type_t *types;
	db_type_t *cmd_types = NULL;
	pi_vals_t *vals;
	pi_vals_t *cmd_vals = NULL;
	str link_cmd;
	str *linkCmd;
	str *cmd_linkCmd = NULL;
	int i;
	int size = 0;
	int table_size;
	pi_table_col_t *table_cols;

	for(node=cmd_node->children;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_COL_NODE) == 0) {
			if(size)
				keys = (db_key_t*)shm_realloc(cmd_keys,
					(size+1)*sizeof(db_key_t));
			else
				keys = (db_key_t*)shm_malloc(sizeof(db_key_t));
			if (keys==NULL) {LM_ERR("oom\n");return -1;}
			cmd_keys = keys;
			keys = &cmd_keys[size];
			memset(keys, 0, sizeof(db_key_t));
			key = (str*)shm_malloc(sizeof(str));
			if (key==NULL) {LM_ERR("oom\n");return -1;}
			/* get the col field */
			field.s = pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_FIELD_NODE);
			if(field.s==NULL){
				LM_ERR("no %s in %s [%.*s] %s [%.*s] %s %s\n",
					PI_XML_FIELD_NODE,
					cmd_node->parent->parent->name,
					module->module.len, module->module.s,
					cmd_node->parent->name,
					cmd->name.len, cmd->name.s,
					cmd_node->name, node->name);
				return -1;
			}
			field.len = strlen(field.s);
			if(field.len==0){
				LM_ERR("empty %s in %s [%.*s] %s [%.*s] %s %s\n",
					PI_XML_FIELD_NODE,
					cmd_node->parent->parent->name,
					module->module.len, module->module.s,
					cmd_node->parent->name,
					cmd->name.len, cmd->name.s,
					cmd_node->name, node->name);
				return -1;
			}
			/* Each field must be valid */
			table_size = cmd->db_table->cols_size;
			table_cols = cmd->db_table->cols;
			for(i=0;i<table_size;i++){
				if(field.len==table_cols[i].field.len &&
					strncmp(table_cols[i].field.s,
						field.s,
						field.len)==0) break;
			}
			if(i==table_size){
				LM_ERR("invalid %s [%.*s] in %s [%.*s] %s [%.*s] %s %s"
					" for [%.*s]\n",
					PI_XML_FIELD_NODE,
					field.len, field.s,
					cmd_node->parent->parent->name,
					module->module.len, module->module.s,
					cmd_node->parent->name,
					cmd->name.len, cmd->name.s,
					cmd_node->name, node->name,
					cmd->db_table->name.len, cmd->db_table->name.s);
				return -1;
			}
			if(shm_str_dup(key, &field)) return -1;
			*keys = key;
			xmlFree(field.s); field.s = NULL; field.len = 0;
			LM_DBG("cmd_keys=[%p] keys=[%p]->[%p]->[%.*s]\n",
						cmd_keys, keys, *keys,
						(*keys)->len, (*keys)->s);
			/* Retrieve the type */
			if(mod_cmd_types){
				if(size)
					types = (db_type_t*)shm_realloc(cmd_types,
						(size+1)*sizeof(db_type_t));
				else
					types =
					(db_type_t*)shm_malloc(sizeof(db_type_t));
				if (types==NULL) {LM_ERR("oom\n");return -1;}
				cmd_types = types;
				types = &cmd_types[size];
				memset(types, 0, sizeof(db_type_t));
				*types = table_cols[i].type;
			}
			/* Retrieve the ops */
			if(mod_cmd_ops){
				if(size)
					ops = (db_op_t*)shm_realloc(cmd_ops,
						(size+1)*sizeof(db_op_t));
				else
					ops = (db_op_t*)shm_malloc(sizeof(db_op_t));
				if (ops==NULL) {LM_ERR("oom\n");return -1;}
				cmd_ops = ops;
				ops = &cmd_ops[size];
				memset(ops, 0, sizeof(db_op_t));
				/* Retrieve the col op */
				operator =
					pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_OPERATOR_NODE);
				if(operator==NULL){
					LM_ERR("no %s in %s [%.*s] %s [%.*s] %s %s\n",
						PI_XML_OPERATOR_NODE,
						cmd_node->parent->parent->name,
						module->module.len, module->module.s,
						cmd_node->parent->name,
						cmd->name.len, cmd->name.s,
						cmd_node->name, node->name);
					return -1;
				}
				op_len = strlen(operator);
				if(op_len==0){
					LM_ERR("empty %s in %s [%.*s] %s [%.*s] %s %s\n",
						PI_XML_OPERATOR_NODE,
						cmd_node->parent->parent->name,
						module->module.len, module->module.s,
						cmd_node->parent->name,
						cmd->name.len, cmd->name.s,
						cmd_node->name, node->name);
					return -1;
				}else if(op_len==1){
					if(strncmp(OP_LT,operator,1)==0)
						*ops = operator;
					else if(strncmp(OP_GT,operator,1)==0)
						*ops = operator;
					else if(strncmp(OP_EQ,operator,1)==0)
						*ops = operator;
				}else if(op_len==2){
					if(strncmp(OP_LEQ,operator,2)==0)
						*ops = operator;
					else if(strncmp(OP_GEQ,operator,2)==0)
						*ops = operator;
					else if(strncmp(OP_NEQ,operator,2)==0)
						*ops = operator;
				}
				if(*ops==NULL){
					LM_ERR("unexpected %s [%s] in "
						"%s [%.*s] %s [%.*s] %s %s\n",
						PI_XML_OPERATOR_NODE,
						operator,
						cmd_node->parent->parent->name,
						module->module.len, module->module.s,
						cmd_node->parent->name,
						cmd->name.len, cmd->name.s,
						cmd_node->name, node->name);
					return -1;
				}
				/* We need to copy the null string terminator */
				op_len++;
				_operator = shm_malloc(op_len);
				if(_operator==NULL){LM_ERR("oom\n"); return -1;}
				memcpy(_operator, operator, op_len);
				*ops = _operator;
				xmlFree(operator); operator = NULL; op_len = 0;
				LM_DBG("%s [%p]=>[%p]=>[%.*s] %s [%.*s] %s %s [%.*s][%s]\n",
					cmd_node->parent->parent->name, module,
					module->module.s,
					module->module.len, module->module.s,
					cmd_node->parent->name,
					cmd->name.len, cmd->name.s,
					cmd_node->name, node->name,
					(**keys).len, (**keys).s, *ops);
			}else{
				LM_DBG("%s [%p]=>[%p]=>[%.*s] %s [%.*s] %s %s [%.*s][]\n",
					cmd_node->parent->parent->name, module,
					module->module.s,
					module->module.len, module->module.s,
					cmd_node->parent->name,
					cmd->name.len, cmd->name.s,
					cmd_node->name, node->name,
					(**keys).len, (**keys).s);
			}
			/* Retrieve the vals */
			if(mod_cmd_vals){
				if(size)
					vals = (pi_vals_t*)shm_realloc(cmd_vals,
						(size+1)*sizeof(pi_vals_t));
				else
					vals =
					(pi_vals_t*)shm_malloc(sizeof(pi_vals_t));
				if(vals==NULL) {LM_ERR("oom\n");return -1;}
				cmd_vals = vals;
				vals = &cmd_vals[size];
				memset(vals, 0, sizeof(pi_vals_t));
				if(pi_getColVals(module, cmd, vals, node)!=0)
					return -1;
			}
			/* Retrieve the link_cmds */
			if(mod_cmd_linkCmd){
				if(size)
					linkCmd = (str*)shm_realloc(cmd_linkCmd,
						(size+1)*sizeof(str));
				else
					linkCmd = (str*)shm_malloc(sizeof(str));
				if(linkCmd==NULL) {LM_ERR("oom\n");return -1;}
				cmd_linkCmd = linkCmd;
				linkCmd = &cmd_linkCmd[size];
				memset(linkCmd, 0, sizeof(str));
				/* get the link_cmd */
				link_cmd.s = pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_LINK_CMD_NODE);
				if(link_cmd.s!=NULL){
					link_cmd.len = strlen(link_cmd.s);
					if(link_cmd.len!=0){
						LM_DBG("got %s=[%.*s] in %s [%.*s] %s [%.*s] %s %s\n",
							PI_XML_LINK_CMD_NODE,
							link_cmd.len, link_cmd.s,
							cmd_node->parent->parent->name,
							module->module.len, module->module.s,
							cmd_node->parent->name,
							cmd->name.len, cmd->name.s,
							cmd_node->name, node->name);
						if(shm_str_dup(linkCmd, &link_cmd)) return -1;
					}
					xmlFree(link_cmd.s); link_cmd.s = NULL; link_cmd.len = 0;
				}
			}
			size++;
		}
	}
	if(size==0){
		LM_ERR("empty %s in %s [%.*s] %s [%.*s]\n",
			cmd_node->name, cmd_node->parent->parent->name,
			module->module.len, module->module.s,
			cmd_node->parent->name, cmd->name.len, cmd->name.s);
		return -1;
	}else if(cmd_keys!=NULL){
		*mod_cmd_keys = cmd_keys;
		LM_DBG("***  mod_cmd_keys=[%p] *mod_cmd_keys=[%p] cmd_keys=[%p]\n",
				mod_cmd_keys, *mod_cmd_keys, cmd_keys);
		if(cmd_keys) for(i=0;i<size;i++)
			LM_DBG("cmd_keys[%d]=[%p]->[%p]->[%.*s]\n",
				i, &cmd_keys[i], cmd_keys[i]->s,
				cmd_keys[i]->len, cmd_keys[i]->s);
		if(mod_cmd_ops) *mod_cmd_ops = cmd_ops;
		if(mod_cmd_types) *mod_cmd_types = cmd_types;
		if(mod_cmd_vals&&cmd_vals) *mod_cmd_vals = cmd_vals;
		if(mod_cmd_linkCmd) *mod_cmd_linkCmd = cmd_linkCmd;
		if(cmd_vals) for(i=0;i<size;i++){
			LM_DBG("cmd_vals[%d]=[%p]->[%d][%p][%p]\n",
				i, &cmd_vals[i], cmd_vals[i].vals_size,
				cmd_vals[i].ids, cmd_vals[i].vals);
			for(op_len=0;op_len<cmd_vals[i].vals_size;op_len++)
				LM_DBG("    [%d][%d] [%p]->[%.*s] [%p]->[%.*s]\n",
					i, op_len,
					&cmd_vals[i].ids[op_len],
					cmd_vals[i].ids[op_len].len,
					cmd_vals[i].ids[op_len].s,
					&cmd_vals[i].vals[op_len],
					cmd_vals[i].vals[op_len].len,
					cmd_vals[i].vals[op_len].s);
		}
		if(mod_cmd_linkCmd&&cmd_linkCmd) *mod_cmd_linkCmd = cmd_linkCmd;
		*key_size = size;
		if(cmd_ops) for(i=0;i<size;i++)
			LM_DBG("cmd_ops[%d]=[%p]->[%s]\n",
				i, &cmd_ops[i], cmd_ops[i]);
		LM_DBG("\n");
	}
	return 0;
}

int pi_getCmds(pi_db_table_t *pi_db_tables, int pi_db_tables_size,
		pi_mod_t *modules, xmlNodePtr mod_node)
{
	int i;
	int j;
	char *val;
	int val_len;
	pi_cmd_t *cmds;
	xmlNodePtr node, cmd_cols;
	str name;

	for(node=mod_node->children,modules->cmds_size=0;node;node=node->next){
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)PI_XML_CMD_NODE) == 0) {
			if(modules->cmds_size)
				cmds = (pi_cmd_t*)shm_realloc(modules->cmds,
					(modules->cmds_size+1)*sizeof(pi_cmd_t));
			else
				cmds = (pi_cmd_t*)shm_malloc(sizeof(pi_cmd_t));;
			if (cmds==NULL) {LM_ERR("oom\n");return -1;}
			modules->cmds = cmds;
			cmds = &modules->cmds[modules->cmds_size];
			memset(cmds, 0, sizeof(pi_cmd_t));
			cmds->type = -1;
			/* Populate the cmd name */
			name.s =
				pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_CMD_NAME_NODE);
			if(name.s==NULL){
				LM_ERR("no %s for %s [%.*s]\n",
					PI_XML_CMD_NAME_NODE,
					mod_node->name,
					modules->module.len, modules->module.s);
				return -1;
			}
			name.len = strlen(name.s);
			if(name.len==0){
				LM_ERR("empty %s for %s [%.*s]\n",
					PI_XML_CMD_NAME_NODE,
					mod_node->name,
					modules->module.len, modules->module.s);
				return -1;
			}
			if(shm_str_dup(&cmds->name, &name)!=0) return -1;
			xmlFree(name.s);name.s=NULL;name.len=0;
			/* Each cmd name MUST be unique */
			for(i=0;i<modules->cmds_size;i++){
				if(cmds->name.len==modules->cmds[i].name.len &&
                                        strncmp(modules->cmds[i].name.s,
                                                cmds->name.s,
						cmds->name.len)==0){
					LM_ERR("duplicated %s %s %s [%.*s]\n",
						mod_node->name, modules->module.s,
						node->name,
						cmds->name.len, cmds->name.s);
					return -1;
				}
			}
			/* Populate the db_table_index */
			val = pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_DB_TABLE_ID_NODE);
			if(val==NULL){
				LM_ERR("no %s for %s [%.*s] %s [%.*s]\n",
					PI_XML_DB_TABLE_ID_NODE,
					mod_node->name,
					modules->module.len, modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				return -1;
			}
			val_len = strlen(val);
			if(val_len==0){
				LM_ERR("empty %s for %s [%.*s] %s [%.*s]\n",
					PI_XML_DB_URL_ID_NODE,
					mod_node->name,
					modules->module.len, modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				xmlFree(val);
				return -1;
			}
			/* Get db_table */
			for(i=0;i<pi_db_tables_size;i++){
				if(val_len==pi_db_tables[i].id.len &&
					strncmp(pi_db_tables[i].id.s,
						val, val_len)==0){
					cmds->db_table = &pi_db_tables[i];
					break;
				}
			}
			if (i==pi_db_tables_size){
				LM_ERR("bogus %s [%s] for %s [%.*s] %s [%.*s]\n",
					PI_XML_DB_TABLE_ID_NODE, val,
					mod_node->name,
					modules->module.len, modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				xmlFree(val);
				return -1;
			}
			xmlFree(val);
			/* Get cmd_type */
			val = pi_xmlNodeGetNodeContentByName(node->children,
						PI_XML_CMD_TYPE_NODE);
			if(val==NULL){
				LM_ERR("no %s for %s [%.*s] %s [%.*s]\n",
					PI_XML_CMD_TYPE_NODE,
					mod_node->name,
					modules->module.len, modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				return -1;
			}
			val_len = strlen(val);
			if(val_len==0){
				LM_ERR("empty %s for %s [%.*s] %s [%.*s]\n",
					PI_XML_CMD_TYPE_NODE,
					mod_node->name,
					modules->module.len, modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				xmlFree(val);
				return -1;
			}else if(val_len==8){
				if(strncmp("DB_QUERY",val,8)==0){
					cmds->type = DB_CAP_QUERY;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_CLAUSE_COLS_NODE);
					if(cmd_cols!=NULL)
						if (pi_getCols( modules,
								cmds,
								&cmds->c_ops,
								&cmds->c_keys,
								&cmds->c_types,
								&cmds->c_vals,
								NULL,
								&cmds->c_keys_size,
								cmd_cols)!=0)
							return -1;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_QUERY_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								NULL,
								&cmds->q_keys,
								&cmds->q_types,
								NULL,
								&cmds->link_cmd,
								&cmds->q_keys_size,
								cmd_cols)!=0)
							return -1;
					}else{
						LM_ERR("no %s in %s [%.*s] %s [%.*s]\n",
							PI_XML_QUERY_COLS_NODE,
							mod_node->name,
							modules->module.len,
							modules->module.s,
							node->name,
							cmds->name.len,
							cmds->name.s);
						return -1;
					}
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_ORDER_BY_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								NULL,
								&cmds->o_keys,
								NULL,
								NULL,
								NULL,
								&cmds->o_keys_size,
								cmd_cols)!=0)
							return -1;
					}
				}
			}else if(val_len==9){
				if(strncmp("DB_INSERT",val,9)==0){
					cmds->type = DB_CAP_INSERT;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_QUERY_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								NULL,
								&cmds->q_keys,
								&cmds->q_types,
								&cmds->q_vals,
								NULL,
								&cmds->q_keys_size,
								cmd_cols)!=0)
							return -1;
					}else{
						LM_ERR("no %s in %s [%.*s] %s [%.*s]\n",
							PI_XML_QUERY_COLS_NODE,
							mod_node->name,
							modules->module.len,
							modules->module.s,
							node->name,
							cmds->name.len,
							cmds->name.s);
						return -1;
					}
				}else if(strncmp("DB_DELETE",val,9)==0){
					cmds->type = DB_CAP_DELETE;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_CLAUSE_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								&cmds->c_ops,
								&cmds->c_keys,
								&cmds->c_types,
								&cmds->c_vals,
								NULL,
								&cmds->c_keys_size,
								cmd_cols)!=0)
							return -1;
					}else{
						LM_ERR("no %s in %s [%.*s] %s [%.*s]\n",
							PI_XML_CLAUSE_COLS_NODE,
							mod_node->name,
							modules->module.len,
							modules->module.s,
							node->name,
							cmds->name.len,
							cmds->name.s);
						return -1;
					}

				}else if(strncmp("DB_UPDATE",val,9)==0){
					cmds->type = DB_CAP_UPDATE;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_CLAUSE_COLS_NODE);
					if(cmd_cols!=NULL)
						if (pi_getCols( modules,
								cmds,
								&cmds->c_ops,
								&cmds->c_keys,
								&cmds->c_types,
								&cmds->c_vals,
								NULL,
								&cmds->c_keys_size,
								cmd_cols)!=0)
							return -1;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_QUERY_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								NULL,
								&cmds->q_keys,
								&cmds->q_types,
								&cmds->q_vals,
								NULL,
								&cmds->q_keys_size,
								cmd_cols)!=0)
							return -1;
					}else{
						LM_ERR("no %s in %s [%.*s] %s [%.*s]\n",
							PI_XML_QUERY_COLS_NODE,
							mod_node->name,
							modules->module.len,
							modules->module.s,
							node->name,
							cmds->name.len,
							cmds->name.s);
						return -1;
					}
				}
			}else if(val_len==10){
				if(strncmp("DB_REPLACE",val,10)==0){
					cmds->type = DB_CAP_REPLACE;
					cmd_cols =
					pi_xmlNodeGetNodeByName(node->children,
						PI_XML_QUERY_COLS_NODE);
					if(cmd_cols!=NULL){
						if (pi_getCols( modules,
								cmds,
								NULL,
								&cmds->q_keys,
								&cmds->q_types,
								&cmds->q_vals,
								NULL,
								&cmds->q_keys_size,
								cmd_cols)!=0)
							return -1;
					}else{
						LM_ERR("no %s in %s [%.*s] %s [%.*s]\n",
							PI_XML_QUERY_COLS_NODE,
							mod_node->name,
							modules->module.len,
							modules->module.s,
							node->name,
							cmds->name.len,
							cmds->name.s);
						return -1;
					}
				}
			}
			if(cmds->type==-1){
				LM_ERR("unexpected type [%s] for %s [%.*s] %s [%.*s]\n",
					val, mod_node->name,
					modules->module.len,
					modules->module.s,
					PI_XML_CMD_NODE,
					cmds->name.len, cmds->name.s);
				xmlFree(val);
				return -1;
			}
			xmlFree(val);
			/**/
			LM_DBG("got node %s %s %s [%.*s] [%p]=>[%.*s]\n",
					mod_node->name, node->name,
					PI_XML_CMD_NAME_NODE,
					cmds->name.len, cmds->name.s,
					cmds->db_table->name.s,
					cmds->db_table->name.len,
					cmds->db_table->name.s);
			if(cmds->c_keys)
				for(i=0;i<cmds->c_keys_size;i++){
					LM_DBG("    [%d] c_keys=[%.*s] "
						"c_ops=[%s] c_types=[%d]\n",
						i, (*(cmds->c_keys[i])).len,
						(*(cmds->c_keys[i])).s,
						cmds->c_ops[i], cmds->c_types[i]);
					if(cmds->c_vals)
						for(j=0;j<cmds->c_vals->vals_size;j++)
							LM_DBG("      c_vals[%d] "
							"id=[%.*s] val=[%.*s]\n",
							j,
							cmds->c_vals->ids->len,
							cmds->c_vals->ids->s,
							cmds->c_vals->vals->len,
							cmds->c_vals->vals->s);
				}
			if(cmds->q_keys)
				for(i=0;i<cmds->q_keys_size;i++){
					LM_DBG("    [%d] q_keys=[%.*s] "
						"q_types=[%d] link_cmd=[%.*s]\n",
						i, (*(cmds->q_keys[i])).len,
						(*(cmds->q_keys[i])).s,
						cmds->q_types[i],
						(cmds->link_cmd)?(cmds->link_cmd[i]).len:0,
						(cmds->link_cmd)?(cmds->link_cmd[i]).s:NULL);
					if(cmds->q_vals)
						for(j=0;j<cmds->q_vals->vals_size;j++)
							LM_DBG("      c_vals[%d] "
							"id=[%.*s] val=[%.*s]\n",
							j,
							cmds->q_vals->ids->len,
							cmds->q_vals->ids->s,
							cmds->q_vals->vals->len,
							cmds->q_vals->vals->s);
				}
			if(cmds->o_keys)
				for(i=0;i<cmds->o_keys_size;i++)
					LM_DBG("    o_keys[%d]=[%.*s]\n",
						i, (*(cmds->o_keys[i])).len,
						(*(cmds->o_keys[i])).s);
			/**/
			modules->cmds_size++;
		}
	}
	return 0;
}

int pi_getMods(pi_framework_t *_pi_framework_data, xmlNodePtr framework_node)
{
	int i;
	pi_mod_t *modules;
	xmlNodePtr mod_node;
	pi_mod_t *pi_modules;
	str module;

	/* Build pi commands skeleton */
	for(mod_node=framework_node->children,_pi_framework_data->pi_modules_size=0;
					mod_node;mod_node=mod_node->next){
		if (xmlStrcasecmp(mod_node->name,
			(const xmlChar*)PI_XML_MOD_NODE) == 0) {
			if(_pi_framework_data->pi_modules_size)
				modules = (pi_mod_t*)shm_realloc(_pi_framework_data->pi_modules,
					(_pi_framework_data->pi_modules_size+1)*
					sizeof(pi_mod_t));
			else
				modules = (pi_mod_t*)shm_malloc(sizeof(pi_mod_t));
			if(modules==NULL){
				LM_ERR("oom\n");
				return -1;
			}
			_pi_framework_data->pi_modules = modules;
			pi_modules = _pi_framework_data->pi_modules;
			modules = &pi_modules[_pi_framework_data->pi_modules_size];
			memset(modules, 0, sizeof(pi_mod_t));

			/* Populate module name */
			module.s =
				pi_xmlNodeGetNodeContentByName(mod_node->children,
							PI_XML_MOD_NAME_NODE);
			if(module.s==NULL){
				LM_ERR("no %s for node %s\n",
					PI_XML_MOD_NAME_NODE,
					PI_XML_MOD_NODE);
				return -1;
			}
			module.len = strlen(module.s);
			if(module.len==0){
				LM_ERR("empty %s for node %s\n",
					PI_XML_MOD_NAME_NODE,
					PI_XML_MOD_NODE);
				return -1;
			}
			if(shm_str_dup(&modules->module, &module)!=0) return -1;
			xmlFree(module.s);module.s=NULL;module.len=0;
			/* Each mod name MUST be unique */
			for(i=0;i<_pi_framework_data->pi_modules_size;i++){
				if(modules->module.len==pi_modules[i].module.len &&
                                        strncmp(pi_modules[i].module.s,
                                                modules->module.s,
						modules->module.len)==0){
					LM_ERR("duplicated %s [%.*s]\n",
						mod_node->name,
						modules->module.len,
						modules->module.s);
					return -1;
				}
			}
			/* Get cmds */
			if(pi_getCmds(_pi_framework_data->pi_db_tables,
					_pi_framework_data->pi_db_tables_size,
					modules, mod_node)!=0)
				return -1;
			_pi_framework_data->pi_modules_size++;
			LM_DBG("got node %s [%.*s]\n",
				mod_node->name,
				modules->module.len, modules->module.s);
		}
	}
	if(_pi_framework_data->pi_modules_size==0){
		LM_ERR("no %s node in config file\n", PI_XML_MOD_NODE);
		return -1;
	}
	return 0;
}


void pi_freeDbUrlNodes(pi_db_url_t **pi_db_urls, int pi_db_urls_size)
{
	int i;
	pi_db_url_t *_pi_db_urls = *pi_db_urls;

	if(_pi_db_urls==NULL) return;
	for(i=0;i<pi_db_urls_size;i++){
		shm_free(_pi_db_urls[i].id.s);
		_pi_db_urls[i].id.s = NULL;
		shm_free(_pi_db_urls[i].db_url.s);
		_pi_db_urls[i].db_url.s = NULL;
	}
	shm_free(*pi_db_urls); *pi_db_urls = NULL;
	return;
}
void pi_freeDbTables(pi_db_table_t **pi_db_tables, int pi_db_tables_size)
{
	int i, j;
	pi_db_table_t *_pi_db_tables = *pi_db_tables;

	if(_pi_db_tables==NULL) return;
	for(i=0;i<pi_db_tables_size;i++){
		shm_free(_pi_db_tables[i].id.s);
		_pi_db_tables[i].id.s = NULL;
		shm_free(_pi_db_tables[i].name.s);
		_pi_db_tables[i].name.s = NULL;
		shm_free(_pi_db_tables[i].db_url_id.s);
		_pi_db_tables[i].db_url_id.s = NULL;
		for(j=0;j<_pi_db_tables[i].cols_size;j++){
			shm_free(_pi_db_tables[i].cols[j].field.s);
			_pi_db_tables[i].cols[j].field.s = NULL;
		}
		shm_free(_pi_db_tables[i].cols);
		_pi_db_tables[i].cols = NULL;
	}
	shm_free(*pi_db_tables); *pi_db_tables = NULL;
	return;
}
void pi_freeMods(pi_mod_t **pi_modules, int pi_modules_size)
{
	int i, j, k;
	pi_mod_t *_pi_modules = *pi_modules;
	db_key_t *cmd_keys;
	db_op_t *cmd_ops;
	pi_vals_t *cmd_vals;
	str *cmd_linkCmd;

	if(_pi_modules==NULL) return;
	for(i=0;i<pi_modules_size;i++){
		if(_pi_modules[i].module.s){
			shm_free(_pi_modules[i].module.s);
			_pi_modules[i].module.s = NULL;
		}
		for(j=0;j<_pi_modules[i].cmds_size;j++){
			if(_pi_modules[i].cmds[j].name.s){
				shm_free(_pi_modules[i].cmds[j].name.s);
				_pi_modules[i].cmds[j].name.s = NULL;
			}
			/* */
			cmd_keys = _pi_modules[i].cmds[j].c_keys;
			cmd_ops = _pi_modules[i].cmds[j].c_ops;
			cmd_vals = _pi_modules[i].cmds[j].c_vals;
			for(k=0;k<_pi_modules[i].cmds[j].c_keys_size;k++){
				if(cmd_ops && cmd_ops[k]){
					shm_free((char*)cmd_ops[k]);
					cmd_ops[k] = NULL;
				}
				if(cmd_keys && cmd_keys[k]){
					if(cmd_keys[k]->s){
						shm_free(cmd_keys[k]->s);
						cmd_keys[k]->s = NULL;
					}
					shm_free(cmd_keys[k]);
					cmd_keys[k] = NULL;
				}
				if(cmd_vals){
					if(cmd_vals[k].ids){
						if(cmd_vals[k].ids->s){
							shm_free(cmd_vals[k].ids->s);
							cmd_vals[k].ids->s = NULL;
						}
						shm_free(cmd_vals[k].ids);
						cmd_vals[k].ids = NULL;
					}
					if(cmd_vals[k].vals){
						if(cmd_vals[k].vals->s){
							shm_free(cmd_vals[k].vals->s);
							cmd_vals[k].vals->s = NULL;
						}
						shm_free(cmd_vals[k].vals);
						cmd_vals[k].vals = NULL;
					}
				}
			}
			if(_pi_modules[i].cmds[j].c_keys){
				shm_free(_pi_modules[i].cmds[j].c_keys);
				_pi_modules[i].cmds[j].c_keys = NULL;
			}
			if(_pi_modules[i].cmds[j].c_ops){
				shm_free(_pi_modules[i].cmds[j].c_ops);
				_pi_modules[i].cmds[j].c_ops = NULL;
			}
			if(_pi_modules[i].cmds[j].c_types){
				shm_free(_pi_modules[i].cmds[j].c_types);
				_pi_modules[i].cmds[j].c_types = NULL;
			}
			if(_pi_modules[i].cmds[j].c_vals){
				shm_free(_pi_modules[i].cmds[j].c_vals);
				_pi_modules[i].cmds[j].c_vals = NULL;
			}
			/* */
			cmd_keys = _pi_modules[i].cmds[j].q_keys;
			cmd_vals = _pi_modules[i].cmds[j].q_vals;
			cmd_linkCmd = _pi_modules[i].cmds[j].link_cmd;
			for(k=0;k<_pi_modules[i].cmds[j].q_keys_size;k++){
				if(cmd_keys && cmd_keys[k]){
					if(cmd_keys[k]->s){
						shm_free(cmd_keys[k]->s);
						cmd_keys[k]->s = NULL;
					}
					shm_free(cmd_keys[k]);
					cmd_keys[k] = NULL;
				}
				if(cmd_vals){
					if(cmd_vals[k].ids){
						if(cmd_vals[k].ids->s){
							shm_free(cmd_vals[k].ids->s);
							cmd_vals[k].ids->s = NULL;
						}
						shm_free(cmd_vals[k].ids);
						cmd_vals[k].ids = NULL;
					}
					if(cmd_vals[k].vals){
						if(cmd_vals[k].vals->s){
							shm_free(cmd_vals[k].vals->s);
							cmd_vals[k].vals->s = NULL;
						}
						shm_free(cmd_vals[k].vals);
						cmd_vals[k].vals = NULL;
					}
				}
				if(cmd_linkCmd && cmd_linkCmd[k].s){
					shm_free(cmd_linkCmd[k].s);
					cmd_linkCmd[k].s = NULL;
				}
			}
			if(_pi_modules[i].cmds[j].q_keys){
				shm_free(_pi_modules[i].cmds[j].q_keys);
				_pi_modules[i].cmds[j].q_keys = NULL;
			}
			if(_pi_modules[i].cmds[j].q_types){
				shm_free(_pi_modules[i].cmds[j].q_types);
				_pi_modules[i].cmds[j].q_types = NULL;
			}
			if(_pi_modules[i].cmds[j].q_vals){
				shm_free(_pi_modules[i].cmds[j].q_vals);
				_pi_modules[i].cmds[j].q_vals = NULL;
			}
			if(_pi_modules[i].cmds[j].link_cmd){
				shm_free(_pi_modules[i].cmds[j].link_cmd);
				_pi_modules[i].cmds[j].link_cmd = NULL;
			}
			cmd_keys = NULL; cmd_vals = NULL;
			/* */
			cmd_keys = _pi_modules[i].cmds[j].c_keys;
			for(k=0;k<_pi_modules[i].cmds[j].c_keys_size;k++){
				if(cmd_keys && cmd_keys[k]){
					if(cmd_keys[k]->s){
						shm_free(cmd_keys[k]->s);
						cmd_keys[k]->s = NULL;
					}
					shm_free(cmd_keys[k]);
					cmd_keys[k] = NULL;
				}
			}
			if(_pi_modules[i].cmds[j].c_keys){
				shm_free(_pi_modules[i].cmds[j].c_keys);
				_pi_modules[i].cmds[j].c_keys = NULL;
			}
			cmd_keys = NULL;
		}
		if(_pi_modules[i].cmds){
			shm_free(_pi_modules[i].cmds);
			_pi_modules[i].cmds = NULL;
		}
	}
	if(*pi_modules){
		shm_free(*pi_modules); *pi_modules = NULL;
	}
	return;
}

int pi_init_cmds(pi_framework_t **framework_data, const char* filename)
{
	xmlDocPtr doc;
	xmlNodePtr framework_node;
	pi_framework_t *_framework_data = NULL;
	pi_db_table_t *_pi_db_tables;
	int _pi_db_tables_size;
	pi_mod_t *_pi_modules;
	int _pi_modules_size;

	if(filename==NULL) {LM_ERR("NULL filename\n");return -1;}
	doc = xmlParseFile(filename);
	if(doc==NULL){
		LM_ERR("Failed to parse xml file: %s\n", filename);
		return -1;
	}

	/* Extract the framework node */
	framework_node = pi_xmlNodeGetNodeByName(doc->children,
						PI_XML_FRAMEWORK_NODE);
	if (framework_node==NULL) {
		LM_ERR("missing node %s\n", PI_XML_FRAMEWORK_NODE);
		goto xml_error;
	}

	_framework_data = *framework_data;
	if(_framework_data==NULL){
		_framework_data =
		(pi_framework_t*)shm_malloc(sizeof(pi_framework_t));
		if(_framework_data==NULL) {LM_ERR("oom\n");goto xml_error;}
		memset(_framework_data, 0, sizeof(pi_framework_t));

		/* Extract the db_url nodes */
		if(pi_getDbUrlNodes(_framework_data, framework_node)!=0)
			goto xml_error;

		/* Extract the db_url nodes */
		if(pi_getDbTables(_framework_data, framework_node)!=0)
			goto xml_error;

		/* Build pi commands skeleton */
		if(pi_getMods(_framework_data, framework_node)!=0)
			goto xml_error;

		if(doc)xmlFree(doc);
		doc=NULL;
		*framework_data = _framework_data;
	}else{ /* This is a reload */
		_pi_db_tables = _framework_data->pi_db_tables;
		_pi_db_tables_size = _framework_data->pi_db_tables_size;
		_framework_data->pi_db_tables = NULL;
		_framework_data->pi_db_tables_size = 0;
		_pi_modules = _framework_data->pi_modules;
		_pi_modules_size = _framework_data->pi_modules_size;
		_framework_data->pi_modules = NULL;
		_framework_data->pi_modules_size = 0;

		/* Extract the db_url nodes */
		if(pi_getDbTables(_framework_data, framework_node)!=0)
			goto xml_reload_error;

		/* Build pi commands skeleton */
		if(pi_getMods(_framework_data, framework_node)!=0)
			goto xml_reload_error;

		if(doc)xmlFree(doc);
		doc=NULL;
		*framework_data = _framework_data;

	}
	return 0;
xml_error:
	/* FIXME: free thw whole structure */
	if(_framework_data){shm_free(_framework_data);}
	if(doc)xmlFree(doc);
	doc=NULL;
	return -1;
xml_reload_error:
	pi_freeDbTables(&_framework_data->pi_db_tables,
			_framework_data->pi_db_tables_size);
	pi_freeMods(&_framework_data->pi_modules,
			_framework_data->pi_modules_size);
	_framework_data->pi_db_tables = _pi_db_tables;
	_framework_data->pi_db_tables_size = _pi_db_tables_size;
	_framework_data->pi_modules = _pi_modules;
	_framework_data->pi_modules_size = _pi_modules_size;
	if(doc)xmlFree(doc);
	doc=NULL;
	return -1;
}

int pi_framework_init(void)
{
	if (!pi_framework.s)
		return 0;
	return pi_init_cmds(&pi_framework_data, pi_framework.s);
}

static pi_db_url_t *pi_find_db_url(pi_framework_t *framework,
		const str *url)
{
	int i;
	for (i = 0; i < framework->pi_db_urls_size; i++)
		if (framework->pi_db_urls[i].db_url.len == url->len &&
			!memcmp(framework->pi_db_urls[i].db_url.s, url->s, url->len))
			return &framework->pi_db_urls[i];
	return NULL;
}

static pi_db_url_t *pi_add_module_db_url(pi_framework_t *framework,
		const str *module, const str *url)
{
	pi_db_url_t *urls, *db_url;
	str id;
	char *id_buf;

	db_url = pi_find_db_url(framework, url);
	if (db_url)
		return db_url;
	urls = shm_realloc(framework->pi_db_urls,
			(framework->pi_db_urls_size + 1) * sizeof(*urls));
	if (!urls)
		return NULL;
	framework->pi_db_urls = urls;
	db_url = &urls[framework->pi_db_urls_size];
	memset(db_url, 0, sizeof(*db_url));
	id_buf = shm_malloc(module->len + 8);
	if (!id_buf)
		return NULL;
	memcpy(id_buf, "module:", 7);
	memcpy(id_buf + 7, module->s, module->len);
	id_buf[module->len + 7] = '\0';
	id.s = id_buf;
	id.len = module->len + 7;
	if (shm_str_dup(&db_url->id, &id) != 0 ||
		shm_str_dup(&db_url->db_url, url) != 0) {
		shm_free(id_buf);
		return NULL;
	}
	shm_free(id_buf);
	framework->pi_db_urls_size++;
	return db_url;
}

static pi_db_url_t *pi_find_db_url_id(pi_framework_t *framework,
		const str *id)
{
	int i;
	for (i = 0; i < framework->pi_db_urls_size; i++)
		if (framework->pi_db_urls[i].id.len == id->len &&
			!memcmp(framework->pi_db_urls[i].id.s, id->s, id->len))
			return &framework->pi_db_urls[i];
	return NULL;
}

static int pi_resolve_connectors(pi_framework_t *framework)
{
	pi_db_url_t *module_url, *table_url;
	pi_mod_t *module;
	pi_cmd_t *command;
	str module_url_str;
	char **module_db_url;
	int i, j;

	for (i = 0; i < framework->pi_modules_size; i++) {
		module = &framework->pi_modules[i];
		module_url = NULL;
		module_db_url = find_param_export(module->module.s, "db_url",
				STR_PARAM);
		if (module_db_url && *module_db_url && **module_db_url) {
			module_url_str.s = *module_db_url;
			module_url_str.len = strlen(*module_db_url);
			module_url = pi_add_module_db_url(framework, &module->module,
					&module_url_str);
		} else if (db_default_url) {
			module_url_str.s = db_default_url;
			module_url_str.len = strlen(db_default_url);
			module_url = pi_add_module_db_url(framework, &module->module,
					&module_url_str);
		}

		for (j = 0; j < module->cmds_size; j++) {
			command = &module->cmds[j];
			if (command->db_table->db_url_id.len)
				table_url = pi_find_db_url_id(framework,
						&command->db_table->db_url_id);
			else
				table_url = module_url;
			if (!table_url) {
				LM_ERR("no database connector for module [%.*s], table [%.*s]; "
					"set db_url_id in the PI XML or configure the module db_url\n",
					module->module.len, module->module.s,
					command->db_table->id.len, command->db_table->id.s);
				return -1;
			}
			if (command->db_table->db_url &&
				command->db_table->db_url != table_url) {
				LM_ERR("table [%.*s] is used with multiple database connectors; "
					"set an explicit db_url_id in the PI XML\n",
					command->db_table->id.len, command->db_table->id.s);
				return -1;
			}
			command->db_table->db_url = table_url;
		}
	}
	return 0;
}

int pi_framework_init_db(void)
{
	int i;
	if (!pi_framework_data)
		return 0;
	if (pi_resolve_connectors(pi_framework_data) < 0)
		return -1;
	for (i = 0; i < pi_framework_data->pi_db_urls_size; i++) {
		pi_framework_data->pi_db_urls[i].db_handle =
				pkg_malloc(sizeof(db_con_t *));
		if (!pi_framework_data->pi_db_urls[i].db_handle)
			return -1;
		*pi_framework_data->pi_db_urls[i].db_handle = NULL;
		if (pi_init_db(pi_framework_data, i) < 0)
			return -1;
	}
	return 0;
}

int pi_framework_child_init(void)
{
	int i;
	if (!pi_framework_data)
		return 0;
	for (i = 0; i < pi_framework_data->pi_db_urls_size; i++)
		if (pi_connect_db(pi_framework_data, i) < 0)
			return -1;
	return 0;
}

void pi_framework_destroy_db(void)
{
	int i;
	if (!pi_framework_data)
		return;
	for (i = 0; i < pi_framework_data->pi_db_urls_size; i++) {
		if (!pi_framework_data->pi_db_urls[i].db_handle)
			continue;
		if (*pi_framework_data->pi_db_urls[i].db_handle)
			pi_framework_data->pi_db_urls[i].dbf.close(
					*pi_framework_data->pi_db_urls[i].db_handle);
		pkg_free(pi_framework_data->pi_db_urls[i].db_handle);
		pi_framework_data->pi_db_urls[i].db_handle = NULL;
	}
}



int pi_parse_url(const char* url, int* mod, int* cmd)
{
	int url_len = strlen(url);
	int index = 0;
	int i;
	int mod_len, cmd_len;
	pi_mod_t *pi_modules = pi_framework_data->pi_modules;


	if (url_len<0) {
		LM_ERR("Invalid url length [%d]\n", url_len);
		return -1;
	}
	if (url_len==0) return 0;
	if (url[0] != '/') {
		LM_ERR("URL starting with [%c] instead of'/'\n", *url);
		return -1;
	}
	index++;

	/* Looking for "mod" */
	if (index>=url_len)
		return 0;
	for(i=index;i<url_len && url[i]!='/';i++);
	mod_len = i - index;
	for(i=0;i<pi_framework_data->pi_modules_size &&
		(mod_len!=pi_modules[i].module.len ||
		strncmp(&url[index], pi_modules[i].module.s,mod_len)!=0);i++);
	if (i==pi_framework_data->pi_modules_size) {
		LM_ERR("Invalid mod [%.*s] in url [%s]\n",
			mod_len, &url[index], url);
		return -1;
	}
	*mod = i;
	LM_DBG("got mod [%d][%.*s]\n", *mod, mod_len, &url[index]);

	index += mod_len;
	LM_DBG("index=%d url_len=%d\n", index, url_len);
	if (index>=url_len)
		return 0;

	/* skip over '/' */
	index++;

	/* Looking for "cmd" */
	if (index>=url_len)
		return 0;
	for(i=index;i<url_len && url[i]!='/';i++);
	cmd_len = i - index;
	for(i=0;i<pi_modules[*mod].cmds_size &&
		(cmd_len!=pi_modules[*mod].cmds[i].name.len ||
		strncmp(&url[index], pi_modules[*mod].cmds[i].name.s, cmd_len)!=0);
		i++);
	if (i==pi_modules[*mod].cmds_size) {
		LM_ERR("Invalid cmd [%.*s] in url [%s]\n",
			cmd_len, &url[index], url);
		return -1;
	}
	*cmd = i;
	LM_DBG("got cmd [%d][%.*s]\n", *cmd, cmd_len, &url[index]);
	index += cmd_len;
	if (index>=url_len)
		return 0;
	/* skip over '/' */
	index++;
	if (url_len - index>0) {
		LM_DBG("got extra [%s]\n", &url[index]);
	}

	return 0;
}
