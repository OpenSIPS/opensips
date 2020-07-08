/*
 * check_address related functions
 *
 * Copyright (C) 2003 Juha Heinanen
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System
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

#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../../config.h"
#include "../../db/db.h"
#include "../../ip_addr.h"
#include "../../socket_info.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_from.h"
#include "../../mod_fix.h"
#include "../../resolve.h"

#include "permissions.h"
#include "hash.h"
#include "address.h"
#include "partitions.h"

#define TABLE_VERSION 5

str def_part = str_init("default");

/* table & column names */
str db_url;
str address_table = str_init("address");   /* Name of address table */
str ip_col = str_init("ip");               /* Name of ip column */
str proto_col = str_init("proto");         /* Name of protocol column */
str pattern_col = str_init("pattern");     /* Name of pattern column */
str info_col = str_init("context_info");   /* Name of context info column */
str grp_col = str_init("grp");             /* Name of address group column */
str mask_col = str_init("mask");           /* Name of mask column */
str port_col = str_init("port");           /* Name of port column */
str id_col = str_init("id");               /* Name of id column */

int init_address_part(struct pm_partition*);


int proto_char2int(str *proto) {
	int ret_proto;
	if (proto->len==0 || (proto->len==3 && !strcasecmp(proto->s, "any")))
		return PROTO_NONE;
	if (parse_proto((unsigned char*)proto->s, proto->len, &ret_proto) < 0)
		return -1;
	return ret_proto;
}


int init_address(void)
{
	struct pm_partition *el, *prev_el;

	if (db_url.s)
		db_url.len = strlen(db_url.s);

	address_table.len = strlen(address_table.s);
	ip_col.len = strlen(ip_col.s);
	proto_col.len = strlen(proto_col.s);
	pattern_col.len = strlen(pattern_col.s);
	info_col.len = strlen(info_col.s);
	grp_col.len = strlen(grp_col.s);
	mask_col.len = strlen(mask_col.s);
	port_col.len = strlen(port_col.s);

	if (init_address_df_part() != 0) {
		LM_ERR("failed to init the 'default' partition\n");
		return -1;
	}

	el = get_partitions();

	while (el) {
		if (init_address_part(el) != 0) {
			LM_ERR("failed to initialize the '%.*s' partition\n",
			       el->name.len, el->name.s);
			return -1;
		}
		prev_el = el;
		el = el->next;
		pkg_free(prev_el);
	}

	return 0;
}


/*
 * Reload address table to new hash table and when done, make new hash table
 * current one.
 */
int reload_address_table(struct pm_part_struct *part_struct)
{
	db_key_t cols[8];
	db_res_t* res = NULL;
	db_row_t* row;
	db_val_t* val;

	struct address_list **new_hash_table;
	struct subnet *new_subnet_table;
	int i, mask, proto, group, port, id;
	struct ip_addr *ip_addr;
	struct net *subnet;
	str str_pattern = {NULL,0}, str_info={NULL,0};
	str str_src_ip, str_proto;
	UNUSED(id);

	cols[0] = &ip_col;
	cols[1] = &grp_col;
	cols[2] = &mask_col;
	cols[3] = &port_col;
	cols[4] = &proto_col;
	cols[5] = &pattern_col;
	cols[6] = &info_col;
	cols[7] = &id_col;

	if (part_struct->perm_dbf.use_table(part_struct->db_handle,
											&part_struct->table) < 0) {
		LM_ERR("failed to use address table\n");
		return -1;
	}

	if (part_struct->perm_dbf.query(part_struct->db_handle, NULL, 0, NULL,
													cols, 0, 8, 0, &res) < 0) {
		LM_ERR("failed to query database\n");
		return -1;
	}

	/* Choose new hash table and free its old contents */
	if (*part_struct->hash_table == part_struct->hash_table_1) {
		empty_hash(part_struct->hash_table_2);
		new_hash_table = part_struct->hash_table_2;
	} else {
		empty_hash(part_struct->hash_table_1);
		new_hash_table = part_struct->hash_table_1;
	}

	/* Choose new subnet table */
	if (*part_struct->subnet_table == part_struct->subnet_table_1) {
		empty_subnet_table(part_struct->subnet_table_2);
		new_subnet_table = part_struct->subnet_table_2;
	} else {
		empty_subnet_table(part_struct->subnet_table_1);
		new_subnet_table = part_struct->subnet_table_1;
	}

	row = RES_ROWS(res);
	LM_DBG("number of rows in address table: %d\n", RES_ROW_N(res));

	if (RES_COL_N(res) != 8) {
		LM_ERR("too many columns\n");
		goto error;
	}

	for (i = 0; i < RES_ROW_N(res); i++) {

		val = ROW_VALUES(row + i);
		if ((VAL_TYPE(val)!=DB_STRING && VAL_TYPE(val)!=DB_STR) ||
				VAL_NULL(val)) {
			LM_ERR("invalid IP column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 1) != DB_INT && VAL_TYPE(val + 1) != DB_BIGINT) ||
		VAL_NULL(val + 1) ||
					VAL_INT(val + 1) < 0) {
			LM_ERR("invalid group column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 2) != DB_INT && VAL_TYPE(val + 2) != DB_BIGINT) ||
		VAL_NULL(val + 2) || VAL_INT(val + 2) < 0) {
			LM_ERR("invalid mask column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 3) != DB_INT && VAL_TYPE(val + 3) != DB_BIGINT) ||
		VAL_NULL(val + 3)) {
			LM_ERR("invalid port column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 4) != DB_STRING && VAL_TYPE(val + 4) != DB_STR) ||
			VAL_NULL(val + 4)) {
			LM_ERR("invalid protocol column type on row %d, skipping..\n", i);
			continue;
		}
		if (VAL_TYPE(val + 5) != DB_STRING && VAL_TYPE(val + 5) != DB_STR) {
			LM_ERR("invalid pattern column type on row %d, skipping..\n", i);
			continue;
		}
		if (VAL_TYPE(val + 6) != DB_STRING && VAL_TYPE(val + 6) != DB_STR) {
			LM_ERR("invalid info column type on row %d, skipping..\n", i);
			goto error;
		}
		id = (unsigned int) VAL_INT(val + 7);

		/* IP string */
		if (VAL_TYPE(val)==DB_STRING) {
			str_src_ip.s = (char*)VAL_STRING(val);
			str_src_ip.len = strlen(str_src_ip.s);
		} else {
			str_src_ip = VAL_STR(val);
		}
		if (str_src_ip.len==0) {
			LM_DBG("empty ip field in address table, ignoring entry"
					" number %d\n", i);
			continue;
		}

		if ( (ip_addr=str2ip(&str_src_ip))==NULL &&
		(ip_addr=str2ip6(&str_src_ip))==NULL ) {
			LM_DBG("invalid ip <%.*s> in address table, ignoring entry "
				"with id %d\n", str_src_ip.len, str_src_ip.s, id);
			continue;
		}

		/* now that we know the AF family, we can validate the mask len */
		if ( (ip_addr->af==AF_INET && VAL_INT(val + 2)>32) ||
		(ip_addr->af==AF_INET6 && VAL_INT(val + 2)>128) ) {
			LM_DBG("netmask size %d too large of IP's AF %d, ignoring entry"
				" number %d\n", VAL_INT(val + 2), ip_addr->af, i);
			continue;
		}

		/* proto string */
		if (VAL_TYPE(val+4)==DB_STRING) {
			str_proto.s = (char*)VAL_STRING(val+4);
			str_proto.len = strlen(str_proto.s);
		} else {
			str_proto = VAL_STR(val+4);
		}

		if (str_proto.len==4 && !strncasecmp(str_proto.s, "none",4)) {
			LM_DBG("protocol field is \"none\" in address table, ignoring"
					" entry with id %d\n", id);
			continue;
		}

		proto = proto_char2int(&str_proto);
		if (proto == -1) {
			LM_DBG("unknown protocol field in address table, ignoring"
					" entry with id %d\n", id);
			continue;
		}

		/* pattern string */
		if (!VAL_NULL(val + 5)) {
			if (VAL_TYPE(val+5)==DB_STRING) {
				str_pattern.s = (char*)VAL_STRING(val+5);
				str_pattern.len = strlen(str_pattern.s);
			} else {
				str_pattern = VAL_STR(val+5);
			}
		} else {
			str_pattern.len = 0;
			str_pattern.s = 0;
		}

		/* info string */
		if (!VAL_NULL(val + 6)) {
			if (VAL_TYPE(val+6)==DB_STRING) {
				str_info.s = (char*)VAL_STRING(val+6);
				str_info.len = strlen(str_info.s);
			} else {
				str_info = VAL_STR(val+6);
			}
		} else {
			str_info.len = 0;
			str_info.s = 0;
		}

		group = (unsigned int) VAL_INT(val + 1);
		port = (unsigned int) VAL_INT(val + 3);
		mask = (unsigned int) VAL_INT(val + 2);

		if ( (mask == 32 && ip_addr->af==AF_INET) ||
		(mask == 128 && ip_addr->af==AF_INET6) ) {
			if (hash_insert(new_hash_table, ip_addr, group, port, proto,
				&str_pattern, &str_info) == -1) {
					LM_ERR("hash table insert error\n");
					goto error;
			}
			LM_DBG("Tuple <%.*s, %u, %u, %u, %.*s, %.*s> inserted into "
					"address hash table\n", str_src_ip.len, str_src_ip.s,
					group, port, proto, str_pattern.len, str_pattern.s,
					str_info.len,str_info.s);
		} else {
			subnet = mk_net_bitlen(ip_addr, mask);
			if (subnet_table_insert(new_subnet_table, group, subnet,
				port, proto, &str_pattern, &str_info) == -1) {
					LM_ERR("subnet table problem\n");
					if (subnet) {
						pkg_free(subnet);
					}
					goto error;
				}
			LM_DBG("Tuple <%.*s, %u, %u, %u> inserted into subnet table\n",
					str_src_ip.len, str_src_ip.s, group, mask, port);
			/* subnet in pkg; needs to be freed since was copied to shm */
			if (subnet) {
				pkg_free(subnet);
			}
		}
	}

	part_struct->perm_dbf.free_result(part_struct->db_handle, res);

	*part_struct->hash_table = new_hash_table;
	*part_struct->subnet_table = new_subnet_table;
	LM_DBG("address table reloaded successfully.\n");

	return 1;
error:
	part_struct->perm_dbf.free_result(part_struct->db_handle, res);
	return -1;
}


/*
 * Initialize data structures
 */
int init_address_part(struct pm_partition *partition)
{
	struct pm_part_struct *part_struct;
	/* Check if hash table needs to be loaded from address table */
	if (!partition->url.s) {
		LM_INFO("db_url parameter of permissions module not set, "
			"disabling allow_address\n");
		return 0;
	}

	part_struct = pkg_malloc(sizeof (struct pm_part_struct));
	if (part_struct == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	memset(part_struct, 0, sizeof(struct pm_part_struct));

	part_struct->name = partition->name;
	part_struct->url = partition->url;
	part_struct->table = partition->table;

	if (db_bind_mod(&partition->url, &part_struct->perm_dbf) < 0) {
		LM_ERR("failed to load a database support module\n");
		return -1;
	}

	if (!DB_CAPABILITY(part_struct->perm_dbf, DB_CAP_QUERY)) {
		LM_ERR("database module does not implement 'query' function\n");
		return -1;
	}

	part_struct->hash_table_1 = part_struct->hash_table_2 = 0;
	part_struct->hash_table = 0;

	part_struct->db_handle = part_struct->perm_dbf.init(&partition->url);
	if (!part_struct->db_handle) {
		LM_ERR("unable to connect database\n");
		return -1;
	}

	if (db_check_table_version(&part_struct->perm_dbf, part_struct->db_handle,
				&partition->table,
				TABLE_VERSION) < 0) {
		LM_ERR("error during table version check.\n");
		part_struct->perm_dbf.close(part_struct->db_handle);
		return -1;
	}

	part_struct->hash_table_1 = hash_create();
	if (!part_struct->hash_table_1) return -1;

	part_struct->hash_table_2  = hash_create();
	if (!part_struct->hash_table_2) goto error;

	part_struct->hash_table = (struct address_list ***)shm_malloc
							(sizeof(struct address_list **));
	if (!part_struct->hash_table) goto error;

	*part_struct->hash_table = part_struct->hash_table_1;

	part_struct->subnet_table_1 = new_subnet_table();
    if (!part_struct->subnet_table_1) goto error;

    part_struct->subnet_table_2 = new_subnet_table();
    if (!part_struct->subnet_table_2) goto error;

	part_struct->subnet_table = (struct subnet **)shm_malloc(sizeof(struct subnet *));
	if (!part_struct->subnet_table) goto error;

	*part_struct->subnet_table = part_struct->subnet_table_1;

	if (reload_address_table(part_struct) == -1) {
		LM_CRIT("reload of address table failed\n");
		goto error;
	}

	part_struct->perm_dbf.close(part_struct->db_handle);
	part_struct->db_handle = 0;

	add_part_struct(part_struct);

	return 0;

error:
	if (part_struct->hash_table_1) {
		hash_destroy(part_struct->hash_table_1);
		part_struct->hash_table_1 = 0;
	}
	if (part_struct->hash_table_2) {
		hash_destroy(part_struct->hash_table_2);
		part_struct->hash_table_2 = 0;
	}
	if (part_struct->hash_table) {
		shm_free(part_struct->hash_table);
		part_struct->hash_table = 0;
	}

	if (part_struct->subnet_table_1) {
		free_subnet_table(part_struct->subnet_table_1);
		part_struct->subnet_table_1 = 0;
	}

	if (part_struct->subnet_table_2) {
		free_subnet_table(part_struct->subnet_table_2);
		part_struct->subnet_table_2 = 0;
    }
	if (part_struct->subnet_table) {
		shm_free(part_struct->subnet_table);
		part_struct->subnet_table = 0;
	}
	part_struct->perm_dbf.close(part_struct->db_handle);
	part_struct->db_handle = 0;

	pkg_free(part_struct);
	return -1;
}


/*
 * Open database connection if necessary
 */
int mi_init_address(void)
{
	struct pm_part_struct *it;


	for (it=get_part_structs(); it; it=it->next) {
		if (it->db_handle)
			continue;

		it->db_handle = it->perm_dbf.init(&it->url);
		if (!it->db_handle) {
			LM_ERR("unable to connect database\n");
			return -1;
		}
	}
    return 0;
}


/*
 * Close connections and release memory
 */
void clean_address(struct pm_part_struct *part_struct)
{
	if (part_struct->hash_table_1) hash_destroy(part_struct->hash_table_1);
	if (part_struct->hash_table_2) hash_destroy(part_struct->hash_table_2);
	if (part_struct->hash_table) shm_free(part_struct->hash_table);
}


/*
 *
 */
int check_addr(struct sip_msg* msg, int* grp, str* s_ip, int *port, long proto,
				pv_spec_t *info, char *pattern, struct pm_part_struct *part)
{
	struct ip_addr *ip;
	int hash_ret, subnet_ret;

	/* ip addr */
	if ( (ip=str2ip(s_ip))==NULL && (ip=str2ip6(s_ip))==NULL ) {
		LM_ERR("invalid ip address <%.*s>!\n", s_ip->len, s_ip->s);
		return -1;
	}

	LM_DBG("Looking for : <%.*s:%d, %.*s, %d, %d, %s>\n",
		part->name.len, part->name.s, *grp,
		s_ip->len, s_ip->s, (int)proto, *port, ZSW(pattern) );

	hash_ret = hash_match(msg, *part->hash_table, *grp,
			ip, *port, (int)proto, pattern, info);
	if (hash_ret < 0) {
		subnet_ret = match_subnet_table(msg, *part->subnet_table, *grp,
				ip, *port, (int)proto, pattern, info);
		hash_ret = (hash_ret > subnet_ret) ? hash_ret : subnet_ret;
	}

	return hash_ret;
}


int check_src_addr(struct sip_msg *msg, int *grp,
				pv_spec_t *info, char* pattern, struct pm_part_struct *part)
{

	int hash_ret, subnet_ret;
	struct ip_addr *ip;

	ip = &msg->rcv.src_ip;

	LM_DBG("Looking for : <%.*s:%d, %s, %d, %d, %s>\n",
		part->name.len, part->name.s, *grp,
		ip_addr2a(ip), msg->rcv.proto, msg->rcv.src_port, ZSW(pattern) );

	hash_ret = hash_match(msg, *part->hash_table, *grp, ip,
		msg->rcv.src_port, msg->rcv.proto, pattern, info);
	if (hash_ret < 0) {
			subnet_ret = match_subnet_table(msg, *part->subnet_table,
				*grp, ip, msg->rcv.src_port, msg->rcv.proto, pattern,info);
			hash_ret = (hash_ret > subnet_ret) ? hash_ret : subnet_ret;
	}

	return hash_ret;
}


int get_source_group(struct sip_msg* msg, pv_spec_t *out_var,
												struct pm_part_struct *part)
{
	int group;
	struct ip_addr *ip;
	pv_value_t pvt;

	ip = &msg->rcv.src_ip;
	LM_DBG("Looking for <%s, %u> in address table\n",
			ip_addr2a(ip), msg->rcv.src_port);

	group = find_group_in_hash_table(*part->hash_table,
		ip, msg->rcv.src_port);
	if (group == -1) {

		LM_DBG("Looking for <%x, %u> in subnet table\n",
			msg->rcv.src_ip.u.addr32[0], msg->rcv.src_port);

		group = find_group_in_subnet_table(*part->subnet_table,
			ip, msg->rcv.src_port);
		if (group == -1) {
			LM_DBG("IP <%s:%u> not found in any group\n",
					ip_addr2a(ip), msg->rcv.src_port);
			return -1;
		}
	}
	LM_DBG("Found <%d>\n", group);

	pvt.flags = PV_VAL_INT|PV_TYPE_INT;
	pvt.rs.s = NULL;
	pvt.rs.len = 0;
	pvt.ri = group;

	if (pv_set_value(msg, out_var, (int)EQ_T, &pvt) < 0) {
		LM_ERR("setting of pvar failed\n");
		return -1;
	}

	return 1;
}
