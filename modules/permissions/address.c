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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2004-06-07  updated to the new DB api, moved reload_address_table (andrei)
 *  2009-09-10  major refactoring (irina)
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

static inline int proto_char2int(str *proto) {
	int ret_proto;
	if (proto->len==0 || (proto->len==3 && !strcasecmp(proto->s, "any")))
		return PROTO_NONE;
	if (parse_proto((unsigned char*)proto->s, proto->len, &ret_proto) < 0)
		return -1;
	return ret_proto;
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
		if ((VAL_TYPE(val + 1) != DB_INT && VAL_TYPE(val + 1) != DB_BIGINT) || VAL_NULL(val + 1) ||
					VAL_INT(val + 1) < 0) {
			LM_ERR("invalid group column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 2) != DB_INT && VAL_TYPE(val + 2) != DB_BIGINT) || VAL_NULL(val + 2) ||
					VAL_INT(val + 2) < 0 || VAL_INT(val + 2) > 32) {
			LM_ERR("invalid mask column type on row %d, skipping..\n", i);
			continue;
		}
		if ((VAL_TYPE(val + 3) != DB_INT && VAL_TYPE(val + 3) != DB_BIGINT) || VAL_NULL(val + 3)) {
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

		ip_addr = str2ip(&str_src_ip);

		if (!ip_addr) {
			LM_DBG("invalid ip field in address table, ignoring entry "
				"with id %d\n", id);
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

		if (mask == 32) {
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
int init_address(struct pm_partition *partition)
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
		LM_ERR("load a database support module\n");
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
int check_addr_6(struct sip_msg* msg,
		char* grp_sgp, char* ip_sp, char* port_sp, char* proto_sp,
		char* info, char* pattern) {

	unsigned int port;
	int group, proto, hash_ret, subnet_ret, ret = 1;
	struct ip_addr *ip;
	str str_ip, str_proto, str_port, pattern_s, str_part_group;
	struct pm_part_struct *part_struct;
	struct part_var *pvar, *pvar_new;

	memset(&str_ip, 0, sizeof(str));
	memset(&str_proto, 0, sizeof(str));

	if (grp_sgp) {
		pvar = (struct part_var *) grp_sgp;

		if (pvar->type == TYPE_PV) {
			if (fixup_get_svalue(msg, pvar->u.gp, &str_part_group)) {
			    LM_ERR("cannot get group value\n");
				return -1;
			}

			pvar_new = pkg_malloc(sizeof(struct part_var));
			if (pvar_new == NULL) {
				LM_ERR("no more pkg mem\n");
				return -1;
			}

			if (check_addr_param1( &str_part_group, pvar_new)) {
				LM_ERR("failed to parse [%s]!", str_part_group.s);
				return -1;
			}
			group = pvar_new->u.parsed_part.v.ival;

			if (pvar_new->u.parsed_part.partition.s)
				part_struct = get_part_struct(&pvar_new->u.parsed_part.partition);
			else
				part_struct = get_part_struct(&def_part);

			pkg_free(pvar_new);
		} else {
			group = pvar->u.parsed_part.v.ival;
			if (pvar->u.parsed_part.partition.s)
				part_struct = get_part_struct(&pvar->u.parsed_part.partition);
			else
				part_struct = get_part_struct(&def_part);
		}

		if (group < 0) {
			LM_ERR("invalid group value\n");
			return -1;
		}
	} else {
		group = 0;
		part_struct = get_part_struct(&def_part);
	}

	if (part_struct == NULL) {
		LM_ERR("no db_url defined or no (such) partition!\n");
		return -1;
	}

	if (ip_sp) {
		if (fixup_get_svalue(msg, (gparam_p)ip_sp, &str_ip)) {
			LM_ERR("cannot get str_ip string\n");
			return -1;
		}
	} else {
		LM_ERR("source ip not provided!\n");
		return -1;
	}
	if (str_ip.len <= 0 || !str_ip.s) {
		LM_ERR("source ip is not set!\n");
		return -1;
	}

	ip = str2ip(&str_ip);
	if (!ip) {
		LM_ERR("invalid ip set <%.*s>!\n", str_ip.len, str_ip.s);
		return -1;
	}


	if (proto_sp) {
		if (fixup_get_svalue(msg, (gparam_p) proto_sp, &str_proto)) {
			LM_ERR("cannot get str_proto string\n");
			return -1;
		}
	}
	if (str_proto.len <= 0 || !str_proto.s) {
		str_proto.s = "any";
		str_proto.len = strlen(str_proto.s);
	}

	if ((proto = proto_char2int(&str_proto)) < 0) {
		LM_ERR("unknown protocol %.*s\n", str_proto.len, str_proto.s);
		return -1;
	}

	if (port_sp) {
		if (fixup_get_svalue(msg, (gparam_p)port_sp, &str_port)) {
		    LM_ERR("cannot get port value\n");
	    	return -1;
		}

		if (str2int(&str_port, &port) < 0) {
			LM_ERR("invalid port value\n");
			return -1;
		}
	} else
		port = 0;

	if (pattern) {
		if (fixup_get_svalue(msg, (gparam_p)pattern, &pattern_s) < 0) {
			LM_ERR("cannot get pattern value\n");
			return -1;
		}
		pattern = pkg_malloc(pattern_s.len + 1);
		if (!pattern) {
			LM_ERR("no more pkg mem\n");
			return -1;
		}
		memcpy(pattern, pattern_s.s, pattern_s.len);
		pattern[pattern_s.len] = 0;
	}

	LM_DBG("Looking for : <%d, %.*s, %.*s, %d, %s>\n", group, str_ip.len,
			str_ip.s, str_proto.len, str_proto.s, port, ZSW(pattern) );

	hash_ret = hash_match(msg, *part_struct->hash_table, group, ip, port,
				proto, pattern, info);
	if (hash_ret < 0) {
	    subnet_ret = match_subnet_table(msg, *part_struct->subnet_table, group,
				ip, port, proto, pattern, info);
	    ret = (hash_ret > subnet_ret) ? hash_ret : subnet_ret;
	}

	if (pattern)
		pkg_free(pattern);
	return ret;
}

int check_addr_4(struct sip_msg *msg,
       char *grp, char *src_ip_sp, char *port_sp, char *proto_sp) {
	return check_addr_6(msg, grp, src_ip_sp, port_sp, proto_sp,
			NULL, NULL);
}

int check_addr_5(struct sip_msg *msg,
	char *grp, char *src_ip_sp, char *port_sp, char *proto_sp, char *info) {
	return check_addr_6(msg, grp, src_ip_sp, port_sp, proto_sp,
			info, NULL);
}

int check_src_addr_3(struct sip_msg *msg,
		                char *grp, char *info, char* pattern) {

	int group, hash_ret, subnet_ret, ret = 1;
	struct in_addr in;
	str str_ip, str_part_group;
	struct ip_addr *ip;
	str pattern_s;
	struct pm_part_struct *part_struct;
	struct part_var *pvar, *pvar_new;

	if (grp) {
		pvar = (struct part_var *) grp;

		if (pvar->type == TYPE_PV) {
			if (fixup_get_svalue(msg, pvar->u.gp, &str_part_group)) {
			    LM_ERR("cannot get group value\n");
				return -1;
			}
			pvar_new = pkg_malloc(sizeof(struct part_var));
			if (pvar_new == NULL) {
				LM_ERR("no more pkg mem\n");
				return -1;
			}

			if (check_addr_param1( &str_part_group, pvar_new)) {
				LM_ERR("failed to parse [%s]!", str_part_group.s);
				return -1;
			}
			group = pvar_new->u.parsed_part.v.ival;
			if (pvar_new->u.parsed_part.partition.s)
				part_struct = get_part_struct(&pvar_new->u.parsed_part.partition);
			else
				part_struct = get_part_struct(&def_part);

			pkg_free(pvar_new);
		} else {
			group = pvar->u.parsed_part.v.ival;

			if (pvar->u.parsed_part.partition.s)
				part_struct = get_part_struct(&pvar->u.parsed_part.partition);
			else
				part_struct = get_part_struct(&def_part);
		}

		if (group < 0) {
			LM_ERR("invalid group value\n");
			return -1;
		}
	} else {
		group = 0;
		part_struct = get_part_struct(&def_part);
	}

	if (part_struct == NULL) {
		LM_ERR("no db_url defined or no (such) partition!\n");
		return -1;
	}

	in.s_addr = msg->rcv.src_ip.u.addr32[0];
	str_ip.s = inet_ntoa(in);

	if (!str_ip.s) {
		LM_ERR("error at inet_ntoa\n");
		return -1;
	}

	str_ip.len = strlen(str_ip.s);
	ip = str2ip(&str_ip);

	LM_DBG("Looking for : <%d, %.*s, %d, %d> in tables\n",
				group, str_ip.len, str_ip.s,
				msg->rcv.src_port,
				msg->rcv.proto);
	if (pattern) {
		if (fixup_get_svalue(msg, (gparam_p)pattern, &pattern_s) < 0) {
			LM_ERR("cannot get pattern value\n");
			return -1;
		}
		pattern = pkg_malloc(pattern_s.len + 1);
		if (!pattern) {
			LM_ERR("no more pkg mem\n");
			return -1;
		}
		memcpy(pattern, pattern_s.s, pattern_s.len);
		pattern[pattern_s.len] = 0;
	}

	hash_ret = hash_match(msg, *part_struct->hash_table, group,
				ip,
				msg->rcv.src_port,
				msg->rcv.proto,
				pattern,
				info);
	if (hash_ret < 0) {
	    subnet_ret = match_subnet_table(msg, *part_struct->subnet_table, group,
				ip,
				msg->rcv.src_port,
				msg->rcv.proto,
				pattern,
				info);
            ret = (hash_ret > subnet_ret) ? hash_ret : subnet_ret;
        }

	if (pattern)
		pkg_free(pattern);
	return ret;
}


int check_src_addr_2(struct sip_msg* msg,
		        char* grp, char* info) {
	return check_src_addr_3(msg, grp, info, NULL);
}


int check_src_addr_1(struct sip_msg* msg,
		        char* grp) {
	return check_src_addr_3(msg, grp, NULL, NULL);
}



int get_source_group(struct sip_msg* msg, char *arg) {
	int group = -1;
	struct in_addr in;
	struct ip_addr *ip;
	str str_ip, partition;
	pv_value_t pvt;
	struct part_pvar *ppv;
	struct pm_part_struct *ps;

	ppv  = (struct part_pvar *)arg;

	if (ppv->part) {
		if (fixup_get_svalue(msg, ppv->part, &partition)) {
			    LM_ERR("cannot get partition value\n");
				return -1;
		}

		str_trim_spaces_lr(partition);
		ps = get_part_struct(&partition);

		if (ps == NULL) {
			LM_ERR("no such partition (%.*s)\n", partition.len, partition.s);
			return -1;
		}

	} else {
		ps = get_part_struct(&def_part);
		if (ps == NULL) {
			LM_ERR("no default partition\n");
			return -1;
		}
	}

	LM_DBG("Looking for <%x, %u> in address table\n",
			msg->rcv.src_ip.u.addr32[0], msg->rcv.src_port);

	in.s_addr = msg->rcv.src_ip.u.addr32[0];
	str_ip.s = inet_ntoa(in);
	str_ip.len = str_ip.s ? strlen(str_ip.s) : 0;

	ip = str2ip(&str_ip);

	group = find_group_in_hash_table(*ps->hash_table,
				ip,
				msg->rcv.src_port);
	if (group == -1) {

		LM_DBG("Looking for <%x, %u> in subnet table\n",
			msg->rcv.src_ip.u.addr32[0], msg->rcv.src_port);

		group = find_group_in_subnet_table(*ps->subnet_table,
				ip,
				msg->rcv.src_port);
		if (group == -1) {
			LM_DBG("IP <%.*s:%u> not found in any group\n",
					str_ip.len, str_ip.s, msg->rcv.src_port);
			return -1;
		}
	}
	LM_DBG("Found <%d>\n", group);

	pvt.flags = PV_VAL_INT|PV_TYPE_INT;
	pvt.rs.s = NULL;
	pvt.rs.len = 0;
	pvt.ri = group;

	if (pv_set_value(msg, ppv->sp, (int)EQ_T, &pvt) < 0) {
		LM_ERR("setting of pvar failed\n");
		return -1;
	}

	return 1;
}
