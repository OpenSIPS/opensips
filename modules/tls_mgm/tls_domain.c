/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2004,2005 Free Software Foundation, Inc.
 * Copyright (C) 2006 enum.at
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include "../../mem/mem.h"
#include "../../lib/csv.h"
#include "tls_domain.h"
#include "tls_params.h"
#include "api.h"
#include <stdlib.h>
#include <fnmatch.h>


struct tls_domain **tls_server_domains;
struct tls_domain **tls_client_domains;

map_t server_dom_matching;
map_t client_dom_matching;

rw_lock_t *dom_lock;

struct tls_domain *tls_find_domain_by_name(str *name, struct tls_domain **dom_list)
{
	struct tls_domain *d;

	if (dom_list)
		for (d = *dom_list; d; d = d->next)
			if (name->len == d->name.len && memcmp(name->s, d->name.s, name->len) == 0)
				return d;

	return NULL;
}

struct tls_domain *find_first_script_dom(struct tls_domain *dom)
{
	struct tls_domain *d;

	for (d = dom; d && d->flags & DOM_FLAG_DB; d = d->next) ;

	return d;
}

void map_free_node(void *val)
{
	if (val)
		shm_free(val);
}

void map_remove_tls_dom(struct tls_domain *dom)
{
	map_t map = dom->flags & DOM_FLAG_SRV ? server_dom_matching : client_dom_matching;
	map_iterator_t it, it_tmp;
	struct dom_filt_array *doms_array;
	void **val;
	int i, j;

	map_first(map, &it);
	while (iterator_is_valid(&it)) {
		it_tmp = it;
		iterator_next(&it);

		val = iterator_val(&it_tmp);
		doms_array = (struct dom_filt_array *)*val;
		for (i = 0; i < doms_array->size; i++)
			if (doms_array->arr[i].dom_link == dom) {
				for (j = i + 1; j < doms_array->size; j++)
					doms_array->arr[j-1] = doms_array->arr[j];
				doms_array->size--;
			}
		if (doms_array->size == 0) {
			map_free_node(doms_array);
			iterator_delete(&it_tmp);
		}
	}
}

void tls_free_domain(struct tls_domain *dom)
{
	str_list *m_it, *m_tmp;
	int i;

	dom->refs--;
	if (dom->refs == 0) {
		if (dom->ctx) {
			for (i = 0; i < dom->ctx_no; i++)
				SSL_CTX_free(dom->ctx[i]);
			shm_free(dom->ctx);
		}
		lock_destroy(dom->lock);
		lock_dealloc(dom->lock);

		map_remove_tls_dom(dom);

		m_it = dom->match_domains;
		while (m_it) {
			m_tmp = m_it;
			m_it = m_it->next;
			shm_free(m_tmp);
		}
		m_it = dom->match_addresses;
		while (m_it) {
			m_tmp = m_it;
			m_it = m_it->next;
			shm_free(m_tmp);
		}

		shm_free(dom);
	}
}

/* frees the DB domains */
void tls_free_db_domains(struct tls_domain *dom)
{
	struct tls_domain *tmp;

	while (dom && dom->flags & DOM_FLAG_DB) {
		tmp = dom;
		dom = dom->next;
		map_remove_tls_dom(tmp);
		tls_free_domain(tmp);
	}
}

void tls_release_domain(struct tls_domain* dom)
{
	if (!dom || !(dom->flags & DOM_FLAG_DB))
		return;

	if (dom_lock)
		lock_start_write(dom_lock);

	tls_free_domain(dom);

	if (dom_lock)
		lock_stop_write(dom_lock);
}

int set_all_domain_attr(struct tls_domain **dom, char **str_vals, int *int_vals,
							str* blob_vals)
{
	size_t len;
	char *p;
	struct tls_domain *d = *dom;
	size_t cadir_len = str_vals[STR_VALS_CADIR_COL] ?
		strlen(str_vals[STR_VALS_CADIR_COL]) : 0;
	size_t cplist_len = str_vals[STR_VALS_CPLIST_COL] ?
		strlen(str_vals[STR_VALS_CPLIST_COL]) : 0;
	size_t crl_dir_len = str_vals[STR_VALS_CRL_DIR_COL] ?
		strlen(str_vals[STR_VALS_CRL_DIR_COL]) : 0;
	size_t eccurve_len = str_vals[STR_VALS_ECCURVE_COL] ?
		strlen(str_vals[STR_VALS_ECCURVE_COL]) : 0;
	char name_buf[255];
	int name_len;
	str method_str;

	len = sizeof(struct tls_domain) + d->name.len;

	if (cadir_len)
		len += cadir_len + 1;

	if (cplist_len)
		len += cplist_len + 1;

	if (crl_dir_len)
		len += crl_dir_len + 1;

	if (eccurve_len)
		len += eccurve_len + 1;

	if(blob_vals[BLOB_VALS_CERTIFICATE_COL].len && blob_vals[BLOB_VALS_CERTIFICATE_COL].s)
		len += blob_vals[BLOB_VALS_CERTIFICATE_COL].len;

	if(blob_vals[BLOB_VALS_PK_COL].len && blob_vals[BLOB_VALS_PK_COL].s)
		len += blob_vals[BLOB_VALS_PK_COL].len;

	if(blob_vals[BLOB_VALS_CALIST_COL].len && blob_vals[BLOB_VALS_CALIST_COL].s)
		len += blob_vals[BLOB_VALS_CALIST_COL].len;

	if(blob_vals[BLOB_VALS_DHPARAMS_COL].len && blob_vals[BLOB_VALS_DHPARAMS_COL].s)
		len += blob_vals[BLOB_VALS_DHPARAMS_COL].len;

	memcpy(name_buf, d->name.s, d->name.len);
	name_len = d->name.len;

	d = shm_realloc(d, len);
	if (d == NULL) {
		LM_ERR("insufficient shm memory\n");
		d = *dom;
		*dom = (*dom)->next;
		shm_free(d);
		return -1;
	}

	*dom = d;

	method_str.s = str_vals[STR_VALS_METHOD_COL];
	method_str.len = method_str.s ? strlen(method_str.s) : 0;

	if (tls_get_method(&method_str, &d->method, &d->method_max) < 0) {
		shm_free(d);
		return -1;
	}

	if (int_vals[INT_VALS_VERIFY_CERT_COL] != -1) {
		d->verify_cert = int_vals[INT_VALS_VERIFY_CERT_COL];
	}

	if (int_vals[INT_VALS_CRL_CHECK_COL] != -1) {
		d->crl_check_all = int_vals[INT_VALS_CRL_CHECK_COL];
	}

	if (int_vals[INT_VALS_REQUIRE_CERT_COL] != -1) {
		d->require_client_cert = int_vals[INT_VALS_REQUIRE_CERT_COL];
	}

	p = (char *) (d + 1);

	d->name.s = p;
	d->name.len = name_len;
	memcpy(p, name_buf, name_len);

	p = p + d->name.len;

	memset(p, 0, len - (sizeof(struct tls_domain) + d->name.len));

	if (cadir_len) {
		d->ca_directory = p;
		memcpy(p, str_vals[STR_VALS_CADIR_COL], cadir_len);
		p = p + cadir_len + 1;
	}

	if (blob_vals[BLOB_VALS_CALIST_COL].len && blob_vals[BLOB_VALS_CALIST_COL].s) {
		d->ca.s = p;
		d->ca.len = blob_vals[BLOB_VALS_CALIST_COL].len;
		memcpy(p, blob_vals[BLOB_VALS_CALIST_COL].s, blob_vals[BLOB_VALS_CALIST_COL].len);
		p = p + d->ca.len;
	}

	if (blob_vals[BLOB_VALS_CERTIFICATE_COL].len && blob_vals[BLOB_VALS_CERTIFICATE_COL].s) {
		d->cert.s = p;
		d->cert.len = blob_vals[BLOB_VALS_CERTIFICATE_COL].len;
		memcpy(p, blob_vals[BLOB_VALS_CERTIFICATE_COL].s, blob_vals[BLOB_VALS_CERTIFICATE_COL].len);
		p = p + d->cert.len;
	}


	if (cplist_len) {
		d->ciphers_list = p;
		memcpy(p, str_vals[STR_VALS_CPLIST_COL], cplist_len);
		p = p + cplist_len + 1;
	}

	if (crl_dir_len) {
		d->crl_directory = p;
		memcpy(p, str_vals[STR_VALS_CRL_DIR_COL], crl_dir_len);
		p = p + crl_dir_len + 1;
	}

	if (blob_vals[BLOB_VALS_DHPARAMS_COL].len && blob_vals[BLOB_VALS_DHPARAMS_COL].s) {
		d->dh_param.s = p;
		d->dh_param.len = blob_vals[BLOB_VALS_DHPARAMS_COL].len;
		memcpy(p, blob_vals[BLOB_VALS_DHPARAMS_COL].s, blob_vals[BLOB_VALS_DHPARAMS_COL].len);
		p = p + d->dh_param.len;
	}

	if (eccurve_len) {
		d->tls_ec_curve = p;
		memcpy(p, str_vals[STR_VALS_ECCURVE_COL], eccurve_len);
		p = p + eccurve_len + 1;
	}

	if (blob_vals[BLOB_VALS_PK_COL].len && blob_vals[BLOB_VALS_PK_COL].s) {
		d->pkey.s = p;
		d->pkey.len = blob_vals[BLOB_VALS_PK_COL].len;
		memcpy(p, blob_vals[BLOB_VALS_PK_COL].s, blob_vals[BLOB_VALS_PK_COL].len);
		p = p + d->pkey.len;
	}

	return 0;
}

/*
 * returns a TLS server domain that matches this address (there may be multiple
 * domains that match this address, return the first one to be found)
 * return NULL if no TLS domain found
 */
struct tls_domain *
tls_find_server_domain(struct ip_addr *ip, unsigned short port)
{
	char addr_buf[64];
	str addr_s;
	struct dom_filt_array *dom_array;
	void **val;
	str match_any_s = str_init("*");

	if (dom_lock)
		lock_start_read(dom_lock);

	sprintf(addr_buf, "%s:%d", ip_addr2a(ip), port);
	addr_s.s = addr_buf;
	addr_s.len = strlen(addr_buf);

	val = map_find(server_dom_matching, addr_s);
	if (!val) {
		/* try to find a domain which matches any address */
		val = map_find(server_dom_matching, match_any_s);
		if (!val) {
			if (dom_lock)
				lock_stop_read(dom_lock);
			return NULL;
		} else
			dom_array = (struct dom_filt_array *)*val;
	} else
		dom_array = (struct dom_filt_array *)*val;

	ref_tls_dom(dom_array->arr[0].dom_link);

	if (dom_lock)
		lock_stop_read(dom_lock);

	LM_DBG("found TLS server domain: %.*s\n",
				dom_array->arr[0].dom_link->name.len,
				dom_array->arr[0].dom_link->name.s);
	return dom_array->arr[0].dom_link;
}

struct tls_domain *
tls_find_domain_by_filters(struct ip_addr *ip, unsigned short port,
							str *domain_filter, int type)
{
	char addr_buf[64];
	str addr_s;
	struct dom_filt_array *dom_array;
	void **val;
	int i;
	str match_any_s = str_init("*");
	char fnm_s[256];

	if (dom_lock)
		lock_start_read(dom_lock);

	sprintf(addr_buf, "%s:%d", ip_addr2a(ip), port);
	addr_s.s = addr_buf;
	addr_s.len = strlen(addr_buf);

	val = map_find(type == DOM_FLAG_SRV ?
					server_dom_matching : client_dom_matching, addr_s);
	if (!val) {
		/* try to find domains which match any address */
		val = map_find(type == DOM_FLAG_SRV ?
						server_dom_matching : client_dom_matching, match_any_s);
		if (!val) {
			if (dom_lock)
				lock_stop_read(dom_lock);
			return NULL;
		} else
			dom_array = (struct dom_filt_array *)*val;
	} else
		dom_array = (struct dom_filt_array *)*val;

	for (i = 0; i < dom_array->size; i++) {
		memcpy(fnm_s, domain_filter->s, domain_filter->len);
		fnm_s[domain_filter->len] = 0;
		if (!fnmatch(dom_array->arr[i].hostname->s.s, fnm_s, 0)) {
			ref_tls_dom(dom_array->arr[i].dom_link);
			if (dom_lock)
				lock_stop_read(dom_lock);
			return dom_array->arr[i].dom_link;
		}
	}

	if (dom_lock)
		lock_stop_read(dom_lock);

	return NULL;
}

/*
 * find TLS client domain by name
 * return NULL if virtual domain not found
 */
struct tls_domain *tls_find_client_domain_name(str *name)
{
	struct tls_domain *d;

	if (dom_lock)
		lock_start_read(dom_lock);

	d = tls_find_domain_by_name(name, tls_client_domains);
	if (d)
		ref_tls_dom(d);

	if (dom_lock)
		lock_stop_read(dom_lock);

	return d;
}

/*
 * find TLS client domain
 * return NULL if virtual domain not found
 */
struct tls_domain *tls_find_client_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *dom = NULL;
	struct usr_avp *tls_dom_avp = NULL, *sip_dom_avp = NULL;
	int_str val;
	str match_any_dom = str_init("*");
	str *sip_domain = &match_any_dom;

	if (tls_client_domain_avp > 0) {
		tls_dom_avp = search_first_avp(0, tls_client_domain_avp, &val, 0);
		if (!tls_dom_avp) {
			if (sip_client_domain_avp > 0) {
				sip_dom_avp = search_first_avp(0, sip_client_domain_avp, &val, 0);
				if (sip_dom_avp) {
					sip_domain = &val.s;
					LM_DBG("Match TLS domain by sip domain AVP: '%.*s'\n",
						val.s.len, ZSW(val.s.s));
				}
			}
		} else
			sip_domain = NULL;  /* search by tls domain name */
	} else {
		if (sip_client_domain_avp > 0) {
			sip_dom_avp = search_first_avp(0, sip_client_domain_avp, &val, 0);
			if (sip_dom_avp) {
				sip_domain = &val.s;
				LM_DBG("Match TLS domain by sip domain AVP: '%.*s'\n",
					val.s.len, ZSW(val.s.s));
			}
		}
	}

	if (!sip_domain)
		dom = tls_find_client_domain_name(&val.s);
	else
		dom = tls_find_domain_by_filters(ip, port, sip_domain, DOM_FLAG_CLI);

	if (dom)
			LM_DBG("found TLS client domain: %.*s\n",
				dom->name.len, dom->name.s);

	return dom;
}

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
int tls_new_domain(str *name, int type, struct tls_domain **dom)
{
	struct tls_domain *d;

	LM_DBG("adding new domain: [%.*s] type %d\n", name->len, name->s, type);

	d = shm_malloc(sizeof(struct tls_domain) + name->len);
	if (d == NULL) {
		LM_ERR("No more shm memory\n");
		return -1;
	}

	memset(d, 0, sizeof(struct tls_domain));

	d->lock = lock_alloc();
	if (!d->lock){
		LM_ERR("Failed to allocate lock\n");
		shm_free(d);
		return -1;
	}

	if (lock_init(d->lock) == NULL) {
		LM_ERR("Failed to init lock\n");
		shm_free(d);
		return -1;
	}

	d->name.s = (char*)(d+1);
	d->name.len = name->len;
	memcpy(d->name.s, name->s, name->len);

	d->flags |= type;
	d->crl_check_all = crl_check_all;

	if (type == DOM_FLAG_SRV) {
		d->verify_cert         = tls_verify_client_cert;
		d->require_client_cert = tls_require_client_cert;
	} else {
		d->verify_cert         = tls_verify_server_cert;
		d->require_client_cert = 0;
	}
	d->method = TLS_METHOD_UNSPEC;

	d->refs = 1;

	d->next = *dom;
	*dom = d;

	return 0;
}

static int add_match_filt_to_dom(str *filter_s, str_list **filter_list)
{
	str_list *match_filt;

	match_filt = shm_malloc(sizeof *match_filt);
	if (!match_filt) {
		LM_ERR("No more shm mem\n");
		return -1;
	}
	if (shm_nt_str_dup(&match_filt->s, filter_s) < 0) {
		shm_free(match_filt);
		return -1;
	}

	match_filt->next = *filter_list;
	*filter_list = match_filt;

	return 0;
}

int parse_match_domains(struct tls_domain *tls_dom, str *domains_s)
{
	csv_record *list, *it;
	str match_any_s = str_init("*");

	if (domains_s->s) {
		list = parse_csv_record(domains_s);
		if (!list) {
			LM_ERR("Failed to parse CSV record\n");
			return -1;
		}

		for (it = list; it; it = it->next)
			if (add_match_filt_to_dom(&it->s, &tls_dom->match_domains) < 0) {
				free_csv_record(list);
				return -1;
			}

		free_csv_record(list);
	} else {
		/* an empty domain filter list is equivalent with mathcing any domain */
		if (add_match_filt_to_dom(&match_any_s, &tls_dom->match_domains) < 0)
			return -1;
	}

	return 0;
}

static int parse_domain_address(char *val, unsigned int len, struct ip_addr **ip,
								unsigned int *port)
{
	char *p = val;
	str s;

	/* get the IP */
	s.s = p;
	if ((p = q_memrchr(p, ':', len)) == NULL) {
		LM_ERR("TLS domain address has to be in [IP:port] format\n");
		goto parse_err;
	}
	s.len = p - s.s;
	p++;
	if ((*ip = str2ip(&s)) == NULL && (*ip = str2ip6(&s)) == NULL) {
		LM_ERR("[%.*s] is not an ip\n", s.len, s.s);
		goto parse_err;
	}

	/* what is left should be a port */
	s.s = p;
	s.len = val + len - p;
	if (str2int(&s, port) < 0) {
		LM_ERR("[%.*s] is not a port\n", s.len, s.s);
		goto parse_err;
	}

	return 0;

parse_err:
	LM_ERR("invalid TLS domain address [%s]\n", val);
	return -1;
}

int parse_match_addresses(struct tls_domain *tls_dom, str *addresses_s)
{
	csv_record *list, *it;
	str match_any_s = str_init("*");
	struct ip_addr *addr;
	char addr_buf[64];
	str addr_s;
	unsigned int port;

	if (addresses_s->s) {
		if (addresses_s->s[0] == MATCH_ANY_VAL) {
			if (add_match_filt_to_dom(&match_any_s, &tls_dom->match_addresses) < 0)
				return -1;

			return 0;
		}

		list = parse_csv_record(addresses_s);
		if (!list) {
			LM_ERR("Failed to parse CSV record\n");
			return -1;
		}
		for (it = list; it; it = it->next) {
			if (parse_domain_address(it->s.s, it->s.len, &addr, &port) < 0) {
				LM_ERR("Failed to parse address filter: %.*s\n", it->s.len,
					it->s.s);
				free_csv_record(list);
				return -1;
			}

			sprintf(addr_buf, "%s:%d", ip_addr2a(addr), port);
			addr_s.s = addr_buf;
			addr_s.len = strlen(addr_buf);
			if (add_match_filt_to_dom(&addr_s, &tls_dom->match_addresses) < 0) {
				free_csv_record(list);
				return -1;
			}
		}

		free_csv_record(list);
	} else
		if (add_match_filt_to_dom(&match_any_s, &tls_dom->match_addresses) < 0)
				return -1;

	return 0;
}

int db_add_domain(char **str_vals, int *int_vals, str* blob_vals,
			struct tls_domain **serv_dom, struct tls_domain **cli_dom,
			struct tls_domain *script_srv_doms, struct tls_domain *script_cli_doms)
{
	str name, addresses_s, domains_s;

	name.s = str_vals[STR_VALS_DOMAIN_COL];
	name.len = name.s ? strlen(name.s) : 0;
	if (name.len == 0) {
		LM_ERR("DB defined domain, id: %d, must have a name\n", int_vals[INT_VALS_ID_COL]);
		return -1;
	}

	addresses_s.s = str_vals[STR_VALS_MATCH_ADDRESS_COL];
	addresses_s.len = addresses_s.s ? strlen(addresses_s.s) : 0;

	domains_s.s = str_vals[STR_VALS_MATCH_DOMAIN_COL];
	domains_s.len = domains_s.s ? strlen(domains_s.s) : 0;

	if (int_vals[INT_VALS_TYPE_COL] == CLIENT_DOMAIN_TYPE) {
		if (tls_find_domain_by_name(&name, cli_dom) ||
			tls_find_domain_by_name(&name, &script_cli_doms)) {
			LM_ERR("Domain: [%.*s] already defined\n", name.len, name.s);
			return -1;
		}

		if (tls_new_domain(&name, DOM_FLAG_CLI, cli_dom) < 0) {
			LM_ERR("failed to add new client domain [%.*s]\n",
				name.len, name.s);
			return -1;
		}

		if (parse_match_addresses(*cli_dom, &addresses_s) < 0) {
			LM_ERR("Failed to parse address matching filters\n");
			return -1;
		}
		if (parse_match_domains(*cli_dom, &domains_s) < 0) {
			LM_ERR("Failed to parse domain matching filters\n");
			return -1;
		}

		(*cli_dom)->flags |= DOM_FLAG_DB;

		if (set_all_domain_attr(cli_dom, str_vals, int_vals, blob_vals) < 0) {
			LM_ERR("failed to set domain [%.*s] attributes\n", name.len, name.s);
			return -1;
		}
	} else if (int_vals[INT_VALS_TYPE_COL] == SERVER_DOMAIN_TYPE) {
		if (tls_find_domain_by_name(&name, serv_dom) ||
			tls_find_domain_by_name(&name, &script_srv_doms)) {
			LM_ERR("Domain name: [%.*s] already defined\n", name.len, name.s);
			return -1;
		}

		if (tls_new_domain(&name, DOM_FLAG_SRV, serv_dom) < 0) {
			LM_ERR("failed to add new server domain [%.*s]\n",
				name.len, name.s);
			return -1;
		}

		if (parse_match_addresses(*serv_dom, &addresses_s) < 0) {
			LM_ERR("Failed to parse address matching filters\n");
			return -1;
		}

		if (parse_match_domains(*serv_dom, &domains_s) < 0) {
			LM_ERR("Failed to parse domain matching filters\n");
			return -1;
		}

		(*serv_dom)->flags |= DOM_FLAG_DB;

		if (set_all_domain_attr(serv_dom, str_vals, int_vals,blob_vals) < 0) {
			LM_ERR("failed to set domain [%.*s] attributes\n", name.len, name.s);
			return -1;
		}
	} else {
		LM_ERR("unknown TLS domain type [%d] in DB\n",
			int_vals[INT_VALS_TYPE_COL]);
		return -1;
	}

	return 0;
}

int update_matching_map(struct tls_domain *tls_dom)
{
	str_list *addrf_s, *domf_s;
	struct dom_filt_array *doms_array;
	void **val;
	int pos;

	for (addrf_s = tls_dom->match_addresses; addrf_s; addrf_s = addrf_s->next) {
		val = map_get(tls_dom->flags & DOM_FLAG_SRV ?
			server_dom_matching : client_dom_matching, addrf_s->s);
		if (!val) {
			LM_ERR("No more shm memory!\n");
			return -1;
		}

		if (!*val) {
			doms_array = shm_malloc(sizeof *doms_array);
			if (!doms_array) {
				LM_ERR("No more shm memory!\n");
				return -1;
			}
			memset(doms_array, 0, sizeof *doms_array);
			*val = doms_array;
		} else
			doms_array = (struct dom_filt_array *)*val;

		/* map this address to each domain filter of this tls domain */
		for (domf_s = tls_dom->match_domains; domf_s; domf_s = domf_s->next) {
			pos = (doms_array->size)++;
			doms_array->arr[pos].hostname = domf_s;
			doms_array->arr[pos].dom_link = tls_dom;
		}
	}

	return 0;
}

int compare_dom_filters(const void *p1, const void *p2)
{
	struct domain_filter *d1 = (struct domain_filter *)p1;
	struct domain_filter *d2 = (struct domain_filter *)p2;

	if (d1->hostname->s.len == 1 && d1->hostname->s.s[0] == MATCH_ANY_VAL) {
		/* if d1 is '*', it is 'greater' than any other value of d2 (except '*') */
		if (d2->hostname->s.len == 1 && d2->hostname->s.s[0] == MATCH_ANY_VAL)
			return 0;
		else
			return 1;
	} else {
		/* if d1 is not '*' and d2 is '*', d1 is 'smaller' */
		if (d2->hostname->s.len == 1 && d2->hostname->s.s[0] == MATCH_ANY_VAL)
			return -1;
		else {
			/* if d1 contains '*', it is 'greater' than any other value of d2
			 * (except if d2 also contains '*') */
			if (q_memchr(d1->hostname->s.s, MATCH_ANY_VAL, d1->hostname->s.len)) {
				if (q_memchr(d2->hostname->s.s, MATCH_ANY_VAL, d2->hostname->s.len))
					return 0;
				else
					return 1;
			} else {
				if (q_memchr(d2->hostname->s.s, MATCH_ANY_VAL, d2->hostname->s.len))
					return -1;
				else
					return 0;
			}
		}
	}
}

int sort_map_dom_arrays(map_t matching_map)
{
	map_iterator_t it;
	struct dom_filt_array *doms_array;
	void **val;

	if (map_first(matching_map, &it) < 0) {
		LM_ERR("Matching map does not exist\n");
		return -1;
	}

	while (iterator_is_valid(&it)) {
		val = iterator_val(&it);
		if (!val) {
			LM_ERR("Failed to get map value\n");
			return -1;
		}
		doms_array = (struct dom_filt_array *)*val;
		qsort(doms_array->arr, doms_array->size, sizeof(struct domain_filter),
			compare_dom_filters);

		if (iterator_next(&it) < 0) {
			LM_ERR("Failed to iterate to next element in matching map\n");
			return -1;
		}
	}

	return 0;
}

