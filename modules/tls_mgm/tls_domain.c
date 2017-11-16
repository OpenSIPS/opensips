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
#include "tls_domain.h"
#include "tls_params.h"
#include "api.h"
#include <stdlib.h>

struct tls_domain **tls_server_domains;
struct tls_domain **tls_client_domains;
struct tls_domain **tls_default_server_domain;
struct tls_domain **tls_default_client_domain;
struct tls_domain *tls_def_srv_dom_orig, *tls_def_cli_dom_orig;

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

	for (d = dom; d && d->type & TLS_DOMAIN_DB; d = d->next) ;

	return d;
}

void tls_release_domain_aux(struct tls_domain *dom)
{
	dom->refs--;
	if (dom->refs == 0) {
		SSL_CTX_free(dom->ctx);
		lock_destroy(dom->lock);
		lock_dealloc(dom->lock);
		shm_free(dom);
	}
}

/* frees the DB domains */
void tls_release_db_domains(struct tls_domain *dom)
{
	struct tls_domain *tmp;

	while (dom && dom->type & TLS_DOMAIN_DB) {
		tmp = dom;
		dom = dom->next;
		tls_release_domain_aux(tmp);
	}
}

void tls_release_domain(struct tls_domain* dom)
{
	if (!dom || !(dom->type & TLS_DOMAIN_DB))
		return;

	if (dom_lock)
		lock_start_write(dom_lock);

	tls_release_domain_aux(dom);

	if (dom_lock)
		lock_stop_write(dom_lock);
}

int set_all_domain_attr(struct tls_domain **dom, char **str_vals, int *int_vals,
							str* blob_vals)
{
	size_t len;
	char *p;
	struct tls_domain *d = *dom;
	size_t cadir_len = strlen(str_vals[STR_VALS_CADIR_COL]);
	size_t cplist_len = strlen(str_vals[STR_VALS_CPLIST_COL]);
	size_t crl_dir_len = strlen(str_vals[STR_VALS_CRL_DIR_COL]);
	size_t eccurve_len = strlen(str_vals[STR_VALS_ECCURVE_COL]);
	char name_buf[255];
	int name_len;

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
		LM_ERR("insufficient shm memory");
		d = *dom;
		*dom = (*dom)->next;
		shm_free(d);
		return -1;
	}

	*dom = d;
	if (strcasecmp(str_vals[STR_VALS_METHOD_COL], "SSLV23") == 0 || strcasecmp(str_vals[STR_VALS_METHOD_COL], "TLSany") == 0)
		d->method = TLS_USE_SSLv23;
	else if (strcasecmp(str_vals[STR_VALS_METHOD_COL], "TLSV1") == 0)
		d->method = TLS_USE_TLSv1;
	else if (strcasecmp(str_vals[STR_VALS_METHOD_COL], "TLSV1_2") == 0)
		d->method = TLS_USE_TLSv1_2;

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
 * find server domain with given ip and port
 * return default domain if virtual domain not found
 */
struct tls_domain *
tls_find_server_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p;

	if (dom_lock)
		lock_start_read(dom_lock);

	p = *tls_server_domains;
	while (p) {
		if ((p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS server domain found\n");
			if (p->type & TLS_DOMAIN_DB) {
				lock_get(p->lock);
				p->refs++;
				lock_release(p->lock);
				if (dom_lock)
					lock_stop_read(dom_lock);
			}
			return p;
		}
		p = p->next;
	}

	lock_get((*tls_default_server_domain)->lock);
	(*tls_default_server_domain)->refs++;
	lock_release((*tls_default_server_domain)->lock);

	if (dom_lock)
		lock_stop_read(dom_lock);

	LM_DBG("virtual TLS server domain not found, "
		"Using default TLS server domain settings\n");

	return *tls_default_server_domain;
}

/*
 * find client domain with given ip and port,
 * return default domain if virtual domain not found
 */
struct tls_domain *
tls_find_client_domain_addr(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p = *tls_client_domains;
	while (p) {
		if ((p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS client domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS client domain not found, "
		"Using default TLS client domain settings\n");
	return *tls_default_client_domain;
}

/*
 * find client domain with given name,
 * return 0 if name based virtual domain not found
 */
struct tls_domain *
tls_find_client_domain_name(str name)
{
	struct tls_domain *p = *tls_client_domains;
	while (p) {
		if ((p->name.len == name.len) && !strncasecmp(p->name.s, name.s, name.len)) {
			LM_DBG("virtual TLS client domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS client domain not found\n");
	return 0;
}

/*
 * find client domain
 * return 0 if virtual domain not found
 */
struct tls_domain *tls_find_client_domain(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *dom;
	struct usr_avp *avp;
	int_str val;

	avp = NULL;

	if (tls_client_domain_avp > 0)
		avp = search_first_avp(0, tls_client_domain_avp, &val, 0);
	else
		LM_DBG("name based TLS client domain matching is disabled\n");

	if (dom_lock)
		lock_start_read(dom_lock);

	if (!avp) {
		LM_DBG("no TLS client domain AVP set, looking "
			"to match TLS client domain by scoket\n");
		dom = tls_find_client_domain_addr(ip, port);
		if (dom) {
			LM_DBG("found TLS client domain [%s:%d] based on socket\n",
				ip_addr2a(&dom->addr), dom->port);
		}
	} else {
		LM_DBG("TLS client domain AVP found = '%.*s'\n",
			val.s.len, ZSW(val.s.s));
		dom = tls_find_client_domain_name(val.s);
		if (dom) {
			LM_DBG("found TLS client domain '%.*s' by name\n",
				val.s.len, ZSW(val.s.s));
		} else {
			LM_DBG("TLS client domain not found by name, "
				"trying socket based TLS client domain matching\n");
			dom = tls_find_client_domain_addr(ip, port);
			if (dom) {
				LM_DBG("found TLS client domain [%s:%d] based on socket\n",
					ip_addr2a(&dom->addr), dom->port);
			}
		}
	}

	if (dom && dom->type & TLS_DOMAIN_DB) {
		lock_get(dom->lock);
		dom->refs++;
		lock_release(dom->lock);
	}

	if (dom_lock)
		lock_stop_read(dom_lock);

	return dom;
}

/*
 * create a new server domain
 */
int tls_new_server_domain(str *name, struct ip_addr *ip, unsigned short port,
								struct tls_domain **dom)
{
	struct tls_domain *d;

	d = tls_new_domain(name, TLS_DOMAIN_SRV);
	if (d == NULL) {
		LM_ERR("shm memory allocation failure\n");
		return -1;
	}

	/* fill socket data */
	memcpy(&d->addr, ip, sizeof(struct ip_addr));
	d->port = port;
	d->refs = 1;

	/* add this new domain to the linked list */
	d->next = *dom;
	*dom = d;

	return 0;
}

/*
 * create a new client domain
 */
int tls_new_client_domain(str *name, struct ip_addr *ip, unsigned short port,
										struct tls_domain **dom)
{
	struct tls_domain *d;

	d = tls_new_domain(name, TLS_DOMAIN_CLI);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return -1;
	}

	if (ip) {
		/* fill socket data */
		memcpy(&d->addr, ip, sizeof(struct ip_addr));
		d->port = port;
	} else
		d->addr.af = AF_INET;

	d->refs = 1;

	/* add this new domain to the linked list */
	d->next = *dom;
	*dom = d;

	return 0;
}


int aloc_default_doms_ptr(void)
{
	if (!tls_default_server_domain) {
		tls_default_server_domain = shm_malloc(sizeof *tls_default_server_domain);
		if (!tls_default_server_domain) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_default_server_domain = NULL;
	}

	if (!tls_default_client_domain) {
		tls_default_client_domain = shm_malloc(sizeof *tls_default_client_domain);
		if (!tls_default_client_domain) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_default_client_domain = NULL;
	}

	return 0;
}

int tls_new_default_domain(int type, struct tls_domain **dom)
{
	struct tls_domain *d;
	str default_name = str_init(DEFAULT_DOM_NAME_S);

	d = tls_new_domain(&default_name, type);
	if (!d) {
		LM_ERR("Failed to allocate domain\n");
		return -1;
	}

	d->refs = 1;
	d->addr.af = AF_INET;

	*dom = d;

	return 0;
}

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
struct tls_domain *tls_new_domain(str *name, int type)
{
	struct tls_domain *d;

	LM_DBG("adding new domain: [%.*s] type %d\n", name->len, name->s, type);

	d = shm_malloc(sizeof(struct tls_domain) + name->len);
	if (d == NULL) {
		LM_ERR("No more shm memory\n");
		return 0;
	}

	memset(d, 0, sizeof(struct tls_domain));

	d->lock = lock_alloc();
	if (!d->lock){
		LM_ERR("Failed to allocate lock\n");
		shm_free(d);
		return 0;
	}

	if (lock_init(d->lock) == NULL) {
		LM_ERR("Failed to init lock\n");
		shm_free(d);
		return 0;
	}

	d->name.s = (char*)(d+1);
	d->name.len = name->len;
	memcpy(d->name.s, name->s, name->len);

	d->type = type;
	d->crl_check_all = crl_check_all;

	if (type & TLS_DOMAIN_SRV) {
		d->verify_cert         = tls_verify_client_cert;
		d->require_client_cert = tls_require_client_cert;
	} else {
		d->verify_cert         = tls_verify_server_cert;
		d->require_client_cert = 0;
	}
	d->method = TLS_METHOD_UNSPEC;

	return d;
}


#define DB_ADD_DEFAULT_DOM(_def_dom, _type) \
do { \
	if (*(_def_dom) == NULL) { \
		if (tls_new_default_domain((_type), (_def_dom)) < 0) { \
			LM_ERR("Unable to add default domain\n"); \
			return -1; \
		} \
	} else { \
		LM_ERR("Default domain already defined in DB\n"); \
		return -1; \
	} \
	if (set_all_domain_attr((_def_dom), str_vals, int_vals, blob_vals) < 0) { \
		LM_ERR("Failed to set default domain attributes"); \
		return -1; \
	} \
	(*(_def_dom))->type |= TLS_DOMAIN_DB; \
} while (0)

int db_add_domain(char **str_vals, int *int_vals, str* blob_vals,
			struct tls_domain **serv_dom, struct tls_domain **cli_dom,
			struct tls_domain **def_serv_dom, struct tls_domain **def_cli_dom,
			struct tls_domain *script_srv_doms, struct tls_domain *script_cli_doms)
{
	struct ip_addr *ip = NULL;
	unsigned int port = 0;
	str name, address;

	name.s = str_vals[STR_VALS_DOMAIN_COL];
	name.len = name.s ? strlen(name.s) : 0;

	if (name.len == 0) {
		LM_ERR("DB defined domain id: %d must have a name\n", int_vals[INT_VALS_ID_COL]);
		return -1;
	}

	address.s = str_vals[STR_VALS_ADDRESS_COL];
	address.len = address.s ? strlen(address.s) : 0;

	if (int_vals[INT_VALS_TYPE_COL] == CLIENT_DOMAIN) {
		if (tls_find_domain_by_name(&name, cli_dom) ||
			tls_find_domain_by_name(&name, &script_cli_doms)) {
			LM_ERR("Domain name: [%.*s] already defined\n", name.len, name.s);
			return -1;
		}

		if (!memcmp(name.s, DEFAULT_DOM_NAME_S, DEFAULT_DOM_NAME_LEN)) {
			/* default client domain */
			DB_ADD_DEFAULT_DOM(def_cli_dom, TLS_DOMAIN_CLI);

			return 0;
		}

		if (address.len && parse_domain_address(address.s, address.len, &ip, &port) < 0)
			return -1;

		if (tls_new_client_domain(&name, ip, port, cli_dom) < 0) {
			LM_ERR("failed to add new client domain [%.*s]\n",
				name.len, name.s);
			return -1;
		}

		(*cli_dom)->type |= TLS_DOMAIN_DB;

		if (set_all_domain_attr(cli_dom, str_vals, int_vals, blob_vals) < 0) {
			LM_ERR("failed to set domain [%.*s] attributes\n", name.len, name.s);
			return -1;
		}
	} else if (int_vals[INT_VALS_TYPE_COL] == SERVER_DOMAIN) {
		if (tls_find_domain_by_name(&name, serv_dom) ||
			tls_find_domain_by_name(&name, &script_srv_doms)) {
			LM_ERR("Domain name: [%.*s] already defined\n", name.len, name.s);
			return -1;
		}

		if (!memcmp(name.s, DEFAULT_DOM_NAME_S, DEFAULT_DOM_NAME_LEN)) {
			/* default server domain */
			DB_ADD_DEFAULT_DOM(def_serv_dom, TLS_DOMAIN_SRV);

			return 0;
		}

		if (address.len == 0) {
			LM_ERR("Server domain must have an address\n");
			return -1;
		}

		if (parse_domain_address(address.s, address.len, &ip, &port) < 0)
			return -1;

		if (tls_new_server_domain(&name, ip, port, serv_dom) < 0) {
			LM_ERR("failed to add new server domain [%.*s]\n", name.len, name.s);
			return -1;
		}

		(*serv_dom)->type |= TLS_DOMAIN_DB;

		if (set_all_domain_attr(serv_dom, str_vals, int_vals,blob_vals) < 0) {
			LM_ERR("failed to set domain [%.*s] attr\n", name.len, name.s);
			return -1;
		}
	} else if (int_vals[INT_VALS_TYPE_COL] == DEFAULT_DOM_BOTH) {
		if (memcmp(name.s, DEFAULT_DOM_NAME_S, DEFAULT_DOM_NAME_LEN)) {
			LM_ERR("This type is only for default domains\n");
			return -1;
		}

		DB_ADD_DEFAULT_DOM(def_cli_dom, TLS_DOMAIN_CLI);

		DB_ADD_DEFAULT_DOM(def_serv_dom, TLS_DOMAIN_SRV);
	} else {
		LM_ERR("unknown TLS domain type [%d] in DB\n",
			int_vals[INT_VALS_TYPE_COL]);
		return -1;
	}

	return 0;
}

/*
 * clean up
 */
void
tls_free_domains(void)
{
	struct tls_domain *p;
	while (*tls_server_domains) {
		p = *tls_server_domains;
		*tls_server_domains = (*tls_server_domains)->next;
		shm_free(p);
	}
	while (*tls_client_domains) {
		p = *tls_client_domains;
		*tls_client_domains = (*tls_client_domains)->next;
		shm_free(p);
	}
}

