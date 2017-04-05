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
#include <stdlib.h>

struct tls_domain *tls_server_domains;
struct tls_domain *tls_client_domains;
struct tls_domain tls_default_server_domain;
struct tls_domain tls_default_client_domain;

rw_lock_t *dom_lock;

struct tls_domain *tls_find_domain_by_id( str *id)
{
	struct tls_domain *d;
	if (tls_db_enabled)
		lock_start_read(dom_lock);
	for (d=tls_server_domains ; d ; d=d->next ) {
		if (id->len==d->id.len && memcmp(id->s,d->id.s,id->len)==0) {
			if (tls_db_enabled)
				lock_stop_read(dom_lock);
			return d;
		}
	}
	for (d=tls_client_domains ; d ; d=d->next ) {
		if (id->len==d->id.len && memcmp(id->s,d->id.s,id->len)==0) {
			if (tls_db_enabled)
				lock_stop_read(dom_lock);
			return d;
		}
	}
	if (tls_db_enabled)
		lock_stop_read(dom_lock);
	return NULL;
}


void tls_release_domain_aux(struct tls_domain *dom)
{
	dom->refs--;
	if (dom->refs == 0) {
		if (dom->name.s)
			shm_free(dom->name.s);
		SSL_CTX_free(dom->ctx);
		lock_destroy(dom->lock);
		lock_dealloc(dom->lock);
		shm_free(dom);
	}
}

void tls_release_all_domains(struct tls_domain *dom)
{
	while (dom) {
		tls_release_domain_aux(dom);
		dom = dom->next;
	}
}

void tls_release_domain(struct tls_domain* dom)
{
	if (!dom || !tls_db_enabled || dom == &tls_default_server_domain ||
		dom == &tls_default_client_domain)
		return;
	lock_start_write(dom_lock);
	tls_release_domain_aux(dom);
	lock_stop_write(dom_lock);
}

int set_all_domain_attr(struct tls_domain **dom, char **str_vals, int *int_vals, str* blob_vals)
{
	size_t len;
	char *p;
	struct tls_domain *d = *dom;
	size_t cadir_len = strlen(str_vals[STR_VALS_CADIR_COL]);
	size_t cplist_len = strlen(str_vals[STR_VALS_CPLIST_COL]);
	size_t crl_dir_len = strlen(str_vals[STR_VALS_CRL_DIR_COL]);
	size_t eccurve_len = strlen(str_vals[STR_VALS_ECCURVE_COL]);


	len = sizeof(struct tls_domain) +d->id.len;

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

	p = p + d->id.len;

	memset(p, 0, len - (sizeof(struct tls_domain) +d->id.len));

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
	if (tls_db_enabled)
		lock_start_read(dom_lock);
	struct tls_domain *p = tls_server_domains;
	while (p) {
		if ((p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS server domain found\n");
			if (tls_db_enabled) {
				lock_get(p->lock);
				p->refs++;
				lock_release(p->lock);
				lock_stop_read(dom_lock);
			}
			return p;
		}
		p = p->next;
	}
	if (tls_db_enabled)
		lock_stop_read(dom_lock);
	LM_DBG("virtual TLS server domain not found, "
		"Using default TLS server domain settings\n");
	return &tls_default_server_domain;
}

/*
 * find client domain with given ip and port,
 * return default domain if virtual domain not found
 */
struct tls_domain *
tls_find_client_domain_addr(struct ip_addr *ip, unsigned short port)
{
	struct tls_domain *p = tls_client_domains;
	while (p) {
		if ((p->name.len == 0) && (p->port == port) && ip_addr_cmp(&p->addr, ip)) {
			LM_DBG("virtual TLS client domain found\n");
			return p;
		}
		p = p->next;
	}
	LM_DBG("virtual TLS client domain not found, "
		"Using default TLS client domain settings\n");
	return &tls_default_client_domain;
}

/*
 * find client domain with given name,
 * return 0 if name based virtual domain not found
 */
struct tls_domain *
tls_find_client_domain_name(str name)
{
	struct tls_domain *p = tls_client_domains;
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
struct tls_domain *tls_find_client_domain(struct ip_addr *ip,
				   unsigned short port){
	struct tls_domain *dom;
	struct usr_avp *avp;
	int_str val;

	avp = NULL;

	if (tls_client_domain_avp > 0) {
		avp = search_first_avp(0, tls_client_domain_avp, &val, 0);
	} else {
		LM_DBG("name based TLS client domains are disabled\n");
	}
	if (tls_db_enabled)
		lock_start_read(dom_lock);
	if (!avp) {
		LM_DBG("no TLS client domain AVP set, looking "
			"for socket based TLS client domain\n");
		dom = tls_find_client_domain_addr(ip, port);
		if (dom) {
			LM_DBG("found socket based TLS client domain "
				"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
		}
	} else {
		LM_DBG("TLS client domain AVP found = '%.*s'\n",
			val.s.len, ZSW(val.s.s));
		dom = tls_find_client_domain_name(val.s);
		if (dom) {
			LM_DBG("found name based TLS client domain "
				"'%.*s'\n", val.s.len, ZSW(val.s.s));
		} else {
			LM_DBG("no name based TLS client domain found, "
				"trying socket based TLS client domains\n");
			dom = tls_find_client_domain_addr(ip, port);
			if (dom) {
				LM_DBG("found socket based TLS client domain [%s:%d]\n",
					ip_addr2a(&dom->addr), dom->port);
			}
		}
	}

	if (tls_db_enabled) {

		if (dom && dom != &tls_default_client_domain) {
			lock_get(dom->lock);
			dom->refs++;
			lock_release(dom->lock);
		}

		lock_stop_read(dom_lock);
	}
	return dom;
}

/*
 * create a new server domain (identified by a socket)
 */
int tls_new_server_domain( str *id, struct ip_addr *ip, unsigned short port,
								struct tls_domain **dom)
{
	struct tls_domain *d;

	d = tls_new_domain( id, TLS_DOMAIN_SRV);
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
 * create a new client domain (identified by a socket)
 */
int tls_new_client_domain(str *id, struct ip_addr *ip, unsigned short port,
										struct tls_domain **dom)
{
	struct tls_domain *d;

	d = tls_new_domain( id, TLS_DOMAIN_CLI);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
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
 * create a new client domain (identified by a string)
 */
int tls_new_client_domain_name( str *id, str *domain, struct tls_domain **dom)
{
	struct tls_domain *d;

	d = tls_new_domain( id, TLS_DOMAIN_CLI | TLS_DOMAIN_NAME);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return -1;
	}
	/* initialize name data */
	d->name.s = shm_malloc(domain->len);
	if (d->name.s == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		shm_free(d);
		return -1;
	}
	memcpy(d->name.s, domain->s, domain->len);
	d->name.len = domain->len;
	d->refs = 1;

	/* add this new domain to the linked list */
	d->next = *dom;
	*dom = d;
	return 0;
}

/*
 * allocate memory and set default values for
 * TLS domain structure
 */
struct tls_domain *tls_new_domain( str *id, int type)
{
	struct tls_domain *d;

	LM_DBG("adding new domain id: [%.*s] type %d\n", id->len, id->s, type);

	d = shm_malloc(sizeof(struct tls_domain) + id->len);
	if (d == NULL) {
		LM_ERR("pkg memory allocation failure\n");
		return 0;
	}
	
	memset( d, 0, sizeof(struct tls_domain));
	
	d->lock = lock_alloc();
	
	if (!d->lock){
		LM_ERR("failed to allocate lock \n");
		shm_free(d);
		return 0;
	}
	
	if (lock_init(d->lock) == NULL) {
		LM_ERR("Failed to init lock \n");
		shm_free(d);
		return 0;
	}

	d->id.s = (char*)(d+1);
	d->id.len = id->len;
	memcpy( d->id.s, id->s, id->len);

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

/*
 * clean up
 */
void
tls_free_domains(void)
{
	struct tls_domain *p;
	while (tls_server_domains) {
		p = tls_server_domains;
		tls_server_domains = tls_server_domains->next;
		shm_free(p);
	}
	while (tls_client_domains) {
		p = tls_client_domains;
		tls_client_domains = tls_client_domains->next;
		/* ToDo: If socket based client domains will be implemented, the name may
		   be empty (must be set to NULL manually). Thus no need to free it */
		if (p->name.s) {
			shm_free(p->name.s);
		}
		shm_free(p);
	}
}

