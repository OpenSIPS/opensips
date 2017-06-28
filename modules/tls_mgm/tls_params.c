/*
 * Copyright (C) 2015 OpenSIPS Solutions
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
 *
 *
 * History:
 * -------
 *  2015-02-18  first version (bogdan)
 */


#include <string.h>

#include "../../dprint.h"
#include "../../resolve.h"  /* for str2ip() */
#include "../../ut.h"

#include "tls_params.h"
#include "api.h"


int tlsp_add_srv_domain(modparam_t type, void *val)
{
	struct ip_addr *ip = NULL;
	unsigned int port;
	str name;

	if (parse_domain_def((char*)val, &name, &ip, &port) < 0)
		return -1;

	if (ip == NULL) {
		LM_ERR("server domains must have an address\n");
		return -1;
	}

	if (tls_server_domains == NULL) {
		tls_server_domains = shm_malloc(sizeof *tls_server_domains);
		if (!tls_server_domains) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_server_domains = NULL;
	}

	if (tls_find_domain_by_name(&name, tls_server_domains)) {
		LM_ERR("Domain name: [%.*s] already defined\n", name.len, name.s);
		return -1;
	}

	/* add domain */
	if (tls_new_server_domain(&name, ip, port, tls_server_domains) < 0) {
		LM_ERR("failed to add new server domain [%.*s]\n", name.len, name.s);
		return -1;
	}

	return 1;
}


int tlsp_add_cli_domain(modparam_t type, void *val)
{
	struct ip_addr *ip = NULL;
	unsigned int port = 0;
	str name;

	if (parse_domain_def((char*)val, &name, &ip, &port) < 0)
		return -1;

	if (tls_client_domains == NULL) {
		tls_client_domains = shm_malloc(sizeof *tls_client_domains);
		if (!tls_client_domains) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_client_domains = NULL;
	}

	if (tls_find_domain_by_name(&name, tls_client_domains)) {
		LM_ERR("Domain name: [%.*s] already defined\n", name.len, name.s);
		return -1;
	}

	/* add domain */
	if (tls_new_client_domain(&name, ip, port, tls_client_domains) < 0) {
		LM_ERR("failed to add new client domain [%.*s]\n", name.len, name.s);
		return -1;
	}

	return 1;
}


static int split_param_val(char *in, str *name, str *val)
{
	char *p = (char*)in;

	/* format is '[name]value' or 'value' */

	/* trim spaces at the beginning */
	while (*p && isspace(*p)) p++;

	/* first try to get the name */
	name->s = p;
	if (*p != '[')
		goto just_value;

	p++;

	if ((p = strchr(p, ']')) == NULL) {
		LM_ERR("Invalid domain name, no mathcing ']' character\n");
		return -1;
	}

	/* name found */
	name->s++; /* skip '[' */
	name->len = p - name->s;
	p++; /* skip ']' */

	/* what is left should be the value */
	val->s = p;
	val->len = in + strlen(in) - p;
	if (val->len == 0) {
		LM_ERR("Empty value\n");
		return -1;
	}

	return 0;

just_value:
	val->s = name->s;
	val->len = strlen(val->s);
	if (val->len == 0) {
		LM_ERR("Empty value\n");
		return -1;
	}

	name->s = NULL;
	name->len = 0;

	return 0;
}


#define set_domain_attr( _name, _field, _val) \
	do { \
		struct tls_domain *_d; \
		if ((_name).s) { \
			/* specific TLS domain */ \
			_d = tls_find_domain_by_name(&(_name), tls_server_domains); \
			if (!_d && (_d = tls_find_domain_by_name(&(_name), tls_client_domains)) == NULL) { \
				LM_ERR("TLS domain [%.*s] not defined in '%s'\n", \
					(_name).len, (_name).s, (char*)in); \
				return -1; \
			} \
			_d->_field = _val; \
		} else { \
			/* set default domains */ \
			(*tls_default_server_domain)->_field = _val; \
			(*tls_default_client_domain)->_field = _val; \
		} \
	} while(0)

static int set_up_default_doms(void) {
	int no_cli = 0, no_srv = 0;

	if (!tls_default_server_domain)
		no_srv = 1;
	if (!tls_default_client_domain)
		no_cli = 1;

	if (aloc_default_doms_ptr() < 0)
		return -1;

	if (no_srv && tls_new_default_domain(TLS_DOMAIN_SRV, tls_default_server_domain) < 0) {
		LM_ERR("Failed to add default server domain\n");
		return -1;
	}
	if (no_cli && tls_new_default_domain(TLS_DOMAIN_CLI, tls_default_client_domain) < 0) {
		LM_ERR("Failed to add default client domain\n");
		return -1;
	}

	return 0;
}

int tlsp_set_method(modparam_t type, void *in)
{
	str name;
	str val;
	int method;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	if (strcasecmp(val.s, "SSLV23")==0 || strcasecmp(val.s, "TLSany")==0 )
		method = TLS_USE_SSLv23;
	else if (strcasecmp(val.s, "TLSV1")==0 )
		method = TLS_USE_TLSv1;
	else if (strcasecmp(val.s, "TLSV1_2")==0 )
		method = TLS_USE_TLSv1_2;
	else {
		LM_ERR("unsupported method [%s]\n",val.s);
		return -1;
	}

	set_domain_attr(name, method, method);

	return 1;
}


int tlsp_set_verify(modparam_t type, void *in)
{
	str name;
	str val;
	unsigned int verify;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &verify)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}

	set_domain_attr(name, verify_cert, verify);

	return 1;
}


int tlsp_set_require(modparam_t type, void *in)
{
	str name;
	str val;
	unsigned int req;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &req)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}
	
	set_domain_attr(name, require_client_cert, req);
	return 1;
}

int tlsp_set_crl_check(modparam_t type, void *in)
{
	str name;
	str val;
	unsigned int check;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &check)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}

	set_domain_attr(name, crl_check_all, check);
	return 1;
}

int tlsp_set_crldir(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, crl_directory, val.s);
	return 1;
}

int tlsp_set_certificate(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;
	
	set_domain_attr(name, cert, val);
	return 1;
}


int tlsp_set_pk(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, pkey, val);
	return 1;
}


int tlsp_set_calist(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, ca, val);
	return 1;
}


int tlsp_set_cadir(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, ca_directory, val.s);
	return 1;
}


int tlsp_set_cplist(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, ciphers_list, val.s);
	return 1;
}


int tlsp_set_dhparams(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, dh_param, val);
	return 1;
}


int tlsp_set_eccurve(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (!name.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(name, tls_ec_curve, val.s);
	return 1;
}
