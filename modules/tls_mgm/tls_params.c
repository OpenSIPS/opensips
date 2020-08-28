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
	str name;

	name.s = (char *)val;
	name.len = strlen(name.s);

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
	if (tls_new_domain(&name, DOM_FLAG_SRV, tls_server_domains) < 0) {
		LM_ERR("failed to add new server domain [%.*s]\n", name.len, name.s);
		return -1;
	}

	return 1;
}


int tlsp_add_cli_domain(modparam_t type, void *val)
{
	str name;

	name.s = (char *)val;
	name.len = strlen(name.s);

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
	if (tls_new_domain(&name, DOM_FLAG_CLI, tls_client_domains) < 0) {
		LM_ERR("failed to add new client domain [%.*s]\n", name.len, name.s);
		return -1;
	}

	return 1;
}


static int split_param_val(char *in, str *name, str *val)
{
	char *p = (char*)in;

	/* format is '[name]value' */

	/* trim spaces at the beginning */
	while (*p && isspace(*p)) p++;

	/* get the domain name */
	name->s = p;
	if (*p != '[') {
		LM_ERR("No TLS domain name\n");
		return -1;
	}
	p++;
	if ((p = strchr(p, ']')) == NULL) {
		LM_ERR("Invalid TLS domain name, no mathcing ']' character\n");
		return -1;
	}
	name->s++; /* skip '[' */
	name->len = p - name->s;
	if (name->len == 0) {
		LM_ERR("Empty TLS domain name\n");
		return -1;
	}
	p++; /* skip ']' */

	/* what is left should be the value */
	val->s = p;
	val->len = in + strlen(in) - p;
	if (val->len == 0) {
		LM_ERR("Empty value\n");
		return -1;
	}

	return 0;
}


#define set_domain_attr( _name, _field, _val) \
	do { \
		struct tls_domain *_d; \
		_d = tls_find_domain_by_name(&(_name), tls_server_domains); \
		if (!_d && (_d = tls_find_domain_by_name(&(_name), tls_client_domains)) == NULL) { \
			LM_ERR("TLS domain [%.*s] not defined in '%s'\n", \
				(_name).len, (_name).s, (char*)in); \
			return -1; \
		} \
		_d->_field = _val; \
	} while(0)


int tlsp_set_match_addr(modparam_t type, void *in)
{
	str name;
	str val;
	struct tls_domain *d;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	d = tls_find_domain_by_name(&name, tls_server_domains);
	if (!d && (d = tls_find_domain_by_name(&name, tls_client_domains)) == NULL) {
		LM_ERR("TLS domain [%.*s] not defined\n", name.len, name.s);
		return -1;
	}

	if (parse_match_addresses(d, &val) < 0) {
		LM_ERR("Failed to parse domain matching filters for domain [%.*s]\n",
			d->name.len, d->name.s);
		return -1;
	}

	return 1;
}

int tlsp_set_match_dom(modparam_t type, void *in)
{
	str name;
	str val;
	struct tls_domain *d;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	d = tls_find_domain_by_name(&name, tls_server_domains);
	if (!d && (d = tls_find_domain_by_name(&name, tls_client_domains)) == NULL) {
		LM_ERR("TLS domain [%.*s] not defined\n", name.len, name.s);
		return -1;
	}

	if (parse_match_domains(d, &val) < 0) {
		LM_ERR("Failed to parse domain matching filters for domain [%.*s]\n",
			d->name.len, d->name.s);
		return -1;
	}

	return 1;
}

int tlsp_set_method(modparam_t type, void *in)
{
	str name;
	str val;
	enum tls_method method, method_max;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	if (tls_get_method(&val, &method, &method_max) < 0)
		return -1;

	set_domain_attr(name, method, method);
	set_domain_attr(name, method_max, method_max);

	return 1;
}


int tlsp_set_verify(modparam_t type, void *in)
{
	str name;
	str val;
	unsigned int verify;

	if (split_param_val((char*)in, &name, &val) < 0)
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

	set_domain_attr(name, crl_directory, val.s);
	return 1;
}

int tlsp_set_certificate(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
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

	set_domain_attr(name, pkey, val);
	return 1;
}


int tlsp_set_calist(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
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

	set_domain_attr(name, ca_directory, val.s);
	return 1;
}


int tlsp_set_cplist(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
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

	set_domain_attr(name, dh_param, val);
	return 1;
}


int tlsp_set_eccurve(modparam_t type, void *in)
{
	str name;
	str val;

	if (split_param_val((char*)in, &name, &val) < 0)
		return -1;

	set_domain_attr(name, tls_ec_curve, val.s);
	return 1;
}
