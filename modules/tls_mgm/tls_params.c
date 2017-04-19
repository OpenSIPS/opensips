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
	struct ip_addr *ip;
	unsigned int port;
	str domain;
	str id;

	if (parse_domain_def((char*)val, &id, &ip, &port, &domain) < 0)
		return -1;

	if (ip==NULL) {
		LM_ERR("server domains do not support 'domain name' in definition\n");
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

	/* add domain */
	if (tls_new_server_domain(&id, ip, port, tls_server_domains) < 0) {
		LM_ERR("failed to add new server domain [%s]\n",(char*)val);
		return -1;
	}

	return 1;
}


int tlsp_add_cli_domain(modparam_t type, void *val)
{
	struct ip_addr *ip;
	unsigned int port;
	str domain;
	str id;

	if (parse_domain_def((char*)val, &id, &ip, &port, &domain) < 0)
		return -1;

	if (tls_client_domains == NULL) {
		tls_client_domains = shm_malloc(sizeof *tls_client_domains);
		if (!tls_client_domains) {
			LM_ERR("No more shm mem\n");
			return -1;
		}
		*tls_client_domains = NULL;
	}

	/* add domain */
	if (ip==NULL) {
		if (tls_new_client_domain_name(&id, &domain, tls_client_domains) < 0) {
			LM_ERR("failed to add new client domain name [%s]\n",(char*)val);
			return -1;
		}
	} else {
		if (tls_new_client_domain(&id, ip, port, tls_client_domains) < 0) {
			LM_ERR("failed to add new client domain [%s]\n",(char*)val);
			return -1;
		}
	}

	return 1;
}

static int parse_address(str address, struct ip_addr **ip, unsigned int *port)
{
	char *p = address.s;
	str s;

	/* get IP */
	s.s = p;
	if ((p = strchr(p, ':')) == NULL)
		goto parse_err;
	s.len = p - s.s;
	p++;
	if ((*ip = str2ip(&s)) == NULL) {
		LM_ERR("[%.*s] is not an ip\n", s.len, s.s);
		goto parse_err;
	}

	/* what is left should be a port */
	s.s = p;
	s.len = address.s + address.len - p;
	if (str2int(&s, port) < 0) {
		LM_ERR("[%.*s] is not a port\n", s.len, s.s);
		goto parse_err;
	}

	return 0;

parse_err:
	LM_ERR("invalid address [%s]\n", address.s);
	return -1;
}

int tlsp_db_add_domain(char **str_vals, int *int_vals, str* blob_vals, 
					struct tls_domain **serv_dom, struct tls_domain **cli_dom,
					struct tls_domain **def_serv_dom, struct tls_domain **def_cli_dom)
{
	struct ip_addr *ip;
	unsigned int port;
	str domain, address;
	str id;

	id.s = int2str(int_vals[INT_VALS_ID_COL], &id.len);

	address.s = str_vals[STR_VALS_ADDRESS_COL];
	address.len = address.s ? strlen(address.s) : 0;

	/* add domain */
	if (int_vals[INT_VALS_TYPE_COL] == CLIENT_DOMAIN) {
		domain.s = str_vals[STR_VALS_DOMAIN_COL];
		domain.len = domain.s ? strlen(domain.s) : 0;

		if (domain.len) {
			/* client domain defined by domain name */
			if (tls_new_client_domain_name(&id, &domain, cli_dom) < 0) {
				LM_ERR("failed to add new client domain name [%.*s]\n",
					domain.len, domain.s);
				return -1;
			}
		} else {
			if (!address.len) {
				/* default client domain */

				if (*def_cli_dom == NULL) {
					if (tls_new_default_domain(TLS_DOMAIN_CLI, def_cli_dom) < 0) {
						LM_ERR("Unable to add default client domain\n");
						return -1;
					}
				} else {
					LM_ERR("Default client domain already defined in DB\n");
					return -1;
				}

				if (set_all_domain_attr(def_cli_dom, str_vals, int_vals, blob_vals) < 0) {
					LM_ERR("Failed to set default client domain attributes");
					return -1;
				}

				(*def_cli_dom)->type |= TLS_DOMAIN_DB;

				return 0;
			}

			/* client domain defined by address */
			if (parse_address(address, &ip, &port) < 0)
				return -1;

			if (tls_new_client_domain(&id, ip, port, cli_dom) < 0) {
				LM_ERR("failed to add new client domain [%s]\n",
					str_vals[STR_VALS_ADDRESS_COL]);
				return -1;
			}
		}

		(*cli_dom)->type |= TLS_DOMAIN_DB;

		if (set_all_domain_attr(cli_dom, str_vals, int_vals, blob_vals) < 0) {
			if (domain.len)
				LM_ERR("failed to set domain [%.*s] attributes\n", domain.len, domain.s);
			else
				LM_ERR("failed to set domain [%s] attributes\n", str_vals[STR_VALS_ADDRESS_COL]);
			return -1;
		}
	} else if (int_vals[INT_VALS_TYPE_COL] == SERVER_DOMAIN) {
		if (!address.len) {
			/* default server domain */

			if (*def_serv_dom == NULL) {
				if (tls_new_default_domain(TLS_DOMAIN_SRV, def_serv_dom) < 0) {
					LM_ERR("Unable to add default server domain\n");
					return -1;
				}
			} else {
				LM_ERR("Default server domain already defined in DB\n");
				return -1;
			}

			if (set_all_domain_attr(def_serv_dom, str_vals, int_vals, blob_vals) < 0) {
				LM_ERR("Failed to set default server domain attributes");
				return -1;
			}

			(*def_serv_dom)->type |= TLS_DOMAIN_DB;

			return 0;
		}

		if (parse_address(address, &ip, &port) < 0)
			return -1;

		if (tls_new_server_domain(&id, ip, port, serv_dom) < 0) {
			LM_ERR("failed to add new server domain [%s]\n",
				str_vals[STR_VALS_ADDRESS_COL]);
			return -1;
		}

		(*serv_dom)->type |= TLS_DOMAIN_DB;

		if (set_all_domain_attr(serv_dom, str_vals, int_vals,blob_vals) < 0) {
			LM_ERR("failed to set domain [%s] attr\n",
				str_vals[STR_VALS_ADDRESS_COL]);
			return -1;
		}
	} else {
		LM_ERR("unknown TLS domain type [%d] in DB\n", 
			int_vals[INT_VALS_TYPE_COL]);
		return -1;
	}

	return 0;
}


static void split_param_val(char *in, str *id, str *val)
{
	char *p = (char*)in;

	/* format is '[ID]value' or 'value' */

	/* trim spaces at the beginning */
	while ( *p && isspace(*p) ) p++;

	/* first try to get the ID */
	id->s = p;
	if (*p!='[')
		goto just_value;

	/* try consume an alphanumerical ID */
	p++;
	while ( *p && isalnum(*p) ) p++;
	if (*p==0)
		goto just_value;

	while ( *p && isspace(*p) ) p++;
	if (*p==0 || *p!=']')
		goto just_value;

	/* ID found */
	id->s++; /* skip '[' */
	id->len = p-id->s;
	p++; /* skip ']' */

	/* what is left should be the value */
	val->s = p;
	val->len = in + strlen(in) - p;
	return;

just_value:
	val->s = id->s;
	val->len = strlen(id->s);
	id->s = NULL;
	id->len = 0;
	return;
}


#define set_domain_attr( _id, _field, _val) \
	do { \
		struct tls_domain *_d; \
		if ((_id).s) { \
			/* specific TLS domain */ \
			if ( (_d=tls_find_domain_by_id(&(_id)))==NULL ) { \
				LM_ERR("TLS domain [%.*s] not defined in [%s]\n", \
					(_id).len, (_id).s, (char*)in); \
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
	str id;
	str val;
	int method;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
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

	set_domain_attr(id, method, method);
	return 1;
}


int tlsp_set_verify(modparam_t type, void *in)
{
	str id;
	str val;
	unsigned int verify;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &verify)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}

	set_domain_attr(id, verify_cert, verify);

	return 1;
}


int tlsp_set_require(modparam_t type, void *in)
{
	str id;
	str val;
	unsigned int req;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &req)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}
	
	set_domain_attr(id, require_client_cert, req);
	return 1;
}

int tlsp_set_crl_check(modparam_t type, void *in)
{
	str id;
	str val;
	unsigned int check;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	if (str2int(&val, &check)!=0) {
		LM_ERR("option is not a number [%s]\n",val.s);
		return -1;
	}

	set_domain_attr(id, crl_check_all, check);
	return 1;
}

int tlsp_set_crldir(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, crl_directory, val.s);
	return 1;
}

int tlsp_set_certificate(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;
	
	set_domain_attr(id, cert, val);
	return 1;
}


int tlsp_set_pk(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, pkey, val);
	return 1;
}


int tlsp_set_calist(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, ca, val);
	return 1;
}


int tlsp_set_cadir(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, ca_directory, val.s);
	return 1;
}


int tlsp_set_cplist(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, ciphers_list, val.s);
	return 1;
}


int tlsp_set_dhparams(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, dh_param, val);
	return 1;
}


int tlsp_set_eccurve(modparam_t type, void *in)
{
	str id;
	str val;

	split_param_val((char*)in, &id, &val);

	if (!id.s && set_up_default_doms() < 0)
		return -1;

	set_domain_attr(id, tls_ec_curve, val.s);
	return 1;
}
