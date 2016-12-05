/*
 * File:   api.h
 * Author: cristi
 *
 * Created on September 1, 2015, 5:23 PM
 */

#ifndef TLS_API_H
#define TLS_API_H

#include "../../resolve.h"

typedef struct tls_domain * (*tls_find_server_domain_f) (struct ip_addr *, unsigned short);
typedef struct tls_domain * (*tls_find_client_domain_f) (struct ip_addr *, unsigned short);
typedef int (*get_send_timeout_f) (void);
typedef int (*get_handshake_timeout_f) (void);
typedef void (*tls_release_domain_f) (struct tls_domain *);

struct tls_mgm_binds {
    get_send_timeout_f get_send_timeout;
    get_handshake_timeout_f get_handshake_timeout;
    tls_find_server_domain_f find_server_domain;
    tls_find_client_domain_f find_client_domain;
    tls_release_domain_f release_domain;
};


typedef int(*load_tls_mgm_f)(struct tls_mgm_binds *binds);

static int parse_domain_address(char *val, struct ip_addr **ip,
											unsigned int *port, str *domain)
{
	char *p = (char*)val;
	str s;

	/* get IP */
	s.s = p;
	if ( (p=strchr( p, ':'))==NULL )
		goto has_domain;
	s.len = p-s.s;
	p++;
	if ( (*ip=str2ip( &s ))==NULL ) {
		LM_ERR("[%.*s] is not an ip\n", s.len, s.s);
		goto parse_err;
	}

	/* what is left should be a port */
	s.s = p;
	s.len = val + strlen(val) - p;
	if (str2int( &s, port)<0) {
		LM_ERR("[%.*s] is not a port\n", s.len, s.s);
		goto parse_err;
	}

	return 0;

has_domain:
	/* what is left should be a domain */
	domain->s = s.s;
	domain->len = val + strlen(val) - s.s;
	*ip = NULL;

	return 0;
parse_err:
	LM_ERR("invalid TLS domain [%s] (error around pos %d)\n",
		val, (int)(long)(p-val) );
	return -1;
}

static inline int parse_domain_def(char *val, str *id, struct ip_addr **ip,
											unsigned int *port, str *domain)
{
	char *p = (char*)val;

	if (!val)
		goto parse_err;

	/* first get the ID */
	id->s = p;
	if ( (p=strchr( p, '='))==NULL )
		goto parse_err;
	id->len = p-id->s;
	p++;

	return parse_domain_address(p, ip, port, domain);

parse_err:
	LM_ERR("invalid TLS domain [%s] (error around pos %d)\n",
		val, (int)(long)(p-val) );
	return -1;
}

static inline int load_tls_mgm_api(struct tls_mgm_binds *binds) {
    load_tls_mgm_f load_tls;

    /* import the DLG auto-loading function */
    if (!(load_tls = (load_tls_mgm_f) find_export("load_tls_mgm", 0, 0)))
        return -1;

    /* let the auto-loading function load all DLG stuff */
    if (load_tls(binds) == -1)
        return -1;

    return 0;
}

#endif	/* TLS_API_H */
