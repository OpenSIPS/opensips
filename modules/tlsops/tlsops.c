/*$Id$
 *
 * Copyright (C) 2006 nic.at
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2006-01-26  initial version
 *
 * tls module, it implements the following commands:
 * is_peer_verified(): returns 1 if the message is received via TLS
 *     and the peer was verified during TLS connection handshake,
 *     otherwise it returns -1
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>

#include "../../sr_module.h"
#include "tlsops.h"
#include "tls_select.h"
#include "../../tcp_conn.h"    /* struct tcp_connection */
#include "../../tcp_server.h"  /* tcpconn_get() */
#include "../../sr_module.h"
#include "../../pvar.h"
#include "../../tls/tls_init.h"
#include "../../parser/parse_from.h"
#include "../../parser/digest/digest.h"


int tcp_con_lifetime=DEFAULT_TCP_CONNECTION_LIFETIME;

/* definition of exported functions */
static int is_peer_verified(struct sip_msg*, char*, char*);

/*
 * Check if To header field contains the same username
 * as digest credentials
 */
int tls_check_to(struct sip_msg* _msg, char* _str1, char* _str2);

/*
 * Check if From header field contains the same username
 * as digest credentials
 */
int tls_check_from(struct sip_msg* _msg, char* _str1, char* _str2);

/* MI function to refresh all TLS CRL & CA configuration */
static struct mi_root* mi_refresh_crl_ca(struct mi_root* cmd, void* param);

/* definition of internal functions */
static int mod_init(void);
static void mod_destroy(void);

/* Return codes reference */
#define OK 		 	 1		/* success */
#define ERR_INTERNAL		-1		/* Internal Error */
#define ERR_CREDENTIALS 	-2		/* No credentials error */
#define ERR_DBUSE  		-3		/* Data Base Use error */
#define ERR_USERNOTFOUND  	-4		/* No found username error */
#define ERR_DBEMTPYRES		-5		/* Emtpy Query Result */

#define ERR_DBACCESS	   	-7     		/* Data Base Access Error */
#define ERR_DBQUERY	  	-8		/* Data Base Query Error */
#define ERR_SPOOFEDUSER   	-9		/* Spoofed User Error */
#define ERR_NOMATCH	    	-10		/* No match Error */

/*
 * Module parameter variables
 */

/*
 * Exported functions
 */
static cmd_export_t cmds[]={
	{"is_peer_verified", (cmd_function)is_peer_verified,   0, 0, 0,
			REQUEST_ROUTE},
	{"tls_check_to", (cmd_function)tls_check_to, 0, 0, 0,
			REQUEST_ROUTE},
	{"tls_check_from", (cmd_function)tls_check_from, 0, 0, 0,
			REQUEST_ROUTE},
	{0,0,0,0,0,0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{0,0,0}
};

/*
 * MI Commands
 */
static mi_export_t mi_cmds[] = {
		{ "refresh_crl_ca",    0, mi_refresh_crl_ca,     0,  0,  0},
		{  0,                  0, 0,                     0,  0,  0}
};

/*
 *  pseudo variables
 */
static pv_export_t mod_items[] = {
	/* TLS session parameters */
	{{"tls_version", sizeof("tls_version")-1},
		850, tlsops_version, 0,
		0, 0, 0, 0 },
	{{"tls_description", sizeof("tls_description")-1},
		850, tlsops_desc, 0,
		0, 0, 0, 0 },
	{{"tls_cipher_info", sizeof("tls_cipher_info")-1},
		850, tlsops_cipher, 0,
		0, 0, 0, 0 },
	{{"tls_cipher_bits", sizeof("tls_cipher_bits")-1},
		850,  tlsops_bits, 0,
		0, 0, 0, 0 },
	/* general certificate parameters for peer and local */
	{{"tls_peer_version", sizeof("tls_peer_version")-1},
		850, tlsops_cert_version, 0,
		0, 0, pv_init_iname, CERT_PEER  },
	{{"tls_my_version", sizeof("tls_my_version")-1},
		850, tlsops_cert_version, 0,
		0, 0, pv_init_iname, CERT_LOCAL },
	{{"tls_peer_serial", sizeof("tls_peer_serial")-1},
		850, tlsops_sn, 0,
		0, 0, pv_init_iname, CERT_PEER  },
	{{"tls_my_serial", sizeof("tls_my_serial")-1},
		850, tlsops_sn,0,
		0, 0, pv_init_iname, CERT_LOCAL },
	/* certificate parameters for peer and local, for subject and issuer*/
	{{"tls_peer_subject", sizeof("tls_peer_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT },
	{{"tls_peer_issuer", sizeof("tls_peer_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  },
	{{"tls_my_subject", sizeof("tls_my_subject")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT },
	{{"tls_my_issuer", sizeof("tls_my_issuer")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  },
	{{"tls_peer_subject_cn", sizeof("tls_peer_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_CN },
	{{"tls_peer_issuer_cn", sizeof("tls_peer_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_CN },
	{{"tls_my_subject_cn", sizeof("tls_my_subject_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_CN },
	{{"tls_my_issuer_cn", sizeof("tls_my_issuer_cn")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_CN },
	{{"tls_peer_subject_locality", sizeof("tls_peer_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_L },
	{{"tls_peer_issuer_locality", sizeof("tls_peer_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_L },
	{{"tls_my_subject_locality", sizeof("tls_my_subject_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_L },
	{{"tls_my_issuer_locality", sizeof("tls_my_issuer_locality")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_L },
	{{"tls_peer_subject_country", sizeof("tls_peer_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_C },
	{{"tls_peer_issuer_country", sizeof("tls_peer_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_C },
	{{"tls_my_subject_country", sizeof("tls_my_subject_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_C },
	{{"tls_my_issuer_country", sizeof("tls_my_issuer_country")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_C },
	{{"tls_peer_subject_state", sizeof("tls_peer_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_ST },
	{{"tls_peer_issuer_state", sizeof("tls_peer_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_ST },
	{{"tls_my_subject_state", sizeof("tls_my_subject_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_ST },
	{{"tls_my_issuer_state", sizeof("tls_my_issuer_state")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_ST },
	{{"tls_peer_subject_organization", sizeof("tls_peer_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_O },
	{{"tls_peer_issuer_organization", sizeof("tls_peer_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_O },
	{{"tls_my_subject_organization", sizeof("tls_my_subject_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_O },
	{{"tls_my_issuer_organization", sizeof("tls_my_issuer_organization")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_O },
	{{"tls_peer_subject_unit", sizeof("tls_peer_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_SUBJECT | COMP_OU },
	{{"tls_my_subject_serial", sizeof("tls_my_subject_serial")-1},
			850, tlsops_comp, 0,
			0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_SUBJECT_SERIAL },
	{{"tls_peer_subject_serial", sizeof("tls_peer_subject_serial")-1},
			850, tlsops_comp, 0,
			0, 0, pv_init_iname, CERT_PEER | CERT_SUBJECT | COMP_SUBJECT_SERIAL },
	{{"tls_peer_issuer_unit", sizeof("tls_peer_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_PEER  | CERT_ISSUER  | COMP_OU },
	{{"tls_my_subject_unit", sizeof("tls_my_subject_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_SUBJECT | COMP_OU },
	{{"tls_my_issuer_unit", sizeof("tls_my_issuer_unit")-1},
		850, tlsops_comp, 0,
		0, 0, pv_init_iname, CERT_LOCAL | CERT_ISSUER  | COMP_OU },
	/* subject alternative name parameters for peer and local */
	{{"tls_peer_san_email", sizeof("tls_peer_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_E },
	{{"tls_my_san_email", sizeof("tls_my_san_email")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_E },
	{{"tls_peer_san_hostname", sizeof("tls_peer_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_HOST },
	{{"tls_my_san_hostname", sizeof("tls_my_san_hostname")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_HOST },
	{{"tls_peer_san_uri", sizeof("tls_peer_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_URI },
	{{"tls_my_san_uri", sizeof("tls_my_san_uri")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_URI },
	{{"tls_peer_san_ip", sizeof("tls_peer_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_PEER  | COMP_IP },
	{{"tls_my_san_ip", sizeof("tls_my_san_ip")-1},
		850, tlsops_alt, 0,
		0, 0, pv_init_iname, CERT_LOCAL | COMP_IP },
	/* peer certificate validation parameters */
	{{"tls_peer_verified", sizeof("tls_peer_verified")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_VERIFIED },
	{{"tls_peer_revoked", sizeof("tls_peer_revoked")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_REVOKED },
	{{"tls_peer_expired", sizeof("tls_peer_expired")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_EXPIRED },
	{{"tls_peer_selfsigned", sizeof("tls_peer_selfsigned")-1},
		850, tlsops_check_cert, 0,
		0, 0, pv_init_iname, CERT_SELFSIGNED },
	{{"tls_peer_notBefore", sizeof("tls_peer_notBefore")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, CERT_NOTBEFORE },
	{{"tls_peer_notAfter", sizeof("tls_peer_notAfter")-1},
		850, tlsops_validity, 0,
		0, 0, pv_init_iname, CERT_NOTAFTER },

	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }

};

/*
 * Module interface
 */
struct module_exports exports = {
	"tlsops",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,        /* Exported functions */
	params,      /* Exported parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_items,   /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,    /* module initialization function */
	0,           /* response function */
	mod_destroy, /* destroy function */
	0            /* child initialization function */
};

static int mod_init(void)
{
	LM_DBG("%s module - initializing...\n", exports.name);

	return 0;
}


static void mod_destroy(void)
{
	LM_DBG("%s module - shutting down...\n", exports.name);
}


static int is_peer_verified(struct sip_msg* msg, char* foo, char* foo2)
{
	struct tcp_connection *c;
	SSL *ssl;
	long ssl_verify;
	X509 *x509_cert;

	LM_DBG("started...\n");
	if (msg->rcv.proto != PROTO_TLS) {
		LM_ERR("proto != TLS --> peer can't be verified, return -1\n");
		return -1;
	}

	LM_DBG("trying to find TCP connection of received message...\n");
	/* what if we have multiple connections to the same remote socket? e.g. we can have
	     connection 1: localIP1:localPort1 <--> remoteIP:remotePort
	     connection 2: localIP2:localPort2 <--> remoteIP:remotePort
	   but I think the is very unrealistic */
	c=tcpconn_get(0, &(msg->rcv.src_ip), msg->rcv.src_port, tcp_con_lifetime);
	if (!c) {
		LM_ERR("no corresponding TLS/TCP connection found."
				" This should not happen... return -1\n");
		return -1;
	}
	LM_DBG("corresponding TLS/TCP connection found. s=%d, fd=%d, id=%d\n",
			c->s, c->fd, c->id);

	if (!c->extra_data) {
		LM_ERR("no extra_data specified in TLS/TCP connection found."
				" This should not happen... return -1\n");
		tcpconn_put(c);
		return -1;
	}

	ssl = (SSL *) c->extra_data;

	ssl_verify = SSL_get_verify_result(ssl);
	if ( ssl_verify != X509_V_OK ) {
		LM_WARN("verification of presented certificate failed... return -1\n");
		tcpconn_put(c);
		return -1;
	}

	/* now, we have only valid peer certificates or peers without certificates.
	 * Thus we have to check for the existence of a peer certificate
	 */
	x509_cert = SSL_get_peer_certificate(ssl);
	if ( x509_cert == NULL ) {
		LM_WARN("tlsops:is_peer_verified: WARNING: peer did not presented "
			"a certificate. Thus it could not be verified... return -1\n");
		tcpconn_put(c);
		return -1;
	}

	X509_free(x509_cert);

	tcpconn_put(c);

	LM_DBG("tlsops:is_peer_verified: peer is successfuly verified"
		"...done\n");
	return 1;
}

/*
 *  mi cmd: refresh_crl_ca
 *
 */

static struct mi_root* mi_refresh_crl_ca(struct mi_root* cmd, void* param)
{
	LM_INFO("mi_refresh_crl_ca:start\n");
	reload_tls_domains_crl_ca_all();

	return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
}

/*
 * Check if a header field contains the same username
 * as TLS CN
 */
static inline int check_username(struct sip_msg* _m, struct sip_uri *_uri) {
#define CN_BUFF_SIZE 256
	str cn = {0,0};
	str usr = {0,0};
	char cn_buff[CN_BUFF_SIZE];
	char usr_buff[CN_BUFF_SIZE];

	if (_uri == NULL) {
		LM_ERR("Bad parameter\n");
		return ERR_INTERNAL;
	}

	/* Parse To/From URI */
	/* Make sure that the URI contains username */
	if (_uri->user.len == 0 || _uri->host.len == 0) {
		LM_ERR("Username not found in URI\n");
		return ERR_USERNOTFOUND;
	}

	/* make CN like identifier */
	if ((_uri->user.len + _uri->host.len + 4) >= CN_BUFF_SIZE){
		LM_ERR("Username buffer too short\n");
		return ERR_INTERNAL;
	}

	snprintf(usr_buff, CN_BUFF_SIZE, "%.*s@%.*s",
			 _uri->user.len, _uri->user.s,
			 _uri->host.len, _uri->host.s);
	usr.s = usr_buff;
	usr.len = _uri->user.len + _uri->host.len + 1;

	/* Get CN from the peer certificate */
	if (tlsops_get_peer_cn(_m, &cn, cn_buff, CN_BUFF_SIZE) != 0) {
		LM_ERR("Could not extract CN\n");
		return ERR_INTERNAL;
	}

	/* Check URI match to the CN match */
	if (usr.len == cn.len) {
		if (!strncasecmp(usr.s, cn.s,
						 usr.len)) {
			LM_DBG("Digest username and URI username match\n");
			return OK;
		} else {
			LM_INFO("Spoofed user '%.*s' should be '%.*s' as in CN\n",
					usr.len, usr.s,
					cn.len, cn.s);
			return ERR_SPOOFEDUSER;
		}
	}

	LM_INFO("Digest username and URI username do NOT match, '%.*s' should be '%.*s' as in CN\n",
			usr.len, usr.s,
			cn.len, cn.s);
	return ERR_NOMATCH;
}

/*
 * Check username part in To header field
 */
int tls_check_to(struct sip_msg* _m, char* _s1, char* _s2)
{
	if (!_m->to && ((parse_headers(_m, HDR_TO_F, 0) == -1) || (!_m->to))) {
		LM_ERR("Error while parsing To header field\n");
		return ERR_INTERNAL;
	}
	if(parse_to_uri(_m)==NULL) {
		LM_ERR("Error while parsing To header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, &get_to(_m)->parsed_uri);
}

/*
 * Check username part in From header field
 */
int tls_check_from(struct sip_msg* _m, char* _s1, char* _s2)
{
	if (parse_from_header(_m) < 0) {
		LM_ERR("Error while parsing From header field\n");
		return ERR_INTERNAL;
	}
	if(parse_from_uri(_m)==NULL) {
		LM_ERR("Error while parsing From header URI\n");
		return ERR_INTERNAL;
	}

	return check_username(_m, &get_from(_m)->parsed_uri);
}
