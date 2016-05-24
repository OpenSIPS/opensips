/*
 * Copyright (C) 2015 OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
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
 *  2015-02-12  first version (bogdan)
 */

#include <openssl/ui.h>
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>

#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../timer.h"
#include "../../receive.h"
#include "../../pt.h"
#include "../../parser/msg_parser.h"
#include "../../pvar.h"

#include "../../net/proto_tcp/tcp_common_defs.h"
#include "tls_config.h"
#include "tls_domain.h"
#include "tls_server.h"
#include "tls_params.h"
#include "tls_select.h"

/* definition of exported functions */
static int is_peer_verified(struct sip_msg*, char*, char*);

static int tls_port_no = SIPS_PORT;
static char *tls_domain_avp = NULL;

static int tls_max_msg_chunks = TCP_CHILD_MAX_MSG_CHUNK;

/* 0: send CRLF pong to incoming CRLFCRLF ping */
static int tls_crlf_pingpong = 1;

/* 0: do not drop single CRLF messages */
static int tls_crlf_drop = 0;

static int  mod_init(void);
static void mod_destroy(void);
static int proto_tls_init(struct proto_info *pi);
static int proto_tls_init_listener(struct socket_info *si);
static int proto_tls_send(struct socket_info* send_sock,
		char* buf, unsigned int len, union sockaddr_union* to, int id);

/* buffer to be used for reading all TCP SIP messages
   detached from the actual con - in order to improve
   paralelism ( process the SIP message while the con
   can be sent back to main to do more stuff */
static struct tcp_req tls_current_req;

/* re-use similar and existing functions from the TCP-plain protocol */
#define _tcp_common_write        tls_blocking_write
#define _tcp_common_current_req  tls_current_req
#include "../../net/proto_tcp/tcp_common.h"


static int tls_read_req(struct tcp_connection* con, int* bytes_read);
static int tls_conn_init(struct tcp_connection* c);
static void tls_conn_clean(struct tcp_connection* c);



static cmd_export_t cmds[] = {
	{"proto_init", (cmd_function)proto_tls_init, 0, 0, 0, 0},
	{"is_peer_verified", (cmd_function)is_peer_verified,   0, 0, 0,
			REQUEST_ROUTE},
	{0,0,0,0,0,0}
};


static param_export_t params[] = {
	{ "tls_port",              INT_PARAM,         &tls_port_no               },
	{ "tls_handshake_timeout", INT_PARAM,         &tls_handshake_timeout     },
	{ "tls_send_timeout",      INT_PARAM,         &tls_send_timeout          },
	{ "client_domain_avp",     STR_PARAM,         &tls_domain_avp            },
	{ "server_domain", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_add_srv_domain },
	{ "client_domain", STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_add_cli_domain },
	{ "tls_method",    STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_method     },
	{ "verify_cert",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_verify     },
	{ "require_cert",  STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_require    },
	{ "certificate",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_certificate},
	{ "private_key",   STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_pk         },
	{ "ca_list",       STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_calist     },
	{ "ca_dir",        STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_cadir      },
	{ "ciphers_list",  STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_cplist     },
	{ "dh_params",     STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_dhparams   },
	{ "ec_curve",      STR_PARAM|USE_FUNC_PARAM,  (void*)tlsp_set_eccurve    },
	{ "tls_crlf_pingpong",     INT_PARAM,         &tls_crlf_pingpong         },
	{ "tls_crlf_drop",         INT_PARAM,         &tls_crlf_drop             },
	{ "tls_max_msg_chunks",    INT_PARAM,         &tls_max_msg_chunks        },
	{0, 0, 0}
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



struct module_exports exports = {
	PROTO_PREFIX "tls",  /* module name*/
	MOD_TYPE_DEFAULT,    /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	mod_items,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
};


/**************  Controll related functions ***************/


#define OS_SSL_SESS_ID ((unsigned char*)"opensips-tls-1.11.0")
#define OS_SSL_SESS_ID_LEN (sizeof(OS_SSL_SESS_ID)-1)

#if OPENSSL_VERSION_NUMBER < 0x00908000L
        #error "using an unsupported version of OpenSSL (< 0.9.8)"
#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L
	#warning ""
	#warning "=============================================================="
	#warning "Your version of OpenSSL is < 1.0.1."
	#warning " Upgrade for better compatibility, features and security fixes!"
	#warning "============================================================="
	#warning ""
#endif

SSL_METHOD     *ssl_methods[TLS_USE_TLSv1_2 + 1];

#define VERIFY_DEPTH_S 3

static int tls_static_locks_no=0;
static gen_lock_set_t* tls_static_locks=NULL;

struct CRYPTO_dynlock_value {
	gen_lock_t lock;
};

/*
 * Wrappers around OpenSIPS shared memory functions
 * (which can be macros)
 */
static void* os_malloc(size_t size)
{
	return shm_malloc(size);
}


static void* os_realloc(void *ptr, size_t size)
{
	return shm_realloc(ptr, size);
}


static void os_free(void *ptr)
{
	if (ptr)
		shm_free(ptr);
}


static void tls_static_locks_ops(int mode, int n, const char* file, int line)
{
	if (n<0 || n>tls_static_locks_no) {
		LM_ERR("BUG - SSL Lib attempting to acquire bogus lock\n");
		abort();
	}

	if (mode & CRYPTO_LOCK) {
		lock_set_get(tls_static_locks,n);
	} else {
		lock_set_release(tls_static_locks,n);
	}
}


static unsigned long tls_get_id(void)
{
	return my_pid();
}


static struct CRYPTO_dynlock_value* tls_dyn_lock_create(const char* file,
																	int line)
{
	struct CRYPTO_dynlock_value* new_lock;

	new_lock=shm_malloc(sizeof(struct CRYPTO_dynlock_value));
	if (new_lock==0){
		LM_ERR("Failed to allocated new dynamic lock\n");
		return 0;
	}
	if (lock_init(&new_lock->lock)==0) {
		LM_ERR("Failed to init new dynamic lock\n");
		shm_free(new_lock);
		return 0;
	}

	return new_lock;
}


static void tls_dyn_lock_ops(int mode, struct CRYPTO_dynlock_value* dyn_lock,
												const char* file, int line)
{
	if (mode & CRYPTO_LOCK) {
		lock_get(&dyn_lock->lock);
	} else {
		lock_release(&dyn_lock->lock);
	}
}


static void tls_dyn_lock_destroy(struct CRYPTO_dynlock_value *dyn_lock,
													const char* file, int line)
{
	lock_destroy(&dyn_lock->lock);
	shm_free(dyn_lock);
}


static int tls_init_multithread(void)
{
	/* init static locks support */
	tls_static_locks_no = CRYPTO_num_locks();

	if (tls_static_locks_no>0) {
		/* init a lock set & pass locking function to SSL */
		tls_static_locks = lock_set_alloc(tls_static_locks_no);
		if (tls_static_locks == NULL) {
			LM_ERR("Failed to alloc static locks\n");
			return -1;
		}
		if (lock_set_init(tls_static_locks)==0) {
				LM_ERR("Failed to init static locks\n");
				lock_set_dealloc(tls_static_locks);
				return -1;
		}
		CRYPTO_set_locking_callback(tls_static_locks_ops);
	}

	CRYPTO_set_id_callback(tls_get_id);

	/* dynamic locks support*/
	CRYPTO_set_dynlock_create_callback(tls_dyn_lock_create);
	CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_ops);
	CRYPTO_set_dynlock_destroy_callback(tls_dyn_lock_destroy);

	return 0;
}


/*
 * initialize ssl methods
 */
static void
init_ssl_methods(void)
{
	LM_DBG("entered\n");

	ssl_methods[TLS_USE_TLSv1_cli-1] = (SSL_METHOD*)TLSv1_client_method();
	ssl_methods[TLS_USE_TLSv1_srv-1] = (SSL_METHOD*)TLSv1_server_method();
	ssl_methods[TLS_USE_TLSv1-1] = (SSL_METHOD*)TLSv1_method();

	ssl_methods[TLS_USE_SSLv23_cli-1] = (SSL_METHOD*)SSLv23_client_method();
	ssl_methods[TLS_USE_SSLv23_srv-1] = (SSL_METHOD*)SSLv23_server_method();
	ssl_methods[TLS_USE_SSLv23-1] = (SSL_METHOD*)SSLv23_method();

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	ssl_methods[TLS_USE_TLSv1_2_cli-1] = (SSL_METHOD*)TLSv1_2_client_method();
	ssl_methods[TLS_USE_TLSv1_2_srv-1] = (SSL_METHOD*)TLSv1_2_server_method();
	ssl_methods[TLS_USE_TLSv1_2-1] = (SSL_METHOD*)TLSv1_2_method();
#endif
}


static int check_for_krb(void)
{
	SSL_CTX *xx;
	int j;

	xx = SSL_CTX_new(ssl_methods[tls_method - 1]);
	if (xx==NULL)
		return -1;

	for( j=0 ; j<sk_SSL_CIPHER_num(xx->cipher_list) ; j++) {
		SSL_CIPHER *yy = sk_SSL_CIPHER_value(xx->cipher_list,j);
		if ( yy->id>=SSL3_CK_KRB5_DES_64_CBC_SHA &&
		 yy->id<=SSL3_CK_KRB5_RC4_40_MD5 ) {
			LM_INFO("KRB5 cipher %s found\n", yy->name);
			SSL_CTX_free(xx);
			return 1;
		}
	}

	SSL_CTX_free(xx);
	return 0;
}


#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
/*
 * Load and set DH params to be used in ephemeral key exchange from a file.
 */
static int
set_dh_params(SSL_CTX * ctx, char *filename)
{
	LM_DBG("Entered\n");
	BIO *bio = BIO_new_file(filename, "r");
	if (!bio) {
		LM_ERR("unable to open dh params file '%s'\n", filename);
		return -1;
	}

	DH *dh = PEM_read_bio_DHparams(bio, 0, 0, 0);
	BIO_free(bio);
	if (!dh) {
		LM_ERR("unable to read dh params from '%s'\n", filename);
		return -1;
	}

	if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
		LM_ERR("unable to set dh params\n");
		return -1;
	}

	DH_free(dh);
	LM_DBG("DH params from '%s' successfuly set\n", filename);
	return 0;
}


/*
 * Set elliptic curve.
 */
static int set_ec_params(SSL_CTX * ctx, const char* curve_name)
{
	int curve = 0;
	if (curve_name) {
		curve = OBJ_txt2nid(curve_name);
	}
	if (curve > 0) {
		EC_KEY *ecdh = EC_KEY_new_by_curve_name (curve);
		if (! ecdh) {
			LM_ERR("unable to create EC curve\n");
			return -1;
		}
		if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh)) {
			LM_ERR("unable to set tmp_ecdh\n");
			return -1;
		}
		EC_KEY_free (ecdh);
	}
	else {
		LM_ERR("unable to find the EC curve\n");
		return -1;
	}
	return 0;
}
#endif


/* This callback is called during each verification process,
at each step during the chain of certificates (this function
is not the certificate_verification one!). */
int verify_callback(int pre_verify_ok, X509_STORE_CTX *ctx) {
	char buf[256];
	X509 *err_cert;
	int err, depth;

	depth = X509_STORE_CTX_get_error_depth(ctx);
	LM_NOTICE("depth = %d\n",depth);
	if ( depth > VERIFY_DEPTH_S ) {
		LM_NOTICE("cert chain too long ( depth > VERIFY_DEPTH_S)\n");
		pre_verify_ok=0;
	}

	if( pre_verify_ok ) {
		LM_NOTICE("preverify is good: verify return: %d\n", pre_verify_ok);
		return pre_verify_ok;
	}

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof buf);

	LM_NOTICE("subject = %s\n", buf);
	LM_NOTICE("verify error:num=%d:%s\n",
		err, X509_verify_cert_error_string(err));
	LM_NOTICE("error code is %d\n", ctx->error);

	switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
				buf,sizeof buf);
			LM_NOTICE("issuer= %s\n",buf);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_CERT_NOT_YET_VALID:
			LM_NOTICE("notBefore\n");
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		case X509_V_ERR_CERT_HAS_EXPIRED:
			LM_NOTICE("notAfter\n");
			break;
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
			LM_NOTICE("unable to decrypt cert "
				"signature\n");
			break;
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
			LM_NOTICE("unable to decode issuer "
				"public key\n");
			break;
		case X509_V_ERR_OUT_OF_MEM:
			LM_NOTICE("out of memory \n");
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			LM_NOTICE("Self signed certificate "
				"issue\n");
			break;
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
			LM_NOTICE("certificate chain too long\n");
			break;
		case X509_V_ERR_INVALID_CA:
			LM_NOTICE("invalid CA\n");
			break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			LM_NOTICE("path length exceeded\n");
			break;
		case X509_V_ERR_INVALID_PURPOSE:
			LM_NOTICE("invalid purpose\n");
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			LM_NOTICE("certificate untrusted\n");
			break;
		case X509_V_ERR_CERT_REJECTED:
			LM_NOTICE("certificate rejected\n");
			break;

		default:
			LM_NOTICE("something wrong with the cert"
				" ... error code is %d (check x509_vfy.h)\n", ctx->error);
			break;
	}

	LM_NOTICE("verify return:%d\n", pre_verify_ok);
	return(pre_verify_ok);
}


/*
 * Setup default SSL_CTX (and SSL * ) behavior:
 *     verification, cipherlist, acceptable versions, ...
 */
static int init_ssl_ctx_behavior( struct tls_domain *d ) {
	int verify_mode;

#if (OPENSSL_VERSION_NUMBER > 0x10001000L)
	/*
	 * set dh params
	 */
	if (!d->tmp_dh_file) {
			LM_DBG("no DH params file for tls[%s:%d] defined, "
					"using default '%s'\n", ip_addr2a(&d->addr), d->port,
					tls_tmp_dh_file);
			d->tmp_dh_file = tls_tmp_dh_file;
	}
	if (d->tmp_dh_file && set_dh_params(d->ctx, d->tmp_dh_file) < 0)
			return -1;

	if (d->tls_ec_curve) {
		if (set_ec_params(d->ctx, d->tls_ec_curve) < 0) {
			return -1;
		}
	}
	else {
		LM_NOTICE("No EC curve defined\n");
	}
#else
	if (d->tmp_dh_file  || tls_tmp_dh_file)
		LM_WARN("DH params file discarded as not supported by your openSSL version\n");
	if (d->tls_ec_curve)
		LM_WARN("EC params file discarded as not supported by your openSSL version\n");
#endif

	if( d->ciphers_list != 0 ) {
		if( SSL_CTX_set_cipher_list(d->ctx, d->ciphers_list) == 0 ) {
			LM_ERR("failure to set SSL context "
				"cipher list '%s'\n", d->ciphers_list);
			return -1;
		} else {
			LM_NOTICE("cipher list set to %s\n", d->ciphers_list);
		}
	} else {
		LM_DBG( "cipher list null ... setting default\n");
	}

	/* Set a bunch of options:
	 *     do not accept SSLv2 / SSLv3
	 *     no session resumption
	 *     choose cipher according to server's preference's*/

	SSL_CTX_set_options(d->ctx,
		SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
		SSL_OP_CIPHER_SERVER_PREFERENCE);

	/* Set verification procedure
	 * The verification can be made null with SSL_VERIFY_NONE, or
	 * at least easier with SSL_VERIFY_CLIENT_ONCE instead of
	 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT.
	 * For extra control, instead of 0, we can specify a callback function:
	 *           int (*verify_callback)(int, X509_STORE_CTX *)
	 * Also, depth 2 may be not enough in some scenarios ... though no need
	 * to increase it much further */

	if (d->type & TLS_DOMAIN_SRV) {
		/* Server mode:
		 * SSL_VERIFY_NONE
		 *   the server will not send a client certificate request to the
		 *   client, so the client  will not send a certificate.
		 * SSL_VERIFY_PEER
		 *   the server sends a client certificate request to the client.
		 *   The certificate returned (if any) is checked. If the verification
		 *   process fails, the TLS/SSL handshake is immediately terminated
		 *   with an alert message containing the reason for the verification
		 *   failure. The behaviour can be controlled by the additional
		 *   SSL_VERIFY_FAIL_IF_NO_PEER_CERT and SSL_VERIFY_CLIENT_ONCE flags.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   if the client did not return a certificate, the TLS/SSL handshake
		 *   is immediately terminated with a ``handshake failure'' alert.
		 *   This flag must be used together with SSL_VERIFY_PEER.
		 * SSL_VERIFY_CLIENT_ONCE
		 *   only request a client certificate on the initial TLS/SSL
		 *   handshake. Do not ask for a client certificate again in case of
		 *   a renegotiation. This flag must be used together with
		 *   SSL_VERIFY_PEER.
		 */

		if( d->verify_cert ) {
			verify_mode = SSL_VERIFY_PEER;
			if( d->require_client_cert ) {
				LM_WARN("client verification activated. Client "
					"certificates are mandatory.\n");
				verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			} else
				LM_WARN("client verification activated. Client "
					"certificates are NOT mandatory.\n");
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_WARN("client verification NOT activated. Weaker security.\n");
		}
	} else {
		/* Client mode:
		 * SSL_VERIFY_NONE
		 *   if not using an anonymous cipher (by default disabled), the
		 *   server will send a certificate which will be checked. The result
		 *   of the certificate verification process can be checked after the
		 *   TLS/SSL handshake using the SSL_get_verify_result(3) function.
		 *   The handshake will be continued regardless of the verification
		 *   result.
		 * SSL_VERIFY_PEER
		 *   the server certificate is verified. If the verification process
		 *   fails, the TLS/SSL handshake is immediately terminated with an
		 *   alert message containing the reason for the verification failure.
		 *   If no server certificate is sent, because an anonymous cipher is
		 *   used, SSL_VERIFY_PEER is ignored.
		 * SSL_VERIFY_FAIL_IF_NO_PEER_CERT
		 *   ignored
		 * SSL_VERIFY_CLIENT_ONCE
		 *   ignored
		 */

		if( d->verify_cert ) {
			verify_mode = SSL_VERIFY_PEER;
			LM_WARN("server verification activated.\n");
		} else {
			verify_mode = SSL_VERIFY_NONE;
			LM_WARN("server verification NOT activated. Weaker security.\n");
		}
	}

	SSL_CTX_set_verify( d->ctx, verify_mode, verify_callback);
	SSL_CTX_set_verify_depth( d->ctx, VERIFY_DEPTH_S);

	SSL_CTX_set_session_cache_mode( d->ctx, SSL_SESS_CACHE_SERVER );
	SSL_CTX_set_session_id_context( d->ctx, OS_SSL_SESS_ID,
		OS_SSL_SESS_ID_LEN );

	return 0;
}


/*
 * load a certificate from a file
 * (certificate file can be a chain, starting by the user cert,
 * and ending in the root CA; if not all needed certs are in this
 * file, they are looked up in the caFile or caPATH (see verify
 * function).
 */
static int load_certificate(SSL_CTX * ctx, char *filename)
{
	LM_DBG("entered\n");
	if (!SSL_CTX_use_certificate_chain_file(ctx, filename)) {
		LM_ERR("unable to load certificate file '%s'\n",
			filename);
		return -1;
	}

	LM_DBG("'%s' successfuly loaded\n", filename);
	return 0;
}


/*
 * Load a caList, to be used to verify the client's certificate.
 * The list is to be stored in a single file, containing all
 * the acceptable root certificates.
 */
static int load_ca(SSL_CTX * ctx, char *filename)
{
	LM_DBG("Entered\n");
	if (!SSL_CTX_load_verify_locations(ctx, filename, 0)) {
		LM_ERR("unable to load ca '%s'\n", filename);
		return -1;
	}

	LM_DBG("CA '%s' successfuly loaded\n", filename);
	return 0;
}


/*
 * Load a caList from a directory instead of a single file.
 */
static int load_ca_dir(SSL_CTX * ctx, char *directory)
{
	LM_DBG("Entered\n");
	if (!SSL_CTX_load_verify_locations(ctx, 0 , directory)) {
		LM_ERR("unable to load ca directory '%s'\n", directory);
		return -1;
	}

	LM_DBG("CA '%s' successfuly loaded from directory\n", directory);
	return 0;
}


static int passwd_cb(char *buf, int size, int rwflag, void *filename)
{
	UI             *ui;
	const char     *prompt;

	ui = UI_new();
	if (ui == NULL)
		goto err;

	prompt = UI_construct_prompt(ui, "passphrase", filename);
	UI_add_input_string(ui, prompt, 0, buf, 0, size - 1);
	UI_process(ui);
	UI_free(ui);
	return strlen(buf);

err:
	LM_ERR("passwd_cb failed\n");
	if (ui)
		UI_free(ui);
	return 0;
}


/*
 * load a private key from a file
 */
static int load_private_key(SSL_CTX * ctx, char *filename)
{
#define NUM_RETRIES 3
	int idx, ret_pwd;
	LM_DBG("entered\n");

	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, filename);

	for(idx = 0, ret_pwd = 0; idx < NUM_RETRIES; idx++ ) {
		ret_pwd = SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM);
		if ( ret_pwd ) {
			break;
		} else {
			LM_ERR("unable to load private key file '%s'. \n"
				"Retry (%d left) (check password case)\n",
				filename, (NUM_RETRIES - idx -1) );
			continue;
		}
	}

	if( ! ret_pwd ) {
		LM_ERR("unable to load private key file '%s'\n",
			filename);
		return -1;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		LM_ERR("key '%s' does not match the public key of the certificate\n",
			filename);
		return -1;
	}

	LM_DBG("key '%s' successfuly loaded\n", filename);
	return 0;
}


/*
 * initialize tls virtual domains
 */
static int init_tls_domains(struct tls_domain *d)
{
	struct tls_domain *dom;

	dom = d;
	while (d) {
		if (d->name.len) {
			LM_INFO("Processing TLS domain '%.*s'\n",
				d->name.len, ZSW(d->name.s));
		} else {
			LM_INFO("Processing TLS domain [%s:%d]\n",
				ip_addr2a(&d->addr), d->port);
		}

		/*
		* set method
		*/
		if (d->method == TLS_METHOD_UNSPEC) {
			LM_DBG("no method for tls[%s:%d], using default\n",
				ip_addr2a(&d->addr), d->port);
			d->method = tls_method;
		}

		/*
		* create context
		*/
		d->ctx = SSL_CTX_new(ssl_methods[d->method - 1]);
		if (d->ctx == NULL) {
			LM_ERR("cannot create ssl context for "
				"tls[%s:%d]\n", ip_addr2a(&d->addr), d->port);
			return -1;
		}
		if (init_ssl_ctx_behavior( d ) < 0)
			return -1;

		/*
		* load certificate
		*/
		if (!d->cert_file) {
			LM_NOTICE("no certificate for tls[%s:%d] defined, using default"
					"'%s'\n", ip_addr2a(&d->addr), d->port,	tls_cert_file);
			d->cert_file = tls_cert_file;
		}
		if (load_certificate(d->ctx, d->cert_file) < 0)
			return -1;

		/*
		* load ca
		*/
		if (!d->ca_file) {
			LM_NOTICE("no CA for tls[%s:%d] defined, "
				"using default '%s'\n", ip_addr2a(&d->addr), d->port,
				tls_ca_file);
			d->ca_file = tls_ca_file;
		}
		if (d->ca_file && load_ca(d->ctx, d->ca_file) < 0)
			return -1;

		/*
		* load ca from directory
		*/
		if (!d->ca_directory) {

			LM_NOTICE("no CA for tls[%s:%d] defined, "
				"using default '%s'\n", ip_addr2a(&d->addr), d->port,
				 tls_ca_dir);
			d->ca_directory = tls_ca_dir;
		}

		if (d->ca_directory && load_ca_dir(d->ctx, d->ca_directory) < 0)
			return -1;

		d = d->next;
	}

	/*
	* load all private keys as the last step (may prompt for password)
	*/
	d = dom;
	while (d) {
		if (!d->pkey_file) {
			LM_NOTICE("no private key for tls[%s:%d] defined, using default"
					"'%s'\n", ip_addr2a(&d->addr), d->port, tls_pkey_file);
			d->pkey_file = tls_pkey_file;
		}
		if (load_private_key(d->ctx, d->pkey_file) < 0)
			return -1;
		d = d->next;
	}
	return 0;
}


static int mod_init(void)
{
	str s;
	int n;

	LM_INFO("initializing TLS protocol\n");

	if (tls_domain_avp) {
		s.s = tls_domain_avp;
		s.len = strlen(s.s);
		if (parse_avp_spec( &s, &tls_client_domain_avp)) {
			LM_ERR("cannot parse tls_client_avp");
			return -1;
		}
	}

	/*
	* this has to be called before any function calling CRYPTO_malloc,
	* CRYPTO_malloc will set allow_customize in openssl to 0
	*/
	if (!CRYPTO_set_mem_functions(os_malloc, os_realloc, os_free)) {
		LM_ERR("unable to set the memory allocation functions\n");
		LM_ERR("NOTE: check if you have openssl 1.0.1e-fips, as this "
			"version is know to be broken; if so, you need to upgrade or "
			"downgrade to a differen openssl version !!\n");
		return -1;
	}

#if !defined(OPENSSL_NO_COMP)
	STACK_OF(SSL_COMP)* comp_methods;
	/* disabling compression */
	LM_WARN("disabling compression due ZLIB problems\n");
	comp_methods = SSL_COMP_get_compression_methods();
	if (comp_methods==0) {
		LM_INFO("openssl compression already disabled\n");
	} else {
		sk_SSL_COMP_zero(comp_methods);
	}
#endif

	if (tls_init_multithread() < 0) {
		LM_ERR("failed to init multi-threading support\n");
		return -1;
	}

	SSL_library_init();
	SSL_load_error_strings();
	init_ssl_methods();

	n = check_for_krb();
	if (n==-1) {
		LM_ERR("kerberos check failed\n");
		return -1;
	}

	if ( ( n ^
#ifndef OPENSSL_NO_KRB5
	1
#else
	0
#endif
	)!=0 ) {
		LM_ERR("compiled agaist an openssl with %s"
			"kerberos, but run with one with %skerberos\n",
			(n==1)?"":"no ",(n!=1)?"no ":"");
		return -1;
	}


	/*
	 * finish setting up the tls default domains
	 */
	tls_default_client_domain.type = TLS_DOMAIN_DEF|TLS_DOMAIN_CLI ;
	tls_default_client_domain.addr.af = AF_INET;

	tls_default_server_domain.type = TLS_DOMAIN_DEF|TLS_DOMAIN_SRV;
	tls_default_server_domain.addr.af = AF_INET;

	/*
	 * now initialize tls default domains
	 */
	if ( (n=init_tls_domains(&tls_default_server_domain)) ) {
		return n;
	}
	if ( (n=init_tls_domains(&tls_default_client_domain)) ) {
		return n;
	}
	/*
	 * now initialize tls virtual domains
	 */
	if ( (n=init_tls_domains(tls_server_domains)) ) {
		return n;
	}
	if ( (n=init_tls_domains(tls_client_domains)) ) {
		return n;
	}
	/*
	 * we are all set
	 */
	return 0;
}


/*
 * called from main.c when opensips exits (main process)
 */
static void mod_destroy(void)
{
	struct tls_domain *d;
	LM_DBG("entered\n");

	d = tls_server_domains;
	while (d) {
		if (d->ctx)
			SSL_CTX_free(d->ctx);
		d = d->next;
	}
	d = tls_client_domains;
	while (d) {
		if (d->ctx)
			SSL_CTX_free(d->ctx);
		d = d->next;
	}
	if (tls_default_server_domain.ctx) {
		SSL_CTX_free(tls_default_server_domain.ctx);
	}
	if (tls_default_client_domain.ctx) {
		SSL_CTX_free(tls_default_client_domain.ctx);
	}
	tls_free_domains();

	/* TODO - destroy static locks */

	/* library destroy */
	ERR_free_strings();
	/*SSL_free_comp_methods(); - this function is not on std. openssl*/
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	return;
}


static int proto_tls_init(struct proto_info *pi)
{
	pi->default_port		= tls_port_no;

	pi->tran.init_listener	= proto_tls_init_listener;
	pi->tran.send			= proto_tls_send;
	pi->tran.dst_attr		= tcp_conn_fcntl;

	pi->net.flags			= PROTO_NET_USE_TCP;
	pi->net.read			= (proto_net_read_f)tls_read_req;
	pi->net.conn_init		= tls_conn_init;
	pi->net.conn_clean		= tls_conn_clean;

	return 0;
}



static int proto_tls_init_listener(struct socket_info *si)
{
	/*
	 * reuse tcp initialization
	 */
	if (tcp_init_listener(si) < 0) {
		LM_ERR("failed to initialize TCP part\n");
		goto error;
	}

	return 0;

error:
	if (si->socket != -1) {
		close(si->socket);
		si->socket = -1;
	}
	return -1;
}


static int tls_conn_init(struct tcp_connection* c)
{
	struct tls_domain *dom;

	struct usr_avp *avp;
	int_str val;

	/*
	* new connection within a single process, no lock necessary
	*/
	LM_DBG("entered: Creating a whole new ssl connection\n");

	if ( c->flags&F_CONN_ACCEPTED ) {
		/* connection created as a result of an accept -> server */
		c->proto_flags = F_TLS_DO_ACCEPT;
		LM_DBG("looking up socket based TLS server "
			"domain [%s:%d]\n", ip_addr2a(&c->rcv.dst_ip), c->rcv.dst_port);
		dom = tls_find_server_domain(&c->rcv.dst_ip, c->rcv.dst_port);
		if (dom) {
			LM_DBG("found socket based TLS server domain "
				"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
				c->extra_data = SSL_new(dom->ctx);
		} else {
			LM_ERR("no TLS server domain found\n");
			return -1;
		}
	} else {
		/* connection created as a result of a connect -> client */
		avp = NULL;
		c->proto_flags = F_TLS_DO_CONNECT;
		if (tls_client_domain_avp > 0) {
			avp = search_first_avp(0, tls_client_domain_avp, &val, 0);
		} else {
			LM_DBG("name based TLS client domains are disabled\n");
		}
		if (!avp) {
			LM_DBG("no TLS client domain AVP set, looking "
				"for socket based TLS client domain\n");
			dom = tls_find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
			if (dom) {
				LM_DBG("found socket based TLS client domain "
					"[%s:%d]\n", ip_addr2a(&dom->addr), dom->port);
					c->extra_data = SSL_new(dom->ctx);
			} else {
				LM_ERR("no TLS client domain found\n");
				return -1;
			}
		} else {
			LM_DBG("TLS client domain AVP found = '%.*s'\n",
				val.s.len, ZSW(val.s.s));
			dom = tls_find_client_domain_name(val.s);
			if (dom) {
				LM_DBG("found name based TLS client domain "
					"'%.*s'\n", val.s.len, ZSW(val.s.s));
				c->extra_data = SSL_new(dom->ctx);
			} else {
				LM_DBG("no name based TLS client domain found, "
					"trying socket based TLS client domains\n");
				dom = tls_find_client_domain(&c->rcv.src_ip, c->rcv.src_port);
				if (dom) {
					LM_DBG("found socket based TLS client domain [%s:%d]\n",
					ip_addr2a(&dom->addr), dom->port);
					c->extra_data = SSL_new(dom->ctx);
				} else {
					LM_ERR("no TLS client domain found\n");
					return -1;
				}
			}
		}
	}
	if (!c->extra_data) {
		LM_ERR("failed to create SSL structure\n");
		return -1;
	}

#ifndef OPENSSL_NO_KRB5
	if ( ((SSL *)c->extra_data)->kssl_ctx ) {
		kssl_ctx_free( ((SSL *)c->extra_data)->kssl_ctx );
		((SSL *)c->extra_data)->kssl_ctx = 0;
	}
#endif

	if ( c->proto_flags & F_TLS_DO_ACCEPT ) {
		LM_DBG("Setting in ACCEPT mode (server)\n");
		SSL_set_accept_state((SSL *) c->extra_data);
	} else {
		LM_DBG("Setting in CONNECT mode (client)\n");
		SSL_set_connect_state((SSL *) c->extra_data);
	}
	return 0;
}


static void tls_conn_clean(struct tcp_connection* c)
{
	/*
	* runs within global tcp lock
	*/
	LM_DBG("entered\n");

	if (c->extra_data) {
		tls_update_fd(c,c->s);

		tls_conn_shutdown(c);
		SSL_free((SSL *) c->extra_data);
		c->extra_data = 0;
	}
}


static struct tcp_connection* tls_sync_connect(struct socket_info* send_sock,
		union sockaddr_union* server, int *fd)
{
	int s;
	union sockaddr_union my_name;
	socklen_t my_name_len;
	struct tcp_connection* con;

	s=socket(AF2PF(server->s.sa_family), SOCK_STREAM, 0);
	if (s==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	if (tcp_init_sock_opt(s)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}
	my_name_len = sockaddru_len(send_sock->su);
	memcpy( &my_name, &send_sock->su, my_name_len);
	su_setport( &my_name, 0);
	if (bind(s, &my_name.s, my_name_len )!=0) {
		LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
		goto error;
	}

	if (tcp_connect_blocking(s, &server->s, sockaddru_len(*server))<0){
		LM_ERR("tcp_blocking_connect failed\n");
		goto error;
	}
	con=tcp_conn_create(s, server, send_sock, S_CONN_OK);
	if (con==NULL){
		LM_ERR("tcp_conn_create failed, closing the socket\n");
		goto error;
	}
	*fd = s;
	return con;
	/*FIXME: set sock idx! */
error:
	/* close the opened socket */
	if (s!=-1) close(s);
	return 0;
}


static int proto_tls_send(struct socket_info* send_sock,
				char* buf, unsigned int len, union sockaddr_union* to, int id)
{
	struct tcp_connection *c;
	struct ip_addr ip;
	int port;
	int fd, n;

	if (to){
		su2ip_addr(&ip, to);
		port=su_getport(to);
		n = tcp_conn_get(id, &ip, port, PROTO_TLS, &c, &fd);
	}else if (id){
		n = tcp_conn_get(id, 0, 0, PROTO_NONE, &c, &fd);
	}else{
		LM_CRIT("prot_tls_send called with null id & to\n");
		return -1;
	}

	if (n<0) {
		/* error during conn get, return with error too */
		LM_ERR("failed to acquire connection\n");
		return -1;
	}

	/* was connection found ?? */
	if (c==0) {
		if (tcp_no_new_conn) {
			return -1;
		}
		LM_DBG("no open tcp connection found, opening new one\n");
		/* create tcp connection */
		if ((c=tls_sync_connect(send_sock, to, &fd))==0) {
			LM_ERR("connect failed\n");
			return -1;
		}
		goto send_it;
	}

	/* now we have a connection, let's what we can do with it */
	/* BE CAREFUL now as we need to release the conn before exiting !!! */
	if (fd==-1) {
		/* connection is not writable because of its state */
		/* return error, nothing to do about it */
		tcp_conn_release(c, 0);
		return -1;
	}

send_it:
	LM_DBG("sending via fd %d...\n",fd);

	n = tls_blocking_write(c, fd, buf, len);
	tcp_conn_set_lifetime( c, tcp_con_lifetime);

	LM_DBG("after write: c= %p n=%d fd=%d\n",c, n, fd);
	LM_DBG("buf=\n%.*s\n", (int)len, buf);
	if (n<0){
		LM_ERR("failed to send\n");
		c->state=S_CONN_BAD;
		if (c->proc_id != process_no)
			close(fd);
		tcp_conn_release(c, 0);
		return -1;
	}

	/* only close the FD if not already in the context of our process
	either we just connected, or main sent us the FD */
	if (c->proc_id != process_no)
		close(fd);

	tcp_conn_release(c, 0);
	return n;
}


static int tls_read_req(struct tcp_connection* con, int* bytes_read)
{
	int bytes;
	int total_bytes;
	struct tcp_req* req;

	bytes=-1;
	total_bytes=0;

	if (con->con_req) {
		req=con->con_req;
		LM_DBG("Using the per connection buff \n");
	} else {
		LM_DBG("Using the global ( per process ) buff \n");
		init_tcp_req(&tls_current_req, 0);
		req=&tls_current_req;
	}

	if (tls_fix_read_conn(con)!=0) {
		LM_ERR("failed to do pre-tls reading\n");
		goto error;
	}
	if(con->state!=S_CONN_OK)
		goto done; /* not enough data */

again:
	if(req->error==TCP_REQ_OK){
		/* if we still have some unparsed part, parse it first,
		 * don't do the read*/
		if (req->parsed<req->pos){
			bytes=0;
		}else{
			bytes=tls_read(con,req);
			if (bytes<0) {
				LM_ERR("failed to read \n");
				goto error;
			}
		}

		tcp_parse_headers(req, tls_crlf_pingpong, tls_crlf_drop);
#ifdef EXTRA_DEBUG
					/* if timeout state=0; goto end__req; */
		LM_DBG("read= %d bytes, parsed=%d, state=%d, error=%d\n",
				bytes, (int)(req->parsed-req->start), req->state,
				req->error );
		LM_DBG("last char=0x%02X, parsed msg=\n%.*s\n",
				*(req->parsed-1), (int)(req->parsed-req->start),
				req->start);
#endif
		total_bytes+=bytes;
		/* eof check:
		 * is EOF if eof on fd and req.  not complete yet,
		 * if req. is complete we might have a second unparsed
		 * request after it, so postpone release_with_eof
		 */
		if ((con->state==S_CONN_EOF) && (req->complete==0)) {
			LM_DBG("EOF received\n");
			goto done;
		}
	}

	if (req->error!=TCP_REQ_OK){
		LM_ERR("bad request, state=%d, error=%d "
				  "buf:\n%.*s\nparsed:\n%.*s\n", req->state, req->error,
				  (int)(req->pos-req->buf), req->buf,
				  (int)(req->parsed-req->start), req->start);
		LM_DBG("- received from: port %d\n", con->rcv.src_port);
		print_ip("- received from: ip ",&con->rcv.src_ip, "\n");
		goto error;
	}

	switch (tcp_handle_req(req, con, tls_max_msg_chunks) ) {
		case 1:
			goto again;
		case -1:
			goto error;
	}

	LM_DBG("tls_read_req end\n");
done:
	if (bytes_read) *bytes_read=total_bytes;
	/* connection will be released */
	return 0;
error:
	/* connection will be released as ERROR */
	return -1;
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
	tcp_conn_get(0, &(msg->rcv.src_ip), msg->rcv.src_port, PROTO_TLS, &c, NULL/*fd*/);
	if (c==NULL) {
		LM_ERR("no corresponding TLS/TCP connection found."
				" This should not happen... return -1\n");
		return -1;
	}
	LM_DBG("corresponding TLS/TCP connection found. s=%d, fd=%d, id=%d\n",
			c->s, c->fd, c->id);

	if (!c->extra_data) {
		LM_ERR("no extra_data specified in TLS/TCP connection found."
				" This should not happen... return -1\n");
		goto error;
	}

	ssl = (SSL *) c->extra_data;

	ssl_verify = SSL_get_verify_result(ssl);
	if ( ssl_verify != X509_V_OK ) {
		LM_WARN("verification of presented certificate failed... return -1\n");
		goto error;
	}

	/* now, we have only valid peer certificates or peers without certificates.
	 * Thus we have to check for the existence of a peer certificate
	 */
	x509_cert = SSL_get_peer_certificate(ssl);
	if ( x509_cert == NULL ) {
		LM_WARN("tlsops:is_peer_verified: WARNING: peer did not presented "
			"a certificate. Thus it could not be verified... return -1\n");
		goto error;
	}

	X509_free(x509_cert);

	tcp_conn_release(c, 0);

	LM_DBG("tlsops:is_peer_verified: peer is successfuly verified"
		"...done\n");
	return 1;
error:
	tcp_conn_release(c, 0);
	return -1;
}
