/*
 * Copyright (C) 2007 Alexander Christ,
 *    Cologne University of Applied Sciences
 * Copyright (C) 2009 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
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
 * openser is distributed in the hope that it will be useful,
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
 *  2007-03-29  initial version
 *  2007-04-06  changes regarding pointer types and signess
 *  2009-01-19  majore rework on header manipulation (searching, creating and
 *              adding SIP headers) (bogdan)
 */


/* Some functions are based on examples of [VIE-02].
 * You can download these examples at
 *    http://www.opensslbook.com/code.html.
 *
 * [VIE-02] Viega, John; Messier, Matt; Chandra Pravir: Network Security
 *    with OpenSSL.
 *  First Edition, Beijing, ... : O'Reilly, 2002
 *
 * The function "static STACK_OF(X509) * load_untrusted(char * certfile)" is
 * based on the function"static STACK_OF(X509) *load_untrusted(char *certfile)"
 * of the openssl sources. (apps/verify.c, version 0.9.7e, line 290)
 *
 * Some functions are based on or copied from the source of the Textops module.
 */

#include <fnmatch.h>

/* make strptime available */
#define _GNU_SOURCE
#include <time.h>

#include <stdlib.h>
#include <locale.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ctype.h>
#include <dirent.h>
#include <strings.h>
#include <dlfcn.h>

#include "../../sr_module.h"
#include "../../pvar.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../parser/parse_hname2.h"
#include "../../parser/contact/contact.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "identity.h"


#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_free EVP_MD_CTX_cleanup
#endif

/* parameters */

/* cert of authentication service */
static char * authCert = NULL;
/* private key of authentication service */
static char * privKey = NULL;
/* uri of Identity-Info header field, for authentication
 * service NOT for verifier */
static char * certUri = NULL;
/* path where the verifier can find the certificates */
static char * verCert = NULL;
/* file containing the list of trusted CAs for verifier */
static char * caList = NULL;
/* file containing the list of revoked certificates (crl) for verifier */
static char * crlList = NULL;
/* switch whether crls should be used (1) or not (0), default: not */
static int useCrls = 0;

/* global variables */

/* validity of cert of authentication service: notBefore */
static time_t authCert_notBefore = -1;
/* validity of cert of authentication service: notAfter */
static time_t authCert_notAfter = -1;
/* private key of authentication service */
static EVP_PKEY * privKey_evp = NULL;
/* verCert with a '/' at the end */
static char * verCertWithSlash = NULL;
/* needed for certificate verification */
static X509_STORE * store = NULL;
/* needed for certificate verification */
static X509_STORE_CTX * verify_ctx = NULL;

static cmd_export_t cmds[]={
	{"authservice",(cmd_function)authservice_, {{0,0,0}},
		REQUEST_ROUTE | BRANCH_ROUTE | LOCAL_ROUTE},
	{"verifier",(cmd_function)verifier_, {{0,0,0}},
		REQUEST_ROUTE},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[]={
	{"authCert", STR_PARAM, &authCert},
	{"privKey", STR_PARAM, &privKey},
	{"certUri", STR_PARAM, &certUri},
	{"verCert", STR_PARAM, &verCert},
	{"caList", STR_PARAM, &caList},
	{"crlList", STR_PARAM, &crlList},
	{"useCrls", INT_PARAM, &useCrls},
	{0,0,0}
};

/** module exports */
struct module_exports exports= {
	"identity", /* name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds, /* exported functions */
	0,    /* exported async functions */
	params,	/* parameters to be exportet */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* local processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	(response_function) 0, /* response function */
	mod_destroy, /* destroy function */
	0,           /* per-child init function */
	0            /* reload confirm function */
};



/**
 * init module function
 *    return value: -1: error
 *                   0: else
 */
static int mod_init(void)
{
	LM_INFO("initializing ...\n");

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if(!caList)
	{
		LM_ERR("caList not set\n");
		return 0;
	}

	if(!privKey)
	{
		LM_ERR("modparam privKey not set\n");
		return 0;
	}

	if(!authCert)
	{
		LM_ERR("param authCert not set\n");
		return 0;
	}

	if(!verCert)
	{
		LM_ERR("verCert not set\n");
		return 0;
	}

	if(useCrls && (!crlList))
	{
		LM_ERR("useCrls=1 and crlList not set\n");
		return 0;
	}

	if(!setAuthCertPeriod())
	{
		LM_ERR("initialization failed\n");
		return -1;
	}

	if(!readPrivKey())
	{
		LM_ERR("initialization failed\n");
		return -1;
	}

	if(!certUri)
	{
		LM_ERR("certUri not set\n");
		return -1;
	}

	if(!initVerCertWithSlash())
	{
		LM_ERR("initialization failed\n");
		return -1;
	}

	if(!prepareCertValidation())
	{
		LM_ERR("initialization failed\n");
		return -1;
	}

	return 0;
}


/**
 * destroy function
 */
static void mod_destroy(void)
{
	if(privKey_evp)
	{
		EVP_PKEY_free(privKey_evp);
	}

	if(store)
	{
		X509_STORE_free(store);
	}

	if(verify_ctx)
	{
		X509_STORE_CTX_free(verify_ctx);
	}

	EVP_cleanup();

	if((verCert != verCertWithSlash) && verCertWithSlash)
	{
		pkg_free(verCertWithSlash);
	}
}


/* authentication service
   return value:  -1: error
                  -2: message out of time
                  -3: Date header field does not match validity period of cert
                   1: success
*/
static int authservice_(struct sip_msg* msg, char* str1, char* str2)
{
	time_t dateHFValue = -1;
	int retval = 0;
	char dateHF[MAX_TIME] = "\0";
	long dateDelta = -1;

	/* parse all headers */
	if (parse_headers(msg, HDR_EOH_F, 0)!=0)
	{
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	retval = getDate(dateHF, &dateHFValue, msg);

	switch(retval)
	{
		case 1:
			/* Date header field exists */
			dateDelta = getDateDelta(dateHFValue);
			if((dateDelta >= MAXDATEDELTA_AUTH) || dateDelta < 0)
			{
				return -2;
			}
			break;
		case 0:
			/* Date header field does not exist */
			if(!addDate(dateHF, &dateHFValue, msg))
			{
				LM_ERR("addDate failed\n");
				return -1;
			}
			break;
		case -1:
			LM_ERR("error reading Date header field\n");
			return -1;
			break;
	}

	if(!authCertMatchesDate(dateHFValue))
	{
		return -3;
	}

	/* is content len hdr found ?
	if(msg->content_length)
	{
		if(!addContentLength(msg))
		{
			LM_ERR("addContentLength failed\n");
			return -1;
		}
	}*/


	if(!addIdentity(dateHF, msg))
	{
		LM_ERR("addIdentity failed\n");
		return -1;
	}

	if(!addIdentityInfo(msg))
	{
		LM_ERR("addIdentityInfo failed\n");
		return -1;
	}

	return 1;
}


/* verifier
return value: -438: You should send a 438-reply.
			-437: You should send a 437-reply.
			-436: You should send a 436-reply.
			-428: You should send a 428-reply.
			-3: Error verifying Date header field.
			-2: Authentication service is not authoritative.
			-1: An error occurred.
			1: verification OK
*/
static int verifier_(struct sip_msg* msg, char* str1, char* str2)
{
	char identityHF[MAX_IDENTITY] = "\0";
	X509 * cert = NULL;
	int retval = -1;
	STACK_OF(X509) * certchain = NULL;

	/* parse all headers */
	if (parse_headers(msg, HDR_EOH_F, 0)!=0) {
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	retval = getIdentityHF(identityHF, msg);
	switch(retval)
	{
		case 0:
			/* Identity header field does not exist */
			return -428;
		case -1:
			LM_ERR("getIdentityHF failed\n");
			return -1;
	}

	if(!getCert(&cert, &certchain, msg))
	{
		return -436;
	}

	if(!validateCert(cert, certchain))
	{
		X509_free(cert);
		sk_X509_pop_free(certchain, X509_free);
		return -437;
	}
	sk_X509_pop_free(certchain, X509_free);

	if(!checkAuthority(cert, msg))
	{
		X509_free(cert);
		return -2;
	}

	if(!checkSign(cert, identityHF, msg))
	{
		X509_free(cert);
		return -438;
	}

	if(!checkDate(cert, msg))
	{
		X509_free(cert);
		return -3;
	}

	X509_free(cert);
	return 1;
}


static time_t my_timegm(struct tm *tm)
{
	time_t ret;
	char *tz;

	tz = getenv("TZ");
	setenv("TZ", "", 1);
	tzset();
	ret = mktime(tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();
	return ret;
}


/* reads the Date header field of msg
   return value: -1: error
                  0: Date header field does not exist
                  1: success

   dateHF must point to an array with at least MAX_TIME bytes
*/
static int getDate(char * dateHF, time_t * dateHFValue, struct sip_msg * msg)
{
	struct hdr_field * date = NULL;
	struct tm tmDate;


	if(!dateHF || !dateHFValue || !msg)
	{
		LM_ERR("dateHF, dateHFValue or msg not set\n");
		return -1;
	}

	date = get_header_by_static_name(msg, "Date");
	if (!date)
	{
		return 0;
	}

	if(date->body.len >= MAX_TIME)
	{
		LM_ERR("Date header field to long\n");
		return -1;
	}

	/* date->body.len < MAX_TIME */
	strncpy(dateHF, date->body.s, date->body.len);
	dateHF[date->body.len] = '\0';

	if(!strptime(dateHF, DATE_FORMAT, &tmDate))
	{
		LM_ERR("error while parsing Date header field\n");
		return -1;
	}

	/* covert struct tm to time_t */
	*dateHFValue = my_timegm(&tmDate);
	if(*dateHFValue == -1)
	{
		LM_ERR("error while converting timestamp\n");
		return -1;
	}

	return 1;
}


/* adds a Date header field to msg
   return value:   0: error
                   1: success
*/
static int addDate(char * dateHF, time_t * dateHFValue, struct sip_msg * msg)
{
	#define DATE_HDR_S  "Date: "
	#define DATE_HDR_L  (sizeof(DATE_HDR_S)-1)
	char* buf;
	size_t len = 0;
	struct tm * bd_time = NULL;

	if(!dateHF || !dateHFValue || !msg)
	{
		LM_ERR("dateHF, dateHFValue or msg not set\n");
		return 0;
	}

	*dateHFValue = time(0);

	bd_time = gmtime(dateHFValue);
	if(!bd_time)
	{
		LM_ERR("gmtime failed\n");
		return 0;
	}

	len=strftime(dateHF, MAX_TIME, DATE_FORMAT, bd_time);
	if (len>MAX_TIME-1 || len==0)
	{
		LM_ERR("unexpected time length\n");
		return 0;
	}

	buf = (char*)pkg_malloc(MAX_TIME+DATE_HDR_L+CRLF_LEN);
	if(buf== NULL)
	{
		LM_ERR("no more memory\n");
		return 0;
	}
	memcpy( buf, DATE_HDR_S, DATE_HDR_L);
	memcpy( buf+DATE_HDR_L, dateHF, len);
	memcpy( buf+DATE_HDR_L+len, CRLF, CRLF_LEN);

	if ( id_add_header( msg, buf, DATE_HDR_L+len+CRLF_LEN )!=0) {
		LM_ERR("failed to add Date header\n");
		return 0;
	}

	return 1;
}


/* calculates | now - dateHFValue |
   return value:	result,
   					-1: if an error occurred
*/
static long getDateDelta(time_t dateHFValue)
{
	time_t now;

	now = time(0);
	if(now == -1)
	{
		LM_ERR("time() call failed\n");
		return -1;
	}

	return (labs(now - dateHFValue));
}


/* checks whether certificate of authentication service matches dateHFValue
   return value:	1: dateHFValue matches certificate
   					0: else
*/
static int authCertMatchesDate(time_t dateHFValue)
{
	if ( (dateHFValue >= authCert_notBefore) &&
	(dateHFValue <= authCert_notAfter))
	{
		return 1;
	}

	return 0;
}


/* adds a Content-Length header field to msg
   return value: 1: success
                 0: else

annotation: This function is based on the function search_body_f of the
			Textops module.
static int addContentLength(struct sip_msg * msg)
{
	str body;
	char * tmp = NULL;
	char buf[MAX_CONTENT_LENGTH] = "\0";

	body.s = get_body(msg);
	if (body.s == 0)
	{
		//body does not exist
		body.len = 0;
	}
	else
	{
		//body exists
		body.len = msg->len -(int)(body.s-msg->buf);
	}


	snprintf(buf, MAX_CONTENT_LENGTH, "Content-Length: %i\r\n", body.len);
	buf[MAX_CONTENT_LENGTH - 1] = '\0';

	tmp = buf; //we need a char * for &-operation

	if(add_header_fixup( (void**) &tmp, 1) != 0)
	{
		LOG(L_ERR, "idenity: addContentLength: ERROR: add_header_fixup failed\n");
		return 0;
	}

	if(append_hf_1(msg, tmp, 0) != 1)
	{
		pkg_free(tmp);
		LOG(L_ERR, "identity: addContentLength: ERROR: append_hf_1 failed\n");
		return 0;
	}
	pkg_free(tmp);
	return 1;

}*/


/* builds digest string of msg
   Return value: 1: success
                 0: else
    digestString must point to an array with at least MAX_DIGEST bytes
*/
static int makeDigestString(char * digestString, char * dateHF,
														struct sip_msg * msg)
{
	struct to_body * from = NULL;
	struct to_body * to = NULL;
	struct cseq_body * cseq = NULL;
	struct hdr_field * date = NULL;
	contact_t * contact = NULL;
	unsigned int l;
	str tmp;

	if(!digestString || !msg)
	{
		LM_ERR("not all parameters set\n");
		return 0;
	}

	l = 0;

	/* ###from### */
	if(parse_from_header(msg) != 0)
	{
		LM_ERR("error parsing from header\n");
		return 0;
	}

	from = get_from(msg);
	if(!from)
	{
		LM_ERR("error getting from header\n");
		return 0;
	}

	if (l+from->uri.len+1>MAX_DIGEST) {
		LM_ERR("buffer to short 1\n");
		return 0;
	}
	memcpy( digestString+l, from->uri.s, from->uri.len);
	l += from->uri.len;
	*(digestString+(l++)) = '|';

	/* ###To### */
	to = get_to(msg);
	if(!to)
	{
		LM_ERR("error getting to header\n");
		return 0;
	}

	if (l+to->uri.len+1>MAX_DIGEST) {
		LM_ERR("buffer to short 2\n");
		return 0;
	}
	memcpy( digestString+l, to->uri.s, to->uri.len);
	l += to->uri.len;
	*(digestString+(l++)) = '|';

	/* ###callid### */
	if(!msg->callid)
	{
		LM_ERR("error getting callid header\n");
		return 0;
	}

	if (l+msg->callid->body.len+1>MAX_DIGEST) {
		LM_ERR("buffer to short 3\n");
		return 0;
	}
	memcpy( digestString+l, msg->callid->body.s, msg->callid->body.len);
	l += msg->callid->body.len;
	*(digestString+(l++)) = '|';

	/* ###CSeq### */
	cseq = (struct cseq_body *)msg->cseq->parsed;
	if (!cseq)
	{
		LM_ERR("error getting cseq header\n");
		return 0;
	}

	tmp.s = cseq->number.s;
	tmp.len = cseq->number.len;

	/* strip leading zeros */
	while((*(tmp.s) == '0') && (tmp.len > 1))
	{
		(tmp.s)++;
		(tmp.len)--;
	}

	if (l+tmp.len+cseq->method.len+2>MAX_DIGEST) {
		LM_ERR("buffer to short 4\n");
		return 0;
	}
	memcpy( digestString+l, tmp.s, tmp.len);
	l += tmp.len;
	*(digestString+(l++)) = ' ';
	memcpy( digestString+l, cseq->method.s, cseq->method.len);
	l += cseq->method.len;
	*(digestString+(l++)) = '|';

	/* ###Date### */
	if(!dateHF)
	{
		/* Date header field is taken from msg: verifier */
		date = get_header_by_static_name(msg,"Date");
		if (!date)
		{
			LM_ERR("error getting date header\n");
			return 0;
		}
		tmp = date->body;
	}
	else
	{
		/* Date header field is taken from dateHF: authentication service */
		tmp.s = dateHF;
		tmp.len = strlen(tmp.s);
	}

	if (l+tmp.len+1>MAX_DIGEST) {
		LM_ERR("buffer to short 5\n");
		return 0;
	}
	memcpy( digestString+l, tmp.s, tmp.len);
	l += tmp.len;
	*(digestString+(l++)) = '|';

	/* ###Contact### */
	if(msg->contact)
	{
		if(parse_contact(msg->contact) != 0)
		{
			LM_ERR("error parsing contact header\n");
			return 0;
		}
		/* first contact in list */
		contact = ((contact_body_t *)(msg->contact->parsed))->contacts;
		tmp = contact->uri;
	} else {
		tmp.len = 0;
		tmp.s = 0;
	}

	if (l+tmp.len+1>MAX_DIGEST) {
		LM_ERR("buffer to short 6\n");
		return 0;
	}
	if (tmp.len) {
		memcpy( digestString+l, tmp.s, tmp.len);
		l += tmp.len;
	}
	*(digestString+(l++)) = '|';

	/* ###body### */
	if ( get_body(msg,&tmp)!=0 ) {
		LM_ERR("failed to inspect body\n");
		return 0;
	}
	if (tmp.len != 0) {
		if (l+tmp.len+1>MAX_DIGEST) {
			LM_ERR("buffer to short 7\n");
			return 0;
		}
		memcpy( digestString+l, tmp.s, tmp.len);
		l += tmp.len;
		*(digestString+(l++)) = 0;
	}

	LM_DBG("Digest-String=>%s<\n", digestString);
	return 1;
}


/* adds a Identity header field to msg
return value: 1: success
			0: else
*/
static int addIdentity(char * dateHF, struct sip_msg * msg)
{
	#define IDENTITY_HDR_S  "Identity: \""
	#define IDENTITY_HDR_L  (sizeof(IDENTITY_HDR_S)-1)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX *pctx;
#else
	EVP_MD_CTX ctx, *pctx = &ctx;
#endif
	unsigned int siglen = 0;
	int b64len = 0;
	unsigned char * sig = NULL;
	char digestString[MAX_DIGEST];
	str buf;

	if(!makeDigestString(digestString, dateHF, msg))
	{
		LM_ERR("error making digest string\n");
		return 0;
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	pctx = EVP_MD_CTX_new();
#endif

	EVP_SignInit(pctx, EVP_sha1());

	EVP_SignUpdate(pctx, digestString, strlen(digestString));

	sig = pkg_malloc(EVP_PKEY_size(privKey_evp));
	if(!sig)
	{
		EVP_MD_CTX_free(pctx);
		LM_ERR("failed allocating memory\n");
		return 0;
	}

	if(!EVP_SignFinal(pctx, sig, &siglen, privKey_evp))
	{
		EVP_MD_CTX_free(pctx);
		pkg_free(sig);
		LM_ERR("error calculating signature\n");
		return 0;
	}
	EVP_MD_CTX_free(pctx);

	/* ###Base64-encoding### */
	/* annotation: The next few lines are based on example 7-11 of [VIE-02] */
	b64len = (((siglen + 2) / 3) * 4) + 1;
	buf.len = IDENTITY_HDR_L + b64len + 1 + CRLF_LEN;
	buf.s = pkg_malloc(buf.len);
	if(!buf.s)
	{
		pkg_free(sig);
		LM_ERR("error allocating memory\n");
		return 0;
	}
	memcpy( buf.s, IDENTITY_HDR_S, IDENTITY_HDR_L);
	EVP_EncodeBlock((unsigned char*)(buf.s+IDENTITY_HDR_L), sig, siglen);
	memcpy( buf.s+IDENTITY_HDR_L+b64len, "\""CRLF, CRLF_LEN+1);

	pkg_free(sig);

	if ( id_add_header( msg, buf.s, buf.len )!=0) {
		pkg_free(buf.s);
		LM_ERR("failed to add Identity header\n");
		return 0;
	}

	return 1;
}


/* adds an Identity-Info header field to msg
   Return value: 1: success
                 0: else
*/
static int addIdentityInfo(struct sip_msg * msg)
{
	#define IDENTITY_INFO_HDR_S "Identity-Info: <"
	#define IDENTITY_INFO_HDR_L (sizeof(IDENTITY_INFO_HDR_S)-1)
	#define IDENTITY_INFO_PARAM_S ">;alg=rsa-sha1"
	#define IDENTITY_INFO_PARAM_L (sizeof(IDENTITY_INFO_PARAM_S)-1)
	char *buf = NULL;
	int len = 0;
	char *p;

	len = IDENTITY_INFO_HDR_L + strlen(certUri) +
		IDENTITY_INFO_PARAM_L + CRLF_LEN;
	buf = (char*)pkg_malloc(len);
	if (buf==NULL) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}
	p = buf;
	memcpy( p, IDENTITY_INFO_HDR_S, IDENTITY_INFO_HDR_L);
	p += IDENTITY_INFO_HDR_L;
	memcpy( p, certUri, strlen(certUri) );
	p += strlen(certUri);
	memcpy( p, IDENTITY_INFO_PARAM_S CRLF, IDENTITY_INFO_PARAM_L+CRLF_LEN);

	if ( id_add_header( msg, buf, len )!=0) {
		LM_ERR("failed to add Identity-Info header\n");
		return 0;
	}

	return 1;
}


/* reads Identity header field from msg
   Return value: 1: success
                 0: Identity header field does not exist
                 1: else
   identityHF must point to an array with at least MAX_IDENTITY bytes
*/
static int getIdentityHF(char * identityHF, struct sip_msg * msg)
{
	struct hdr_field * identity = NULL;

	if(!identityHF || !msg)
	{
		LM_ERR("identityHF or msg not set\n");
		return -1;
	}

	identity = get_header_by_static_name(msg, "Identity");
	if (!identity)
	{
		/* Identity header field does not exist */
		return 0;
	}

	if(((identity->body.len) - 2) >= MAX_IDENTITY)
	{
		LM_ERR("identity header to long\n");
		return -1;
	}

	/* " at the beginning and at the end are cutted */
	memcpy( identityHF, identity->body.s+1, identity->body.len-2);
	identityHF[(identity->body.len) - 2] = '\0';

	return 1;
}


/* checks whether msg contains an Identity-Info header field; if yes,
   the cert is readed
   Return value: 1: success; *certp + *certchainp point to data
                 0: else, *certp + *certchainp empty
*/
static int getCert(X509 ** certp, STACK_OF(X509) ** certchainp,
														struct sip_msg * msg)
{
	struct hdr_field * identityInfo = NULL;
	int uriLen = 0;
	char * end = NULL;
	char * begin = NULL;
	char uri[MAX_IDENTITY_INFO] = "\0";
	char filename[MAX_FILENAME] = "\0";
	FILE * fp = NULL;
	char backup;

	if(!certp || !msg || !certchainp)
	{
		LM_ERR("certp, certchainp or msg not set\n");
		return 0;
	}

	identityInfo = get_header_by_static_name(msg, "Identity-Info");
	if (!identityInfo)
	{
		/* Identity-Info header field does not exist */
		return 0;
	}

	if((identityInfo->body.len) >= MAX_IDENTITY_INFO)
	{
		LM_ERR("identity-info header to long\n");
		return 0;
	}

	backup = identityInfo->body.s[identityInfo->body.len];
	identityInfo->body.s[identityInfo->body.len] = 0;

	/* check, whether the algorithm is rsa-sha1 */
	if(fnmatch("*;*alg*=*rsa-sha1*", identityInfo->body.s, FNM_CASEFOLD) != 0)
	{
		LM_INFO("unknown alg-parameter in Identity-Info header field\n");
		identityInfo->body.s[identityInfo->body.len] = backup;
		return 0;
	}

	//begin and end of uri (filename)
	begin = strchr( identityInfo->body.s, '<');
	end = strchr( identityInfo->body.s, '>');

	identityInfo->body.s[identityInfo->body.len] = backup;

	if(!begin || !end)
	{
		LM_ERR("unable to get uri from Identity-Info header field\n");
		return 0;
	}

	uriLen = end - begin - 1;
	if (uriLen+1>MAX_IDENTITY_INFO) {
		LM_ERR("identity uri too long\n");
		return 0;
	}

	memcpy(uri, begin+1, uriLen);
	uri[uriLen] = '\0';

	/* replace forbidden characters */
	if(!uri2filename(uri))
	{
		LM_ERR("error while uri2filename\n");
		return 0;
	}

	/* path */
	strncpy(filename, verCertWithSlash, MAX_FILENAME - 1);
	filename[MAX_FILENAME - 1] = '\0';

	/* complete filename */
	strncat(filename, uri, (MAX_FILENAME - strlen(filename) - 1));

	fp = fopen(filename, "r");
	if(!fp)
	{
		LM_INFO("unable to open file \"%s\"\n", filename);
		return 0;
	}

	LM_DBG("file \"%s\" opened\n", filename);

	*certp = PEM_read_X509(fp, NULL, NULL, NULL);
	if(!(*certp))
	{
		fclose(fp);
		LM_ERR("unable to read cert from file \"%s\"\n", filename);
		return 0;
	}
	fclose(fp);

	*certchainp = load_untrusted(filename);
	if(!(*certchainp))
	{
		X509_free(*certp);
		LM_ERR("unable to read certchain from file \"%s\"\n", filename);
		return 0;
	}

	return 1;
}


/* checks whether cert is valid
   Return value: 1: success, cert is valid
                 0: else

   Annotation: This function is based on example 10-7 of [VIE-02].
*/
static int validateCert(X509 * cert, STACK_OF(X509) * certchain)
{
	int result = 0;

	if(!cert || !certchain)
	{
		LM_ERR("cert or certchain not set\n");
		return 0;
	}

	/* X509_STORE_CTX_init did not return an error condition
	   in prior versions */
	if(X509_STORE_CTX_init(verify_ctx, store, cert, certchain) != 1)
	{
		X509_STORE_CTX_cleanup(verify_ctx);
		LM_ERR("Error initializing verification context\n");
		return 0;
	}

	result = X509_verify_cert(verify_ctx);
	X509_STORE_CTX_cleanup(verify_ctx);

	if(result != 1)
	{
		LM_INFO("Error verifying the certificate\n");
		return 0;
	}

	return 1;
}


/* checks whether the signing authentication service is authoritative
   for the URI in the From header field.
   Return value: 1: authentication service is authoritative
                 0: else
   Annotation: This function is based on example 5-8 of [VIE-02].
*/
static int checkAuthority(X509 * cert, struct sip_msg * msg)
{
	struct to_body * from = NULL;
	struct sip_uri fromUri;
	char hostname[MAX_HOSTNAME] = "\0";
	char tmp[MAX_HOSTNAME] = "\0";
	int foundDNSName = 0;

	int num, i, j;
	X509_EXTENSION * cext;
	char * extstr;
	X509V3_EXT_METHOD * meth;
	void * ext_str = NULL;
	const unsigned char * data;
	STACK_OF(CONF_VALUE) * val;
	CONF_VALUE * nval;
	int len;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ASN1_OCTET_STRING *adata;
#endif

	if(!cert || !msg)
	{
		LM_ERR("msg or cert not set\n");
		return 0;
	}

	if(parse_from_header(msg) != 0)
	{
		LM_ERR("error parsing from header\n");
		return 0;
	}

	from = get_from(msg);
	if(!from)
	{
		LM_ERR("error getting from header\n");
		return 0;
	}

	if(parse_uri(from->uri.s, from->uri.len, &fromUri) != 0)
	{
		LM_ERR("error parsing from uri\n");
		return 0;
	}

	if((fromUri.host.len) >= MAX_HOSTNAME)
	{
		LM_ERR("from-hostname to long\n");
		return 0;
	}

	strncpy(hostname, fromUri.host.s, fromUri.host.len);
	hostname[fromUri.host.len] = '\0';

	/* first, check subjectAltName extensions */
	num = X509_get_ext_count(cert);

	for(i = 0; i < num; i++)
	{
		cext = X509_get_ext(cert, i);

		extstr = (char *)
			OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(cext)));

		if(!strcmp(extstr, "subjectAltName"))
		{
			if(!(meth = (X509V3_EXT_METHOD*)X509V3_EXT_get(cext)))
			{
				LM_ERR("X509V3_EXT_get failed\n");
				return 0;
			}
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			adata = X509_EXTENSION_get_data(cext);
			data = ASN1_STRING_get0_data(adata);
			len = ASN1_STRING_length(adata);
#else
			data = cext->value->data;
			len = cext->value->length;
#endif
			if(meth->it)
			{
				ext_str = ASN1_item_d2i(NULL, &data,
					len, ASN1_ITEM_ptr(meth->it));
			}
			else
			{
				 ext_str = meth->d2i(NULL, &data, len);
			}

			val = meth->i2v(meth, ext_str, NULL);

			for (j = 0;  j < sk_CONF_VALUE_num(val);  j++)
			{
				nval = sk_CONF_VALUE_value(val, j);

				if(!strcmp(nval->name, "DNS"))
				{
					/* entry of type dNSName found */
					foundDNSName = 1;

					if(hostNameMatch(hostname, nval->value) == 1)
					{
						/* authentication service is authoritative */
						return 1;
					}
				}
			}
		}
	}

	/* if no subjectAltName extension is found, Common Name of subject
	   will be checked */
	if(foundDNSName == 0)
	{
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
			NID_commonName, tmp, MAX_HOSTNAME);
		tmp[MAX_HOSTNAME - 1] = '\0';

		if(hostNameMatch(hostname, tmp) == 1)
		{
			/* authentication service is authoritative */
			return 1;
		}
	}
	return 0;
}


/* checks the sinature
   Return value: 1: signature OK
                 0: else
*/
static int checkSign(X509 * cert, char * identityHF, struct sip_msg * msg)
{
	EVP_PKEY * pubkey = NULL;
	char digestString[MAX_DIGEST] = "\0";
	int siglen = -1;
	unsigned char * sigbuf = NULL;
	int b64len = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_MD_CTX *pctx;
#else
	EVP_MD_CTX ctx, *pctx = &ctx;
#endif
	int result = 0;
	char *p;
	unsigned long err;

	if(!cert || !identityHF || !msg)
	{
		LM_ERR("cert or identityHF or msg not set\n");
		return 0;
	}

	if(!makeDigestString(digestString, NULL, msg))
	{
		LM_ERR("error creating digest string\n");
		return 0;
	}

	b64len = strlen(identityHF);
	if(b64len < 4)
	{
		LM_ERR("base64 string to short\n");
		return 0;
	}

	/* data size decreases during base64 decoding */
	sigbuf = pkg_malloc(b64len + 1);
	if(!sigbuf)
	{
		LM_ERR("error allocating memory\n");
		return 0;
	}

	siglen = EVP_DecodeBlock(sigbuf, (unsigned char *)identityHF, b64len);
	if(siglen <= 1)
	{
		pkg_free(sigbuf);
		LM_ERR("error base64-decoding Identity header field\n");
		return 0;
	}
	/* EVP_DecodeBlock counts the terminating '=', but this padding character does not
	belong to the signature.*/
	p=strstr(identityHF , "=");
	siglen-=strspn(p , "=");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	pctx = EVP_MD_CTX_new();
#endif
	EVP_VerifyInit(pctx, EVP_sha1());
	EVP_VerifyUpdate(pctx, digestString, strlen(digestString));

	pubkey = X509_get_pubkey(cert);
	if(!pubkey)
	{
		EVP_MD_CTX_free(pctx);
		pkg_free(sigbuf);
		LM_ERR("error reading pubkey from cert\n");
		return 0;
	}

	result = EVP_VerifyFinal(pctx, sigbuf, siglen, pubkey);

	EVP_PKEY_free(pubkey);
	EVP_MD_CTX_free(pctx);
	pkg_free(sigbuf);

	switch(result)
	{
		case -1:
			LM_ERR("error verifying signature\n");
			return 0;
		case 0:
			err=ERR_get_error();
			LM_ERR("signature not valid Reason: %s\n",ERR_reason_error_string(err));
			return 0;
		case 1:
			return 1;
		default:
			LM_ERR("unknown error verifying signature\n");
			return 0;
	}
}


/* checks the Date header field:
   - difference between now and Date header field must be smaller
     than +-MAXDATEDELTA_VER
   - Date header field and validity period of cert must match
   Return value: 1: OK
                 0: else
*/
static int checkDate(X509 * cert, struct sip_msg * msg)
{
	char dateHF[MAX_TIME] = "\0"; // dummy for calling getDate
	time_t timeOfDateHF = -1;
	time_t certNotBefore = -1;
	time_t certNotAfter = -1;
	long dateDelta = -1;

	if(getDate(dateHF, &timeOfDateHF, msg) != 1)
	{
		LM_ERR("error getting date of msg\n");
		return 0;
	}

	/* now <--> Date header field */
	dateDelta = getDateDelta(timeOfDateHF);
	if(dateDelta == -1)
	{
		LM_ERR("error calculating date delta\n");
		return 0;
	}

	if(dateDelta > MAXDATEDELTA_VER)
	{
		LM_INFO("date delta > MAXDATEDELTA_VER\n");
		return 0;
	}

	/* Date header field <--> certificate */
	if(!getCertValidity(cert, &certNotBefore, &certNotAfter))
	{
		LM_ERR("getCertValidity failed\n");
		return 0;
	}

	if((timeOfDateHF < certNotBefore) || (timeOfDateHF > certNotAfter))
	{
		LM_INFO("date header field and validity period of cert "
			"do not match\n");
		return 0;
	}

	return 1;
}



//#########################helper functions#########################

/* parses a date from a certificate
return value: date; -1 for an error
*/
static time_t parseX509Date(ASN1_STRING * dateString)
{
	unsigned char * tmp = NULL;
	struct tm tmDate;

	if(!dateString)
	{
		LM_ERR("dateString not set\n");
		return -1;
	}

	if((ASN1_UTCTIME_check(dateString)) && (dateString->length == 13))
	{
		/* UTCTIME string, GMT
		YYMMDDhhmmssZ
		*/

		tmp = dateString->data;

		tmDate.tm_year = (tmp[0] - '0') * 10 + (tmp[1] - '0');
		if(tmDate.tm_year < 50) //see chap. 4.1.2.5.1, rfc 3280
		{
			tmDate.tm_year = tmDate.tm_year + 100;
		}

		tmDate.tm_mon = (tmp[2] - '0') * 10 + (tmp[3] - '0') - 1;
		tmDate.tm_mday = (tmp[4] - '0') * 10 + (tmp[5] - '0');
		tmDate.tm_hour = (tmp[6] - '0') * 10 + (tmp[7] - '0');
		tmDate.tm_min = (tmp[8] - '0') * 10 + (tmp[9] - '0');
		tmDate.tm_sec = (tmp[10] - '0') * 10 + (tmp[11] - '0');

		return (my_timegm(&tmDate));
	}

	/* needed for years >= 2050 */
	if ((ASN1_GENERALIZEDTIME_check(dateString)) && (dateString->length == 15))
	{
		/* GENERALIZEDTIME string; GMT
		YYYYMMDDhhmmssZ
		*/
		tmp = dateString->data;

		tmDate.tm_year = (tmp[0] - '0') * 1000 +
			(tmp[1] - '0') * 100 + (tmp[2] - '0') * 10 + (tmp[3] - '0') - 1900;

		tmDate.tm_mon = (tmp[4] - '0') * 10 + (tmp[5] - '0') - 1;
		tmDate.tm_mday = (tmp[6] - '0') * 10 + (tmp[7] - '0');
		tmDate.tm_hour = (tmp[8] - '0') * 10 + (tmp[9] - '0');
		tmDate.tm_min = (tmp[10] - '0') * 10 + (tmp[11] - '0');
		tmDate.tm_sec = (tmp[12] - '0') * 10 + (tmp[13] - '0');

		return (my_timegm(&tmDate));
	}

	return -1;
}


/* sets authCert_notBefore and authCert_notAfter, checks whether
   cert is valid now
      return value: 1: success
                    0: else
*/
static int setAuthCertPeriod(void)
{
	FILE * fp = NULL;
	X509 * authCertX509 = NULL;//cert of authentication service
	time_t now = -1;

	fp = fopen(authCert, "r");
	if(!fp)
	{
		LM_ERR("could not open authCert: %s\n", authCert);
		return 0;
	}

	authCertX509 = PEM_read_X509(fp, NULL, NULL, NULL);
	if(!authCertX509)
	{
		fclose(fp);
		LM_ERR("could not read certificate of authentication service\n");
		return 0;
	}

	fclose (fp);

	if(!getCertValidity(authCertX509, &authCert_notBefore, &authCert_notAfter))
	{
		X509_free(authCertX509);
		LM_ERR("could not get validity of authCert\n");
		return 0;
	}

	X509_free(authCertX509);

	now = time(0);
	if(now == -1)
	{
		LM_ERR("time failed\n");
		return 0;
	}

	if(!authCertMatchesDate(now))
	{
		LM_ERR("authCert is not valid now\n");
		return 0;
	}

	return 1;
}


/* reads the validity of cert and sets notBefore and notAfter
   return value:  1: success
                  0: else
*/
static int getCertValidity(X509 * cert, time_t * notBefore, time_t * notAfter)
{
	ASN1_STRING * notBeforeSt = NULL;
	ASN1_STRING * notAfterSt = NULL;

	if(!cert || !notBefore || !notAfter)
	{
		LM_ERR("some parameters not set\n");
		return 0;
	}

	notBeforeSt = X509_get_notBefore(cert);
	notAfterSt = X509_get_notAfter(cert);

	if(!notBeforeSt || !notAfterSt)
	{
		LM_ERR("failed to read cert-values\n");
		return 0;
	}

	*notBefore = parseX509Date(notBeforeSt);
	*notAfter = parseX509Date(notAfterSt);

	if(*notBefore < 0 || *notAfter < 0)
	{
		LM_ERR("failed to parse notBefore or notAfter\n");
		return 0;
	}

	return 1;
}


/* reads private key of authentication service and stores it in privKey_evp
   return value: 1: success
                 0: else
*/
static int readPrivKey(void)
{
	FILE * fp = NULL;

	fp = fopen(privKey, "r");
	if (!fp)
	{
		LM_ERR("could not open privKey: %s\n", privKey);
		return 0;
	}

	privKey_evp = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if(!privKey_evp)
	{
		fclose(fp);
		LM_ERR("could not read privKey\n");
		return 0;
	}
	fclose(fp);

	return 1;
}


/* replaces every forbidden char with a '-'. Only alphanumeric characters,
   '_' and '.' are allowed. If the first char is a '.', 0 is returned also.
   Return value: 1: success
                 0: else
*/
static int uri2filename(char * name)
{
	if(!name)
	{
		return 0;
	}

	if(name[0] == '.')
	{
		LM_ERR("uri starts with '.'\n");
		return 0;
	}

	while(*name != '\0')
	{
		if(!isalnum(*name) && (*name != '_') && (*name != '.'))
		{
			*name = '-';
		}
		name++;
	}

	return 1;
}


/* sets verCertWithSlash, verCert is used, If necessary, a '/' is
   added at the end.
   Return value: 1: success
                 0: else
*/
static int initVerCertWithSlash(void)
{
	DIR * dirTmp = NULL;
	int len = 0;

	len = strlen(verCert);
	if(verCert[len - 1] != '/')
	{
		/* add a '/' */
		verCertWithSlash = pkg_malloc(len + 2);
		if(!verCertWithSlash)
		{
			LM_ERR("pkg_malloc failed\n");
			return 0;
		}

		strcpy(verCertWithSlash, verCert);
		verCertWithSlash[len] = '/';
		verCertWithSlash[len+1] = '\0';
	}
	else
	{
		verCertWithSlash = verCert;
	}

	/* check whether path exists or not */
	dirTmp = opendir(verCertWithSlash);

	if(!dirTmp)
	{
		LM_ERR("unable to open verCert directory\n");
		return 0;
	}
	closedir(dirTmp);

	return 1;
}


/* prepares cert validation for verifier
   return value: 1: success
                 0: else
   annotation: This function is based on example 10-7 of [VIE-02].
*/
static int prepareCertValidation(void)
{
	X509_LOOKUP * lookup = NULL;

	seed_prng();

	/* create the cert store and set the verify callback */
	store = X509_STORE_new();
	if(!store)
	{
		LM_ERR("Error creating X509_STORE_CTX object\n");
		return 0;
	}
	X509_STORE_set_verify_cb_func(store, verify_callback);

	/* load the CA certificates and CRLs */
	if(X509_STORE_load_locations(store, caList, NULL) != 1)
	{
		LM_ERR("Error loading the caList\n");
		return 0;
	}
	if(X509_STORE_set_default_paths(store) != 1)
	{
		LM_ERR("Error loading the system-wide CA certificates\n");
		return 0;
	}
	if(!(lookup = X509_STORE_add_lookup (store, X509_LOOKUP_file ())))
	{
		LM_ERR("Error creating X509_LOOKUP object\n");
		return 0;
	}

	if(useCrls)
	{
		if(X509_load_crl_file(lookup, crlList, X509_FILETYPE_PEM) < 1)
		{
			/* changed from !=1 to < 1
			return value = number of loaded crls
			*/
			LM_ERR("Error reading the crlList file\n");
			return 0;
		}
		/* enabling verification against CRLs is
		   not possible in prior versions */
		/* set the flags of the store so that CRLs are consulted */
		X509_STORE_set_flags(store,
				X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	/* create a verification context and initialize it */
	if(!(verify_ctx = X509_STORE_CTX_new()))
	{
		LM_ERR("Error creating X509_STORE_CTX object\n");
		return 0;
	}

	return 1;
}


/* logs the reason of an negative verification result
   return value: ok
   annotation: This function is based on example 10-7 of [VIE-02].
*/
static int verify_callback(int ok, X509_STORE_CTX * stor)
{
	if (!ok)
	{
		int err = X509_STORE_CTX_get_error(stor);
		LM_INFO("certificate validation failed: %s\n",
			X509_verify_cert_error_string(err));
	}

	return ok;
}


/*
  annotation: This function is copied from file ssl/common.c of [VIE-02].
*/
void seed_prng(void)
{
	RAND_load_file("/dev/urandom", 1024);
}


/* loads a certificate chain
   return value: STACK_OF(X509) *: on success
                 NULL: else
   annotation: This function is based on the function
      "static STACK_OF(X509) *load_untrusted(char *certfile)" of the openssl
       sources. (apps/verify.c, version 0.9.7e, line 290)
*/
static STACK_OF(X509) * load_untrusted(char * certfile)
{
	STACK_OF(X509_INFO) *sk=NULL;
	STACK_OF(X509) *stack=NULL, *ret=NULL;
	BIO *in=NULL;
	X509_INFO *xi=NULL;

	stack = sk_X509_new_null();
	if(!stack)
	{
		LM_ERR("memory allocation failure\n");
		goto end;
	}

	in=BIO_new_file(certfile, "r");
	if(!in)
	{
		LM_ERR("error opening the file, %s\n",certfile);
		goto end;
	}

	/* This loads from a file, a stack of x509/crl/pkey sets */
	sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL);
	if(!sk)
	{
		LM_ERR("error reading the file, %s\n",certfile);
		goto end;
	}

	/* scan over it and pull out the certs */
	while(sk_X509_INFO_num(sk))
	{
		xi=sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL)
		{
			sk_X509_push(stack,xi->x509);
			xi->x509 = NULL;
		}
		X509_INFO_free(xi);
	}

	if(!sk_X509_num(stack))
	{
		LM_ERR("no certificates in file, %s\n",certfile);
		sk_X509_free(stack);
		goto end;
	}
	ret = stack;

end:
	BIO_free(in);
	sk_X509_INFO_free(sk);
	return(ret);
}


/* counts how many '.' arg contains
   return value: number of '.' (>=0)
                 -1: error
*/
static int pcount(char * arg)
{
	int i = 0;

	if(!arg)
	{
		LM_ERR("arg not set\n");
		return -1;
	}

	while(*arg != '\0')
	{
		if(*arg == '.')
		{
			i++;
		}
		arg++;
	}
	return(i);
}


/* checks if fromHostname matches certHostname
return value: 1: fromHostname matches certHostname
			0: else
*/
static int hostNameMatch(char * fromHostname, char * certHostname)
{
	if(!fromHostname || !certHostname)
	{
		LM_ERR("fromHostname or certHostname not set\n");
		return 0;
	}

	if(strpbrk(certHostname, HOSTNAME_ILLCHAR))
	{
		/* avoid that '[' or '?' are interpreted by fnmatch */
		LM_ERR("illegal chars in certHostname\n");
		return 0;
	}

	if(pcount(certHostname) != pcount(fromHostname))
	{
		/* check, whether number of points is equal
		   rfc2818: "Names may contain the wildcard
		   character * which is considered to match any single domain name
		   component or component fragment. E.g., *.a.com matches foo.a.com but
		   not bar.foo.a.com. f*.com matches foo.com but not bar.com.
		*/
		LM_INFO("pcount of certHostname and fromHostname not matched - "
		"certHostname=[%s] - fromHostname=[%s]\n",certHostname,fromHostname);
		return 0;
	}

	/* FNM_CASEFOLD = case-insensitive */
	if(fnmatch(certHostname, fromHostname, FNM_CASEFOLD) != 0)
	{
		LM_INFO("certHostname and fromHostname do not match\n");
		return 0;
	}
	return 1;
}



static int id_add_header(struct sip_msg* msg, char* s, int len)
{
	struct lump* anchor;

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (!anchor) {
		LM_ERR("can't get anchor\n");
		return -1;
	}


	if (!insert_new_lump_before(anchor, s, len, 0)) {
		LM_ERR("can't insert lump\n");
		return -1;
	}

	return 0;
}

