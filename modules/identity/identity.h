/*
 *Copyright (C) 2007 Alexander Christ,
 * Cologne University of Applied Sciences
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 * History:
 * -------
 *  2007-03-29  initial version
 *  2007-04-06  added GPL copyright, #ifndef ... ; changed MIN macro
 *
 */

#ifndef _IDENTITY_H_
#define _IDENTITY_H_

/* Solaris does not define FNM_CASEFOLD for fnmatch() */
#ifdef __OS_solaris
#define FNM_CASEFOLD FNM_IGNORECASE
#endif

#define MAX_TIME 64 //max. length of timestamp
#define DATE_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define MAXDATEDELTA_AUTH 600 //max. allowed | dateHF - now | for authentication service in seconds
#define MAXDATEDELTA_VER 3600 //max. allowed | dateHF - now | for verifier in seconds
#define MAX_CONTENT_LENGTH 25 //max. length of body of Content-Length header field
#define MAX_DIGEST 2048 //max. length of digest string
#define MAX_IDENTITY 800 // max. length of Identity header field
#define MAX_IDENTITY_INFO 100 //max. length of Idenity-Info header field
#define MAX_FILENAME 200 //max. length of string containing a filename
#define MAX_HOSTNAME 50 //max. lenght of hostname of From header field

#define HOSTNAME_ILLCHAR "?[" //forbidden characters in certHostname

#define MIN(a, b) ((a < b) ? a : b)

static int mod_init(void);
static void mod_destroy(void);

static int authservice_(struct sip_msg* msg, char* str1, char* str2);
static int verifier_(struct sip_msg* msg, char* str1, char* str2);
static int getDate(char * dateHF, time_t * dateHFValue, struct sip_msg * msg);
static int addDate(char * dateHF, time_t * dateHFValue, struct sip_msg * msg);
static long getDateDelta(time_t dateHFValue);
static int authCertMatchesDate(time_t dateHFValue);
static int makeDigestString(char * digestString, char * dateHF, struct sip_msg * msg);
static int addIdentity(char * dateHF, struct sip_msg * msg);
static int addIdentityInfo(struct sip_msg * msg);
static int getIdentityHF(char * identityHF, struct sip_msg * msg);
static int getCert(X509 ** certp, STACK_OF(X509) ** certchainp, struct sip_msg * msg);
static int validateCert(X509 * cert, STACK_OF(X509) * certchain);
static int checkAuthority(X509 * cert, struct sip_msg * msg);
static int checkSign(X509 * cert, char * identityHF, struct sip_msg * msg);
static int checkDate(X509 * cert, struct sip_msg * msg);

static int uri2filename(char * name);
static time_t parseX509Date(ASN1_STRING * dateString);
static int setAuthCertPeriod();
static int getCertValidity(X509 * cert, time_t * notBefore, time_t * notAfter);
static int readPrivKey();
static int initVerCertWithSlash();
static int prepareCertValidation();
static int verify_callback(int ok, X509_STORE_CTX * stor);
static void seed_prng(void);
static STACK_OF(X509) * load_untrusted(char * certfile);
static int pcount(char * arg);
static int hostNameMatch(char * fromHostname, char * certHostname);

static int id_add_header(struct sip_msg* msg, char* s, int len);

#endif
