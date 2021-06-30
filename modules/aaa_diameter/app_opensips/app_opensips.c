/*********************************************************************************************************
* Software License Agreement (BSD License)                                                               *
* Author: Liviu Chircu <liviu@opensips.org>								 *
*													 *
* Copyright (c) 2021, OpenSIPS Solutions								 *
* All rights reserved.											 *
* 													 *
* Redistribution and use of this software in source and binary forms, with or without modification, are  *
* permitted provided that the following conditions are met:						 *
* 													 *
* * Redistributions of source code must retain the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer.										 *
*    													 *
* * Redistributions in binary form must reproduce the above 						 *
*   copyright notice, this list of conditions and the 							 *
*   following disclaimer in the documentation and/or other						 *
*   materials provided with the distribution.								 *
* 													 *
* * Neither the name of the WIDE Project or NICT nor the 						 *
*   names of its contributors may be used to endorse or 						 *
*   promote products derived from this software without 						 *
*   specific prior written permission of WIDE Project and 						 *
*   NICT.												 *
* 													 *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED *
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A *
* PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 	 *
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 	 *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR *
* TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF   *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.								 *
*********************************************************************************************************/

/**
 * This extension is compatible with OpenSIPS 3.2+ releases and offers:
 *   - accounting support.  Records arrive via ACR messages and are
 *         continuously appended to a file on disk.
 *
 *   - digest authentication support.  This is done via MAR messages (RFC 4740
 *         SIP Application), where "app_opensips" compares the user-provided
 *         digest response with its own digest response computation using
 *         pre-cached password hashes taken from MySQL or Postgres.
 */

#include <mysql.h>
#include <gcrypt.h>
#include <freeDiameter/extension.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

#include "avps.h"

#define NO_STATE_MAINTAINED 1

MYSQL *db_conn;
static char *db_host = "localhost";
static char *db_user = "opensips";
static char *db_pass = "opensipsrw";
static char *db_db = "opensips";
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct {
	struct dict_object * Accounting_Record_Number;
	struct dict_object * Accounting_Record_Type;
	struct dict_object * Acct_Session_Id;
	struct dict_object * Event_Timestamp;

	struct dict_object * Auth_Application_Id;
	struct dict_object * Auth_Session_State;
	struct dict_object * User_Name;
	struct dict_object * Digest_Username;
	struct dict_object * Digest_Realm;
	struct dict_object * Digest_Nonce;
	struct dict_object * Digest_Method;
	struct dict_object * Digest_URI;
	struct dict_object * Digest_Response;
} dm_dict;

#define ACC_MAX_DAYS 10
static FILE *acc_log[ACC_MAX_DAYS];
static char *acc_log_dir = "/var/log/freeDiameter";
static char *acc_log_path = "/var/log/freeDiameter/acc.log";
static int acc_log_idx = -1;
static pthread_mutex_t acc_rotate_lock = PTHREAD_MUTEX_INITIALIZER;
static int acc_log_cdrs;

struct _str {
	char *s;
	int len;
};
typedef struct _str str;


static int init_acc_log(void)
{
	pthread_mutexattr_t mattr;
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(&acc_rotate_lock, &mattr);
	pthread_mutexattr_destroy(&mattr);

	FILE *f = fopen(acc_log_path, "a");
	if (!f) {
		/* create the basedir, in an attempt to fix the issue */
		if (mkdir(acc_log_dir, 0775) < 0)
			fd_log_error("[ACC] failed to create directory %s (%d: %s)",
				acc_log_dir, errno, strerror(errno));

		f = fopen(acc_log_path, "a");
		if (!f) {
			fd_log_error("[ACC] failed to open %s (%d: %s)", acc_log_path,
				errno, strerror(errno));
			return -1;
		}
	}

	acc_log_cdrs = 1;
	return 0;
}

static int init_auth(void)
{
	const int mysql_reconnect_val = 1;

	db_conn = mysql_init(NULL);
	mysql_options(db_conn, MYSQL_OPT_RECONNECT, &mysql_reconnect_val);

	/* Connect to database */
	if (!mysql_real_connect(db_conn, db_host,
			db_user, db_pass, db_db, 0, NULL, 0)) {
		fd_log_error("[AUTH] failed to connect to MySQL: %s", mysql_error(db_conn));
		return errno;
	} else {
		fd_log_debug("[AUTH] connected to MySQL");
	}

	return 0;
}

static FILE *get_acc_log(void)
{
	static int last_day = -1;
	time_t now = time(NULL);
	int current_day = (*localtime(&now)).tm_yday;
	char fp_buf[128], *fpath;

	pthread_mutex_lock(&acc_rotate_lock);

	if (last_day == -1 || last_day != current_day) {
		if (acc_log_idx != -1) {
			fclose(acc_log[acc_log_idx]);
			acc_log[acc_log_idx] = NULL;
		}

		acc_log_idx = (acc_log_idx + 1) % ACC_MAX_DAYS;

		if (acc_log_idx > 0) {
			sprintf(fp_buf, "%s.%d", acc_log_path, acc_log_idx);
			fpath = fp_buf;
		} else {
			fpath = acc_log_path;
		}

		acc_log[acc_log_idx] = fopen(fpath, "a");
		fd_log_debug("[ACC] opened %s for writing (append mode)", fpath);
		if (!acc_log[acc_log_idx]) {
			fd_log_error("[ACC] failed to open %s (%d: %s)\n", fpath, errno, strerror(errno));
			return NULL;
		}

		last_day = current_day;
	}

	pthread_mutex_unlock(&acc_rotate_lock);

	return acc_log[acc_log_idx];
}

#define IOV_ADD_NUMBER(number) \
	{\
		buf[nums] = malloc(20 + 1); \
		iov[n].iov_len = sprintf(buf[nums], "%lld", (long long)number); \
		iov[n].iov_base = buf[nums]; \
		nums++; n++; \
		iov[n].iov_base = ","; \
		iov[n].iov_len = 1; \
		n++; \
	}

#define IOV_ADD_STRING(str_val, str_len) \
	{\
		iov[n].iov_base = str_val; \
		iov[n].iov_len = str_len; \
		n++; \
		iov[n].iov_base = ","; \
		iov[n].iov_len = 1; \
		n++; \
	}

#define IOV_CLEANUP() \
	{\
		for (nums -= 1; nums > 0; nums--) \
			free(buf[nums]); \
	}

/* Callback for incoming Base Accounting application messages */
static int acc_request( struct msg ** msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	#define MAX_ACC_COLS  100
	struct iovec iov[MAX_ACC_COLS * 2];
	char *buf[MAX_ACC_COLS];
	struct msg_hdr *hdr = NULL;
	int rc, n = 0, nums = 0;

	fd_log_debug("[ACC] request received");
	TRACE_ENTRY("%p %p %p %p", msg, avp, sess, act);

	if (msg == NULL)
		return EINVAL;

	/* Check what we received */
	CHECK_FCT( fd_msg_hdr(*msg, &hdr) );

	if (hdr->msg_flags & CMD_FLAG_REQUEST) {
		/* It was a request, create an answer */
		struct msg *ans, *qry;
		struct avp * a = NULL;
		struct avp_hdr * h = NULL;
		os0_t s;
		size_t sl;

		qry = *msg;
		/* Create the answer message, including the Session-Id AVP */
		CHECK_FCT( fd_msg_new_answer_from_req ( fd_g_config->cnf_dict, msg, 0 ) );
		ans = *msg;

		/* Set the Origin-Host, Origin-Realm, Result-Code AVPs */
		CHECK_FCT( fd_msg_rescode_set( ans, "DIAMETER_SUCCESS", NULL, NULL, 1 ) );

		fd_log_debug("--------------Received the following Accounting message:--------------");

		CHECK_FCT( fd_sess_getsid ( sess, &s, &sl ) );
		fd_log_debug("Session: %.*s", (int)sl, s);

		/* The AVPs that we copy in the answer */
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Accounting_Record_Type, &a) );
		if (a) {
			CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
			fd_log_debug("Accounting-Record-Type: %d (%s)", h->avp_value->u32,
						/* it would be better to search this in the dictionary, but it is only for debug, so ok */
						(h->avp_value->u32 == 1) ? "EVENT_RECORD" :
						(h->avp_value->u32 == 2) ? "START_RECORD" :
						(h->avp_value->u32 == 3) ? "INTERIM_RECORD" :
						(h->avp_value->u32 == 4) ? "STOP_RECORD" :
						"<unknown value>"
					);
			CHECK_FCT( fd_msg_avp_new ( dm_dict.Accounting_Record_Type, 0, &a ) );
			CHECK_FCT( fd_msg_avp_setvalue( a, h->avp_value ) );
			CHECK_FCT( fd_msg_avp_add( ans, MSG_BRW_LAST_CHILD, a ) );
		}

		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Accounting_Record_Number, &a) );
		if (a) {
			CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
			fd_log_debug("[ACC] Accounting-Record-Number: %d", h->avp_value->u32);
			CHECK_FCT( fd_msg_avp_new ( dm_dict.Accounting_Record_Number, 0, &a ) );
			CHECK_FCT( fd_msg_avp_setvalue( a, h->avp_value ) );
			CHECK_FCT( fd_msg_avp_add( ans, MSG_BRW_LAST_CHILD, a ) );
		}

		struct avp * nextavp;
		CHECK_FCT(  fd_msg_browse(qry, MSG_BRW_FIRST_CHILD, (void *)&nextavp, NULL)  );
		while (nextavp) {
			CHECK_FCT( fd_msg_avp_hdr( nextavp, &h )  );

			/* special handling for Event-Timestamp, which needs decoding */
			if (h->avp_code == 55) {
				time_t ts;
				unsigned char *bytes;

				bytes = h->avp_value->os.data;

				ts = ((time_t)bytes[0] << 24) | ((time_t)bytes[1] << 16) |
				     ((time_t)bytes[2] << 8) | (time_t)bytes[3];

				ts -= 2208988800UL;
				fd_log_debug("[ACC] Event-Timestamp (UNIX ts): %lu", ts);
				IOV_ADD_NUMBER(ts);
				goto next;
			}

			if (h->avp_value->os.len) {
				IOV_ADD_STRING(h->avp_value->os.data, h->avp_value->os.len);
				fd_log_debug("[ACC] adding AVP %d (string, '%.*s')",
						h->avp_code, h->avp_value->os.len, h->avp_value->os.data);
			} else {
				IOV_ADD_NUMBER(h->avp_value->u32);
				fd_log_debug("[ACC] adding AVP %d (integer, %d)",
						h->avp_code, h->avp_value->u32);
			}

next:
			CHECK_FCT( fd_msg_browse(nextavp, MSG_BRW_NEXT, (void *)&nextavp, NULL) );
		}

		if (acc_log_cdrs && n) {
			FILE *f = get_acc_log();

			iov[n - 1].iov_base = "\n";

			fd_log_debug("[ACC] writing record to disk\n", f);
			rc = writev(fileno(f), iov, n);
			if (rc < 0) {
				fd_log_error("[ACC] failed to write to disk (%d: %s)\n",
				        errno, strerror(errno));
			} else {
				fflush(f);
			}

			IOV_CLEANUP();
		}

		fd_log_debug("----------------------------------------------------------------------");

		/* Send the answer */
		CHECK_FCT( fd_msg_send( msg, NULL, NULL ) );

	} else {
		/* We received an answer message, just discard it */
		CHECK_FCT( fd_msg_free( *msg ) );
		*msg = NULL;
	}

	return 0;
}


static inline void print_hex(char *clear_text, const unsigned char *cipher_text, int len)
{
	int i;

	for (i = 0; i < len; i++)
		sprintf(&clear_text[2 * i], "%2.2hhx", cipher_text[i]);

	clear_text[2 * len] = '\0';
}


static int digest_auth_verify(const str *ha1, const str *method, const str *uri,
		const str *nonce, const str *response)
{
	gcry_md_hd_t h;
	unsigned int md5_len = gcry_md_get_algo_dlen(GCRY_MD_MD5);
	char *ha2, *my_response;

	/* compute HA2 */
	{
		gcry_md_open(&h, GCRY_MD_MD5, GCRY_MD_FLAG_SECURE);
		gcry_md_write(h, method->s, method->len);
		gcry_md_write(h, ":", 1);
		gcry_md_write(h, uri->s, uri->len);

		ha2 = malloc(2 * md5_len + 1);
		print_hex(ha2, gcry_md_read(h, GCRY_MD_MD5), md5_len);
		gcry_md_close(h);
	}

	/* compute Response */
	{
		gcry_md_open(&h, GCRY_MD_MD5, GCRY_MD_FLAG_SECURE);
		gcry_md_write(h, ha1->s, ha1->len);
		gcry_md_write(h, ":", 1);
		gcry_md_write(h, nonce->s, nonce->len);
		gcry_md_write(h, ":", 1);
		gcry_md_write(h, ha2, 2 * md5_len);

		my_response = malloc(2 * md5_len + 1);
		print_hex(my_response, gcry_md_read(h, GCRY_MD_MD5), md5_len);
		gcry_md_close(h);
	}

	fd_log_debug("[AUTH] computed response: %s", my_response);

	return
		response->len != 2 * md5_len
		|| memcmp(response->s, my_response, response->len);
}


static int auth_request( struct msg ** msg, struct avp * avp, struct session * sess, void * data, enum disp_action * act)
{
	MYSQL_RES *res;
	MYSQL_ROW row;

	struct msg_hdr *hdr = NULL;
	struct msg *ans, *qry;
	struct avp * a = NULL;
	struct avp_hdr * h = NULL;
	union avp_value val;
	str user = {NULL, 0}, auth_user, realm, nonce, uri, method, response;
	int ret;
	char *rc = NULL;
	char query[200];

	fd_log_debug("[AUTH] request received");

	TRACE_ENTRY("%p %p %p %p", msg, avp, sess, act);

	if (msg == NULL)
		return EINVAL;

	/* Check what we received */
	CHECK_FCT( fd_msg_hdr(*msg, &hdr) );

	if (!(hdr->msg_flags & CMD_FLAG_REQUEST)) {
		/* We received an answer message, just discard it */
		CHECK_FCT( fd_msg_free( *msg ) );
		*msg = NULL;
		return 0;
	}

	/* It was a request, create an answer */

	qry = *msg;
	/* Create the answer message, including the Session-Id AVP */
	CHECK_FCT( fd_msg_new_answer_from_req ( fd_g_config->cnf_dict, msg, 0 ) );
	ans = *msg;

	/* User-Name (optional) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.User_Name, &a) );
		if (a) {
			CHECK_FCT( fd_msg_avp_hdr( a, &h )  );

			user.s = (char *)h->avp_value->os.data;
			user.len = h->avp_value->os.len;
			fd_log_debug("User-Name: %.*s %p", user.len, user.s, user.s);
		}
	}

	/* Digest-Username (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_Username, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );

		auth_user.s = (char *)h->avp_value->os.data;
		auth_user.len = h->avp_value->os.len;

		fd_log_debug("Digest-Username: %.*s %p", auth_user.len, auth_user.s, auth_user.s);

		if (user.s) {
			char *u = memchr(user.s, '@', user.len);
			int ulen;

			if (u)
				ulen = u - user.s;
			else
				ulen = user.len;

			if (ulen != auth_user.len || memcmp(user.s, auth_user.s, ulen)) {
				rc = "DIAMETER_ERROR_IDENTITIES_DONT_MATCH";
				goto prepare_response;
			}
		}
	}

	/* Digest-Realm (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_Realm, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );

		realm.s = (char *)h->avp_value->os.data;
		realm.len = h->avp_value->os.len;

		fd_log_debug("Digest-Realm: %.*s %p", realm.len, realm.s, realm.s);
	}

	/* at this point, we can fetch the user's HA1 hash */
	{
		char *esc_user = malloc(auth_user.len * 2 + 1);
		mysql_real_escape_string(db_conn, esc_user, auth_user.s, auth_user.len);

		char *esc_realm = malloc(realm.len * 2 + 1);
		mysql_real_escape_string(db_conn, esc_realm, realm.s, realm.len);

		ret = snprintf(query, 200,
			"SELECT ha1 FROM subscriber WHERE username='%s' AND domain='%s' LIMIT 1",
			esc_user, esc_realm);
		if (ret >= 200) {
			fd_log_error("[AUTH] error - buffer overflow (%d >= 200)", ret);
			rc = "DIAMETER_UNABLE_TO_COMPLY";
			goto prepare_response;
		}

		CHECK_POSIX(pthread_mutex_lock(&db_mutex));
		if (mysql_query(db_conn, query))
		{
			CHECK_POSIX(pthread_mutex_unlock(&db_mutex));
			fd_log_error("[AUTH] subscriber query failed: %s", mysql_error(db_conn));
			rc = "DIAMETER_UNABLE_TO_COMPLY";
			goto prepare_response;
		}

		res = mysql_store_result(db_conn);

		CHECK_POSIX(pthread_mutex_unlock(&db_mutex));
		row = mysql_fetch_row(res);
		if (!row) {
			mysql_free_result(res);
			rc = "DIAMETER_ERROR_USER_UNKNOWN";
			goto prepare_response;
		}

		fd_log_debug("[AUTH] user %.*s@%.*s has ha1b: %s",
			auth_user.len, auth_user.s, realm.len, realm.s, row[0]);
	}

	/* Digest-Nonce (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_Nonce, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
		nonce.s = (char *)h->avp_value->os.data;
		nonce.len = h->avp_value->os.len;
		fd_log_debug("Digest-Nonce: %.*s", nonce.len, nonce.s);
	}

	/* Digest-URI (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_URI, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
		uri.s = (char *)h->avp_value->os.data;
		uri.len = h->avp_value->os.len;
		fd_log_debug("Digest-URI: %.*s", uri.len, uri.s);
	}

	/* Digest-Method (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_Method, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
		method.s = (char *)h->avp_value->os.data;
		method.len = h->avp_value->os.len;
		fd_log_debug("Digest-Method: %.*s", method.len, method.s);
	}

	/* Digest-Response (mandatory) */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Digest_Response, &a) );
		if (!a) {
			rc = "DIAMETER_MISSING_AVP";
			goto prepare_response;
		}

		CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
		response.s = (char *)h->avp_value->os.data;
		response.len = h->avp_value->os.len;
		fd_log_debug("Digest-Response: %.*s", response.len, response.s);
	}

	ret = digest_auth_verify(&(str){row[0], strlen(row[0])},
			&method, &uri, &nonce, &response);
	mysql_free_result(res);

	if (ret != 0)
		rc = "DIAMETER_AUTHENTICATION_REJECTED";

prepare_response:
	/* Auth-Application-Id */
	{
		CHECK_FCT( fd_msg_avp_new( dm_dict.Auth_Application_Id, 0, &a ) );

		/* Set its value */
		memset(&val, 0, sizeof(val));
		val.i32 = 6;
		CHECK_FCT( fd_msg_avp_setvalue( a, &val ) );

		/* Add it to the message */
		CHECK_FCT( fd_msg_avp_add( ans, MSG_BRW_LAST_CHILD, a ) );
	}

	if (!rc)
		rc = "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED";

	/* Set the Origin-Host, Origin-Realm, Result-Code AVPs */
	CHECK_FCT( fd_msg_rescode_set( ans, rc, NULL, NULL, 0 ) );

	/* Auth-Session-State */
	{
		CHECK_FCT( fd_msg_avp_new( dm_dict.Auth_Session_State, 0, &a ) );

		/* Set its value */
		memset(&val, 0, sizeof(val));
		val.i32 = NO_STATE_MAINTAINED;
		CHECK_FCT( fd_msg_avp_setvalue( a, &val ) );

		/* Add it to the message */
		CHECK_FCT( fd_msg_avp_add( ans, MSG_BRW_LAST_CHILD, a ) );
	}

	CHECK_FCT( fd_msg_add_origin ( ans, 0 ) );

	/* Acct-Session-Id */
	{
		CHECK_FCT( fd_msg_search_avp ( qry, dm_dict.Acct_Session_Id, &a) );
		if (a) {
			CHECK_FCT( fd_msg_avp_hdr( a, &h )  );
			fd_log_debug("Acct-Session-Id: %.*s", h->avp_value->os.len, h->avp_value->os.data);

			CHECK_FCT( fd_msg_avp_new ( dm_dict.Acct_Session_Id, 0, &a ) );
			CHECK_FCT( fd_msg_avp_setvalue( a, h->avp_value ) );
			CHECK_FCT( fd_msg_avp_add( ans, MSG_BRW_LAST_CHILD, a ) );
		}
	}

	/* Send the answer */
	CHECK_FCT( fd_msg_send( msg, NULL, NULL ) );

	return 0;
}


static int parse_conf_string(const char *confstring,
                              char **extra_avps_file, int *lib_mode)
{
	char *p;

	*extra_avps_file = NULL;
	*lib_mode = 0;

	if (!confstring)
		goto out;

	p = strcasestr(confstring, "extra-avps-file");
	if (p) {
		p += strlen("extra-avps-file");
		while (*p != '/' && *p != '\0')
			p++;

		if (*p != '/') {
			fd_log_error("'extra-avps-file' requires an absolute file path\n");
		} else {
			char *e = p;
			while (!isspace(*e) && *e != ';' && *e != '\0')
				e++;
			*extra_avps_file = malloc(e - p + 1);
			memcpy(*extra_avps_file, p, e - p);
			(*extra_avps_file)[e - p] = '\0';
		}
	}

	p = strcasestr(confstring, "library-mode");
	if (p) {
		p += strlen("library-mode");
		while (!isdigit(*p) && *p != ';' && *p != '\0')
			p++;
		if (isdigit(*p) && *p != '0')
			*lib_mode = 1;
	}

out:
	fd_log_debug("[INIT] extra-avps-file: %s", *extra_avps_file);
	fd_log_debug("[INIT] library-mode: %d", *lib_mode);
	return 0;
}


/* entry point: register handlers for Accounting and Digest Auth */
static int os_entry(char *confstring)
{
	struct disp_when data;
	char *extra_avps_file;
	int lib_mode;

	CHECK_FCT(parse_conf_string(confstring, &extra_avps_file, &lib_mode));
	CHECK_FCT(parse_extra_avps(extra_avps_file));
	free(extra_avps_file);

	if (lib_mode)
		return 0;

	CHECK_FCT(register_osips_avps());

	/* Initialize the dictionary objects we use */
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Accounting-Record-Number", &dm_dict.Accounting_Record_Number, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Accounting-Record-Type", &dm_dict.Accounting_Record_Type, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Acct-Session-Id", &dm_dict.Acct_Session_Id, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Event-Timestamp", &dm_dict.Event_Timestamp, ENOENT) );

	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Application-Id", &dm_dict.Auth_Application_Id, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Auth-Session-State", &dm_dict.Auth_Session_State, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "User-Name", &dm_dict.User_Name, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-Username", &dm_dict.Digest_Username, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-Realm", &dm_dict.Digest_Realm, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-Nonce", &dm_dict.Digest_Nonce, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-URI", &dm_dict.Digest_URI, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-Response", &dm_dict.Digest_Response, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Digest-Method", &dm_dict.Digest_Method, ENOENT) );

	/* Register the dispatch callback */
	memset(&data, 0, sizeof data);
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_NAME, "Diameter Base Accounting", &data.app, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Accounting-Request", &data.command, ENOENT) );
	CHECK_FCT( fd_disp_register( acc_request, DISP_HOW_CC, &data, NULL, NULL ) );

	/* Advertise the support for the Diameter Base Accounting application in the peer */
	CHECK_FCT( fd_disp_app_support ( data.app, NULL, 0, 1 ) );

	memset(&data, 0, sizeof data);
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_NAME, "Diameter Session Initiation Protocol (SIP) Application", &data.app, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME, "Multimedia-Auth-Request", &data.command, ENOENT) );
	CHECK_FCT( fd_disp_register( auth_request, DISP_HOW_CC, &data, NULL, NULL ) );

	/* Advertise the support for the SIP application in the peer */
	CHECK_FCT( fd_disp_app_support ( data.app, NULL, 0, 1 ) );

	if (init_acc_log() != 0)
		fd_log_error("[ACC] failed to init logging!  CDR generation is disabled!");

	if (init_auth() != 0)
		fd_log_error("[AUTH] failed to initialize auth support!");

	return 0;
}

/* Unload */
void fd_ext_fini(void)
{
	return;
}

EXTENSION_ENTRY("app_opensips", os_entry);
