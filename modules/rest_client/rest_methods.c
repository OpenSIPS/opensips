/*
 * $Id$
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "rest_methods.h"
#include "rest_cb.h"

static char err_buff[CURL_ERROR_SIZE];
static char print_buff[MAX_CONTENT_TYPE_LEN];

#define w_curl_easy_setopt(h, opt, value) \
	do { \
		rc = curl_easy_setopt(h, opt, value); \
		if (rc != CURLE_OK) { \
			LM_ERR("setopt operation %d failed (%d)\n", opt, rc); \
			goto error; \
		} \
	} while (0)

/**
 * rest_get_method - performs an HTTP GET request, stores results in pvars
 * @msg:		sip message struct
 * @url:		HTTP URL to be queried
 * @body_pv:	pseudo var which will hold the result body
 * @ctype_pv:	pvar which will hold the body encoding method
 * @code_pv:	pvar to hold the HTTP return code
 */
int rest_get_method(struct sip_msg *msg, char *url,
                    pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	CURLcode rc;
	CURL *handle = NULL;
	long http_rc;
	pv_value_t pv_val;
	str st = { print_buff, 0 };
	str body = { NULL, 0 }, tbody;

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		return -1;
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);
	w_curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buff);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEHEADER, &st);

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(handle);

	if (code_pv) {
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		LM_DBG("Last response code: %ld\n", http_rc);

		pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
		pv_val.ri = (int)http_rc;

		if (pv_set_value(msg, code_pv, 0, &pv_val) != 0) {
			LM_ERR("Set code pv value failed!\n");
			goto error;
		}
	}

	if (rc != CURLE_OK) {
		LM_ERR("Error [%i] while performing curl operation\n", rc);
		LM_ERR("[%s]\n", err_buff);

		goto error;
	}

	tbody = body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto error;
	}

	if (body.s) {
		pkg_free(body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto error;
		}
	}

	curl_easy_cleanup(handle);
	return 1;

error:
	curl_easy_cleanup(handle);
	return -1;
}

/**
 * rest_post_method - performs an HTTP POST request, stores results in pvars
 * @msg:		sip message struct
 * @url:		HTTP URL to be queried
 * @ctype:		Value for the "Content-Type: " header of the request
 * @body:		Body of the request
 * @body_pv:	pseudo var which will hold the result body
 * @ctype_pv:	pvar which will hold the result content type
 * @code_pv:	pvar to hold the HTTP return code
 */
int rest_post_method(struct sip_msg *msg, char *url, char *ctype, char *body,
                     pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	CURLcode rc;
	CURL *handle = NULL;
	long http_rc;
	struct curl_slist *list = NULL;
	str st = { print_buff, 0 };
	str res_body = { NULL, 0 }, tbody;
	pv_value_t pv_val;

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		return -1;
	}

	if (ctype) {
		sprintf(print_buff, "Content-Type: %s", ctype);
		list = curl_slist_append(list, print_buff);
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, list);
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_POST, 1);
	w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);
	w_curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buff);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res_body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEHEADER, &st);

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(handle);
	if (code_pv) {
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		LM_DBG("Last response code: %ld\n", http_rc);

		pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
		pv_val.ri = (int)http_rc;

		if (pv_set_value(msg, code_pv, 0, &pv_val) != 0) {
			LM_ERR("Set code pv value failed!\n");
			goto error;
		}
	}

	curl_slist_free_all(list);

	if (rc != CURLE_OK) {
		LM_ERR("Error [%i] while performing curl operation\n", rc);
		LM_ERR("[%s]\n", err_buff);

		goto error;
	}

	tbody = res_body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto error;
	}

	if (res_body.s) {
		pkg_free(res_body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto error;
		}
	}

	curl_easy_cleanup(handle);
	return 1;

error:
	curl_easy_cleanup(handle);
	return -1;
}
