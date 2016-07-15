/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "../../mem/shm_mem.h"
#include "../../async.h"
#include "rest_methods.h"
#include "rest_cb.h"

static char print_buff[MAX_CONTENT_TYPE_LEN];

CURLM *multi_handle;

/* simultaneous ongoing transfers within this process */
static int transfers;
static int read_fds[FD_SETSIZE];

/* libcurl's reported running handles */
static int running_handles;

static long sleep_on_bad_timeout = 500; /* ms */


#define clean_header_list(list) \
	do { \
		if (list) { \
			curl_slist_free_all(list); \
			list = NULL; \
		} \
	} while (0)

#define w_curl_easy_setopt(h, opt, value) \
	do { \
		rc = curl_easy_setopt(h, opt, value); \
		if (rc != CURLE_OK) { \
			LM_ERR("curl_easy_setopt(%d): (%s)\n", opt, curl_easy_strerror(rc)); \
			goto cleanup; \
		} \
	} while (0)

static inline char is_new_transfer(int fd)
{
	int it;

	for (it = 0; it < transfers; it++) {
		if (fd == read_fds[it])
			return 0;
	}

	return 1;
}

static inline void add_transfer(int fd)
{
	read_fds[transfers++] = fd;
}

static inline char del_transfer(int fd)
{
	int it;

	LM_DBG("del fd %d\n", fd);

	for (it = 0; it < transfers; it++) {
		if (fd == read_fds[it]) {
			transfers--;
			for (; it < transfers; it++)
				read_fds[it] = read_fds[it + 1];

			return 0;
		}
	}

	return -1;
}

/**
 * start_async_http_req - performs an HTTP request, stores results in pvars
 *		- TCP connect phase is synchronous, due to libcurl limitations
 *		- TCP read phase is asynchronous, thanks to the libcurl multi interface
 *
 * @msg:		sip message struct
 * @method:		HTTP verb
 * @url:		HTTP URL to be queried
 * @req_body:	Body of the request (NULL if not needed)
 * @req_ctype:	Value for the "Content-Type: " header of the request (same as ^)
 * @out_handle: CURL easy handle used to perform the transfer
 * @body:	    reply body; gradually reallocated as data arrives
 * @ctype:	    will eventually hold the last "Content-Type" header of the reply
 */
int start_async_http_req(struct sip_msg *msg, enum rest_client_method method,
					     char *url, char *req_body, char *req_ctype,
					     CURL **out_handle, str *body, str *ctype)
{
	CURL *handle;
	CURLcode rc;
	CURLMcode mrc;
	struct curl_slist *list = NULL;
	fd_set rset, wset, eset;
	int max_fd, fd, i;
	long busy_wait, timeout;
	long retry_time, check_time = 5; /* 5ms looping time */
	int msgs_in_queue;
	CURLMsg *cmsg;

	if (transfers == FD_SETSIZE) {
		LM_ERR("too many ongoing tranfers: %d\n", FD_SETSIZE);
		clean_header_list(list);
		return ASYNC_NO_IO;
	}

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list(list);
		return ASYNC_NO_IO;
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	switch (method) {
	case REST_CLIENT_POST:
		w_curl_easy_setopt(handle, CURLOPT_POST, 1);
		w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req_body);

		if (req_ctype) {
			sprintf(print_buff, "Content-Type: %s", req_ctype);
			list = curl_slist_append(list, print_buff);
			w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, list);
		}
		break;
	case REST_CLIENT_GET:
		break;

	default:
		LM_ERR("Unsupported rest_client_method: %d, defaulting to GET\n", method);
	}

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, body);

	if (ctype) {
		w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
		w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, ctype);
	}

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_multi_add_handle(multi_handle, handle);

	timeout = connection_timeout_ms;
	/* obtain a read fd in "connection_timeout" seconds at worst */
	for (timeout = connection_timeout_ms; timeout > 0; timeout -= busy_wait) {
		mrc = curl_multi_perform(multi_handle, &running_handles);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		mrc = curl_multi_timeout(multi_handle, &retry_time);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_timeout: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		if (retry_time == -1) {
			LM_INFO("curl_multi_timeout() returned -1, pausing %ldms...\n",
					sleep_on_bad_timeout);
			busy_wait = sleep_on_bad_timeout;
			usleep(1000UL * busy_wait);
			continue;
		}

		busy_wait = retry_time < timeout ? retry_time : timeout;

		/**
		 * libcurl is currently stuck in internal operations (connect)
		 *    we have to wait a bit until we receive a read fd
		 */
		for (i = 0; i < busy_wait; i += check_time) {
			/* transfer may have already been completed!! */
			while ((cmsg = curl_multi_info_read(multi_handle, &msgs_in_queue))) {
				if (cmsg->easy_handle == handle && cmsg->msg == CURLMSG_DONE) {
					LM_DBG("done, no need for async!\n");

					clean_header_list(list);
					*out_handle = handle;
					return ASYNC_SYNC;
				}
			}

			FD_ZERO(&rset);
			mrc = curl_multi_fdset(multi_handle, &rset, &wset, &eset, &max_fd);
			if (mrc != CURLM_OK) {
				LM_ERR("curl_multi_fdset: %s\n", curl_multi_strerror(mrc));
				goto error;
			}

			if (max_fd != -1) {
				for (fd = 0; fd <= max_fd; fd++) {
					if (FD_ISSET(fd, &rset)) {

						LM_DBG(" >>>>>>>>>> fd %d ISSET(read)\n", fd);
						if (is_new_transfer(fd)) {
							LM_DBG("add fd to read list: %d\n", fd);
							add_transfer(fd);
							goto success;
						}
					}
				}
			}

			usleep(1000UL * check_time);
		}
	}

	LM_ERR("timeout while connecting to '%s' (%ld sec)\n", url, connection_timeout);
	goto error;

success:
	clean_header_list(list);
	*out_handle = handle;
	return fd;

error:
	mrc = curl_multi_remove_handle(multi_handle, handle);
	if (mrc != CURLM_OK)
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));

cleanup:
	clean_header_list(list);
	curl_easy_cleanup(handle);
	return ASYNC_NO_IO;
}

enum async_ret_code resume_async_http_req(int fd, struct sip_msg *msg, void *_param)
{
	CURLcode rc;
	CURLMcode mrc;
	rest_async_param *param = (rest_async_param *)_param;
	int running, max_fd;
	long http_rc;
	fd_set rset, wset, eset;
	pv_value_t val;

	mrc = curl_multi_perform(multi_handle, &running);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
		return -1;
	}
	LM_DBG("running handles: %d\n", running);

	if (running == running_handles) {
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	if (running > running_handles) {
		LM_BUG("incremented handles!!");
		/* default async status is DONE */
		return -1;
	}

	running_handles = running;

	FD_ZERO(&rset);
	mrc = curl_multi_fdset(multi_handle, &rset, &wset, &eset, &max_fd);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_fdset: %s\n", curl_multi_strerror(mrc));
		/* default async status is DONE */
		return -1;
	}

	if (max_fd == -1) {
		if (running_handles != 0) {
			LM_BUG("running_handles == %d", running_handles);
			abort();
			/* default async status is DONE */
			return -1;
		}

		if (FD_ISSET(fd, &rset)) {
			LM_BUG("fd %d is still in rset!", fd);
			abort();
			/* default async status is DONE */
			return -1;
		}

	} else if (FD_ISSET(fd, &rset)) {
		LM_DBG("fd %d still transferring...\n", fd);
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	if (del_transfer(fd) != 0) {
		LM_BUG("failed to delete fd %d", fd);
		abort();
		/* default async status is DONE */
		return -1;
	}

	mrc = curl_multi_remove_handle(multi_handle, param->handle);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));
		/* default async status is DONE */
		return -1;
	}

	val.flags = PV_VAL_STR;
	val.rs = param->body;
	if (pv_set_value(msg, param->body_pv, 0, &val) != 0)
		LM_ERR("failed to set output body pv\n");

	if (param->ctype_pv) {
		val.rs = param->ctype;
		if (pv_set_value(msg, param->ctype_pv, 0, &val) != 0)
			LM_ERR("failed to set output ctype pv\n");
	}

	if (param->code_pv) {
		rc = curl_easy_getinfo(param->handle, CURLINFO_RESPONSE_CODE, &http_rc);
		if (rc != CURLE_OK) {
			LM_ERR("curl_easy_getinfo: %s\n", curl_easy_strerror(rc));
			http_rc = 0;
		}

		LM_DBG("Last response code: %ld\n", http_rc);

		val.flags = PV_VAL_INT|PV_TYPE_INT;
		val.ri = (int)http_rc;
		if (pv_set_value(msg, param->code_pv, 0, &val) != 0)
			LM_ERR("failed to set output code pv\n");
	}

	pkg_free(param->body.s);
	if (param->ctype_pv && param->ctype.s)
		pkg_free(param->ctype.s);
	curl_easy_cleanup(param->handle);
	pkg_free(param);

	/* default async status is DONE */
	return 1;
}

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
	str st = { 0, 0 };
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
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, &st);

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
			goto cleanup;
		}
	}

	if (rc != CURLE_OK) {
		LM_ERR("curl_easy_perform: %s\n", curl_easy_strerror(rc));
		goto cleanup;
	}

	tbody = body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto cleanup;
	}

	if (body.s) {
		pkg_free(body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}

		if (st.s)
			pkg_free(st.s);
	}

	curl_easy_cleanup(handle);
	return 1;

cleanup:
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
int rest_post_method(struct sip_msg *msg, char *url, char *body, char *ctype,
                     pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	CURLcode rc;
	CURL *handle = NULL;
	long http_rc;
	struct curl_slist *list = NULL;
	str st = { 0, 0 };
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
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res_body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, &st);

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(handle);
	clean_header_list(list);

	if (code_pv) {
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		LM_DBG("Last response code: %ld\n", http_rc);

		pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
		pv_val.ri = (int)http_rc;

		if (pv_set_value(msg, code_pv, 0, &pv_val) != 0) {
			LM_ERR("Set code pv value failed!\n");
			goto cleanup;
		}
	}

	if (rc != CURLE_OK) {
		LM_ERR("curl_easy_perform: %s\n", curl_easy_strerror(rc));
		goto cleanup;
	}

	tbody = res_body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto cleanup;
	}

	if (res_body.s) {
		pkg_free(res_body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}

		if (st.s)
			pkg_free(st.s);
	}

	curl_easy_cleanup(handle);
	return 1;

cleanup:
	clean_header_list(list);
	curl_easy_cleanup(handle);
	return -1;
}
