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
#include "../../lib/list.h"

#include "rest_methods.h"
#include "rest_cb.h"

static char print_buff[MAX_CONTENT_TYPE_LEN];

/* additional HTTP headers for the next request */
static struct curl_slist *header_list = NULL;

/* simultaneous ongoing transfers within this process */
static int transfers;
static int read_fds[FD_SETSIZE];

/* libcurl's reported running handles */
static int running_handles;

extern int _async_resume_retr_timeout;
extern int _async_resume_retr_itv;

#define clean_header_list \
	do { \
		if (header_list) { \
			curl_slist_free_all(header_list); \
			header_list = NULL; \
		} \
	} while (0)

#define w_curl_easy_setopt(h, opt, value) \
	do { \
		rc = curl_easy_setopt(h, opt, value); \
		if (rc != CURLE_OK) { \
			LM_ERR("curl_easy_setopt(%d): (%s)\n", opt, curl_easy_strerror(rc)); \
			clean_header_list; \
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
 * We cannot use the "parallel transfers" feature of libcurl's multi interface
 * because that would consume read events from some of its file descriptors that
 * we also manually add to the OpenSIPS reactor. This may lead to dangling
 * descriptors in the reactor, as well as some OpenSIPS async routes which
 * are not triggered.
 *
 * To work around this, we can still achieve the desired effect with a pool of
 * multi handles each doing a single transfer, rather than using 1 multi handle
 * doing multiple transfers.
 *
 * The size of the multi pool may grow indefinitely.
 */
struct list_head multi_pool;
static int multi_pool_sz;

static OSS_CURLM *get_multi(void)
{
	OSS_CURLM *multi_list;

	if (list_empty(&multi_pool)) {
		if (multi_pool_sz == max_async_transfers) {
			LM_ERR("max async transfers! (%d)\n", max_async_transfers);
			return NULL;
		}

		multi_list = pkg_malloc(sizeof *multi_list);
		if (!multi_list) {
			LM_ERR("out of mem!\n");
			return NULL;
		}
		multi_pool_sz++;
		LM_DBG("multi pool size is now %d\n", multi_pool_sz);

		multi_list->multi_handle = curl_multi_init();
		return multi_list;
	}

	multi_list = list_entry(multi_pool.next, OSS_CURLM, list);
	list_del(multi_pool.next);

	return multi_list;
}

static void put_multi(OSS_CURLM *multi_list)
{
	list_add(&multi_list->list, &multi_pool);
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
 * @async_parm: output param, will contain async handles
 * @body:	    reply body; gradually reallocated as data arrives
 * @ctype:	    will eventually hold the last "Content-Type" header of the reply
 */
int start_async_http_req(struct sip_msg *msg, enum rest_client_method method,
					     char *url, char *req_body, char *req_ctype,
					     rest_async_param *async_parm, str *body, str *ctype)
{
	CURL *handle;
	CURLcode rc;
	CURLMcode mrc;
	fd_set rset, wset, eset;
	int max_fd, fd;
	long busy_wait, timeout;
	long retry_time;
	OSS_CURLM *multi_list;
	CURLM *multi_handle;

	if (transfers == FD_SETSIZE) {
		LM_ERR("too many ongoing tranfers: %d\n", FD_SETSIZE);
		clean_header_list;
		return ASYNC_NO_IO;
	}

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list;
		return ASYNC_NO_IO;
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	switch (method) {
	case REST_CLIENT_POST:
		w_curl_easy_setopt(handle, CURLOPT_POST, 1);
		w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req_body);

		if (req_ctype) {
			snprintf(print_buff, MAX_CONTENT_TYPE_LEN, "Content-Type: %s", req_ctype);
			header_list = curl_slist_append(header_list, print_buff);
			w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
		}
		break;
	case REST_CLIENT_GET:
		break;

	default:
		LM_ERR("Unsupported rest_client_method: %d, defaulting to GET\n", method);
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 0);

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

	multi_list = get_multi();
	if (!multi_list) {
		LM_INFO("failed to get a multi handle, doing blocking query\n");
		rc = curl_easy_perform(handle);
		clean_header_list;
		async_parm->handle = handle;
		return ASYNC_SYNC;
	}

	multi_handle = multi_list->multi_handle;
	curl_multi_add_handle(multi_handle, handle);

	timeout = connection_timeout_ms;
	busy_wait = connect_poll_interval;

	/* obtain a read fd in "connection_timeout" seconds at worst */
	for (timeout = connection_timeout_ms; timeout > 0; timeout -= busy_wait) {
		mrc = curl_multi_perform(multi_handle, &running_handles);
		if (mrc != CURLM_OK && mrc != CURLM_CALL_MULTI_PERFORM) {
			LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		mrc = curl_multi_timeout(multi_handle, &retry_time);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_timeout: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		LM_DBG("libcurl TCP connect: we should wait up to %ldms "
		       "(timeout=%ldms, poll=%ldms)!\n", retry_time,
		       connection_timeout_ms, connect_poll_interval);

		if (retry_time == -1) {
			LM_DBG("curl_multi_timeout() returned -1, pausing %ldms...\n",
			        busy_wait);
			goto busy_wait;
		}

		if (retry_time > connection_timeout_ms)
			LM_INFO("initial TCP connect: we must wait at least %ldms! Please "
			        "consider increasing 'connection_timeout'!\n", retry_time);

		busy_wait = retry_time < timeout ? retry_time : timeout;

		/* transfer may have already been completed!! */
		if (running_handles == 0) {
			LM_DBG("done, no need for async!\n");

			clean_header_list;
			async_parm->handle = handle;
			mrc = curl_multi_remove_handle(multi_handle, handle);
			if (mrc != CURLM_OK) {
				LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));
			}
			put_multi(multi_list);
			return ASYNC_SYNC;
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

					LM_DBG("ongoing transfer on fd %d\n", fd);
					if (is_new_transfer(fd)) {
						LM_DBG(">>> add fd %d to ongoing transfers\n", fd);
						add_transfer(fd);
						goto success;
					}
				}
			}
		}

		/*
		 * from curl_multi_timeout() docs: "retry_time" milliseconds "at most!"
		 *         -> we'll only wait "connect_poll_interval" ms
		 */
		busy_wait = connect_poll_interval < timeout ?
		            connect_poll_interval : timeout;

busy_wait:
		/* libcurl seems to be stuck in internal operations (TCP connect?) */
		LM_DBG("busy waiting %ldms ...\n", busy_wait);
		usleep(1000UL * busy_wait);
	}

	LM_ERR("timeout while connecting to '%s' (%ld sec)\n", url, connection_timeout);
	goto error;

success:
	async_parm->header_list = header_list;
	async_parm->handle = handle;
	async_parm->multi_list = multi_list;
	header_list = NULL;
	return fd;

error:
	mrc = curl_multi_remove_handle(multi_handle, handle);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));
	}
	put_multi(multi_list);

cleanup:
	clean_header_list;
	curl_easy_cleanup(handle);
	return ASYNC_NO_IO;
}

enum async_ret_code resume_async_http_req(int fd, struct sip_msg *msg, void *_param)
{
	CURLcode rc;
	CURLMcode mrc;
	rest_async_param *param = (rest_async_param *)_param;
	int running = 0, max_fd;
	long http_rc;
	fd_set rset, wset, eset;
	pv_value_t val;
	int ret = 1, retr;
	CURLM *multi_handle;

	multi_handle = param->multi_list->multi_handle;

	retr = 0;
	do {
		mrc = curl_multi_perform(multi_handle, &running);
		if (mrc != CURLM_CALL_MULTI_PERFORM)
			break;
		LM_DBG("retry last perform...\n");
		usleep(_async_resume_retr_itv);
		retr += _async_resume_retr_itv;
	} while (retr < _async_resume_retr_timeout);

	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
		return -1;
	}

	LM_DBG("running handles: %d\n", running);
	if (running == 1) {
		LM_DBG("transfer in progress...\n");
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	if (running != 0) {
		LM_BUG("non-zero running handles!! (%d)", running);
		abort();
	}

	FD_ZERO(&rset);
	mrc = curl_multi_fdset(multi_handle, &rset, &wset, &eset, &max_fd);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_fdset: %s\n", curl_multi_strerror(mrc));
		ret = -1;
		goto out;
	}

	if (max_fd == -1) {
		if (FD_ISSET(fd, &rset)) {
			LM_BUG("fd %d is still in rset!", fd);
			abort();
		}

	} else if (FD_ISSET(fd, &rset)) {
		LM_DBG("fd %d still transferring...\n", fd);
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	curl_slist_free_all(param->header_list);

	if (del_transfer(fd) != 0) {
		LM_BUG("failed to delete fd %d", fd);
		abort();
	}

	mrc = curl_multi_remove_handle(multi_handle, param->handle);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));
		/* default async status is DONE */
		return -1;
	}
	put_multi(param->multi_list);

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

out:
	pkg_free(param->body.s);
	if (param->ctype_pv && param->ctype.s)
		pkg_free(param->ctype.s);
	curl_easy_cleanup(param->handle);
	pkg_free(param);

	/* default async status is DONE */
	return ret;
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
		clean_header_list;
		return -1;
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 0);

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
	clean_header_list;

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
		trim(&pv_val.rs);

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}
	}

	if (st.s)
		pkg_free(st.s);

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
	str st = { 0, 0 };
	str res_body = { NULL, 0 }, tbody;
	pv_value_t pv_val;

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list;
		return -1;
	}

	if (ctype) {
		snprintf(print_buff, MAX_CONTENT_TYPE_LEN, "Content-Type: %s", ctype);
		header_list = curl_slist_append(header_list, print_buff);
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_POST, 1);
	w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 0);

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
	clean_header_list;

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
		trim(&pv_val.rs);

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}
	}

	if (st.s)
		pkg_free(st.s);

	curl_easy_cleanup(handle);
	return 1;

cleanup:
	curl_easy_cleanup(handle);
	return -1;
}

/**
 * rest_append_hf - add a custom HTTP header before a rest call
 * @msg:		sip message struct
 * @hfv:		HTTP header field and value
 */
int rest_append_hf_method(struct sip_msg *msg, str *hfv)
{
	char buf[MAX_HEADER_FIELD_LEN];

	if (hfv->len + 1 > MAX_HEADER_FIELD_LEN) {
		LM_ERR("header field buffer too small\n");
		return -1;
	}	

	/* TODO: header validation */

	/* append the header to the global list */
	strncpy(buf, hfv->s, hfv->len);
	buf[hfv->len] = '\0';
	header_list = curl_slist_append(header_list, buf);

	return 1;		
}
