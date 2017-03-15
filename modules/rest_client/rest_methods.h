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

#ifndef _REST_METHODS_
#define _REST_METHODS_

#include "../../pvar.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"

/* maximum size for the first line */
#define FLINE_MAX 512
#define BODY_MAX 1024
#define TRACE_BUF_MAX_SIZE 1024

extern struct list_head multi_pool;

extern long connection_timeout;
extern long connect_poll_interval;
extern long connection_timeout_ms;
extern int max_async_transfers;
extern long curl_timeout;

extern char *ssl_capath;
extern int ssl_verifypeer;
extern int ssl_verifyhost;

/* Currently supported HTTP verbs */
enum rest_client_method {
	REST_CLIENT_GET,
	REST_CLIENT_PUT,
	REST_CLIENT_POST
};


typedef struct _rest_trace_param {
	str callid;

	char req_first_line[FLINE_MAX];
	int  req_fline_len;

	char rpl_first_line[FLINE_MAX];
	int  rpl_fline_len;

	char req_body[BODY_MAX];
	int  req_len;

	char rpl_body[BODY_MAX];
	int  rpl_len;

	long local_port;
	char local_ip[INET6_ADDRSTRLEN];

	long remote_port;
	char remote_ip[INET6_ADDRSTRLEN];

	str correlation;
} rest_trace_param_t;

struct rest_append_param {
	str callid;

	str fline;
	str body;
};

struct _oss_curlm {
	CURLM *multi_handle;
	struct list_head list;
};
typedef struct _oss_curlm OSS_CURLM;

typedef struct rest_async_param_ {
	enum rest_client_method method;
	OSS_CURLM *multi_list;
	CURL *handle;
	str body;
	str ctype;

	rest_trace_param_t* tparam;

	pv_spec_p body_pv;
	pv_spec_p ctype_pv;
	pv_spec_p code_pv;
} rest_async_param;

int rest_get_method(struct sip_msg *msg, char *url,
                    pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv);
int rest_post_method(struct sip_msg *msg, char *url, char *body, char *ctype,
                     pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv);
int rest_put_method(struct sip_msg *msg, char *url, char *body, char *ctype,
                     pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv);

int start_async_http_req(struct sip_msg *msg, enum rest_client_method method,
					     char *url, char *req_body, char *req_ctype,
					     rest_async_param *async_parm, str *body, str *ctype);
enum async_ret_code resume_async_http_req(int fd, struct sip_msg *msg, void *param);

int rest_append_hf_method(struct sip_msg *msg, str *hfv);

#endif /* _REST_METHODS_ */

