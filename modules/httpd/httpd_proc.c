/*
 * $Id$
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */


#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <grp.h>
#include <stdlib.h>

#ifdef LIBMICROHTTPD
#include <stdint.h>
#include <stdarg.h>
#include <microhttpd.h>
#endif

#include "../../sr_module.h"
#include "../../str.h"
#include "../../ut.h"
//#include "../../mem/mem.h"
//#include "../../mem/shm_mem.h"
#include "httpd_load.h"


extern int port;
extern str ip;
extern str buffer;
extern struct httpd_cb *httpd_cb_list;


static const str MI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str MI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str MI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");

#ifdef LIBMICROHTTPD
struct MHD_Daemon *dmn;
#endif

struct httpd_cb *get_httpd_cb(const char *url)
{
	int url_len;
	int index;
	struct httpd_cb *cb;
	str *http_root;

	if (!url) {
		LM_ERR("NULL URL\n"); return NULL;
	}
	url_len = strlen(url);
	if (url_len<=0) {
		LM_ERR("Invalid url length [%d]\n", url_len); return NULL;
	}
	if (url[0] != '/') {
		LM_ERR("URL starting with [%c] instead of'/'\n", *url);
		return NULL;
	}
	cb = httpd_cb_list;
	while(cb) {
		index = 1;
		http_root = cb->http_root;
		if (url_len - index < http_root->len) goto skip;
		if (strncmp(http_root->s, &url[index], http_root->len) != 0) goto skip;
		index += http_root->len;
		if (url_len - index == 0) return cb;
		if (url[index] == '/') return cb;
skip:
		cb = cb->next;
	}

	return NULL;
}


#ifdef LIBMICROHTTPD
int answer_to_connection (void *cls, struct MHD_Connection *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls)
{
	str page = {NULL, 0};
	struct MHD_Response *response;
	int ret = 0;
	void *async_data = NULL;
	struct httpd_cb *cb;
	const char *normalised_url;
	const char *url_args;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, con_cls=%p\n",
			cls, connection, url, method, version,
			(int)*upload_data_size, upload_data, con_cls);

	cb = get_httpd_cb(url);
	if (cb) {
		normalised_url = &url[cb->http_root->len+1];
		LM_DBG("normalised_url=[%s]\n", normalised_url);
		url_args = MHD_lookup_connection_value(connection,
				MHD_GET_ARGUMENT_KIND, "arg");
		cb->callback(cls, (void*)connection,
				normalised_url, url_args,
				method, version,
				upload_data, upload_data_size, con_cls,
				&buffer, &page);
	} else {
		page = MI_HTTP_U_URL;
	}

	if (page.s) {
		LM_DBG("MHD_create_response_from_data [%p:%d]\n",
			page.s, page.len);
		response = MHD_create_response_from_data(page.len,
							(void*)page.s,
							0, 1);
	} else {
		LM_DBG("MHD_create_response_from_callback\n");
		response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
							buffer.len,
							cb->flush_data_callback,
							(void*)async_data,
							NULL);
	}
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);

	return ret;
}
#endif

void httpd_proc(int rank)
{
#ifdef LIBMICROHTTPD
	int status;
	fd_set rs;
	fd_set ws;
	fd_set es;
	int max;
#endif
	struct httpd_cb *cb = httpd_cb_list;

        /*child's initial settings*/
        if (init_mi_child()!=0) {
                LM_ERR("failed to init the mi process\n");
                exit(-1);
        }

	/* Allocating http response buffer */
	buffer.s = (char*)pkg_malloc(sizeof(char)*buffer.len);
	if (buffer.s==NULL) {
		LM_ERR("oom\n");
		exit(-1);
	}

	while(cb) {
		if (cb->init_proc_callback)
			cb->init_proc_callback();
		cb = cb->next;
	}

#ifdef LIBMICROHTTPD
	struct timeval tv;
	struct sockaddr_in saddr_in;

	memset(&saddr_in, 0, sizeof(saddr_in));
	if (ip.s)
		saddr_in.sin_addr.s_addr = inet_addr(ip.s);
	else
		saddr_in.sin_addr.s_addr = INADDR_ANY;
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = htons(port);

	LM_DBG("init_child [%d] - HTTP Server init [%d]\n", rank, getpid());
	dmn = MHD_start_daemon(MHD_NO_FLAG|MHD_USE_DEBUG, port, NULL, NULL,
			&(answer_to_connection), NULL,
			MHD_OPTION_SOCK_ADDR, &saddr_in,
			MHD_OPTION_END);

	if (NULL == dmn) {
		LM_ERR("unable to start http daemon\n");
		exit(-1);
	}

	while(1) {
		max = 0;
		FD_ZERO (&rs);
		FD_ZERO (&ws);
		FD_ZERO (&es);
		if (MHD_YES != MHD_get_fdset (dmn, &rs, &ws, &es, &max)) {
			LM_ERR("unable to get file descriptors\n");
			exit(-1);
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		//LM_DBG("select(%d,%p,%p,%p,%p)\n",max+1, &rs, &ws, &es, &tv);
		status = select(max+1, &rs, &ws, &es, &tv);
		switch(status){
		case EBADF:
			LM_ERR("error returned by select: EBADF [%d] "
				"(Bad file descriptor)\n", status);
			exit(-1);
			break;
		case EINTR:
			LM_WARN("error returned by select: EINTR [%d] "
				"(Non blocked signal caught)\n", status);
			//exit(-1);
			break;
		case EINVAL:
			LM_ERR("error returned by select: EINVAL [%d] "
				"(Invalid # of fd [%d] or timeout)\n",
				status, max+1);
			exit(-1);
			break;
		case ENOMEM:
			LM_ERR("error returned by select: ENOMEM [%d] "
				"(No more memory)\n", status);
			exit(-1);
			break;
		default:
			if(status<0){
				LM_ERR("error returned by select: [%d] "
					"[%d][%s]\n", status, errno, strerror(errno));
				exit(-1);
			}
		}
		//LM_DBG("select returned %d\n", status);
		status = MHD_run(dmn);
		if (status == MHD_NO) {
			LM_ERR("unable to run http daemon\n");
			exit(-1);
		}
	}
#endif
	LM_DBG("HTTP Server stopped!\n");
}

void httpd_proc_destroy(void)
{
#ifdef LIBMICROHTTPD
	LM_DBG("destroying module ...\n");
	MHD_stop_daemon (dmn);
#endif
	return;
}
