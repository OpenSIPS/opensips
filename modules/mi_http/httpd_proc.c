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
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "http_fnc.h"


extern int port;
extern int buf_size;


static const str MI_HTTP_U_ERROR = str_init("<html><body>"
"Internal server error!</body></html>");
static const str MI_HTTP_U_URL = str_init("<html><body>"
"Unable to parse URL!</body></html>");
static const str MI_HTTP_U_METHOD = str_init("<html><body>"
"Unexpected method (only GET is accepted)!</body></html>");


#ifdef LIBMICROHTTPD
struct MHD_Daemon *dmn;


static int flush_data(void *cls, uint64_t pos, char *buf, int max)
{
	struct mi_handler *hdl = (struct mi_handler*)cls;
	gen_lock_t *lock;
	mi_http_async_resp_data_t *async_resp_data;
	str page = {NULL, 0};

	if (hdl==NULL) {
		LM_ERR("Unexpected NULL mi handler!\n");
		return -1;
	}
	LM_DBG("hdl=[%p], hdl->param=[%p], pos=[%d], buf=[%p], max=[%d]\n",
		 hdl, hdl->param, (int)pos, buf, max);

	if (pos){
		LM_DBG("freeing hdl=[%p]: hdl->param=[%p], "
			" pos=[%d], buf=[%p], max=[%d]\n",
			 hdl, hdl->param, (int)pos, buf, max);
		shm_free(hdl);
		return -1;
	}
	async_resp_data =
		(mi_http_async_resp_data_t*)((char*)hdl+sizeof(struct mi_handler));
	lock = async_resp_data->lock;
	lock_get(lock);
	if (hdl->param) {
		if (*(struct mi_root**)hdl->param) {
			page.s = buf;
			LM_DBG("tree=[%p]\n", *(struct mi_root**)hdl->param);
			if (mi_http_build_page(&page, max,
						async_resp_data->mod,
						async_resp_data->cmd,
						*(struct mi_root**)hdl->param)!=0){
				LM_ERR("Unable to build response\n");
				shm_free(*(void**)hdl->param);
				*(void**)hdl->param = NULL;
				lock_release(lock);
				memcpy(buf, MI_HTTP_U_ERROR.s, MI_HTTP_U_ERROR.len);
				return MI_HTTP_U_ERROR.len;
			} else {
				shm_free(*(void**)hdl->param);
				*(void**)hdl->param = NULL;
				lock_release(lock);
				return page.len;
			}
		} else {
			LM_DBG("data not ready yet\n");
			lock_release(lock);
			return 0;
		}
	} else {
		lock_release(lock);
		LM_ERR("Invalid async reply\n");
		memcpy(buf, MI_HTTP_U_ERROR.s, MI_HTTP_U_ERROR.len);
		return MI_HTTP_U_ERROR.len;
	}
	lock_release(lock);
	LM_CRIT("done?\n");
	shm_free(hdl);
	return -1;
}


int answer_to_connection (void *cls, struct MHD_Connection *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		size_t *upload_data_size, void **con_cls)
{
	str page = {NULL, 0};
	struct MHD_Response *response;
	int ret = 0;
	int mod = -1;
	int cmd = -1;
	const char *query_cmd;
	struct mi_root *tree = NULL;
	struct mi_handler *async_hdl;

	LM_DBG("START *** cls=%p, connection=%p, url=%s, method=%s, "
		"versio=%s, upload_data[%d]=%p, con_cls=%p\n",
			cls, connection, url, method, version,
			*upload_data_size, upload_data, con_cls);
	if (strncmp(method, "GET", 3)==0) {
		if(0 == mi_http_parse_url(url, &mod, &cmd)) {
			query_cmd = MHD_lookup_connection_value(connection,
					MHD_GET_ARGUMENT_KIND, "arg");
			LM_DBG("query_cmd [%p]->[%s]\n", query_cmd, query_cmd);
			if (mod>=0 && cmd>=0 && query_cmd) {
				tree = mi_http_run_mi_cmd(mod, cmd, query_cmd,
								&page, &async_hdl);
				if (tree == NULL) {
					LM_ERR("no reply\n");
					page = MI_HTTP_U_ERROR;
				} else if (tree == MI_ROOT_ASYNC_RPL) {
					LM_DBG("got an async reply\n");
					tree = NULL;
				} else {
					LM_DBG("building on page [%p:%d]\n",
						page.s, page.len);
					if(0!=mi_http_build_page(&page, buf_size,
								mod, cmd, tree)){
						LM_ERR("unable to build response\n");
						page = MI_HTTP_U_ERROR;
					}
				}
			} else {
				page.s = miHTTPResponse_Buf;
				if(0 != mi_http_build_page(&page, buf_size,
							mod, cmd, tree)) {
					LM_ERR("unable to build response\n");
					page = MI_HTTP_U_ERROR;
				}
			}
			if (tree) {
				free_mi_tree(tree);
				tree = NULL;
			}
		} else {
			LM_ERR("unable to parse URL [%s]\n", url);
			page = MI_HTTP_U_URL;
		}
	} else {
		LM_ERR("unexpected method [%s]\n", method);
		page = MI_HTTP_U_METHOD;
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
							buf_size,
							&flush_data,
							(void*)async_hdl,
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
        /*child's initial settings*/
        if (init_mi_child()!=0) {
                LM_ERR("failed to init the mi process\n");
                exit(-1);
        }

	/* Build a cache of all mi commands */
	if (0!=mi_http_init_cmds())
		exit(-1);

	/* build async lock */
	if (mi_http_init_async_lock() != 0)
		exit(-1);

#ifdef LIBMICROHTTPD
	struct timeval tv;
	struct sockaddr_in saddr_in;
	//str host = str_init("");

	memset(&saddr_in, 0, sizeof(saddr_in));
	//saddr_in.sin_addr.s_addr = inet_addr(host.s);
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
		//status = select(max+1, &rs, &ws, &es, NULL);
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
	mi_http_destroy_async_lock();
	return;
}
