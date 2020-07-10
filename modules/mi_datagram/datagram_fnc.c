/*
 * Copyright (C) 2007 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2007-06-25  first version (ancuta)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include "../../resolve.h"
#include "mi_datagram.h"
#include "datagram_fnc.h"
#include "../../mi/mi_trace.h"

/* solaris doesn't have SUN_LEN  */
#ifndef SUN_LEN
#define SUN_LEN(sa)	 ( strlen((sa)->sun_path) + \
					 (size_t)(((struct sockaddr_un*)0)->sun_path) )
#endif
/* AF_LOCAL is not defined on solaris */
#if !defined(AF_LOCAL)
#define AF_LOCAL AF_UNIX
#endif

int flags;
static char *mi_buf = 0;

typedef union {
	struct sockaddr_un un;
	struct sockaddr_in in;
} reply_addr_t;


typedef struct{
	reply_addr_t address;
	int address_len;
	int tx_sock;
}my_socket_address;

struct async_param {
	mi_item_t *id;
	my_socket_address addr;
};

static reply_addr_t reply_addr;
static unsigned int reply_addr_len;

/* Timeout for sending replies in milliseconds */
extern int mi_socket_timeout;
static unsigned int mi_socket_domain;

extern sockaddr_dtgram mi_dtgram_addr;
extern trace_dest t_dst;
extern int mi_trace_mod_id;

extern int mi_datagram_pp;

static int mi_sock_check(int fd, char* fname);

static str PARSE_ERR_STR    = str_init(MI_PARSE_ERROR);
static str INTERNAL_ERR_STR = str_init(MI_INTERNAL_ERROR);

static str backend = str_init("datagram");
static union sockaddr_union *sv_socket=0;

static const char *unknown_method = "unknown";

int  mi_init_datagram_server(sockaddr_dtgram *addr, unsigned int socket_domain,
						rx_tx_sockets * socks, int mode, int uid, int gid )
{
	char * socket_name;

	/* create sockets rx and tx ... */
	/***********************************/
	mi_socket_domain = socket_domain;
	/**********************************/

	socks->rx_sock = socket(socket_domain, SOCK_DGRAM, 0);
	if (socks->rx_sock == -1) {
		LM_ERR("cannot create RX socket: %s\n", strerror(errno));
		return -1;
	}

	switch(socket_domain) {
		case AF_LOCAL:
			LM_DBG("we have a unix socket: %s\n", addr->unix_addr.sun_path);
			socket_name = addr->unix_addr.sun_path;
			if(bind(socks->rx_sock,(struct sockaddr*)&addr->unix_addr,
					SUN_LEN(&addr->unix_addr))< 0) {
				LM_ERR("bind: %s\n", strerror(errno));
				goto err_rx;
			}
			if(mi_sock_check(socks->rx_sock, socket_name)!=0)
				goto err_rx;
			/* change permissions */
			if (mode){
				if (chmod(socket_name, mode)<0){
					LM_ERR("failed to change the permissions for %s to %04o:"
						"%s[%d]\n",socket_name, mode, strerror(errno), errno);
					goto err_rx;
				}
			}
			/* change ownership */
			if ((uid!=-1) || (gid!=-1)){
				if (chown(socket_name, uid, gid)<0){
					LM_ERR("failed to change the owner/group for %s to %d.%d;"
					"%s[%d]\n",socket_name, uid, gid, strerror(errno), errno);
					goto err_rx;
				}
			}
			/* create TX socket */
			socks->tx_sock = socket( socket_domain, SOCK_DGRAM, 0);
			if (socks->tx_sock == -1) {
				LM_ERR("cannot create socket: %s\n", strerror(errno));
				goto err_rx;
			};
			/* Turn non-blocking mode on for tx*/
			flags = fcntl(socks->tx_sock, F_GETFL);
			if (flags == -1) {
				LM_ERR("fcntl failed: %s\n", strerror(errno));
				goto err_both;
			}
			if (fcntl(socks->tx_sock, F_SETFL, flags | O_NONBLOCK) == -1) {
				LM_ERR("fcntl: set non-blocking failed: %s\n",strerror(errno));
				goto err_both;
			}
			break;

		case AF_INET:
			if (bind(socks->rx_sock, &addr->udp_addr.s,
			sockaddru_len(addr->udp_addr))< 0) {
				LM_ERR("bind: %s\n", strerror(errno));
				goto err_rx;
			}
			socks->tx_sock = socks->rx_sock;
			break;
		case AF_INET6:
			if(bind(socks->rx_sock, (struct sockaddr*)&addr->udp_addr.sin6,
					sizeof(addr->udp_addr)) < 0) {
				LM_ERR("bind: %s\n", strerror(errno));
				goto err_rx;
			}
			socks->tx_sock = socks->rx_sock;
			break;
		default:
			LM_ERR("domain not supported\n");
			goto err_rx;

	}

	return 0;
err_both:
	close(socks->tx_sock);
err_rx:
	close(socks->rx_sock);
	return -1;
}



int mi_init_datagram_buffer(void){

	mi_buf = pkg_malloc(DATAGRAM_SOCK_BUF_SIZE+1);
	if ( mi_buf==NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	return 0;
}

/* reply socket security checks:
 * checks if fd is a socket, is not hardlinked and it's not a softlink
 * opened file descriptor + file name (for soft link check)
 * returns 0 if ok, <0 if not */
int mi_sock_check(int fd, char* fname)
{
	struct stat fst;
	struct stat lst;

	if (fstat(fd, &fst)<0){
		LM_ERR("fstat failed: %s\n",
		strerror(errno));
		return -1;
	}
	/* check if socket */
	if (!S_ISSOCK(fst.st_mode)){
		LM_ERR("%s is not a sock\n", fname);
		return -1;
	}
	/* check if hard-linked */
	if (fst.st_nlink>1){
		LM_ERR("security: sock_check: %s is hard-linked %d times\n",
				fname, (unsigned)fst.st_nlink);
		return -1;
	}

	/* lstat to check for soft links */
	if (lstat(fname, &lst)<0){
		LM_ERR("lstat failed: %s\n", strerror(errno));
		return -1;
	}
	if (S_ISLNK(lst.st_mode)){
		LM_ERR("security: sock_check: %s is a soft link\n", fname);
		return -1;
	}
	/* if this is not a symbolic link, check to see if the inode didn't
	 * change to avoid possible sym.link, rm sym.link & replace w/ sock race
	 */
	/*LM_DBG("for %s lst.st_dev %fl fst.st_dev %i lst.st_ino %i fst.st_ino"
		"%i\n", fname, lst.st_dev, fst.st_dev, lst.st_ino, fst.st_ino);*/
	/*if ((lst.st_dev!=fst.st_dev)||(lst.st_ino!=fst.st_ino)){
		LM_ERR("security: sock_check: "
			"socket	%s inode/dev number differ: %d %d \n", fname,
			(int)fst.st_ino, (int)lst.st_ino);
	}*/
	/* success */
	return 0;
}



/* this function sends the reply over the reply socket */
static int mi_send_dgram(int fd, char* buf, unsigned int len,
				const struct sockaddr* to, int tolen, int timeout)
{
	int n;
	size_t total_len;
	total_len = strlen(buf);

	/*LM_DBG("response is %s \n tolen is %i "
			"and len is %i\n",buf,	tolen,len);*/

	if(total_len == 0 || tolen ==0)
		return -1;

	if (total_len>DATAGRAM_SOCK_BUF_SIZE)
	{
		LM_DBG("datagram too big, "
			"truncking, datagram_size is %i\n",DATAGRAM_SOCK_BUF_SIZE);
		len = DATAGRAM_SOCK_BUF_SIZE;
	}
	/*LM_DBG("destination address length is %i\n", tolen);*/
	n=sendto(fd, buf, len, 0, to, tolen);
	return n;
}


/*************************** async functions ******************************/
static inline void free_async_handler( struct mi_handler *hdl )
{
	if (hdl) {
		free_shm_mi_item(((struct async_param *)hdl->param)->id);
		shm_free(hdl);
	}
}


static void datagram_close_async(mi_response_t *resp,struct mi_handler *hdl,
																	int done)
{
	str print_buf;
	int ret;
	struct async_param *p;

	p = (struct async_param *)hdl->param;

	if ( resp!=0 || done )
	{
		if (resp!=0) {
			/*allocate the response datagram*/
			print_buf.s = pkg_malloc(DATAGRAM_SOCK_BUF_SIZE);
			if(!print_buf.s){
				LM_ERR("no more pkg memory\n");
				return;
			}
			print_buf.len = DATAGRAM_SOCK_BUF_SIZE;

			ret = print_mi_response(resp, p->id,
					&print_buf, mi_datagram_pp);
			if (ret == MI_NO_RPL) {
				LM_DBG("No reply for jsonrpc notification\n");
			} else if (ret < 0) {
				LM_ERR("failed to print json response\n");
				if (mi_send_dgram(p->addr.tx_sock, MI_INTERNAL_ERROR,
					MI_INTERNAL_ERROR_LEN,
					(struct sockaddr*)&reply_addr, reply_addr_len,
					mi_socket_timeout) < 0)
					LM_ERR("failed to send reply: %s | errno=%d\n",
							MI_INTERNAL_ERROR, errno);
			} else {
				print_buf.len = strlen(print_buf.s);
				ret = mi_send_dgram(p->addr.tx_sock, print_buf.s, print_buf.len,
						(struct sockaddr *)&p->addr.address, p->addr.address_len,
						mi_socket_timeout);
				if (ret>0)
					LM_DBG("the response: %s has been sent in %i octets\n",
						print_buf.s, ret);
				else
					LM_ERR("failed to send the response: %s (%d)\n",
						strerror(errno), errno);
			}

			free_mi_response(resp);
			pkg_free(print_buf.s);
		} else {
			if (mi_send_dgram(p->addr.tx_sock, MI_INTERNAL_ERROR,
				MI_INTERNAL_ERROR_LEN,
				(struct sockaddr*)&reply_addr, reply_addr_len,
				mi_socket_timeout) < 0)
				LM_ERR("failed to send reply: %s | errno=%d\n",
						MI_INTERNAL_ERROR, errno);
		}
	}

	if (done)
		free_async_handler( hdl );
}



static inline struct mi_handler* build_async_handler(unsigned int sock_domain,
								reply_addr_t *reply_addr, unsigned int reply_addr_len,
								int tx_sock, mi_item_t *id)
{
	struct mi_handler *hdl;
	void * p;
	struct async_param *param;

	hdl = (struct mi_handler*)shm_malloc( sizeof(struct mi_handler) +
			sizeof(struct async_param));
	if (hdl==0) {
		LM_ERR("no more shm mem\n");
		return 0;
	}

	p = (void *)((hdl) + 1);
	param = p;
	param->id = shm_clone_mi_item(id);

	memcpy(&param->addr.address, reply_addr, sizeof(reply_addr_t));

	param->addr.address_len  = reply_addr_len;
	param->addr.tx_sock = tx_sock;

	hdl->handler_f = datagram_close_async;
	hdl->param = (void*)param;

	return hdl;
}

static inline void trace_datagram_err(str *message)
{
	char *req_method = (char *)unknown_method;
	union sockaddr_union cl_socket;

	memcpy( &cl_socket.sin, &reply_addr.in, sizeof(reply_addr.in));

	if (!sv_socket)
		sv_socket = &mi_dtgram_addr.udp_addr;

	mi_trace_request(&cl_socket, sv_socket, req_method, strlen(req_method),
						NULL, &backend, t_dst);

	mi_trace_reply(sv_socket, &cl_socket, message, t_dst);
}

static inline void trace_datagram_request(struct mi_cmd* f, char *req_method,
											mi_item_t *params)
{
	union sockaddr_union cl_socket;

	if (!req_method)
		req_method = (char *)unknown_method;

	/* command not traced */
	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	memcpy( &cl_socket.sin, &reply_addr.in, sizeof(reply_addr.in));


	if ( !sv_socket ) {
		sv_socket = &mi_dtgram_addr.udp_addr;
	}

	mi_trace_request(&cl_socket, sv_socket, req_method, strlen(req_method),
		params, &backend, t_dst);
}

static inline void trace_datagram_reply( struct mi_cmd* f, str* message)
{
	union sockaddr_union cl_socket;

	if ( f && !is_mi_cmd_traced( mi_trace_mod_id, f) )
		return;

	memcpy( &cl_socket.sin, &reply_addr.in, sizeof(reply_addr.in));

	mi_trace_reply( sv_socket, &cl_socket, message, t_dst);
}

void mi_datagram_server(int rx_sock, int tx_sock)
{
	int ret = 0;
	const char **parse_end = NULL;
	char *req_method = NULL;
	mi_request_t request;
	mi_response_t *response = NULL;
	struct mi_handler *async_hdl;
	struct mi_cmd *cmd = NULL;
	str print_buf;

	while(1){/*read the datagram*/
		reply_addr_len = sizeof(reply_addr);

		ret = recvfrom(rx_sock, mi_buf, DATAGRAM_SOCK_BUF_SIZE, 0,
					(struct sockaddr*)&reply_addr, &reply_addr_len);

		if (ret < 0) {
			LM_ERR("recvfrom %d: (%d) %s\n", ret, errno, strerror(errno));
			if ((errno == EINTR) ||
				(errno == EAGAIN) ||
				(errno == EWOULDBLOCK) ||
				(errno == ECONNREFUSED)) {
				LM_DBG("got %d (%s), going on\n", errno, strerror(errno));
				continue;
			}
			LM_DBG("error in recvfrom\n");
			continue;
		}

		if(ret == 0)
			continue;

		mi_buf[ret] = '\0';
		LM_DBG("received %d |%.*s|\n", ret, ret, mi_buf);

		if(ret> DATAGRAM_SOCK_BUF_SIZE){
				LM_ERR("buffer overflow\n");
				continue;
		}

		memset(&request, 0, sizeof request);
		if (parse_mi_request(mi_buf, parse_end, &request) < 0) {
			LM_ERR("cannot parse command: %.*s\n", ret, mi_buf);

			if (mi_send_dgram(tx_sock, MI_PARSE_ERROR, MI_PARSE_ERROR_LEN,
				(struct sockaddr* )&reply_addr, reply_addr_len,
				mi_socket_timeout) < 0)
				LM_ERR("failed to send reply: %s | errno=%d\n",
						MI_PARSE_ERROR, errno);

			trace_datagram_err(&PARSE_ERR_STR);
			continue;
		}

		req_method = mi_get_req_method(&request);
		if (req_method)
			cmd = lookup_mi_cmd(req_method, strlen(req_method));

		/* if asyncron cmd, build the async handler */
		if (cmd && cmd->flags & MI_ASYNC_RPL_FLAG) {
			async_hdl = build_async_handler(mi_socket_domain,
					&reply_addr, reply_addr_len, tx_sock, request.id);
			if (async_hdl==0) {
				LM_ERR("failed to build async handler\n");
				if (mi_send_dgram(tx_sock, MI_INTERNAL_ERROR, MI_INTERNAL_ERROR_LEN,
					(struct sockaddr* )&reply_addr, reply_addr_len,
					mi_socket_timeout) < 0)
					LM_ERR("failed to send reply: %s | errno=%d\n",
							MI_INTERNAL_ERROR, errno);

				trace_datagram_err(&INTERNAL_ERR_STR);

				goto free_req;
			}
		} else{
			async_hdl = 0;
		}

		response = handle_mi_request(&request, cmd, async_hdl);

		if (response == NULL) {
			LM_ERR("failed to build response!\n");

			if (mi_send_dgram(tx_sock, MI_INTERNAL_ERROR, MI_INTERNAL_ERROR_LEN,
				(struct sockaddr* )&reply_addr, reply_addr_len,
				mi_socket_timeout) < 0)
				LM_ERR("failed to send reply: %s | errno=%d\n",
						MI_INTERNAL_ERROR, errno);

			trace_datagram_err(&INTERNAL_ERR_STR);

			if (async_hdl)
				free_async_handler(async_hdl);
			goto free_req;
		} else if (response != MI_ASYNC_RPL) {
			trace_datagram_request(cmd, req_method, request.params);

			print_buf.s = mi_buf;
			print_buf.len = DATAGRAM_SOCK_BUF_SIZE;
			ret = print_mi_response(response, request.id,
					&print_buf, mi_datagram_pp);

			if (ret == MI_NO_RPL) {
				LM_DBG("No reply for jsonrpc notification\n");
			} else if (ret < 0) {
				LM_ERR("failed to print json response\n");

				if (mi_send_dgram(tx_sock, MI_INTERNAL_ERROR, MI_INTERNAL_ERROR_LEN,
					(struct sockaddr* )&reply_addr, reply_addr_len,
					mi_socket_timeout) < 0)
					LM_ERR("failed to send reply: %s | errno=%d\n",
							MI_INTERNAL_ERROR, errno);

				trace_datagram_reply(cmd, &INTERNAL_ERR_STR);

				goto free_resp;
			} else {
				print_buf.len = strlen(print_buf.s);
				ret = mi_send_dgram(tx_sock, print_buf.s, print_buf.len,
								(struct sockaddr* )&reply_addr,
								reply_addr_len, mi_socket_timeout);
				if (ret>0){
					LM_DBG("the response: %s has been sent in %i octets\n",
						print_buf.s, ret);

					trace_datagram_reply(cmd, &print_buf);
				}else{
					LM_ERR("failed to send the response: %s (%d)\n",
						strerror(errno), errno);

					trace_datagram_reply(cmd, &INTERNAL_ERR_STR);
				}
			}
free_resp:
			if (async_hdl)
					free_async_handler(async_hdl);
			if (response)
				free_mi_response(response);
		} else
			continue;
free_req:
		free_mi_request_parsed(&request);
		continue;
	}
}
