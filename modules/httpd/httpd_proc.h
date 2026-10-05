/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */


#ifndef _MI_HTTP_HTTPD_PROC_H
#define _MI_HTTP_HTTPD_PROC_H

#include "../../str.h"

#ifdef LIBMICROHTTPD
#include <microhttpd.h>
extern struct MHD_Daemon *dmn;

#if (MHD_VERSION >= 0x00097002)
#define MHD_RET enum MHD_Result
#else
#define MHD_RET int
#endif
#endif

struct httpd_server {
	str name;
	str ip;
	int port;
	int buf_size;
	int conn_timeout;
	int post_buf_size;
	int receive_buf_size;
	str tls_cert_file;
	str tls_key_file;
	str tls_ciphers;
	int workers;
	int listen_fd;
};

extern struct httpd_server *httpd_servers;
extern int httpd_n_servers;

void httpd_proc(int rank);
void httpd_proc_destroy(void);
int httpd_pre_fork(void);
int httpd_post_fork(void);

#endif

