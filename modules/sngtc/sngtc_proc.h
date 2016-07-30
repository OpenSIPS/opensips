/**
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
 * History
 * -------
 * 2013-06-05  created (liviu)
 *
 */

#include <sng_tc/sngtc_node.h>

enum request_type { REQ_CREATE_SESSION, REQ_FREE_SESSION };

/* information needed to make a request to the sangoma worker */
struct sngtc_request {
	enum request_type type;

	/* pipe descriptor used to send the response */
	int response_fd;

	struct sngtc_codec_request sng_req;
	struct sngtc_codec_reply   *sng_reply;
};

extern int sangoma_pipe[2];

void sangoma_worker_loop(int proc_no);

