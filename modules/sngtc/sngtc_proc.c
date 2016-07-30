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

#include <unistd.h>

#include "../../str.h"
#include "../../pt.h"
#include "../../dprint.h"

#include "sngtc.h"
#include "sngtc_proc.h"

void sangoma_worker_loop(int proc_no)
{
	struct sngtc_request req;
	int rc;

	close(sangoma_pipe[WRITE_END]);

	for (;;) {
		rc = 0;

		LM_DBG("reading from pipe\n");
		if (read(sangoma_pipe[READ_END], &req, sizeof(req)) < 0) {
			LM_ERR("failed to read from pipe (%d - %s)\n", errno,
			       strerror(errno));
			continue;
		}

		switch (req.type) {
		case REQ_CREATE_SESSION:
			LM_DBG("CREATE request\n");

			if (sngtc_create_transcoding_session(&req.sng_req, req.sng_reply, 0)
			    != 0) {
				LM_ERR("failed to create sng transcoding session\n");
				sngtc_print_request(L_ERR, req.sng_req);
				rc = 1;
			}
			break;

		case REQ_FREE_SESSION:
			LM_DBG("FREE request\n");
			sngtc_print_reply(L_DBG, req.sng_reply);

			if (sngtc_free_transcoding_session(req.sng_reply) != 0) {
				LM_ERR("failed to free sng transcoding session\n");
				sngtc_print_reply(L_ERR, req.sng_reply);
				rc = 1;
			}
			break;

		default:
			LM_ERR("dropping invalid sangoma request: %d\n", req.type);
			rc = 1;
		}

		if (write(req.response_fd, &rc, sizeof(rc)) < 0)
			LM_ERR("failed to write in response pipe fd %d (%d: %s)\n",
			       req.response_fd, errno, strerror(errno));
	}
}

