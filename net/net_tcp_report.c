/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "../dprint.h"
#include "../ipc.h"
#include "trans.h"
#include "net_tcp.h"
#include "net_tcp_report.h"

/* is the process TCP MAIN ? */
extern int is_tcp_main;

typedef struct _tcp_report_job {
	/* TCP connection ID */
	unsigned long long conn_id;
	/* TCP connection flags */
	unsigned long long conn_flags;
	/* reporting type */
	int type;
	/* the protocol ID */
	int proto;
	/* extra data */
	void *extra;
} tcp_report_job;


static void tcp_report_ipc_handler(int sender, void *param)
{
	tcp_report_job *job = (tcp_report_job*)param;

	/* run the report callback  */
	protos[job->proto].net.report( job->type, job->conn_id, job->conn_flags,
		job->extra);
	/* and free the job memory */
	shm_free(job);
}


/* Pushes a TCP event as a repot to the PROTO layer. Depending on the type of
 * of the reported event, the function will construct and push forward a
 * per-type string holding the description of the reported event - the TCP
 * connection itself does not propgate further to the proto layer.
 * As the TCP MAIN process has a special status when comes to what it is able
 * to do (handling, communication,etc) and to avoid any problems within the
 * PROTO layer (when handling the report), the function will take care NOT to
 * run the "report" handler in the TCP MAIN - it will push the execution to
 * a TCP WORKER process via IPC.
 * Parameters:
 *   - conn - the tcp connection; be carefull what you do with it as there is
 *            0 guarantee on what happens with the conn after the triggering;
 *            it may be destoied, so do not keep references to it;
 *   - type - the reported event, CLOSE, STATS, others
 *   - extra - data specific to the event; to be sure you do not end-up with
 *            any dangling pointers, either use static/global data, either
 *            malloced/freeed when passing it here.
 */
void tcp_trigger_report(struct tcp_connection *conn, int type, void *extra)
{
	tcp_report_job *job;

	/* any reporting function registered by the PROTO layer ? */
	if (protos[conn->type].net.report==NULL)
		return;

	/* convert the extra data, from what we get from the TRANSport layer
	 * to what we pass to the reporting callback ;
	 * Basically aggregate info from "conn" and "extra" to generate a more
	 * complex "extra" to be passed further */
	if (type == TCP_REPORT_CLOSE) {
		/* the extra is the "reason" string for having the TCP connection
		 * closed; it is a static string, so no handling/conversion is
		 * needed for it */
	} else {
		LM_ERR("not understanding report type %d, discarding\n", type);
		return;
	}

	/* now, trigger the "report" callback from the PROTO layer */
	if (is_tcp_main) {

		/* we are in TCP MAIN, use IPC to push the report */

		/* build and send the job */
		job = shm_malloc(sizeof(tcp_report_job));
		if (job==NULL) {
			LM_ERR("failed to allocated SHM mem, discarding report\n");
			return;
		}
		job->type = type;
		job->conn_id = conn->cid;
		job->conn_flags = conn->flags;
		job->proto = conn->type;
		job->extra = extra;
		/* ...sending it any worker via RPC dispatching */
		if (ipc_dispatch_rpc( tcp_report_ipc_handler, job)<0) {
			LM_ERR("failed to send IPC job, discarding report\n");
			shm_free(job);
			return;
		}
		/* done here */

	} else {

		/* do the reporting inline */

		/* run the report callback  */
		protos[conn->type].net.report( type, conn->cid, conn->flags, extra);

	}

	return;
}

