/* 
 *$Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * ---------
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-29 transport-independent message zero-termination in
 *            receive_msg (jiri)
 * 2003-02-07 undoed jiri's zero term. changes (they break tcp) (andrei)
 * 2003-02-10 moved zero-term in the calling functions (udp_receive &
 *            tcp_read_req)
 * 2003-08-13 fixed exec_pre_cb returning 0 (backported from stable) (andrei)
 * 2004-02-06 added user preferences support - destroy_avps() (bogdan)
 * 2004-04-30 exec_pre_cb is called after basic sanity checks (at least one
 *            via present & parsed ok)  (andrei)
 * 2004-08-23 avp core changed - destroy_avp-> reset_avps (bogdan)
 * 2005-07-26 default onreply route added (andrei)
 * 2006-12-22 functions for script flags added (bogdan)
 */

/*! 
 * \file 
 * \brief Receive message and process routing for it
 */


#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "receive.h"
#include "globals.h"
#include "dprint.h"
#include "route.h"
#include "parser/msg_parser.h"
#include "forward.h"
#include "action.h"
#include "mem/mem.h"
#include "ip_addr.h"
#include "script_cb.h"
#include "dset.h"
#include "usr_avp.h"
#include "core_stats.h"
#include "ut.h"


#include "tcp_server.h" /* for tcpconn_add_alias */


#ifdef DEBUG_DMALLOC
#include <mem/dmalloc.h>
#endif

static unsigned int msg_no=0;
/* address preset vars */
str default_global_address={0,0};
str default_global_port={0,0};
str default_via_address={0,0};
str default_via_port={0,0};

unsigned int get_next_msg_no(void)
{
	return ++msg_no;
}

/*! \note WARNING: buf must be 0 terminated (buf[len]=0) or some things might 
 * break (e.g.: modules/textops)
 */
int receive_msg(char* buf, unsigned int len, struct receive_info* rcv_info) 
{
	struct sip_msg* msg;
	struct timeval start;

	msg=pkg_malloc(sizeof(struct sip_msg));
	if (msg==0) {
		LM_ERR("no pkg mem left for sip_msg\n");
		goto error;
	}
	msg_no++;
	/* number of vias parsed -- good for diagnostic info in replies */
	via_cnt=0;

	memset(msg,0, sizeof(struct sip_msg)); /* init everything to 0 */
	/* fill in msg */
	msg->buf=buf;
	msg->len=len;
	msg->rcv=*rcv_info;
	msg->id=msg_no;
	msg->set_global_address=default_global_address;
	msg->set_global_port=default_global_port;
	
	if (parse_msg(buf,len, msg)!=0){
		LM_ERR("parse_msg failed\n");
		goto parse_error;
	}
	LM_DBG("After parse_msg...\n");

	start_expire_timer(start,execmsgthreshold);

	/* ... clear branches from previous message */
	clear_branches();

	if (msg->first_line.type==SIP_REQUEST) {
		update_stat( rcv_reqs, 1);
		/* sanity checks */
		if ((msg->via1==0) || (msg->via1->error!=PARSE_OK)){
			/* no via, send back error ? */
			LM_ERR("no via found in request\n");
			update_stat( err_reqs, 1);
			goto parse_error;
		}
		/* check if necessary to add receive?->moved to forward_req */
		/* check for the alias stuff */
#ifdef USE_TCP
		if (msg->via1->alias && tcp_accept_aliases && 
				(((rcv_info->proto==PROTO_TCP) && !tcp_disable)
#ifdef USE_TLS
					|| ((rcv_info->proto==PROTO_TLS) && !tls_disable)
#endif
				)
			){
			if (tcpconn_add_alias(rcv_info->proto_reserved1, msg->via1->port,
									rcv_info->proto)!=0){
				LM_ERR("tcp alias failed\n");
				/* continue */
			}
		}
#endif

		LM_DBG("preparing to run routing scripts...\n");
		/* set request route type --bogdan*/
		set_route_type( REQUEST_ROUTE );

		/* execute pre-script callbacks, if any;
		 * if some of the callbacks said not to continue with
		 * script processing, don't do so;
		 * if we are here basic sanity checks are already done
		 * (like presence of at least one via), so you can count
		 * on via1 being parsed in a pre-script callback --andrei
		 */
		if (exec_pre_req_cb(msg)==0 ) {
			update_stat( drp_reqs, 1);
			goto end; /* drop the message */
		}

		/* exec the routing script */
		run_top_route(rlist[DEFAULT_RT].a, msg);

		/* execute post request-script callbacks */
		exec_post_req_cb(msg);
	} else if (msg->first_line.type==SIP_REPLY) {
		update_stat( rcv_rpls, 1);
		/* sanity checks */
		if ((msg->via1==0) || (msg->via1->error!=PARSE_OK)){
			/* no via, send back error ? */
			LM_ERR("no via found in reply\n");
			update_stat( err_rpls, 1);
			goto parse_error;
		}

		/* set reply route type --bogdan*/
		set_route_type( ONREPLY_ROUTE );

		/* execute pre-script callbacks, if any ;
		 * if some of the callbacks said not to continue with
		 * script processing, don't do so ;
		 * if we are here, basic sanity checks are already done
		 * (like presence of at least one via), so you can count
		 * on via1 being parsed in a pre-script callback --andrei
		 */
		if (exec_pre_rpl_cb(msg)==0 ) {
			update_stat( drp_rpls, 1);
			goto end; /* drop the reply */
		}

		/* exec the onreply routing script */
		if ( onreply_rlist[DEFAULT_RT].a!=0 &&
		(run_top_route(onreply_rlist[DEFAULT_RT].a,msg)&ACT_FL_DROP)
		&& msg->REPLY_STATUS<200 ) {
			LM_DBG("dropping provisional reply %d\n", msg->REPLY_STATUS);
			update_stat( drp_rpls, 1);
			goto end; /* drop the message */
		} else {
			/* send the msg */
			forward_reply(msg);
			/* TODO - TX reply stat */
		}

		/* execute post reply-script callbacks */
		exec_post_rpl_cb(msg);
	}

end:
	stop_expire_timer(start,execmsgthreshold,"msg processing",msg->buf,msg->len,0);
	/* free possible loaded avps -bogdan */
	reset_avps();
	LM_DBG("cleaning up\n");
	free_sip_msg(msg);
	pkg_free(msg);
	return 0;
parse_error:
	exec_parse_err_cb(msg);
	free_sip_msg(msg);
	pkg_free(msg);
error:
	return -1;
}

