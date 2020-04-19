/*
 * call center module - call queuing and distribution
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../../ut.h"
#include "cc_queue.h"

extern stat_var *stg_terminated_calls;
extern stat_var *stg_dist_incalls;
extern str queue_pos_param;


/* this function must be call under
 *    1) general data lock as it accesses diverent data to calculate the next state
 *    2) call lock as it is changing the call state
 */
int cc_call_state_machine(struct cc_data *data, struct cc_call *call,
																str *leg)
{
	struct cc_agent *agent;
	str *out = NULL;
	int state =0;
	int pos = -1;
	int len;
	char *s;

	switch (call->state) {
		case CC_CALL_NONE:
			/* next should be welcome msg if any */
			if ( call->flow->recordings[ AUDIO_WELCOME ].len  ) {
				LM_DBG("selecting WELCOME\n");
				out = &(call->flow->recordings[ AUDIO_WELCOME ]);
				state = CC_CALL_WELCOME;
				break;
			}
			/* no Welcome message -> got for queue/agent  */
		case CC_CALL_WELCOME:
			/* next should be dissuading, if the case and if any */
			if (call->flow->diss_ewt_th && call->eta > call->flow->diss_ewt_th
			&& call->flow->recordings[AUDIO_DISSUADING].len ) {
				/* callback/dissuading message */
				LM_DBG("selecting DISSUADING on EWT\n");
				out = &(call->flow->recordings[ AUDIO_DISSUADING ]);
				state = call->flow->diss_hangup ?
					CC_CALL_DISSUADING2 : CC_CALL_DISSUADING1;
				break;
			} else
			if (call->flow->diss_qsize_th &&
			call->flow->diss_qsize_th <= data->queue.calls_no &&
			call->flow->recordings[AUDIO_DISSUADING].len ) {
				/* callback/dissuading message */
				LM_DBG("selecting DISSUADING on QUEUE SIZE\n");
				out = &(call->flow->recordings[ AUDIO_DISSUADING ]);
				state = call->flow->diss_hangup ?
					CC_CALL_DISSUADING2 : CC_CALL_DISSUADING1;
				break;
			} 
			/* got for queue/agent */
		case CC_CALL_DISSUADING1:
		case CC_CALL_QUEUED:
			/* search for an available agent */
			/* if we have a flow_id recording, we push the call in the queue */
			if (!call->flow->recordings[AUDIO_FLOW_ID].len)
				agent = get_free_agent_by_skill( data, call->flow->skill);
			else
				agent = NULL;
			if (agent) {
				/* send it to agent */
				LM_DBG("selecting AGENT %p (%.*s)\n",agent,
					agent->id.len, agent->id.s);
				if(call->flow->recordings[AUDIO_FLOW_ID].len) {
					out = &call->flow->recordings[AUDIO_FLOW_ID];
					state = CC_CALL_PRE_TOAGENT;
					LM_DBG("moved to PRE_TOAGENT from %d\n", call->state);
				}
				else {
					state = CC_CALL_TOAGENT;
					out = &agent->location;
					LM_DBG("moved to TOAGENT from %d, out=%p\n", call->state, out);
				}
				/* mark agent as used */
				agent->state = CC_AGENT_INCALL;
				call->agent = agent;
				call->agent->ref_cnt++;
				update_stat( stg_dist_incalls, 1);
				update_stat( call->flow->st_dist_incalls, 1);
				call->fst_flags |= FSTAT_DIST;
				update_stat( call->agent->st_dist_incalls, +1);
				break;
			} else {
				/* put it into queue */
				LM_DBG("selecting QUEUE\n");
				out = &(call->flow->recordings[AUDIO_QUEUE]);
				state = CC_CALL_QUEUED;
				if(call->state == CC_CALL_QUEUED) {
					LM_DBG("State is already queued %p\n", call);
					break;
				}
				/* add it to queue */
				pos = cc_queue_push_call( data, call, 0);
			}
			break;
		case CC_CALL_DISSUADING2:
		case CC_CALL_TOAGENT:
		case CC_CALL_ENDED:
			LM_DBG("selecting END\n");
			call->state = CC_CALL_ENDED;
			return 0;
		default:
			LM_CRIT("Bogus state [%p] [%d]\n", call, call->state);
	}

	if (out) {
		/* compute the new SIP URI */
		/* report the queue position ? */
		if (queue_pos_param.s && pos>=0)
			s = int2str((unsigned long)pos, &len);
		else
			s = NULL;
		leg->s = (char*)pkg_malloc(out->len+(s?(queue_pos_param.len+len+2):0));
		if (leg->s) {
			leg->len = out->len;
			memcpy(leg->s,out->s,out->len);
			if (s) {
				leg->s[leg->len++] = ';';
				memcpy(leg->s+leg->len, queue_pos_param.s,queue_pos_param.len);
				leg->len += queue_pos_param.len;
				leg->s[leg->len++] = '=';
				memcpy(leg->s+leg->len, s, len);
				leg->len += len;
			}
			call->prev_state = call->state;
			call->state = state;
			return 0;
		}
	}

	leg->s = NULL;
	leg->len = 0;

	return -1;
}


