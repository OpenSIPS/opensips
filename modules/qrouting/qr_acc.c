#include "qr_acc.h"

extern qr_rule_t * qr_rules_start;
int myn = 0;

int test_acc(struct sip_msg* msg) {
	qr_gw_t  *gw = qr_rules_start->dest->dst.gw;
	struct timespec  cur_time;
	int_str invite_time;
	/* register callback for the responses to this INVITE */
	if(tmb.register_tmcb(msg, 0,TMCB_RESPONSE_IN, qr_check_reply_tmcb,
				(void*)gw, 0) <= 0) {
		LM_ERR("cannot register TMCB_RESPONSE_IN\n");
		return -1;
	}

	/* get the time of INVITE */
	if(clock_gettime(CLOCK_REALTIME, &cur_time) < 0) {
		LM_ERR("failed to get system time\n");
		return -1;
	}

	invite_time.s.s = (char*)&cur_time;
	invite_time.s.len = sizeof(struct timespec);

	/* save the pointer to the time structure in an avp */
	if(add_avp(AVP_VAL_STR, avp_invite_time_pdd, invite_time) < 0) {
		LM_ERR("failed to attach avp (time of invite) to transaction\n");
		return -1;
	}
	return 1;
}

/* a call for this gateway returned 200OK */
inline void qr_add_200OK(qr_gw_t * gw) {
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.as);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
}

/* a call for this gateway returned 4XX */
inline void qr_add_4xx(qr_gw_t * gw) {
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
}

/*
 * returns the elapsed time in miliseconds from
 * a given moment specified by time_t
 */
double get_elapsed_time(struct timespec * start) {
	struct timespec now;
	double seconds, elapsed = 0, milisec_start, milisec_now;

	if(clock_gettime(CLOCK_REALTIME, &now) < 0) {
		LM_ERR("failed to get the current time[RESPONSE]\n");
		return -1;
	}

	seconds = difftime(now.tv_sec, start->tv_sec); /* seconds elapsed betwen
											now and the initial invite */
	if(seconds < 0) {
		LM_ERR("negative time elapsed from INVITE\n");
		return -1;
	}
	/* compute the difference in 100miliseconds */
	elapsed += (seconds * 1000);
	milisec_start = start->tv_nsec/1000000;
	milisec_now = now.tv_nsec/1000000;
	elapsed += (milisec_now - milisec_start);

	return elapsed;
}

/*
 * checks the response to an INVITE  and does accounting accordingly
 */
void qr_check_reply_tmcb(struct cell *cell, int type, struct tmcb_params *ps) {
	int_str time_of_invite;
	double pdd_tm;
	qr_gw_t *gw = (qr_gw_t*)ps->param;

	if(gw == NULL)
		return;

	if(ps->code == 180 || ps->code == 183) { /* Ringing */
		if(search_first_avp(AVP_VAL_STR, avp_invite_time_pdd, &time_of_invite,
					NULL) < 0) {
			LM_ERR("failed to find the avp containing the time of invite "\
					"maybe it is not the first 18X response\n");
		} else if(time_of_invite.s.s != 0) {
			if(( pdd_tm =
						get_elapsed_time(
								(struct timespec*)time_of_invite.s.s))
					< 0) {
				return; /* TODO: smth smarter? */
			}

		}
	} else if(ps->code >= 200 && ps->code<500) { /* completed calls */
		if(ps->code == 200) {
			qr_add_200OK(qr_rules_start->dest[0].dst.gw);
		} else if (ps->code != 408 || (ps->code == 408 && (cell->flags &
						T_UAC_HAS_RECV_REPLY) )){ /* if it's 408 it must have
													 one provisional response */
			qr_add_4xx(gw);
		}
	} else if(ps->code >= 500) { /* 1XX should not be accounted -
									provisional responses */
		lock_get(gw->acc_lock);
		++(qr_rules_start->dest[0].dst.gw->current_interval.n.ok);
		lock_release(gw->acc_lock);
	}
}

