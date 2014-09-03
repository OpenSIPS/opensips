#include "qr_acc.h"

extern qr_rule_t * qr_rules_start;
int myn = 0;

static void free_timespec(void * to_free) {
	shm_free((struct timespec*)to_free);
}

static inline int init_trans_prop(qr_trans_prop_t * trans_prop) {
	memset(trans_prop, 0, sizeof(qr_trans_prop_t));

	trans_prop->prop_lock
		= (gen_lock_t*)lock_alloc();
	if (!lock_init(trans_prop->prop_lock)) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	return 0;

}

static void release_trans_prop(void *param) {
	qr_trans_prop_t * to_free;

	to_free = (qr_trans_prop_t *)param;
	if(to_free->invite) {
		shm_free(to_free->invite);
	}
	if(to_free->prop_lock) {
		lock_destroy(to_free->prop_lock);
		lock_dealloc(to_free->prop_lock);
	}
	shm_free(to_free);
}

int test_acc(struct sip_msg* msg) {
	qr_gw_t  *gw = qr_rules_start->dest->dst.gw;
	struct timespec  *cur_time = (struct timespec *)shm_malloc(
			sizeof(struct timespec));
	qr_trans_prop_t *trans_prop = (qr_trans_prop_t*)shm_malloc(
			sizeof(qr_trans_prop_t));
	init_trans_prop(trans_prop);

	/* get the time of INVITE */
	if(clock_gettime(CLOCK_REALTIME, cur_time) < 0) {
		LM_ERR("failed to get system time\n");
		return -1;
	}

	/* save transaction properties */
	trans_prop->invite = cur_time;
	trans_prop->gw = gw;

	dlgcb.create_dlg(msg, 0); /* for call duration */
	/* register callback for the responses to this INVITE */
	if(tmb.register_tmcb(msg, 0,TMCB_RESPONSE_IN, qr_check_reply_tmcb,
				(void*)trans_prop, release_trans_prop) <= 0) {
		LM_ERR("cannot register TMCB_RESPONSE_IN\n");
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
 * returns the elapsed time from
 * a given moment specified by time_t.
 * -if mu = 's' it returnes the time in seconds
 * -if mu = 'm' it returnes the time in miliseconds
 */
static double get_elapsed_time(struct timespec * start, char mu) {
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
	if(mu == 'm') {
		/* compute the difference in miliseconds */
		elapsed += (seconds * 1000);
		milisec_start = start->tv_nsec/1000000;
		milisec_now = now.tv_nsec/1000000;
		elapsed += (milisec_now - milisec_start);
		return elapsed;
	} else if(mu == 's') {
		/* return seconds elapsed */
		return seconds;
	}

	return -1;
}

/*
 * checks the response to an INVITE  and does accounting accordingly
 */
void qr_check_reply_tmcb(struct cell *cell, int type, struct tmcb_params *ps) {
	double pdd_tm = 0;
	qr_trans_prop_t *trans_prop = (qr_trans_prop_t*)*ps->param;
	struct dlg_cell *cur_dlg; /* for accouting call time */
	struct timespec *time_200OK;

	if(trans_prop == NULL)
		return;

	if(ps->code == 180 || ps->code == 183) { /* Ringing - provisional response */
		lock_get(trans_prop->prop_lock);
		if(!(trans_prop->state & QR_TM_100RCVD)) {
			trans_prop->state |= QR_TM_100RCVD; /* mark the rcv of the first
												   1XX provisional reponse */
			lock_release(trans_prop->prop_lock);
			if(( pdd_tm =
						get_elapsed_time(
							(struct timespec*)trans_prop->invite, 'm'))
					< 0) {
				return; /* TODO: smth smarter? */
			}
		} else {
			lock_release(trans_prop->prop_lock);
		}

	} else if(ps->code >= 200 && ps->code<500) { /* completed calls */
		if(ps->code == 200) { /* calee answered */
			qr_add_200OK(trans_prop->gw);
			time_200OK = shm_malloc(sizeof(struct timeval));


			if(clock_gettime(CLOCK_REALTIME, time_200OK) < 0) {
				LM_ERR("failed to get system time\n");
				return ;
			}

			if((cur_dlg = dlgcb.get_dlg()) < 0) {
				LM_ERR("failed to create dialog\n");
				return ; /* TODO: goto accouting */
			}
			if(dlgcb.register_dlgcb(cur_dlg, DLGCB_TERMINATED, (void*)call_ended,
						(void*)time_200OK, free_timespec) != 0) {
				LM_ERR("failed to register callback for call termination\n");
			}
		} else if (ps->code != 408 || (ps->code == 408 && (cell->flags &
						T_UAC_HAS_RECV_REPLY) )){ /* if it's 408 it must have
													 one provisional response */
			qr_add_4xx(trans_prop->gw);
		}
	} else if(ps->code >= 500) { /* 1XX should not be accounted -
									provisional responses */
		lock_get(trans_prop->gw->acc_lock);
		++(trans_prop->gw->current_interval.n.ok);
		lock_release(trans_prop->gw->acc_lock);
	}
}

void call_ended(struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params) {
	double cd;
	struct timespec *time_200OK = (struct timespec*)*params->param;
	if((cd = get_elapsed_time(time_200OK,'s')) < 0) {
		return;
	}
	LM_DBG("call duration = %lf", cd);
}

