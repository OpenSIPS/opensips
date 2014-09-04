#include "qr_acc.h"

extern qr_rule_t * qr_rules_start;
int myn = 0;

/* free the parameter of the dialog callback */
inline static void release_dialog_prop(void * param) {
	qr_dialog_prop_t *to_free = (qr_dialog_prop_t*)param;
	if(to_free->time_200OK)
		shm_free(to_free->time_200OK);
	shm_free(to_free);
}

/* initialize the qr_trans_prop_t structure */
static inline int init_trans_prop(qr_trans_prop_t * trans_prop) {
	trans_prop->prop_lock
		= (gen_lock_t*)lock_alloc();
	if(trans_prop->prop_lock == NULL) {
		LM_ERR("failed to allocate lock (no more shm memory?)\n");
		return -1;
	}
	if (!lock_init(trans_prop->prop_lock)) {
		LM_ERR("failed to init lock\n");
		return -1;
	}
	if((trans_prop->invite = (struct timespec *)shm_malloc(
					sizeof(struct timespec))) == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	return 0;
}

/* free the param of the tm callback */
static void release_trans_prop(void *param) {
	qr_trans_prop_t * to_free;

	to_free = (qr_trans_prop_t *)param;
	if(to_free->invite) {
		shm_free(to_free->invite);
		to_free->invite = 0;
	}
	if(to_free->prop_lock) {
		lock_destroy(to_free->prop_lock);
		lock_dealloc(to_free->prop_lock);
		to_free->prop_lock = 0;
	}
	shm_free(to_free);
}

int test_acc(struct sip_msg* msg) {
	qr_gw_t  *gw = qr_rules_start->dest->dst.gw;
	qr_trans_prop_t *trans_prop = (qr_trans_prop_t*)shm_malloc(
			sizeof(qr_trans_prop_t));
	if(trans_prop == NULL) {
		LM_ERR("no more shm memory\n");
		goto error;
	}

	memset(trans_prop, 0, sizeof(qr_trans_prop_t));

	if(init_trans_prop(trans_prop) < 0) {
		LM_ERR("failed to init transaction properties (for qrouting)\n");
		goto error;
	}

	/* get the time of INVITE */
	if(clock_gettime(CLOCK_REALTIME, trans_prop->invite) < 0) {
		LM_ERR("failed to get system time\n");
		goto error;
	}

	/* save transaction properties */
	trans_prop->gw = gw;

	if(dlgcb.create_dlg(msg, 0) < 0) { /* for call duration */
		LM_ERR("failed to create dialog\n");
		goto error;
	}
	/* register callback for the responses to this INVITE */
	if(tmb.register_tmcb(msg, 0,TMCB_RESPONSE_IN, qr_check_reply_tmcb,
				(void*)trans_prop, release_trans_prop) <= 0) {
		LM_ERR("cannot register TMCB_RESPONSE_IN\n");
		goto error;
	}

	return 1;
error:
	if(trans_prop != NULL) {
		release_trans_prop(trans_prop); /* cur_time is released here */
	}

	return -1;
}

/* a call for this gateway returned 200OK */
inline void qr_add_200OK(qr_gw_t * gw) {
	lock_start_read(gw->ref_lock);
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.as);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
	lock_stop_read(gw->ref_lock);
}

/* a call for this gateway returned 4XX */
inline void qr_add_4xx(qr_gw_t * gw) {
	lock_start_read(gw->ref_lock);
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
	lock_stop_read(gw->ref_lock);
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

static void call_ended(struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params) {
	double cd;
	qr_dialog_prop_t *dialog_prop = (qr_dialog_prop_t*)params;
	struct timespec *time_200OK = (struct timespec*)*params->param;
	if((cd = get_elapsed_time(time_200OK,'s')) < 0) {
		return;
	}
	lock_start_read(dialog_prop->gw->ref_lock);
	lock_get(dialog_prop->gw->acc_lock); /* protect the statistics */
	++(dialog_prop->gw->current_interval.n.cd);
	dialog_prop->gw->current_interval.stats.cd += cd;
	lock_release(dialog_prop->gw->acc_lock);
	lock_stop_read(dialog_prop->gw->ref_lock);
	LM_DBG("call duration = %lf", cd);
}

/*
 * checks the response to an INVITE  and does accounting accordingly
 */
void qr_check_reply_tmcb(struct cell *cell, int type, struct tmcb_params *ps) {
	double pdd_tm = 0;
	qr_trans_prop_t *trans_prop = (qr_trans_prop_t*)*ps->param;
	struct dlg_cell *cur_dlg; /* for accouting call time */
	struct qr_dialog_prop *dialog_prop;

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
			lock_start_read(trans_prop->gw->ref_lock); /* so the current
														  interval won't be
														  changed by the timer
														  process */
			lock_get(trans_prop->gw->acc_lock); /* protect the statistics */
			++(trans_prop->gw->current_interval.n.pdd);
			trans_prop->gw->current_interval.stats.pdd += pdd_tm;
			lock_release(trans_prop->gw->acc_lock);
			lock_stop_read(trans_prop->gw->ref_lock);

		} else {
			lock_release(trans_prop->prop_lock); /* this was not the first 18X */
		}

	} else if(ps->code >= 200 && ps->code<500) { /* completed calls */
		if(ps->code == 200) { /* calee answered */
			qr_add_200OK(trans_prop->gw);
			if((dialog_prop = (qr_dialog_prop_t *)shm_malloc(
							sizeof(qr_dialog_prop_t))) ==NULL) {
				LM_ERR("no more shm memory\n");
				goto error;
			}
			memset(dialog_prop, 0, sizeof(qr_dialog_prop_t));

			if((dialog_prop->time_200OK = (struct timespec*)shm_malloc(
							sizeof(struct timespec))) == NULL) {
				LM_ERR("no more shm memory\n");
				goto error;
			}

			if(clock_gettime(CLOCK_REALTIME, dialog_prop->time_200OK) < 0) {
				LM_ERR("failed to get system time\n");
				goto error;
			}
			dialog_prop->gw = trans_prop->gw;

			if((cur_dlg = dlgcb.get_dlg()) < 0) {
				LM_ERR("failed to create dialog\n");
				goto error;
			}
			/* callback for call duration => called at the end of the call */
			if(dlgcb.register_dlgcb(cur_dlg, DLGCB_TERMINATED, (void*)call_ended,
						(void*)dialog_prop, release_dialog_prop) != 0) {
				LM_ERR("failed to register callback for call termination\n");
				goto error;
			}
		} else if (ps->code != 408 || (ps->code == 408 && (cell->flags &
						T_UAC_HAS_RECV_REPLY) )){ /* if it's 408 it must have
													 one provisional response */
			qr_add_4xx(trans_prop->gw);
		}
	}
	if(ps->code >= 200) { /* 1XX should not be accounted -
								provisional responses */
		lock_start_read(trans_prop->gw->ref_lock);
		lock_get(trans_prop->gw->acc_lock);
		++(trans_prop->gw->current_interval.n.ok);
		lock_release(trans_prop->gw->acc_lock);
		lock_stop_read(trans_prop->gw->ref_lock);
	}
	return ;
error:
	if(dialog_prop != NULL) {
		release_dialog_prop(dialog_prop);
	}
}


