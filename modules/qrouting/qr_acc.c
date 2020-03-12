/*
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */

#include "../drouting/dr_cb.h"

#include "qrouting.h"
#include "qr_acc.h"

struct tm_binds tmb;
struct dlg_binds dlgcb;
struct dr_binds drb;

/* initialize the qr_trans_prop_t structure */
static inline int init_trans_prop(qr_trans_prop_t *trans_prop)
{
	trans_prop->prop_lock = lock_alloc();
	if (!trans_prop->prop_lock) {
		LM_ERR("oom\n");
		return -1;
	}

	if (!lock_init(trans_prop->prop_lock)) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	return 0;
}

/* free the param of the tm callback */
static void release_trans_prop(void *param)
{
	qr_trans_prop_t *to_free = (qr_trans_prop_t *)param;

	if (to_free->prop_lock) {
		lock_destroy(to_free->prop_lock);
		lock_dealloc(to_free->prop_lock);
		to_free->prop_lock = QR_PTR_POISON;
	}

	shm_free(to_free);
}

void qr_acc(void *param)
{
	struct dr_acc_call_params *ap = (struct dr_acc_call_params *)param;
	qr_trans_prop_t *trans_prop;
	qr_rule_t *rule;
	int gw_id, cr_id;
	struct sip_msg *msg = ap->msg;

	LM_DBG("engaging accounting for rule %p, cr: %d, gw: %d\n", ap->rule,
	       ap->cr_id, ap->gw_id);

	if (msg->REQ_METHOD == METHOD_INVITE) {
		rule = ap->rule;
		gw_id = ap->gw_id;
		cr_id = ap->cr_id;

		/* first invocation of this callback, for branch #0 */
		if (!ap->data) {
			trans_prop = shm_malloc(sizeof *trans_prop);
			if (!trans_prop) {
				LM_ERR("oom\n");
				goto error;
			}
			memset(trans_prop, 0, sizeof *trans_prop);

			if (init_trans_prop(trans_prop) < 0) {
				LM_ERR("failed to init transaction properties\n");
				goto error;
			}

			if (dlgcb.create_dlg(msg, 0) < 0) { /* for call duration */
				LM_ERR("failed to create dialog\n");
				goto error;
			}

			/* register callback for the responses to this INVITE */
			if (tmb.register_tmcb(msg, 0, TMCB_RESPONSE_IN|TMCB_ON_FAILURE,
			        qr_check_reply_tmcb, (void *)trans_prop,
			        release_trans_prop) <= 0) {
				LM_ERR("cannot register TMCB_RESPONSE_IN\n");
				goto error;
			}

			ap->data = trans_prop;
		} else {
			trans_prop = (qr_trans_prop_t *)ap->data;
		}

		/* update the gateway in use */
		if (cr_id == -1) /* if the destination is not within a carrier */
			trans_prop->gw = rule->dest[gw_id].gw;
		else /* if the destination is within a carrier */
			trans_prop->gw = rule->dest[cr_id].grp.gw[gw_id];

		/* refresh the time of this new INVITE branch */
		if (clock_gettime(CLOCK_REALTIME, &trans_prop->invite) < 0) {
			LM_ERR("failed to get system time\n");
			goto error;
		}
	} else {
		LM_DBG("skipping method %d\n", msg->REQ_METHOD);
	}

	return;

error:
	if (trans_prop)
		release_trans_prop(trans_prop);
}

/* a call for this gateway returned 200OK */
static inline void qr_add_200OK(qr_gw_t *gw) {
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.as);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
}

/* a call for this gateway returned 4XX */
static inline void qr_add_4xx(qr_gw_t *gw) {
	lock_get(gw->acc_lock);
	++(gw->current_interval.stats.cc);
	lock_release(gw->acc_lock);
}

static inline void qr_add_pdd(qr_gw_t *gw, double pdd_tm) {
	lock_get(gw->acc_lock); /* protect the statistics */
	++(gw->current_interval.n.pdd);
	gw->current_interval.stats.pdd += pdd_tm;
	lock_release(gw->acc_lock);
}

static inline void qr_add_setup(qr_gw_t *gw, double st) {
	lock_get(gw->acc_lock); /* protect the statistics */
	++(gw->current_interval.n.setup);
	gw->current_interval.stats.st += st;
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
	double seconds, elapsed = 0;

	if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
		LM_ERR("failed to get the current time[RESPONSE]\n");
		return -1;
	}

	seconds = difftime(now.tv_sec, start->tv_sec); /* seconds elapsed betwen
													  now and the initial invite */
	if (seconds < 0) {
		LM_ERR("negative time elapsed\n");
		return -1;
	}

	if (mu == 'm') {
		/* compute the difference in miliseconds */
		elapsed += (seconds * 1000);
		elapsed += (now.tv_nsec - start->tv_nsec)/1000000;
		return elapsed;
	} else if (mu == 's') {
		/* return seconds elapsed */
		return seconds;
	}

	return -1;
}

/*
 * callback for getting the duration of the call
 */
static void qr_call_ended(struct dlg_cell*dlg, int type,
                          struct dlg_cb_params *params)
{
	double cd;
	qr_dialog_prop_t *dialog_prop = (qr_dialog_prop_t *)*params->param;

	if ((cd = get_elapsed_time(&dialog_prop->time_200OK, 's')) < 0) {
		LM_ERR("call duration negative\n");
		return;
	}

	lock_get(dialog_prop->gw->acc_lock); /* protect the statistics */
	++(dialog_prop->gw->current_interval.n.cd);
	dialog_prop->gw->current_interval.stats.cd += cd;
	lock_release(dialog_prop->gw->acc_lock);
}

/*
 * checks the response to an INVITE  and does accounting accordingly
 */
void qr_check_reply_tmcb(struct cell *cell, int type, struct tmcb_params *ps)
{
	double pdd_tm = 0, st = 0;
	qr_trans_prop_t *trans_prop = (qr_trans_prop_t *)*ps->param;
	struct dlg_cell *cur_dlg; /* for accounting call time */
	struct qr_dialog_prop *dialog_prop;

	LM_DBG("tm reply (%d%s) from gw %.*s\n", ps->code,
	       ps->code == 408 ? cell->flags & T_UAC_HAS_RECV_REPLY ?
	       " external" : " internal" : "",
	       drb.get_gw_name(trans_prop->gw->dr_gw)->len,
	       drb.get_gw_name(trans_prop->gw->dr_gw)->s);

	if (ps->code == 180 || ps->code == 183) { /* Ringing - provisional response */
		lock_get(trans_prop->prop_lock);

		/* compute the PDD _at most once_ */
		if (!(trans_prop->state & QR_TM_180_RCVD)) {
			trans_prop->state |= QR_TM_180_RCVD;
			lock_release(trans_prop->prop_lock);

			if ((pdd_tm = get_elapsed_time(&trans_prop->invite, 'm')) < 0) {
				lock_release(trans_prop->prop_lock);
				return;
			}

			qr_add_pdd(trans_prop->gw, pdd_tm);
		} else {
			lock_release(trans_prop->prop_lock);
		}

	} else if (ps->code >= 200 && ps->code < 500) { /* completed calls */
		if (ps->code == 200) { /* calee answered */
			if ((st = get_elapsed_time(&trans_prop->invite, 'm')) < 0) {
				LM_ERR("negative setup time\n");
				return;
			}

			/* if there was no 180/183, count PDD using the 200 OK! */
			lock_get(trans_prop->prop_lock);
			if (!(trans_prop->state & QR_TM_180_RCVD)) {
				trans_prop->state |= QR_TM_180_RCVD;
				lock_release(trans_prop->prop_lock);

				qr_add_pdd(trans_prop->gw, pdd_tm);
			} else {
				lock_release(trans_prop->prop_lock);
			}

			qr_add_setup(trans_prop->gw, st);

			qr_add_200OK(trans_prop->gw);

			if (!(dialog_prop = shm_malloc(sizeof *dialog_prop))) {
				LM_ERR("oom\n");
				return;
			}
			memset(dialog_prop, 0, sizeof *dialog_prop);

			if (clock_gettime(CLOCK_REALTIME, &dialog_prop->time_200OK) < 0) {
				LM_ERR("failed to get system time\n");
				return;
			}

			dialog_prop->gw = trans_prop->gw;

			if ((cur_dlg = dlgcb.get_dlg()) == NULL) {
				LM_ERR("failed to create dialog\n");
				return;
			}

			/* callback for call duration => called at the end of the call */
			if (dlgcb.register_dlgcb(cur_dlg, DLGCB_TERMINATED, qr_call_ended,
						(void *)dialog_prop, osips_shm_free) != 0) {
				LM_ERR("failed to register callback for call termination\n");
				return;
			}

		} else if (ps->code != 408 || (cell->flags & T_UAC_HAS_RECV_REPLY)) {
			/* an internal 408 timeout is not a completed call! */
			qr_add_4xx(trans_prop->gw);
		}
	}

	/* 1XX should not be accounted - provisional responses */
	if (ps->code >= 200) {
		lock_get(trans_prop->gw->acc_lock);
		++(trans_prop->gw->current_interval.n.ok);
		lock_release(trans_prop->gw->acc_lock);
	}
}

/* adds/removes two qr_n_calls_t structures */
static inline void add_n_calls(qr_n_calls_t *x, qr_n_calls_t *y, char op)
{
	int i;

	if (op == '+') {
		x->ok += y->ok;
		x->pdd += y->pdd;
		x->setup += y->setup;
		x->cd += y->cd;

		for (i = 0; i < qr_xstats_n; i++)
			x->xtot[i] += y->xtot[i];

	} else if (op == '-') {
		x->ok -= y->ok;
		x->pdd -= y->pdd;
		x->setup -= y->setup;
		x->cd -= y->cd;

		for (i = 0; i < qr_xstats_n; i++)
			x->xtot[i] -= y->xtot[i];
	}
}

/* adds/removes two qr_calls_t structures */
static inline void add_calls(qr_calls_t *x, qr_calls_t *y, char op) {
	int i;

	if (op == '+') {
		x->as += y->as;
		x->cc += y->cc;
		x->pdd += y->pdd;
		x->st += y->st;
		x->cd += y->cd;

		for (i = 0; i < qr_xstats_n; i++)
			x->xsum[i] += y->xsum[i];

	} else if (op == '-') {
		x->as -= y->as;
		x->cc -= y->cc;
		x->pdd -= y->pdd;
		x->st -= y->st;
		x->cd -= y->cd;

		for (i = 0; i < qr_xstats_n; i++)
			x->xsum[i] -= y->xsum[i];
	}
}

/* adds/removes two qr_stats_t structures */
static inline void add_stats(qr_stats_t *x, qr_stats_t *y, char op) {
	add_n_calls(&x->n, &y->n, op);
	add_calls(&x->stats, &y->stats, op);
}


/* testing purpose only */
void show_stats(qr_gw_t *gw) {
	LM_INFO("*****************************\n");
	LM_INFO("ans seizure: %lf / %lf\n", gw->summed_stats.stats.as,
			gw->summed_stats.n.ok);
	LM_INFO("completed calls: %lf / %lf\n", gw->summed_stats.stats.cc,
			gw->summed_stats.n.ok);
	LM_INFO("post dial delay: %lf / %lf\n", gw->summed_stats.stats.pdd,
			gw->summed_stats.n.pdd);
	LM_INFO("setup time: %lf / %lf\n", gw->summed_stats.stats.st,
			gw->summed_stats.n.setup);
	LM_INFO("call duration: %lf / %lf\n", gw->summed_stats.stats.cd,
			gw->summed_stats.n.cd);
	LM_INFO("*****************************\n");
}

/* update the statistics for a gateway */
void update_gw_stats(qr_gw_t *gw)
{
	qr_stats_t diff;

	lock_get(gw->acc_lock);

	/* prepare a diff of current/last stat samples */
	diff = gw->current_interval;
	add_stats(&diff, &gw->lru_interval->calls, '-');

	/* apply the diff to the summed stats */
	lock_start_write(gw->ref_lock);
	add_stats(&gw->summed_stats, &diff, '+');
	gw->state |= QR_STATUS_DIRTY;
	lock_stop_write(gw->ref_lock);

	/* rotate the sampling window */
	gw->lru_interval->calls = gw->current_interval;
//	show_stats(gw);
	memset(&gw->current_interval, 0, sizeof(qr_stats_t));
	gw->lru_interval = gw->lru_interval->next; /* the 'oldest' sample interval
													becomes the 'newest' */
	lock_release(gw->acc_lock);
}


/* update the statistics for a group of gateways */
void update_grp_stats(qr_grp_t grp)
{
	int i;

	for (i = 0; i < grp.n; i++)
		update_gw_stats(grp.gw[i]);

	grp.state |= QR_STATUS_DIRTY;
}
