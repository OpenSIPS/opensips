#ifndef __FRD_EVENTS_H__
#define __FRD_EVENTS_H__

#include "frd_stats.h"

int frd_event_init(void);
void frd_event_destroy(void);
void raise_warning_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, int *ruleid);
void raise_critical_event(str *param, unsigned int *val, unsigned int *thr,
		str *user, str *number, int *ruleid);


/* Dialog callback */

typedef struct {
	frd_thresholds_t *thr;
	str user;
	str number;
	int ruleid;
	unsigned int data_rev;
} frd_dlg_param;

 void dialog_terminate_CB(struct dlg_cell *dlgc, int type,
		struct dlg_cb_params *params);


#endif
