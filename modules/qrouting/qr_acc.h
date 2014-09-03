#ifndef __QR_ACC_H__
#define __QR_ACC_H__

#include <time.h>

#include "../tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "qr_stats.h"

#define QR_TM_100RCVD (1<<0)

struct tm_binds tmb;
struct dlg_binds dlgcb;
struct dlg * dlg_cell;

typedef struct qr_trans_prop {
	qr_gw_t *gw;
	gen_lock_t *prop_lock;
	struct timespec *invite;
	char state;
} qr_trans_prop_t;


int test_acc(struct sip_msg*);
inline void qr_add_200OK(qr_gw_t * gw);
inline void qr_add_4xx(qr_gw_t*);
void qr_check_reply_tmcb(struct cell*, int ,struct tmcb_params*);
void call_ended(struct dlg_cell* dlg, int type,
		struct dlg_cb_params * params);

#endif
