#ifndef __QR_ACC_H__
#define __QR_ACC_H__

#include <time.h>

#include "../tm/tm_load.h"
#include "qr_stats.h"

struct tm_binds tmb;
int avp_invite_time_pdd; /* AVP for storing the time of the INVITE */


int test_acc(struct sip_msg*);
inline void qr_add_200OK(qr_gw_t * gw);
inline void qr_add_4xx(qr_gw_t*);
void qr_check_reply_tmcb(struct cell*, int ,struct tmcb_params*);

#endif
