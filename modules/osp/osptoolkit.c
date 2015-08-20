/*
 * opensips osp module.
 *
 * This module enables opensips to communicate with an Open Settlement
 * Protocol (OSP) server.  The Open Settlement Protocol is an ETSI
 * defined standard for Inter-Domain VoIP pricing, authorization
 * and usage exchange.  The technical specifications for OSP
 * (ETSI TS 101 321 V4.1.1) are available at www.etsi.org.
 *
 * Uli Abend was the original contributor to this module.
 *
 * Copyright (C) 2001-2005 Fhg Fokus
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <osp/osptrans.h>
#include "../../dprint.h"
#include "osptoolkit.h"

static OSPTTHREADRETURN ospReportUsageWork(void* usagearg);

typedef struct _osp_usage {
    OSPTTRANHANDLE transaction; /* Transaction handle */
    unsigned cause;             /* Release code */
    unsigned duration;          /* Length of call */
    time_t start;               /* Call start time */
    time_t end;                 /* Call end time */
    time_t alert;               /* Call alert time */
    time_t connect;             /* Call connect time */
    unsigned haspdd;            /* Is PDD Info present */
    unsigned pdd;               /* Post Dial Delay, in seconds */
    OSPE_RELEASE release;       /* EP that released the call */
} osp_usage;

/*
 * Get OSP transaction ID from transaction handle
 * param transaction OSP transaction headle
 * return OSP transaction ID
 */
unsigned long long ospGetTransactionId(
    OSPTTRANHANDLE transaction)
{
    OSPTTRANS* context = NULL;
    unsigned long long id = 0;
    int errorcode = OSPC_ERR_NO_ERROR;

    context = OSPPTransactionGetContext(transaction, &errorcode);

    if (errorcode == OSPC_ERR_NO_ERROR) {
        id = (unsigned long long)context->TransactionID;
    } else {
        LM_ERR("failed to extract transaction_id from transaction handle %d (%d)\n",
            transaction,
            errorcode);
    }

    return id;
}

/*
 * Create a thread to report OSP usage
 * param ospvTransaction OSP transaction handle
 * param ospvReleaseCode Call release reason
 * param ospvDurating Call duration
 * param ospvStartTime Call start time
 * param ospvEndTime Call end time
 * param ospvAlertTime Call alert time
 * param ospvConnectTime Call connected  time
 * param ospvIsPDDInfoPresent If post dial delay information avaliable
 * param ospvPostDialDelay Post dial delay information, in seconds
 * param ospvReleaseSource Which side release the call
 */
void ospReportUsageWrapper(
    OSPTTRANHANDLE ospvTransaction,
    unsigned ospvReleaseCode,
    unsigned ospvDuration,
    time_t ospvStartTime,
    time_t ospvEndTime,
    time_t ospvAlertTime,
    time_t ospvConnectTime,
    unsigned ospvIsPDDInfoPresent,
    unsigned ospvPostDialDelay,
    OSPE_RELEASE ospvReleaseSource)
{
    osp_usage* usage;
    OSPTTHREADID threadid;
    OSPTTHRATTR threadattr;
    int errorcode;

    LM_DBG("schedule usage report for '%llu'\n", ospGetTransactionId(ospvTransaction));

    usage = (osp_usage*)malloc(sizeof(osp_usage));

    usage->transaction = ospvTransaction;
    usage->cause = ospvReleaseCode;
    usage->duration = ospvDuration;
    usage->start = ospvStartTime;
    usage->end = ospvEndTime;
    usage->alert = ospvAlertTime;
    usage->connect = ospvConnectTime;
    usage->haspdd = ospvIsPDDInfoPresent;
    usage->pdd = ospvPostDialDelay;
    usage->release = ospvReleaseSource;

    OSPM_THRATTR_INIT(threadattr, errorcode);

    OSPM_SETDETACHED_STATE(threadattr, errorcode);

    OSPM_CREATE_THREAD(threadid, &threadattr, ospReportUsageWork, usage, errorcode);

    OSPM_THRATTR_DESTROY(threadattr);
}

/*
 * Report OSP usage thread function
 * param usagearg OSP usage information
 * return
 */
static OSPTTHREADRETURN ospReportUsageWork(
    void* usagearg)
{
    int i;
    const int MAX_RETRIES = 5;
    osp_usage* usage;
    int errorcode;

    usage = (osp_usage*)usagearg;

    OSPPTransactionRecordFailure(
        usage->transaction,
        usage->cause);

#if 0
    OSPPTransactionSetTermCause(
        usage->transaction,
        OSPC_TCAUSE_SIP,
        usage->cause,
        NULL);
#endif

    for (i = 1; i <= MAX_RETRIES; i++) {
        errorcode = OSPPTransactionReportUsage(
            usage->transaction,
            usage->duration,
            usage->start,
            usage->end,
            usage->alert,
            usage->connect,
            usage->haspdd,
            usage->pdd * 1000,
            usage->release,
            NULL, -1, -1, -1, -1, NULL, NULL);

        if (errorcode == OSPC_ERR_NO_ERROR) {
            LM_DBG("reporte usage for '%llu'\n",
                ospGetTransactionId(usage->transaction));
            break;
        } else {
            LM_ERR("failed to report usage for '%llu' (%d) attempt '%d' of '%d'\n",
                ospGetTransactionId(usage->transaction),
                errorcode,
                i,
                MAX_RETRIES);
        }
    }

    OSPPTransactionDelete(usage->transaction);

    free(usage);

    OSPTTHREADRETURN_NULL();
}
