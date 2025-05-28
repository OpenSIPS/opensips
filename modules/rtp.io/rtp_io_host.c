/*
 * Copyright (C) 2023-2025 Sippy Software, Inc.
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
 *
 */

#include "../../sr_module.h"
#include "../../reactor_defs.h"
#include "../../reactor_proc.h"

#include "librtpproxy.h"

#include "rtp_io.h"
#include "rtp_io_host.h"
#include "rtp_io_util.h"

#if defined(__linux__)
static int optreset; /* Not present in linux */
#endif

static struct opt_save {
    char *optarg;
    int optind;
    int optopt;
    int opterr;
    int optreset;
} opt_save = {.optind = 1};

#define OPT_SAVE() (opt_save = (struct opt_save){optarg, optind, optopt, opterr, optreset})
#define OPT_RESTORE() ({ \
    optarg = opt_save.optarg; \
    optind = opt_save.optind; \
    optopt = opt_save.optopt; \
    opterr = opt_save.opterr; \
    optreset = opt_save.optreset; \
})

int *rtpp_host_process_no;

int init_rtpp_host(void)
{
    rtpp_host_process_no = shm_malloc(sizeof *rtpp_host_process_no);
    if (!rtpp_host_process_no) {
        LM_ERR("cannot allocate space for rtpp host process number\n");
        return -1;
    }
    *rtpp_host_process_no = 0;

    return 0;
}

void rtpproxy_host_process(int rank)
{
    int argc;
    const char *const *argv = rtp_io_env_gen_argv(&rpi_descp->env, &argc);
    if (argv == NULL)
        goto e1;
    if (rtp_io_close_cnlt_socks() != 0)
        goto e1;

    OPT_RESTORE();
    rpi_descp->rtpp_cfsp = rtpp_main(argc, argv);
    free((void *)argv);
    if (rpi_descp->rtpp_cfsp == NULL)
        goto e1;

    if (reactor_proc_init("rtp.io events") < 0) {
        LM_ERR("failed to init the rtp.io events\n");
        goto e1;
    }

    *rtpp_host_process_no = process_no;
    reactor_proc_loop();
    return;
e1:
    abort();
}

void
ipc_shutdown_rtpp_host(int sender, void *param)
{

    LM_DBG("shutting down rtpproxy host...\n");
    rtpp_shutdown(rpi_descp->rtpp_cfsp);
    for (int i = 0; i < (rpi_descp->socks->n * 2); i++) {
        if (rpi_descp->socks->holder[i] != -1)
            close(rpi_descp->socks->holder[i]);
    }
    free(rpi_descp->socks);
}
