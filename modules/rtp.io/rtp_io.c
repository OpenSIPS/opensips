/*
 * Copyright (C) 2023 Sippy Software, Inc.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../mod_fix.h"
#include "../../pt.h"
#include "../../dprint.h"

#include "librtpproxy.h"

#include "rtp_io.h"
#include "rtp_io_util.h"
#include "rtp_io_params.h"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static const dep_export_t deps = {
    { /* OpenSIPS module dependencies */
        { MOD_TYPE_DEFAULT, "rtpproxy", DEP_SILENT|DEP_REVERSE },
        { MOD_TYPE_NULL, NULL, 0 },
    },
};

static int rtp_io_getchildsock(int);

/*
 * Exported functions
 */
static const cmd_export_t cmds[] = {
    {"rtp_io_getchildsock", (cmd_function)rtp_io_getchildsock, {0}, 0},
    {0}
};

/*
 * Exported params
 */
static const param_export_t params[] = {
    {"rtpproxy_args",       STR_PARAM|USE_FUNC_PARAM, (void*)rio_set_rtpp_args},
    {0}
};

struct module_exports exports= {
    "rtp.io",        /* module's name */
    MOD_TYPE_DEFAULT,/* class of this module */
    MODULE_VERSION,
    DEFAULT_DLFLAGS, /* dlopen flags */
    0,		 /* load function */
    &deps,           /* OpenSIPS module dependencies */
    cmds,            /* exported functions */
    0,               /* exported async functions */
    params,      	 /* param exports */
    0,       	 /* exported statistics */
    0,         	 /* exported MI functions */
    NULL,       	 /* exported pseudo-variables */
    0,		 /* exported transformations */
    0,               /* extra processes */
    0,        	 /* module pre-initialization function */
    mod_init,        /* module initialization function */
    0,               /* reply processing function */
    mod_destroy,
    child_init,      /* per-child init function */
    0
};

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

#define howmany(x, y) (sizeof(x) / sizeof(y))

static struct rtpp_env argv0 = {.cp = "rtpproxy"};

static struct rtp_io_desc rpi_desc = {
    .env = {.len = 1, .first = &argv0, .last = &argv0},
};

struct rtp_io_desc *rpi_descp = &rpi_desc;

#define ENV_ADD(x, elabel, ...) { \
    struct rtpp_env *_e = rtp_io_env_asprintf((x), ##__VA_ARGS__); \
    if (_e == NULL) \
        goto elabel; \
    rtp_io_env_append(&rpi_descp->env, _e); \
}

static int
rio_socks_init(int nsocks)
{
    size_t asize;
    struct rtp_io_socks *socks;

    LM_DBG("allocating %s(%d)\n", exports.name, nsocks);

    asize = sizeof(struct rtp_io_socks) + (nsocks * sizeof(int) * 2);
    socks = malloc(asize);
    if (socks == NULL)
        goto e0;

    memset(socks, '\0', asize);
    rpi_descp->socks = socks;
    return 0;
e0:
    return -1;
}

static int mod_init(void)
{
    int nsocks;
    const char * const argv_stat[] = {
        "-d", "err",
        "-n", "tcp:127.0.0.1:9642",
        "--dso", "catch_dtmf",
        "--dso", "dtls_gw",
        "--dso", "ice_lite",
    };

    nsocks = count_child_processes();

    if (nsocks <= 1)
        goto e0;

    LM_DBG("initializing %s(%d)\n", exports.name, nsocks);

    if (rio_socks_init(nsocks) != 0)
        goto e0;

    for (int i = 0; i < howmany(argv_stat, *argv_stat); i++) {
        ENV_ADD(argv_stat[i], e1);
    }

    for (int i = 0; i < nsocks; i++) {
        int *fdp = &rpi_descp->socks->holder[i * 2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdp) < 0)
            goto e1;
        ENV_ADD("-s", e1);
        ENV_ADD("fd:%d", e1, fdp[0]);
    }


    int argc;
    const char *const *argv = rtp_io_env_gen_argv(&rpi_descp->env, &argc);
    if (argv == NULL)
        goto e1;

    OPT_RESTORE();
    rpi_descp->rtpp_cfsp = rtpp_main(argc, argv);
    free((void *)argv);
    if (rpi_descp->rtpp_cfsp == NULL)
        goto e1;

    rpi_descp->socks->n = nsocks;

    return 0;
e1:
    free(rpi_descp->socks);
e0:
    return -1;
}

void mod_destroy(void)
{
    struct rtpp_env *enext;

    LM_DBG("cleaning up %s...\n", exports.name);
    rtpp_shutdown(rpi_descp->rtpp_cfsp);
    for (const struct rtpp_env *e = rpi_descp->env.first; e != NULL; e = enext) {
        enext = e->next;
        if (e->atype == env_heap)
            free(e->_cp);
        if (e == &argv0)
            continue;
        free((void *)e);
    }
    for (int i = 0; i < (rpi_descp->socks->n * 2); i++) {
        if (rpi_descp->socks->holder[i] != -1)
            close(rpi_descp->socks->holder[i]);
    }
    free(rpi_descp->socks);
}

#include <assert.h>

static int
child_init(int rank)
{

    if (rank < 0)
        return 0;

    for (int i = 0; i < rpi_descp->socks->n; i++) {
        int *fdp = &rpi_descp->socks->holder[i * 2];
        if (close(fdp[0]) < 0)
	    return (-1);
        fdp[0] = -1;
        if (i == rank - 1)
	    continue;
        if (close(fdp[1]) < 0)
	    return (-1);
        fdp[1] = -1;
    }

    return (0);
}

static int rtp_io_getchildsock(int rank)
{

    if (rank < 1 || rank > rpi_descp->socks->n)
        return (-1);

    int *fdp = &rpi_descp->socks->holder[(rank - 1) * 2];
    return (fdp[1]);
}
