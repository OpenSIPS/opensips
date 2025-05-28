#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../dprint.h"

#include "rtp_io.h"
#include "rtp_io_util.h"

struct rtpp_env *
rtp_io_env_asprintf(const char *format, ...)
{
    va_list ap;
    int rc;
    char *cp;

    va_start(ap, format);
    rc = vasprintf(&cp, format, ap);
    va_end(ap);
    if (rc < 0)
        goto e0;
    struct rtpp_env *rep = rtp_io_env_strref(cp);
    if (rep != NULL) {
        rep->atype = env_heap;
    } else {
        free(cp);
    }
    return rep;
e0:
    return (NULL);
}

struct rtpp_env *
rtp_io_env_strref(const char *cp)
{
    struct rtpp_env *rep;

    rep = malloc(sizeof(struct rtpp_env));
    if (rep == NULL)
        goto e0;
    memset(rep, '\0', sizeof(struct rtpp_env));
    rep->cp = cp;
    return (rep);
e0:
    return (NULL);
}

void
rtp_io_env_append(struct rtpp_env_hd *ecp, struct rtpp_env *ep)
{
    if (ecp->first == NULL) {
        ecp->last = ecp->first = ep;
    } else {
        ecp->_last->next = ep;
        ecp->last = ep;
    }
    ecp->len += 1;
}

const char *const *
rtp_io_env_gen_argv(struct rtpp_env_hd *ecp, int *lenp)
{
    const char **rval;
    const struct rtpp_env *ep;

    size_t asize = ecp->len * sizeof(rval[0]);
    rval = malloc(asize);
    if (rval == NULL)
        return (NULL);
    memset(rval, '\0', asize);
    ep = ecp->first;
    for (int i = 0; i < ecp->len; i++) {
        rval[i] = ep->cp;
        ep = ep->next;
    }
    *lenp = ecp->len;
    return (const char *const *)rval;
}

int rtp_io_close_serv_socks(void)
{

    for (int i = 0; i < (rpi_descp->socks->n * 2); i+=2) {
        if (rpi_descp->socks->holder[i] != -1) {
            close(rpi_descp->socks->holder[i]);
            rpi_descp->socks->holder[i] = -1;
        }
    }
    return (0);
}

int rtp_io_close_cnlt_socks(void)
{

    for (int i = 0; i < (rpi_descp->socks->n * 2); i+=2) {
        if (rpi_descp->socks->holder[i+1] != -1) {
            close(rpi_descp->socks->holder[i+1]);
            rpi_descp->socks->holder[i+1] = -1;
        }
    }
    return (0);
}
