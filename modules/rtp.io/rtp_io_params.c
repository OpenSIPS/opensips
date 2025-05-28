#include <ctype.h>
#include <string.h>

#include "../../sr_module.h"

#include "rtp_io.h"
#include "rtp_io_util.h"
#include "rtp_io_params.h"

int
rio_set_rtpp_args(modparam_t type, void *val)
{
    char * p;

    p = (char *)val;


    if (p == NULL || *p == '\0') {
        return 0;
    }
    do {
        char *ep = strchr(p, ' ');
        if (ep != NULL) {
            *ep = '\0';
        }
        struct rtpp_env *rep = rtp_io_env_strref(p);
        if (rep == NULL) {
            return -1;
        }
        rtp_io_env_append(&rpi_descp->env, rep);
        if (ep == NULL)
            break;
        p = ep + 1;
        while (isspace(*p))
            p++;
    } while (*p != '\0');
    return 0;
}
