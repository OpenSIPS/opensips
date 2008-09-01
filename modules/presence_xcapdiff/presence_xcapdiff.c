#include "../presence/bind_presence.h"
#include "../pua/pua_bind.h"

MODULE_VERSION

str s_event_name = str_init("xcap-diff");
str s_content_type = str_init("application/xcap-diff+xml");

static int mod_init(void);
static int child_init(int);
static void destroy(void);

static cmd_export_t cmds[] =
{
    {0, 0, 0, 0, 0, 0}
};

int enable_presence = 1;
int enable_pua = 1;

static param_export_t params[] = {
    { "enable_presence", INT_PARAM, &enable_presence },
    { "enable_pua",      INT_PARAM, &enable_pua },
    {0, 0, 0}
};

struct module_exports exports= {
    "presence_xcapdiff",        /* module name */
    DEFAULT_DLFLAGS,            /* dlopen flags */
    cmds,                       /* exported functions */
    params,                     /* exported parameters */
    0,                          /* exported statistics */
    0,                          /* exported MI functions */
    0,                          /* exported pseudo-variables */
    0,                          /* extra processes */
    mod_init,                   /* module initialization function */
    (response_function) 0,      /* response handling function */
    destroy,                    /* destroy function */
    child_init                  /* per-child init function */ //perhaps should be NULL?
};

int xcapdiff_process_body(publ_info_t* publ, str** fin_body, int ver, str** tuple)
{
	*fin_body= publ->body;
	return 0;
}

static int mod_init(void)
{
    LM_INFO("initializing...\n");

    if (enable_presence)
    {
        bind_presence_t bind_presence;
        presence_api_t pres;

        bind_presence= (bind_presence_t)find_export("bind_presence", 1,0);
        if (!bind_presence) {
            LM_ERR("find_export(\"bind_presence\") failed\n");
            return -1;
        }

        if (bind_presence(&pres) < 0) {
            LM_ERR("bind_presence failed\n");
            return -1;
        }

        pres_ev_t event;

        memset(&event, 0, sizeof(pres_ev_t));
        event.name = s_event_name;
        event.content_type = s_content_type;
        event.default_expires= 3600;
        event.type = PUBL_TYPE;
        event.req_auth = 0;

        if (pres.add_event(&event) < 0) {
            LM_ERR("pres.add_event(\"xcap-diff\")\n");
            return -1;
        }
    }

    if (enable_pua)
    {
        bind_pua_t bind_pua = (bind_pua_t)find_export("bind_pua", 1,0);
        if (!bind_pua)
        {
            LM_ERR("find_export(\"bind_pua\", 1,0) failed\n");
            return -1;
        }

        pua_api_t pua;
        if (bind_pua(&pua) < 0)
        {
            LM_ERR("bind_pua() failed\n");
            return -1;
        }

        if(pua.add_event(XCAPDIFF_EVENT, s_event_name.s, s_content_type.s, xcapdiff_process_body)< 0)
        {
            LM_ERR("pua.add_event(XCAPDIFF_EVENT) failed\n");
            return -1;
        }
    }

    return 0;
}

static int child_init(int rank)
{
    LM_DBG("[%d] pid [%d]\n", rank, getpid());

    return 0;
}

static void destroy(void)
{
    LM_DBG("destroying module ...\n");

    return;
}
