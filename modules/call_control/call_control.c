/*
 * Copyright (C) 2005-2019 Dan Pascu
 *
 * This file is part of OpenSIPS, a free SIP server.
 *
 * OpenSIPS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the OpenSIPS software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * OpenSIPS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../script_cb.h"
#include "../../parser/digest/digest.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../tm/tm_load.h"



#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
# define INLINE inline
#else
# define INLINE
#endif

#define CANONICAL_URI_AVP_SPEC "$avp(cc_can_uri)"
#define SIGNALING_IP_AVP_SPEC  "$avp(cc_signaling_ip)"
#define DIVERTER_AVP_SPEC      "$avp(cc_diverter)"
#define CALL_LIMIT_AVP_SPEC    "$avp(cc_call_limit)"
#define CALL_TOKEN_AVP_SPEC    "$avp(cc_call_token)"

// Although `AF_LOCAL' is mandated by POSIX.1g, `AF_UNIX' is portable to
// more systems.  `AF_UNIX' was the traditional name stemming from BSD, so
// even most POSIX systems support it.  It is also the name of choice in
// the Unix98 specification. So if there's no AF_LOCAL fallback to AF_UNIX
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

// Solaris does not have the MSG_NOSIGNAL flag for the send(2) syscall
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif


typedef int Bool;
#define True  1
#define False 0


typedef struct AVP_Param {
    str spec;
    int name;
    unsigned short type;
} AVP_Param;


typedef struct AVP_List {
    str name;
    pv_spec_p spec;
    struct AVP_List *next;
} AVP_List;


#define RETRY_INTERVAL 10
#define BUFFER_SIZE    8192


typedef struct CallControlSocket {
    char *name;             // name
    int  sock;              // socket
    int  timeout;           // how many milliseconds to wait for an answer
    time_t last_failure;    // time of the last failure
    char data[BUFFER_SIZE]; // buffer for the answer data
} CallControlSocket;


// Function prototypes
static int CallControl(struct sip_msg *msg, char *str1, char *str2);

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);

int parse_init(unsigned int type, void *val);
int parse_start(unsigned int type, void *val);
int parse_stop(unsigned int type, void *val);


// Local global variables
static CallControlSocket callcontrol_socket = {
    "/var/run/callcontrol/socket", // name
    -1,                            // sock
    500,                           // timeout in 500 milliseconds if there is no answer
    0,                             // time of the last failure
    ""                             // data
};

static int disable = False;

// The AVP where the diverter URI is stored (if defined)
static AVP_Param diverter_avp = {str_init(DIVERTER_AVP_SPEC), -1, 0};

// The AVP where the canonical URI is stored (if defined)
static AVP_Param canonical_uri_avp = {str_init(CANONICAL_URI_AVP_SPEC), -1, 0};

// The AVP where the caller signaling IP is stored (if defined)
static AVP_Param signaling_ip_avp = {str_init(SIGNALING_IP_AVP_SPEC), -1, 0};

// The AVP where the call limit is stored (if defined)
static AVP_Param call_limit_avp = {str_init(CALL_LIMIT_AVP_SPEC), -1, 0};

// The AVP where the call token is stored (if defined)
static AVP_Param call_token_avp = {str_init(CALL_TOKEN_AVP_SPEC), -1, 0};


struct dlg_binds dlg_api;
static int prepaid_account_flag = -1;
static char *prepaid_account_str = 0;

AVP_List *init_avps = NULL, *start_avps = NULL, *stop_avps = NULL;

pv_elem_t *model;


static cmd_export_t commands[] = {
    {"call_control", (cmd_function)CallControl, {{0, 0, 0}}, REQUEST_ROUTE},
    {0, 0, {{0, 0, 0}}, 0}
};


static param_export_t parameters[] = {
    {"init",                    STR_PARAM|USE_FUNC_PARAM, (void*)parse_init},
    {"start",                   STR_PARAM|USE_FUNC_PARAM, (void*)parse_start},
    {"stop",                    STR_PARAM|USE_FUNC_PARAM, (void*)parse_stop},
    {"disable",                 INT_PARAM, &disable},
    {"socket_name",             STR_PARAM, &(callcontrol_socket.name)},
    {"socket_timeout",          INT_PARAM, &(callcontrol_socket.timeout)},
    {"diverter_avp",            STR_PARAM, &(diverter_avp.spec.s)},
    {"canonical_uri_avp",       STR_PARAM, &(canonical_uri_avp.spec.s)},
    {"signaling_ip_avp",        STR_PARAM, &(signaling_ip_avp.spec.s)},
    {"call_limit_avp",          STR_PARAM, &(call_limit_avp.spec.s)},
    {"call_token_avp",          STR_PARAM, &(call_token_avp.spec.s)},
    {"prepaid_account_flag",    STR_PARAM, &prepaid_account_str},
    {0, 0, 0}
};


static dep_export_t deps = {
    // OpenSIPS module dependencies
    {
        {MOD_TYPE_DEFAULT, "dialog", DEP_ABORT},
        {MOD_TYPE_NULL, NULL, 0}
    },
    // modparam dependencies
    {
        {NULL, NULL}
    }
};


struct module_exports exports = {
    "call_control",   // module name
    MOD_TYPE_DEFAULT, // class of this module
    MODULE_VERSION,   // module version
    DEFAULT_DLFLAGS,  // dlopen flags
    NULL,             // load function
    &deps,            // module dependencies
    commands,         // exported functions
    NULL,             // exported async functions
    parameters,       // exported parameters
    NULL,             // exported statistics
    NULL,             // exported MI functions
    NULL,             // exported pseudo-variables
    NULL,             // exported transformations
    NULL,             // extra processes
    NULL,             // pre-init function
    mod_init,         // module init function (before fork. kids will inherit)
    NULL,             // reply processing function
    destroy,          // destroy function
    child_init,       // child init function
    NULL              // reload confirm function
};



typedef enum CallControlAction {
    CAInitialize = 1,
    CAStart,
    CAStop
} CallControlAction;


typedef struct CallInfo {
    CallControlAction action;
    unsigned long long dialog_id;
    str ruri;
    str diverter;
    str source_ip;
    str callid;
    str from;
    str from_tag;
    str call_token;
    char* prepaid_account;
    int call_limit;
} CallInfo;



void
destroy_list(AVP_List *avp_list)
{
    AVP_List *avp, *next;

    avp = avp_list;
    while (avp) {
        next = avp->next;
        pkg_free(avp);
        avp = next;
    }
}


int
parse_param(char *value, AVP_List **avp_list)
{
    char *ptr;
    str buffer;
    AVP_List *avp = NULL;

    ptr = value;

    while (*ptr) {
        avp = pkg_malloc(sizeof(AVP_List));
        if (!avp) {
            LM_ERR("out of private memory\n");
            return -1;
        }
        avp->next = *avp_list;
        avp->spec = pkg_malloc(sizeof(pv_spec_t));
        if (!avp->spec) {
            LM_ERR("out of private memory\n");
            pkg_free(avp);
            return -1;
        }

        while (isspace(*ptr)) ptr++;
        if (*ptr == '\0') {
            LM_ERR("malformed modparam\n");
            pkg_free(avp->spec);
            pkg_free(avp);
            return -1;
        }

        avp->name.s = ptr;

        while (isgraph(*ptr) && *ptr != '=') ptr++;
        if (*ptr == '\0') {
            LM_ERR("malformed modparam\n");
            pkg_free(avp->spec);
            pkg_free(avp);
            return -1;
        }

        avp->name.len = ptr - avp->name.s;

        while (isspace(*ptr)) ptr++;
        if (*ptr != '=') {
            LM_ERR("malformed modparam\n");
            pkg_free(avp->spec);
            pkg_free(avp);
            return -1;
        }
        ptr++;

        while (isspace(*ptr)) ptr++;

        buffer.s = ptr;
        buffer.len = strlen(ptr);

        ptr = pv_parse_spec(&buffer, avp->spec);

        if (ptr == NULL) {
            LM_ERR("malformed modparam\n");
            pkg_free(avp->spec);
            pkg_free(avp);
            return -1;
        }

        *avp_list = avp;
    }

    return 0;
}


int
parse_init(unsigned int type, void *value)
{
    if (parse_param(value, &init_avps) == -1)
        return E_CFG;
    return 0;
}


int
parse_start(unsigned int type, void *value)
{
    if (parse_param(value, &start_avps) == -1)
        return E_CFG;
    return 0;
}


int
parse_stop(unsigned int type, void *value)
{
    if (parse_param(value, &stop_avps) == -1)
        return E_CFG;
    return 0;
}



// Message checking and parsing
//

static Bool
has_to_tag(struct sip_msg *msg)
{
    str tag;

    if (!msg->to) {
        if (parse_headers(msg, HDR_TO_F, 0)==-1) {
            LM_ERR("cannot parse 'To' header\n");
            return False;
        }
        if (!msg->to) {
            LM_ERR("missing 'To' header\n");
            return False;
        }
    }

    tag = get_to(msg)->tag_value;

    if (tag.s==NULL || tag.len==0) {
        return False;
    }

    return True;
}


// Get canonical request URI
static str
get_canonical_request_uri(struct sip_msg* msg)
{
    int_str value;

    if (!search_first_avp(canonical_uri_avp.type | AVP_VAL_STR,
                          canonical_uri_avp.name, &value, NULL) ||
        value.s.s==NULL || value.s.len==0) {

        return *GET_RURI(msg);
    }

    return value.s;
}


// Get caller signaling IP
static str
get_signaling_ip(struct sip_msg* msg)
{
    int_str value;

    if (!search_first_avp(signaling_ip_avp.type | AVP_VAL_STR,
                          signaling_ip_avp.name, &value, NULL) ||
        !value.s.s || value.s.len==0) {

        value.s.s = ip_addr2a(&msg->rcv.src_ip);
        value.s.len = strlen(value.s.s);
    }

    return value.s;
}


static str
get_diverter(struct sip_msg *msg)
{
    struct hdr_field *header;
    dig_cred_t *credentials;
    int_str avpvalue;
    static str diverter;

    diverter.s   = "None";
    diverter.len = 4;

    if (search_first_avp(diverter_avp.type|AVP_VAL_STR, diverter_avp.name, &avpvalue, NULL)) {
        // have a diverted call
        diverter = avpvalue.s;
    } else {
        get_authorized_cred(msg->proxy_auth, &header);
        if (header) {
            credentials = &((auth_body_t*)(header->parsed))->digest;
        } else {
            if (parse_headers(msg, HDR_PROXYAUTH_F, 0) == -1) {
                LM_ERR("cannot parse Proxy-Authorization header\n");
                return diverter;
            }
            if (!msg->proxy_auth)
                return diverter;
            if (parse_credentials(msg->proxy_auth) != 0) {
                LM_ERR("cannot parse credentials\n");
                return diverter;
            }
            credentials = &((auth_body_t*)(msg->proxy_auth->parsed))->digest;
        }

        if (credentials->username.user.len > 0 &&
            credentials->username.domain.len > 0 &&
            credentials->realm.len == 0 &&
            credentials->nonce.len == 0 &&
            credentials->response.len == 0) {
            // this is a call diverted from the failure route
            // and sent back to proxy with append_pa_hf()
            diverter = credentials->username.whole;
        }
    }

    return diverter;
}


static int
get_call_limit(struct sip_msg* msg)
{
    int_str value;
    struct usr_avp *avp;

    avp = search_first_avp(call_limit_avp.type, call_limit_avp.name, &value, NULL);
    if (!avp)
        return 0;
    if (avp->flags & AVP_VAL_STR) {
        return atoi(value.s.s);
    } else {
        return value.n;
    }
}


static str
get_call_token(struct sip_msg* msg)
{
    int_str value;
    struct usr_avp *avp;
    static str call_token;

    call_token.s   = "None";
    call_token.len = 4;

    avp = search_first_avp(call_token_avp.type, call_token_avp.name, &value, NULL);
    if (avp) {
        if (avp->flags & AVP_VAL_STR) {
            call_token = value.s;
        } else {
            call_token.s = int2str(value.n, &call_token.len);
        }
    }
    return call_token;
}


static CallInfo*
get_call_info(struct sip_msg *msg, CallControlAction action)
{
    static CallInfo call_info;
    int headers;

    memset(&call_info, 0, sizeof(struct CallInfo));

    switch (action) {
    case CAInitialize:
        headers = HDR_CALLID_F|HDR_FROM_F;
        break;
    case CAStart:
    case CAStop:
        headers = HDR_CALLID_F;
        break;
    default:
        // Invalid action. Should never get here.
        assert(False);
        return NULL;
    }

    if (parse_headers(msg, headers, 0) == -1) {
        LM_ERR("cannot parse required headers\n");
        return NULL;
    }

    if (headers & HDR_CALLID_F) {
        if (msg->callid == NULL) {
            LM_ERR("missing Call-ID header\n");
            return NULL;
        }

        call_info.callid = msg->callid->body;
        trim(&call_info.callid);
    }

    if (headers & HDR_FROM_F) {
        struct to_body *from; // yeah. suggestive structure name ;)

        if (msg->from == NULL) {
            LM_ERR("missing From header\n");
            return NULL;
        }
        if (!msg->from->parsed && parse_from_header(msg)==-1) {
            LM_ERR("cannot parse From header\n");
            return NULL;
        }

        from = get_from(msg);

        if (from->body.s==NULL || from->body.len==0) {
            LM_ERR("missing From\n");
            return NULL;
        }
        if (from->tag_value.s==NULL || from->tag_value.len==0) {
            LM_ERR("missing From tag\n");
            return NULL;
        }

        call_info.from = from->body;
        call_info.from_tag = from->tag_value;
    }

    if (action == CAInitialize) {
        call_info.ruri = get_canonical_request_uri(msg);
        call_info.diverter = get_diverter(msg);
        call_info.source_ip = get_signaling_ip(msg);
        call_info.call_limit = get_call_limit(msg);
        call_info.call_token = get_call_token(msg);
        if (prepaid_account_flag >= 0) {
            call_info.prepaid_account = isflagset(msg, prepaid_account_flag)==1 ? "true" : "false";
        } else {
            call_info.prepaid_account = "unknown";
        }
    }

    call_info.action = action;

    return &call_info;
}


static char*
make_request(CallInfo *call)
{
    static char request[8192];
    int len;

    switch (call->action) {
    case CAInitialize:
        len = snprintf(request, sizeof(request),
                       "init\r\n"
                       "ruri: %.*s\r\n"
                       "diverter: %.*s\r\n"
                       "sourceip: %.*s\r\n"
                       "callid: %.*s\r\n"
                       "from: %.*s\r\n"
                       "fromtag: %.*s\r\n"
                       "prepaid: %s\r\n"
                       "call_limit: %d\r\n"
                       "call_token: %.*s\r\n"
                       "\r\n",
                       call->ruri.len, call->ruri.s,
                       call->diverter.len, call->diverter.s,
                       call->source_ip.len, call->source_ip.s,
                       call->callid.len, call->callid.s,
                       call->from.len, call->from.s,
                       call->from_tag.len, call->from_tag.s,
                       call->prepaid_account,
                       call->call_limit,
                       call->call_token.len, call->call_token.s);

        if (len >= sizeof(request)) {
            LM_ERR("callcontrol request is longer than %zu bytes\n", sizeof(request));
            return NULL;
        }

        break;

    case CAStart:
        len = snprintf(request, sizeof(request),
                       "start\r\n"
                       "callid: %.*s\r\n"
                       "dialogid: %llu\r\n"
                       "\r\n",
                       call->callid.len, call->callid.s, call->dialog_id);

        if (len >= sizeof(request)) {
            LM_ERR("callcontrol request is longer than %zu bytes\n", sizeof(request));
            return NULL;
        }

        break;

    case CAStop:
        len = snprintf(request, sizeof(request),
                       "stop\r\n"
                       "callid: %.*s\r\n"
                       "\r\n",
                       call->callid.len, call->callid.s);

        if (len >= sizeof(request)) {
            LM_ERR("callcontrol request is longer than %zu bytes\n", sizeof(request));
            return NULL;
        }

        break;

    default:
        // should never get here, but keep gcc from complaining
        assert(False);
        return NULL;
    }

    return request;
}


static char*
make_custom_request(struct sip_msg *msg, CallInfo *call)
{
    static char request[8192];
    AVP_List *avp_list, *avp;
    pv_value_t avp_value;
    int len = 0;

    switch (call->action) {
    case CAInitialize:
        avp_list = init_avps;
        break;
    case CAStart:
        avp_list = start_avps;
        break;
    case CAStop:
        avp_list = stop_avps;
        break;
    default:
        // should never get here, but keep gcc from complaining
        assert(False);
        return NULL;
    }

    for (avp=avp_list; avp; avp=avp->next) {
        if (pv_get_spec_value(msg, avp->spec, &avp_value) < 0) {
            LM_ERR("cannot get the spec's value!\n");
            return NULL;
        }
        if (avp_value.flags & PV_VAL_INT) {
            len += snprintf(request + len, sizeof(request) - len - 1,
                            "%.*s = %d ", avp->name.len, avp->name.s, avp_value.ri);
        } else if (avp_value.flags & PV_VAL_STR) {
            len += snprintf(request + len, sizeof(request) - len - 1,
                            "%.*s = %.*s ", avp->name.len, avp->name.s, avp_value.rs.len, avp_value.rs.s);
        }

        if (len >= sizeof(request)) {
            LM_ERR("callcontrol request is longer than %zu bytes\n", sizeof(request));
            return NULL;
        }
    }

    return request;
}


// Functions dealing with the external call_control helper
//

static Bool
callcontrol_connect(void)
{
    struct sockaddr_un addr;

    if (callcontrol_socket.sock >= 0)
        return True;

    if (callcontrol_socket.last_failure + RETRY_INTERVAL > time(NULL))
        return False;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, callcontrol_socket.name, sizeof(addr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SA_LEN
    addr.sun_len = strlen(addr.sun_path);
#endif

    callcontrol_socket.sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (callcontrol_socket.sock < 0) {
        LM_ERR("can't create socket\n");
        callcontrol_socket.last_failure = time(NULL);
        return False;
    }
    if (connect(callcontrol_socket.sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LM_ERR("failed to connect to %s: %s\n", callcontrol_socket.name, strerror(errno));
        close(callcontrol_socket.sock);
        callcontrol_socket.sock = -1;
        callcontrol_socket.last_failure = time(NULL);
        return False;
    }

    return True;
}

static void
callcontrol_disconnect(void)
{
    if (callcontrol_socket.sock < 0)
        return;

    close(callcontrol_socket.sock);
    callcontrol_socket.sock = -1;
    callcontrol_socket.last_failure = time(NULL);
}

static char*
send_command(char *command)
{
    int cmd_len, bytes, tries, sent, received, count;
    struct timeval timeout;
    fd_set rset;

    if (!callcontrol_connect())
        return NULL;

    cmd_len = strlen(command);

    for (sent=0, tries=0; sent<cmd_len && tries<3; tries++, sent+=bytes) {
        do
            bytes = send(callcontrol_socket.sock, command+sent, cmd_len-sent, MSG_DONTWAIT|MSG_NOSIGNAL);
        while (bytes == -1 && errno == EINTR);
        if (bytes == -1) {
            switch (errno) {
            case ECONNRESET:
            case EPIPE:
                callcontrol_disconnect();
                callcontrol_socket.last_failure = 0; // we want to reconnect immediately
                if (callcontrol_connect()) {
                    sent = bytes = 0;
                    continue;
                } else {
                    LM_ERR("connection with callcontrol did die\n");
                }
                break;
            case EACCES:
                LM_ERR("permission denied sending to %s\n", callcontrol_socket.name);
                break;
            case EWOULDBLOCK:
                // this shouldn't happen as we read back all the answer after a request.
                // if it would block, it means there is an error.
                LM_ERR("sending command would block!\n");
                break;
            default:
                LM_ERR("%d: %s\n", errno, strerror(errno));
                break;
            }
            callcontrol_disconnect();
            return NULL;
        }
    }
    if (sent < cmd_len) {
        LM_ERR("couldn't send complete command after 3 tries\n");
        callcontrol_disconnect();
        return NULL;
    }

    callcontrol_socket.data[0] = 0;
    received = 0;
    while (True) {
        FD_ZERO(&rset);
        FD_SET(callcontrol_socket.sock, &rset);
        timeout.tv_sec = callcontrol_socket.timeout / 1000;
        timeout.tv_usec = (callcontrol_socket.timeout % 1000) * 1000;

        do
            count = select(callcontrol_socket.sock + 1, &rset, NULL, NULL, &timeout);
        while (count == -1 && errno == EINTR);

        if (count == -1) {
            LM_ERR("select failed: %d: %s\n", errno, strerror(errno));
            callcontrol_disconnect();
            return NULL;
        } else if (count == 0) {
            LM_ERR("did timeout waiting for an answer\n");
            callcontrol_disconnect();
            return NULL;
        } else {
            do
                bytes = recv(callcontrol_socket.sock, callcontrol_socket.data+received, BUFFER_SIZE-1-received, 0);
            while (bytes == -1 && errno == EINTR);
            if (bytes == -1) {
                LM_ERR("failed to read answer: %d: %s\n", errno, strerror(errno));
                callcontrol_disconnect();
                return NULL;
            } else if (bytes == 0) {
                LM_ERR("connection with callcontrol closed\n");
                callcontrol_disconnect();
                return NULL;
            } else {
                callcontrol_socket.data[received+bytes] = 0;
                if (strstr(callcontrol_socket.data+received, "\r\n")!=NULL) {
                    break;
                }
                received += bytes;
            }
        }
    }

    return callcontrol_socket.data;
}


// Call control processing
//

// Return codes:
//   2 - No limit
//   1 - Limited
//  -1 - No credit
//  -2 - Locked
//  -3 - Duplicated callid
//  -4 - Call limit reached
//  -5 - Internal error (message parsing, communication, ...)
static int
call_control_initialize(struct sip_msg *msg)
{
    CallInfo *call;
    char *message, *result = NULL;


    call = get_call_info(msg, CAInitialize);
    if (!call) {
        LM_ERR("can't retrieve call info\n");
        return -5;
    }


    if (!init_avps)
        message = make_request(call);
    else
        message = make_custom_request(msg, call);

    if (!message)
        return -5;

   result = send_command(message);

    if (result==NULL) {
        return -5;
    } else if (strcasecmp(result, "No limit\r\n")==0) {
        return 2;
    } else if (strcasecmp(result, "Limited\r\n")==0) {
        return 1;
    } else if (strcasecmp(result, "No credit\r\n")==0) {
        return -1;
    } else if (strcasecmp(result, "Locked\r\n")==0) {
        return -2;
    } else if (strcasecmp(result, "Duplicated callid\r\n")==0) {
        return -3;
    } else if (strcasecmp(result, "Call limit reached\r\n")==0) {
        return -4;
    } else {
        return -5;
    }
}


// Called during a dialog for start and update requests
//
// Return codes:
//   1 - Ok
//  -1 - Session not found
//  -5 - Internal error (message parsing, communication, ...)
static int
call_control_start(struct sip_msg *msg, struct dlg_cell *dlg)
{
    CallInfo *call;
    char *message, *result;

    call = get_call_info(msg, CAStart);
    if (!call) {
        LM_ERR("can't retrieve call info\n");
        return -5;
    }

    call->dialog_id = (unsigned long long) dlg->h_entry << 32 | dlg->h_id;

    if (!start_avps)
        message = make_request(call);
    else
        message = make_custom_request(msg, call);

    if (!message)
        return -5;

    result = send_command(message);

    if (result==NULL) {
        return -5;
    } else if (strcasecmp(result, "Ok\r\n")==0) {
        return 1;
    } else if (strcasecmp(result, "Not found\r\n")==0) {
        return -1;
    } else {
        return -5;
    }
}


// Called during a dialog ending to stop callcontrol
//
// Return codes:
//   1 - Ok
//  -1 - Session not found
//  -5 - Internal error (message parsing, communication, ...)
static int
call_control_stop(struct sip_msg *msg, str callid)
{
    CallInfo call;
    char *message, *result;

    call.action = CAStop;
    call.callid = callid;

    if (!stop_avps)
        message = make_request(&call);
    else
        message = make_custom_request(msg, &call);

    if (!message)
        return -5;

    result = send_command(message);

    if (result==NULL) {
        return -5;
    } else if (strcasecmp(result, "Ok\r\n")==0) {
        return 1;
    } else if (strcasecmp(result, "Not found\r\n")==0) {
        return -1;
    } else {
        return -5;
    }
}


// Dialog callbacks and helpers
//

typedef enum {
    CCInactive = 0,
    CCActive
} CallControlState;


static void
__dialog_replies(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
    struct sip_msg *reply = _params->msg;

    if (reply!=FAKED_REPLY && reply->REPLY_STATUS==200) {
        call_control_start(reply, dlg);
    }
}


static void
__dialog_ended(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
    if ((int)(long)*_params->param == CCActive) {
        call_control_stop(_params->msg, dlg->callid);
        *_params->param = (void *)CCInactive;
    }
}


static void
__dialog_loaded(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
    if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, __dialog_replies, NULL, NULL) != 0)
        LM_ERR("cannot register callback for dialog confirmation\n");
    if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_FAILED | DLGCB_EXPIRED | DLGCB_DESTROY, __dialog_ended, (void*)CCActive, NULL) != 0)
        LM_ERR("cannot register callback for dialog termination\n");
}


// Public API
//

// Return codes:
//   2 - No limit
//   1 - Limited
//  -1 - No credit
//  -2 - Locked
//  -3 - Duplicated callid
//  -4 - Call limit reached
//  -5 - Internal error (message parsing, communication, ...)
static int
CallControl(struct sip_msg *msg, char *str1, char *str2)
{
    int result;
    struct dlg_cell *dlg;
    CallInfo *call;

    if (disable)
        return 2;

    if (msg->first_line.type!=SIP_REQUEST || msg->REQ_METHOD!=METHOD_INVITE || has_to_tag(msg)) {
        LM_WARN("call_control should only be called for the first INVITE\n");
        return -5;
    }

    result = call_control_initialize(msg);
    if (result == 1) {
        // A call with a time limit that will be traced by callcontrol

        if (dlg_api.create_dlg(msg, 0) < 0) {
            LM_ERR("could not create new dialog\n");
            call = get_call_info(msg, CAStop);
            if (!call) {
                LM_ERR("can't retrieve call info\n");
                return -5;
            }
            call_control_stop(msg, call->callid);
            return -5;
        }

        dlg = dlg_api.get_dlg();
        if (!dlg) {
            LM_CRIT("error getting dialog\n");
            call = get_call_info(msg, CAStop);
            if (!call) {
                LM_ERR("can't retrieve call info\n");
                return -5;
            }
            call_control_stop(msg, call->callid);
            return -5;
        }

        if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, __dialog_replies, NULL, NULL) != 0) {
            LM_ERR("cannot register callback for dialog confirmation\n");
            call_control_stop(msg, dlg->callid);
            return -5;
        }

        if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_FAILED | DLGCB_EXPIRED | DLGCB_DESTROY, __dialog_ended, (void*)CCActive, NULL) != 0) {
            LM_ERR("cannot register callback for dialog termination\n");
            call_control_stop(msg, dlg->callid);
            return -5;
        }

    }

    return result;
}


// Module management: initialization/destroy/function-parameter-fixing/...
//

static int
mod_init(void)
{
    pv_spec_t avp_spec;

    // initialize the canonical_uri_avp structure
    if (canonical_uri_avp.spec.s==NULL || *(canonical_uri_avp.spec.s)==0) {
        LM_ERR("missing/empty canonical_uri_avp parameter. using default.\n");
        canonical_uri_avp.spec.s = CANONICAL_URI_AVP_SPEC;
    }
    canonical_uri_avp.spec.len = strlen(canonical_uri_avp.spec.s);
    if (pv_parse_spec(&(canonical_uri_avp.spec), &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
        LM_CRIT("invalid AVP specification for canonical_uri_avp: `%s'\n", canonical_uri_avp.spec.s);
        return -1;
    }
    if (pv_get_avp_name(0, &(avp_spec.pvp), &(canonical_uri_avp.name), &(canonical_uri_avp.type))!=0) {
        LM_CRIT("invalid AVP specification for canonical_uri_avp: `%s'\n", canonical_uri_avp.spec.s);
        return -1;
    }

    // initialize the signaling_ip_avp structure
    if (signaling_ip_avp.spec.s==NULL || *(signaling_ip_avp.spec.s)==0) {
        LM_ERR("missing/empty signaling_ip_avp parameter. using default.\n");
        signaling_ip_avp.spec.s = SIGNALING_IP_AVP_SPEC;
    }
    signaling_ip_avp.spec.len = strlen(signaling_ip_avp.spec.s);
    if (pv_parse_spec(&(signaling_ip_avp.spec), &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
        LM_CRIT("invalid AVP specification for signaling_ip_avp: `%s'\n", signaling_ip_avp.spec.s);
        return -1;
    }
    if (pv_get_avp_name(0, &(avp_spec.pvp), &(signaling_ip_avp.name), &(signaling_ip_avp.type))!=0) {
        LM_CRIT("invalid AVP specification for signaling_ip_avp: `%s'\n", signaling_ip_avp.spec.s);
        return -1;
    }

    // initialize the call_limit_avp structure
    if (call_limit_avp.spec.s==NULL || *(call_limit_avp.spec.s)==0) {
        LM_ERR("missing/empty call_limit_avp parameter. using default.\n");
        call_limit_avp.spec.s = CALL_LIMIT_AVP_SPEC;
    }
    call_limit_avp.spec.len = strlen(call_limit_avp.spec.s);
    if (pv_parse_spec(&(call_limit_avp.spec), &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
        LM_CRIT("invalid AVP specification for call_limit_avp: `%s'\n", call_limit_avp.spec.s);
        return -1;
    }
    if (pv_get_avp_name(0, &(avp_spec.pvp), &(call_limit_avp.name), &(call_limit_avp.type))!=0) {
        LM_CRIT("invalid AVP specification for call_limit_avp: `%s'\n", call_limit_avp.spec.s);
        return -1;
    }

    // initialize the call_token_avp structure
    if (call_token_avp.spec.s==NULL || *(call_token_avp.spec.s)==0) {
        LM_ERR("missing/empty call_token_avp parameter. using default.\n");
        call_token_avp.spec.s = CALL_TOKEN_AVP_SPEC;
    }
    call_token_avp.spec.len = strlen(call_token_avp.spec.s);
    if (pv_parse_spec(&(call_token_avp.spec), &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
        LM_CRIT("invalid AVP specification for call_token_avp: `%s'\n", call_token_avp.spec.s);
        return -1;
    }
    if (pv_get_avp_name(0, &(avp_spec.pvp), &(call_token_avp.name), &(call_token_avp.type))!=0) {
        LM_CRIT("invalid AVP specification for call_token_avp: `%s'\n", call_token_avp.spec.s);
        return -1;
    }

    // initialize the diverter_avp structure
    if (diverter_avp.spec.s==NULL || *(diverter_avp.spec.s)==0) {
        LM_ERR("missing/empty diverter_avp parameter. using default.\n");
        diverter_avp.spec.s = DIVERTER_AVP_SPEC;
    }
    diverter_avp.spec.len = strlen(diverter_avp.spec.s);
    if (pv_parse_spec(&(diverter_avp.spec), &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
        LM_CRIT("invalid AVP specification for diverter_avp: `%s'\n", diverter_avp.spec.s);
        return -1;
    }
    if (pv_get_avp_name(0, &(avp_spec.pvp), &(diverter_avp.name), &(diverter_avp.type))!=0) {
        LM_CRIT("invalid AVP specification for diverter_avp: `%s'\n", diverter_avp.spec.s);
        return -1;
    }

    // bind to the dialog API
    if (load_dlg_api(&dlg_api)!=0) {
        LM_CRIT("cannot load the dialog module API\n");
        return -1;
    }

    // register dialog loading callback
    if (dlg_api.register_dlgcb(NULL, DLGCB_LOADED, __dialog_loaded, NULL, NULL) != 0) {
        LM_CRIT("cannot register callback for dialogs loaded from the database\n");
    }

    prepaid_account_flag = get_flag_id_by_name(FLAG_TYPE_MSG,
        prepaid_account_str, 0);

    return 0;
}


static int
child_init(int rank)
{
    // initialize the connection to callcontrol if needed
    if (!disable)
        callcontrol_connect();

    return 0;
}


static void
destroy(void)
{
    if (init_avps)
        destroy_list(init_avps);

    if (start_avps)
        destroy_list(start_avps);

    if (stop_avps)
        destroy_list(stop_avps);
}


