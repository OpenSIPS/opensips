
#ifndef _EV_XMLRPC_H_
#define _EV_XMLRPC_H_

/* transport protocols name */
#define XMLRPC_NAME		"xmlrpc"
#define XMLRPC_STR		{ XMLRPC_NAME, sizeof(XMLRPC_NAME) - 1}

/* module flag */
#define XMLRPC_FLAG		(1 << 27)

#define COLON_C			':'

#endif

#ifdef HAVE_SCHED_YIELD
#include <sched.h>
#else
#include <unistd.h>
/** Fake sched_yield if no unistd.h include is available */
        #define sched_yield()   sleep(0)
#endif
