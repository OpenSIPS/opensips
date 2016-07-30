/*
 * mangler module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * History:
 * --------
 *  2003-04-07 first version.
 */




#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../error.h"


#include "mangler.h"
#include "sdp_mangler.h"
#include "contact_ops.h"
#include "utils.h"
#include "common.h"

#ifdef DEMO

#include "../tm/t_hooks.h"
#include "../tm/tm_load.h"
#include "../tm/h_table.h"
struct tm_binds tmb;

#endif





/*
 * Module destroy function prototype
 */
static void destroy (void);



/*
 * Module initialization function prototype
 */
static int mod_init (void);


char *contact_flds_separator = DEFAULT_SEPARATOR;



static param_export_t params[] = {
	{"contact_flds_separator",STR_PARAM,&contact_flds_separator},
	{0, 0, 0}
};	/* perhaps I should add pre-compiled expressions */



/*
 * Exported functions
 */
static cmd_export_t cmds[] =
{
	{"sdp_mangle_ip",   (cmd_function)sdp_mangle_ip, 2,0, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"sdp_mangle_port", (cmd_function)sdp_mangle_port, 1,0, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"encode_contact",  (cmd_function)encode_contact,2,0, 0, REQUEST_ROUTE|ONREPLY_ROUTE},
	{"decode_contact",  (cmd_function)decode_contact,0,0, 0, REQUEST_ROUTE},
	{"decode_contact_header", (cmd_function)decode_contact_header,0,0,0,REQUEST_ROUTE|ONREPLY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Module interface
 */
struct module_exports exports = {
	"mangler",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,			/* Exported functions */
	0,				/* Exported async functions */
	params,			/* Exported parameters */
	0,				/* exported statistics */
	0,				/* exported MI functions */
	0,              /* exported pseudo-variables */
	0,              /* extra processes */
	mod_init,		/* module initialization function */
	0,				/* response function */
	destroy,		/* destroy function */
	0				/* child initialization function */
};


#ifdef DEMO
/* MANGLING EXAMPLE */
/* ================================================================= */
static void func_invite(struct cell *t,struct sip_msg *msg,int code,void *param)
{
	int i;
	//callback function
	if (!check_transaction_quadruple(msg))
		{
		//we do not have a correct message from/callid/cseq/to
		return;
		}
	i = encode_contact(msg,"enc_prefix","193.175.135.38");
	fprintf(stdout,"decode/encode = returned %d\n",i);fflush(stdout);

	if (t->is_invite)
		{
			if (msg->buf != NULL)
			{
			fprintf(stdout,"INVITE:received \n%s\n",msg->buf);fflush(stdout);
			i = sdp_mangle_port(msg,"1000",NULL);
			fprintf(stdout,"sdp_mangle_port returned %d\n",i);fflush(stdout);
			i = sdp_mangle_ip(msg,"10.0.0.0/16","123.124.125.126");
			fprintf(stdout,"sdp_mangle_ip returned %d\n",i);fflush(stdout);

			}
			else fprintf(stdout,"INVITE:received NULL\n");fflush(stdout);
		}
	else
		{
			fprintf(stdout,"NOT INVITE(REGISTER?) received \n%s\n",msg->buf);fflush(stdout);
			//i = decode_contact(msg,NULL,NULL);
			//fprintf(stdout,"decode/encode = returned %d\n",i);fflush(stdout);
		}
	fflush(stdout);
}

#endif


int prepare (void)
{

	/* using pre-compiled expressions to speed things up*/
	compile_expresions(PORT_REGEX,IP_REGEX);

#ifdef DEMO
	fprintf(stdout,"===============NEW RUN================\n");

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	//register callbacks
	if (tmb.register_tmcb(TMCB_REQUEST_OUT,func_invite,0) <= 0) return -1;
#endif
	return 0;
}



static int mod_init (void)
{
	ipExpression = NULL;
	portExpression = NULL;
	prepare ();
	/*
	 * Might consider to compile at load time some regex to avoid compilation
	 * every time I use this functions
	 */
	return 0;
}


static void destroy (void)
{
	/*free some compiled regex expressions */
	free_compiled_expresions();
#ifdef DEMO
	fprintf(stdout,"Freeing pre-compiled expressions\n");
#endif

	return;
}
