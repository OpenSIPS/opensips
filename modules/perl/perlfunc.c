/*
 * Perl module for OpenSIPS
 *
 * Copyright (C) 2006 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
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

#include <string.h>
#include <stdio.h>

#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../parser/parse_param.h"
#include "../../parser/msg_parser.h"
#include "../../dprint.h"
#include "../../action.h"
#include "../../config.h"
#include "../../parser/parse_uri.h"
#include "../../mod_fix.h"

#include "perlfunc.h"
#include "perl.h"


/*
 * Check for existence of a function.
 */
int perl_checkfnc(char *fnc) {

	if (get_cv(fnc, 0)) {
		return 1;
	} else {
		return 0;
	}
}


int perl_exec_simple(struct sip_msg* _msg, str *_fnc_s, str *_param_s)
{
	char *fnc;
	char* args[2] = {NULL, NULL};
	int flags = G_DISCARD | G_EVAL;
	int ret;

	if (_param_s) {
		args[0] = pkg_malloc(_param_s->len+1);
		if (!args[0]) {
			LM_ERR("No more pkg mem!\n");
			return -1;
		}
		memcpy(args[0], _param_s->s, _param_s->len);
		args[0][_param_s->len] = 0;
	} else
		flags |= G_NOARGS;

	fnc = pkg_malloc(_fnc_s->len);
	if (!fnc) {
		LM_ERR("No more pkg mem!\n");
		return -1;
	}
	memcpy(fnc, _fnc_s->s, _fnc_s->len);
	fnc[_fnc_s->len] = 0;

	if (perl_checkfnc(fnc)) {
		LM_DBG("running perl function \"%s\"\n", fnc);

		call_argv(fnc, flags, args);
		ret = 1;
	} else {
		LM_ERR("unknown function '%s' called.\n", fnc);
		ret = -1;
	}

	if (_param_s)
		pkg_free(args[0]);
	pkg_free(fnc);

	return ret;
}

/*
 * Run function, with current SIP message as a parameter
 */
int perl_exec(struct sip_msg* _msg, str* _fnc_s, str* mystr)
{
	int retval;
	SV *m;
	str reason;
	str pfnc, pparam;
	char *fnc;

	fnc = pkg_malloc(_fnc_s->len);
	if (!fnc) {
		LM_ERR("No more pkg mem!\n");
		return -1;
	}
	memcpy(fnc, _fnc_s->s, _fnc_s->len);
	fnc[_fnc_s->len] = 0;

	dSP;

	if (!perl_checkfnc(fnc)) {
		LM_ERR("unknown perl function called.\n");
		reason.s = "Internal error";
		reason.len = sizeof("Internal error")-1;
		if (sigb.reply(_msg, 500, &reason, NULL) == -1)
		{
			LM_ERR("failed to send reply\n");
		}
		goto error;
	}

	switch ((_msg->first_line).type) {
	case SIP_REQUEST:
		if (parse_sip_msg_uri(_msg) < 0) {
			LM_ERR("failed to parse Request-URI\n");

			reason.s = "Bad Request-URI";
			reason.len = sizeof("Bad Request-URI")-1;
			if (sigb.reply(_msg, 400, &reason, NULL) == -1) {
				LM_ERR("failed to send reply\n");
			}
			goto error;
		}
		break;
	case SIP_REPLY:
		break;
	default:
		LM_ERR("invalid firstline\n");
		goto error;
	}



	ENTER;				/* everything created after here */
	SAVETMPS;			/* ...is a temporary variable.   */
	PUSHMARK(SP);			/* remember the stack pointer    */

	m = sv_newmortal();		/* create a mortal SV to be killed on FREETMPS */
	sv_setref_pv(m, "OpenSIPS::Message", (void *)_msg); /* bless the message with a class */
	SvREADONLY_on(SvRV(m));		/* set the content of m to be readonly  */

	XPUSHs(m);			/* Our reference to the stack... */

	if (mystr)
		XPUSHs(sv_2mortal(newSVpv(mystr->s, mystr->len)));
		/* Our string to the stack... */

	PUTBACK;			/* make local stack pointer global */

	call_pv(fnc, G_EVAL|G_SCALAR);		/* call the function     */
	SPAGAIN;			/* refresh stack pointer         */
	/* pop the return value from stack */
	retval = POPi;

	PUTBACK;
	FREETMPS;			/* free that return value        */
	LEAVE;				/* ...and the XPUSHed "mortal" args.*/
	return retval;

error:
	pkg_free(fnc);
	return -1;
}
