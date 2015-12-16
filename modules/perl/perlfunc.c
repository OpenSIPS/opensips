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



int perl_fixup(void** param, int param_no)
{
	int ret=E_UNSPEC;
	pv_elem_t* model;

	if (param == NULL || (param_no < 1 || param_no > 2)) {
		LM_ERR("invalid number of parameters\n");
		return -1;
	}

	if (param_no == 1) {
		/* simple fixup */
		return fixup_spve(param);
	} else {
		/* can have more vars for each param */
		str s = {*param, strlen(*param)};

		ret = pv_parse_format(&s, &model);
		if (ret) {
			LM_ERR("wrong format [%s] for param no %d!\n",
					(char*)*param, param_no);
			pkg_free(s.s);
			return E_UNSPEC;
		}

		*param = (void *)model;
		ret = 0;
	}

	return ret;
}

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

/*
 * parse function and parameters
 * returns p(arsed)fnc name and p(arsed)prm parameters
 * requiers output strs to be allocated
 */
int perl_parse_params(struct sip_msg *msg, char *fnc, char *prm,
		str *pfnc, str *pprm)
{
	if (!pfnc && !pprm) {
		LM_ERR("null output parameters given!\n");
		return -1;
	}

	if (msg == 0 || fnc == 0) {
		LM_ERR("null input parameters given!\n");
		return -1;
	}

	if (fixup_get_svalue(msg, (gparam_p)fnc, pfnc) != 0) {
		LM_ERR("invalid function name given\n");
		return -1;
	}

	if (prm && pprm && pv_printf_s(msg, (pv_elem_p)prm, pprm)!=0) {
		LM_ERR("invalid function paramters given!\n");
		return -1;
	}

	return 0;
}

/*
 * Run function without parameters
 */

int perl_exec_simple(char* fnc, char* args[], int flags) {

	if (perl_checkfnc(fnc)) {
		LM_DBG("running perl function \"%s\"", fnc);

		call_argv(fnc, flags, args);
	} else {
		LM_ERR("unknown function '%s' called.\n", fnc);
		return -1;
	}

	return 1;
}

int perl_exec_simple1(struct sip_msg* _msg, char* fnc, char* str2) {
	char *args[] = { NULL };
	str pfnc;

	if (perl_parse_params(_msg, fnc, NULL, &pfnc, NULL)) {
		LM_ERR("failed to parse params\n");
		return -1;
	}



	return perl_exec_simple(pfnc.s, args, G_DISCARD | G_NOARGS | G_EVAL);
}

int perl_exec_simple2(struct sip_msg* _msg, char* fnc, char* param) {
	str pfnc, pparam;

	if (perl_parse_params(_msg, fnc, param, &pfnc, &pparam)) {
		LM_ERR("failed to parse params\n");
		return -1;
	}

	char *args[] = { pparam.s, NULL };

	return perl_exec_simple(pfnc.s, args, G_DISCARD | G_EVAL);
}

/*
 * Run function, with current SIP message as a parameter
 */
int perl_exec1(struct sip_msg* _msg, char* fnc, char *foobar) {
	return perl_exec2(_msg, fnc, NULL);
}

int perl_exec2(struct sip_msg* _msg, char* fnc, char* mystr) {
	int retval;
	SV *m;
	str reason;
	str pfnc, pparam;


	if (perl_parse_params(_msg, fnc, mystr, &pfnc, mystr?&pparam:NULL)) {
		LM_ERR("failed to parse params\n");
		return -1;
	}

	fnc = pfnc.s;
	mystr = mystr ? pparam.s : NULL;

	dSP;

	if (!perl_checkfnc(fnc)) {
		LM_ERR("unknown perl function called.\n");
		reason.s = "Internal error";
		reason.len = sizeof("Internal error")-1;
		if (sigb.reply(_msg, 500, &reason, NULL) == -1)
		{
			LM_ERR("failed to send reply\n");
		}
		return -1;
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
			return -1;
		}
		break;
	case SIP_REPLY:
		break;
	default:
		LM_ERR("invalid firstline");
		return -1;
	}



	ENTER;				/* everything created after here */
	SAVETMPS;			/* ...is a temporary variable.   */
	PUSHMARK(SP);			/* remember the stack pointer    */

	m = sv_newmortal();		/* create a mortal SV to be killed on FREETMPS */
	sv_setref_pv(m, "OpenSIPS::Message", (void *)_msg); /* bless the message with a class */
	SvREADONLY_on(SvRV(m));		/* set the content of m to be readonly  */

	XPUSHs(m);			/* Our reference to the stack... */

	if (mystr)
		XPUSHs(sv_2mortal(newSVpv(mystr, strlen(mystr))));
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
}
