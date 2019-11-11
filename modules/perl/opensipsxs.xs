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

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <unistd.h>
#undef load_module

/* perl.h defines union semun */
#ifdef USE_SYSV_SEM
# undef _SEM_SEMUN_UNDEFINED
#endif

#include "../../sr_module.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../usr_avp.h"
#include "../../action.h"
#include "../../flags.h"
#include "../../pvar.h"
#include "../../mem/mem.h"
#include "../../route_struct.h"
#include "../../serialize.h"
#include "../../qvalue.h"
#include "../../dprint.h"
#include "../../mod_fix.h"
#include "../../ut.h"
#include "../../dset.h"

enum xs_uri_members {
	XS_URI_USER = 0,
	XS_URI_PASSWD,
	XS_URI_HOST,
	XS_URI_PORT,
	XS_URI_PARAMS,
	XS_URI_HEADERS,
	XS_URI_TRANSPORT,
	XS_URI_TTL,
	XS_URI_USER_PARAM,
	XS_URI_MADDR,
	XS_URI_METHOD,
	XS_URI_LR,
	XS_URI_R2,
	XS_URI_TRANSPORT_VAL,
	XS_URI_TTL_VAL,
	XS_URI_USER_PARAM_VAL,
	XS_URI_MADDR_VAL,
	XS_URI_METHOD_VAL,
	XS_URI_LR_VAL,
	XS_URI_R2_VAL
	
	/* These members are no strings:
		unsigned short port_no;
	unsigned short proto; / * from transport * /
	uri_type type; / * uri scheme */
};

/*
 * Return the sip_msg struct referred to by perl reference sv
 */
struct sip_msg * sv2msg(SV *sv) {
	struct sip_msg* m;
	if (SvROK(sv)) {
		sv = SvRV(sv);
		if (SvIOK(sv)) {
			m = INT2PTR(struct sip_msg*, SvIV(sv));
			return m;
		}
	}
	return NULL; /* In case of error above... */
}

struct sip_uri * sv2uri(SV *sv) {
	struct sip_uri* u;
	if (SvROK(sv)) {
		sv = SvRV(sv);
		if (SvIOK(sv)) {
			u = INT2PTR(struct sip_uri*, SvIV(sv));
			return u;
		}
	}
	return NULL; /* In case of error above... */
}

struct action * sv2action(SV *sv) {
	struct action* a;
	if (SvROK(sv)) {
		sv = SvRV(sv);
		if (SvIOK(sv)) {
			a = INT2PTR(struct action*, SvIV(sv));
			return a;
		}
	}
	return NULL; /* In case of error above... */
}

/*
 * We have a private function for two reasons:
 * a) Return SIP_INVALID even if type was sth different
 * b) easy access
 */

inline static int getType(struct sip_msg *msg) {
	int t = SIP_INVALID;

	if (!msg) return SIP_INVALID;

	switch ((msg->first_line).type) {
		case SIP_REQUEST:	t = SIP_REQUEST; break;
		case SIP_REPLY:		t = SIP_REPLY; break;
	}
	return t;
}
		

SV *getStringFromURI(SV *self, enum xs_uri_members what) {
	struct sip_uri *myuri = sv2uri(self);
	str *ret = NULL;

	if (!myuri) {
		LM_ERR("Invalid URI reference\n");
		ret = NULL;
	} else {
		
		switch (what) {
			case XS_URI_USER:	ret = &(myuri->user);
						break;
			case XS_URI_HOST:	ret = &(myuri->host);
						break;
			case XS_URI_PASSWD:	ret = &(myuri->passwd);
						break;
			case XS_URI_PORT:	ret = &(myuri->port);
						break;
			case XS_URI_PARAMS:	ret = &(myuri->params);
						break;
			case XS_URI_HEADERS:	ret = &(myuri->headers);
						break;
			case XS_URI_TRANSPORT:	ret = &(myuri->transport);
						break;
			case XS_URI_TTL:		ret = &(myuri->ttl);
						break;
			case XS_URI_USER_PARAM:	ret = &(myuri->user_param);
						break;
			case XS_URI_MADDR:	ret = &(myuri->maddr);
						break;
			case XS_URI_METHOD:	ret = &(myuri->method);
						break;
			case XS_URI_LR:		ret = &(myuri->lr);
						break;
			case XS_URI_R2:		ret = &(myuri->r2);
						break;
			case XS_URI_TRANSPORT_VAL:	ret = &(myuri->transport_val);
						break;
			case XS_URI_TTL_VAL:	ret = &(myuri->ttl_val);
						break;
			case XS_URI_USER_PARAM_VAL:	ret = &(myuri->user_param_val);
						break;
			case XS_URI_MADDR_VAL:	ret = &(myuri->maddr_val);
						break;
			case XS_URI_METHOD_VAL:	ret = &(myuri->method_val);
						break;
			case XS_URI_LR_VAL:	ret = &(myuri->lr_val);
						break;
			case XS_URI_R2_VAL:	ret = &(myuri->r2_val);
						break;

			default:	LM_INFO("Unknown URI element"
						" requested: %d\n", what);
					break;
		}
	}

	if ((ret) && (ret->len)) {
		return sv_2mortal(newSVpv(ret->s, ret->len));
	} else {
		return &PL_sv_undef;
	}
}


static int perl_do_action(struct sip_msg* msg, struct action *act,
    cmd_export_t *cmd, int *retval)
{
    void* cmdp[MAX_CMD_PARAMS];
    pv_value_t tmp_vals[MAX_CMD_PARAMS];
    int i;
    struct cmd_param *param;
    gparam_p gp;

    if (fix_cmd(cmd->params, act->elem) < 0) {
		LM_ERR("failed to fix command '%s'\n", cmd->name);
		return -1;
	}

	if (get_cmd_fixups(msg, cmd->params, act->elem, cmdp, tmp_vals) < 0) {
		LM_ERR("failed to get fixups for command '%s'\n", cmd->name);
		return -1;
	}

	*retval = cmd->function(msg,
		cmdp[0],cmdp[1],cmdp[2],
		cmdp[3],cmdp[4],cmdp[5],
		cmdp[6],cmdp[7]);

	for (param=cmd->params, i=1; param->flags; param++, i++) {
		gp = (gparam_p)act->elem[i].u.data;
		if (!gp)
			continue;

		if (param->free_fixup && param->free_fixup(&cmdp[i-1]) < 0) {
			LM_ERR("failed to free fixups for command '%s'\n", cmd->name);
			return -1;
		}

		if (param->flags & CMD_PARAM_REGEX && gp->type != GPARAM_TYPE_PVS) {
			regfree((regex_t*)cmdp[i-1]);
			pkg_free(cmdp[i-1]);
		}
	}

    return 0;
}

/*
 * Calls an exported function.
 *
 * Return codes:
 *   -1 - Function not available (or other error).
 *    1 - Function was called. Its return value is returned via the retval
 *        parameter.
 */

int moduleFunc(struct sip_msg *m, char *func, char **pargs, int *retval)
{
	cmd_export_t *exp_func_struct;
	struct action *act;
	action_elem_t elems[MAX_ACTION_ELEMS];
	int i, n = 0;
	struct cmd_param *param;
	str s;
	pv_spec_t *specs[MAX_CMD_PARAMS];
	int rval;

	if (!func) {
		LM_ERR("moduleFunc called with null function name. Error.\n");
		return -1;
	}

	exp_func_struct = find_cmd_export_t(func, 0);
	if (!exp_func_struct) {
		LM_ERR("function '%s' called, but not available\n", func);
		*retval = -1;
		return -1;
	}

	for (i=0; i < MAX_CMD_PARAMS; i++) {
		if (pargs[i]) {
			n++;
			if (strlen(pargs[i]) == 0)  /* 'undef' argument */ {
				elems[i+1].type = NULLV_ST;
				pargs[i] = NULL;
			} else
				elems[i+1].type = NOSUBTYPE;
		}
		specs[i] = NULL;
	}

	rval = check_cmd_call_params(exp_func_struct, elems, n);
	if (rval == -1 || rval == -2) {
		LM_ERR("to few or too many parameters\n");
		*retval = -1;
		return -1;
	} else if (rval == -3) {
		LM_ERR("mandatory parameter ommited\n");
		*retval = -1;
		return -1;
	}

	elems[0].type = CMD_ST;
	elems[0].u.data = exp_func_struct;

	for (param=exp_func_struct->params, i=1; param->flags; param++, i++) {
		if (!pargs[i-1])
			continue;

		if (param->flags & CMD_PARAM_INT) {
			elems[i].type = NUMBER_ST;
			s.s = pargs[i-1];
		    s.len =  strlen(s.s);
			if (str2sint(&s, (int*)&elems[i].u.number) < 0) {
				LM_ERR("parameter [%d] should be an integer\n", i);
				*retval = -1;
				return -1;
			}
		} else if (param->flags & (CMD_PARAM_STR | CMD_PARAM_REGEX)) {
			elems[i].type = STR_ST;
			elems[i].u.data = pargs[i-1];
		} else if (param->flags & CMD_PARAM_VAR) {
			elems[i].type = SCRIPTVAR_ST;
			specs[i] = pkg_malloc(sizeof *specs[i]);
			if (!specs[i]) {
				LM_ERR("oom\n");
				*retval = -1;
				return -1;
			}
			s.s = pargs[i-1];
			s.len = strlen(s.s);
			if (pv_parse_spec(&s, specs[i]) == NULL) {
				LM_ERR("unknown script variable: %.*s\n", s.len, s.s);
				*retval = -1;
				return -1;
			}
			elems[i].u.data = specs[i];
		}
	}

	act = mk_action(CMD_T, n+1, elems, 0, "perl");

	if (!act) {
		LM_ERR("action structure could not be created. Error.\n");
		*retval = -1;
		return -1;
	}

	if (perl_do_action(m, act, exp_func_struct, retval) < 0) {
		*retval = -1;
		return -1;
	}

	for (i=0; i < MAX_CMD_PARAMS; i++)
		pv_spec_free(specs[i]);

	/* free the gparam_t structs allocated by fix_cmd() */
	for (i=1; i < MAX_ACTION_ELEMS; i++)
		if (act->elem[i].u.data)
			pkg_free(act->elem[i].u.data);

	pkg_free(act);
	
	return 1;
}


/**
 * Rewrite Request-URI
 */
static inline int rw_ruri(struct sip_msg* _m, char* _s)
{
	str s;

	s.s = _s;
	s.len = strlen(_s);

	if (set_ruri(_m, &s) < 0) {
		LM_ERR("Error setting RURI\n");
		return -1;
	}

	return 0;
}


/**
 * Compile a string with pseudo variables substituted by their values.
 * A string buffer is allocated. Deallocate afterwards!
 */
char *pv_sprintf(struct sip_msg *m, char *fmt) {
	int buf_size = 4096;
	pv_elem_t *model;
	str s;
	char *out = (char *)pkg_malloc(buf_size);
	char *ret = NULL;

	if (!out) {
		LM_ERR("pv_sprintf: Memory exhausted!\n");
		return NULL;
	}

	s.s = fmt; s.len = strlen(s.s);
	if(pv_parse_format(&s, &model) < 0) {
		LM_ERR("pv_sprintf: ERROR: wrong format[%s]!\n",
			fmt);
		return NULL;
	}

	if(pv_printf(m, model, out, &buf_size) < 0) {
		ret = NULL;
	} else {
		ret = strdup(out);
	}

	pv_elem_free_all(model);
	pkg_free(out);

	return ret;
}

/**
 * Convert an SV to an int_str struct. Needed in AVP package.
 * - val: SV to convert.
 * - is: pointer to resulting int_str
 * - flags: pointer to flags to set
 * - strflag: flag mask to be or-applied for string match
 */

static inline int sv2int_str(SV *val, int_str *is,
		      unsigned short *flags, unsigned short strflag) {
	char *s;
	STRLEN len;

	if (!SvOK(val)) {
		LM_ERR("AVP:sv2int_str: Invalid value "
			"(not a scalar).\n");
		return 0;
	}
	
	if (SvIOK(val)) { /* numerical name */
		is->n = SvIV(val);
		*flags = 0;
		return 1;
	} else if (SvPOK(val)) {
		s = SvPV(val, len);
		is->s.len = len;
		is->s.s = s;
		(*flags) |= strflag;
		return 1;
	} else {
		LM_ERR("AVP:sv2int_str: Invalid value "
			"(neither string nor integer).\n");
		return 0;
	}
}

/* ************************************************************************ */
/* Object methods begin here */

=head1 OpenSIPS

This module provides access to a limited number of OpenSIPS core functions.
As the most interesting functions deal with SIP messages, they are located
in the OpenSIPS::Message class below.

=cut

MODULE = OpenSIPS PACKAGE = OpenSIPS

=head2 log(level,message)

Logs the message with OpenSIPS's logging facility. The logging level
is one of the following:

 * L_ALERT
 * L_CRIT
 * L_ERR
 * L_WARN
 * L_NOTICE
 * L_INFO
 * L_DBG

Please note that this method is I<NOT> automatically exported, as it collides
with the perl function log (which calculates the logarithm). Either explicitly
import the function (via C<use OpenSIPS qw ( log );>), or call it with its full
name:

 OpenSIPS::log(L_INFO, "foobar");

=cut

void
log(level, log)
    int level
    char *log
  PREINIT:
  INIT:
  CODE:
	switch (level) {
	case L_ALERT:	LM_ALERT("%s", log); break;
	case L_CRIT:	LM_CRIT("%s", log); break;
	case L_ERR:	LM_ERR("%s", log); break;
	case L_WARN:	LM_WARN("%s", log); break;
	case L_NOTICE:	LM_NOTICE("%s", log); break;
	case L_INFO:	LM_INFO("%s", log); break;
	default:	LM_DBG("%s", log); break;
	}
  OUTPUT:



MODULE = OpenSIPS PACKAGE = OpenSIPS::Message

PROTOTYPES: ENABLE

=head1 OpenSIPS::Message

This package provides access functions for an OpenSIPS C<sip_msg> structure and
its sub-components. Through its means it is possible to fully configure
alternative routing decisions.

=cut

=head2 getType()

Returns one of the constants SIP_REQUEST, SIP_REPLY, SIP_INVALID stating the
type of the current message.

=cut

int
getType(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
  	RETVAL = getType(msg);
  OUTPUT:
  	RETVAL
	
	

=head2 getStatus()

Returns the status code of the current Reply message. This function is invalid
in Request context!

=cut

SV *
getStatus(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) != SIP_REPLY) {
			LM_ERR("getStatus: Status not available in"
				" non-reply messages.");
			ST(0) = &PL_sv_undef;
		} else {
			ret = &((msg->first_line).u.reply.status);
			ST(0) = sv_2mortal(newSVpv(ret->s, ret->len));
		}
	}


=head2 getReason()

Returns the reason of the current Reply message. This function is invalid
in Request context!

=cut

SV *
getReason(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) != SIP_REPLY) {
			LM_ERR("getReason: Reason not available in"
				" non-reply messages.");
			ST(0) = &PL_sv_undef;
		} else {
			ret = &((msg->first_line).u.reply.reason);
			ST(0) = sv_2mortal(newSVpv(ret->s, ret->len));
		}
	}


=head2 getVersion()

Returns the version string of the current SIP message.

=cut

SV *
getVersion(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) == SIP_REQUEST) {
			ret = &((msg->first_line).u.request.version);
		} else { /* SIP_REPLY */
			ret = &((msg->first_line).u.reply.version);
		}
		ST(0) = sv_2mortal(newSVpv(ret->s, ret->len));
	}


=head2 getRURI()

This function returns the recipient URI of the present SIP message:

C<< my $ruri = $m->getRURI(); >>

getRURI returns a string. See L</"getParsedRURI()"> below how to receive a
parsed structure.

This function is valid in request messages only.

=cut

SV *
getRURI(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) != SIP_REQUEST) {
			LM_ERR("Not a request message - "
				"no RURI available.\n");
			ST(0) = &PL_sv_undef;
		} else {
			ret = &((msg->first_line).u.request.uri);
			ST(0) = sv_2mortal(newSVpv(ret->s, ret->len));
		}
	}


=head2 getMethod()

Returns the current method, such as C<INVITE>, C<REGISTER>, C<ACK> and so on.

C<< my $method = $m->getMethod(); >>

This function is valid in request messages only.

=cut

char *
getMethod(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) != SIP_REQUEST) {
			LM_ERR("Not a request message - "
				"no method available.\n");
			ST(0) = &PL_sv_undef;
		} else {
			ret = &((msg->first_line).u.request.method);
			ST(0) = sv_2mortal(newSVpv(ret->s, ret->len));
		}
	}


=head2 getFullHeader()

Returns the full message header as present in the current message.
You might use this header to further work with it with your
favorite MIME package.

C<< my $hdr = $m->getFullHeader(); >>

=cut

SV *
getFullHeader(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    char *firsttoken;
    long headerlen;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		if (getType(msg) == SIP_INVALID) {
			LM_ERR("getFullHeader: Invalid message type.\n");
			ST(0)  = &PL_sv_undef;
		} else {
			if (parse_headers(msg, ~0, 0) < 0)
				LM_ERR("cannot parse headers\n");
			if (getType(msg) == SIP_REQUEST) {
				firsttoken = (msg->first_line).u.request.method.s;
			} else { /* SIP_REPLY */
				firsttoken = (msg->first_line).u.reply.version.s;
			}

			if (msg->eoh == NULL)
				headerlen = 0;
			else
				headerlen = ((long)(msg->eoh))
						-((long)(firsttoken));

			if (headerlen > 0) {
				ST(0) = 
				    sv_2mortal(newSVpv(firsttoken, headerlen));
			} else {
				ST(0) = &PL_sv_undef;
			}
		}
	}


=head2 getBody()

Returns the message body.

=cut

SV *
getBody(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str body;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		body.s = NULL;
		if (get_body(msg,&body) < 0) {
			LM_ERR("Message has no body\n");
			ST(0) = &PL_sv_undef;
		} else {
			ST(0) = sv_2mortal(newSVpv(body.s, 0));
		}
	}


=head2 getMessage()

Returns the whole message including headers and body.

=cut

SV *
getMessage(self)
    SV *self
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		ST(0) = sv_2mortal(newSVpv(msg->buf, 0));
	}


=head2 getHeader(name)

Returns the body of the first message header with this name.

C<< print $m->getHeader("To"); >>

B<C<< "John" <sip:john@doe.example> >>>

=cut

SV *
getHeader(self, name)
    SV *self;
    char *name;
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    str *body = NULL;
    struct hdr_field *hf;
    int found = 0;
    int namelen = strlen(name);
  INIT:
  PPCODE:
	LM_DBG("searching '%s'\n", name);

	if (!msg) {
		LM_ERR("Invalid message reference\n");
	} else {
		if (parse_headers(msg, ~0, 0) < 0)
			LM_ERR("cannot parse headers!\n");
		for (hf = msg->headers; hf; hf = hf->next) {
			if (namelen == hf->name.len) {
				if (strncmp(name, hf->name.s, namelen) == 0) {
					/* Found the right header. */
					found = 1;
					body = &(hf->body);
					XPUSHs(sv_2mortal(newSVpv(body->s,
								  body->len)));
				}
			}
		}
	}
	if (!found) {
		XPUSHs(&PL_sv_undef);
	}



=head2 getHeaderNames()

Returns an array of all header names. Duplicates possible!

=cut

AV *
getHeaderNames(self)
    SV *self;
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    struct hdr_field *hf = NULL;
    int found = 0;
  PPCODE:
	
	if (!msg) {
		LM_ERR("Invalid message reference\n");
	} else {
		if (parse_headers(msg, ~0, 0) < 0)
			LM_ERR("cannot parse headers!\n");
		for (hf = msg->headers; hf; hf = hf->next) {
			found = 1;
			XPUSHs(sv_2mortal(newSVpv(hf->name.s, hf->name.len)));
		}
	}
	if (!found) {
		XPUSHs(&PL_sv_undef);
	}


=head2 moduleFunction(func,string1,string2,string3,string4,string5,string6,string7,string8)

Search for an arbitrary function in module exports and call it with the
parameters self, string1, string2, ..., string8

As this function provides access to the functions that are exported to the
OpenSIPS configuration file, it is autoloaded for unknown functions. Instead of
writing

 $m->moduleFunction("sl_send_reply", "500", "Internal Error");
 $m->moduleFunction("xlog", "L_INFO", "foo");
 
you may as well write

 $m->sl_send_reply("500", "Internal Error");
 $m->xlog("L_INFO", "foo");

=cut


int
moduleFunction (self, func, string1 = NULL, string2 = NULL, string3 = NULL, string4 = NULL, string5 = NULL, string6 = NULL, string7 = NULL, string8 = NULL)
    SV *self;
    char *func;
    char *string1;
    char *string2;
    char *string3;
    char *string4;
    char *string5;
    char *string6;
    char *string7;
    char *string8;
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    int retval; /* Return value of called function */
    int ret;    /* Return value of moduleFunc - < 0 for "non existing function" and other errors */
    char *pargs[MAX_CMD_PARAMS];
  INIT:
  CODE:
	LM_DBG("Calling exported func: '%s'\n", func);

	pargs[0] = string1;
	pargs[1] = string2;
	pargs[2] = string3;
	pargs[3] = string4;
	pargs[4] = string5;
	pargs[5] = string6;
	pargs[6] = string7;
	pargs[7] = string8;

	if (!msg) {
		LM_ERR("invalid message received!\n");
		retval = -1;
	} else {
		ret = moduleFunc(msg, func, pargs, &retval);
		if (ret < 0) {
			LM_ERR("calling module function '%s' failed."
				" Missing loadmodule?\n", func);
			retval = -1;
		}
	}
	RETVAL = retval;
  OUTPUT:
	RETVAL



=head2 log(level,message) (deprecated type)

Logs the message with OpenSIPS's logging facility. The logging level
is one of the following:

 * L_ALERT
 * L_CRIT
 * L_ERR
 * L_WARN
 * L_NOTICE
 * L_INFO
 * L_DBG

The logging function should be accessed via the OpenSIPS module variant. This
one, located in OpenSIPS::Message, is deprecated.

=cut

void
log(self, level, log)
    SV *self
    int level
    char *log
  PREINIT:
  INIT:
  CODE:
	switch (level) {
	case L_ALERT:	LM_ALERT("%s", log); break;
	case L_CRIT:	LM_CRIT("%s", log); break;
	case L_ERR:	LM_ERR("%s", log); break;
	case L_WARN:	LM_WARN("%s", log); break;
	case L_NOTICE:	LM_NOTICE("%s", log); break;
	case L_INFO:	LM_INFO("%s", log); break;
	default:	LM_DBG("%s", log); break;
	}



=head2 rewrite_ruri(newruri)

Sets a new destination (recipient) URI. Useful for rerouting the
current message/call.

 if ($m->getRURI() =~ m/\@somedomain.net/) {
   $m->rewrite_ruri("sip:dispatcher\@organization.net");
 }

=cut

int
rewrite_ruri(self, newruri)
    SV *self;
    char *newruri;
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		if (getType(msg) != SIP_REQUEST) {
			LM_ERR("Not a Request. RURI rewrite unavailable.\n");
			RETVAL = -1;
		} else {
			LM_DBG("New R-URI is [%s]\n", newruri);
			RETVAL = rw_ruri(msg, newruri);
		}
	}
  OUTPUT:
	RETVAL



=head2 setFlag(flag)

Sets a message flag. The constants as known from the C API may be used,
when Constants.pm is included.

=cut

int
setFlag(self, flag)
    SV *self;
    unsigned int flag;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = setflag(msg, flag);
	}
  OUTPUT:
	RETVAL


=head2 resetFlag(flag)

Resets a message flag.

=cut

int
resetFlag(self, flag)
    SV *self;
    unsigned int flag;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = resetflag(msg, flag);
	}
  OUTPUT:
	RETVAL

=head2 isFlagSet(flag)

Returns whether a message flag is set or not.

=cut

int
isFlagSet(self, flag)
    SV *self;
    unsigned int flag;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
  INIT:
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = isflagset(msg, flag) == 1 ? 1 : 0;
	}
  OUTPUT:
	RETVAL


=head2 pseudoVar(string)

Returns a new string where all pseudo variables are substituted by their values.
Can be used to receive the values of single variables, too.

B<Please remember that you need to escape the '$' sign in perl strings!>

=cut

SV *
pseudoVar(self, varstring)
    SV *self;
    char *varstring;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
	char *ret;
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = &PL_sv_undef;
	} else {
		ret = pv_sprintf(msg, varstring);
		if (ret) {
			ST(0) = sv_2mortal(newSVpv(ret, strlen(ret)));
			free(ret);
		} else {
			ST(0) = &PL_sv_undef;
		}
	}



=head2 append_branch(branch,qval)

Append a branch to current message.

=cut

int
append_branch(self, branch = NULL, qval = NULL)
	SV *self;
	char *branch;
	char *qval;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
	action_elem_t elems[MAX_ACTION_ELEMS];
	qvalue_t q;
	int err = 0;
	struct action *act = NULL;
	str branch_s;
  INIT:
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = 1;
		if (qval) {
			if (str2q(&q, qval, strlen(qval)) < 0) {
				LM_ERR("append_branch: Bad q value.\n");
				RETVAL = -1;
			} else { /* branch and qval set */
				branch_s.s = branch;
				branch_s.len = strlen(branch);
			}
		} else {
			if (branch) { /* branch set, qval unset */
				branch_s.s = branch;
				branch_s.len = strlen(branch);
				q = Q_UNSPECIFIED;
			} else { /* neither branch nor qval set */
				q = Q_UNSPECIFIED;
				branch_s.s = NULL;
			}
		}

		if (RETVAL != -1)
			RETVAL = append_branch(msg, branch_s.s ? &branch_s : NULL,
						&msg->dst_uri, &msg->path_vec, q, getb0flags(msg),
						msg->force_send_socket);
	}
  OUTPUT:
	RETVAL



=head2 serialize_branches(clean_before, keep_order)

Serialize branches.

=cut

int serialize_branches(self, clean_before, keep_order)
	SV *self;
	int clean_before;
	int keep_order;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = serialize_branches(msg, clean_before, keep_order);
	}
  OUTPUT:
	RETVAL



=head2 next_branches()

Next branches.

=cut

int
next_branches(self)
	SV *self;
  PREINIT:
	struct sip_msg *msg = sv2msg(self);
  CODE:
  	if (!msg) {
		LM_ERR("Invalid message reference\n");
		RETVAL = -1;
	} else {
		RETVAL = next_branches(msg);
	}
  OUTPUT:
	RETVAL




=head2 getParsedRURI()

Returns the current destination URI as an OpenSIPS::URI object.

=cut

SV *
getParsedRURI(self)
    SV *self;
  PREINIT:
    struct sip_msg *msg = sv2msg(self);
    struct sip_uri *uri;
    SV *ret;
  INIT:
  CODE:
	if (!msg) {
		LM_ERR("Invalid message reference\n");
		ST(0) = NULL;
	} else {
		if (parse_sip_msg_uri(msg) < 0 || parse_headers(msg, ~0, 0) < 0) {
			LM_ERR("cannot parse message uri!\n");
			ST(0) = &PL_sv_undef;
		} else {
			uri = &(msg->parsed_uri);
			ret = sv_newmortal();
			sv_setref_pv(ret, "OpenSIPS::URI", (void *)uri);
			SvREADONLY_on(SvRV(ret));

			ST(0) = ret;
		}
	}
	


MODULE = OpenSIPS PACKAGE = OpenSIPS::URI

=head1 OpenSIPS::URI

This package provides functions for access to sip_uri structures.

=cut




=head2 user()

Returns the user part of this URI.

=cut

SV *
user(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_USER);


=head2 host()

Returns the host part of this URI.

=cut

SV *
host(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_HOST);


=head2 passwd()

Returns the passwd part of this URI.

=cut

SV *
passwd(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_PASSWD);


=head2 port()

Returns the port part of this URI.

=cut

SV *
port(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_PORT);


=head2 params()

Returns the params part of this URI.

=cut

SV *
params(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_PARAMS);


=head2 headers()

Returns the headers part of this URI.

=cut

SV *
headers(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_HEADERS);


=head2 transport()

Returns the transport part of this URI.

=cut

SV *
transport(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_TRANSPORT);


=head2 ttl()

Returns the ttl part of this URI.

=cut

SV *
ttl(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_TTL);


=head2 user_param()

Returns the user_param part of this URI.

=cut

SV *
user_param(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_USER_PARAM);



=head2 maddr()

Returns the maddr part of this URI.

=cut

SV *
maddr(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_MADDR);

=head2 method()

Returns the method part of this URI.

=cut

SV *
method(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_METHOD);


=head2 lr()

Returns the lr part of this URI.

=cut

SV *
lr(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_LR);


=head2 r2()

Returns the r2 part of this URI.

=cut

SV *
r2(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_R2);


=head2 transport_val()

Returns the transport_val part of this URI.

=cut

SV *
transport_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_TRANSPORT_VAL);


=head2 ttl_val()

Returns the ttl_val part of this URI.

=cut

SV *
ttl_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_TTL_VAL);


=head2 user_param_val()

Returns the user_param_val part of this URI.

=cut

SV *
user_param_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_USER_PARAM_VAL);


=head2 maddr_val()

Returns the maddr_val part of this URI.

=cut

SV *
maddr_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_MADDR_VAL);


=head2 method_val()

Returns the method_val part of this URI.

=cut

SV *
method_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_METHOD_VAL);


=head2 lr_val()

Returns the lr_val part of this URI.

=cut

SV *
lr_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_LR_VAL);


=head2 r2_val()

Returns the r2_val part of this URI.

=cut

SV *
r2_val(self)
    SV *self;
  CODE:
	ST(0) = getStringFromURI(self, XS_URI_R2_VAL);



=head1 OpenSIPS::AVP

This package provides access functions for OpenSIPS's AVPs.
These variables can be created, evaluated, modified and removed through this
package.

Please note that these functions do NOT support the notation used
in the configuration file, but directly work on strings or numbers. See
documentation of add method below.

=cut


MODULE = OpenSIPS PACKAGE = OpenSIPS::AVP

=head2 add(name,val)

Add an AVP.

Add an OpenSIPS AVP to its environment. name and val may both be integers or
strings; this function will try to guess what is correct. Please note that
 
 OpenSIPS::AVP::add("10", "10")

is something different than

 OpenSIPS::AVP::add(10, 10)

due to this evaluation: The first will create _string_ AVPs with the name
10, while the latter will create a numerical AVP.

You can modify/overwrite AVPs with this function.

=cut

int
add(p_name, p_val)
	SV *p_name;
	SV *p_val;
  PREINIT:
	int_str name;
	int_str val;
	unsigned short flags = 0;
	char *s;
	STRLEN len;
  CODE:
  	RETVAL = 0;
	if (SvOK(p_name) && SvOK(p_val)) {
		if (!sv2int_str(p_name, &name, &flags, AVP_NAME_STR)) {
			RETVAL = -1;
		} else if (!sv2int_str(p_val, &val, &flags, AVP_VAL_STR)) {
			RETVAL = -1;
		}

		if (RETVAL == 0) {
			if (flags & AVP_NAME_STR) {
				name.n = get_avp_id(&name.s);
			}
			RETVAL = add_avp(flags, name.n, val);
		}
	}
  OUTPUT:
	RETVAL




=head2 get(name)

get an OpenSIPS AVP:

 my $numavp = OpenSIPS::AVP::get(5);
 my $stravp = OpenSIPS::AVP::get("foo");

=cut

int
get(p_name)
	SV *p_name;
  PREINIT:
	struct usr_avp *first_avp;
	int_str name;
	int_str val;
	unsigned short flags = 0;
	SV *ret = &PL_sv_undef;
	int err = 0;
	char *s;
	STRLEN len;
  CODE:
	if (SvOK(p_name)) {
		if (!sv2int_str(p_name, &name, &flags, AVP_NAME_STR)) {
			LM_ERR("AVP:get: Invalid name.\n");
			err = 1;
		}
	} else {
		LM_ERR("AVP:get: Invalid name.\n");
		err = 1;
	}
	
	if (err == 0) {
		if (flags & AVP_NAME_STR) {
			name.n = get_avp_id(&name.s);
		}
		first_avp = search_first_avp(flags, name.n, &val, NULL);
		
		if (first_avp != NULL) { /* found correct AVP */
			if (is_avp_str_val(first_avp)) {
				ret = sv_2mortal(newSVpv(val.s.s, val.s.len));
			} else {
				ret = sv_2mortal(newSViv(val.n));
			}
		} else {
			/* Empty AVP requested. */
		}
	}

	ST(0) = ret;




=head2 destroy(name)

Destroy an AVP.

 OpenSIPS::AVP::destroy(5);
 OpenSIPS::AVP::destroy("foo");

=cut

int
destroy(p_name)
	SV *p_name;
  PREINIT:
	struct usr_avp *first_avp;
	int_str name;
	int_str val;
	unsigned short flags = 0;
	SV *ret = &PL_sv_undef;
	char *s;
	STRLEN len;
  CODE:
	RETVAL = 1;
	if (SvOK(p_name)) {
		if (!sv2int_str(p_name, &name, &flags, AVP_NAME_STR)) {
			RETVAL = 0;
			LM_ERR("AVP:destroy: Invalid name.\n");
		}
	} else {
		RETVAL = 0;
		LM_ERR("VP:destroy: Invalid name.\n");
	}
	
	if (RETVAL == 1) {
		if (flags & AVP_NAME_STR) {
			name.n = get_avp_id(&name.s);
		}
		first_avp = search_first_avp(flags, name.n, &val, NULL);
		
		if (first_avp != NULL) { /* found correct AVP */
			destroy_avp(first_avp);
		} else {
			RETVAL = 0;
			/* Empty AVP requested. */
		}
	}

  OUTPUT:
	RETVAL


