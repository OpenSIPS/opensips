/*
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
 * 2003-04-04  convenience inbound-uri parser parse_orig_ruri
 *             introduced (jiri)
 * 2003-04-11  new parse_uri introduced (better, parses also some parameters,
 *              works in one pass) (andrei)
 * 2003-04-11  ser_error is now set in parse_uri (andrei)
 * 2003-04-26  ZSW (jiri)
 * 2003-07-03  sips:, r2, lr=on support added (andrei)
 * 2005-02-25  preliminary tel uri support (andrei)
 * 2005-03-03  more tel uri fixes (andrei)
 * 2006-11-28  Added statistic support for the number of bad URI's
 *             (Jeffrey Magder - SOMA Networks)
 *  2011-04-20  added support for URI unknown parameters (osas)
 */


#include "parse_uri.h"
#include <string.h>
#include "../dprint.h"
#include "../ut.h"   /* q_memchr */
#include "../error.h"
#include "../errinfo.h"
#include "../core_stats.h"
#include "../strcommon.h"

static const str uri_type_names[7] = {
	{NULL, 0}, /*This is the error type*/
	str_init("sip"),
	str_init("sips"),
	str_init("tel"),
	str_init("tels"),
	str_init("urn:service"),
	str_init("urn:nena:service")
};

char* uri_type2str(const uri_type type, char *result)
{
	if (type == ERROR_URI_T)
		return NULL;

	memcpy(result, uri_type_names[type].s, uri_type_names[type].len);
	return result + uri_type_names[type].len;
}

int uri_typestrlen(const uri_type type)
{
	return uri_type_names[type].len;
}

uri_type str2uri_type(char * buf)
{
	int scheme = 0;
	uri_type type = ERROR_URI_T;
	scheme=buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24);
	scheme|=0x20202020;
	if (scheme==SIP_SCH){
		type=SIP_URI_T;
	}else if(scheme==SIPS_SCH){
		if(buf[4]==':')
			type=SIPS_URI_T;
		else type = ERROR_URI_T;
	}else if (scheme==TEL_SCH){
		type=TEL_URI_T;
	}else if (scheme==URN_SERVICE_SCH){
		if (memcmp(buf+3,URN_SERVICE_STR,URN_SERVICE_STR_LEN) == 0) {
			type=URN_SERVICE_URI_T;
		}
		else if (memcmp(buf+3,URN_NENA_SERVICE_STR,URN_NENA_SERVICE_STR_LEN) == 0) {
			type=URN_NENA_SERVICE_URI_T;
		}
	}
	return type;
}

int parse_uri_headers(str headers, str h_name[], str h_val[], int h_size)
{
	enum states {URI_H_HEADER, URI_H_VALUE};
	register enum states state;
	char* h; /* header start */
	char* v; /* header value start */
	str* header;		/* current header */
	str* header_val;	/* current header val */
	register char* p;
	char* end;
	unsigned int i = 0;

	/* init */
	end = headers.s + headers.len;
	p = h = headers.s;
	v = NULL;
	header = &h_name[0];
	header_val = &h_val[0];
	state = URI_H_HEADER;
	memset(h_name, 0, h_size * sizeof(str));
	memset(h_val, 0, h_size * sizeof(str));

	for(;p<end; p++){
		switch((unsigned char)state){
		case URI_H_HEADER:
			switch(*p){
			case '=':
				v = p+1;
				header->s = h;
				header->len = p-h;
				state = URI_H_VALUE;
				break;
			case '?':
				LM_ERR("Header without value\n");
				h = p+1;
				header->s = h;
				header->len = p-h;
				header_val->s = NULL;
				header_val->len = 0;

				/* advance header and header_val */
				i++;
				if(i<h_size){
					header = &h_name[i];
					header_val = &h_val[i];
				} else {
					LM_ERR("To many URI headers\n");
					return -1;
				}
				break;
			}
			break;
		case URI_H_VALUE:
			switch(*p){
			case '=':
				LM_ERR("Ignoring unexpected '=' inside URI header value\n");
				break;
			case '?':
				h = p+1;
				header_val->s = v;
				header_val->len = p-v;
				state = URI_H_HEADER;

				/* advance header and header_val */
				i++;
				if(i<h_size){
					header = &h_name[i];
					header_val = &h_val[i];
				} else {
					LM_ERR("To many URI headers\n");
					return -1;
				}
				break;
			}
			break;
		default:
			LM_ERR("Unexpected state [%d]\n", state);
			return -1;
		}
	}

	switch(state){
	case URI_H_HEADER:
		LM_ERR("Header without value\n");
		header->s = h;
		header->len = p-h;
		header_val->s = NULL;
		header_val->len = 0;
		break;
	case URI_H_VALUE:
		header_val->s = v;
		header_val->len = p-v;
		break;
	}

#ifdef EXTRA_DEBUG
	for(i=0; i<h_size && h_name[i].s; i++)
		LM_DBG("header=[%p]-><%.*s> val=[%p]-><%.*s>\n",
			h_name[i].s, h_name[i].len, h_name[i].s,
			h_val[i].s, h_val[i].len, h_val[i].s);
#endif

	return 0;
}

int print_uri(struct sip_uri *uri, str *out_buf)
{
#define append_str_chunk(field) \
	do { \
		if (bytes + uri->field.len > out_buf->len) { \
			LM_ERR("no more space left! printed so far: '%.*s'\n", \
		           bytes, out_buf->s); \
			return -1; \
		} \
		memcpy(out_buf->s + bytes, uri->field.s, uri->field.len); \
		bytes += uri->field.len; \
	} while (0)

#define append_char(ch) \
	do { \
		if (bytes + 1 > out_buf->len) { \
			LM_ERR("no more space left! printed so far: '%.*s'\n", \
		           bytes, out_buf->s); \
			return -1; \
		} \
		out_buf->s[bytes++] = ch; \
	} while (0)

#define VAL(p) p##_val

#define append_param(p) \
	do { \
		if (uri->p.s) { \
			append_char(';'); \
			append_str_chunk(p); \
		} \
	} while (0)

#define append_uk_param(idx) \
	do { \
		if (uri->u_name[idx].s) { \
			append_char(';'); \
			if (bytes + uri->u_name[idx].len > out_buf->len) { \
				LM_ERR("no more space left! printed so far: '%.*s'\n", \
			           bytes, out_buf->s); \
				return -1; \
			} \
			memcpy(out_buf->s + bytes, uri->u_name[idx].s, uri->u_name[idx].len); \
			bytes += uri->u_name[idx].len; \
			if (uri->u_val[idx].s) { \
				append_char('='); \
				if (bytes + uri->u_val[idx].len > out_buf->len) { \
					LM_ERR("no more space left! printed so far: '%.*s'\n", \
				           bytes, out_buf->s); \
					return -1; \
				} \
				memcpy(out_buf->s + bytes, uri->u_val[idx].s, uri->u_val[idx].len); \
				bytes += uri->u_val[idx].len; \
			} \
		} \
	} while (0)

	int bytes = 0;
	int i;

	memcpy(out_buf->s, uri_type_names[uri->type].s, uri_type_names[uri->type].len);
	bytes += uri_type_names[uri->type].len;
	append_char(':');
	append_str_chunk(user);
	if (uri->passwd.s) {
		append_char(':');
		append_str_chunk(passwd);
	}
	if (uri->host.s) {
		append_char('@');
		append_str_chunk(host);
	}
	if (uri->port.s) {
		append_char(':');
		append_str_chunk(port);
	}

	append_param(transport);
	append_param(ttl);
	append_param(user_param);
	append_param(maddr);
	append_param(method);
	append_param(lr);
	append_param(r2);
	append_param(gr);
	append_param(pn_provider);
	append_param(pn_prid);
	append_param(pn_param);
	append_param(pn_purr);

	for (i = 0; i < uri->u_params_no; i++)
		append_uk_param(i);

	out_buf->len = bytes;

	return 0;
#undef append_str_chunk
#undef append_char
#undef VAL
#undef append_param
#undef append_uk_param
}

/* buf= pointer to beginning of uri (sip:x@foo.bar:5060;a=b?h=i)
 * len= len of uri
 * returns: fills uri & returns <0 on error or 0 if ok
 */
int parse_uri(char* buf, int len, struct sip_uri* uri)
{
	enum states  {	URI_INIT, URI_USER, URI_PASSWORD, URI_PASSWORD_ALPHA,
					URI_HOST, URI_HOST_P,
					URI_HOST6_P, URI_HOST6_END, URI_PORT,
					URI_PARAM, URI_PARAM_P, URI_PARAM_VAL_P,
					URI_VAL_P, URI_HEADERS,
					/* param states */
					/* transport */
					PT_T, PT_R, PT_A, PT_N, PT_S, PT_P, PT_O, PT_R2, PT_T2,
					PT_eq,
					/* ttl */
					PTTL_T2, PTTL_L, PTTL_eq,
					/* user */
					PU_U, PU_S, PU_E, PU_R, PU_eq,
					/* method */
					PM_M, PM_E, PM_T, PM_H, PM_O, PM_D, PM_eq,
					/* maddr */
					PMA_A, PMA_D, PMA_D2, PMA_R, PMA_eq,
					/* lr */
					PLR_L, PLR_R_FIN, PLR_eq,
					/* gr */
					PG_G, PG_G_FIN, PG_eq,
					/* r2 */
					PR2_R, PR2_2_FIN, PR2_eq,
					/* transport values */
					/* udp */
					VU_U, VU_D, VU_P_FIN,
					/* tcp */
					VT_T, VT_C, VT_P_FIN,
					/* tls */
					VTLS_L, VTLS_S_FIN,
					/* sctp */
					VS_S, VS_C, VS_T, VS_P_FIN,
					/* ws */
					VW_W, VW_S, VW_S_FIN, VWS_S_FIN,

					/* pn-{provider, prid, param, purr} (RFC 8599 - SIP PN) */
					PN_P, PN_N, PN_dash, PN_P2, PN_PR,
					PN1_O, PN1_V, PN1_I, PN1_D, PN1_E, PN1_FIN, PN1_eq,
					PN2_I, PN2_D, PN2_eq,
					PN3_A, PN3_R, PN3_A2, PN3_M, PN3_eq,
					PN4_U, PN4_R, PN4_R2, PN4_eq,

	};
	register enum states state;
	char* s;
	char* b; /* param start */
	char *v; /* value start */
	str* param; /* current param */
	str* param_val; /* current param val */
	str user;
	str password;
	int port_no;
	register char* p;
	char* end;
	char* pass;
	int found_user;
	int error_headers;
	unsigned int scheme;
	uri_type backup;
#ifdef EXTRA_DEBUG
	int i;
#endif

#define case_port( ch, var) \
	case ch: \
			 (var)=(var)*10+ch-'0'; \
			 break

#define still_at_user  \
						if (found_user==0){ \
							user.s=uri->host.s; \
							if (pass){\
								user.len=pass-user.s; \
								password.s=pass+1; \
								password.len=p-password.s; \
							}else{ \
								user.len=p-user.s; \
							}\
							/* save the uri type/scheme */ \
							backup=uri->type; \
							/* everything else is 0 */ \
							memset(uri, 0, sizeof(struct sip_uri)); \
							/* restore the scheme, copy user & pass */ \
							uri->type=backup; \
							uri->user=user; \
							if (pass)	uri->passwd=password;  \
							s=p+1; \
							found_user=1;\
							error_headers=0; \
							state=URI_HOST; \
						}else goto error_bad_char

#define check_host_end \
					case ':': \
						/* found the host */ \
						uri->host.s=s; \
						uri->host.len=p-s; \
						state=URI_PORT; \
						s=p+1; \
						break; \
					case ';': \
						uri->host.s=s; \
						uri->host.len=p-s; \
						state=URI_PARAM; \
						s=p+1; \
						break; \
					case '?': \
						uri->host.s=s; \
						uri->host.len=p-s; \
						state=URI_HEADERS; \
						s=p+1; \
						break; \
					case '&': \
					case '@': \
						goto error_bad_char


#define param_set(t_start, v_start) \
					param->s=(t_start);\
					param->len=(p-(t_start));\
					param_val->s=(v_start); \
					param_val->len=(p-(v_start))

#define u_param_set(t_start, v_start) \
			if (uri->u_params_no < URI_MAX_U_PARAMS){ \
				if((v_start)>(t_start)){ \
					uri->u_name[uri->u_params_no].s=(t_start); \
					uri->u_name[uri->u_params_no].len=((v_start)-(t_start)-1); \
					if(p>(v_start)) { \
						uri->u_val[uri->u_params_no].s=(v_start); \
						uri->u_val[uri->u_params_no].len=(p-(v_start)); \
					} \
				} else { \
					uri->u_name[uri->u_params_no].s=(t_start); \
					uri->u_name[uri->u_params_no].len=(p-(t_start)); \
				} \
				uri->u_params_no++; \
			} else { \
				LM_ERR("unknown URI param list excedeed\n"); \
			}

#define semicolon_case \
					case';': \
						if (pass){ \
							found_user=1;/* no user, pass cannot contain ';'*/ \
							pass=0; \
						} \
						state=URI_PARAM   /* new param */

#define question_case \
					case '?': \
						uri->params.s=s; \
						uri->params.len=p-s; \
						state=URI_HEADERS; \
						s=p+1; \
						if (pass){ \
							found_user=1;/* no user, pass cannot contain '?'*/ \
							pass=0; \
						}

#define colon_case \
					case ':': \
						if (found_user==0){ \
							/*might be pass but only if user not found yet*/ \
							if (pass){ \
								found_user=1; /* no user */ \
								pass=0; \
							}else{ \
								pass=p; \
							} \
						} \
						state=URI_PARAM_P /* generic param */

#define param_common_cases \
					case '@': \
						/* ughhh, this is still the user */ \
						still_at_user; \
						break; \
					semicolon_case; \
						break; \
					question_case; \
						break; \
					colon_case; \
						break

#define u_param_common_cases \
					case '@': \
						/* ughhh, this is still the user */ \
						still_at_user; \
						break; \
					semicolon_case; \
						u_param_set(b, v); \
						break; \
					question_case; \
						u_param_set(b, v); \
						break; \
					colon_case; \
						break

#define value_common_cases \
					case '@': \
						/* ughhh, this is still the user */ \
						still_at_user; \
						break; \
					semicolon_case; \
						param_set(b, v); \
						break; \
					question_case; \
						param_set(b, v); \
						break; \
					colon_case; \
						state=URI_VAL_P; \
						break

#define param_switch(old_state, c1, c2, new_state) \
			case old_state: \
				switch(*p){ \
					case c1: \
					case c2: \
						state=(new_state); \
						break; \
					u_param_common_cases; \
					default: \
						state=URI_PARAM_P; \
				} \
				break
#define param_switch1(old_state, c1, new_state) \
			case old_state: \
				switch(*p){ \
					case c1: \
						state=(new_state); \
						break; \
					param_common_cases; \
					default: \
						state=URI_PARAM_P; \
				} \
				break
#define param_xswitch1(old_state, c1, new_state) \
			case old_state: \
				switch(*p){ \
					case c1: \
						state=(new_state); \
						break; \
					default: \
						goto error_bad_char; \
				} \
				break
#define param_switch_big(old_state, c1, c2, d1, d2, new_state_c, new_state_d) \
			case old_state : \
				switch(*p){ \
					case c1: \
					case c2: \
						state=(new_state_c); \
						break; \
					case d1: \
					case d2: \
						state=(new_state_d); \
						break; \
					u_param_common_cases; \
					default: \
						state=URI_PARAM_P; \
				} \
				break
#define param_switch_bigger(old_state, c1, c2, d1, d2, e1, e2, new_state_c, new_state_d, new_state_e) \
			case old_state : \
				switch(*p){ \
					case c1: \
					case c2: \
						state=(new_state_c); \
						break; \
					case d1: \
					case d2: \
						state=(new_state_d); \
						break; \
					case e1: \
					case e2: \
						state=(new_state_e); \
						break; \
					u_param_common_cases; \
					default: \
						state=URI_PARAM_P; \
				} \
				break
#define value_switch(old_state, c1, c2, new_state) \
			case old_state: \
				switch(*p){ \
					case c1: \
					case c2: \
						state=(new_state); \
						break; \
					value_common_cases; \
					default: \
						state=URI_VAL_P; \
				} \
				break
#define value_switch_big(old_state, c1, c2, d1, d2, new_state_c, new_state_d) \
			case old_state: \
				switch(*p){ \
					case c1: \
					case c2: \
						state=(new_state_c); \
						break; \
					case d1: \
					case d2: \
						state=(new_state_d); \
						break; \
					value_common_cases; \
					default: \
						state=URI_VAL_P; \
				} \
				break

#define transport_fin(c_state, proto_no) \
			case c_state: \
				switch(*p){ \
					case '@': \
						still_at_user; \
						break; \
					semicolon_case; \
						param_set(b, v); \
						uri->proto=(proto_no); \
						break; \
					question_case; \
						param_set(b, v); \
						uri->proto=(proto_no); \
						break; \
					colon_case;  \
					default: \
						state=URI_VAL_P; \
						break; \
				} \
				break



	/* init */
	end=buf+len;
	p=buf+4;
	found_user=0;
	error_headers=0;
	b=v=0;
	param=param_val=0;
	pass=0;
	password.s = 0;
	password.len = 0;
	port_no=0;
	state=URI_INIT;
	memset(uri, 0, sizeof(struct sip_uri)); /* zero it all, just to be sure*/
	/*look for sip:, sips: or tel:*/
	if (len<5) goto error_too_short;
	scheme=buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24);
	scheme|=0x20202020;
	if (scheme==SIP_SCH){
		uri->type=SIP_URI_T;
	}else if(scheme==SIPS_SCH){
		if(buf[4]==':'){ p++; uri->type=SIPS_URI_T;}
		else goto error_bad_uri;
	}else if (scheme==TEL_SCH){
		uri->type=TEL_URI_T;
	}else if (scheme==URN_SERVICE_SCH){
		if (memcmp(buf+3,URN_SERVICE_STR,URN_SERVICE_STR_LEN) == 0) {
			p+= URN_SERVICE_STR_LEN-1;
			uri->type=URN_SERVICE_URI_T;
		}
		else if (memcmp(buf+3,URN_NENA_SERVICE_STR,URN_NENA_SERVICE_STR_LEN) == 0) {
			p+= URN_NENA_SERVICE_STR_LEN-1;
			uri->type=URN_NENA_SERVICE_URI_T;
		}else goto error_bad_uri;
	}else goto error_bad_uri;

	s=p;
	for(;p<end; p++){
		switch((unsigned char)state){
			case URI_INIT:
				switch(*p){
					case '[':
						/* uri =  [ipv6address]... */
						state=URI_HOST6_P;
						s=p;
						break;
					case ']':
						/* invalid, no uri can start with ']' */
					case ':':
						/* the same as above for ':' */
						goto error_bad_char;
					case '@': /* error no user part */
						goto error_bad_char;
					default:
						state=URI_USER;
				}
				break;
			case URI_USER:
				switch(*p){
					case '@':
						/* found the user*/
						uri->user.s=s;
						uri->user.len=p-s;
						state=URI_HOST;
						found_user=1;
						s=p+1; /* skip '@' */
						break;
					case ':':
						/* found the user, or the host? */
						uri->user.s=s;
						uri->user.len=p-s;
						state=URI_PASSWORD;
						s=p+1; /* skip ':' */
						break;
					case ';':
						/* this could be still the user or
						 * params?*/
						uri->host.s=s;
						uri->host.len=p-s;
						state=URI_PARAM;
						s=p+1;
						break;
					case '?': /* still user or headers? */
						uri->host.s=s;
						uri->host.len=p-s;
						state=URI_HEADERS;
						s=p+1;
						break;
						/* almost anything permitted in the user part */
					case '[':
					case ']': /* the user part cannot contain "[]" */
						goto error_bad_char;
				}
				break;
			case URI_PASSWORD: /* this can also be the port (missing user)*/
				switch(*p){
					case '@':
						/* found the password*/
						uri->passwd.s=s;
						uri->passwd.len=p-s;
						port_no=0;
						state=URI_HOST;
						found_user=1;
						s=p+1; /* skip '@' */
						break;
					case ';':
						/* upps this is the port */
						uri->port.s=s;
						uri->port.len=p-s;
						uri->port_no=port_no;
						/* user contains in fact the host */
						uri->host.s=uri->user.s;
						uri->host.len=uri->user.len;
						uri->user.s=0;
						uri->user.len=0;
						state=URI_PARAM;
						found_user=1; /*  there is no user part */
						s=p+1;
						break;
					case '?':
						/* upps this is the port */
						uri->port.s=s;
						uri->port.len=p-s;
						uri->port_no=port_no;
						/* user contains in fact the host */
						uri->host.s=uri->user.s;
						uri->host.len=uri->user.len;
						uri->user.s=0;
						uri->user.len=0;
						state=URI_HEADERS;
						found_user=1; /*  there is no user part */
						s=p+1;
						break;
					case_port('0', port_no);
					case_port('1', port_no);
					case_port('2', port_no);
					case_port('3', port_no);
					case_port('4', port_no);
					case_port('5', port_no);
					case_port('6', port_no);
					case_port('7', port_no);
					case_port('8', port_no);
					case_port('9', port_no);
					case '[':
					case ']':
					case ':':
						goto error_bad_char;
					default:
						/* it can't be the port, non number found */
						port_no=0;
						state=URI_PASSWORD_ALPHA;
				}
				break;
			case URI_PASSWORD_ALPHA:
				switch(*p){
					case '@':
						/* found the password*/
						uri->passwd.s=s;
						uri->passwd.len=p-s;
						state=URI_HOST;
						found_user=1;
						s=p+1; /* skip '@' */
						break;
					case ';': /* contains non-numbers => cannot be port no*/
					case '?':
						goto error_bad_port;
					case '[':
					case ']':
					case ':':
						goto error_bad_char;
				}
				break;
			case URI_HOST:
				switch(*p){
					case '[':
						state=URI_HOST6_P;
						break;
					case ':':
					case ';':
					case '?': /* null host name ->invalid */
					case '&':
					case '@': /*chars not allowed in hosts names */
						goto error_bad_host;
					default:
						state=URI_HOST_P;
				}
				break;
			case URI_HOST_P:
				switch(*p){
					check_host_end;
				}
				break;
			case URI_HOST6_END:
				switch(*p){
					check_host_end;
					default: /*no chars allowed after [ipv6] */
						goto error_bad_host;
				}
				break;
			case URI_HOST6_P:
				switch(*p){
					case ']':
						state=URI_HOST6_END;
						break;
					case '[':
					case '&':
					case '@':
					case ';':
					case '?':
						goto error_bad_host;
				}
				break;
			case URI_PORT:
				switch(*p){
					case ';':
						uri->port.s=s;
						uri->port.len=p-s;
						uri->port_no=port_no;
						state=URI_PARAM;
						s=p+1;
						break;
					case '?':
						uri->port.s=s;
						uri->port.len=p-s;
						uri->port_no=port_no;
						state=URI_HEADERS;
						s=p+1;
						break;
					case_port('0', port_no);
					case_port('1', port_no);
					case_port('2', port_no);
					case_port('3', port_no);
					case_port('4', port_no);
					case_port('5', port_no);
					case_port('6', port_no);
					case_port('7', port_no);
					case_port('8', port_no);
					case_port('9', port_no);
					case '&':
					case '@':
					case ':':
					default:
						goto error_bad_port;
				}
				break;
			case URI_PARAM: /* beginning of a new param */
				switch(*p){
					param_common_cases;
					/* recognized params */
					case 't':
					case 'T':
						b=p;
						state=PT_T;
						break;
					case 'u':
					case 'U':
						b=p;
						state=PU_U;
						break;
					case 'm':
					case 'M':
						b=p;
						state=PM_M;
						break;
					case 'l':
					case 'L':
						b=p;
						state=PLR_L;
						break;
					case 'g':
					case 'G':
						b=p;
						state=PG_G;
						break;
					case 'r':
					case 'R':
						b=p;
						state=PR2_R;
						break;
					case 'p':
					case 'P':
						b=p;
						state=PN_P;
						break;
					default:
						b=p;
						state=URI_PARAM_P;
				}
				break;
			case URI_PARAM_P: /* ignore current param */
				/* supported params:
				 *  maddr, transport, ttl, lr, user, method, r2  */
				switch(*p){
					u_param_common_cases;
					case '=':
						v=p + 1;
						state=URI_PARAM_VAL_P;
						break;
				};
				break;
			case URI_PARAM_VAL_P: /* value of the ignored current param */
				switch(*p){
					u_param_common_cases;
				};
				break;
			/* ugly but fast param names parsing */
			/*transport */
			param_switch_big(PT_T,  'r', 'R', 't', 'T', PT_R, PTTL_T2);
			param_switch(PT_R,  'a', 'A', PT_A);
			param_switch(PT_A,  'n', 'N', PT_N);
			param_switch(PT_N,  's', 'S', PT_S);
			param_switch(PT_S,  'p', 'P', PT_P);
			param_switch(PT_P,  'o', 'O', PT_O);
			param_switch(PT_O,  'r', 'R', PT_R2);
			param_switch(PT_R2, 't', 'T', PT_T2);
			param_switch1(PT_T2, '=',  PT_eq);
			/* value parsing */
			case PT_eq:
				param=&uri->transport;
				param_val=&uri->transport_val;
				uri->proto = PROTO_OTHER;
				switch (*p){
					param_common_cases;
					case 'u':
					case 'U':
						v=p;
						state=VU_U;
						break;
					case 't':
					case 'T':
						v=p;
						state=VT_T;
						break;
					case 's':
					case 'S':
						v=p;
						state=VS_S;
						break;
					case 'w':
					case 'W':
						v=p;
						state=VW_W;
						break;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;
				/* generic value */
			case URI_VAL_P:
				switch(*p){
					value_common_cases;
				}
				break;
			/* udp */
			value_switch(VU_U,  'd', 'D', VU_D);
			value_switch(VU_D,  'p', 'P', VU_P_FIN);
			transport_fin(VU_P_FIN, PROTO_UDP);
			/* tcp */
			value_switch_big(VT_T,  'c', 'C', 'l', 'L', VT_C, VTLS_L);
			value_switch(VT_C,  'p', 'P', VT_P_FIN);
			transport_fin(VT_P_FIN, PROTO_TCP);
			/* tls */
			value_switch(VTLS_L, 's', 'S', VTLS_S_FIN);
			transport_fin(VTLS_S_FIN, PROTO_TLS);
			/* sctp */
			value_switch(VS_S, 'c', 'C', VS_C);
			value_switch(VS_C, 't', 'T', VS_T);
			value_switch(VS_T, 'p', 'P', VS_P_FIN);
			transport_fin(VS_P_FIN, PROTO_SCTP);
			/* ws */
			value_switch(VW_W, 's', 'S', VW_S);
			case VW_S:
				if (*p == 's' || *p == 'S') {
					state=(VWS_S_FIN);
					break;
				}
				/* if not a 's' transiting to VWS_S_FIN, fallback
				 * to testing as existing VW_S_FIN (NOTE the missing break) */
				state=(VW_S_FIN);
			transport_fin(VW_S_FIN, PROTO_WS);
			transport_fin(VWS_S_FIN, PROTO_WSS);

			/* ttl */
			param_switch(PTTL_T2,  'l', 'L', PTTL_L);
			param_switch1(PTTL_L,  '=', PTTL_eq);
			case PTTL_eq:
				param=&uri->ttl;
				param_val=&uri->ttl_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* user param */
			param_switch(PU_U, 's', 'S', PU_S);
			param_switch(PU_S, 'e', 'E', PU_E);
			param_switch(PU_E, 'r', 'R', PU_R);
			param_switch1(PU_R, '=', PU_eq);
			case PU_eq:
				param=&uri->user_param;
				param_val=&uri->user_param_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* method*/
			param_switch_big(PM_M, 'e', 'E', 'a', 'A', PM_E, PMA_A);
			param_switch(PM_E, 't', 'T', PM_T);
			param_switch(PM_T, 'h', 'H', PM_H);
			param_switch(PM_H, 'o', 'O', PM_O);
			param_switch(PM_O, 'd', 'D', PM_D);
			param_switch1(PM_D, '=', PM_eq);
			case PM_eq:
				param=&uri->method;
				param_val=&uri->method_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/*maddr*/
			param_switch(PMA_A,  'd', 'D', PMA_D);
			param_switch(PMA_D,  'd', 'D', PMA_D2);
			param_switch(PMA_D2, 'r', 'R', PMA_R);
			param_switch1(PMA_R, '=', PMA_eq);
			case PMA_eq:
				param=&uri->maddr;
				param_val=&uri->maddr_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* lr */
			param_switch(PLR_L,  'r', 'R', PLR_R_FIN);
			case PLR_R_FIN:
				switch(*p){
					case '@':
						still_at_user;
						break;
					case '=':
						state=PLR_eq;
						break;
					semicolon_case;
						uri->lr.s=b;
						uri->lr.len=(p-b);
						break;
					question_case;
						uri->lr.s=b;
						uri->lr.len=(p-b);
						break;
					colon_case;
						break;
					default:
						state=URI_PARAM_P;
				}
				break;
				/* handle lr=something case */
			case PLR_eq:
				param=&uri->lr;
				param_val=&uri->lr_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* r2 */
			param_switch1(PR2_R,  '2', PR2_2_FIN);
			case PR2_2_FIN:
				switch(*p){
					case '@':
						still_at_user;
						break;
					case '=':
						state=PR2_eq;
						break;
					semicolon_case;
						uri->r2.s=b;
						uri->r2.len=(p-b);
						break;
					question_case;
						uri->r2.s=b;
						uri->r2.len=(p-b);
						break;
					colon_case;
						break;
					default:
						state=URI_PARAM_P;
				}
				break;
				/* handle r2=something case */
			case PR2_eq:
				param=&uri->r2;
				param_val=&uri->r2_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;


			/* gr */
			param_switch(PG_G,  'r', 'R', PG_G_FIN);
			case PG_G_FIN:
				switch(*p){
					case '@':
						still_at_user;
						break;
					case '=':
						state=PG_eq;
						break;
					semicolon_case;
						uri->gr.s=b;
						uri->gr.len=(p-b);
						break;
					question_case;
						uri->gr.s=b;
						uri->gr.len=(p-b);
						break;
					colon_case;
						break;
					default:
						state=URI_PARAM_P;
				}
				break;
				/* handle gr=something case */
			case PG_eq:
				param=&uri->gr;
				param_val=&uri->gr_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;


			/* pn-* */
			param_switch(PN_P, 'n', 'N', PN_N);
			param_switch1(PN_N, '-', PN_dash);
			param_switch(PN_dash, 'p', 'P', PN_P2);

			param_switch_bigger(PN_P2, 'r', 'R', 'a', 'A', 'u', 'U',
			                    PN_PR, PN3_A, PN4_U);
			param_switch_big(PN_PR, 'o', 'O', 'i', 'I', PN1_O, PN2_I);

			/* pn-provider */
			param_switch(PN1_O, 'v', 'V', PN1_V);
			param_switch(PN1_V, 'i', 'I', PN1_I);
			param_switch(PN1_I, 'd', 'D', PN1_D);
			param_switch(PN1_D, 'e', 'E', PN1_E);
			param_switch(PN1_E, 'r', 'R', PN1_FIN);
			case PN1_FIN:
				param=&uri->pn_provider;
				switch(*p){
					case '@':
						still_at_user;
						break;
					case '=':
						state=PN1_eq;
						break;
					semicolon_case;
						uri->pn_provider.s=b;
						uri->pn_provider.len=(p-b);
						break;
					question_case;
						uri->pn_provider.s=b;
						uri->pn_provider.len=(p-b);
						break;
					colon_case;
						break;
					default:
						state=URI_PARAM_P;
				}
				break;
				/* handle pn-provider=something case */
			case PN1_eq:
				param=&uri->pn_provider;
				param_val=&uri->pn_provider_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* pn-prid */
			param_switch(PN2_I, 'd', 'D', PN2_D);
			param_xswitch1(PN2_D, '=', PN2_eq);
			case PN2_eq:
				param=&uri->pn_prid;
				param_val=&uri->pn_prid_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* pn-param */
			param_switch(PN3_A, 'r', 'R', PN3_R);
			param_switch(PN3_R, 'a', 'A', PN3_A2);
			param_switch(PN3_A2, 'm', 'M', PN3_M);
			param_xswitch1(PN3_M, '=', PN3_eq);
			case PN3_eq:
				param=&uri->pn_param;
				param_val=&uri->pn_param_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;

			/* pn-purr */
			param_switch(PN4_U, 'r', 'R', PN4_R);
			param_switch(PN4_R, 'r', 'R', PN4_R2);
			param_xswitch1(PN4_R2, '=', PN4_eq);
			case PN4_eq:
				param=&uri->pn_purr;
				param_val=&uri->pn_purr_val;
				switch(*p){
					param_common_cases;
					default:
						v=p;
						state=URI_VAL_P;
				}
				break;


			case URI_HEADERS:
				/* for now nobody needs them so we completely ignore the
				 * headers (they are not allowed in request uri) --andrei */
				switch(*p){
					case '@':
						/* yak, we are still at user */
						still_at_user;
						break;
					case ';':
						/* we might be still parsing user, try it */
						if (found_user) goto error_bad_char;
						error_headers=1; /* if this is not the user
											we have an error */
						/* if pass is set => it cannot be user:pass
						 * => error (';') is illegal in a header */
						if (pass) goto error_headers;
						break;
					case ':':
						if (found_user==0){
							/*might be pass but only if user not found yet*/
							if (pass){
								found_user=1; /* no user */
								pass=0;
							}else{
								pass=p;
							}
						}
						break;
					case '?':
						if (pass){
							found_user=1; /* no user, pass cannot contain '?'*/
							pass=0;
						}
						break;
				}
				break;
			default:
				goto error_bug;
		}
	}

	/*end of uri */
	switch (state){
		case URI_INIT: /* error empty uri */
			goto error_too_short;
		case URI_USER:
			/* this is the host, it can't be the user */
			if (found_user) goto error_bad_uri;
			uri->host.s=s;
			uri->host.len=p-s;
			state=URI_HOST;
			break;
		case URI_PASSWORD:
			/* this is the port, it can't be the passwd */
			if (found_user) goto error_bad_port;
			uri->port.s=s;
			uri->port.len=p-s;
			uri->port_no=port_no;
			uri->host=uri->user;
			uri->user.s=0;
			uri->user.len=0;
			break;
		case URI_PASSWORD_ALPHA:
			/* this is the port, it can't be the passwd */
			goto error_bad_port;
		case URI_HOST_P:
		case URI_HOST6_END:
			uri->host.s=s;
			uri->host.len=p-s;
			break;
		case URI_HOST: /* error: null host */
		case URI_HOST6_P: /* error: unterminated ipv6 reference*/
			goto error_bad_host;
		case URI_PORT:
			uri->port.s=s;
			uri->port.len=p-s;
			uri->port_no=port_no;
			break;
		case URI_PARAM:
		case URI_PARAM_P:
		case URI_PARAM_VAL_P:
			u_param_set(b, v);
		/* intermediate param states */
		case PT_T: /* transport */
		case PT_R:
		case PT_A:
		case PT_N:
		case PT_S:
		case PT_P:
		case PT_O:
		case PT_R2:
		case PT_T2:
		case PT_eq: /* ignore empty transport params */
		case PTTL_T2: /* ttl */
		case PTTL_L:
		case PTTL_eq:
		case PU_U:  /* user */
		case PU_S:
		case PU_E:
		case PU_R:
		case PU_eq:
		case PM_M: /* method */
		case PM_E:
		case PM_T:
		case PM_H:
		case PM_O:
		case PM_D:
		case PM_eq:
		case PLR_L: /* lr */
		case PR2_R:  /* r2 */
		case PG_G: /* gr */
			uri->params.s=s;
			uri->params.len=p-s;
			break;
		/* fin param states */
		case PLR_R_FIN:
		case PLR_eq:
			uri->params.s=s;
			uri->params.len=p-s;
			uri->lr.s=b;
			uri->lr.len=p-b;
			break;
		case PR2_2_FIN:
		case PR2_eq:
			uri->params.s=s;
			uri->params.len=p-s;
			uri->r2.s=b;
			uri->r2.len=p-b;
			break;
		case PG_G_FIN:
		case PG_eq:
			uri->params.s=s;
			uri->params.len=p-s;
			uri->gr.s=b;
			uri->gr.len=p-b;
			break;
		case PN1_FIN:
		case PN1_eq:
			uri->params.s=s;
			uri->params.len=p-s;
			uri->pn_provider.s=b;
			uri->pn_provider.len=p-b;
			break;
		case URI_VAL_P:
		/* intermediate value states */
		case VU_U:
		case VU_D:
		case VT_T:
		case VT_C:
		case VTLS_L:
		case VS_S:
		case VS_C:
		case VW_W:
		case VS_T:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			break;
		/* fin value states */
		case VU_P_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_UDP;
			break;
		case VT_P_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_TCP;
			break;
		case VTLS_S_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_TLS;
			break;
		case VS_P_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_SCTP;
			break;
		case VW_S:
		case VW_S_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_WS;
			break;
		case VWS_S_FIN:
			uri->params.s=s;
			uri->params.len=p-s;
			param_set(b, v);
			uri->proto=PROTO_WSS;
			break;
		/* headers */
		case URI_HEADERS:
			uri->headers.s=s;
			uri->headers.len=p-s;
			if (error_headers) goto error_headers;
			break;
		/* intermediate PN param states */
		case PN_P:
		case PN_N:
		case PN_dash:
		case PN_P2:
		case PN_PR:
		case PN1_O:
		case PN1_V:
		case PN1_I:
		case PN1_D:
		case PN1_E:
		case PN2_I:
		case PN3_A:
		case PN3_R:
		case PN3_A2:
		case PN4_U:
		case PN4_R:
			uri->params.s=s;
			uri->params.len=p-s;
			break;
		case PN2_D:
		case PN2_eq:
		case PN3_M:
		case PN3_eq:
		case PN4_R2:
		case PN4_eq:
			goto error_bad_uri;
		default:
			goto error_bug;
	}
	switch(uri->type){
		case TEL_URI_T:
		case TELS_URI_T:
			/* fix tel uris, move the number in uri and empty the host */
			uri->user=uri->host;
			uri->host.s="";
			uri->host.len=0;
			break;
		case SIP_URI_T:
		case SIPS_URI_T:
		case URN_SERVICE_URI_T:
			/* nothing to do for these URIs */
			break;
		case URN_NENA_SERVICE_URI_T:
			uri->user.s=0;
			uri->user.len=0;
			uri->host.s="";
			uri->host.len=0;
			break;
		case ERROR_URI_T:
			LM_ERR("unexpected error (BUG?)\n");
			goto error_bad_uri;
			break; /* do nothing, avoids a compilation warning */
	}
#ifdef EXTRA_DEBUG
	/* do stuff */
	LM_DBG("parsed uri:\n type=%d user=<%.*s>(%d)\n passwd=<%.*s>(%d)\n"
			" host=<%.*s>(%d)\n port=<%.*s>(%d): %d\n params=<%.*s>(%d)\n"
			" headers=<%.*s>(%d)\n",
			uri->type,
			uri->user.len, ZSW(uri->user.s), uri->user.len,
			uri->passwd.len, ZSW(uri->passwd.s), uri->passwd.len,
			uri->host.len, ZSW(uri->host.s), uri->host.len,
			uri->port.len, ZSW(uri->port.s), uri->port.len, uri->port_no,
			uri->params.len, ZSW(uri->params.s), uri->params.len,
			uri->headers.len, ZSW(uri->headers.s), uri->headers.len
		);
	LM_DBG(" uri params:\n   transport=<%.*s>, val=<%.*s>, proto=%d\n",
			uri->transport.len, ZSW(uri->transport.s), uri->transport_val.len,
			ZSW(uri->transport_val.s), uri->proto);
	LM_DBG("   user-param=<%.*s>, val=<%.*s>\n",
			uri->user_param.len, ZSW(uri->user_param.s),
			uri->user_param_val.len, ZSW(uri->user_param_val.s));
	LM_DBG("   method=<%.*s>, val=<%.*s>\n",
			uri->method.len, ZSW(uri->method.s),
			uri->method_val.len, ZSW(uri->method_val.s));
	LM_DBG("   ttl=<%.*s>, val=<%.*s>\n",
			uri->ttl.len, ZSW(uri->ttl.s),
			uri->ttl_val.len, ZSW(uri->ttl_val.s));
	LM_DBG("   maddr=<%.*s>, val=<%.*s>\n",
			uri->maddr.len, ZSW(uri->maddr.s),
			uri->maddr_val.len, ZSW(uri->maddr_val.s));
	LM_DBG("   lr=<%.*s>, val=<%.*s>\n", uri->lr.len, ZSW(uri->lr.s),
			uri->lr_val.len, ZSW(uri->lr_val.s));
	LM_DBG("   r2=<%.*s>, val=<%.*s>\n", uri->r2.len, ZSW(uri->r2.s),
			uri->r2_val.len, ZSW(uri->r2_val.s));
	for(i=0; i<URI_MAX_U_PARAMS && uri->u_name[i].s; i++)
		LM_DBG("uname=[%p]-><%.*s> uval=[%p]-><%.*s>\n",
			uri->u_name[i].s, uri->u_name[i].len, uri->u_name[i].s,
			uri->u_val[i].s, uri->u_val[i].len, uri->u_val[i].s);
	if (i!=uri->u_params_no)
		LM_ERR("inconsisten # of u_name:[%d]!=[%d]\n", i, uri->u_params_no);
#endif
	return 0;

error_too_short:
	LM_ERR("uri too short: <%.*s> (%d)\n",
			len, ZSW(buf), len);
	goto error_exit;
error_bad_char:
	LM_ERR("bad char '%c' in state %d"
			" parsed: <%.*s> (%d) / <%.*s> (%d)\n",
			*p, state, (int)(p-buf), ZSW(buf), (int)(p-buf),
			len, ZSW(buf), len);
	goto error_exit;
error_bad_host:
	LM_ERR("bad host in uri (error at char %c in"
			" state %d) parsed: <%.*s>(%d) /<%.*s> (%d)\n",
			*p, state, (int)(p-buf), ZSW(buf), (int)(p-buf),
			len, ZSW(buf), len);
	goto error_exit;
error_bad_port:
	LM_ERR("bad port in uri (error at char %c in"
			" state %d) parsed: <%.*s>(%d) /<%.*s> (%d)\n",
			*p, state, (int)(p-buf), ZSW(buf), (int)(p-buf),
			len, ZSW(buf), len);
	goto error_exit;
error_bad_uri:
	LM_ERR("bad uri, state %d parsed: <%.*s> (%d) / <%.*s> (%d)\n",
			 state, (int)(p-buf), ZSW(buf), (int)(p-buf), len,
			 ZSW(buf), len);
	goto error_exit;
error_headers:
	LM_ERR("bad uri headers: <%.*s>(%d) / <%.*s>(%d)\n",
			uri->headers.len, ZSW(uri->headers.s), uri->headers.len,
			len, ZSW(buf), len);
	goto error_exit;
error_bug:
	LM_CRIT("bad state %d parsed: <%.*s> (%d) / <%.*s> (%d)\n",
			 state, (int)(p-buf), ZSW(buf), (int)(p-buf), len, ZSW(buf), len);
error_exit:
	ser_error=E_BAD_URI;
	uri->type=ERROR_URI_T;
	update_stat(bad_URIs, 1);
	return E_BAD_URI;
}


int parse_sip_msg_uri(struct sip_msg* msg)
{
	char* tmp;
	int tmp_len;
	if (msg->parsed_uri_ok) return 1;

	if (msg->new_uri.s){
		tmp=msg->new_uri.s;
		tmp_len=msg->new_uri.len;
	}else{
		tmp=msg->first_line.u.request.uri.s;
		tmp_len=msg->first_line.u.request.uri.len;
	}
	if (parse_uri(tmp, tmp_len, &msg->parsed_uri)<0){
		LM_ERR("bad uri <%.*s>\n", tmp_len, tmp);
		msg->parsed_uri_ok=0;
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM, "error parsing r-uri");
		set_err_reply(400, "bad r-uri");
		return -1;
	}
	msg->parsed_uri_ok=1;
	return 0;
}


int parse_orig_ruri(struct sip_msg* msg)
{
	str *uri;

	if (msg->parsed_orig_ruri_ok)
		return 1;

	uri = &REQ_LINE(msg).uri;

	if (parse_uri(uri->s, uri->len, &msg->parsed_orig_ruri)<0) {
		LM_ERR("bad uri <%.*s>\n", uri->len, ZSW(uri->s));
		msg->parsed_orig_ruri_ok = 0;
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
				"error parsing incoming uri");
		set_err_reply(400, "bad i-uri");
		return -1;
	}

	msg->parsed_orig_ruri_ok = 1;
	return 0;
}

#define compare_uri_val(field,cmpfunc) \
	do { \
		if (first.field.len != second.field.len) \
		{ \
			LM_DBG("Different URI field - " #field "\n"); \
			return 1; \
		} \
		else \
		{ \
			if (first.field.len != 0) \
				if (cmpfunc(first.field.s,second.field.s,first.field.len)) \
				{ \
					LM_DBG("Different URI field - " #field "\n"); \
					return 1; \
				} \
		} \
	} while (0)

/* Compare 2 SIP URIs according to RFC 3261
 *
 * Return value : 0 if URIs match
 *				  1 if URIs don't match
 *				 -1 if errors have occurred
 */
int compare_uris(str *raw_uri_a,struct sip_uri* parsed_uri_a,
					str *raw_uri_b,struct sip_uri *parsed_uri_b)
{
	#define UNESCAPED_BUF_LEN 1024
	char unescaped_a[UNESCAPED_BUF_LEN], unescaped_b[UNESCAPED_BUF_LEN];

	str unescaped_userA={unescaped_a, UNESCAPED_BUF_LEN};
	str unescaped_userB={unescaped_b, UNESCAPED_BUF_LEN};

	struct sip_uri first;
	struct sip_uri second;
	char matched[URI_MAX_U_PARAMS];
	int i,j;

	if ( (!raw_uri_a && !parsed_uri_a) || (!raw_uri_b && !parsed_uri_b) )
	{
		LM_ERR("Provide either a raw or parsed form of a SIP URI\n");
		return -1;
	}

	if (raw_uri_a && raw_uri_b)
	{

		/* maybe we're lucky and straight-forward comparison succeeds */
		if (raw_uri_a->len == raw_uri_b->len)
			if (strncasecmp(raw_uri_a->s,raw_uri_b->s,raw_uri_a->len) == 0)
			{
				LM_DBG("straight-forward URI match\n");
				return 0;
			}
	}

	/* XXX - maybe if we have two parsed sip_uris,
	 * or only one parsed and one raw,
	 * it should be possible to do a straight-forward
	 * URI match ? */

	if (parsed_uri_a)
		first = *parsed_uri_a;
	else
	{
		if (parse_uri(raw_uri_a->s,raw_uri_a->len,&first) < 0)
		{
			LM_ERR("Failed to parse first URI\n");
			return -1;
		}
	}

	if (parsed_uri_b)
		second = *parsed_uri_b;
	else
	{
		if (parse_uri(raw_uri_b->s,raw_uri_b->len,&second) < 0)
		{
			LM_ERR("Failed to parse second URI\n");
			return -1;
		}
	}

	if (first.type != second.type)
	{
		LM_DBG("Different uri types\n");
		return 1;
	}

	if (unescape_user(&first.user, &unescaped_userA) < 0 ||
			unescape_user(&second.user, &unescaped_userB) < 0) {
		LM_ERR("Failed to unescape user!\n");
		return -1;
	}

	first.user = unescaped_userA;
	second.user = unescaped_userB;

	compare_uri_val(user,strncmp);
	compare_uri_val(passwd,strncmp);
	compare_uri_val(host,strncasecmp);
	compare_uri_val(port,strncmp);

	compare_uri_val(transport_val,strncasecmp);
	compare_uri_val(ttl_val,strncasecmp);
	compare_uri_val(user_param_val,strncasecmp);
	compare_uri_val(maddr_val,strncasecmp);
	compare_uri_val(method_val,strncasecmp);
	compare_uri_val(lr_val,strncasecmp);
	compare_uri_val(r2_val,strncasecmp);

	if (first.u_params_no == 0 || second.u_params_no == 0)
		/* one URI doesn't have other params,
		 * automatically all unknown params in other URI match
		 */
		goto headers_check;

	memset(matched,0,URI_MAX_U_PARAMS);

	for (i=0;i<first.u_params_no;i++)
		for (j=0;j<second.u_params_no;j++)
			if (matched[j] == 0 &&
				(first.u_name[i].len == second.u_name[j].len &&
                strncasecmp(first.u_name[i].s,second.u_name[j].s,
							first.u_name[i].len) == 0))
				{
                    /* point of no return - matching unknown parameter values */
					if (first.u_val[i].len != second.u_val[j].len)
					{
						LM_DBG("Different URI param value for param %.*s\n",
								first.u_name[i].len,first.u_name[i].s);
						return 1;
					}
					else
					{
						if (first.u_val[i].len == 0)
						{
							/* no value for unknown params - match */
							matched[j] = 1;
							break;
						}

						if (strncasecmp(first.u_val[i].s,second.u_val[j].s,
							second.u_val[j].len))
						{
							LM_DBG("Different URI param value for param %.*s\n",
								first.u_name[i].len,first.u_name[i].s);
							return 1;
						}
						else
						{
							matched[j] = 1;
							break;
						}
					}
				}

	/* got here, it means all unknown params in first URI have been resolved
		=> first URI matched second URI, and the other way around
	*/

headers_check:
	 /* XXX Do we really care ? */
	compare_uri_val(headers,strncasecmp);
	return 0;
}
