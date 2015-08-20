/*
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 * 2011-06-28  initial implementation (Ovidiu Sas)
 */

#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "../ut.h"
#include "../errinfo.h"
#include "../mem/mem.h"
#include "parse_replaces.h"

/*
 * This method is used to parse Replaces header body.
 *
 * params: buf : pointer to Replaces body
 *         buf_len : Replaces body length
 *         replaces_b : pointer to parsing structure
 * returns 0 on success,
 *        -1 on failure.
 */
int parse_replaces_body(char* buf, int buf_len, struct replaces_body* replaces_b)
{
	enum states {CLID, PARAM, PARAM_P, PARAM_VAL_P, VAL_P,
			/* param states */
			/* to-tag */
			/* 5 - 11 */
			TT_T, TT_O, TT__, TT_T2, TT_A, TT_G, TT_eq,
			/* from-tag */
			/* 12 - 20 */
			FT_F, FT_R, FT_O, FT_M, FT__, FT_T, FT_A, FT_G, FT_eq,
			/* early-only */
			/* 21 - 31 */
			EO_E, EO_A, EO_R, EO_L, EO_Y, EO__, EO_O, EO_N, EO_L2, EO_Y2_FIN, EO_eq
	};
	register enum states state;
	char* b = NULL;	/* current param val */
	char* v = NULL;	/* current param val */
	str* param = NULL;
	str* param_val = NULL;
	register char* p;
	char* end;


#define param_set(t_start, v_start)			\
			param->s=(t_start);		\
			param->len=(p-(t_start));	\
			param_val->s=(v_start);		\
			param_val->len=(p-(v_start))

#define u_param_set(t_start, v_start)			\
			/* FIXME: save unknown params */


#define semicolon_case					\
			case';':			\
				state=PARAM /* new param */


#define param_common_cases				\
			semicolon_case;			\
				break

#define u_param_common_cases				\
			semicolon_case;			\
				u_param_set(b, v);	\
				break


#define param_single_switch(old_state, c1, new_state)	\
		case old_state:				\
			switch(*p){			\
			case c1:			\
				state=(new_state);	\
				break;			\
			u_param_common_cases;		\
			default:			\
				state=PARAM_P;		\
			}				\
			break

#define param_switch(old_state, c1, c2, new_state)	\
		case old_state:				\
			switch(*p){			\
			case c1:			\
			case c2:			\
				state=(new_state);	\
				break;			\
			u_param_common_cases;		\
			default:			\
				state=PARAM_P;		\
			}				\
			break

#define param_switch1(old_state, c1, new_state)		\
		case old_state:				\
			switch(*p){			\
			case c1:			\
				state=(new_state);	\
				break;			\
			param_common_cases;		\
			default:			\
				state=PARAM_P;		\
			}				\
			break


#define value_common_cases				\
			semicolon_case;			\
				param_set(b, v);	\
				break


#define value_switch(old_state, c1, c2, new_state)	\
		case old_state:				\
			switch(*p){			\
			case c1:			\
			case c2:			\
				state=(new_state);	\
				break;			\
			value_common_cases;		\
			default:			\
				state=VAL_P;		\
			}				\
			break


	/* init */
	p = buf;
	end = buf + buf_len;
	state = CLID;
	memset(replaces_b, 0, sizeof(struct replaces_body));
	for(;p<end; p++){
		//LM_DBG("got[%c] in state[%d]\n",*p,state);
		switch((unsigned char)state){
		case CLID:
			switch(*p){
			case ';':
				replaces_b->callid_val.s=buf;
				replaces_b->callid_val.len=p-buf;
				state = PARAM;
				break;
			}
			break;
		case PARAM: /* beginning of a new param */
			switch(*p){
			param_common_cases;
			/* recognized params */
			case 't':
			case 'T':
				b = p;
				state=TT_T;
				break;
			case 'f':
			case 'F':
				b = p;
				state=FT_F;
				break;
			case 'e':
			case 'E':
				b = p;
				state=EO_E;
				break;
			default:
				b = p;
				state=PARAM;
			}
			break;
		case PARAM_P: /* ignore current param */
			/* supported params: to-tag, from-tag, early-only */
			switch(*p){
			u_param_common_cases;
			case '=':
				v=p+1;
				state=PARAM_VAL_P;
				break;
			};
			break;
		case PARAM_VAL_P: /* value of the ignored current param */
			switch(*p){
			u_param_common_cases;
			};
			break;
		case VAL_P:
			switch(*p){
			value_common_cases;
			}
			break;

		/* early-only param */
		param_switch(EO_E, 'a', 'A', EO_A);
		param_switch(EO_A, 'r', 'R', EO_R);
		param_switch(EO_R, 'l', 'L', EO_L);
		param_switch(EO_L, 'y', 'Y', EO_Y);
		param_single_switch(EO_Y, '-', EO__);
		param_switch(EO__, 'o', 'O', EO_O);
		param_switch(EO_O, 'n', 'N', EO_N);
		param_switch(EO_N, 'l', 'L', EO_L2);
		param_switch(EO_L2, 'y', 'Y', EO_Y2_FIN);
		case EO_Y2_FIN:
			switch(*p){
			case '=':
				state = EO_eq;
				break;
			semicolon_case;
				replaces_b->early_only.s=b;
				replaces_b->early_only.len=(p-b);
				break;
			default:
				state=PARAM_P;
			}
			break;
			/* handle early-only=something case */
		case EO_eq:
			param = &replaces_b->early_only;
			param_val = &replaces_b->early_only_val;
			switch(*p){
			param_common_cases;
			default:
				v=p;
				state = VAL_P;
			}
			break;

		/* from-tag param */
		param_switch(FT_F, 'r', 'R', FT_R);
		param_switch(FT_R, 'o', 'O', FT_O);
		param_switch(FT_O, 'm', 'M', FT_M);
		param_single_switch(FT_M, '-', FT__);
		param_switch(FT__, 't', 'T', FT_T);
		param_switch(FT_T, 'a', 'A', FT_A);
		param_switch(FT_A, 'g', 'G', FT_G);
		param_switch1(FT_G, '=', FT_eq);
		case FT_eq:
			param = &replaces_b->from_tag;
			param_val = &replaces_b->from_tag_val;
			switch(*p){
			param_common_cases;
			default:
				v=p;
				state = VAL_P;
			}
			break;

		/* to-tag param */
		param_switch(TT_T, 'o', 'O', TT_O);
		param_single_switch(TT_O, '-', TT__);
		param_switch(TT__, 't', 'T', TT_T2);
		param_switch(TT_T2, 'a', 'A', TT_A);
		param_switch(TT_A, 'g', 'G', TT_G);
		param_switch1(TT_G, '=', TT_eq);
		case TT_eq:
			param = &replaces_b->to_tag;
			param_val = &replaces_b->to_tag_val;
			switch(*p){
			param_common_cases;
			default:
				v=p;
				state = VAL_P;
			}
			break;

		default:
			LM_CRIT("bad state %d parsed: <%.*s> (%d) / <%.*s> (%d)\n",
			state, (int)(p-buf), ZSW(buf), (int)(p-buf), buf_len, ZSW(buf), buf_len);
			return -1;
		}
	}

	switch(state){
	case CLID:
		replaces_b->callid_val.s=buf;
		replaces_b->callid_val.len=p-buf;
		break;
	case PARAM:
	case PARAM_P:
	case PARAM_VAL_P:
		u_param_set(b, v);
	/* intermediate param states */
	case EO_E: /* early-only */
	case EO_A:
	case EO_R:
	case EO_L:
	case EO_Y:
	case EO__:
	case EO_O:
	case EO_N:
	case EO_L2:
	case FT_F: /* from-tag */
	case FT_R:
	case FT_O:
	case FT_M:
	case FT__:
	case FT_T:
	case FT_A:
	case FT_G:
	case FT_eq: /* ignore empty from-tag params */
	case TT_T: /* to-tag */
	case TT_O:
	case TT__:
	case TT_T2:
	case TT_A:
	case TT_G:
	case TT_eq: /* ignore empty to-tag params */
		break;
	/* fin param states */
	case EO_Y2_FIN:
	case EO_eq:
		replaces_b->early_only.s=b;
		replaces_b->early_only.len=p-b;
		break;
	case VAL_P:
		param_set(b, v);
		break;

	default:
		LM_CRIT("bad state %d parsed: <%.*s> (%d) / <%.*s> (%d)\n",
			state, (int)(p-buf), ZSW(buf), (int)(p-buf), buf_len, ZSW(buf), buf_len);
		return -1;
	}

	return 0;
}

