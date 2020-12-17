/**
 *
 * Copyright (C) 2016 OpenSIPS Foundation
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
 * History
 * -------
 *  2016-09-xx  initial version (rvlad-patrascu)
 */

#include "../../ut.h"
#include "../../pvar.h"
#include "isup.h"

static int iam_params[] = {ISUP_PARM_NATURE_OF_CONNECTION_IND, ISUP_PARM_FORWARD_CALL_IND,
	ISUP_PARM_CALLING_PARTY_CAT, ISUP_PARM_TRANSMISSION_MEDIUM_REQS, ISUP_PARM_CALLED_PARTY_NUM, -1};

static int acm_params[] = {ISUP_PARM_BACKWARD_CALL_IND, -1};

static int frj_params[] = {ISUP_PARM_FACILITY_IND, ISUP_PARM_CAUSE, -1};

static int faa_far_params[] = {ISUP_PARM_FACILITY_IND, -1};

static int con_params[] = {ISUP_PARM_BACKWARD_CALL_IND, -1};

static int rel_params[] = {ISUP_PARM_CAUSE, -1};

static int cpg_params[] = {ISUP_PARM_EVENT_INFO, -1};

static int sus_res_params[] = {ISUP_PARM_SUSPEND_RESUME_IND, -1};

static int sam_params[] = {ISUP_PARM_SUBSEQUENT_NUMBER, -1};

static int usr_params[] = {ISUP_PARM_USER_TO_USER_INFO, -1};

static int isup_empty_params[] = {-1};


struct isup_message_data isup_messages[NO_ISUP_MESSAGES] = {
	{str_init("Initial address"), "IAM", ISUP_IAM, 4, 1, iam_params},
	{str_init("Address complete"), "ACM", ISUP_ACM, 1, 0, acm_params},
	{str_init("Answer"), "ANM", ISUP_ANM, 0, 0, isup_empty_params},
	{str_init("Connect"), "CON", ISUP_CON, 1, 0, con_params},
	{str_init("Release"), "REL", ISUP_REL, 0, 1, rel_params},
	{str_init("Release complete"), "RLC", ISUP_RLC, 0, 0, isup_empty_params},
	{str_init("Call progress"), "CPG", ISUP_CPG, 1, 0, cpg_params},
	{str_init("Facility reject"), "FRJ", ISUP_FRJ, 1, 1, frj_params},
	{str_init("Facility accepted"), "FAA", ISUP_FAA, 1, 0, faa_far_params},
	{str_init("Facility request"), "FAR", ISUP_FAR, 1, 0, faa_far_params},
	{str_init("Confusion"), "CFN", ISUP_CFN, 0, 1, rel_params},
	{str_init("Suspend"), "SUS", ISUP_SUS, 1, 0, sus_res_params},
	{str_init("Resume"), "RES", ISUP_RES, 1, 0, sus_res_params},
	{str_init("Subsequent address"), "SAM", ISUP_SAM, 0, 1, sam_params},
	{str_init("Forward transfer"), "FOT", ISUP_FOT, 0, 0, isup_empty_params},
	{str_init("User-to-user information"), "USR", ISUP_USR, 0, 1, usr_params},
	{str_init("Network resource management"), "NRM", ISUP_NRM, 0, 0, isup_empty_params},
	{str_init("Facility"), "FAC", ISUP_FAC, 0, 0, isup_empty_params},
	{str_init("Identification request"), "IRQ", ISUP_IRQ, 0, 0, isup_empty_params},
	{str_init("Identification response"), "IRS", ISUP_IRS, 0, 0, isup_empty_params},
	{str_init("Loop prevention"), "LPR", ISUP_LPR, 0, 0, isup_empty_params},
	{str_init("Application transport"), "APT", ISUP_APT, 0, 0, isup_empty_params},
	{str_init("Pre-release information"), "PRI", ISUP_PRI, 0, 0, isup_empty_params}
};


#define SUBF_INIT_EMPTY {{0,0}, {0, {{0, 0}}, {0}}}

static struct isup_subfield nature_of_conn_ind_subf[] = {
	{str_init("Satellite indicator"), {3,
		{str_init("no satellite"), str_init("one satellite"), str_init("two satellites")}, {0,1,2}}},
	{str_init("Continuity check indicator"), {3,
		{str_init("not required"), str_init("required"), str_init("performed")}, {0,1,2}}},
	{str_init("Echo control device indicator"), {2,
		{str_init("not included"), str_init("included")}, {0,1}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield forward_call_ind_subf[] = {
	{str_init("National/international call indicator"), {2,
		{str_init("national"), str_init("international")}, {0,1}}},
	{str_init("End-to-end method indicator"), {4,
		{str_init("no method"), str_init("pass-along"), str_init("SCCP"),
		 str_init("pass-along and SCCP")}, {0,1,2,3}}},
	{str_init("Interworking indicator"), {2,
		{str_init("no interworking"), str_init("interworking")}, {0,1}}},
	{str_init("End-to-end information indicator"), {2,
		{str_init("no end-to-end"), str_init("end-to-end")}, {0,1}}},
	{str_init("ISDN user part indicator"), {2,
		{str_init("not all the way"), str_init("all the way")}, {0,1}}},
	{str_init("ISDN user part preference indicator"), {3,
		{str_init("preferred"), str_init("not required"), str_init("required")}, {0,1,2}}},
	{str_init("ISDN access indicator"), {2,
		{str_init("non-ISDN"), str_init("ISDN")}, {0,1}}},
	{str_init("SCCP method indicator"), {4,
		{str_init("no indication"), str_init("connectionless"), str_init("connection"),
		 str_init("connectionless and connection")}, {0,1,2,3}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield opt_forward_call_ind_subf[] = {
	{str_init("Closed user group call indicator"), {3,
		{str_init("non-CUG"), str_init("outgoing allowed"), str_init("outgoing not allowed")}, {0,2,3}}},
	{str_init("Simple segmentation indicator"), {2,
		{str_init("no additional information"), str_init("additional information")}, {0,1}}},
	{str_init("Connected line identity request indicator"), {2,
		{str_init("not requested"), str_init("requested")}, {0,1}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield called_party_num_subf[] = {
	{str_init("Odd/even indicator"), {2,
		{str_init("even"), str_init("odd")}, {0,1}}},
	{str_init("Nature of address indicator"), {8,
		{str_init("subscriber"), str_init("unknown"), str_init("national"), str_init("international"),
		 str_init("network-specific"), str_init("network routing national"),
		 str_init("network routing network-specific"), str_init("network routing with CDN")},
		{1,2,3,4,5,6,7,8}}},
	{str_init("Internal Network Number indicator"), {2,
		{str_init("allowed"), str_init("not allowed")}, {0,1}}},
	{str_init("Numbering plan indicator"), {3,
		{str_init("ISDN"), str_init("Data"), str_init("Telex")}, {1,3,4}}},
	{str_init("Address signal"), {0, {{0, 0}}, {0}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield calling_party_num_subf[] = {
	{str_init("Odd/even indicator"), {2,
		{str_init("even"), str_init("odd")}, {0,1}}},
	{str_init("Nature of address indicator"), {4,
		{str_init("subscriber"), str_init("unknown"), str_init("national"),
		 str_init("international")}, {1,2,3,4}}},
	{str_init("Number Incomplete indicator"), {2,
		{str_init("complete"), str_init("incomplete")}, {0,1}}},
	{str_init("Numbering plan indicator"), {3,
		{str_init("ISDN"), str_init("Data"), str_init("Telex")}, {1,3,4}}},
	{str_init("Address presentation restricted indicator"), {4,
		{str_init("allowed"), str_init("restricted"), str_init("not available"),
		 str_init("reserved")}, {0,1,2,3}}},
	{str_init("Screening indicator"), {2,
		{str_init("user"), str_init("network")}, {1,3}}},
	{str_init("Address signal"), {0, {{0, 0}}, {0}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield backward_call_ind_subf[] = {
	{str_init("Charge indicator"), {2,
		{str_init("no indication"), str_init("no charge")}, {0,1}}},
	{str_init("Called party's status indicator"), {3,
		{str_init("no indication"), str_init("subscriber free"), str_init("connect")}, {0,1,2}}},
	{str_init("Called party's category indicator"), {3,
		{str_init("no indication"), str_init("ordinary subscriber"), str_init("payphone")}, {0,1,2}}},
	{str_init("End to End method indicator"), {4,
		{str_init("no end-to-end"), str_init("pass-along"), str_init("SCCP"),
		 str_init("pass-along and SCCP")}, {0,1,2,3}}},
	{str_init("Interworking indicator"), {2,
		{str_init("no interworking"), str_init("interworking")}, {0,1}}},
	{str_init("End to End information indicator"), {2,
		{str_init("no end-to-end"), str_init("end-to-end")}, {0,1}}},
	{str_init("ISDN user part indicator"), {2,
		{str_init("not all the way"), str_init("all the way")}, {0,1}}},
	{str_init("Holding indicator"), {2,
		{str_init("not requested"), str_init("requested")}, {0,1}}},
	{str_init("ISDN access indicator"), {2,
		{str_init("non-ISDN"), str_init("ISDN")}, {0,1}}},
	{str_init("Echo control device indicator"), {2,
		{str_init("not included"), str_init("included")}, {0,1}}},
	{str_init("SCCP method indicator"), {4,
		{str_init("no indication"), str_init("connectionless"), str_init("connection"),
		 str_init("connectionless and connection")}, {0,1,2,3}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield opt_backward_call_ind_subf[] = {
	{str_init("In-band information indicator"), {2,
		{str_init("no indication"), str_init("available")}, {0,1}}},
	{str_init("Call diversion may occur indicator"), {2,
		{str_init("no indication"), str_init("call diversion")}, {0,1}}},
	{str_init("Simple segmentation indicator"), {2,
		{str_init("no additional information"), str_init("additional information")}, {0,1}}},
	{str_init("MLPP user indicator"), {2,
		{str_init("no indication"), str_init("MLPP user")}, {0,1}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield connected_num_subf[] = {
	{str_init("Odd/even indicator"), {2,
		{str_init("even"), str_init("odd")}, {0,1}}},
	{str_init("Nature of address indicator"), {4,
		{str_init("subscriber"), str_init("unknown"), str_init("national"),
		 str_init("international")}, {1,2,3,4}}},
	{str_init("Numbering plan indicator"), {3,
		{str_init("ISDN"), str_init("Data"), str_init("Telex")}, {1,3,4}}},
	{str_init("Address presentation restricted indicator"), {3,
		{str_init("allowed"), str_init("restricted"), str_init("not available")}, {0,1,2}}},
	{str_init("Screening indicator"), {2,
		{str_init("user"), str_init("network")}, {1,3}}},
	{str_init("Address signal"), {0, {{0, 0}}, {0}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield original_called_num_subf[] = {
        {str_init("Odd/even indicator"), {2,
                {str_init("even"), str_init("odd")}, {0,1}}},
        {str_init("Nature of address indicator"), {4,
                {str_init("subscriber"), str_init("unknown"), str_init("national"),
                 str_init("international")}, {1,2,3,4}}},
        {str_init("Numbering plan indicator"), {3,
                {str_init("ISDN"), str_init("Data"), str_init("Telex")}, {1,3,4}}},
        {str_init("Address presentation restricted indicator"), {4,
                {str_init("allowed"), str_init("restricted"), str_init("not available"), str_init("reserved")}, {0,1,2,3}}},
        {str_init("Address signal"), {0, {{0, 0}}, {0}}},
        SUBF_INIT_EMPTY};

static struct isup_subfield redirection_info_subf[] = {
	{str_init("Redirecting indicator"), {7,
		{str_init("no redirection"), str_init("call rerouted"),
		 str_init("call rerouted, all information restricted"), str_init("call diverted"),
		 str_init("Call diverted, all information restricted"),
		 str_init("call rerouted, redirection number restricted"),
	     str_init("call diversion, redirection number restricted")}, {0,1,2,3,4,5,6}}},
	{str_init("Original redirection reason"), {4,
		{str_init("unknown/not available"), str_init("user busy"), str_init("no reply"),
		 str_init("unconditional")}, {0,1,2,3}}},
	{str_init("Redirection counter"), {5,
		{str_init("1"), str_init("2"), str_init("3"), str_init("4"), str_init("5")}, {1,2,3,4,5}}},
	{str_init("Redirecting reason"), {7,
		{str_init("unknown/not available"), str_init("user busy"), str_init("no reply"),
		 str_init("unconditional"), str_init("deflection alerting"), str_init("deflection response"),
		 str_init("mobile not reachable")}, {0,1,2,3,4,5,6}}},
	SUBF_INIT_EMPTY};

/* Recommendation and Diagnostics subfields not supported */
static struct isup_subfield cause_ind_subf[] = {
	{str_init("Location"), {8,
		{str_init("user"), str_init("LPN"),str_init("LN"), str_init("TN"), str_init("RLN"),
		 str_init("RPN"), str_init("INTL"), str_init("BI")}, {0,1,2,3,4,5,7,10}}},
	{str_init("Coding standard"), {4,
		{str_init("ITU-T"), str_init("ISO/IEC"), str_init("national"), str_init("location")}, {0,1,2,3}}},
	{str_init("Cause value"), {0, {{0, 0}}, {0}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield subsequent_num_subf[] = {
	{str_init("Odd/even indicator"), {2,
		{str_init("even"), str_init("odd")}, {0,1}}},
	{str_init("Address signal"), {0, {{0, 0}}, {0}}},
	SUBF_INIT_EMPTY};

static struct isup_subfield event_info_subf[] = {
	{str_init("Event indicator"), {6,
		{str_init("alerting"), str_init("progress"), str_init("in-band or pattern"),
		 str_init("busy"), str_init("no reply"), str_init(" unconditional")}, {1,2,3,4,5,6}}},
	{str_init("Event presentation restricted indicator"), {2,
		{str_init("no indication"), str_init("restricted")}, {0,1}}},
	SUBF_INIT_EMPTY};

static struct isup_predef_vals calling_party_cat_pvals = {
	11, {str_init("unknown"), str_init("french"), str_init("english"), str_init("german"),
	str_init("russian"), str_init("spanish"), str_init("ordinary"), str_init("priority"),
	str_init("data"), str_init("test"), str_init("payphone")}, {0,1,2,3,4,5,10,11,12,13,15}
};

static struct isup_predef_vals transm_med_req_pvals = {
	8, {str_init("speech"), str_init("64 kbit/s unrestricted"), str_init("3.1 kHz audio"),
	str_init("64 kbit/s preferred"), str_init("2 x 64 kbit/s"), str_init("384 kbit/s"),
	str_init("1536 kbit/s"), str_init("1920 kbit/s")}, {0,2,3,6,7,8,9,10}
};

static inline char digit2char(unsigned char digit)
{
	switch (digit & 0xf) {
		case 0x0:
			return '0';
		case 0x1:
			return '1';
		case 0x2:
			return '2';
		case 0x3:
			return '3';
		case 0x4:
			return '4';
		case 0x5:
			return '5';
		case 0x6:
			return '6';
		case 0x7:
			return '7';
		case 0x8:
			return '8';
		case 0x9:
			return '9';
		case 0xa:
			return 'A';
		case 0xb:
			return 'B';
		case 0xc:
			return 'C';
		case 0xd:
			return 'D';
		case 0xe:
			return '*';
		case 0xf:
			return '#';
		default:
			return 0;
	}
}

char char2digit(char localchar)
{
	switch (localchar) {
		case '0':
			return 0x0;
		case '1':
			return 0x1;
		case '2':
			return 0x2;
		case '3':
			return 0x3;
		case '4':
			return 0x4;
		case '5':
			return 0x5;
		case '6':
			return 0x6;
		case '7':
			return 0x7;
		case '8':
			return 0x8;
		case '9':
			return 0x9;
		case 'a':
		case 'A':
			return 0xa;
		case 'b':
		case 'B':
			return 0xb;
		case 'c':
		case 'C':
			return 0xc;
		case 'd':
		case 'D':
			return 0xd;
		case 'e':
		case 'E':
		case '*':
			return 0xe;
		case 'f':
		case 'F':
		case '#':
			return 0xf;
		default:
			return 0x0;
	}
}

static void isup_get_number(str *dest, unsigned char *src, int srclen, int oddeven)
{
	int i;

	if (oddeven < 2) {
		/* BCD odd or even */
		for (i = 0; i < ((srclen * 2) - oddeven); i++)
			dest->s[i] = digit2char(src[i/2] >> ((i % 2) ? 4 : 0));
	} else {
		/* oddeven = 2 for IA5 characters */
		for (i = 0; i < srclen; i++)
			dest->s[i] = src[i];
	}
	dest->len = i;
}

static void isup_put_number(unsigned char *dest, str src, int *len, int *oddeven)
{
	int i = 0;

	if (src.len % 2) {
		*oddeven = 1;
		*len = src.len/2 + 1;
	} else {
		*oddeven = 0;
		*len = src.len/2;
	}

	while (i < src.len) {
		dest[i] = 0;

		if (!(i % 2))
			dest[i/2] |= (char2digit(src.s[i]) & 0xf);
		else
			dest[i/2] |= ((char2digit(src.s[i]) << 4) & 0xf0);

		i++;
	}
}

static inline int get_predef_val(int param_idx, int subfield_idx, str val_alias)
{
	int i;

	if (isup_params[param_idx].subfield_list[subfield_idx].predef_vals.no_vals == 0) {
		LM_ERR("No string aliases supported for subfield <%.*s>\n",
			isup_params[param_idx].subfield_list[subfield_idx].name.len,
			isup_params[param_idx].subfield_list[subfield_idx].name.s);
		return -1;
	}

	for (i = 0; i < isup_params[param_idx].subfield_list[subfield_idx].predef_vals.no_vals; i++)
		if (!memcmp(isup_params[param_idx].subfield_list[subfield_idx].predef_vals.aliases[i].s,
			val_alias.s, val_alias.len))
			return isup_params[param_idx].subfield_list[subfield_idx].predef_vals.vals[i];

	LM_ERR("Unknown value alias <%.*s>\n", val_alias.len, val_alias.s);

	return -1;
}

#define SET_BITS(_byte, _mask, _shift, _new_val) \
	(_byte & ~_mask) | ((_new_val << _shift) & _mask)

#define PARAM_CHECK_INT_VAL() \
do { \
	if (val == NULL || val->flags & PV_VAL_NULL) \
		new_val = 0; \
	else if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) { \
		if (val->ri > 255) { \
			LM_ERR("Value to big, should fit one byte\n"); \
			return -1; \
		} \
		new_val = val->ri; \
	} else if (val->flags & PV_VAL_STR) { \
		if ((new_val = get_predef_val(param_idx, subfield_idx, val->rs)) < 0) \
			return -1; \
	} else { \
		LM_ERR("Invalid value\n"); \
		return -1; \
	} \
} while (0)

#define NUM_PARAM_GET_VAL_PV(_addr_sig_subf_idx) \
do { \
	if (val == NULL || val->flags & PV_VAL_NULL) { \
		new_val = 0; \
		num.len = 0; \
		num.s = NULL; \
	} else  if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) { \
		if (subfield_idx == (_addr_sig_subf_idx)) { \
			LM_ERR("String value required\n"); \
			return -1; \
		} else { \
			if (val->ri > 255) { \
				LM_ERR("Value to big, should fit one byte\n"); \
				return -1; \
			} \
			new_val = val->ri; \
		} \
	} else if (val->flags & PV_VAL_STR) { \
		if (subfield_idx == (_addr_sig_subf_idx)) { \
			num.len = val->rs.len; \
			num.s = val->rs.s; \
		} else { \
			if ((new_val = get_predef_val(param_idx, subfield_idx, val->rs)) < 0) \
				return -1; \
		} \
	} else { \
		LM_ERR("Invalid value\n"); \
		return -1; \
	} \
} while (0)

/* specific parameter parse/write functions */

void nature_of_conn_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,0};
	int shift[] = {0,2,4};
	int mask[] =  {3,3,1};

	if (subfield_idx < 0 || subfield_idx > 2) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
}

int nature_of_conn_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
									pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,0};
	int mask[] =  {0x3,0xc,0x10};
	int shift[] = {0,2,4};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 2) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 1;

	return 0;
}

void forward_call_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,0,0,0,0,1,1};
	int shift[] = {0,1,3,4,5,6,0,1};
	int mask[] =  {1,3,1,1,1,3,1,3};

	if (subfield_idx < 0 || subfield_idx > 7) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
}

int forward_call_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val,
								int *len, pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,0,0,0,0,1,1};
	int mask[] =  {0x1,0x6,0x8,0x10,0x20,0xc0,0x1,0x6};
	int shift[] = {0,1,3,4,5,6,0,1};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 7) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 2;

	return 0;
}

void redirection_info_parsef(int subfield_idx, unsigned char *param_val, int len,
								int *int_res, str *str_res)
{
	int idx[] =   {0,0,1,1};
	int shift[] = {0,4,0,4};
	int mask[] =  {7,0xf,7,0xf};

	if (subfield_idx < 0 || subfield_idx > 3) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
}

int redirection_info_writef(int param_idx, int subfield_idx, unsigned char *param_val,
                                                                int *len, pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,1,1};
	int mask[] =  {0x7,0xf0,0x7,0xf0};
	int shift[] = {0,4,0,4};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 3) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
								mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 2;

	return 0;
}

void opt_forward_call_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	switch (subfield_idx) {
	case 0:
		*int_res = param_val[0] & 0x03;
		break;
	case 1:
		*int_res = param_val[0] & (1 << 2);
		break;
	case 2:
		*int_res = param_val[0] & (1 << 7);
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
	}
}

int opt_forward_call_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
									pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,0};
	int mask[] =  {0x3,0x4,0x80};
	int shift[] = {0,2,7};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 2) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 1;

	return 0;
}

void called_party_num_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,1,1};
	int shift[] = {7,0,7,4};
	int mask[] =  {1,0x7f,1,7};
	int oddeven = (param_val[0] >> 7) & 0x1;

	if (subfield_idx < 0 || subfield_idx > 4) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	switch (subfield_idx) {
	case 0:
		*int_res = oddeven;
		break;
	case 4:
		isup_get_number(str_res, param_val + 2, len - 2, oddeven);
		break;
	default:
		*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
	}
}

int called_party_num_writef(int param_idx, int subfield_idx, unsigned char *param_val,
								int *len, pv_value_t *val)
{
	int new_val;
	int num_len, oddeven;
	str num;
	int idx[] =   {0,0,1,1};
	int mask[] =  {0x80,0x7f,0x80,0x70};
	int shift[] = {7,0,7,4};

	NUM_PARAM_GET_VAL_PV(4);

	if (subfield_idx < 0 || subfield_idx > 4) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	if (subfield_idx == 4) {
		isup_put_number(param_val + 2, num, &num_len, &oddeven);
		/* also set oddeven, just in case it wasn't already */
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, oddeven);
		*len = num_len + 2;
	} else {
		param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);
		if (*len == 0)
			*len = 2;
	}

	return 0;
}

void calling_party_num_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,1,1,1,1};
	int shift[] = {7,0,7,4,2,0};
	int mask[] =  {1,0x7f,1,7,3,3};
	int oddeven = (param_val[0] >> 7) & 0x1;

	if (subfield_idx < 0 || subfield_idx > 6) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	switch (subfield_idx) {
	case 0:
		*int_res = oddeven;
		break;
	case 6:
		isup_get_number(str_res, param_val + 2, len - 2, oddeven);
		break;
	default:
		*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
	}
}

int calling_party_num_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;
	int num_len, oddeven;
	str num;
	int idx[] =   {0,0,1,1,1,1};
	int mask[] =  {0x80,0x7f,0x80,0x70,0xc,0x3};
	int shift[] = {7,0,7,4,2,0};

	NUM_PARAM_GET_VAL_PV(6);

	if (subfield_idx < 0 || subfield_idx > 6) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	if (subfield_idx == 6) {
		isup_put_number(param_val + 2, num, &num_len, &oddeven);
		/* also set oddeven, just in case it wasn't already */
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, oddeven);
		*len = num_len + 2;
	} else {
		param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);
		if (*len == 0)
			*len = 2;
	}

	return 0;
}

void backward_call_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,0,0,1,1,1,1,1,1,1};
	int shift[] = {0,2,4,6,0,1,2,3,4,5,7};
	int mask[] =  {3,3,3,3,1,1,1,1,1,1,3};

	if (subfield_idx < 0 || subfield_idx > 10) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
}

int backward_call_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,0,0,1,1,1,1,1,1,1};
	int mask[] =  {0x3,0xc,0x30,0xc0,0x1,0x2,0x4,0x8,0x10,0x20,0x180};
	int shift[] = {0,2,4,6,0,1,2,3,4,5,7};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 10) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 2;

	return 0;
}

void opt_backward_call_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,0,0};
	int shift[] = {0,1,2,3};
	int mask[] =  {1,1,1,1};

	if (subfield_idx < 0 || subfield_idx > 3) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
}

int opt_backward_call_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;
	int idx[] =   {0,0,0,0};
	int mask[] =  {1,2,4,8};
	int shift[] = {0,1,2,3};

	PARAM_CHECK_INT_VAL();

	if (subfield_idx < 0 || subfield_idx > 3) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);

	*len = 1;

	return 0;
}

void connected_num_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int idx[] =   {0,0,1,1,1};
	int shift[] = {7,0,4,2,0};
	int mask[] =  {1,0x7f,7,3,3};
	int oddeven = (param_val[0] >> 7) & 0x1;

	if (subfield_idx < 0 || subfield_idx > 5) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	switch (subfield_idx) {
	case 0:
		*int_res = oddeven;
		break;
	case 5:
		isup_get_number(str_res, param_val + 2, len - 2, oddeven);
		break;
	default:
		*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
	}
}

int connected_num_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;
	int num_len, oddeven;
	str num;
	int idx[] =   {0,0,1,1,1};
	int mask[] =  {0x80,0x7f,0x70,0xc,0x3};
	int shift[] = {7,0,4,2,0};

	NUM_PARAM_GET_VAL_PV(5);


	if (subfield_idx < 0 || subfield_idx > 5) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	if (subfield_idx == 5) {
		isup_put_number(param_val + 2, num, &num_len, &oddeven);
		/* also set oddeven, just in case it wasn't already */
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, oddeven);
		*len = num_len + 2;
	} else {
		param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
										mask[subfield_idx], shift[subfield_idx], new_val);
		if (*len == 0)
			*len = 2;
	}

	return 0;
}

void original_called_num_parsef(int subfield_idx, unsigned char *param_val, int len,
								int *int_res, str *str_res)
{
	int idx[] =   {0,0,1,1};
	int shift[] = {7,0,4,2};
	int mask[] =  {1,0x7f,7,3};
	int oddeven = (param_val[0] >> 7) & 0x1;

	if (subfield_idx < 0 || subfield_idx > 4) {
		LM_ERR("BUG - bad subfield\n");
		return;
	}

	switch (subfield_idx) {
	case 0:
		*int_res = oddeven;
		break;
	case 4:
		isup_get_number(str_res, param_val + 2, len - 2, oddeven);
		break;
	default:
		*int_res = (param_val[idx[subfield_idx]] >> shift[subfield_idx]) & mask[subfield_idx];
	}
}

int original_called_num_writef(int param_idx, int subfield_idx,
							unsigned char *param_val, int *len, pv_value_t *val)
{
	int new_val;
	int num_len, oddeven;
	str num;
	int idx[] =   {0,0,1,1};
	int mask[] =  {0x80,0x7f,0x70,0xc};
	int shift[] = {7,0,4,2};

	NUM_PARAM_GET_VAL_PV(4);

	if (subfield_idx < 0 || subfield_idx > 4) {
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	if (subfield_idx == 4) {
		isup_put_number(param_val + 2, num, &num_len, &oddeven);
		/* also set oddeven, just in case it wasn't already */
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, oddeven);
		*len = num_len + 2;
	} else {
		param_val[idx[subfield_idx]] = SET_BITS(param_val[idx[subfield_idx]],
								mask[subfield_idx], shift[subfield_idx], new_val);
		if (*len == 0)
			*len = 2;
	}

	return 0;
}


void cause_ind_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	switch (subfield_idx) {
	case 0:
		*int_res = param_val[0] & 0xf;
		break;
	case 1:
		*int_res = (param_val[0] & 0x60) >> 5;
		break;
	case 2:
		*int_res = param_val[1] & 0x7f;
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
	}
}

int cause_ind_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;

	PARAM_CHECK_INT_VAL();

	/* Extension indicators set to "last octet" */
	param_val[0] = SET_BITS(param_val[0], 0x80, 7, 1);
	param_val[1] = SET_BITS(param_val[1], 0x80, 7, 1);

	switch (subfield_idx) {
	case 0:
		param_val[0] = SET_BITS(param_val[0], 0xf, 0, new_val);
		break;
	case 1:
		param_val[0] = SET_BITS(param_val[0], 0x60, 5, new_val);
		break;
	case 2:
		param_val[1] = SET_BITS(param_val[1], 0x7f, 0, new_val);
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	*len = 2;

	return 0;
}

void subsequent_num_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	int oddeven = (param_val[0] >> 7) & 0x1;

	switch (subfield_idx) {
	case 0:
		*int_res = oddeven;
		break;
	case 1:
		isup_get_number(str_res, param_val + 1, len - 1, oddeven);
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
	}
}

int subsequent_num_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;
	int num_len, oddeven;
	str num;

	NUM_PARAM_GET_VAL_PV(1);

	switch (subfield_idx) {
	case 0:
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, new_val);
		break;
	case 1:
		isup_put_number(param_val + 1, num, &num_len, &oddeven);
		/* also set oddeven, just in case */
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, oddeven);
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	if (subfield_idx == 1)
		*len = num_len + 1;
	else if (*len == 0)
		*len = 1;

	return 0;
}

void event_info_parsef(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res)
{
	switch (subfield_idx) {
	case 0:
		*int_res = param_val[0] & 0x7f;
		break;
	case 1:
		*int_res = (param_val[0] >> 7) & 0x1;
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
	}
}

int event_info_writef(int param_idx, int subfield_idx, unsigned char *param_val, int *len,
								pv_value_t *val)
{
	int new_val;

	PARAM_CHECK_INT_VAL();

	switch (subfield_idx) {
	case 0:
		param_val[0] = SET_BITS(param_val[0], 0x7f, 0, new_val);
		break;
	case 1:
		param_val[0] = SET_BITS(param_val[0], 0x80, 7, new_val);
		break;
	default:
		LM_ERR("BUG - bad subfield\n");
		return -1;
	}

	*len = 1;

	return 0;
}

struct isup_param_data isup_params[NO_ISUP_PARAMS] = {
	{ISUP_PARM_CALL_REF, str_init("Call Reference"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_TRANSMISSION_MEDIUM_REQS, str_init("Transmission Medium Requirement"), NULL, NULL, NULL, &transm_med_req_pvals, 1},
	{ISUP_PARM_ACCESS_TRANS, str_init("Access Transport"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALLED_PARTY_NUM, str_init("Called Party Number"), called_party_num_parsef, called_party_num_writef, called_party_num_subf, NULL, 0},
	{ISUP_PARM_SUBSEQUENT_NUMBER, str_init("Subsequent Number"), subsequent_num_parsef, subsequent_num_writef, subsequent_num_subf, NULL, 0},
	{ISUP_PARM_NATURE_OF_CONNECTION_IND, str_init("Nature of Connection Indicators"), nature_of_conn_ind_parsef, nature_of_conn_ind_writef, nature_of_conn_ind_subf, NULL, 1},
	{ISUP_PARM_FORWARD_CALL_IND, str_init("Forward Call Indicators"), forward_call_ind_parsef, forward_call_ind_writef, forward_call_ind_subf, NULL, 2},
	{ISUP_PARM_OPT_FORWARD_CALL_INDICATOR, str_init("Optional forward call indicators"), opt_forward_call_ind_parsef, opt_forward_call_ind_writef, opt_forward_call_ind_subf, NULL, 0},
	{ISUP_PARM_CALLING_PARTY_CAT, str_init("Calling Party's Category"), NULL, NULL, NULL, &calling_party_cat_pvals, 1},
	{ISUP_PARM_CALLING_PARTY_NUM, str_init("Calling Party Number"), calling_party_num_parsef, calling_party_num_writef, calling_party_num_subf, NULL, 0},
	{ISUP_PARM_REDIRECTING_NUMBER, str_init("Redirecting Number"), original_called_num_parsef, original_called_num_writef, original_called_num_subf, NULL, 0},
	{ISUP_PARM_REDIRECTION_NUMBER, str_init("Redirection Number"), called_party_num_parsef, called_party_num_writef, called_party_num_subf, NULL, 0},
	{ISUP_PARM_CONNECTION_REQ, str_init("Connection Request"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_INR_IND, str_init("Information Request Indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_INF_IND, str_init("Information Indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CONTINUITY_IND, str_init("Continuity Indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_BACKWARD_CALL_IND, str_init("Backward Call Indicators"), backward_call_ind_parsef, backward_call_ind_writef, backward_call_ind_subf, NULL, 2},
	{ISUP_PARM_CAUSE, str_init("Cause Indicators"), cause_ind_parsef, cause_ind_writef, cause_ind_subf, NULL, 0},
	{ISUP_PARM_REDIRECTION_INFO, str_init("Redirection Information"), redirection_info_parsef, redirection_info_writef, redirection_info_subf, NULL, 0},
	{ISUP_PARM_CIRCUIT_GROUP_SUPERVISION_IND, str_init("Circuit group supervision message type"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_RANGE_AND_STATUS, str_init("Range and status"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_MODIFICATION_IND, str_init("Call modification indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_FACILITY_IND, str_init("Facility Indicator"), NULL, NULL, NULL, NULL, 1},
	{ISUP_PARM_CUG_INTERLOCK_CODE, str_init("CUG Interlock Code"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_USER_SERVICE_INFO, str_init("User Service Information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_SIGNALLING_PC, str_init("Signalling point code"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_USER_TO_USER_INFO, str_init("User-to-user information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_CONNECTED_NUMBER, str_init("Connected Number"), connected_num_parsef, connected_num_writef, connected_num_subf, NULL, 0},
	{ISUP_PARM_SUSPEND_RESUME_IND, str_init("Suspend/Resume Indicators"), NULL, NULL, NULL, NULL, 1},
	{ISUP_PARM_TRANSIT_NETWORK_SELECTION, str_init("Transit Network Selection"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_EVENT_INFO, str_init("Event Information"), event_info_parsef, event_info_writef, event_info_subf, NULL, 1},
	{ISUP_PARM_CIRCUIT_ASSIGNMENT_MAP, str_init("Circuit Assignment Map"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CIRCUIT_STATE_IND, str_init("Circuit State Indicator"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARAM_AUTOMATIC_CONGESTION_LEVEL, str_init("Automatic congestion level"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ORIGINAL_CALLED_NUM, str_init("Original called number"), original_called_num_parsef, original_called_num_writef, original_called_num_subf, NULL, 0},
	{ISUP_PARM_OPT_BACKWARD_CALL_IND, str_init("Optional Backward Call Indicators"), opt_backward_call_ind_parsef, opt_backward_call_ind_writef, opt_backward_call_ind_subf, NULL, 0},
	{ISUP_PARM_USER_TO_USER_IND, str_init("User-to-user indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ORIGINATION_ISC_PC, str_init("Origination ISC point code"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_GENERIC_NOTIFICATION_IND, str_init("Generic Notification Indicator"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_HISTORY_INFO, str_init("Call history information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ACCESS_DELIVERY_INFO, str_init("Access Delivery Information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_NETWORK_SPECIFIC_FACILITY, str_init("Network specific facility"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_USER_SERVICE_INFO_PRIME, str_init("User service information prime"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PROPAGATION_DELAY, str_init("Propagation Delay Counter"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REMOTE_OPERATIONS, str_init("Remote operations"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_SERVICE_ACTIVATION, str_init("Service activation"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_USER_TELESERVICE_INFO, str_init("User teleservice information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_TRANSMISSION_MEDIUM_USED, str_init("Transmission medium used"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_DIVERSION_INFO, str_init("Call diversion information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ECHO_CONTROL_INFO, str_init("Echo Control Information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_MESSAGE_COMPAT_INFO, str_init("Message compatibility information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PARAMETER_COMPAT_INFO, str_init("Parameter Compatibility Information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_MLPP_PRECEDENCE, str_init("MLPP precedence"), NULL,NULL, NULL, NULL, 0},
	{ISUP_PARM_MCID_REQUEST_IND, str_init("MCID request indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_MCID_RESPONSE_IND, str_init("MCID response indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_HOP_COUNTER, str_init("Hop Counter"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_TRANSMISSION_MEDIUM_REQ_PRIME, str_init("Transmission medium requirement prime"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_LOCATION_NUMBER, str_init("Location Number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECTION_NUM_RESTRICTION, str_init("Redirection number restriction"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_TRANSFER_REFERENCE, str_init("Call transfer reference"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_LOOP_PREVENTION_IND, str_init("Loop prevention indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_TRANSFER_NUMBER, str_init("Call transfer number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CCSS, str_init("CCSS"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_FORWARD_GVNS, str_init("Forward GVNS"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_BACKWARD_GVNS, str_init("Backward GVNS"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECT_CAPABILITY, str_init("Redirect capability"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_NETWORK_MANAGEMENT_CONTROL, str_init("Network management controls"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CORRELATION_ID, str_init("Correlation id"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_SCF_ID, str_init("SCF id"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_DIVERSION_TREATMENT_IND, str_init("Call diversion treatment indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALLED_IN_NUMBER, str_init("Called IN number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALL_OFFERING_TREATMENT_IND, str_init("Call offering treatment indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CHARGED_PARTY_IDENT, str_init("Charged party identification"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CONFERENCE_TREATMENT_IND, str_init("Conference treatment indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_DISPLAY_INFO, str_init("Display information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_UID_ACTION_IND, str_init("UID action indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_UID_CAPABILITY_IND, str_init("UID capability indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECT_COUNTER, str_init("Redirect Counter"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_APPLICATION_TRANSPORT, str_init("Application transport"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_COLLECT_CALL_REQUEST, str_init("Collect call request"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CCNR_POSSIBLE_IND, str_init("CCNR possible indicator"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_CAPABILITY, str_init("Pivot capability"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_ROUTING_IND, str_init("Pivot routing indicators"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALLED_DIRECTORY_NUMBER, str_init("Called directory number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ORIGINAL_CALLED_IN_NUM, str_init("Original called IN number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CALLING_GEODETIC_LOCATION, str_init("Calling geodetic location"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_HTR_INFO, str_init("HTR information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_NETWORK_ROUTING_NUMBER, str_init("Network routing number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_QUERY_ON_RELEASE_CAPABILITY, str_init("Query on release capability"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_STATUS, str_init("Pivot status"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_COUNTER, str_init("Pivot counter"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_ROUTING_FORWARD_IND, str_init("Pivot routing forward information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_PIVOT_ROUTING_BACKWARD_IND, str_init("Pivot routing backward information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECT_STATUS, str_init("Redirect status"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECT_FORWARD_INFO, str_init("Redirect forward information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_REDIRECT_BACKWARD_INFO, str_init("Redirect backward information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_NUM_PORTABILITY_FORWARD_INFO, str_init("Number portability forward information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_GENERIC_ADDR, str_init("Generic Number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_GENERIC_DIGITS, str_init("Generic Digits"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_EGRESS_SERV, str_init("Egress Service"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_JIP, str_init("Jurisdiction Information Parameter"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CARRIER_ID, str_init("Carrier Identification"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_BUSINESS_GRP, str_init("Business Group"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_GENERIC_NAME, str_init("Generic Name"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_LOCAL_SERVICE_PROVIDER_IDENTIFICATION, str_init("Local Service Provider ID"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_ORIG_LINE_INFO, str_init("Originating line information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_CHARGE_NUMBER, str_init("Charge Number"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_SELECTION_INFO, str_init("Selection Information"), NULL, NULL, NULL, NULL, 0},
	{ISUP_PARM_INVAL, {0,0}, NULL, NULL, NULL, NULL, 0}
};

