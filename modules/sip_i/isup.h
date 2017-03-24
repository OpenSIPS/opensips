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

#ifndef _ISUP_H_
#define _ISUP_H_

#include "../../pvar.h"

#define NO_ISUP_MESSAGES 23

/* ISUP messages */
#define ISUP_IAM	0x01	/*!< Initial address */
#define ISUP_SAM	0x02	/*!< Subsequent address */
#define ISUP_ACM	0x06	/*!< Address complete */
#define ISUP_CON	0x07	/*!< Connect */
#define ISUP_FOT	0x08	/*!< Forward transfer */
#define ISUP_ANM	0x09	/*!< Answer */
#define ISUP_REL	0x0c	/*!< Release */
#define ISUP_SUS	0x0d	/*!< Suspend */
#define ISUP_RES	0x0e	/*!< Resume */
#define ISUP_RLC	0x10	/*!< Release complete */
#define ISUP_FAR	0x1f	/*!< Facility request */
#define ISUP_FAA	0x20	/*!< Facility accepted */
#define ISUP_FRJ	0x21	/*!< Facility reject */
#define ISUP_CPG	0x2c	/*!< Call progress */
#define ISUP_USR	0x2d	/*!< User-to-user information */
#define ISUP_CFN	0x2f	/*!< Confusion */
#define ISUP_NRM	0x32	/*!< Network resource management */
#define ISUP_FAC	0x33	/*!< Facility */
#define ISUP_IRQ	0x36	/*!< Identification request */
#define ISUP_IRS	0x37	/*!< Identification response */
#define ISUP_LPR	0x40	/*!< Loop prevention */
#define ISUP_APT	0x41	/*!< Application transport */
#define ISUP_PRI	0x42	/*!< Pre-release information */


#define NO_ISUP_PARAMS 109

/* ISUP Parameters ITU-T Q.763 */
#define ISUP_PARM_CALL_REF						0x01
#define ISUP_PARM_TRANSMISSION_MEDIUM_REQS		0x02
#define ISUP_PARM_ACCESS_TRANS					0x03
#define ISUP_PARM_CALLED_PARTY_NUM				0x04
#define ISUP_PARM_SUBSEQUENT_NUMBER				0x05
#define ISUP_PARM_NATURE_OF_CONNECTION_IND		0x06
#define ISUP_PARM_FORWARD_CALL_IND				0x07
#define ISUP_PARM_OPT_FORWARD_CALL_INDICATOR	0x08
#define ISUP_PARM_CALLING_PARTY_CAT				0x09
#define ISUP_PARM_CALLING_PARTY_NUM				0x0a
#define ISUP_PARM_REDIRECTING_NUMBER			0x0b
#define ISUP_PARM_REDIRECTION_NUMBER			0x0c
#define ISUP_PARM_CONNECTION_REQ				0x0d
#define ISUP_PARM_INR_IND						0x0e
#define ISUP_PARM_INF_IND						0x0f
#define ISUP_PARM_CONTINUITY_IND				0x10
#define ISUP_PARM_BACKWARD_CALL_IND				0x11
#define ISUP_PARM_CAUSE							0x12
#define ISUP_PARM_REDIRECTION_INFO				0x13
/* 0x14 is Reserved / Event information */
#define ISUP_PARM_CIRCUIT_GROUP_SUPERVISION_IND	0x15
#define ISUP_PARM_RANGE_AND_STATUS				0x16
#define ISUP_PARM_CALL_MODIFICATION_IND			0x17
#define ISUP_PARM_FACILITY_IND					0x18
/* 0x19 is Reserved */
#define ISUP_PARM_CUG_INTERLOCK_CODE			0x1a
/* 0x1b is Reserved */
/* 0x1c is Reserved */
#define ISUP_PARM_USER_SERVICE_INFO				0x1d
#define ISUP_PARM_SIGNALLING_PC					0x1e
/* 0x1f is Reserved */
#define ISUP_PARM_USER_TO_USER_INFO				0x20
#define ISUP_CONNECTED_NUMBER					0x21
#define ISUP_PARM_SUSPEND_RESUME_IND			0x22
#define ISUP_PARM_TRANSIT_NETWORK_SELECTION		0x23
#define ISUP_PARM_EVENT_INFO					0x24
#define ISUP_PARM_CIRCUIT_ASSIGNMENT_MAP		0x25
#define ISUP_PARM_CIRCUIT_STATE_IND				0x26
#define ISUP_PARAM_AUTOMATIC_CONGESTION_LEVEL	0x27
#define ISUP_PARM_ORIGINAL_CALLED_NUM			0x28
#define ISUP_PARM_OPT_BACKWARD_CALL_IND			0x29
#define ISUP_PARM_USER_TO_USER_IND				0x2a
#define ISUP_PARM_ORIGINATION_ISC_PC			0x2b
#define ISUP_PARM_GENERIC_NOTIFICATION_IND		0x2c
#define ISUP_PARM_CALL_HISTORY_INFO				0x2d
#define ISUP_PARM_ACCESS_DELIVERY_INFO			0x2e
#define ISUP_PARM_NETWORK_SPECIFIC_FACILITY		0x2f
#define ISUP_PARM_USER_SERVICE_INFO_PRIME		0x30
#define ISUP_PARM_PROPAGATION_DELAY				0x31
#define ISUP_PARM_REMOTE_OPERATIONS				0x32
#define ISUP_PARM_SERVICE_ACTIVATION			0x33
#define ISUP_PARM_USER_TELESERVICE_INFO			0x34
#define ISUP_PARM_TRANSMISSION_MEDIUM_USED		0x35
#define ISUP_PARM_CALL_DIVERSION_INFO			0x36
#define ISUP_PARM_ECHO_CONTROL_INFO				0x37
#define ISUP_PARM_MESSAGE_COMPAT_INFO			0x38
#define ISUP_PARM_PARAMETER_COMPAT_INFO			0x39
#define ISUP_PARM_MLPP_PRECEDENCE				0x3a
#define ISUP_PARM_MCID_REQUEST_IND				0x3b
#define ISUP_PARM_MCID_RESPONSE_IND				0x3c
#define ISUP_PARM_HOP_COUNTER					0x3d
#define ISUP_PARM_TRANSMISSION_MEDIUM_REQ_PRIME	0x3e
#define ISUP_PARM_LOCATION_NUMBER				0x3f
#define ISUP_PARM_REDIRECTION_NUM_RESTRICTION	0x40
#define ISUP_PARM_CALL_TRANSFER_REFERENCE		0x43
#define ISUP_PARM_LOOP_PREVENTION_IND			0x44
#define ISUP_PARM_CALL_TRANSFER_NUMBER			0x45
#define ISUP_PARM_CCSS							0x4b
#define ISUP_PARM_FORWARD_GVNS					0x4c
#define ISUP_PARM_BACKWARD_GVNS					0x4d
#define ISUP_PARM_REDIRECT_CAPABILITY			0x4e
#define ISUP_PARM_NETWORK_MANAGEMENT_CONTROL	0x5b
#define ISUP_PARM_CORRELATION_ID				0x65
#define ISUP_PARM_SCF_ID						0x66
#define ISUP_PARM_CALL_DIVERSION_TREATMENT_IND	0x6e
#define ISUP_PARM_CALLED_IN_NUMBER				0x6f
#define ISUP_PARM_CALL_OFFERING_TREATMENT_IND	0x70
#define ISUP_PARM_CHARGED_PARTY_IDENT			0x71
#define ISUP_PARM_CONFERENCE_TREATMENT_IND		0x72
#define ISUP_PARM_DISPLAY_INFO					0x73
#define ISUP_PARM_UID_ACTION_IND				0x74
#define ISUP_PARM_UID_CAPABILITY_IND			0x75
#define ISUP_PARM_REDIRECT_COUNTER				0x77
#define ISUP_PARM_APPLICATION_TRANSPORT			0x78
#define ISUP_PARM_COLLECT_CALL_REQUEST			0x79
#define ISUP_PARM_CCNR_POSSIBLE_IND				0x7a
#define ISUP_PARM_PIVOT_CAPABILITY				0x7b
#define ISUP_PARM_PIVOT_ROUTING_IND				0x7c
#define ISUP_PARM_CALLED_DIRECTORY_NUMBER		0x7d
#define ISUP_PARM_ORIGINAL_CALLED_IN_NUM		0x7f
/* 0x80 reserved for future extension */
#define ISUP_PARM_CALLING_GEODETIC_LOCATION		0x81
#define ISUP_PARM_HTR_INFO						0x82
#define ISUP_PARM_NETWORK_ROUTING_NUMBER		0x84
#define ISUP_PARM_QUERY_ON_RELEASE_CAPABILITY	0x85
#define ISUP_PARM_PIVOT_STATUS					0x86
#define ISUP_PARM_PIVOT_COUNTER					0x87
#define ISUP_PARM_PIVOT_ROUTING_FORWARD_IND		0x88
#define ISUP_PARM_PIVOT_ROUTING_BACKWARD_IND	0x89
#define ISUP_PARM_REDIRECT_STATUS				0x8a
#define ISUP_PARM_REDIRECT_FORWARD_INFO			0x8b
#define ISUP_PARM_REDIRECT_BACKWARD_INFO		0x8c
#define ISUP_PARM_NUM_PORTABILITY_FORWARD_INFO	0x8d
#define ISUP_PARM_GENERIC_ADDR					0xc0
#define ISUP_PARM_GENERIC_DIGITS				0xc1
#define ISUP_PARM_EGRESS_SERV					0xc3
#define ISUP_PARM_JIP							0xc4
#define ISUP_PARM_CARRIER_ID					0xc5
#define ISUP_PARM_BUSINESS_GRP					0xc6
#define ISUP_PARM_GENERIC_NAME					0xc7
#define ISUP_PARM_LOCAL_SERVICE_PROVIDER_IDENTIFICATION	0xe4
#define ISUP_PARM_ORIG_LINE_INFO				0xea
#define ISUP_PARM_CHARGE_NUMBER					0xeb
#define ISUP_PARM_SELECTION_INFO				0xee

#define ISUP_PARM_INVAL 0

#define PARM_CALLED_PARTY_NUM_IDX 3
#define PARM_NATURE_OF_CONNECTION_IND_IDX 5
#define PARM_FORWARD_CALL_IND_IDX 6
#define PARM_CALLING_PARTY_NUM_IDX 9
#define PARM_BACKWARD_CALL_IND_IDX 16
#define PARM_CAUSE_IDX 17
#define PARM_INVAL_IDX 108


#define MAX_NO_FIXED_PARAMS 4
#define MAX_NO_VAR_PARAMS 2
#define PARAM_MAX_LEN 128
#define PV_RES_BUF_MAXLEN 256
#define MAX_PREDEF_VALS 15


typedef void (*isup_param_parse_f)(int subfield_idx, unsigned char *param_val, int len,
									int *int_res, str *str_res);
typedef int (*isup_param_write_f)(int param_idx, int subfield_idx, unsigned char *param_val,
									int *len, pv_value_t *val);

struct isup_predef_vals {
	int no_vals;
	str aliases[MAX_PREDEF_VALS];
	unsigned char vals[MAX_PREDEF_VALS];
};

struct isup_subfield {
	str name;
	struct isup_predef_vals predef_vals;
};

struct isup_param_data {
	int param_code;
	str name;
	isup_param_parse_f parse_func;
	isup_param_write_f write_func;
	struct isup_subfield *subfield_list;
	struct isup_predef_vals *single_fld_pvals;
	int len;	/* for mandatory fixed params */
};

struct isup_message_data {
	str name;
	char short_name[3];
	int message_type;		/* message type code */
	int mand_fixed_params;	/* no mandatory fixed params */
	int mand_var_params;	/* no mandatory variable params */
	int *mand_param_list;
};

struct param_parsed_struct {
	unsigned char param_code;
	unsigned char len;
	unsigned char val[PARAM_MAX_LEN];
};

struct opt_param {
	struct param_parsed_struct param;
	struct opt_param *next;
};

struct isup_parsed_struct {
	int message_type;
	int total_len;
	int no_opt_params;
	struct param_parsed_struct mand_fix_params[MAX_NO_FIXED_PARAMS];
	struct param_parsed_struct mand_var_params[MAX_NO_VAR_PARAMS];
	struct opt_param *opt_params_list;
};

extern struct isup_message_data isup_messages[NO_ISUP_MESSAGES];
extern struct isup_param_data isup_params[NO_ISUP_PARAMS];

char char2digit(char localchar);

#endif /* _ISUP_H_ */
