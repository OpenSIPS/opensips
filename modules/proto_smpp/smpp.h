/*
 * Copyright (C) 2019 - OpenSIPS Project
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

#ifndef _SMPP_H_
#define _SMPP_H_

#define SMPP_UNKNOWN 0
#define SMPP_OPEN 1
#define SMPP_BOUND_TX 2
#define SMPP_BOUND_RX 4
#define SMPP_BOUND_TRX 6
#define SMPP_CLOSED 7

#define SMPP_BIND_TRANSCEIVER 0
#define SMPP_BIND_TRANSMITTER 1
#define SMPP_BIND_RECEIVER 2
#define SMPP_OUTBIND 3

#define SMPP_VERSION 0x34

#define HEADER_SZ 16
#define BIND_RECEIVER_BODY_MAX_SZ 82
#define BIND_TRANSMITTER_BODY_MAZ_SZ BIND_RECEIVER_RESP_BODY_MAX_SZ
#define BIND_TRANSCEIVER_BODY_MAZ_SZ BIND_RECEIVER_RESP_BODY_MAX_SZ
#define BIND_RECEIVER_RESP_BODY_MAX_SZ 16
#define BIND_TRANSMITTER_RESP_BODY_MAX_SZ BIND_RECEIVER_RESP_BODY_MAX_SZ
#define BIND_TRANSCEIVER_RESP_BODY_MAX_SZ BIND_RECEIVER_RESP_BODY_MAX_SZ
#define SUBMIT_SM_BODY_MAX_SZ 348
#define DELIVER_SM_RESP_BODY_MAX_SZ 1
#define SUBMIT_SM_RESP_BODY_MAX_SZ 1
#define ENQUIRE_LINK_BODY_MAX_SZ 0
#define REQ_MAX_SZ(_name) (HEADER_SZ + _name ## _BODY_MAX_SZ)

#define ESME_ROK	0x00000000
#define ESME_RBINDFAIL	0x0000000D

#define GENERIC_NACK_CID			0x80000000
#define BIND_RECEIVER_CID			0x00000001
#define BIND_RECEIVER_RESP_CID		0x80000001
#define BIND_TRANSMITTER_CID		0x00000002
#define BIND_TRANSMITTER_RESP_CID	0x80000002
#define QUERY_SM_CID				0x00000003
#define QUERY_SM_RESP_CID			0x80000003
#define SUBMIT_SM_CID				0x00000004
#define SUBMIT_SM_RESP_CID			0x80000004
#define DELIVER_SM_CID				0x00000005
#define DELIVER_SM_RESP_CID			0x80000005
#define UNBIND_CID					0x00000006
#define UNBIND_RESP_CID				0x80000006
#define REPLACE_SM_CID				0x00000007
#define REPLACE_SM_RESP_CID			0x80000007
#define CANCEL_SM_CID				0x00000008
#define CANCEL_SM_RESP_CID			0x80000008
#define BIND_TRANSCEIVER_CID		0x00000009
#define BIND_TRANSCEIVER_RESP_CID	0x80000009
#define OUTBIND_CID					0x0000000B
#define ENQUIRE_LINK_CID			0x00000015
#define ENQUIRE_LINK_RESP_CID		0x80000015
#define SUBMIT_MULTI_CID			0x00000021
#define SUBMIT_MULTI_RESP_CID		0x80000021
#define ALERT_NOTIFICATION_CID		0x00000102
#define DATA_SM_CID					0x00000103
#define DATA_SM_RESP_CID			0x80000103

#define GENERIC_NACK_CID_STR			"generic_nack"
#define BIND_RECEIVER_CID_STR			"bind_receiver"
#define BIND_RECEIVER_RESP_CID_STR		"bind_receiver_resp"
#define BIND_TRANSMITTER_CID_STR		"bind_transmitter"
#define BIND_TRANSMITTER_RESP_CID_STR	"bind_transmitter_resp"
#define QUERY_SM_CID_STR				"query_sm"
#define QUERY_SM_RESP_CID_STR			"query_sm_resp"
#define SUBMIT_SM_CID_STR				"submit_sm"
#define SUBMIT_SM_RESP_CID_STR			"submit_sm_resp"
#define DELIVER_SM_CID_STR				"deliver_sm"
#define DELIVER_SM_RESP_CID_STR			"deliver_sm_resp"
#define UNBIND_CID_STR					"unbind"
#define UNBIND_RESP_CID_STR				"unbind_resp"
#define REPLACE_SM_CID_STR				"replace_sm"
#define REPLACE_SM_RESP_CID_STR			"replace_sm_resp"
#define CANCEL_SM_CID_STR				"cancel_sm"
#define CANCEL_SM_RESP_CID_STR			"cancel_sm_resp"
#define BIND_TRANSCEIVER_CID_STR		"bind_transceiver"
#define BIND_TRANSCEIVER_RESP_CID_STR	"bind_transceiver_resp"
#define OUTBIND_CID_STR					"outbind"
#define ENQUIRE_LINK_CID_STR			"enquire_link"
#define ENQUIRE_LINK_RESP_CID_STR		"enquire_link_resp"
#define SUBMIT_MULTI_CID_STR			"submit_multi"
#define SUBMIT_MULTI_RESP_CID_STR		"submit_multi_resp"
#define ALERT_NOTIFICATION_CID_STR		"alert_notification"
#define DATA_SM_CID_STR					"data_sm"
#define DATA_SM_RESP_CID_STR			"data_sm_resp"

typedef struct {
	uint32_t command_length;
	uint32_t command_id;
	uint32_t command_status;
	uint32_t sequence_number;
} smpp_header_t;

typedef struct smpp_optional{
	uint16_t parameter_tag;
	uint16_t length;
	void *value;
	struct smpp_optional *next;
} smpp_optional_t;

#define MAX_SYSTEM_ID_LEN 16
#define MAX_PASSWORD_LEN 9
#define MAX_SYSTEM_TYPE_LEN 13
#define MAX_ADDRESS_RANGE_LEN 41
#define MAX_SERVICE_TYPE_LEN 6
#define MAX_ADDRESS_LEN 21
#define MAX_SCHEDULE_DELIVERY_LEN 1
#define MAX_VALIDITY_PERIOD 1
#define MAX_MESSAGE_ID 65

typedef struct {
	char system_id[MAX_SYSTEM_ID_LEN];
	char password[MAX_PASSWORD_LEN];
	char system_type[MAX_SYSTEM_TYPE_LEN];
	uint8_t interface_version;
	uint8_t addr_ton;
	uint8_t addr_npi;
	char address_range[MAX_ADDRESS_RANGE_LEN];
} smpp_bind_receiver_t;

typedef struct {
	char system_id[MAX_SYSTEM_ID_LEN];
} smpp_bind_receiver_resp_t;

typedef smpp_bind_receiver_t smpp_bind_transmitter_t;
typedef smpp_bind_receiver_resp_t smpp_bind_transmitter_resp_t;
typedef smpp_bind_receiver_t smpp_bind_transceiver_t;
typedef smpp_bind_receiver_resp_t smpp_bind_transceiver_resp_t;

typedef struct {
	char system_id[MAX_SYSTEM_ID_LEN];
	char password[MAX_PASSWORD_LEN];
} smpp_outbind_t;

typedef struct {
	char service_type[MAX_SERVICE_TYPE_LEN];
	uint8_t source_addr_ton;
	uint8_t source_addr_npi;
	char source_addr[MAX_ADDRESS_LEN];
	uint8_t dest_addr_ton;
	uint8_t dest_addr_npi;
	char destination_addr[MAX_ADDRESS_LEN];
	uint8_t esm_class;
	uint8_t protocol_id;
	uint8_t protocol_flag;
	char schedule_delivery_time[MAX_SCHEDULE_DELIVERY_LEN];
	char validity_period[MAX_VALIDITY_PERIOD];
	uint8_t registered_delivery;
	uint8_t replace_if_present_flag;
	uint8_t data_coding;
	uint8_t sm_default_msg_id;
	uint8_t sm_length;
	char short_message[254];
} smpp_submit_sm_t;

typedef struct {
	char message_id[MAX_MESSAGE_ID];
} smpp_submit_sm_resp_t;

typedef smpp_submit_sm_t smpp_deliver_sm_t;
typedef smpp_submit_sm_resp_t smpp_deliver_sm_resp_t;

#define TYPEDEF_SMPP_REQUEST(_name) \
typedef struct { \
	smpp_header_t *header; \
	_name ## _t *body; \
	smpp_optional_t *optionals; \
	str payload; \
} _name ## _req_t

#define TYPEDEF_SIMPLE_SMPP_REQUEST(_name) \
typedef struct { \
	smpp_header_t *header; \
	smpp_optional_t *optionals; \
	str payload; \
} _name ## _req_t

TYPEDEF_SMPP_REQUEST(smpp_bind_receiver);
TYPEDEF_SMPP_REQUEST(smpp_bind_receiver_resp);
TYPEDEF_SMPP_REQUEST(smpp_bind_transmitter);
TYPEDEF_SMPP_REQUEST(smpp_bind_transmitter_resp);
TYPEDEF_SMPP_REQUEST(smpp_bind_transceiver);
TYPEDEF_SMPP_REQUEST(smpp_bind_transceiver_resp);
TYPEDEF_SMPP_REQUEST(smpp_deliver_sm);
TYPEDEF_SMPP_REQUEST(smpp_deliver_sm_resp);
TYPEDEF_SMPP_REQUEST(smpp_submit_sm);
TYPEDEF_SMPP_REQUEST(smpp_submit_sm_resp);
TYPEDEF_SIMPLE_SMPP_REQUEST(smpp_enquire_link);
TYPEDEF_SIMPLE_SMPP_REQUEST(smpp_enquire_link_resp);

#define MAX_SMS_CHARACTERS	140

#define SMPP_CODING_DEFAULT	0
#define SMPP_CODING_LATIN1	3
#define SMPP_CODING_UCS2	8

#endif
