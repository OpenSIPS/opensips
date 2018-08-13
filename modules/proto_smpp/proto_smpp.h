#ifndef _PROTO_SMPP_H_
#define _PROTO_SMPP_H_

#define SMPP_UNKNOWN 0
#define SMPP_OPEN 1
#define SMPP_DOWN 2
#define SMPP_CLOSED 3

#define BIND_RECEIVER 0
#define BIND_TRANSMITTER 1
#define BIND_TRANSCEIVER 2

#define SMPP_VERSION 0x34

#define HEADER_SZ 16
#define BIND_RECEIVER_BODY_MAX_SZ 82
#define SUBMIT_SM_BODY_MAX_SZ 348
#define DELIVER_SM_RESP_BODY_MAX_SZ 1
#define ENQUIRE_LINK_BODY_MAX_SZ 0
#define REQ_MAX_SZ(_name) (HEADER_SZ + _name ## _BODY_MAX_SZ)


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

typedef struct {
	char system_id[16];
	char password[9];
	char system_type[13];
	uint8_t interface_version;
	uint8_t addr_ton;
	uint8_t addr_npi;
	char address_range[41];
} smpp_bind_receiver_t;

typedef struct {
	char system_id[16];
} smpp_bind_receiver_resp_t;

typedef smpp_bind_receiver_t smpp_bind_transmitter_t;
typedef smpp_bind_receiver_resp_t smpp_bind_transmitter_resp_t;
typedef smpp_bind_receiver_t smpp_bind_transceiver_t;
typedef smpp_bind_receiver_resp_t smpp_bind_transceiver_resp_t;

typedef struct {
	char service_type[6];
	uint8_t source_addr_ton;
	uint8_t source_addr_npi;
	char source_addr[21];
	uint8_t dest_addr_ton;
	uint8_t dest_addr_npi;
	char destination_addr[21];
	uint8_t esm_class;
	uint8_t protocol_id;
	uint8_t protocol_flag;
	char schedule_delivery_time[1];
	char validity_period[1];
	uint8_t registered_delivery;
	uint8_t replace_if_present_flag;
	uint8_t data_coding;
	uint8_t sm_default_msg_id;
	uint8_t sm_length;
	char short_message[254];
} smpp_deliver_sm_t;

typedef struct {
	char message_id[1];
} smpp_deliver_sm_resp_t;

typedef struct {
	char service_type[6];
	uint8_t source_addr_ton;
	uint8_t source_addr_npi;
	char source_addr[21];
	uint8_t dest_addr_ton;
	uint8_t dest_addr_npi;
	char destination_addr[21];
	uint8_t esm_class;
	uint8_t protocol_id;
	uint8_t protocol_flag;
	char schedule_delivery_time[17];
	char validity_period[17];
	uint8_t registered_delivery;
	uint8_t replace_if_present_flag;
	uint8_t data_coding;
	uint8_t sm_default_msg_id;
	uint8_t sm_length;
	char short_message[254];
} smpp_submit_sm_t;

typedef struct {
	char message_id[65];
} smpp_submit_sm_resp_t;

#define TYPEDEF_SMPP_REQUEST(_name) \
typedef struct { \
	smpp_header_t *header; \
	_name ## _t *body; \
	str payload; \
} _name ## _req_t

#define TYPEDEF_SIMPLE_SMPP_REQUEST(_name) \
typedef struct { \
	smpp_header_t *header; \
	str payload; \
} _name ## _req_t

TYPEDEF_SMPP_REQUEST(smpp_bind_receiver);
TYPEDEF_SMPP_REQUEST(smpp_bind_transmitter);
TYPEDEF_SMPP_REQUEST(smpp_bind_transceiver);
TYPEDEF_SMPP_REQUEST(smpp_deliver_sm);
TYPEDEF_SMPP_REQUEST(smpp_deliver_sm_resp);
TYPEDEF_SMPP_REQUEST(smpp_submit_sm);
TYPEDEF_SIMPLE_SMPP_REQUEST(smpp_enquire_link);
TYPEDEF_SIMPLE_SMPP_REQUEST(smpp_enquire_link_resp);

typedef struct smpp_session {
	uint32_t id;
	uint8_t session_status;
	uint8_t session_type;

	gen_lock_t sequence_number_lock;
	uint32_t sequence_number;

	struct ip_addr *ip;
	int port;

	struct tcp_connection *conn;

	union {
		smpp_bind_receiver_t receiver;
		smpp_bind_transmitter_t trasmitter;
		smpp_bind_transceiver_t transceiver;
	} bind;

	struct smpp_session *next;

} smpp_session_t;

#endif
