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
 * History
 * -------
 *  2003-01-28  removed scratchpad (jiri)
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-03-06  enum_request_method changed to begin with 1;
 *               0 reserved for invalid values; (jiri)
 *  2003-03-31  removed sip_msg->repl_add_rm (andrei)
 *  2003-04-01  2 macros added: GET_NEXT_HOP and GET_RURI (janakj)
 *  2003-04-04  structure for parsed inbound uri added (jiri)
 *  2003-04-11  updated the  sip_uri structure (lots of fields added) (andrei)
 *  2003-04-12  added msg_flags to sip_msg (andrei)
 *  2003-11-02  added diversion header field to sip_msg (jh)
 *  2004-11-08  added force_send_socket (andrei)
 *  2005-02-25  uri types added (sip, sips & tel)  (andrei)
 *  2006-02-17  Session-Expires, Min-SE (dhsueh@somanetworks.com)
 *  2007-09-09  added sdp structure (osas)
 *  2011-04-20  added support for URI unknown parameters (osas)
 */


#ifndef MSG_PARSER_H
#define MSG_PARSER_H

#include <strings.h>

#include "../str.h"
#include "../lump_struct.h"
#include "../flags.h"
#include "../ip_addr.h"
#include "../md5utils.h"
#include "../qvalue.h"
#include "../config.h"
#include "parse_def.h"
#include "parse_cseq.h"
#include "parse_content.h"
#include "parse_via.h"
#include "parse_fline.h"
#include "parse_body.h"
#include "hf.h"
#include "../trim.h"


/* convenience short-cut macros */
#define REQ_LINE(_msg) ((_msg)->first_line.u.request)
#define REQ_METHOD   first_line.u.request.method_value
#define REQ_METHOD_S first_line.u.request.method
#define REPLY_STATUS first_line.u.reply.statuscode
#define REPLY_CLASS(_reply) ((_reply)->REPLY_STATUS/100)

/* number methods as power of two to allow bitmap matching */
enum request_method {
	METHOD_UNDEF=0,           /* 0 - --- */
	METHOD_INVITE=1,          /* 1 - 2^0 */
	METHOD_CANCEL=2,          /* 2 - 2^1 */
	METHOD_ACK=4,             /* 3 - 2^2 */
	METHOD_BYE=8,             /* 4 - 2^3 */
	METHOD_INFO=16,           /* 5 - 2^4 */
	METHOD_OPTIONS=32,        /* 6 - 2^5 */
	METHOD_UPDATE=64,         /* 7 - 2^6 */
	METHOD_REGISTER=128,      /* 8 - 2^7 */
	METHOD_MESSAGE=256,       /* 9 - 2^8 */
	METHOD_SUBSCRIBE=512,     /* 10 - 2^9 */
	METHOD_NOTIFY=1024,       /* 11 - 2^10 */
	METHOD_PRACK=2048,        /* 12 - 2^11 */
	METHOD_REFER=4096,        /* 13 - 2^12 */
	METHOD_PUBLISH=8192,      /* 14 - 2^13 */
	METHOD_OTHER=16384        /* 15 - 2^14 */
};

#define FL_FORCE_RPORT       (1<<0)  /* force rport (top via) */
#define FL_FORCE_ACTIVE      (1<<1)  /* force active SDP */
#define FL_FORCE_LOCAL_RPORT (1<<2)  /* force local rport (local via) */
#define FL_SDP_IP_AFS        (1<<3)  /* SDP IP rewritten */
#define FL_SDP_PORT_AFS      (1<<4)  /* SDP port rewritten */
#define FL_SHM_CLONE         (1<<5)  /* msg cloned in SHM as a single chunk */
#define FL_USE_UAC_FROM      (1<<6)  /* take FROM hdr from UAC insteas of UAS*/
#define FL_USE_UAC_TO        (1<<7)  /* take TO hdr from UAC insteas of UAS */
#define FL_USE_UAC_CSEQ      (1<<8)  /* take CSEQ hdr from UAC insteas of UAS*/
#define FL_REQ_UPSTREAM      (1<<9)  /* it's an upstream going request */
#define FL_DO_KEEPALIVE      (1<<10) /* keepalive request's source after a
                                      * positive reply */
#define FL_USE_MEDIA_PROXY   (1<<11) /* use mediaproxy on all messages during
                                      * a dialog */
#define FL_USE_RTPPROXY      (1<<12) /* used by rtpproxy to remember if the msg
                                      * callback had already been registered */
#define FL_NAT_TRACK_DIALOG  (1<<13) /* trigger dialog tracking from the
                                      * nat_traversal module */
#define FL_USE_SIPTRACE      (1<<14) /* used by tracer to check if the tm
                                      * callbacks were registered */
#define FL_SHM_UPDATABLE     (1<<15) /* a SHM cloned message can be updated
                                      * (TM used, requires FL_SHM_CLONE) */
#define FL_SHM_UPDATED       (1<<16) /* an updatable SHM cloned message that 
                                      * had at least one update; if the flag is
                                      * missing, it means the cloned msg was
                                      * never updated.
                                      * (TM used, requires FL_SHM_UPDATABLE) */
#define FL_TM_CB_REGISTERED  (1<<17) /* tm callbacks for this message have been
                                      * registered (by setting this flag, you
                                      * will know if any tm callbacks for this
                                      * message have been registered) */
#define FL_TM_FAKE_REQ       (1<<18) /* the SIP request is a fake one,
                                      * generated based on the transaction,
                                      * either in failure route or resume 
                                      * route */
#define FL_TM_REPLICATED	 (1<<19) /* message received due to a tm replication */
#define FL_BODY_NO_SDP       (1<<20) /* message does not have an SDP body */

/* define the # of unknown URI parameters to parse */
#define URI_MAX_U_PARAMS 10

#define IFISMETHOD(methodname,firstchar)                                  \
if (  (*tmp==(firstchar) || *tmp==((firstchar) | 32)) &&                  \
        strncasecmp( tmp+1, (char *)#methodname+1, methodname##_LEN-1)==0 &&     \
        *(tmp+methodname##_LEN)==' ') {                                   \
                fl->type=SIP_REQUEST;                                     \
                fl->u.request.method.len=methodname##_LEN;                \
                fl->u.request.method_value=METHOD_##methodname;           \
                tmp=buffer+methodname##_LEN;                              \
}


/*
 * Return a URI to which the message should be really sent (not what should
 * be in the Request URI. The following fields are tried in this order:
 * 1) dst_uri
 * 2) new_uri
 * 3) first_line.u.request.uri
 */
#define GET_NEXT_HOP(m) \
(((m)->dst_uri.s && (m)->dst_uri.len) ? (&(m)->dst_uri) : \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri)))


/*
 * Return the Reqeust URI of a message.
 * The following fields are tried in this order:
 * 1) new_uri
 * 2) first_line.u.request.uri
 */
#define GET_RURI(m) \
(((m)->new_uri.s && (m)->new_uri.len) ? (&(m)->new_uri) : (&(m)->first_line.u.request.uri))


enum _uri_type{ERROR_URI_T=0, SIP_URI_T, SIPS_URI_T, TEL_URI_T, TELS_URI_T, URN_SERVICE_URI_T, URN_NENA_SERVICE_URI_T};
typedef enum _uri_type uri_type;

struct sip_uri {
	str user;     /* Username */
	str passwd;   /* Password */
	str host;     /* Host name */
	str port;     /* Port number */
	str params;   /* Parameters */
	str headers;
	unsigned short port_no;
	unsigned short proto; /* from transport */
	uri_type type; /* uri scheme */

	/* parameters [+ "=value" parts, if any] */
	str transport;
	str ttl;
	str user_param;
	str maddr;
	str method;
	str lr;
	str r2; /* ser specific rr parameter */
	str gr; /* GRUU */
	str pn_provider; /* RFC 8599 (SIP PN) */
	str pn_prid;
	str pn_param;
	str pn_purr;

	/* just values */
	str transport_val;
	str ttl_val;
	str user_param_val;
	str maddr_val;
	str method_val;
	str lr_val; /* lr value placeholder for lr=on a.s.o*/
	str r2_val;
	str gr_val;
	str pn_provider_val;
	str pn_prid_val;
	str pn_param_val;
	str pn_purr_val;

	/* unknown params */
	str u_name[URI_MAX_U_PARAMS]; /* Unknown param names */
	str u_val[URI_MAX_U_PARAMS];  /* Unknown param valss */
	unsigned short u_params_no;   /* No of unknown params */
};


#include "parse_to.h"

/* Forward declaration */
struct msg_callback;

struct sip_msg {
	unsigned int id;               /* message id, unique/process*/
	struct msg_start first_line;   /* Message first line */
	struct via_body* via1;         /* The first via */
	struct via_body* via2;         /* The second via */
	struct hdr_field* headers;     /* All the parsed headers*/
	struct hdr_field* last_header; /* Pointer to the last parsed header*/
	hdr_flags_t parsed_flag;       /* Already parsed header field types */

	/* Via, To, CSeq, Call-Id, From, end of header*/
	/* pointers to the first occurrences of these headers;
	 * everything is also saved in 'headers'
	 * (WARNING: do not deallocate them twice!)*/

	struct hdr_field* h_via1;
	struct hdr_field* h_via2;
	struct hdr_field* callid;
	struct hdr_field* to;
	struct hdr_field* cseq;
	struct hdr_field* from;
	struct hdr_field* contact;
	struct hdr_field* maxforwards;
	struct hdr_field* route;
	struct hdr_field* record_route;
	struct hdr_field* path;
	struct hdr_field* content_type;
	struct hdr_field* content_length;
	struct hdr_field* authorization;
	struct hdr_field* expires;
	struct hdr_field* proxy_auth;
	struct hdr_field* supported;
	struct hdr_field* proxy_require;
	struct hdr_field* unsupported;
	struct hdr_field* allow;
	struct hdr_field* event;
	struct hdr_field* accept;
	struct hdr_field* accept_language;
	struct hdr_field* organization;
	struct hdr_field* priority;
	struct hdr_field* subject;
	struct hdr_field* user_agent;
	struct hdr_field* content_disposition;
	struct hdr_field* accept_disposition;
	struct hdr_field* diversion;
	struct hdr_field* rpid;
	struct hdr_field* refer_to;
	struct hdr_field* session_expires;
	struct hdr_field* min_se;
	struct hdr_field* ppi;
	struct hdr_field* pai;
	struct hdr_field* privacy;
	struct hdr_field* call_info;
	struct hdr_field* www_authenticate;
	struct hdr_field* proxy_authenticate;
	struct hdr_field* min_expires;
	struct hdr_field* feature_caps;
	struct hdr_field* replaces;

	struct sip_msg_body *body;

	char* eoh;        /* pointer to the end of header (if found) or null */
	char* unparsed;   /* here we stopped parsing*/

	struct receive_info rcv; /* source & dest ip, ports, proto a.s.o*/

	char* buf;        /* scratch pad, holds a unmodified message,
                           *  via, etc. point into it */
	unsigned int len; /* message len (orig) */

	/* attributes of the msg as first/default branch */
	str new_uri; /* changed first line uri, when you change this
                  * don't forget to set parsed_uri_ok to 0 */
	str dst_uri; /* Destination URI, must be forwarded to this URI if len!=0 */

	qvalue_t ruri_q; /* Q value of RURI */

	unsigned int ruri_bflags; /* per-branch flags for RURI*/

	/* force sending on this socket */
	struct socket_info* force_send_socket;

	/* path vector to generate Route hdrs */
	str path_vec;
	/* end-of-attributes for RURI as first branch*/

	/* current uri */
	int parsed_uri_ok; /* 1 if parsed_uri is valid, 0 if not, set it to 0
	                      if you modify the uri (e.g change new_uri)*/
	struct sip_uri parsed_uri; /* speed-up > keep here the parsed uri*/

	/* the same for original uri */
	int parsed_orig_ruri_ok;
	struct sip_uri parsed_orig_ruri;

	/* modifications */
	struct lump* add_rm;       /* used for all the forwarded requests/replies */
	struct lump* body_lumps;     /* Lumps that update Content-Length */
	struct lump_rpl *reply_lump; /* only for localy generated replies !!!*/

	/* whatever whoever want to append to branch comes here */
	char add_to_branch_s[MAX_BRANCH_PARAM_LEN];
	int add_to_branch_len;

	/* index to TM hash table; stored in core to avoid
	 * unnecessary calculations */
	unsigned int  hash_index;

	/* flags used from script */
	flag_t flags;

	/* flags used by core - allows to set various flags on the message; may
	 * be used for simple inter-module communication or remembering
	 * processing state reached */
	unsigned int msg_flags;

	str set_global_address;
	str set_global_port;

	struct msg_callback *msg_cb;
};


/* pointer to a fakes message which was never received ;
   (when this message is "relayed", it is generated out
    of the original request)
*/
#define FAKED_REPLY     ((struct sip_msg *) -1)

extern int via_cnt;

int parse_msg(char* buf, unsigned int len, struct sip_msg* msg);

int parse_headers(struct sip_msg* msg, hdr_flags_t flags, int next);

char* get_hdr_field(char* buf, char* end, struct hdr_field* hdr);

void free_sip_msg(struct sip_msg* msg);

int clone_headers(struct sip_msg *from_msg, struct sip_msg *to_msg);

/* make sure all HFs needed for transaction identification have been
   parsed; return 0 if those HFs can't be found
 */

int check_transaction_quadruple( struct sip_msg* msg );

/* calculate characteristic value of a message -- this value
   is used to identify a transaction during the process of
   reply matching
 */
inline static int char_msg_val( struct sip_msg *msg, char *cv )
{
	str src[8];

	if (!check_transaction_quadruple(msg)) {
		LM_ERR("can't calculate char_value due to a parsing error\n");
		memset( cv, '0', MD5_LEN );
		return 0;
	}

	src[0]= msg->from->body;
	src[1]= msg->to->body;
	src[2]= msg->callid->body;
	src[3]= msg->first_line.u.request.uri;
	src[4]= get_cseq( msg )->number;

	/* topmost Via is part of transaction key as well ! */
	src[5]= msg->via1->host;
	src[6]= msg->via1->port_str;
	if (msg->via1->branch) {
		src[7]= msg->via1->branch->value;
		MD5StringArray ( cv, src, 8 );
	} else {
		MD5StringArray( cv, src, 7 );
	}
	return 1;
}


/* returns the body of the SIP message (if none, an empty body will be returned)
 */
inline static int get_body(struct sip_msg *msg, str *body)
{
	unsigned int hdrs_len;
	int ct_len;

	if ( parse_headers(msg,HDR_EOH_F, 0)==-1 )
		return -1;

	if (msg->unparsed){
		hdrs_len=(unsigned int)(msg->unparsed-msg->buf);
	} else {
		return -1;
	}

	if ((hdrs_len+2<=msg->len) && (strncmp(CRLF,msg->unparsed,CRLF_LEN)==0) )
		body->s = msg->unparsed + CRLF_LEN;
	else if ( (hdrs_len+1<=msg->len) &&
	(*(msg->unparsed)=='\n' || *(msg->unparsed)=='\r' ) )
		body->s = msg->unparsed + 1;
	else {
		/* no body */
		body->s = NULL;
		body->len = 0;
		return 0;
	}

	/* determin the length of the body */
	body->len = msg->buf + msg->len - body->s;

	/* double check the len against content-length hdr
	   (if present, it must be already parsed) */
	if (msg->content_length) {
		ct_len = get_content_length( msg );
		if (ct_len<body->len)
			body->len = ct_len;
	} else {
		/* no ct -> no body */
		body->s = NULL;
		body->len = 0;
	}

	return 0;
}

/*
 * Get the callid of a message. If returned value is 0, the callid is stored
 * in the _cid field, otherwise -1 is returned on error
 */
inline static int get_callid(struct sip_msg* _m, str* _cid)
{
	if ((parse_headers(_m, HDR_CALLID_F, 0) == -1)) {
		LM_ERR("failed to parse call-id header\n");
		return -1;
	}

	if (_m->callid == NULL) {
		LM_ERR("call-id not found\n");
		return -1;
	}

	_cid->s = _m->callid->body.s;
	_cid->len = _m->callid->body.len;
	trim(_cid);
	return 0;
}


/*
 * Search through already parsed headers (no parsing done) a non-standard
 * header - all known headers are skipped!
 */
#define get_header_by_static_name(_msg, _name) \
		get_header_by_name(_msg, _name, sizeof(_name)-1)
inline static struct hdr_field *get_header_by_name( struct sip_msg *msg,
													char *s, unsigned int len)
{
	struct hdr_field *hdr;

	for( hdr=msg->headers ; hdr ; hdr=hdr->next ) {
		if(len==hdr->name.len && strncasecmp(hdr->name.s,s,len)==0)
			return hdr;
	}
	return NULL;
}


/*
 * Make a private copy of the string and assign it to new_uri (new RURI)
 */
int set_ruri(struct sip_msg* msg, str* uri);


/*
 * Make a private copy of the string and assign it to dst_uri
 */
int set_dst_uri(struct sip_msg* msg, str* uri);


void reset_dst_uri(struct sip_msg *msg);


int set_dst_host_port(struct sip_msg *msg, str *host, str *port);


enum rw_ruri_part {
	RW_RURI_HOST = 1,
	RW_RURI_HOSTPORT,
	RW_RURI_USER,
	RW_RURI_USERPASS,
	RW_RURI_PORT,
	RW_RURI_PREFIX,
	RW_RURI_STRIP,
	RW_RURI_STRIP_TAIL
};

int rewrite_ruri(struct sip_msg *msg, str *sval, int ival,
				enum rw_ruri_part part);


/*
 * Set the q value of the Request-URI
 */
#define set_ruri_q(_msg,_q) \
	(_msg)->ruri_q = _q


/*
 * Get the q value of the Request-URI
 */
#define get_ruri_q(_msg) \
	(_msg)->ruri_q


/*
 * Get the per branch flags for RURI
 */
#define getb0flags(_msg) \
	(_msg)->ruri_bflags


/*
 * Set the per branch flags for RURI
 */
#define setb0flags( _msg, _flags) \
	(_msg)->ruri_bflags = _flags


/*
 * Make a private copy of the string and assign it to path_vec
 */
int set_path_vector(struct sip_msg* msg, str* path);
void clear_path_vector(struct sip_msg* msg);


/*
 * Parses a buffer containing a well formed SIP message and extracts the bodies
 * for FROM , TO , CSEQ and CALL-ID headers.
 */
int extract_ftc_hdrs( char *buf, int len, str *from, str *to, str *cseq,str *callid);

#endif
