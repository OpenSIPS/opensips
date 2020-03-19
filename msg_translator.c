/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Andreas Granig <agranig@linguin.org>
 *   ( covers insert_path_as_route() )
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
 * 2003-01-20  bug_fix: use of return value of snprintf aligned to C99 (jiri)
 * 2003-01-23  added rport patches, contributed by
 *              Maxim Sobolev <sobomax@FreeBSD.org> and heavily modified by me
 *              (andrei)
 * 2003-01-24  added i param to via of outgoing requests (used by tcp),
 *              modified via_builder params (andrei)
 * 2003-01-27  more rport fixes (make use of new via_param->start)  (andrei)
 * 2003-01-27  next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2003-01-29  scratchpad removed (jiri)
 * 2003-02-28  scratchpad compatibility abandoned (jiri)
 * 2003-03-01  VOICE_MAIL defs removed (jiri)
 * 2003-03-06  totags in outgoing replies bookmarked to enable
 *             ACK/200 tag matching (andrei)
 * 2003-03-18  killed the build_warning snprintf (andrei)
 * 2003-03-31  added subst lump support (andrei)
 * 2003-04-01  added opt (conditional) lump support (andrei)
 * 2003-04-02  added more subst lumps: SUBST_{SND,RCV}_ALL
 *              => ip:port;transport=proto (andrei)
 * 2003-04-12  added FL_FORCE_RPORT support (andrei)
 * 2003-04-13  updated warning builder -- fixed (andrei)
 * 2003-07-10  check_via_address knows now how to compare with ipv6 address
 *              references (e.g [::1]) (andrei)
 *             build_req_fomr_sip_req no longer adds 1 for ipv6 via parameter
 *              position calculations ([] are part of host.s now) (andrei)
 * 2003-10-02  via+lump dst address/port can be set to preset values (andrei)
 * 2003-10-08  receive_test function-alized (jiri)
 * 2003-10-20  added body_lump list (sip_msg), adjust_clen (andrei & jan)
 * 2003-11-11  type of rpl_lumps replaced by flags (bogdan)
 * 2007-02-22  insert_path_as_route() imported from TM as we need it for
 *             stateless processing also; contributed by Andreas Granig
 *             (bogdan)
 */

/*!
 * \file
 * \brief Create and translate SIP messages/ message contents
 * - \ref ViaSpecialParams
 */

/*! \page ViaSpecialParams Via header special parameters
 *
 * Via special params:
 *
 * \section requests Requests:
 * - if the address in via is different from the src_ip or an existing
 *   received=something is found, received=src_ip is added (and any preexisting
 *   received is deleted). received is added as the first via parameter if no
 *   receive is previously present or over the old receive.
 * - if the original via contains rport / rport=something or msg->msg_flags
 *   FL_FORCE_RPORT is set (e.g. script force_rport() cmd) rport=src_port
 *   is added (over previous rport / as first via param or after received
 *   if no received was present and received is added too)
 * \section localreplies Local replies:
 *    (see also sl_send_reply)
 *  - rport and received are added in mostly the same way as for requests, but
 *    in the reverse order (first rport and then received). See also
 *    limitations.
 *  - the local reply is sent to the message source ip address. The
 *    destination port is set to the source port if rport is present or
 *    FL_FORCE_RPORT flag is set, to the via port or to
 *    the default sip port (5060) if neither rport or via port are present.
 * \section normalreplies "Normal" replies:
 *  - if received is present the message is sent to the received address else
 *    if no port is present (neither a normal via port or rport) a dns srv
 *    lookup is performed on the host part and the reply is sent to the
 *    resulting ip. If a port is present or the host part is an ip address
 *    the dns lookup will be a "normal" one (A or AAAA).
 *  - if rport is present, it's value will be used as the destination port
 *   (and this will also disable srv lookups)
 *  - if no port is present the destination port will be taken from the srv
 *    lookup. If the srv lookup fails or is not performed (e.g. ip address
 *    in host) the destination port will be set to the default sip port (5060).
 *
 * \section limitations Known limitations:
 * - when locally replying to a message, rport and received will be appended to
 *   the via header parameters (for forwarded requests they are inserted at the
 *   beginning).
 * - a locally generated reply might get two received via parameters if a
 *   received is already present in the original message (this should not
 *   happen though, but ...)
 *
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "msg_translator.h"
#include "error.h"
#include "mem/mem.h"
#include "dprint.h"
#include "config.h"
#include "md5utils.h"
#include "data_lump.h"
#include "data_lump_rpl.h"
#include "ip_addr.h"
#include "resolve.h"
#include "ut.h"
#include "pt.h"
#include "context.h"
#include "net/trans.h"

int disable_503_translation = 0;

#define append_str(_dest,_src,_len) \
	do{\
		memcpy( (_dest) , (_src) , (_len) );\
		(_dest) += (_len) ;\
	}while(0);

#define append_str_trans(_dest,_src,_len,_msg) \
	append_str( (_dest), (_src), (_len) );

extern char version[];
extern int version_len;


/*! \brief check if IP address in Via != source IP address of signaling */
int received_test( struct sip_msg *msg )
{
	int rcvd;

	if(msg->via1->received !=NULL)
		return 1;

	if(msg->via1->maddr){
		rcvd = check_ip_address(&msg->rcv.src_ip, &msg->via1->maddr->value,
			msg->via1->port, msg->via1->proto, received_dns);
	} else {
		rcvd = check_ip_address(&msg->rcv.src_ip,
			&msg->via1->host, msg->via1->port, msg->via1->proto, received_dns);
	}

	return rcvd;
}


static char * warning_builder( struct sip_msg *msg, unsigned int *returned_len)
{
	static char buf[MAX_WARNING_LEN];
	str *foo;
	int print_len, l, clen;
	char* t;

#define str_print(string, string_len) \
		do{ \
			l=(string_len); \
			if ((clen+l)>MAX_WARNING_LEN) \
				goto error_overflow; \
			memcpy(buf+clen, (string), l); \
			clen+=l; \
		}while(0)

#define str_lenpair_print(string, string_len, string2, string2_len) \
		do{ \
			str_print(string, string_len); \
			str_print(string2, string2_len);\
		}while(0)

#define str_pair_print( string, string2, string2_len) \
		str_lenpair_print((string), strlen((string)), (string2), (string2_len))

#define str_int_print(string, intval)\
		do{\
			t=int2str((intval), &print_len); \
			str_pair_print(string, t, print_len);\
		} while(0)

#define str_ipaddr_print(string, ipaddr_val)\
		do{\
			t=ip_addr2a((ipaddr_val)); \
			print_len=strlen(t); \
			str_pair_print(string, t, print_len);\
		} while(0)

	clen=0;
	str_lenpair_print(WARNING, WARNING_LEN,
						msg->rcv.bind_address->name.s,
						msg->rcv.bind_address->name.len);
	str_lenpair_print(":", 1, msg->rcv.bind_address->port_no_str.s,
						msg->rcv.bind_address->port_no_str.len);
	str_print(WARNING_PHRASE, WARNING_PHRASE_LEN);

	/*adding out_uri*/
	if (msg->new_uri.s)
		foo=&(msg->new_uri);
	else
		foo=&(msg->first_line.u.request.uri);
	/* pid= */
	str_int_print(" pid=", my_pid());
	/* req_src_ip= */
	str_ipaddr_print(" req_src_ip=", &msg->rcv.src_ip);
	str_int_print(" req_src_port=", msg->rcv.src_port);
	str_pair_print(" in_uri=", msg->first_line.u.request.uri.s,
								msg->first_line.u.request.uri.len);
	str_pair_print(" out_uri=", foo->s, foo->len);
	str_pair_print(" via_cnt",
				(msg->parsed_flag & HDR_EOH_F)==HDR_EOH_F ? "=" : ">", 1);
	str_int_print("=", via_cnt);
	if (clen<MAX_WARNING_LEN){ buf[clen]='"'; clen++; }
	else goto error_overflow;


	*returned_len=clen;
	return buf;
error_overflow:
	LM_ERR("buffer size exceeded\n");
	*returned_len=0;
	return 0;
}




char* received_builder(struct sip_msg *msg, unsigned int *received_len)
{
	char *buf, *tmp;
	int  len, tmp_len;
	struct ip_addr *source_ip;

	source_ip=&msg->rcv.src_ip;

	buf=pkg_malloc(sizeof(char)*MAX_RECEIVED_SIZE);
	if (buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memcpy(buf, RECEIVED, RECEIVED_LEN);
	if ( (tmp=ip_addr2a(source_ip))==0)
		return 0; /* error*/
	tmp_len=strlen(tmp);
	len=RECEIVED_LEN+tmp_len;

	memcpy(buf+RECEIVED_LEN, tmp, tmp_len);
	buf[len]=0; /*null terminate it */

	*received_len = len;
	return buf;
}



char* rport_builder(struct sip_msg *msg, unsigned int *rport_len)
{
	char* buf, * tmp;
	int len, tmp_len;

	tmp_len=0;
	tmp=int2str(msg->rcv.src_port, &tmp_len);
	len=RPORT_LEN+tmp_len;
	buf=pkg_malloc(sizeof(char)*(len+1));/* space for null term */
	if (buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memcpy(buf, RPORT, RPORT_LEN);
	memcpy(buf+RPORT_LEN, tmp, tmp_len);
	buf[len]=0; /*null terminate it*/

	*rport_len=len;
	return buf;
}



char* id_builder(struct sip_msg* msg, unsigned int *id_len)
{
	char* buf, *p;
	int len, value_len, size;
	char revhex[sizeof(int)*2];

	size=sizeof(int)*2;
	p=&revhex[0];
	if (int2reverse_hex(&p, &size, msg->rcv.proto_reserved1)==-1){
		LM_CRIT("not enough space for id\n");
		return 0;
	}
	value_len=p-&revhex[0];
	len=ID_PARAM_LEN+value_len;
	buf=pkg_malloc(sizeof(char)*(len+1));/* place for ending \0 */
	if (buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memcpy(buf, ID_PARAM, ID_PARAM_LEN);
	memcpy(buf+ID_PARAM_LEN, revhex, value_len);
	buf[len]=0; /* null terminate it */
	*id_len=len;
	return buf;
}



char* clen_builder(struct sip_msg* msg, int *clen_len, int diff)
{
	char *buf, * value_s;
	int len, value, value_len;
	str body;

	if ( (get_body(msg,&body)!=0) ) {
		ser_error=E_BAD_REQ;
		LM_ERR("no message body found (missing crlf?)");
		return 0;
	}
	value = body.len + diff;
	value_s=int2str(value, &value_len);
	LM_DBG("content-length: %d (%s)\n", value, value_s);

	len=CONTENT_LENGTH_LEN+value_len+CRLF_LEN;
	buf=pkg_malloc(sizeof(char)*(len+1));
	if (buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memcpy(buf, CONTENT_LENGTH, CONTENT_LENGTH_LEN);
	memcpy(buf+CONTENT_LENGTH_LEN, value_s, value_len);
	memcpy(buf+CONTENT_LENGTH_LEN+value_len, CRLF, CRLF_LEN);
	buf[len]=0; /* null terminate it */
	*clen_len=len;
	return buf;
}



/*! \brief* checks if a lump opt condition
 * returns 1 if cond is true, 0 if false */
static inline int lump_check_opt(	struct lump *l,
									struct sip_msg* msg,
									struct socket_info* snd_s
									)
{
	struct ip_addr* ip;
	unsigned short port;
	int proto;

#define get_ip_port_proto \
			if (snd_s==0){ \
				LM_CRIT("null send socket\n"); \
				return 1; /* we presume they are different :-) */ \
			} \
			if (msg->rcv.bind_address){ \
				ip=&msg->rcv.bind_address->address; \
				port=msg->rcv.bind_address->port_no; \
				proto=msg->rcv.bind_address->proto; \
			}else{ \
				ip=&msg->rcv.dst_ip; \
				port=msg->rcv.dst_port; \
				proto=msg->rcv.proto; \
			} \

	switch(l->u.cond){
		case COND_FALSE:
			return 0;
		case COND_TRUE:
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_DIFF_REALMS:
			get_ip_port_proto;
			/* faster tests first */
			if ((port==snd_s->port_no)&&(proto==snd_s->proto)&&
				(ip_addr_cmp(ip, &snd_s->address))) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_SAME_REALMS:
			get_ip_port_proto;
			/* faster tests first */
			if ((port!=snd_s->port_no)||(proto!=snd_s->proto)||
				(!ip_addr_cmp(ip, &snd_s->address))) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_DIFF_AF:
			get_ip_port_proto;
			if (ip->af==snd_s->address.af) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_DIFF_PROTO:
			get_ip_port_proto;
			if (proto==snd_s->proto) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_DIFF_PORT:
			get_ip_port_proto;
			if (port==snd_s->port_no) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		case COND_IF_DIFF_IP:
			get_ip_port_proto;
			if (ip_addr_cmp(ip, &snd_s->address)) {
				l->flags &= ~LUMPFLAG_COND_TRUE;
				return 0;
			}
			l->flags |= LUMPFLAG_COND_TRUE;
			return 1;
		default:
			LM_CRIT("unknown lump condition %d\n", l->u.cond);
	}
	return 0; /* false */
}



/*! \brief computes the "unpacked" len of a lump list,
   code moved from build_req_from_req */
int lumps_len(struct sip_msg* msg, struct lump* lumps,
								struct socket_info* send_sock, int max_offset)
{
	unsigned int s_offset, new_len;
	unsigned int last_del;
	struct lump *t, *r;
	str *send_address_str, *send_port_str;
	str *rcv_address_str=NULL;
	str *rcv_port_str=NULL;

#define SUBST_LUMP_LEN(subst_l) \
		switch((subst_l)->u.subst){ \
			case SUBST_RCV_IP: \
				if (msg->rcv.bind_address){ \
					new_len+=rcv_address_str->len; \
				} else \
					LM_BUG("null bind address 1"); \
				break; \
			case SUBST_RCV_PORT: \
				if (msg->rcv.bind_address){ \
					new_len+=rcv_port_str->len; \
				} else \
					LM_BUG("null bind address 2"); \
				break; \
			case SUBST_RCV_PROTO: \
				if (msg->rcv.bind_address){ \
					switch(msg->rcv.bind_address->proto){ \
						/* TODO change this to look in proto !*/ \
						case PROTO_NONE: \
						case PROTO_UDP: \
						case PROTO_TCP: \
						case PROTO_TLS: \
						case PROTO_WSS: \
								new_len+=3; \
								break; \
						case PROTO_SCTP: \
								new_len+=4; \
								break; \
						case PROTO_WS: \
								new_len+=2; \
								break; \
						default: \
						LM_CRIT("unknown proto %d\n", \
								msg->rcv.bind_address->proto); \
					}\
				} else \
					LM_BUG("null bind address 3"); \
				break; \
			case SUBST_RCV_ALL: \
				if (msg->rcv.bind_address){ \
					new_len+=rcv_address_str->len; \
					if (msg->rcv.bind_address->port_no!=SIP_PORT || (rcv_port_str!=&(msg->rcv.bind_address->port_no_str))){ \
						/* add :port_no */ \
						new_len+=1+rcv_port_str->len; \
					}\
						/*add;transport=xxx*/ \
					switch(msg->rcv.bind_address->proto){ \
						case PROTO_NONE: \
						case PROTO_UDP: \
								break; /* udp is the default */ \
						case PROTO_TCP: \
						case PROTO_TLS: \
						case PROTO_WSS: \
								new_len+=TRANSPORT_PARAM_LEN+3; \
								break; \
						case PROTO_SCTP: \
								new_len+=TRANSPORT_PARAM_LEN+4; \
								break; \
						case PROTO_WS: \
								new_len+=TRANSPORT_PARAM_LEN+2; \
								break; \
						default: \
						LM_CRIT("unknown proto %d\n", \
								msg->rcv.bind_address->proto); \
					}\
				} else \
					LM_BUG("null bind address 4"); \
				break; \
			case SUBST_SND_IP: \
				if (send_sock){ \
					new_len+=send_address_str->len; \
				} else \
					LM_BUG("null send_socket 1"); \
				break; \
			case SUBST_SND_PORT: \
				if (send_sock){ \
					new_len+=send_port_str->len; \
				} else \
					LM_BUG("null send_socket 2"); \
				break; \
			case SUBST_SND_PROTO: \
				if (send_sock){ \
					switch(send_sock->proto){ \
						case PROTO_NONE: \
						case PROTO_UDP: \
						case PROTO_TCP: \
						case PROTO_TLS: \
						case PROTO_WSS: \
								new_len+=3; \
								break; \
						case PROTO_SCTP: \
								new_len+=4; \
								break; \
						case PROTO_WS: \
								new_len+=2; \
								break; \
						default: \
						LM_CRIT("unknown proto %d\n", \
								send_sock->proto); \
					}\
				} else \
					LM_BUG("null send_socket 3"); \
				break; \
			case SUBST_SND_ALL: \
				if (send_sock){ \
					new_len+=send_address_str->len; \
					if ((send_sock->port_no!=SIP_PORT) || \
							(send_port_str!=&(send_sock->port_no_str))){ \
						/* add :port_no */ \
						new_len+=1+send_port_str->len; \
					}\
					/*add;transport=xxx*/ \
					switch(send_sock->proto){ \
						case PROTO_NONE: \
						case PROTO_UDP: \
								break; /* udp is the default */ \
						case PROTO_TCP: \
						case PROTO_TLS: \
						case PROTO_WSS: \
								new_len+=TRANSPORT_PARAM_LEN+3; \
								break; \
						case PROTO_SCTP: \
								new_len+=TRANSPORT_PARAM_LEN+4; \
								break; \
						case PROTO_WS: \
								new_len+=TRANSPORT_PARAM_LEN+2; \
								break; \
						default: \
						LM_CRIT("unknown proto %d\n", \
								send_sock->proto); \
					}\
				} else \
					LM_BUG("null send_socket 4"); \
				break; \
			case SUBST_NOP: /* do nothing */ \
				break; \
			default: \
				LM_CRIT("unknown subst type %d\n", \
						(subst_l)->u.subst); \
		}


	s_offset=0;
	new_len=0;
	last_del=0;

	/* init send_address_str & send_port_str */
	if(send_sock && send_sock->adv_name_str.len)
		send_address_str=&(send_sock->adv_name_str);
	else if (msg->set_global_address.s)
		send_address_str=&(msg->set_global_address);
	else if (default_global_address.s)
		send_address_str=&default_global_address;
	else
		send_address_str=&(send_sock->address_str);

	if(send_sock && send_sock->adv_port_str.len)
		send_port_str=&(send_sock->adv_port_str);
	else if (msg->set_global_port.s)
		send_port_str=&(msg->set_global_port);
	else if (default_global_port.s)
		send_port_str=&default_global_port;
	else
		send_port_str=&(send_sock->port_no_str);

	/* init rcv_address_str & rcv_port_str */
	if(msg->rcv.bind_address) {
		if(msg->rcv.bind_address->adv_name_str.len)
			rcv_address_str=&(msg->rcv.bind_address->adv_name_str);
		else if (default_global_address.s)
			rcv_address_str=&default_global_address;
		else
			rcv_address_str=&(msg->rcv.bind_address->address_str);
		if(msg->rcv.bind_address->adv_port_str.len)
			rcv_port_str=&(msg->rcv.bind_address->adv_port_str);
		else if (default_global_port.s)
			rcv_port_str=&default_global_port;
		else
			rcv_port_str=&(msg->rcv.bind_address->port_no_str);
	}

	for (t = lumps; t && t->u.offset<(unsigned int)max_offset ; t = t->next) {
		/* is this lump still valid? (it must not be anchored in a deleted area */
		if (t->u.offset < s_offset && t->u.offset != last_del) {
			LM_DBG("skip a %d, buffer offset=%d, lump offset=%d, last_del=%d\n",
				t->op,s_offset, t->u.offset,last_del);
			continue;
		}

		for (r = t->before; r; r = r->before) {
			switch (r->op) {
				case LUMP_ADD:
					new_len += r->len;
					break;
				case LUMP_ADD_SUBST:
					SUBST_LUMP_LEN(r);
					break;
				case LUMP_ADD_OPT:
					/* skip if this is an OPT lump and the condition is
					 * not satisfied */
					if (!lump_check_opt(r, msg, send_sock))
						goto skip_before;
					break;
				case LUMP_SKIP:
					/* if a SKIP lump, go to the last in the list*/
					if (!r->before || !r->before->before)
						continue;
					for (; r->before->before; r = r->before)
						;
					break;
				default:
					/* only ADD allowed for before/after */
						LM_CRIT("invalid op for data lump (%x)\n", r->op);
			}
		}
skip_before:
		switch (t->op) {
			case LUMP_DEL:
				last_del=t->u.offset;

				if (t->u.offset < s_offset) {
					if (t->u.offset + t->len > s_offset) {
						new_len -= t->len - (s_offset - t->u.offset);
						s_offset = t->u.offset + t->len;
					}
				} else {
					new_len -= t->len;
					s_offset = t->u.offset + t->len;
				}

				break;
			case LUMP_NOP:
				/* do nothing */
				break;
			case LUMP_ADD:
				/* FIXME: inconsistent with process_lumps() */
				new_len += t->len;
				break;
			case LUMP_ADD_OPT:
				LM_BUG("LUMP_ADD_OPT");
				/* we don't do anything here, it's only a condition for
				 * before & after */
				break;
			case LUMP_SKIP:
				LM_BUG("LUMP_SKIP");
				/* we don't do anything here, it's only a condition for
				 * before & after */
				break;
			case LUMP_ADD_SUBST:
				LM_BUG("LUMP_ADD_SUBST");
				SUBST_LUMP_LEN(t);
				break;
			default:
				LM_BUG("op for data lump (%x)", r->op);
		}

		for (r = t->after; r; r = r->after) {
			switch (r->op) {
				case LUMP_ADD:
					new_len+=r->len;
					break;
				case LUMP_ADD_SUBST:
					SUBST_LUMP_LEN(r);
					break;
				case LUMP_ADD_OPT:
					/* skip if this is an OPT lump and the condition is
					 * not satisfied */
					if (!lump_check_opt(r, msg, send_sock))
						goto skip_after;
					break;
				case LUMP_SKIP:
					/* if a SKIP lump, go to the last in the list*/
					if (!r->after || !r->after->after)
						continue;
					for (; r->after->after; r = r->after)
						;
					break;
				default:
					/* only ADD allowed for before/after */
					LM_CRIT("invalid op for data lump (%x)\n", r->op);
			}
		}
skip_after:
		; /* to make gcc 3.* happy */
	}
	return new_len;
}



/*! \brief another helper functions, adds/Removes the lump,
	code moved from build_req_from_req  */

void process_lumps(	struct sip_msg* msg,
					struct lump* lumps,
					char* new_buf,
					unsigned int* new_buf_offs,
					unsigned int* orig_offs,
					struct socket_info* send_sock,
					int max_offset)
{
	struct lump *t, *r;
	char* orig;
	unsigned int size, offset, s_offset;
	unsigned int last_del;
	str *send_address_str, *send_port_str;
	str *rcv_address_str=NULL;
	str *rcv_port_str=NULL;

#define SUBST_LUMP(subst_l) \
	switch((subst_l)->u.subst){ \
		case SUBST_RCV_IP: \
			if (msg->rcv.bind_address){  \
				memcpy(new_buf+offset, rcv_address_str->s, \
					rcv_address_str->len); \
				offset+=rcv_address_str->len; \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("null bind_address\n"); \
			}; \
			break; \
		case SUBST_RCV_PORT: \
			if (msg->rcv.bind_address){  \
				memcpy(new_buf+offset, rcv_port_str->s, \
						rcv_port_str->len); \
				offset+=rcv_port_str->len; \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("null bind_address\n"); \
			}; \
			break; \
		case SUBST_RCV_ALL: \
			if (msg->rcv.bind_address){  \
				/* address */ \
				memcpy(new_buf+offset, rcv_address_str->s, \
						rcv_address_str->len); \
				offset+=rcv_address_str->len; \
				/* :port */ \
				if (msg->rcv.bind_address->port_no!=SIP_PORT || (rcv_port_str!=&(msg->rcv.bind_address->port_no_str))){ \
					new_buf[offset]=':'; offset++; \
					memcpy(new_buf+offset, \
							rcv_port_str->s, \
							rcv_port_str->len); \
					offset+=rcv_port_str->len; \
				}\
				switch(msg->rcv.bind_address->proto){ \
					/* TODO: change this to look into protos ! */ \
					case PROTO_NONE: \
					case PROTO_UDP: \
						break; /* nothing to do, udp is default*/ \
					case PROTO_TCP: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "tcp", 3); \
						offset+=3; \
						break; \
					case PROTO_TLS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "tls", 3); \
						offset+=3; \
						break; \
					case PROTO_SCTP: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "sctp", 4); \
						offset+=4; \
						break; \
					case PROTO_WS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "ws", 2); \
						offset+=2; \
						break; \
					case PROTO_WSS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "wss", 3); \
						offset+=3; \
						break; \
					default: \
						LM_CRIT("unknown proto %d\n", \
								msg->rcv.bind_address->proto); \
				} \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("null bind_address\n"); \
			}; \
			break; \
		case SUBST_SND_IP: \
			if (send_sock){  \
				memcpy(new_buf+offset, send_address_str->s, \
									send_address_str->len); \
				offset+=send_address_str->len; \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("called with null send_sock\n"); \
			}; \
			break; \
		case SUBST_SND_PORT: \
			if (send_sock){  \
				memcpy(new_buf+offset, send_port_str->s, \
									send_port_str->len); \
				offset+=send_port_str->len; \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("called with null send_sock\n"); \
			}; \
			break; \
		case SUBST_SND_ALL: \
			if (send_sock){  \
				/* address */ \
				memcpy(new_buf+offset, send_address_str->s, \
						send_address_str->len); \
				offset+=send_address_str->len; \
				/* :port */ \
				if ((send_sock->port_no!=SIP_PORT) || \
					(send_port_str!=&(send_sock->port_no_str))){ \
					new_buf[offset]=':'; offset++; \
					memcpy(new_buf+offset, send_port_str->s, \
							send_port_str->len); \
					offset+=send_port_str->len; \
				}\
				switch(send_sock->proto){ \
					case PROTO_NONE: \
					case PROTO_UDP: \
						break; /* nothing to do, udp is default*/ \
					case PROTO_TCP: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "tcp", 3); \
						offset+=3; \
						break; \
					case PROTO_TLS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "tls", 3); \
						offset+=3; \
						break; \
					case PROTO_SCTP: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "sctp", 4); \
						offset+=4; \
						break; \
					case PROTO_WS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "ws", 2); \
						offset+=2; \
						break; \
					case PROTO_WSS: \
						memcpy(new_buf+offset, TRANSPORT_PARAM, \
								TRANSPORT_PARAM_LEN); \
						offset+=TRANSPORT_PARAM_LEN; \
						memcpy(new_buf+offset, "wss", 3); \
						offset+=3; \
						break; \
					default: \
						LM_CRIT("unknown proto %d\n", \
								send_sock->proto); \
				} \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("null bind_address\n"); \
			}; \
			break; \
		case SUBST_RCV_PROTO: \
			if (msg->rcv.bind_address){ \
				switch(msg->rcv.bind_address->proto){ \
					case PROTO_NONE: \
					case PROTO_UDP: \
						memcpy(new_buf+offset, "udp", 3); \
						offset+=3; \
						break; \
					case PROTO_TCP: \
						memcpy(new_buf+offset, "tcp", 3); \
						offset+=3; \
						break; \
					case PROTO_TLS: \
						memcpy(new_buf+offset, "tls", 3); \
						offset+=3; \
						break; \
					case PROTO_SCTP: \
						memcpy(new_buf+offset, "sctp", 4); \
						offset+=4; \
						break; \
					case PROTO_WS: \
						memcpy(new_buf+offset, "ws", 2); \
						offset+=2; \
						break; \
					case PROTO_WSS: \
						memcpy(new_buf+offset, "wss", 3); \
						offset+=3; \
						break; \
					default: \
						LM_CRIT("unknown proto %d\n", \
								msg->rcv.bind_address->proto); \
				} \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("called with null send_sock \n"); \
			}; \
			break; \
		case  SUBST_SND_PROTO: \
			if (send_sock){ \
				switch(send_sock->proto){ \
					case PROTO_NONE: \
					case PROTO_UDP: \
						memcpy(new_buf+offset, "udp", 3); \
						offset+=3; \
						break; \
					case PROTO_TCP: \
						memcpy(new_buf+offset, "tcp", 3); \
						offset+=3; \
						break; \
					case PROTO_TLS: \
						memcpy(new_buf+offset, "tls", 3); \
						offset+=3; \
						break; \
					case PROTO_SCTP: \
						memcpy(new_buf+offset, "sctp", 4); \
						offset+=4; \
						break; \
					case PROTO_WS: \
						memcpy(new_buf+offset, "ws", 2); \
						offset+=2; \
						break; \
					case PROTO_WSS: \
						memcpy(new_buf+offset, "wss", 3); \
						offset+=3; \
						break; \
					default: \
						LM_CRIT("unknown proto %d\n", \
								send_sock->proto); \
				} \
			}else{  \
				/*FIXME*/ \
				LM_CRIT("called with null send_sock \n"); \
			}; \
			break; \
		default: \
					LM_CRIT("unknown subst type %d\n", \
							(subst_l)->u.subst); \
	} \
 \

	/* init send_address_str & send_port_str */
	if(send_sock && send_sock->adv_name_str.len)
		send_address_str=&(send_sock->adv_name_str);
	else if (msg->set_global_address.len)
		send_address_str=&(msg->set_global_address);
	else if (default_global_address.s)
		send_address_str=&default_global_address;
	else
		send_address_str=&(send_sock->address_str);
	if(send_sock && send_sock->adv_port_str.len)
		send_port_str=&(send_sock->adv_port_str);
	else if (msg->set_global_port.len)
		send_port_str=&(msg->set_global_port);
	else if (default_global_port.s)
		send_port_str=&default_global_port;
	else
		send_port_str=&(send_sock->port_no_str);

	/* init rcv_address_str & rcv_port_str */
	if(msg->rcv.bind_address) {
		if(msg->rcv.bind_address->adv_name_str.len)
			rcv_address_str=&(msg->rcv.bind_address->adv_name_str);
		else if (default_global_address.s)
			rcv_address_str=&default_global_address;
		else
			rcv_address_str=&(msg->rcv.bind_address->address_str);
		if(msg->rcv.bind_address->adv_port_str.len)
			rcv_port_str=&(msg->rcv.bind_address->adv_port_str);
		else if (default_global_port.s)
			rcv_port_str=&default_global_port;
		else
			rcv_port_str=&(msg->rcv.bind_address->port_no_str);
	}

	orig=msg->buf;
	offset=*new_buf_offs;
	s_offset=*orig_offs;
	last_del=0;

	for (t = lumps; t && t->u.offset<(unsigned int)max_offset ; t = t->next) {
		/* skip this lump if the "offset" is still in a "deleted" area */
		if (t->u.offset < s_offset && t->u.offset != last_del) {
			LM_DBG("skip a %d, buffer offset=%d, lump offset=%d, last_del=%d\n",
				t->op,s_offset, t->u.offset,last_del);
			continue;
		}

		switch (t->op) {
			case LUMP_NOP:
			case LUMP_DEL:
				/* copy till offset (if any) */
				if (s_offset < t->u.offset) {
					size = t->u.offset-s_offset;
					memcpy(new_buf+offset, orig+s_offset, size);
					offset += size;
					s_offset += size;
				}

				if (t->op == LUMP_DEL)
					last_del = t->u.offset;

				/* process before  */
				for (r = t->before; r; r = r->before) {
					switch (r->op) {
						case LUMP_ADD:
							/*just add it here*/
							memcpy(new_buf+offset, r->u.value, r->len);
							offset += r->len;
							break;
						case LUMP_ADD_SUBST:
							SUBST_LUMP(r);
							break;
						case LUMP_ADD_OPT:
							/* skip if this is an OPT lump and the condition is
					 		* not satisfied */
							if (!lump_check_opt(r, msg, send_sock))
								goto skip_nop_before;
							break;
						case LUMP_SKIP:
							/* if a SKIP lump, go to the last in the list*/
							if (!r->before || !r->before->before)
								continue;
							for (; r->before->before; r = r->before)
								;
							break;
						default:
							/* only ADD allowed for before/after */
							LM_BUG("invalid op 1 (%x)",r->op);
					}
				}
skip_nop_before:
				if (t->op == LUMP_DEL) {
					/*
					 * skip at most len bytes from orig msg
					 * and properly handle DEL lumps at the same offset --liviu
					 */
					if (t->u.offset + t->len > s_offset)
						s_offset += t->len - (s_offset - t->u.offset);
				}

				/* process after */
				for (r = t->after; r; r = r->after) {
					switch (r->op) {
						case LUMP_ADD:
							/*just add it here*/
							memcpy(new_buf+offset, r->u.value, r->len);
							offset += r->len;
							break;
						case LUMP_ADD_SUBST:
							SUBST_LUMP(r);
							break;
						case LUMP_ADD_OPT:
							/* skip if this is an OPT lump and the condition is
					 		* not satisfied */
							if (!lump_check_opt(r, msg, send_sock))
								goto skip_nop_after;
							break;
						case LUMP_SKIP:
							/* if a SKIP lump, go to the last in the list*/
							if (!r->after || !r->after->after)
								continue;
							for (; r->after->after; r = r->after)
								;
							break;
						default:
							/* only ADD allowed for before/after */
							LM_BUG("invalid op 2 (%x)", r->op);
					}
				}
skip_nop_after:
				break;
			case LUMP_ADD:
			case LUMP_ADD_SUBST:
			case LUMP_ADD_OPT:
				LM_BUG("ADD|SUBST|OPT");
				/* skip if this is an OPT lump and the condition is
				 * not satisfied */
				if ((t->op==LUMP_ADD_OPT) &&
						(!lump_check_opt(t, msg, send_sock)))
					continue;
				/* just add it here! */
				/* process before  */
				for(r=t->before;r;r=r->before){
					switch (r->op){
						case LUMP_ADD:
							/*just add it here*/
							memcpy(new_buf+offset, r->u.value, r->len);
							offset+=r->len;
							break;
						case LUMP_ADD_SUBST:
							SUBST_LUMP(r);
							break;
						case LUMP_ADD_OPT:
							/* skip if this is an OPT lump and the condition is
					 		* not satisfied */
							if (!lump_check_opt(r, msg, send_sock))
								goto skip_before;
							break;
						case LUMP_SKIP:
							/* if a SKIP lump, go to the last in the list*/
							if (!r->before || !r->before->before) continue;
							for(;r->before->before;r=r->before);
							break;
						default:
							/* only ADD allowed for before/after */
							LM_BUG("invalid op 3 (%x)", r->op);
					}
				}
skip_before:
				/* copy "main" part */
				switch(t->op){
					case LUMP_ADD:
						memcpy(new_buf+offset, t->u.value, t->len);
						offset+=t->len;
						break;
					case LUMP_ADD_SUBST:
						SUBST_LUMP(t);
						break;
					case LUMP_ADD_OPT:
						/* do nothing, it's only a condition */
						break;
					default:
						/* should not ever get here */
						LM_BUG("invalid op 4 %d", t->op);
				}
				/* process after */
				for(r=t->after;r;r=r->after){
					switch (r->op){
						case LUMP_ADD:
							/*just add it here*/
							memcpy(new_buf+offset, r->u.value, r->len);
							offset+=r->len;
							break;
						case LUMP_ADD_SUBST:
							SUBST_LUMP(r);
							break;
						case LUMP_ADD_OPT:
							/* skip if this is an OPT lump and the condition is
					 		* not satisfied */
							if (!lump_check_opt(r, msg, send_sock))
								goto skip_after;
							break;
						case LUMP_SKIP:
							/* if a SKIP lump, go to the last in the list*/
							if (!r->after || !r->after->after) continue;
							for(;r->after->after;r=r->after);
							break;
						default:
							/* only ADD allowed for before/after */
							LM_BUG("invalid op 5 (%x)", r->op);
					}
				}
skip_after:
				break;
			case LUMP_SKIP:
				LM_BUG("LUMP_SKIP");
				/* if a SKIP lump, go to the last in the list*/
				if (!t->next || !t->next->next)
					continue;
				for (; t->next->next; t = t->next)
					;
				break;
			default:
				LM_BUG("invalid op 6 (%x)", t->op);
		}
	}

	*new_buf_offs = offset;
	*orig_offs = s_offset;
}


/* Prepares a body to be re-assembled. This consists of the following ops:
 *   - run the functions to build the parts (if the case)
 *   - add SIP header lumps to change CT header 
 *   - estimating the new len of the body (after applying all the changes)
 * IMPORTANT: keep this function in sync with the reassemble_body_parts()
 *    to be 100% that estimating and building the body leads to the same
 *    result (as len).
 */
static unsigned int prep_reassemble_body_parts( struct sip_msg* msg,
												struct socket_info* send_sock)
{
	struct body_part *part;
	struct lump* lump;
	struct lump* ct;
	unsigned int size;
	unsigned int len = 0;
	unsigned int orig_offs;
	struct hdr_field hf;
	char *hdr, *it;

	/* set the offset (in the original buffer) at the beginning of the body */
	orig_offs = msg->body->part_count ? msg->body->body.s-msg->buf : msg->len ;

	if (msg->body->updated_part_count==0) {

		/* no body to be placed in the new msg !
		 * simply skip the entire body */
		LM_DBG("no part to be added\n");

		/* Remove Content-Type hdr if present */
		if (msg->content_type && msg->content_type->name.s
		&& msg->content_type->name.len
		&& del_lump(msg, msg->content_type->name.s- msg->buf,
		msg->content_type->len, HDR_CONTENTTYPE_T)==0) {
			LM_ERR("failed to add lump to delete content type header\n");
		}

	} else if (msg->body->updated_part_count==1) {

		/* there is only one part to be added, so iterate
		 * and find it */
		LM_DBG("only one part to be added\n");

		for( part=&msg->body->first ; part ; part=part->next)
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED)==0 ) break;

		if (part==NULL) {
			LM_BUG("updated count is 1, but no non-deleted part found :-/\n");
			return len /* 0 */;
		}

		LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
			part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

		if (part->dump_f) {
			/* trigger the the dump function link the resulting buffer
			 * as 'dump' (and to be used and freed when the body buffer
			 * is actually built) */
			if (part->dump_f( part->parsed ,msg, &part->dump)<0) {
				LM_ERR("failed to build part, inserting empty\n");
				part->dump.s = "";
				part->dump.len = 0;
			} else
				len += part->dump.len;
		} else {
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* simpy copy the body of the part */
				len += part->body.len;
			} else {
				/* this is one part that was received (so potentially
				 * modified during runtime) -> apply all body lumps
				 * inside this part */
				orig_offs = part->body.s - msg->buf;
				lump = msg->body_lumps;
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					len += lumps_len( msg, lump, send_sock, 
						part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part */
				len += (part->body.s+part->body.len-msg->buf)-orig_offs;
			}
		}

		/* if the part is new (0->1 addition or 1->1 replacement) or
		 * if the part is kept from a stipped multi-part  (n->1)
		 *   =>  replace the msg content-type with the new one */
		if ( (part->flags & SIP_BODY_PART_FLAG_NEW)
		|| msg->body->part_count>1 ) {
			/* replace the Content-Type hdr */
			if (msg->content_type)
				ct = del_lump(msg, msg->content_type->name.s-msg->buf,
					msg->content_type->len, HDR_CONTENTTYPE_T);
			else
				ct = anchor_lump(msg, msg->unparsed - msg->buf,
					HDR_CONTENTTYPE_T);
			if (ct==NULL) {
				LM_ERR("failed to remove old CT / create anchor\n");
			} else {
				/* if a new part, we need to build the CT header; if a 
				 * received part, simply copied from the part */
				if (part->flags & SIP_BODY_PART_FLAG_NEW) {
					hdr = (char*)pkg_malloc( 14 + part->mime_s.len +CRLF_LEN +
						part->headers.len);
					if (hdr==NULL) {
						LM_ERR("failed to allocate new ct hdr\n");
					} else {
						memcpy( hdr, "Content-Type: ", 14);
						memcpy( hdr+14, part->mime_s.s, part->mime_s.len);
						memcpy( hdr+14+part->mime_s.len, CRLF, CRLF_LEN);
						if (part->headers.len)
							memcpy( hdr+14+part->mime_s.len+CRLF_LEN,
								part->headers.s, part->headers.len);
						if (insert_new_lump_before(ct, hdr,
						14+part->mime_s.len+CRLF_LEN+part->headers.len,
						HDR_CONTENTTYPE_T) == NULL) {
							LM_ERR("failed to create insert lump\n");
							pkg_free(hdr);
						}
					}
				} else {
					/* iterate all the SIP hdrs from this part and keep all
					 * except the "Content-Length" */
					it = part->headers.s;
					while ( it<part->headers.s+part->headers.len ) {
						memset( &hf, 0, sizeof(struct hdr_field));
						it = get_hdr_field( it, part->headers.s+part->headers.len, &hf);
						if (hf.type==HDR_ERROR_T || hf.type==HDR_EOH_T)
							break;
						if (hf.type==HDR_CONTENTLENGTH_T)
							continue;
						/* add this hdr */
						hdr = (char*)pkg_malloc( hf.len);
						if (hdr==NULL) {
							LM_ERR("failed to allocate new ct hdr\n");
						} else {
							memcpy( hdr, hf.name.s, hf.len);
							if (insert_new_lump_before(ct, hdr,
							hf.len, HDR_CONTENTTYPE_T) == NULL) {
								LM_ERR("failed to create insert lump\n");
								pkg_free(hdr);
							}
						}
					}
				}
			}
		} else
			/* if it is an 1->1 keeping the part, try to preserve the
			 * the packing (multi-part or not) of this part */
			if ( (part->flags & SIP_BODY_PART_FLAG_NEW)==0 &&
			msg->body->part_count==1 &&
			msg->body->flags & SIP_BODY_RCV_MULTIPART) {
				/* preserve the original multi-part packing by preserving
				 * the before and after padding between part and body */
				len += msg->body->body.len - part->body.len;
			}

	} else if (msg->body->part_count<2) {

		/* transition from 0/1 to multiple parts,
		 * so we need to add boundries */

		LM_DBG("transition from 0/1 parts to multi part body\n");
		lump = msg->body_lumps;

		for( part=&msg->body->first ; part ; part=part->next) {

			LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
				part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

			/* skip deleted parts */
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED) ) {
				if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
					/* reposition at the end of the skipped body */
					orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;
				continue;
			}

			/* separator and CT header */
			len += 2 /* "--" */ + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN +
			 14/* "Content-Type: " */ + part->mime_s.len +
			 CRLF_LEN + part->headers.len + CRLF_LEN ;

			/* part with dump function ? */
			if (part->dump_f) {
				if (part->dump_f( part->parsed ,msg, &part->dump)<0) {
					LM_ERR("failed to build part, inserting empty\n");
					part->dump.s = "";
					part->dump.len = 0;
				} else
					len += part->dump.len;
				len += CRLF_LEN;
			} else
			/* new part with body attached */
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* simpy copy the body of the part */
				len += part->body.len;
				len += CRLF_LEN;
			} else
			/* old part with lumps */
			{
				/* first find the first lump inside our body part */
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					/* apply the lumps */
					len += lumps_len( msg, lump, send_sock,
						part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part */
				size = (part->body.s+part->body.len-msg->buf)-orig_offs;
				len += size + CRLF_LEN;
			}

			/* reposition at the end of the processed body */
			if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
				orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;

		} /* end for(over the parts) */

		/* the final separator */
		len += 2 /* "--" */ + sizeof(OSS_BOUNDARY)-1 + 2 /* "--" */ + CRLF_LEN;

		/* replace the Content-Type hdr */
		if (msg->content_type)
			ct = del_lump(msg, msg->content_type->name.s-msg->buf,
				msg->content_type->len, HDR_CONTENTTYPE_T);
		else
			ct = anchor_lump(msg, msg->unparsed - msg->buf,
				HDR_CONTENTTYPE_T);
		if (ct==NULL) {
			LM_ERR("failed to remove old CT / create anchor\n");
		} else {
			/* "Content-Type: multipart/mixed;boundary=OSS_BOUNDARY CRLF" */
			hdr = (char*)pkg_malloc( 39 + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN );
			if (hdr==NULL) {
				LM_ERR("failed to allocate new ct hdr\n");
			} else {
				memcpy( hdr,
				"Content-Type: multipart/mixed;boundary=" OSS_BOUNDARY CRLF,
				39 + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN);
				if (insert_new_lump_before(ct, hdr,
				39 + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN,
				HDR_CONTENTTYPE_T) == NULL) {
					LM_ERR("failed to create insert lump\n");
					pkg_free(hdr);
				}
			}
		}

	} else {

		/* multi to multi parts - iterate the list, handle insert new parts,
		 * remove old ones, and modify the kept ones (if the case) */

		LM_DBG("multi to multi part body reconstruction\n");
		lump = msg->body_lumps;

		for( part=&msg->body->first ; part ; part=part->next) {
			/* skip deleted parts */
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED) ) {
				if ( (part->flags & SIP_BODY_PART_FLAG_NEW) == 0 )
					/* reposition at the end of the skipped body */
					orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;
				continue;
			}

			LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
				part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

			/* new part ? */
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* separator and CT header */
				len += 2 /* "--" */ + msg->body->boundary.len +
					CRLF_LEN + 14 /* "Content-Type: " */ + part->mime_s.len +
					CRLF_LEN + part->headers.len + CRLF_LEN ;
				/* simpy copy the body of the part */
				if (part->dump_f) {
					if (part->dump_f( part->parsed ,msg, &part->dump)<0) {
						LM_ERR("failed to build part, inserting empty\n");
						part->dump.s = "";
						part->dump.len = 0;
					} else
						len += part->dump.len;
				} else
					len += part->body.len;
				len += CRLF_LEN;
			} else
			/* old part with dump function */
			if (part->dump_f) {
				/* copy separator and headers from original message */
				len += (part->body.s - msg->buf) - orig_offs;
				/* put in the new body */
				if (part->dump_f( part->parsed ,msg, &part->dump)<0) {
					LM_ERR("failed to build part, inserting empty\n");
					part->dump.s = "";
					part->dump.len = 0;
				} else
					len += part->dump.len;
				len += CRLF_LEN;
				/* skip the old body */
			} else
			/* old part with lumps -> apply changes */
			{
				/* first find the first lump inside our body part
				 * NOTE: we do not need to explicitly copy the separtor and
				 * the headers as they will be automatically got by the 
				 * first lup or by the final copy */
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					/* apply the lumps */
					len += lumps_len( msg, lump, send_sock,
							part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part */
				size = (part->body.s+part->body.len-msg->buf+CRLF_LEN)-orig_offs;
				len += size;
			}

			/* reposition at the end of the processed body */
			if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
				orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;
		} /* end for(over the parts) */

		/* the final separator */
		size = msg->len - orig_offs;
		len += size;

		/* Content-Type hdr does not require changes in this case */
	}

	LM_DBG("resulting body len is %d\n",len);
	return len;
}


void reassemble_body_parts( struct sip_msg* msg, char* new_buf,
						unsigned int* new_offs, unsigned int* orig_offs,
						struct socket_info* send_sock)
{
	struct body_part *part;
	struct lump* lump;
	unsigned int size;
	unsigned int offset;
	int padding=0;

	if (msg->body->updated_part_count==0) {

		/* no body to be placed in the new msg !
		 * simply skip the entire body */
		LM_DBG("no part to be added\n");

	} else if (msg->body->updated_part_count==1) {

		/* there is only one part to be added, so iterate
		 * and find it */
		LM_DBG("only one part to be added\n");

		for( part=&msg->body->first ; part ; part=part->next)
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED)==0 ) break;

		if (part==NULL) {
			LM_BUG("updated count is 1, but no non-deleted part found :-/\n");
			return;
		}

		LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
			part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

		/* handle the special case of preserving a single part which was
		 * received packed as multipart -> copy the boundries as
		 * received */
		if ( msg->body->flags & SIP_BODY_RCV_MULTIPART &&
		msg->body->part_count==1 &&
		(part->flags & SIP_BODY_PART_FLAG_NEW)==0 ) {
			/* copy whatever is between the beginning of the msg body 
			 * and the part body*/
			memcpy(new_buf+*new_offs, msg->body->body.s,
				part->body.s-msg->body->body.s );
			*new_offs += part->body.s-msg->body->body.s;
			padding = 1;
		}

		if (part->dump_f) {
			/* the dump function was triggered when the length was computed
			 * and the resulting buffer was linked as 'dump' (and we need
			 * to free it now) */
			/* copy the new body of the part */
			memcpy(new_buf+*new_offs, part->dump.s, part->dump.len );
			*new_offs += part->dump.len;
			pkg_free(part->dump.s);
			part->dump.s = NULL;
			part->dump.len = 0;
		} else {
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* simply copy the body of the part */
				memcpy(new_buf+*new_offs, part->body.s, part->body.len );
				*new_offs += part->body.len;
			} else {
				/* this is one part that was received (so potentially
				 * modified during runtime) -> apply all body lumps
				 * inside this part */
				*orig_offs = part->body.s - msg->buf;
				lump = msg->body_lumps;
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					/* apply the lumps */
					process_lumps( msg, lump, new_buf, new_offs, orig_offs,
						send_sock, part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part */
				size = (part->body.s+part->body.len-msg->buf)-*orig_offs;
				memcpy(new_buf+*new_offs, msg->buf+*orig_offs, size);
				*new_offs += size;
			}
		}

		if (padding) {
			/* copy whatever is between the end of the part body 
			 * and the end of the msg body*/
			memcpy(new_buf+*new_offs, part->body.s+part->body.len,
				(msg->body->body.s+msg->body->body.len)-
				(part->body.s+part->body.len) );
			*new_offs += (msg->body->body.s+msg->body->body.len)-
				(part->body.s+part->body.len);
		}

	} else if (msg->body->part_count<2) {

		/* transition from 0/1 to multiple parts,
		 * so we need to add boundries */

		LM_DBG("transition from 0/1 parts to multi part body\n");
		offset = *new_offs;
		lump = msg->body_lumps;

		for( part=&msg->body->first ; part ; part=part->next) {

			LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
				part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

			/* skip deleted parts */
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED) ) {
				if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
					/* reposition at the end of the skipped body */
					*orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;
				continue;
			}

			/* separator and CT header */
			memcpy(new_buf+offset, "--" OSS_BOUNDARY CRLF "Content-Type: ",
				2 + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN + 14);
			offset += 2 + sizeof(OSS_BOUNDARY)-1 + CRLF_LEN + 14;
			memcpy(new_buf+offset, part->mime_s.s , part->mime_s.len);
			offset += part->mime_s.len;
			if (part->headers.len==0) {
				memcpy(new_buf+offset, CRLF CRLF , CRLF_LEN+CRLF_LEN);
				offset += CRLF_LEN + CRLF_LEN ;
			} else {
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
				memcpy(new_buf+offset, part->headers.s , part->headers.len);
				offset += part->headers.len ;
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			}

			/* part with dump function ? */
			if (part->dump_f) {
				memcpy(new_buf+offset, part->dump.s, part->dump.len );
				offset += part->dump.len;
				pkg_free(part->dump.s);
				part->dump.s = NULL;
				part->dump.len = 0;
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			} else
			/* new part with body attached */
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* simpy copy the body of the part */
				memcpy(new_buf+offset, part->body.s, part->body.len );
				offset += part->body.len;
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			} else
			/* old part with lumps */
			{
				/* first find the first lump inside our body part */
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					/* apply the lumps */
					process_lumps( msg, lump, new_buf, &offset, orig_offs,
						send_sock, part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part */
				size = (part->body.s+part->body.len-msg->buf)-*orig_offs;
				memcpy(new_buf+offset, msg->buf+*orig_offs, size);
				offset += size;
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			}

			/* reposition at the end of the processed body */
			if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
				*orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN ;

		} /* end for(over the parts) */

		/* the final separator */
		memcpy(new_buf+offset, "--" OSS_BOUNDARY "--" CRLF,
			2 + sizeof(OSS_BOUNDARY)-1 + 2 + CRLF_LEN);
		offset += 2 + sizeof(OSS_BOUNDARY)-1 + 2 + CRLF_LEN;

		/*done here !!*/
		*new_offs = offset;

	} else {

		/* multi to multi parts - iterate the list, handle insert new parts,
		 * remove old ones, and modify the kept ones (if the case) */
		LM_DBG("multi to multi part body reconstruction\n");

		offset = *new_offs;
		lump = msg->body_lumps;
		for( part=&msg->body->first ; part ; part=part->next) {
			/* skip deleted parts */
			if ( (part->flags & SIP_BODY_PART_FLAG_DELETED) ) {
				if ( (part->flags & SIP_BODY_PART_FLAG_NEW) == 0 )
					/* reposition at the end of the skipped body */
					*orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;
				continue;
			}

			LM_DBG("handing part with flags %x, mime %.*s, dump function %p\n",
				part->flags, part->mime_s.len, part->mime_s.s, part->dump_f);

			/* new part ? */
			if ( part->flags & SIP_BODY_PART_FLAG_NEW ) {
				/* separator and CT header */
				memcpy(new_buf+offset, "--" , 2);
				offset += 2;
				memcpy(new_buf+offset, msg->body->boundary.s , msg->body->boundary.len);
				offset += msg->body->boundary.len;
				memcpy(new_buf+offset, CRLF "Content-Type: " , CRLF_LEN+14);
				offset += CRLF_LEN + 14 ;
				memcpy(new_buf+offset, part->mime_s.s , part->mime_s.len);
				offset += part->mime_s.len;
				if (part->headers.len==0) {
					memcpy(new_buf+offset, CRLF CRLF , CRLF_LEN+CRLF_LEN);
					offset += CRLF_LEN + CRLF_LEN ;
				} else {
					memcpy(new_buf+offset, CRLF , CRLF_LEN);
					offset += CRLF_LEN;
					memcpy(new_buf+offset, part->headers.s , part->headers.len);
					offset += part->headers.len ;
					memcpy(new_buf+offset, CRLF , CRLF_LEN);
					offset += CRLF_LEN;
				}
				/* simply copy the body of the part */
				if (part->dump_f) {
					memcpy(new_buf+offset, part->dump.s, part->dump.len );
					offset += part->dump.len;
					part->dump.s = NULL;
					part->dump.len = 0;
				} else {
					memcpy(new_buf+offset, part->body.s, part->body.len );
					offset += part->body.len;
				}
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			} else
			/* old part with dump function */
			if (part->dump_f) {
				/* copy separator and headers from original message */
				size = (part->body.s - msg->buf) - *orig_offs;
				memcpy( new_buf+offset,  msg->buf+*orig_offs, size);
				offset += size;
				/* put in the new body */
				memcpy(new_buf+offset, part->dump.s, part->dump.len );
				offset += part->dump.len;
				pkg_free(part->dump.s);
				part->dump.s = NULL;
				part->dump.len = 0;
				memcpy(new_buf+offset, CRLF , CRLF_LEN);
				offset += CRLF_LEN;
			} else
			/* old part with lumps -> apply changes */
			{
				/* first find the first lump inside our body part
				 * NOTE: we do not need to explicitly copy the separtor and
				 * the headers as they will be automatically got by the 
				 * first lup or by the final copy */
				while ( lump && lump->u.offset<(part->body.s-msg->buf) )
					lump=lump->next;
				if (lump) {
					LM_DBG("lumps found in the part, applying...\n");
					/* apply the lumps */
					process_lumps( msg, lump, new_buf, &offset, orig_offs,
						send_sock, part->body.s+part->body.len-msg->buf);
				}
				/* and copy whatever is left, all the way to the end of part,
				 * including the next CRLF */
				size = (part->body.s+part->body.len-msg->buf+CRLF_LEN)-*orig_offs;
				memcpy(new_buf+offset, msg->buf+*orig_offs, size);
				offset += size;
			}

			/* reposition at the end of the processed body */
			if ((part->flags & SIP_BODY_PART_FLAG_NEW) == 0)
				*orig_offs = part->body.s+part->body.len-msg->buf+CRLF_LEN;

		} /* end for(over the parts) */

		/* the final separator */
		size = msg->len - *orig_offs;
		memcpy(new_buf+offset, msg->buf+*orig_offs , size);
		*new_offs = offset + size;
		*orig_offs += size;

	}
	return;
}


/* Calculated the body difference in lenght after applying
 *   all the changes (over the sip body) !
 * This is a wrapper to hide the differences between 
 *   lump-based changes and body_part-based changes.
 */
static inline int calculate_body_diff(struct sip_msg *msg,
													struct socket_info *sock )
{
	if (msg->body==NULL) {
		/* no body parsed, no advanced ops done, just dummy lumps over body */
		return lumps_len(msg, msg->body_lumps, sock, -1);
	} else {
		return ((int)prep_reassemble_body_parts( msg, sock) - msg->body->body.len);
	}
}


/* Writes down the new SIP message buffer (SIP headers and body) after
 *   after applying all the changes (over SIP hdrs and SIP body) !
 * This is a wrapper to hide the differences between 
 *   lump-based changes and body_part-based changes.
 */
static inline void apply_msg_changes(struct sip_msg *msg,
							char *new_buf, unsigned int *new_offs,
							unsigned int *orig_offs, struct socket_info *sock,
							unsigned int max_offset)
{
	unsigned int size;

	/* apply changes over the SIP headers */
	process_lumps(msg, msg->add_rm, new_buf, new_offs, orig_offs, sock, -1);
	if (msg->body==NULL) {
		/* no body parsed, no advanced ops done, just dummy lumps over body */
		process_lumps(msg, msg->body_lumps, new_buf, new_offs,
			orig_offs, sock, max_offset);
		/* copy the rest of the message */
		memcpy(new_buf+*new_offs, msg->buf+*orig_offs, max_offset-*orig_offs);
		*new_offs += max_offset-*orig_offs;
	} else {
		/* copy whatever is left in the original buffer (up to the body) */
		size = (msg->body->part_count) ?
			  ((msg->body->body.s - msg->buf) - *orig_offs) /* msg had body */
			: (msg->len - *orig_offs);                      /* no body */
		memcpy(new_buf+*new_offs, msg->buf+*orig_offs, size );
		*new_offs += size;
		*orig_offs += size;
		/* rebuild the body, part by part, in a content wise manner */
		reassemble_body_parts(msg, new_buf, new_offs, orig_offs, sock);
	}
}


/*! \brief
 * Adjust/insert Content-Length if necessary
 */
static inline int adjust_clen(struct sip_msg* msg, int body_delta, int proto)
{
	struct lump* anchor;
	char* clen_buf;
	int clen_len;

	/* Calculate message length difference caused by lumps modifying message
	 * body, from this point on the message body must not be modified. Zero
	 * value indicates that the body hasn't been modified
	*/

	clen_buf = 0;
	anchor=0;

	/* check to see if we need to add clen */
	if (is_tcp_based_proto(proto)) {
		if (parse_headers(msg, HDR_CONTENTLENGTH_F, 0)==-1){
			LM_ERR("parsing content-length\n");
			goto error;
		}
		if (msg->content_length==0){
			/* not present, we need to add it */
			/* msg->unparsed should point just before the final crlf
			 * - whole message was parsed by the above parse_headers
			 *   which did not find content-length */
			anchor=anchor_lump(msg, msg->unparsed-msg->buf,
												HDR_CONTENTLENGTH_T);
			if (anchor==0){
				LM_ERR("cannot set clen anchor\n");
				goto error;
			}
		}
	}

	if ((anchor==0) && body_delta){
		if (parse_headers(msg, HDR_CONTENTLENGTH_F, 0) == -1) {
			LM_ERR("parsing Content-Length\n");
			goto error;
		}

		/* The body has been changed, try to find
		 * existing Content-Length
		 */
		/* no need for Content-Length if it's and UDP packet and
		 * it hasn't Content-Length already */
		if (msg->content_length==0){
		    /* content-length doesn't exist, append it */
			/* msg->unparsed should point just before the final crlf
			 * - whole message was parsed by the above parse_headers
			 *   which did not find content-length */
			if (proto!=PROTO_UDP){
				anchor=anchor_lump(msg, msg->unparsed-msg->buf,
													HDR_CONTENTLENGTH_T);
				if (anchor==0){
					LM_ERR("cannot set clen anchor\n");
					goto error;
				}
			}else{
				LM_DBG("the UDP packet has no clen => not adding one \n");
			}
		}else{
			/* Content-Length has been found, remove it */
			anchor = del_lump(	msg, msg->content_length->name.s - msg->buf,
								msg->content_length->len, HDR_CONTENTLENGTH_T);
			if (anchor==0) {
				LM_ERR("can't remove original Content-Length\n");
				goto error;
			}
		}
	}

	if (anchor){
		clen_buf = clen_builder(msg, &clen_len, body_delta);
		if (!clen_buf) goto error;
		if (insert_new_lump_after(anchor, clen_buf, clen_len,
					HDR_CONTENTLENGTH_T) == 0)
			goto error;
	}

	return 0;
error:
	if (clen_buf) pkg_free(clen_buf);
	return -1;
}


/*! \brief
 * Save given Path body as Route header in message.
 *
 * If another Route HF is found, it's placed right before that.
 * Otherwise, it's placed after the last Via HF. If also no
 * Via HF is found, it's placed as first HF.
 */
#define ROUTE_STR  "Route: "
#define ROUTE_LEN  (sizeof(ROUTE_STR)-1)
static inline int insert_path_as_route(struct sip_msg* msg, str* path)
{
	struct lump *anchor;
	char *route;
	struct hdr_field *hf, *last_via=0;

	for (hf = msg->headers; hf; hf = hf->next) {
		if (hf->type == HDR_ROUTE_T) {
			break;
		} else if (hf->type == HDR_VIA_T) {
			last_via = hf;
		}
	}
	if (hf) {
		/* Route HF found, insert before it */
		anchor = anchor_lump(msg, hf->name.s - msg->buf, 0);
	} else if(last_via) {
		if (last_via->next) {
			/* Via HF in between, insert after it */
			anchor = anchor_lump(msg, last_via->next->name.s - msg->buf, 0);
		} else {
			/* Via HF is last, so append */
			anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		}
	} else {
		/* None of the above, insert as first */
		anchor = anchor_lump(msg, msg->headers->name.s - msg->buf, 0);
	}

	if (anchor == 0) {
		LM_ERR("failed to get anchor\n");
		return -1;
	}

	route = pkg_malloc(ROUTE_LEN + path->len + CRLF_LEN);
	if (!route) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}
	memcpy(route, ROUTE_STR, ROUTE_LEN);
	memcpy(route + ROUTE_LEN, path->s, path->len);
	memcpy(route + ROUTE_LEN + path->len, CRLF, CRLF_LEN);

	if (insert_new_lump_before(anchor, route, ROUTE_LEN + path->len + CRLF_LEN, 0) == 0) {
		LM_ERR("failed to insert lump\n");
		return -1;
	}

	return 0;
}

int is_del_via1_lump(struct sip_msg* msg)
{
	struct lump* lump;
	int via1_off, via1_len;

/*	for(lump= msg->add_rm; lump; lump= lump->next)
		if(lump->type == HDR_VIA1_T && lump->op== LUMP_DEL)
			return 1;
*/
	if(!msg->h_via1)
		return 0;

	via1_off = msg->h_via1->name.s - msg->buf;
	via1_len = msg->h_via1->len;

	for(lump= msg->add_rm; lump; lump= lump->next)
	{
		if(lump->type == 0 && lump->op== LUMP_DEL && lump->u.offset == via1_off && lump->len == via1_len)
			return 1;
	}
	return 0;
}

char * build_req_buf_from_sip_req( struct sip_msg* msg,
								unsigned int *returned_len,
								struct socket_info* send_sock, int proto,
								str *via_params, unsigned int flags)
{
	unsigned int len, new_len, received_len, rport_len, uri_len, via_len, body_delta;
	char *line_buf, *received_buf, *rport_buf, *new_buf, *buf, *id_buf;
	unsigned int offset, s_offset, size, id_len;
	struct lump *anchor, *via_insert_param;
	str branch, extra_params, body;
	struct hostport hp;

	id_buf=0;
	id_len=0;
	via_insert_param=0;
	extra_params.len=0;
	extra_params.s=0;
	uri_len=0;
	buf=msg->buf;
	len=msg->len;
	received_len=0;
	rport_len=0;
	new_buf=0;
	received_buf=0;
	rport_buf=0;
	line_buf=0;
	int via1_deleted = 0;

	if (msg->path_vec.len) {
		if (insert_path_as_route(msg, &msg->path_vec) < 0) {
			LM_ERR("adding path lumps failed\n");
			goto error;
		}
	}

	/* Calculate message body difference and adjust
	 * Content-Length
	 */
	body_delta = calculate_body_diff( msg, send_sock);
	if (adjust_clen(msg, body_delta, proto) < 0) {
		LM_ERR("failed to adjust Content-Length\n");
		goto error;
	}

	if (flags&MSG_TRANS_NOVIA_FLAG)
		goto build_msg;

	/* add id if tcp-based protocol  */
	if (is_tcp_based_proto(msg->rcv.proto)) {
		if  ((id_buf=id_builder(msg, &id_len))==0){
			LM_ERR("id_builder failed\n");
			goto error; /* we don't need to free anything,
			                 nothing alloc'ed yet*/
		}
		LM_DBG("id added: <%.*s>, rcv proto=%d\n",
				(int)id_len, id_buf, msg->rcv.proto);
		/* if there was already something there, simply copy them */
		if (via_params && via_params->len != 0) {
			extra_params.len = id_len + via_params->len;
			extra_params.s=pkg_malloc(extra_params.len);
			if(extra_params.s==0) {
				LM_ERR("extra params building failed\n");
				pkg_free(id_buf);
				goto error;
			}
			memcpy(extra_params.s, via_params->s, via_params->len);
			memcpy(extra_params.s + via_params->len, id_buf, id_len);
		} else {
			extra_params.s=id_buf;
			extra_params.len=id_len;
		}
	}

	/* check whether to add rport parameter to local via */
	if(msg->msg_flags&FL_FORCE_LOCAL_RPORT) {
		id_buf=extra_params.s;
		id_len=extra_params.len;
		if (via_params && !extra_params.len) {
			/* if no other parameters were added yet, consider via_params */
			extra_params.len = via_params->len;
			/* otherwise, the via_params were already copied in the id block */
		}
		extra_params.len += RPORT_LEN-1; /* last char in RPORT define is '='
										which is not added, but the new buffer
										will be null terminated */
		extra_params.s = (char*)pkg_malloc(extra_params.len+1);
		if(extra_params.s==0) {
			LM_ERR("extra params building failed\n");
			if (id_buf) pkg_free(id_buf);
			goto error;
		}

		if(id_buf!=0) {
			memcpy(extra_params.s, id_buf, id_len);
			pkg_free(id_buf);
		} else if (via_params)
			memcpy(extra_params.s, via_params->s, via_params->len);
		memcpy(extra_params.s+id_len, RPORT, RPORT_LEN-1);
		extra_params.s[extra_params.len]='\0';
		LM_DBG("extra param added: <%.*s>\n",extra_params.len, extra_params.s);
	}

	branch.s=msg->add_to_branch_s;
	branch.len=msg->add_to_branch_len;
	set_hostport(&hp, msg);
	line_buf = via_builder( &via_len, send_sock, &branch,
						extra_params.len?&extra_params:via_params, proto, &hp);
	if (!line_buf){
		LM_ERR("no via received!\n");
		goto error00;
	}

	via1_deleted = is_del_via1_lump(msg);
	/* check if received needs to be added:
	 *  - if the VIA address and the received address are different
	 *  - if the rport was forced (rport requires received)
	 *  - if the rport was received in the VIA hdr
	 *  - and there is no lump that delets VIA1 hdr */
	if ( (msg->via1->rport || (msg->msg_flags&FL_FORCE_RPORT) ||
			received_test(msg) ) && !via1_deleted) {
		if ((received_buf=received_builder(msg,&received_len))==0){
			LM_ERR("received_builder failed\n");
			goto error01;  /* free also line_buf */
		}
	}

	/* check if rport needs to be updated:
	 *  - if FL_FORCE_RPORT is set add it (and del. any previous version)
	 *  - if via already contains an rport add it and overwrite the previous
	 *  rport value if present (if you don't want to overwrite the previous
	 *  version remove the comments) */
	if (((msg->msg_flags&FL_FORCE_RPORT)||
			(msg->via1->rport /*&& msg->via1->rport->value.s==0*/)) && !via1_deleted){
		if ((rport_buf=rport_builder(msg, &rport_len))==0){
			LM_ERR("rport_builder failed\n");
			goto error01; /* free everything */
		}
	}

	/* add via header to the list */
	/* try to add it before msg. 1st via */
	/* add first via, as an anchor for second via*/
	anchor=anchor_lump(msg, msg->via1->hdr.s-buf, HDR_VIA_T);
	if (anchor==0) goto error01;
	if (insert_new_lump_before(anchor, line_buf, via_len, HDR_VIA_T)==0)
		goto error01;
	/* find out where the offset of the first parameter that should be added
	 * (after host:port), needed by add receive & maybe rport */
	if (msg->via1->params.s){
			size= msg->via1->params.s-msg->via1->hdr.s-1; /*compensate
														  for ';' */
	}else{
			size= msg->via1->host.s-msg->via1->hdr.s+msg->via1->host.len;
			if (msg->via1->port!=0){
				/*size+=strlen(msg->via1->hdr.s+size+1)+1;*/
				size += msg->via1->port_str.len + 1; /* +1 for ':'*/
			}
	}
	/* if received needs to be added, add anchor after host and add it, or
	 * overwrite the previous one if already present */
	if (received_len){
		if (msg->via1->received){ /* received already present => overwrite it*/
			via_insert_param=del_lump(msg,
								msg->via1->received->start-buf-1, /*;*/
								msg->via1->received->size+1, /*;*/ HDR_VIA_T);
		}else if (via_insert_param==0){ /* receive not present, ok */
			via_insert_param=anchor_lump(msg,
										msg->via1->hdr.s-buf+size, HDR_VIA_T);
		}
		if (via_insert_param==0) goto error02; /* free received_buf */
		if (insert_new_lump_after(via_insert_param, received_buf, received_len,
					HDR_VIA_T) ==0 ) goto error02; /* free received_buf */
	}
	/* if rport needs to be updated, delete it if present and add it's value */
	if (rport_len){
		if (msg->via1->rport){ /* rport already present */
			via_insert_param=del_lump(msg,
								msg->via1->rport->start-buf-1, /*';'*/
								msg->via1->rport->size+1 /* ; */, HDR_VIA_T);
		}else if (via_insert_param==0){ /*force rport, no rport present */
			/* no rport, add it */
			via_insert_param=anchor_lump(msg,
									msg->via1->hdr.s-buf+size, HDR_VIA_T);
		}
		if (via_insert_param==0) goto error03; /* free rport_buf */
		if (insert_new_lump_after(via_insert_param, rport_buf, rport_len,
									HDR_VIA_T) ==0 )
			goto error03; /* free rport_buf */
	}

build_msg:
	/* adjust len to the useful part of the message */
	if (get_body(msg, &body) == 0 && body.len)
		len -= (msg->buf + msg->len - body.s - body.len);

	/* compute new msg len and fix overlapping zones*/
	new_len=len+body_delta+lumps_len(msg, msg->add_rm, send_sock,-1);
#ifdef XL_DEBUG
	LM_DBG("new_len(%d)=len(%d)+lumps_len\n", new_len, len);
#endif

	if (msg->new_uri.s){
		uri_len=msg->new_uri.len;
		new_len=new_len-msg->first_line.u.request.uri.len+uri_len;
	}
	if (flags&MSG_TRANS_SHM_FLAG)
		new_buf=(char*)shm_malloc(new_len+1);
	else
		new_buf=(char*)pkg_malloc(new_len+1);
	if (new_buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		goto error00;
	}

	offset=s_offset=0;
	if (msg->new_uri.s){
		/* copy message up to uri */
		size=msg->first_line.u.request.uri.s-buf;
		memcpy(new_buf, buf, size);
		offset+=size;
		s_offset+=size;
		/* add our uri */
		memcpy(new_buf+offset, msg->new_uri.s, uri_len);
		offset+=uri_len;
		s_offset+=msg->first_line.u.request.uri.len; /* skip original uri */
	}

	/* apply changes over SIP hdrs and body */
	apply_msg_changes( msg, new_buf, &offset, &s_offset, send_sock, len);
	if (offset!=new_len) {
		LM_BUG("len mismatch : calculated %d, written %d\n", new_len, offset);
		abort();
	}

	new_buf[new_len]=0;

	*returned_len=new_len;
	/* cleanup */
	if (extra_params.s) pkg_free(extra_params.s);
	return new_buf;

error01:
	if (line_buf) pkg_free(line_buf);
error02:
	if (received_buf) pkg_free(received_buf);
error03:
	if (rport_buf) pkg_free(rport_buf);
error00:
	if (extra_params.s) pkg_free(extra_params.s);
error:
	*returned_len=0;
	return 0;
}



char * build_res_buf_from_sip_res( struct sip_msg* msg,
	unsigned int *returned_len, struct socket_info *sock,int flags)
{
	unsigned int new_len, body_delta, len;
	char *new_buf, *buf;
	unsigned int offset, s_offset;
	str body;

	buf=msg->buf;
	len=msg->len;
	new_buf=0;

	/* Calculate message body difference and adjust
	 * Content-Length
	 */
	body_delta = calculate_body_diff( msg, sock);
	if (adjust_clen(msg, body_delta, (msg->via2? msg->via2->proto:PROTO_UDP))
			< 0) {
		LM_ERR("failed to adjust Content-Length\n");
		goto error;
	}

	/* remove the first via */
	if (!(flags & MSG_TRANS_NOVIA_FLAG)) {
		unsigned int via_len, via_offset;

		if (msg->via1->next) {
			via_len = msg->via1->bsize;
			via_offset = msg->h_via1->body.s-buf;
		} else {
			via_len = msg->h_via1->len;
			via_offset = msg->h_via1->name.s-buf;
		}

		if (del_lump(msg, via_offset, via_len, HDR_VIA_T) == 0) {
			LM_ERR("failed to remove first via\n");
			goto error;
		}
	}

	/* adjust len to the useful part of the message */
	if (get_body(msg, &body) == 0 && body.len)
		len -= (msg->buf + msg->len - body.s - body.len);
	new_len=len+body_delta+lumps_len(msg, msg->add_rm, sock, -1);

	LM_DBG(" old size: %d, new size: %d\n", len, new_len);
	new_buf=(char*)pkg_malloc(new_len+1); /* +1 is for debugging
											 (\0 to print it )*/
	if (new_buf==0){
		LM_ERR("out of pkg mem\n");
		goto error;
	}
	offset=s_offset=0;

	/* apply changes over SIP hdrs and body */
	apply_msg_changes( msg, new_buf, &offset, &s_offset, sock, len);
	if (offset!=new_len) {
		LM_BUG("len mismatch : calculated %d, written %d\n", new_len, offset);
		abort();
	}

	new_buf[new_len]=0; /* debug: print the message */

	/* as it is a relaied reply, if 503, make it 500 (just reply code) */
	if ( !disable_503_translation && msg->first_line.u.reply.statuscode==503 )
		new_buf[(int)(msg->first_line.u.reply.status.s-msg->buf)+2] = '0';
	/* send it! */
	LM_DBG("copied size: orig:%d, new: %d, rest: %d"
			" msg=\n%s\n", s_offset, offset, len-s_offset, new_buf);

	*returned_len=new_len;
	return new_buf;
error:
	*returned_len=0;
	return 0;
}


char * build_res_buf_from_sip_req( unsigned int code, str *text ,str *new_tag,
		struct sip_msg* msg, unsigned int *returned_len, struct bookmark *bmark)
{
	char *buf, *p, *received_buf, *rport_buf, *warning_buf;
	char *content_len_buf, *after_body, *totags;
	unsigned int len, foo, received_len, rport_len;
	unsigned int warning_len, content_len_len;
	struct hdr_field *hdr;
	struct lump_rpl *lump, *body;
	int i;
	str to_tag;

	body = 0;
	buf=0;
	to_tag.s = 0;
	to_tag.len = 0;
	received_buf=rport_buf=warning_buf=content_len_buf=0;
	received_len=rport_len=warning_len=content_len_len=0;

	/* force parsing all headers -- we want to return all
	Via's in the reply and they may be scattered down to the
	end of header (non-block Vias are a really poor property
	of SIP :( ) */
	if (parse_headers( msg, HDR_EOH_F, 0 )==-1) {
		LM_ERR("parse_headers failed\n");
		goto error00;
	}

	/*computes the length of the new response buffer*/
	len = 0;

	/* check if rport needs to be updated */
	if ( (msg->msg_flags&FL_FORCE_RPORT)||
		(msg->via1->rport /*&& msg->via1->rport->value.s==0*/)){
		if ((rport_buf=rport_builder(msg, &rport_len))==0){
			LM_ERR("rport_builder failed\n");
			goto error00;
		}
		if (msg->via1->rport)
			len -= msg->via1->rport->size+1; /* include ';' */
	}

	/* check if received needs to be added or via rport has to be added */
	if (rport_buf || received_test(msg)) {
		if ((received_buf=received_builder(msg,&received_len))==0) {
			LM_ERR("received_builder failed\n");
			goto error01;
		}
	}

	/* first line */
	len += SIP_VERSION_LEN + 1/*space*/ + 3/*code*/ + 1/*space*/ +
		text->len + CRLF_LEN/*new line*/;
	/*headers that will be copied (TO, FROM, CSEQ,CALLID,VIA)*/
	for ( hdr=msg->headers ; hdr ; hdr=hdr->next ) {
		switch (hdr->type) {
			case HDR_TO_T:
				if (new_tag && new_tag->len) {
					to_tag=get_to(msg)->tag_value;
					if (to_tag.len )
						len+=new_tag->len-to_tag.len;
					else
						len+=new_tag->len+TOTAG_TOKEN_LEN/*";tag="*/;
				}
				len += hdr->len;
				break;
			case HDR_VIA_T:
				/* we always add CRLF to via*/
				len+=(hdr->body.s+hdr->body.len)-hdr->name.s+CRLF_LEN;
				if (hdr==msg->h_via1) len += received_len+rport_len;
				break;
			case HDR_RECORDROUTE_T:
				/* RR only for 1xx and 2xx replies */
				if (code<180 || code>=300)
					break;
			case HDR_FROM_T:
			case HDR_CALLID_T:
			case HDR_CSEQ_T:
				/* we keep the original termination for these headers*/
				len += hdr->len;
				break;
			default:
				/* do nothing, we are interested only in the above headers */
				;
		}
	}
	/* lumps length */
	for(lump=msg->reply_lump;lump;lump=lump->next) {
		len += lump->text.len;
		if (lump->flags&LUMP_RPL_BODY)
			body = lump;
	}
	/* server header */
	if (server_signature)
		len += server_header.len + CRLF_LEN;
	/* warning hdr */
	if (sip_warning) {
		warning_buf = warning_builder(msg,&warning_len);
		if (warning_buf) len += warning_len + CRLF_LEN;
		else LM_WARN("warning skipped -- too big\n");
	}
	/* content length hdr */
	if (body) {
		content_len_buf = int2str(body->text.len, (int*)&content_len_len);
		len += CONTENT_LENGTH_LEN + content_len_len + CRLF_LEN;
	} else {
		len += CONTENT_LENGTH_LEN + 1/*0*/ + CRLF_LEN;
	}
	/* end of message */
	len += CRLF_LEN; /*new line*/

	/*allocating mem*/
	buf = (char*) pkg_malloc( len+1 );
	if (!buf)
	{
		LM_ERR("out of pkg memory; needs %d\n",len);
		goto error01;
	}

	/* filling the buffer*/
	p=buf;
	/* first line */
	memcpy( p , SIP_VERSION , SIP_VERSION_LEN );
	p += SIP_VERSION_LEN;
	*(p++) = ' ' ;
	/*code*/
	for ( i=2 , foo = code  ;  i>=0  ;  i-- , foo=foo/10 )
		*(p+i) = '0' + foo - ( foo/10 )*10;
	p += 3;
	*(p++) = ' ' ;
	memcpy( p , text->s , text->len );
	p += text->len;
	memcpy( p, CRLF, CRLF_LEN );
	p+=CRLF_LEN;
	/* headers*/
	for ( hdr=msg->headers ; hdr ; hdr=hdr->next ) {
		switch (hdr->type)
		{
			case HDR_VIA_T:
				if (hdr==msg->h_via1){
					i = 0;
					if (received_buf) {
						i = msg->via1->host.s - msg->via1->hdr.s +
							msg->via1->host.len + (msg->via1->port?
							msg->via1->port_str.len + 1 : 0);
						/* copy via1 up to params */
						append_str( p, hdr->name.s, i);
						/* copy received param */
						append_str( p, received_buf, received_len);
					}
					if (rport_buf){
						if (msg->via1->rport){ /* delete the old one */
							/* copy until rport */
							append_str_trans( p, hdr->name.s+i ,
								msg->via1->rport->start-hdr->name.s-1-i,msg);
							/* copy new rport */
							append_str(p, rport_buf, rport_len);
							/* copy the rest of the via */
							append_str_trans(p, msg->via1->rport->start+
												msg->via1->rport->size,
												hdr->body.s+hdr->body.len-
												msg->via1->rport->start-
												msg->via1->rport->size, msg);
						}else{ /* just copy rport and rest of hdr */
							append_str(p, rport_buf, rport_len);
							append_str_trans( p, hdr->name.s+i ,
								(hdr->body.s+hdr->body.len)-hdr->name.s-i,msg);
						}
					}else{
						/* normal whole via copy */
						append_str_trans( p, hdr->name.s+i ,
							(hdr->body.s+hdr->body.len)-hdr->name.s-i, msg);
					}
				}else{
					/* normal whole via copy */
					append_str_trans( p, hdr->name.s,
							(hdr->body.s+hdr->body.len)-hdr->name.s, msg);
				}
				append_str( p, CRLF,CRLF_LEN);
				break;
			case HDR_RECORDROUTE_T:
				/* RR only for 1xx and 2xx replies */
				if (code<180 || code>=300) break;
				append_str(p, hdr->name.s, hdr->len);
				break;
			case HDR_TO_T:
				if (new_tag && new_tag->len){
					if (to_tag.len ) { /* replacement */
						/* before to-tag */
						append_str( p, hdr->name.s, to_tag.s-hdr->name.s);
						/* to tag replacement */
						bmark->to_tag_val.s=p;
						bmark->to_tag_val.len=new_tag->len;
						append_str( p, new_tag->s,new_tag->len);
						/* the rest after to-tag */
						append_str( p, to_tag.s+to_tag.len,
							hdr->name.s+hdr->len-(to_tag.s+to_tag.len));
					}else{ /* adding a new to-tag */
						after_body=hdr->body.s+hdr->body.len;
						append_str( p, hdr->name.s, after_body-hdr->name.s);
						append_str(p, TOTAG_TOKEN, TOTAG_TOKEN_LEN);
						bmark->to_tag_val.s=p;
						bmark->to_tag_val.len=new_tag->len;
						append_str( p, new_tag->s,new_tag->len);
						append_str( p, after_body,
										hdr->name.s+hdr->len-after_body);
					}
					break;
				} /* no new to-tag -- proceed to 1:1 copying  */
				totags=((struct to_body*)(hdr->parsed))->tag_value.s;
				if (totags) {
					bmark->to_tag_val.s=p+(totags-hdr->name.s);
					bmark->to_tag_val.len=
							((struct to_body*)(hdr->parsed))->tag_value.len;
				} else {
					bmark->to_tag_val.s = NULL;
					bmark->to_tag_val.len = 0;
				}
			case HDR_FROM_T:
			case HDR_CALLID_T:
			case HDR_CSEQ_T:
					append_str(p, hdr->name.s, hdr->len);
					break;
			default:
				/* do nothing, we are interested only in the above headers */
				;
		} /* end switch */
	} /* end for */
	/* lumps */
	for(lump=msg->reply_lump;lump;lump=lump->next)
		if (lump->flags&LUMP_RPL_HDR){
			memcpy(p,lump->text.s,lump->text.len);
			p += lump->text.len;
		}
	/* server header */
	if (server_signature) {
		append_str( p, server_header.s, server_header.len);
		append_str( p, CRLF, CRLF_LEN );
	}
	/* content_length hdr */
	if (content_len_len) {
		append_str( p, CONTENT_LENGTH, CONTENT_LENGTH_LEN);
		append_str( p, content_len_buf, content_len_len );
		append_str( p, CRLF, CRLF_LEN );
	} else {
		append_str( p, CONTENT_LENGTH"0"CRLF,CONTENT_LENGTH_LEN+1+CRLF_LEN);
	}
	/* warning header */
	if (warning_buf) {
		append_str( p, warning_buf, warning_len );
		append_str( p, CRLF, CRLF_LEN );
	}
	/*end of message*/
	memcpy( p, CRLF, CRLF_LEN );
	p+=CRLF_LEN;
	/* body */
	if (body) {
		append_str( p, body->text.s, body->text.len );
	}

	if (len!=(unsigned long)(p-buf))
		LM_CRIT("diff len=%d p-buf=%d\n", len, (int)(p-buf));

	*(p) = 0;
	*returned_len = len;
	/* in req2reply, received_buf is not introduced to lumps and
	   needs to be deleted here
	*/
	if (received_buf) pkg_free(received_buf);
	if (rport_buf) pkg_free(rport_buf);
	return buf;

error01:
	if (received_buf) pkg_free(received_buf);
	if (rport_buf) pkg_free(rport_buf);
error00:
	*returned_len=0;
	return 0;
}



/*! \brief return number of chars printed or 0 if space exceeded;
   assumes buffer size of at least MAX_BRANCH_PARAM_LEN
 */
int branch_builder( unsigned int hash_index,
	/* only either parameter useful */
	unsigned int label, char * char_v,
	int branch,
	char *branch_str, int *len )
{

	char *begin;
	int size;

	/* hash id provided ... start with it */
	size=MAX_BRANCH_PARAM_LEN;
	begin=branch_str;
	*len=0;

	memcpy(begin, MCOOKIE, MCOOKIE_LEN );
	size-=MCOOKIE_LEN;begin+=MCOOKIE_LEN;

	if (int2reverse_hex( &begin, &size, hash_index)==-1)
		return 0;

	if (size) {
		*begin=BRANCH_SEPARATOR;
		begin++; size--;
	} else return 0;

	/* string with request's characteristic value ... use it ... */
	if (char_v) {
		if (memcpy(begin,char_v,MD5_LEN)) {
			begin+=MD5_LEN; size-=MD5_LEN;
		} else return 0;
	} else { /* ... use the "label" value otherwise */
		if (int2reverse_hex( &begin, &size, label )==-1)
			return 0;
	}

	if (size) {
		*begin=BRANCH_SEPARATOR;
		begin++; size--;
	} else return 0;

	if (int2reverse_hex( &begin, &size, branch)==-1)
		return 0;

	*len=MAX_BRANCH_PARAM_LEN-size;
	return size;

}


char* via_builder( unsigned int *len,
	struct socket_info* send_sock,
	str* branch, str* extra_params, int proto, struct hostport* hp)
{
	unsigned int via_len, extra_len;
	char *line_buf;
	int max_len, local_via_len=MY_VIA_LEN;
	str* address_str; /* address displayed in via */
	str* port_str; /* port no displayed in via */

	/* use pre-set address in via or the outbound socket one */
	if (hp && hp->host && hp->host->len)
		address_str=hp->host;
	else
		address_str=get_adv_host(send_sock);

	if (hp && hp->port && hp->port->len)
		port_str=hp->port;
	else
		port_str=get_adv_port(send_sock);

	max_len=local_via_len+address_str->len /* space in MY_VIA */
		+2 /* just in case it is a v6 address ... [ ] */
		+1 /*':'*/+port_str->len
		+(branch?(MY_BRANCH_LEN+branch->len):0)
		+(extra_params?extra_params->len:0)
		+CRLF_LEN+1;
	line_buf=pkg_malloc( max_len );
	if (line_buf==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}

	extra_len=0;

	memcpy(line_buf, MY_VIA, local_via_len);
	if (proto==PROTO_UDP){
		/* do nothing */
	}else if (proto==PROTO_TCP){
		memcpy(line_buf+local_via_len-4, "TCP ", 4);
	}else if (proto==PROTO_TLS){
		memcpy(line_buf+local_via_len-4, "TLS ", 4);
	}else if(proto==PROTO_SCTP){
		memcpy(line_buf+local_via_len-4, "SCTP ", 5);
		local_via_len++;
	}else if(proto==PROTO_WS){
		memcpy(line_buf+local_via_len-4, "WS ", 3);
		local_via_len--;
	}else if(proto==PROTO_WSS){
		memcpy(line_buf+local_via_len-4, "WSS ", 4);
	}else{
		LM_CRIT("unknown proto %d\n", proto);
		return 0;
	}

	via_len=local_via_len+address_str->len; /*space included in MY_VIA*/

	memcpy(line_buf+local_via_len+extra_len, address_str->s, address_str->len);
	line_buf[via_len]=':'; via_len++;
	memcpy(line_buf+via_len, port_str->s, port_str->len);
	via_len+=port_str->len;

	/* branch parameter */
	if (branch){
		memcpy(line_buf+via_len, MY_BRANCH, MY_BRANCH_LEN );
		via_len+=MY_BRANCH_LEN;
		memcpy(line_buf+via_len, branch->s, branch->len );
		via_len+=branch->len;
	}
	/* extra params  */
	if (extra_params){
		memcpy(line_buf+via_len, extra_params->s, extra_params->len);
		via_len+=extra_params->len;
	}

	memcpy(line_buf+via_len, CRLF, CRLF_LEN);
	via_len+=CRLF_LEN;
	line_buf[via_len]=0; /* null terminate the string*/

	*len = via_len;
	return line_buf;
}

#define MAX_URI_LEN		1024
static char uri_buff[MAX_URI_LEN];
char *construct_uri(str *protocol,str *username,str *domain,str *port,
		str *params,int *len)
{
	int pos = 0;

	if (!len)
	{
		LM_ERR("null pointer provided for construct_uri \n");
		return 0;
	}

	if (!protocol->s || protocol->len == 0)
	{
		LM_ERR("no protocol specified\n");
		return 0;
	}

	if (!domain->s || domain->len == 0)
	{
		LM_ERR("no domain specified\n");
		return 0;
	}

	memcpy(uri_buff,protocol->s,protocol->len);
	pos += protocol->len;
	uri_buff[pos++] = ':';

	if (username && username->s && username->len != 0)
	{
		memcpy(uri_buff+pos,username->s,username->len);
		pos += username->len;
		uri_buff[pos++] = '@';
	}

	memcpy(uri_buff+pos,domain->s,domain->len);
	pos += domain->len;

	if (port && port->s && port->len !=0)
	{
		uri_buff[pos++] = ':';
		memcpy(uri_buff+pos,port->s,port->len);
		pos += port->len;
	}

	if (params && params->s && params->len !=0 )
	{
		uri_buff[pos++] = ';';
		memcpy(uri_buff+pos,params->s,params->len);
		pos += params->len;
	}

	uri_buff[pos] = 0;
	*len = pos;
	return uri_buff;
}

/* uses uri_buff above, since contact is still an uri */
char *contact_builder(struct socket_info* send_sock, int *ct_len)
{
	char *p;
	int proto_len = 0;
	str* address_str = get_adv_host(send_sock);
	str* port_str = get_adv_port(send_sock);

	/* sip: */
	p = uri_buff;
	memcpy(p, "sip:", 4);
	p += 4;

	/* host */
	memcpy(p, address_str->s, address_str->len);
	p += address_str->len;

	/* :port */
	*p++ = ':';
	memcpy(p, port_str->s, port_str->len);
	p += port_str->len;

	/* transport if needed */
	if (send_sock->proto != PROTO_UDP) {
		memcpy(p, ";transport=", 11);
		p += 11;
		proto_len = strlen(protos[send_sock->proto].name);
		memcpy(p, protos[send_sock->proto].name, proto_len);
		p += proto_len;
	}

	*p = '\0';

	if (ct_len)
		*ct_len = p - uri_buff;

	return uri_buff;
}
