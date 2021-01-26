/*
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2015-08-14  first version (Ionut Ionita)
 */
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
//#include "../../trace_api.h"
#include "../../proxy.h"
#include "../../forward.h"
#include "../../mod_fix.h"

#include "hep.h"
#include "../compression/compression_api.h"

#include "../../lib/cJSON.h"

#define GENERIC_VENDOR_ID 0x0000
#define HEP_PROTO_SIP  0x01

static int control_id = -1;

struct hep_message_id {
	char* proto;
	int id;
};

struct hep_custom_chunk_desc {
	str chunk_name;

	int vendor;
	int chunk_id;
};


/* for safety this should stay static */
static hid_list_p hid_list=NULL;
/* list of dynamic hids */
static hid_list_p *hid_dyn_list=NULL;
static gen_lock_t *hid_dyn_lock=NULL;

extern int hep_capture_id;
extern int payload_compression;
extern int homer5_on;
extern str homer5_delim;

extern compression_api_t compression_api;

struct hep_message_id hep_ids[] = {
	{ "sip" ,  0x01},
	{ "xlog",  0x64},
	{ "mi"  ,  0x57},    // not standard
	{ "rest",  0x58},    // not standard
	{ "net",   0x59},    // not standard
	{ "control", 0x60},
	{ NULL  ,  0   }
};

struct hep_custom_chunk_desc hep_chunks[] = {
	{ str_init("correlation_id") , 0                     , 0x11},
	{ { NULL, 0}                 , 0                     , 0   }
};



extern union sockaddr_union local_su;
/*
 * @in1 buffer = hep + sip
 * @in2 buffer length
 * @in3 version - needed to make the difference betwen 3 and the first 2 protos
 * @out1 structure containing hep details + headers | see hep.h
 */
int unpack_hep(char *buf, int len, int version, struct hep_desc* h)
{
	int err;

	if (version == 3)
		err = unpack_hepv3(buf, len, h);
	else
		err = unpack_hepv12(buf, len, h);

	return err;
}


/*
 * @in1 buffer = hep + sip
 * @in2 buffer length
 * @out1 structure containing hepv12 details + headers | see hep.h
 */
int unpack_hepv12(char *buf, int len, struct hep_desc* h)
{
	int offset = 0, hl;

	struct hep_hdr *heph;
	char *hep_payload, *end, *hep_ip;
	struct hep_timehdr* heptime_tmp, heptime;

	struct hepv12 h12;

    memset(&heptime, 0, sizeof(struct hep_timehdr));

	hl = offset = sizeof(struct hep_hdr);
    end = buf + len;

	if (len < offset) {
		LM_ERR("len less than offset [%d] vs [%d]\n", len, offset);
		return -1;
	}

	/* hep_hdr */
	heph = (struct hep_hdr*) buf;

	h12.hdr = *heph;

	h12.hdr.hp_sport = ntohs(h12.hdr.hp_sport);
	h12.hdr.hp_dport = ntohs(h12.hdr.hp_dport);

	switch(heph->hp_f){
	case AF_INET:
		hl += sizeof(struct hep_iphdr);
		break;
	case AF_INET6:
		hl += sizeof(struct hep_ip6hdr);
		break;
	default:
		LM_ERR("unsupported family [%d]\n", heph->hp_f);
		return 0;
	}

	/* Check version */
	if((heph->hp_v != 1 && heph->hp_v != 2) || hl != heph->hp_l) {
		LM_ERR("not supported version or bad length: v:[%d] l:[%d] vs [%d]\n",
												heph->hp_v, heph->hp_l, hl);
		return -1;
	}
	h->version = heph->hp_v;

	hep_ip = buf + sizeof(struct hep_hdr);

	if (hep_ip > end){
		LM_ERR("hep_ip is over buf+len\n");
		return 0;
	}

	switch(heph->hp_f){
	case AF_INET:
		offset+=sizeof(struct hep_iphdr);
		h12.addr.hep_ipheader = *((struct hep_iphdr *)hep_ip);

		break;
	case AF_INET6:
		offset+=sizeof(struct hep_ip6hdr);
		h12.addr.hep_ip6header = *((struct hep_ip6hdr *)hep_ip);

		break;
	}


	/* VOIP payload */
	hep_payload = buf + offset;

	if (hep_payload > end) {
		LM_ERR("hep_payload is over buf+len\n");
		return 0;
	}

	/* time */
	if(heph->hp_v == 2) {
		offset+=sizeof(struct hep_timehdr);
		heptime_tmp = (struct hep_timehdr*) hep_payload;
		hep_payload += sizeof(struct hep_timehdr);

		heptime.tv_sec = heptime_tmp->tv_sec;
		heptime.tv_usec = heptime_tmp->tv_usec;
		heptime.captid = heptime_tmp->captid;
	}

	h12.payload.s = hep_payload;
	h12.payload.len = len - offset;

	h12.hep_time = heptime;

	h->u.hepv12 = h12;

	return 0;
}


/*
 * @in1 buffer = hep + sip
 * @in2 buffer length
 * @out1 structure containing hepv3 details + headers | see hep.h
 */
int unpack_hepv3(char *buf, int len, struct hep_desc *h)
{

/*convert from network byte order to host order*/
#define CONVERT_TO_HBO(_hdr) \
	do { \
		_hdr.vendor_id = ntohs(_hdr.vendor_id); \
		_hdr.type_id   = ntohs(_hdr.type_id);   \
		_hdr.length    = ntohs(_hdr.length);    \
	} while (0);

#define UPDATE_BUFFER(_buf, _len, _off) \
	do { \
		_buf += _off; \
		_len -= _off; \
	} while (0);

	int rc;

	unsigned char *compressed_payload;
	unsigned long compress_len;

	struct hepv3 h3;
	unsigned short tlen;
	unsigned long decompress_len;

	generic_chunk_t* gen_chunk, *it;

	u_int16_t chunk_id;
	str decompressed_payload={NULL, 0};

	memset(&h3, 0, sizeof(struct hepv3));

	h->version = 3;

	tlen = ntohs(((hep_ctrl_t*)buf)->length);

	buf += sizeof(hep_ctrl_t);
	tlen -= sizeof(hep_ctrl_t);

	memset( &h3, 0, sizeof(struct hepv3));

	while (tlen > 0) {
		/* we don't look at vendor id; we only need to parse the buffer */
		chunk_id = ((hep_chunk_t*)buf)->type_id;

		switch (ntohs(chunk_id)) {
		case HEP_PROTO_FAMILY:
			/* ip family*/
			h3.hg.ip_family = *((hep_chunk_uint8_t*)buf);

			CONVERT_TO_HBO(h3.hg.ip_family.chunk);
			UPDATE_BUFFER(buf, tlen, h3.hg.ip_family.chunk.length);

			break;
		case HEP_PROTO_ID:
			/* ip protocol ID*/
			h3.hg.ip_proto = *((hep_chunk_uint8_t*)buf);

			CONVERT_TO_HBO(h3.hg.ip_proto.chunk);
			UPDATE_BUFFER(buf, tlen, h3.hg.ip_proto.chunk.length);

			break;
		case HEP_IPV4_SRC:
			/* ipv4 source */
			h3.addr.ip4_addr.src_ip4 = *((hep_chunk_ip4_t*)buf);

			CONVERT_TO_HBO(h3.addr.ip4_addr.src_ip4.chunk);
			UPDATE_BUFFER(buf, tlen, h3.addr.ip4_addr.src_ip4.chunk.length);

			break;
		case HEP_IPV4_DST:
			/* ipv4 dest */
			h3.addr.ip4_addr.dst_ip4 = *((hep_chunk_ip4_t*)buf);

			CONVERT_TO_HBO(h3.addr.ip4_addr.dst_ip4.chunk);
			UPDATE_BUFFER(buf, tlen, h3.addr.ip4_addr.dst_ip4.chunk.length);

			break;
		case HEP_IPV6_SRC:
			/* ipv6 source */
			h3.addr.ip6_addr.src_ip6 = *((hep_chunk_ip6_t*)buf);

			CONVERT_TO_HBO(h3.addr.ip6_addr.src_ip6.chunk);
			UPDATE_BUFFER(buf, tlen, h3.addr.ip6_addr.src_ip6.chunk.length);

			break;
		case HEP_IPV6_DST:
			/* ipv6 dest */
			h3.addr.ip6_addr.dst_ip6 = *((hep_chunk_ip6_t*)buf);

			CONVERT_TO_HBO(h3.addr.ip6_addr.dst_ip6.chunk);
			UPDATE_BUFFER(buf, tlen, h3.addr.ip6_addr.dst_ip6.chunk.length);

			break;
		case HEP_SRC_PORT:
			/* source port */
			h3.hg.src_port = *((hep_chunk_uint16_t*)buf);

			CONVERT_TO_HBO(h3.hg.src_port.chunk);
			h3.hg.src_port.data = ntohs(h3.hg.src_port.data);

			UPDATE_BUFFER(buf, tlen, h3.hg.src_port.chunk.length);

			break;
		case HEP_DST_PORT:
			/* dest port */
			h3.hg.dst_port = *((hep_chunk_uint16_t*)buf);

			CONVERT_TO_HBO(h3.hg.dst_port.chunk);
			h3.hg.dst_port.data = ntohs(h3.hg.dst_port.data);

			UPDATE_BUFFER(buf, tlen, h3.hg.dst_port.chunk.length);

			break;
		case HEP_TIMESTAMP:
			/* timestamp */
			h3.hg.time_sec = *((hep_chunk_uint32_t*)buf);

			CONVERT_TO_HBO(h3.hg.time_sec.chunk);
			h3.hg.time_sec.data = ntohl(h3.hg.time_sec.data);

			UPDATE_BUFFER(buf, tlen, h3.hg.time_sec.chunk.length);

			break;
		case HEP_TIMESTAMP_US:
			/* timestamp microsecs offset */
			h3.hg.time_usec = *((hep_chunk_uint32_t*)buf);

			CONVERT_TO_HBO(h3.hg.time_usec.chunk);
			h3.hg.time_usec.data = ntohl(h3.hg.time_usec.data);

			UPDATE_BUFFER(buf, tlen, h3.hg.time_usec.chunk.length);

			break;
		case HEP_PROTO_TYPE:
			/* proto type */
			h3.hg.proto_t = *((hep_chunk_uint8_t*)buf);

			CONVERT_TO_HBO(h3.hg.proto_t.chunk);
			UPDATE_BUFFER(buf, tlen, h3.hg.proto_t.chunk.length);

			break;
		case HEP_AGENT_ID:
			/* capture agent id */
			h3.hg.capt_id = *((hep_chunk_uint32_t*)buf);

			CONVERT_TO_HBO(h3.hg.capt_id.chunk);
			h3.hg.capt_id.data = ntohl(h3.hg.capt_id.data);

			UPDATE_BUFFER(buf, tlen, h3.hg.capt_id.chunk.length);

			break;
		case HEP_PAYLOAD:
			/* captured packet payload */
			h3.payload_chunk = *((hep_chunk_payload_t*)buf);
			h3.payload_chunk.data = (char *)buf + sizeof(hep_chunk_t);

			CONVERT_TO_HBO(h3.payload_chunk.chunk);
			UPDATE_BUFFER(buf, tlen, h3.payload_chunk.chunk.length);

			break;
		case HEP_COMPRESSED_PAYLOAD:
			/* captured compressed payload(GZIP/inflate)*/

			h3.payload_chunk = *((hep_chunk_payload_t*)buf);
			h3.payload_chunk.data = (char *)buf + sizeof(hep_chunk_t);

			/* first update the buffer for further processing
			 * and convert values to host byte order */
			CONVERT_TO_HBO(h3.payload_chunk.chunk);
			UPDATE_BUFFER(buf, tlen, h3.payload_chunk.chunk.length);

			if (payload_compression) {
				compressed_payload = (unsigned char *)h3.payload_chunk.data;
				compress_len =(unsigned long)
						(h3.payload_chunk.chunk.length - sizeof(hep_chunk_t));

				rc=compression_api.decompress(compressed_payload, compress_len,
								&decompressed_payload, &decompress_len);


				if (compression_api.check_rc(rc)) {
					LM_ERR("payload decompression failed!\n");
					goto safe_exit;
				}

				/* update the length based on the new length */
				h3.payload_chunk.chunk.length += (decompress_len - compress_len);
				h3.payload_chunk.data = decompressed_payload.s;
			}/* else we're just a proxy; leaving everything as is */

			break;
		default:
			/* FIXME hep struct will be in shm, but if we put these in shm
			 * locking will be required */
			if ((gen_chunk = shm_malloc(sizeof(generic_chunk_t)))==NULL) {
				LM_ERR("no more pkg mem!\n");
				return -1;
			}

			memset(gen_chunk, 0, sizeof(generic_chunk_t));
			gen_chunk->chunk = *((hep_chunk_t*)buf);

			CONVERT_TO_HBO(gen_chunk->chunk);

			gen_chunk->data =
				shm_malloc(gen_chunk->chunk.length - sizeof(hep_chunk_t));

			if (gen_chunk->data == NULL) {
				LM_ERR("no more shared memory!\n");
				return -1;
			}

			memcpy(gen_chunk->data, (char *)buf + sizeof(hep_chunk_t),
					gen_chunk->chunk.length - sizeof(hep_chunk_t));


			UPDATE_BUFFER(buf, tlen, gen_chunk->chunk.length);

			if (h3.chunk_list == NULL) {
				h3.chunk_list = gen_chunk;
			} else {
				for (it=h3.chunk_list; it->next; it=it->next);
				it->next = gen_chunk;
			}

			break;
		}
	}

safe_exit:
	h->u.hepv3 = h3;

	return 0;
}

static int
parse_hep_uri(const str *token, str *uri, str *transport, str* version)
{
	enum states {ST_TOK_NAME, ST_TOK_VALUE, ST_TOK_END};
	enum states state = ST_TOK_NAME;

	unsigned int p;
	unsigned int last_equal=0;

	int _word_start=-1, _word_end=-1;

	char c;

	static str version_name_str={"version", sizeof("version")-1};
	static str transport_name_str={"transport", sizeof("transport")-1};

	str name={NULL, 0}, value={NULL, 0};

	if (!token) {
		LM_ERR("bad input parameter!\n");
		return -1;
	}

	if (!uri || !transport) {
		LM_ERR("bad output parameter!\n");
		return -1;
	}

	/* in order to be able to see if we've found the uri or not */
	uri->s = 0;
	uri->len = 0;

	for (p=0; p<token->len; p++) {
		/* if final ';' not provided we fake it */
		if (p != token->len - 1 || token->s[p] == ';') {
			c = token->s[p];
		} else {
			if ((isalnum(token->s[p])||token->s[p]=='$') && _word_start==-1) {
				_word_start = p;
			}
			p++;
			c = ';';
		}

		switch (c){
		case '=':

			_word_end = _word_end == -1 ? p : _word_end;

			if (state==ST_TOK_VALUE) {
				LM_ERR("bad value declaration!parsed until <%.*s>!\n",
						token->len-p, token->s+p);
				return -1;
			}

			name.s = token->s + _word_start;
			name.len = _word_end - _word_start;

			last_equal = p;

			state=ST_TOK_VALUE;
			_word_start=_word_end=-1;

			break;
		case ';':
			_word_end = _word_end == -1 ? p : _word_end;
			value.s = token->s + _word_start;;
			value.len = _word_end - _word_start;


			str_trim_spaces_lr(value);

			/* the 'ip:port' declaration will be the only one in this state */
			if (state==ST_TOK_NAME && last_equal == 0) {
				*uri = value;
				/* just fake that we've found '=' in order for the parser to work */
				last_equal=p;
			} else {
				if (uri->len == 0 || uri->s == 0)
					goto uri_not_found;

				if (name.len == 0 || name.s == 0) {
					LM_ERR("no param name provided! format '<name>=<value>'!\n");
					return -1;
				}

				if (_word_start == -1 || value.len == 0) {
					LM_ERR("Invalid null value for <%.*s>!\n", name.len, name.s);
					return -1;
				}

				if ( name.len == transport_name_str.len &&
						!memcmp(name.s, transport_name_str.s, transport_name_str.len)) {

					*transport = value;
				} else if ( name.len == version_name_str.len &&
						!memcmp(name.s, version_name_str.s, version_name_str.len)) {
					*version = value;
				} else {
					LM_ERR("no match for parameter name <%.*s>!\n",
									name.len, name.s);
					return -1;
				}
			}

			state=ST_TOK_END;
			_word_start=_word_end=-1;

			name.len = 0;
			name.s = 0;

			break;
		case '\n':
		case '\r':
		case '\t':
		case ' ':
			if (_word_start > 0) {
				_word_end = p;
			}
		case '@':
		case '(':
		case ')':
		case '/':
		case ':':
		case '.':
		case '_':
		case '-':
			break;
		default:
			if (_word_start==-1 && (isalnum(token->s[p])||token->s[p]=='$')) {
				_word_start = p;
			}

			if (_word_end == -1 && !isalnum(token->s[p]))
				_word_end = p;

			if (state==ST_TOK_END)
				state = ST_TOK_NAME;

			break;
		}
	}

	if (uri->len == 0 || uri->s == 0)
		goto uri_not_found;

	return 0;

uri_not_found:
	LM_ERR("You should provide at least the ip!\n");
	return -1;
}

static hid_list_p get_hep_id_by_name(str* name, int lock, int ref)
{
	hid_list_p it;

	if (name == NULL || name->s == NULL || name->len == 0) {
		LM_ERR("invalid hep id name!\n");
		return NULL;
	}

	for (it=hid_list; it; it=it->next) {
		if (name->len == it->name.len &&
				!memcmp(name->s, it->name.s, it->name.len)) {
			return it;
		}
	}

	if (hid_dyn_list) {
		if (lock)
			lock_get(hid_dyn_lock);
		for (it=*hid_dyn_list; it; it=it->next) {
			if (name->len == it->name.len &&
					!memcmp(name->s, it->name.s, it->name.len)) {
				if (ref)
					hid_ref(it);
				if (lock)
					lock_release(hid_dyn_lock);
				return it;
			}
		}
		if (lock)
			lock_release(hid_dyn_lock);
	}

	LM_INFO("hep id <%.*s> not found!\n", name->len, name->s);
	return NULL;
}


/*
 * New hep uri. Hep uri format
 * ip[:proto]; version=<1/2/3>; transport=<tcp/udp>;"
 * ';' can miss; version and transport are interchangeable;
 *
 */
hid_list_p new_hep_id(str *name, str *uri_s)
{
	#define IS_UDP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 'u' && (__url__.s[1]|0x20) == 'd' \
					&& (__url__.s[2]|0x20) == 'p'))

	#define IS_TCP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 't' && (__url__.s[1]|0x20) == 'c' \
					&& (__url__.s[2]|0x20) == 'p'))

	hid_list_p el;
	unsigned int port;
	unsigned int ver, trans;
	char *d;

	str uri, transport={0, 0}, version={0, 0}, port_s;

	/* if here the HEP id is unique */
	LM_DBG("Parsing hep id <%.*s>!\n", uri_s->len, uri_s->s);
	if (parse_hep_uri(uri_s, &uri, &transport, &version) < 0) {
		LM_ERR("failed to parse hep uri!\n");
		return NULL;
	}

	LM_DBG("Uri successfully parsed! Building uri structure!\n");
	/* identify the port */
	d = q_memchr(uri.s, ':', uri.len);
	if (d == NULL) {
		port_s.s = HEP_PORT_STR;
		port_s.len = sizeof(HEP_PORT_STR) - 1;
		port = HEP_PORT;
	} else {
		port_s.s = d+1;
		port_s.len = (uri.s+uri.len) - port_s.s;
		uri.len = d - uri.s;
		if (str2int(&port_s, &port)<0) {
			LM_ERR("invalid port <%.*s>!\n", port_s.len, port_s.s);
			return NULL;
		}
	}

	/* check hep version if given; default 3 */
	if (version.s && version.len) {
		if (str2int(&version, &ver) < 0) {
			LM_ERR("Bad version <%.*s\n>", version.len, version.s);
			return NULL;
		}

		if (ver < HEP_FIRST || ver > HEP_LAST) {
			LM_ERR("invalid hep version %d!\n", ver);
			return NULL;
		}
	} else {
		ver = HEP_LAST;
	}

	/* check transport if given; default TCP*/
	if (transport.len && transport.s) {
		if (IS_UDP(transport)) {
			trans = PROTO_HEP_UDP;
		} else if (IS_TCP(transport)) {
			trans = PROTO_HEP_TCP;
		} else {
			LM_ERR("Bad transport <%.*s>!\n", transport.len, transport.s);
			return NULL;
		}
	} else {
		trans = PROTO_HEP_TCP;
	}

	if (trans == PROTO_HEP_TCP && ver < 3) {
		LM_WARN("TCP not available for HEP version < 3! Falling back to udp!\n");
		trans = PROTO_HEP_UDP;
	}

	el=shm_malloc(sizeof(hid_list_t) + name->len + uri.len + port_s.len);
	if (el == NULL) {
		LM_ERR("no more shm!\n");
		return NULL;
	}

	memset(el, 0, sizeof(hid_list_t));

	/* name */
	el->name.len = name->len;
	el->name.s = (char *)(el + 1);
	memcpy(el->name.s, name->s, name->len);

	/* ip */
	el->ip.len = uri.len;
	el->ip.s = el->name.s + el->name.len;
	memcpy(el->ip.s, uri.s, uri.len);

	/* port */
	el->port.len = port_s.len;
	el->port.s = el->ip.s + el->ip.len;
	memcpy(el->port.s, port_s.s, port_s.len);
	el->port_no = port;

	el->version = ver;
	el->transport = trans;

	LM_DBG("Parsed hep id {%.*s} with ip {%.*s} port {%d}"
			" transport {%s} hep version {%d}!\n",
			el->name.len, el->name.s, el->ip.len, el->ip.s,
			el->port_no, el->transport == PROTO_HEP_TCP ? "tcp" : "udp",
			el->version);

	return el;

#undef IS_TCP
#undef IS_UDP
}

/*
 * parse hep id. Hep id format
 * [<name>]ip[:proto]; version=<1/2/3>; transport=<tcp/udp>;"
 * ';' can miss; version and transport are interchangeable;
 *
 */
int parse_hep_id(unsigned int type, void *val)
{
	str uri_s;
	str name = {0, 0};

	hid_list_p it,el;

	uri_s.s = val;
	uri_s.len = strlen(uri_s.s);

	str_trim_spaces_lr(uri_s);

	if (uri_s.len < 3 /* '[*]' */ || uri_s.s[0] != '[') {
		LM_ERR("bad format for uri {%.*s}\n", uri_s.len, uri_s.s);
		return -1;
	} else {
		/* skip the first '[' */
		uri_s.s++; uri_s.len--;
	}

	/* parse the name */
	while (uri_s.s[0]==' ') {
		uri_s.s++;
		uri_s.len--;
	}
	name.s = uri_s.s;
	while (uri_s.len && (uri_s.s[0] != ']' && uri_s.s[0] != ' ')) {
		uri_s.s++;
		uri_s.len--;
		name.len++;
	}
	if (*(uri_s.s-1) != ']')
		while (uri_s.len && uri_s.s[0] != ']') {
			uri_s.s++;
			uri_s.len--;
		}
	if (!uri_s.len || uri_s.s[0] != ']') {
		LM_ERR("bad name [%.*s]!\n", uri_s.len, uri_s.s);
		return -1;
	}
	uri_s.s++;
	uri_s.len--;

	/* no need to lock now, since this is done at startup */
	if (get_hep_id_by_name(&name, 0, 0)) {
		LM_WARN("HEP ID <%.*s> redefined! Not allowed!\n",
				name.len, name.s);
		return -1;
	}

	el = new_hep_id(&name, &uri_s);
	if (!el)
		return -1;

	/* add the new element to the hep id list */
	if (hid_list == NULL) {
		hid_list = el;
	} else {
		for (it=hid_list; it->next; it=it->next);
		it->next = el;
	}

	LM_DBG("Added hep id <%.*s> to list!\n", el->name.len, el->name.s);

	return 0;
}

/*
 *
 * TRACING API HELPER FUNCTIONS
 *
 * */

/**
 *
 */
static trace_message create_hep12_message(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int net_proto, str* payload, int version)
{
	unsigned int totlen=0;

	struct timeval tvb;

	struct hep_desc* hep_msg;

	hep_msg = pkg_malloc(sizeof(struct hep_desc));
	if (hep_msg == NULL) {
		LM_ERR("no more pkg mem!\n");
		return NULL;
	}

	memset(hep_msg , 0, sizeof(struct hep_desc));

	hep_msg->version = version;

	gettimeofday(&tvb, NULL);

	/* Version && proto */
	hep_msg->u.hepv12.hdr.hp_v = version;
	hep_msg->u.hepv12.hdr.hp_f = from_su->s.sa_family;
	hep_msg->u.hepv12.hdr.hp_p = net_proto;

	/* IP version */
	switch (hep_msg->u.hepv12.hdr.hp_f) {
		case AF_INET:
			totlen = sizeof(struct hep_iphdr);
			break;
		case AF_INET6:
			totlen = sizeof(struct hep_ip6hdr);
			break;
	}


	/* COMPLETE LEN */
	totlen += sizeof(struct hep_hdr);
	hep_msg->u.hepv12.hdr.hp_l = totlen;


	if ( payload )
		totlen += payload->len;

	if(version == 2) {
		totlen += sizeof(struct hep_timehdr);
		hep_msg->u.hepv12.hep_time.tv_sec = tvb.tv_sec;
		hep_msg->u.hepv12.hep_time.tv_usec = tvb.tv_usec;
		hep_msg->u.hepv12.hep_time.captid = hep_capture_id;
	}


	switch (hep_msg->u.hepv12.hdr.hp_f) {
		case AF_INET:
			/* Source && Destination ipaddresses*/
			hep_msg->u.hepv12.addr.hep_ipheader.hp_src = from_su->sin.sin_addr;
			hep_msg->u.hepv12.addr.hep_ipheader.hp_dst = to_su->sin.sin_addr;

			hep_msg->u.hepv12.hdr.hp_sport = from_su->sin.sin_port; /* src port */
			hep_msg->u.hepv12.hdr.hp_dport = to_su->sin.sin_port; /* dst port */

			break;
		case AF_INET6:
			/* Source && Destination ipv6addresses*/
			hep_msg->u.hepv12.addr.hep_ip6header.hp6_src = from_su->sin6.sin6_addr;
			hep_msg->u.hepv12.addr.hep_ip6header.hp6_dst = to_su->sin6.sin6_addr;

			hep_msg->u.hepv12.hdr.hp_sport = from_su->sin6.sin6_port; /* src port */
			hep_msg->u.hepv12.hdr.hp_dport = to_su->sin6.sin6_port; /* dst port */
			break;
     }

	if ( payload ) {
		hep_msg->u.hepv12.payload = *payload;
	} else {
		memset( &hep_msg->u.hepv12.payload, 0, sizeof(str) );
	}

	return hep_msg;
}


static trace_message create_hep3_message(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int net_proto, str* payload, int proto)
{
	int rc;
	int iplen=0, tlen;

	struct timeval tvb;

	unsigned long compress_len;

	str compressed_payload={NULL, 0};

	struct hep_desc* hep_msg;

	hep_msg = pkg_malloc(sizeof(struct hep_desc));
	if (hep_msg == NULL) {
		LM_ERR("no more pkg mem!\n");
		return NULL;
	}

	memset(hep_msg, 0, sizeof(struct hep_desc));
	hep_msg->version = 3;

	gettimeofday(&tvb, NULL);

	/* header set */
	memcpy(hep_msg->u.hepv3.hg.header.id, HEP_HEADER_ID, HEP_HEADER_ID_LEN);

	/* IP proto */
	hep_msg->u.hepv3.hg.ip_family.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.ip_family.chunk.type_id   = htons(0x0001);
	hep_msg->u.hepv3.hg.ip_family.data = from_su->s.sa_family;
	hep_msg->u.hepv3.hg.ip_family.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.ip_family));

	/* Proto ID */
	hep_msg->u.hepv3.hg.ip_proto.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.ip_proto.chunk.type_id   = htons(0x0002);
	hep_msg->u.hepv3.hg.ip_proto.data = net_proto;
	hep_msg->u.hepv3.hg.ip_proto.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.ip_proto));


	/* IPv4 */
	if(from_su->s.sa_family == AF_INET) {
		/* SRC IP */
		hep_msg->u.hepv3.addr.ip4_addr.src_ip4.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.addr.ip4_addr.src_ip4.chunk.type_id   = htons(0x0003);
		hep_msg->u.hepv3.addr.ip4_addr.src_ip4.data = from_su->sin.sin_addr;
		hep_msg->u.hepv3.addr.ip4_addr.src_ip4.chunk.length = htons(sizeof(hep_msg->u.hepv3.addr.ip4_addr.src_ip4));

		/* DST IP */
		hep_msg->u.hepv3.addr.ip4_addr.dst_ip4.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.addr.ip4_addr.dst_ip4.chunk.type_id   = htons(0x0004);
		hep_msg->u.hepv3.addr.ip4_addr.dst_ip4.data = to_su->sin.sin_addr;
		hep_msg->u.hepv3.addr.ip4_addr.dst_ip4.chunk.length = htons(sizeof(hep_msg->u.hepv3.addr.ip4_addr.dst_ip4));

		iplen = sizeof(hep_msg->u.hepv3.addr.ip4_addr.dst_ip4) + sizeof(hep_msg->u.hepv3.addr.ip4_addr.src_ip4);

		/* SRC PORT */
		hep_msg->u.hepv3.hg.src_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.hg.src_port.chunk.type_id   = htons(0x0007);
		hep_msg->u.hepv3.hg.src_port.data = from_su->sin.sin_port;
		hep_msg->u.hepv3.hg.src_port.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.src_port));

		/* DST PORT */
		hep_msg->u.hepv3.hg.dst_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.hg.dst_port.chunk.type_id   = htons(0x0008);
		hep_msg->u.hepv3.hg.dst_port.data = to_su->sin.sin_port;
		hep_msg->u.hepv3.hg.dst_port.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.dst_port));
	}
	/* IPv6 */
	else if(from_su->s.sa_family == AF_INET6) {
		/* SRC IPv6 */
		hep_msg->u.hepv3.addr.ip6_addr.src_ip6.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.addr.ip6_addr.src_ip6.chunk.type_id   = htons(0x0005);
		hep_msg->u.hepv3.addr.ip6_addr.src_ip6.data = from_su->sin6.sin6_addr;
		hep_msg->u.hepv3.addr.ip6_addr.src_ip6.chunk.length = htons(sizeof(hep_msg->u.hepv3.addr.ip6_addr.src_ip6));

		/* DST IPv6 */
		hep_msg->u.hepv3.addr.ip6_addr.dst_ip6.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.addr.ip6_addr.dst_ip6.chunk.type_id   = htons(0x0006);
		hep_msg->u.hepv3.addr.ip6_addr.dst_ip6.data = to_su->sin6.sin6_addr;
		hep_msg->u.hepv3.addr.ip6_addr.dst_ip6.chunk.length = htons(sizeof(hep_msg->u.hepv3.addr.ip6_addr.dst_ip6));

		iplen = sizeof(hep_msg->u.hepv3.addr.ip6_addr.dst_ip6) + sizeof(hep_msg->u.hepv3.addr.ip6_addr.src_ip6);

		/* SRC PORT */
		hep_msg->u.hepv3.hg.src_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.hg.src_port.chunk.type_id   = htons(0x0007);
		hep_msg->u.hepv3.hg.src_port.data = from_su->sin6.sin6_port;
		hep_msg->u.hepv3.hg.src_port.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.src_port));

		/* DST PORT */
		hep_msg->u.hepv3.hg.dst_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.hg.dst_port.chunk.type_id   = htons(0x0008);
		hep_msg->u.hepv3.hg.dst_port.data = to_su->sin6.sin6_port;
		hep_msg->u.hepv3.hg.dst_port.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.dst_port));
	}

	/* TIMESTAMP SEC */
	hep_msg->u.hepv3.hg.time_sec.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.time_sec.chunk.type_id   = htons(0x0009);
	hep_msg->u.hepv3.hg.time_sec.data = htonl(tvb.tv_sec);
	hep_msg->u.hepv3.hg.time_sec.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.time_sec));


	/* TIMESTAMP USEC */
	hep_msg->u.hepv3.hg.time_usec.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.time_usec.chunk.type_id   = htons(0x000a);
	hep_msg->u.hepv3.hg.time_usec.data = htonl(tvb.tv_usec);
	hep_msg->u.hepv3.hg.time_usec.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.time_usec));

	/* Protocol TYPE */
	hep_msg->u.hepv3.hg.proto_t.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.proto_t.chunk.type_id   = htons(0x000b);
	hep_msg->u.hepv3.hg.proto_t.data = proto;
	hep_msg->u.hepv3.hg.proto_t.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.proto_t));

	/* Capture ID */
	hep_msg->u.hepv3.hg.capt_id.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.hg.capt_id.chunk.type_id   = htons(0x000c);
	/* */
	hep_msg->u.hepv3.hg.capt_id.data = htonl(hep_capture_id);
	hep_msg->u.hepv3.hg.capt_id.chunk.length = htons(sizeof(hep_msg->u.hepv3.hg.capt_id));

	hep_msg->u.hepv3.payload_chunk.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hep_msg->u.hepv3.payload_chunk.chunk.type_id   = payload_compression ? htons(0x0010) : htons(0x000f);

	if ( payload ) {
		/* The payload length shall be transformed to network order later; now we'll still need the length of
		 * the payload before sending */
		if (!payload_compression) {
			hep_msg->u.hepv3.payload_chunk.data = payload->s;
			hep_msg->u.hepv3.payload_chunk.chunk.length = payload->len + sizeof(hep_chunk_t);
		} else {
		/* compress the payload if requested */
			rc=compression_api.compress((unsigned char*)payload->s, (unsigned long)payload->len,
					&compressed_payload, &compress_len, compression_api.level);
			if (compression_api.check_rc(rc)==0) {
				payload->len = (int)compress_len;
				/* we don't need the payload pointer in this function */
				hep_msg->u.hepv3.payload_chunk.data = compressed_payload.s;
				hep_msg->u.hepv3.payload_chunk.chunk.length = compress_len + sizeof(hep_chunk_t);
			} else {
				LM_WARN("payload compression failed! will send the buffer uncompressed\n");
				hep_msg->u.hepv3.payload_chunk.chunk.type_id = htons(0x000f);
				hep_msg->u.hepv3.payload_chunk.data = payload->s;
				hep_msg->u.hepv3.payload_chunk.chunk.length = payload->len + sizeof(hep_chunk_t);
			}
		}
	} else {
		memset( &hep_msg->u.hepv3.payload_chunk, 0, sizeof( hep_msg->u.hepv3.payload_chunk ) );
	}

	tlen = sizeof(struct hep_generic) + iplen +
					(payload ? (sizeof(hep_chunk_t) + payload->len) : 0);

	/* FIXME WARNING this is not htons */
	hep_msg->u.hepv3.hg.header.length = tlen;

	return hep_msg;
}


static int add_generic_chunk(struct hep_desc* hep_msg, void* data, int len, int data_id)
{
	#define CHECK_LEN(__len, __cmp, __field)              \
		if (__len != __cmp) {                             \
			LM_ERR(__field" size should be %zd!\n", __cmp); \
			return -1;                                    \
		}

	switch (data_id) {
		case HEP_PROTO_FAMILY:
			CHECK_LEN(len, sizeof(u_int8_t), "Proto family");
			hep_msg->u.hepv3.hg.ip_family.data = *(u_int8_t *)data;

			break;
		case HEP_PROTO_ID:
			CHECK_LEN(len, sizeof(u_int8_t), "Proto id");
			hep_msg->u.hepv3.hg.ip_proto.data = *(u_int8_t *)data;

			break;
		case HEP_IPV4_SRC:
			CHECK_LEN(len, sizeof(struct in_addr), "Source ip");
			hep_msg->u.hepv3.addr.ip4_addr.src_ip4.data = *(struct in_addr *)data;

			break;
		case HEP_IPV4_DST:
			CHECK_LEN(len, sizeof(struct in_addr), "Destination ip");
			hep_msg->u.hepv3.addr.ip4_addr.dst_ip4.data = *(struct in_addr *)data;

			break;
		case HEP_IPV6_SRC:
			CHECK_LEN(len, sizeof(struct in6_addr), "Source ipv6");
			hep_msg->u.hepv3.addr.ip6_addr.src_ip6.data = *(struct in6_addr *)data;

			break;
		case HEP_IPV6_DST:
			CHECK_LEN(len, sizeof(struct in6_addr), "Destination ipv6");
			hep_msg->u.hepv3.addr.ip6_addr.dst_ip6.data = *(struct in6_addr *)data;

			break;
		case HEP_SRC_PORT:
			CHECK_LEN(len, sizeof(u_int16_t), "Source port");
			hep_msg->u.hepv3.hg.src_port.data = htons(*(u_int16_t *)data);

			break;
		case HEP_DST_PORT:
			CHECK_LEN(len, sizeof(u_int16_t), "Destination port");
			hep_msg->u.hepv3.hg.dst_port.data = htons(*(u_int16_t *)data);

			break;
		case HEP_TIMESTAMP:
			CHECK_LEN(len, sizeof(u_int32_t), "Timestamp");
			hep_msg->u.hepv3.hg.time_sec.data = htonl(*(u_int32_t *)data);

			break;
		case HEP_TIMESTAMP_US:
			CHECK_LEN(len, sizeof(u_int32_t), "Timestamp microseconds");
			hep_msg->u.hepv3.hg.time_usec.data = htonl(*(u_int32_t *)data);

			break;
		case HEP_PROTO_TYPE:
			CHECK_LEN(len, sizeof(u_int8_t), "Protocol type");
			hep_msg->u.hepv3.hg.proto_t.data = *(u_int8_t *)data;

			break;
		case HEP_AGENT_ID:
			CHECK_LEN(len, sizeof(u_int8_t), "Capture agent id");
			hep_msg->u.hepv3.hg.capt_id.data = htonl(*(u_int32_t*)data);

			break;
		case HEP_PAYLOAD:
		case HEP_COMPRESSED_PAYLOAD:/* do compression here?? */

		default:
			break;
	}

	return 0;
}



static char* build_hep12_buf(struct hep_desc* hep_msg, int* len)
{
	int buflen, p;
	char* buf;

	buflen = hep_msg->u.hepv12.hdr.hp_l + hep_msg->u.hepv12.payload.len;

	if (hep_msg->u.hepv12.hdr.hp_f == AF_INET) {
		buflen += sizeof(struct hep_iphdr);
	} else {
		buflen += sizeof(struct hep_ip6hdr);
	}

	if (hep_msg->version == 2) {
		buflen += sizeof(struct hep_timehdr);
	}

	buf = pkg_malloc(buflen);
	if (buf == NULL) {
		LM_ERR("no more pkg mem!\n");
		return NULL;
	}

	memset(buf, 0, buflen);

	memcpy(buf, &hep_msg->u.hepv12.hdr, sizeof(struct hep_hdr));
	p = sizeof(struct hep_hdr);

	if (hep_msg->u.hepv12.hdr.hp_f == AF_INET) {
		memcpy(buf+p, &hep_msg->u.hepv12.addr.hep_ipheader, sizeof(struct hep_iphdr));
		p += sizeof(struct hep_iphdr);
	} else {
		memcpy(buf+p, &hep_msg->u.hepv12.addr.hep_ip6header, sizeof(struct hep_ip6hdr));
		p += sizeof(struct hep_ip6hdr);
	}

	if (hep_msg->version == 2) {
		memcpy(buf+p, &hep_msg->u.hepv12.hep_time, sizeof(struct hep_timehdr));
		p += sizeof(struct hep_timehdr);
	}

	if ( hep_msg->u.hepv12.payload.s && hep_msg->u.hepv12.payload.len ) {
		memcpy(buf+p, hep_msg->u.hepv12.payload.s,
				hep_msg->u.hepv12.payload.len);
	}

	*len = buflen;

	return buf;

}

static inline char* JSON_toString(void* root)
{
	return cJSON_Print(root);
}

static inline void JSON_free(void* root)
{
	cJSON_Delete(root);
}

static char* build_hep3_buf(struct hep_desc* hep_msg, int* len)
{
	#define UPDATE_CHECK_REMAINING(__rem, __len, __curr) \
		do { \
			if (__rem < __curr) { \
				LM_BUG("bad packet length inside hep structure!\n"); \
				return NULL; \
			} \
			__rem -= __curr; \
			__len += __curr; \
		} while (0);


	int rem, hdr_len, pld_len, corr_len=0;
	char* buf;
	str* h5_buf;

	generic_chunk_t *it, *corr_chunk, correlation;

	*len = 0;

	rem = hep_msg->u.hepv3.hg.header.length;

	if ( hep_msg->fPayload ) {
		/* FIXME no payload compression */
		hep_msg->u.hepv3.payload_chunk.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hep_msg->u.hepv3.payload_chunk.chunk.type_id   = htons(0x000f);
		if ( !homer5_on ) {
			rem -= hep_msg->u.hepv3.payload_chunk.chunk.length;

			hep_msg->u.hepv3.payload_chunk.data = JSON_toString(hep_msg->fPayload);

			hep_msg->u.hepv3.payload_chunk.chunk.length =
				strlen(hep_msg->u.hepv3.payload_chunk.data) + sizeof(hep_chunk_t);

			rem += hep_msg->u.hepv3.payload_chunk.chunk.length;
		} else {
			rem -= hep_msg->u.hepv3.payload_chunk.chunk.length;

			h5_buf = hep_msg->fPayload;
			hep_msg->u.hepv3.payload_chunk.data = h5_buf->s;
			hep_msg->u.hepv3.payload_chunk.chunk.length =
									h5_buf->len + sizeof(hep_chunk_t);

			rem += hep_msg->u.hepv3.payload_chunk.chunk.length;
		}
	}

	if ( hep_msg->correlation ) {
		if ( !homer5_on ) {
			memset( &correlation, 0, sizeof(generic_chunk_t));
			correlation.chunk.vendor_id = htons(0);
			/* hardcoded but this is the header */
			correlation.chunk.type_id = htons(HEP_EXTRA_CORRELATION);
			correlation.chunk.length = sizeof(hep_chunk_t);

			correlation.data = JSON_toString(hep_msg->correlation);
			corr_len += strlen(correlation.data);

			correlation.chunk.length += corr_len;
			rem += correlation.chunk.length;

			correlation.chunk.length = htons(correlation.chunk.length);
		} else {
			/* search to see whether we already got a correlation header */
			for ( it=hep_msg->u.hepv3.chunk_list; it; it=it->next ) {
				if ( it->chunk.type_id == 0x11 ) {
					break;
				}
			}

			h5_buf = hep_msg->correlation;
			if ( it ) {
				corr_chunk = it;
				rem -= it->chunk.length;
			} else {
				corr_chunk = pkg_malloc( sizeof(hep_chunk_t) );
				if ( !corr_chunk ) {
					LM_ERR("no more pkg memory!\n");
					return 0;
				}

				memset( corr_chunk, 0, sizeof(hep_chunk_t) );
				corr_chunk->chunk.type_id = 0x11;
			}

			corr_chunk->chunk.length = sizeof(hep_chunk_t) + h5_buf->len;
			corr_chunk->data = h5_buf->s;


			/* if chunk not exists add it to custom chunk list */
			if ( !it ) {
				corr_chunk->next = hep_msg->u.hepv3.chunk_list;
				hep_msg->u.hepv3.chunk_list = corr_chunk;
			}

			rem += corr_chunk->chunk.length;
		}
	}


	buf = pkg_malloc(rem);

	hep_msg->u.hepv3.hg.header.length = htons(rem);

	if (buf == NULL) {
		LM_ERR("no more pkg mem!\n");
		return NULL;
	}

	memcpy(buf, &hep_msg->u.hepv3.hg, sizeof(hep_generic_t));
	UPDATE_CHECK_REMAINING(rem, *len, sizeof(hep_generic_t));

	if (hep_msg->u.hepv3.hg.ip_family.data == AF_INET) {
		memcpy(buf+*len, &hep_msg->u.hepv3.addr.ip4_addr, sizeof(struct ip4_addr));
		UPDATE_CHECK_REMAINING(rem, *len, sizeof(struct ip4_addr));
	}
	/* IPv6 */
	else if(hep_msg->u.hepv3.hg.ip_family.data == AF_INET6) {
		memcpy(buf+*len, &hep_msg->u.hepv3.addr.ip6_addr, sizeof(struct ip6_addr));
		UPDATE_CHECK_REMAINING(rem, *len, sizeof(struct ip6_addr));
	} else {
		LM_ERR("unknown IP family\n");
		return NULL;
	}

	if ( hep_msg->u.hepv3.payload_chunk.data
				&& hep_msg->u.hepv3.payload_chunk.chunk.length ) {
		pld_len = hep_msg->u.hepv3.payload_chunk.chunk.length - sizeof(hep_chunk_t);
		/* earlier we didn't do htons on this buffer because we needed the
		 * length; we'll do it now */
		hep_msg->u.hepv3.payload_chunk.chunk.length =
					htons(hep_msg->u.hepv3.payload_chunk.chunk.length);

		memcpy(buf+*len, &hep_msg->u.hepv3.payload_chunk, sizeof(hep_chunk_t));
		UPDATE_CHECK_REMAINING(rem, *len, sizeof(hep_chunk_t));

		memcpy(buf+*len, hep_msg->u.hepv3.payload_chunk.data, pld_len);
		UPDATE_CHECK_REMAINING(rem, *len, pld_len);
	}

	/* copy the correlation if exists */
	if ( hep_msg->correlation ) {
		/* if on it will be with the rest of the chunks */
		if ( !homer5_on ) {
			memcpy( buf + *len, &correlation.chunk, sizeof(hep_chunk_t));
			UPDATE_CHECK_REMAINING(rem, *len, sizeof(hep_chunk_t));

			/* can't get the correlation length from header since it's in htons form */
			memcpy(buf + *len, correlation.data, corr_len);
			UPDATE_CHECK_REMAINING(rem, *len, corr_len);

			/* just dumped the string - no need to keep it further on */
			cJSON_PurgeString((char *)correlation.data);
		}
	}

	for (it=hep_msg->u.hepv3.chunk_list; it; it=it->next) {
		hdr_len = it->chunk.length;

		it->chunk.vendor_id = htons(it->chunk.vendor_id);
		it->chunk.length = htons(it->chunk.length);
		it->chunk.type_id = htons(it->chunk.type_id);

		memcpy(buf+*len, &it->chunk, sizeof(hep_chunk_t));
		UPDATE_CHECK_REMAINING(rem, *len, sizeof(hep_chunk_t));

		memcpy(buf+*len, it->data, hdr_len - sizeof(hep_chunk_t));
		UPDATE_CHECK_REMAINING(rem, *len, hdr_len - sizeof(hep_chunk_t));
	}

	if (rem) {
		LM_ERR("%d bytes not copied!\n", rem);
		return NULL;
	}


	return buf;

#undef UPDATE_CHECK_REMAINING
}

/*
 *
 * **********************************
 * *** TRACING API IMPLEMENTATION ***
 * *** -------------------------- ***
 * **********************************
 *
 */

/*
 * create message function
 * */
trace_message create_hep_message(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int net_proto, str* payload, int pld_proto, trace_dest dest)
{
	hid_list_p hep_dest = (hid_list_p) dest;

	if ( !from_su ) {
		local_su.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		from_su = &local_su;
	}

	if ( !to_su ) {
		local_su.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK2;
		to_su = &local_su;
	}

	switch (hep_dest->version) {
		case 1:
		case 2:
			return create_hep12_message(from_su, to_su, net_proto, payload, hep_dest->version);
		case 3:
			return create_hep3_message(from_su, to_su, net_proto, payload, pld_proto);
	}

	LM_ERR("invalid hep protocol version [%d]!", hep_dest->version);
	return NULL;
}


int add_hep_chunk(trace_message message, void* data, int len, int type, int data_id, int vendor)
{
	struct hep_desc* hep_msg;
	generic_chunk_t *hep_chunk=NULL, *it;

	if (message == NULL || data == NULL || len == 0 || data_id == 0) {
		LM_ERR("invalid call! bad input params!\n");
		return -1;
	}

	hep_msg = (struct hep_desc*) message;

	if (hep_msg->version < 3) {
		LM_DBG("Won't add data to HEP proto lower than 3!\n");
		return 0;
	}

	 /* only version 3 here */
	if ( vendor == 0 /* generic chunk */ &&  CHUNK_IS_IN_HEPSTRUCT(data_id)) {
		/* handle generic chunk from hepstruct here  */
		return add_generic_chunk(hep_msg, data, len, data_id);
	}

	/* first check if the chunk is already added and we only need to modify it */
	for (it=hep_msg->u.hepv3.chunk_list; it; it=it->next) {
		if (it->chunk.type_id == data_id && it->chunk.vendor_id == vendor) {
			LM_DBG("Chunk with (id=%d; vendor=%d) already there! Modifying content!\n", data_id, vendor);
			hep_chunk = it;
			break;
		}
	}

	/* change data to network order if needed; won't know the data type later */
	if (type == TRACE_TYPE_UINT16) {
		short* sdata = data;
		*sdata = htons(*sdata);
	} else if (type == TRACE_TYPE_UINT32) {
		int* idata = data;
		*idata = htonl(*idata);
	}

	if (hep_chunk == NULL) {
		LM_DBG("Chunk with (id=%d; vendor=%d) not found! Creating!\n", data_id, vendor);
		hep_chunk = pkg_malloc(sizeof(generic_chunk_t) + len);
		if (!hep_chunk) {
			LM_ERR("cannot allocate hep_chunk in pkg mem!\n");
			return -1;
		}
		memset(hep_chunk, 0, sizeof(generic_chunk_t));

		hep_chunk->data = (void *)(hep_chunk+1);
		/* we don't switch to network byte order here since we might need to check again */
		hep_chunk->chunk.vendor_id = vendor;
		hep_chunk->chunk.type_id = data_id;
	} else {
		/* only check if we need to allocate more memory for this chunk */
		if ((hep_chunk->chunk.length - sizeof(hep_chunk_t)) < len) {
			hep_chunk = pkg_realloc(hep_chunk, sizeof(generic_chunk_t) + len);
			if (!hep_chunk) {
				LM_ERR("cannot re-alloc hep_chunk in pkg mem!\n");
				return -1;
			}
			hep_chunk->data = (void *)(hep_chunk + 1);
		}
	}

	hep_chunk->chunk.length = sizeof(hep_chunk_t) + len;
	hep_msg->u.hepv3.hg.header.length += sizeof(hep_chunk_t) + len;

	memcpy(hep_chunk->data, data, len);

	LM_DBG("Hep chunk with (id=%d; vendor=%d) successfully built!\n", data_id, vendor);

	if (hep_msg->u.hepv3.chunk_list) {
		hep_chunk->next = hep_msg->u.hepv3.chunk_list;
	}

	hep_msg->u.hepv3.chunk_list = hep_chunk;

	return 0;
}

int add_hep_correlation(trace_message message, str* corr_name, str* corr_value)
{
	cJSON* root;
	struct hep_desc* hep_msg;
	str* sip_correlation;

	if ( !message || !corr_name || !corr_value || !corr_value->s || !corr_value->len ) {
		LM_ERR("invalid call! bad input params!\n");
		return -1;
	}

	hep_msg = (struct hep_desc*) message;

	if (hep_msg->version < 3) {
		LM_DBG("Won't add data to HEP proto lower than 3!\n");
		return 0;
	}

	if ( !homer5_on ) {
		if ( hep_msg->correlation) {
			root = (cJSON *) hep_msg->correlation;
		} else {
			root = cJSON_CreateObject();
			if ( !root ) {
				LM_ERR("failed to create correlation object!\n");
				return -1;
			}

			hep_msg->correlation = root;
		}

		_cJSON_AddStrToObject( root, corr_name, corr_value->s, corr_value->len);
	} else {
		if ( !memcmp( corr_name->s, "sip", sizeof("sip") - 1 ) ) {
			/* we'll save sip correlation id as the actual correlation */
			sip_correlation = pkg_malloc( sizeof(str) + corr_value->len );
			if ( !sip_correlation ) {
				LM_ERR("no more pkg mem!\n");
				return -1;
			}

			sip_correlation->s = (char *)( sip_correlation + 1 );
			sip_correlation->len = corr_value->len;

			memcpy( sip_correlation->s, corr_value->s, corr_value->len);
			hep_msg->correlation = sip_correlation;
		}
	}

	return 0;
}

int add_hep_payload(trace_message message, char* pld_name, str* pld_value)
{
	cJSON* root;
	struct hep_desc* hep_msg;

	str* homer5_buf;

	if ( !message || !pld_name || !pld_value || !pld_value->s || !pld_value->len ) {
		LM_ERR("invalid call! bad input params!\n");
		return -1;
	}

	hep_msg = (struct hep_desc*) message;

	if (hep_msg->version < 3) {
		LM_DBG("Won't add data to HEP proto lower than 3!\n");
		return 0;
	}

	if ( !homer5_on ) {
		if ( hep_msg->fPayload ) {
			root = (cJSON *) hep_msg->fPayload;
		} else {
			root = cJSON_CreateObject();
			if ( !root ) {
				LM_ERR("failed to create correlation object!\n");
				return -1;
			}
			hep_msg->fPayload = root;
		}

		cJSON_AddStrToObject( root, pld_name, pld_value->s, pld_value->len);
	} else {
		if ( hep_msg->fPayload ) {
			homer5_buf = hep_msg->fPayload;

			homer5_buf->s = pkg_realloc( homer5_buf->s,
					homer5_buf->len + homer5_delim.len + pld_value->len);
		} else {
			homer5_buf = pkg_malloc( sizeof(str) );
			if ( !homer5_buf ) {
				LM_ERR("no more pkg mem!\n");
				return -1;
			}

			homer5_buf->len = 0;
			homer5_buf->s = pkg_malloc(pld_value->len);

		}

		if ( !homer5_buf->s ) {
			LM_ERR("no more pkg mem!\n");
			if (hep_msg->fPayload==NULL)
				pkg_free(homer5_buf);
			return -1;
		}

		if ( hep_msg->fPayload ) {
			memcpy( homer5_buf->s + homer5_buf->len, homer5_delim.s, homer5_delim.len );
			homer5_buf->len += homer5_delim.len;

			memcpy( homer5_buf->s + homer5_buf->len, pld_value->s, pld_value->len);
			homer5_buf->len += pld_value->len;
		} else {
			memcpy( homer5_buf->s, pld_value->s, pld_value->len);
			homer5_buf->len = pld_value->len;

			hep_msg->fPayload = homer5_buf;
		}
	}

	return 0;
}


int send_hep_message(trace_message message, trace_dest dest, struct socket_info* send_sock)
{
	int len, ret=-1;
	char* buf=0;

	struct proxy_l* p;
	union sockaddr_union* to;

	hid_list_p hep_dest = (hid_list_p) dest;

	if (message == NULL || dest == NULL) {
		LM_ERR("invalid call! bad input params!\n");
		goto end;
	}


	if (((struct hep_desc *)message)->version == 3) {
		/* hep msg will be freed after */
		if ((buf=build_hep3_buf((struct hep_desc *)message, &len))==NULL) {
			LM_ERR("failed to build hep buffer!\n");
			goto end;
		}
	} else {
		if ((buf=build_hep12_buf((struct hep_desc *)message, &len))==NULL) {
			LM_ERR("failed to build hep buffer!\n");
			goto end;
		}
	}

	/* */
	p=mk_proxy( &hep_dest->ip, hep_dest->port_no ? hep_dest->port_no : HEP_PORT, hep_dest->transport, 0);
	if (p == NULL) {
		pkg_free(buf);
		LM_ERR("bad hep host name!\n");
		goto end;
	}

	to=(union sockaddr_union *)pkg_malloc(sizeof(union sockaddr_union));
	if (to == 0) {
		LM_ERR("no more pkg mem!\n");
		pkg_free(buf);
		free_proxy(p);
		pkg_free(p);
		goto end;
	}

	hostent2su(to, &p->host, p->addr_idx, p->port?p->port:HEP_PORT);

	do {
		if (msg_send(send_sock, hep_dest->transport, to, 0, buf, len, NULL) < 0) {
			LM_ERR("Cannot send hep message!\n");
			continue;
		}
		ret=0;
		break;
	} while ( get_next_su( p, to, 0)==0);

	free_proxy(p);
	pkg_free(p);
	pkg_free(to);
	pkg_free(buf);

end:
	return ret;
}

void free_hep_message(trace_message message)
{
	generic_chunk_t *foo=NULL, *it;
	struct hep_desc* hep_msg = message;

	if (hep_msg==NULL)
		return;

	if (hep_msg->version == 3) {
		/* free custom chunks */
		it = hep_msg->u.hepv3.chunk_list;
		while( it ) {
			foo = it;
			it = it->next;
			pkg_free(foo);
		}

		/* free JSON payload if there */
		if ( hep_msg->fPayload ) {
			if ( !homer5_on ) {
				cJSON_PurgeString( hep_msg->u.hepv3.payload_chunk.data );
				JSON_free( hep_msg->fPayload );
			} else {
				if ( ((str *)hep_msg->fPayload)->s )
					pkg_free( ((str *)hep_msg->fPayload)->s );
				pkg_free( hep_msg->fPayload );
			}
		}

		/* free JSON correlation if there */
		if ( hep_msg->correlation ) {
			if ( !homer5_on ) {
				JSON_free( hep_msg->correlation );
			} else {
				pkg_free( hep_msg->correlation );
			}
		}
	}

	pkg_free(hep_msg);
}

trace_dest get_trace_dest_by_name(str *name)
{
	/* don't ref, user should take care of this */
	return get_hep_id_by_name(name, 1, 0);
}

trace_dest new_trace_dest(str *name, str *uri)
{
	hid_list_p it, el = NULL;

	lock_get(hid_dyn_lock);
	if (!hid_dyn_list) {
		LM_CRIT("Dynamic hid list not initialized!\n");
		goto end;
	}
	/* no need to lock now, since this is done at startup */
	if (get_hep_id_by_name(name, 0, 0)) {
		LM_WARN("HEP ID <%.*s> already in use!\n",
				name->len, name->s);
		goto end;
	}

	el = new_hep_id(name, uri);
	if (!el)
		goto end;
	el->dynamic = 1;

	/* add the new element to the hep id list */
	if (*hid_dyn_list == NULL) {
		*hid_dyn_list = el;
	} else {
		for (it=*hid_dyn_list; it->next; it=it->next);
		it->next = el;
	}
	/* ref it for the list */
	hid_ref(el);

	LM_DBG("Added hep id <%.*s> to list!\n", el->name.len, el->name.s);
end:
	lock_release(hid_dyn_lock);
	return el;
}

void release_trace_dest(trace_dest dest)
{
	hid_list_p it, prev;

	if (!hid_dyn_list)
		return;

	lock_get(hid_dyn_lock);

	for (it=*hid_dyn_list, prev = NULL; it; prev=it, it=it->next)
		if (it == dest) {
			if (prev)
				prev->next = it->next;
			else
				*hid_dyn_list = (*hid_dyn_list)->next;
			LM_DBG("releasing dynamic hid [%.*s]!\n",
					it->name.len, it->name.s);
			/* unref it from the list */
			hid_unref(it);
			lock_release(hid_dyn_lock);
			return;
		}
	lock_release(hid_dyn_lock);

	it = (hid_list_p)dest;
	LM_WARN("could not find dynamic hid [%.*s]!!\n",
			it->name.len, it->name.s);
}

/**
 * to add new ids see hep_ids structure defined below
 *
 */
int get_hep_message_id(char* proto)
{
	int idx;

	for ( idx=0; hep_ids[idx].proto != NULL; idx++ )
		if (strcmp(proto, hep_ids[idx].proto) == 0)
			return hep_ids[idx].id;

	LM_ERR("can't find proto <%s>\n", proto);
	return -1;
}

/**
 * to add new chunks see hep_chunks structure defined below
 *
 */
int get_hep_chunk_id(const char* name, int* vendor, int* id)
{
	int i;

	if (name == NULL || vendor == NULL || id == NULL) {
		LM_ERR("bad call!\n");
		return 0;
	}

	for ( i=0; hep_chunks[i].chunk_name.s != NULL; i++) {
		if (!memcmp(name, hep_chunks[i].chunk_name.s, hep_chunks[i].chunk_name.len)) {
			*vendor = hep_chunks[i].vendor;
			*id = hep_chunks[i].chunk_id;

			return 1;
		}
	}

	return 0;
}

unsigned char* generate_hep_guid(char* cookie)
{
#define COOKIE_MAX 16
#define GUID_MAX 20
#define B64_MAX 44

	int cookie_len = 0, rand_val;
	static unsigned char buf[GUID_MAX];
	static unsigned char b64_buf[B64_MAX + 1];

	utime_t uticks;

	memset( b64_buf, 0, B64_MAX + 1);
	if ( cookie ) {
		cookie_len = strlen(cookie);
		if ( cookie_len > COOKIE_MAX ) {
			LM_ERR("cookie too big %s\n", cookie);
			return 0;
		}

		memcpy( b64_buf, cookie, cookie_len );
	}

	/* 4 bytes with pid */
	memcpy( buf, &pt[process_no].pid, 4);

	/* 4 bytes with startup time */
	memcpy( buf + 4, &startup_time, 4);

	/* 8 bytes with ujiffies */
	uticks = get_uticks();
	memcpy( buf + 8, &uticks, 8);

	/* 4 bytes rand() */
	rand_val = rand();
	memcpy( buf + 16, &rand_val, 4);

	base64encode( b64_buf + cookie_len, buf, 20);

	return b64_buf;

#undef COOKIE_MAX
#undef GUID_MAX
#undef B64_MAX
}

int hep_bind_trace_api(trace_proto_t* prot)
{
	if (!prot)
		return -1;

	memset(prot, 0, sizeof(trace_proto_t));

	prot->create_trace_message = create_hep_message;
	prot->add_chunk = add_hep_chunk;
	prot->add_extra_correlation = add_hep_correlation;
	prot->add_payload_part = add_hep_payload;
	prot->send_message = send_hep_message;
	prot->get_trace_dest_by_name = get_trace_dest_by_name;
	prot->new_trace_dest = new_trace_dest;
	prot->release_trace_dest = release_trace_dest;
	prot->free_message = free_hep_message;
	prot->get_message_id = get_hep_message_id;
	prot->get_data_id = get_hep_chunk_id;
	prot->generate_guid = generate_hep_guid;

	return 0;
}

/***************************************************************
 ********************* HEP CORRELATE script function ***********
 ***************************************************************/
int correlate_w(struct sip_msg* msg, str* hep_id,
		str* type1, str* corr_s1,
		str* type2, str* corr_s2)
{
	int ret = -1;
	hid_list_p h;
	trace_message message;

	if ( !msg ) {
		LM_ERR("null sip msg!\n");
		return -1;
	}

	h = get_hep_id_by_name(hep_id, 1, 1);
	if ( h == NULL ) {
		LM_ERR("no hep id with name <%.*s>\n", hep_id->len, hep_id->s );
		return -1;
	}

	if ( h->version < 3 ) {
		LM_ERR("only version 3 or higher of HEP supports correlation!\n");
		goto end;
	}

	if ( control_id < 0 ) {
		control_id = get_hep_message_id( "control" );
	}

	message = create_hep_message( 0, 0, IPPROTO_TCP, 0, control_id, h );
	if ( !message ) {
		LM_ERR("failed to create hep message!\n");
		goto end;
	}

	if ( str_strcmp( type1, type2 ) ) {
		LM_ERR("Type1 <%.*s> must be different from type2!\n",
			type1->len, type1->s);
		return -1;
	}

	add_hep_correlation( message, type1, corr_s1 );
	add_hep_correlation( message, type2, corr_s2 );

	if ( send_hep_message( message, h, 0) < 0 ) {
		LM_ERR(" failed to send hep message to destination!\n");
		goto end;
	}

	free_hep_message( message );
	ret = 1;
end:
	hid_unref(h);
	return ret;
}

/***************************************************************/

int init_hep_id(void)
{
	hid_dyn_lock = lock_alloc();
	if (!hid_dyn_lock) {
		LM_ERR("could not allocate dynamic hid lock!\n");
		return -1;
	}
	if (!lock_init(hid_dyn_lock)) {
		lock_dealloc(hid_dyn_lock);
		LM_ERR("could not allocate dynamic hid lock!\n");
		return -1;
	}
	hid_dyn_list = shm_malloc(sizeof(*hid_dyn_list));
	if (!hid_dyn_list) {
		lock_dealloc(hid_dyn_lock);
		LM_ERR("could not allocate dynamic hid list!\n");
		return -1;
	}
	*hid_dyn_list = 0;
	return 0;
}

void destroy_hep_id(void)
{
	hid_list_p it, next;

	if (!hid_dyn_list)
		return;

	lock_get(hid_dyn_lock);
	for (it=*hid_dyn_list, next=it; it; it=next) {
		next = it->next;
		shm_free(it);
	}
	lock_release(hid_dyn_lock);

	/* release the lock itself */
	lock_dealloc(hid_dyn_lock);
	shm_free(hid_dyn_list);
}
