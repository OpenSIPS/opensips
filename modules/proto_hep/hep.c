/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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

#include "hep.h"
#include "../compression/compression_api.h"

#define GENERIC_VENDOR_ID 0x0000
#define HEP_PROTO_SIP  0x01

/* for safety this should stay static */
static hid_list_p hid_list=NULL;

extern int hep_capture_id;
extern int payload_compression;

extern compression_api_t compression_api;

static int pack_hepv3(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, char **retbuf, int *retlen);
static int pack_hepv12(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, int hep_version,
		char **retbuf, int *retlen);

/*
 *
 * pack as hep; version depends
 * @in1 source sockkadr
 * @in2 dest sockkadr
 * @in3 protocolo
 * @in4 SIP payload
 * @in5 SIP payload length
 * @out1 packed buffer
 * @out2 packed buffer length
 * it's your job to free the buffers
 */
int pack_hep(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, int hep_version, char **retbuf,
		int *retlen)
{

	switch (hep_version) {
		case 1:
		case 2:
			if (pack_hepv12(from_su, to_su, proto, payload,
										plen, hep_version, retbuf, retlen) < 0) {
				LM_ERR("failed to pack using hep protocol version 3\n");
				return -1;
			}
			break;
		case 3:
			if (pack_hepv3(from_su, to_su, proto, payload,
										plen, retbuf, retlen) < 0) {
				LM_ERR("failed to pack using hep protocol version 3\n");
				return -1;
			}
			break;
		default:
			/* version check is being done at startup */
			LM_BUG("invalid hep protocol version [%d]!"
					"Probably memory corruption\n", hep_version);
			return -1;
	}

	return 0;
}

/*
 * pack as hepv3
 * @in1 source sockkadr
 * @in2 dest sockkadr
 * @in3 protocolo
 * @in4 SIP payload
 * @in5 SIP payload length
 * @out1 packed buffer (pkg)
 * @out2 packed buffer length
 */
static int pack_hepv3(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, char **retbuf, int *retlen)
{
	int rc;
	int buflen, iplen=0, tlen;
	char* buffer;

	struct hep_generic hg;
	struct timeval tvb;

	unsigned long compress_len;

	str compressed_payload={NULL, 0};

	hep_chunk_ip4_t src_ip4, dst_ip4;
	hep_chunk_ip6_t src_ip6, dst_ip6;
	hep_chunk_t payload_chunk;

	gettimeofday(&tvb, NULL);

	memset(&hg, 0, sizeof(struct hep_generic));

	/* header set */
	memcpy(hg.header.id, HEP_HEADER_ID, HEP_HEADER_ID_LEN);

	/* IP proto */
	hg.ip_family.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.ip_family.chunk.type_id   = htons(0x0001);
	hg.ip_family.data = from_su->s.sa_family;
	hg.ip_family.chunk.length = htons(sizeof(hg.ip_family));

	/* Proto ID */
	hg.ip_proto.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.ip_proto.chunk.type_id   = htons(0x0002);
	hg.ip_proto.data = proto;
	hg.ip_proto.chunk.length = htons(sizeof(hg.ip_proto));


	/* IPv4 */
	if(from_su->s.sa_family == AF_INET) {
		/* SRC IP */
		src_ip4.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		src_ip4.chunk.type_id   = htons(0x0003);
		src_ip4.data = from_su->sin.sin_addr;
		src_ip4.chunk.length = htons(sizeof(src_ip4));

		/* DST IP */
		dst_ip4.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		dst_ip4.chunk.type_id   = htons(0x0004);
		dst_ip4.data = to_su->sin.sin_addr;
		dst_ip4.chunk.length = htons(sizeof(dst_ip4));

		iplen = sizeof(dst_ip4) + sizeof(src_ip4);

		/* SRC PORT */
		hg.src_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hg.src_port.chunk.type_id   = htons(0x0007);
		hg.src_port.data = htons(from_su->sin.sin_port);
		hg.src_port.chunk.length = htons(sizeof(hg.src_port));

		/* DST PORT */
		hg.dst_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hg.dst_port.chunk.type_id   = htons(0x0008);
		hg.dst_port.data = htons(to_su->sin.sin_port);
		hg.dst_port.chunk.length = htons(sizeof(hg.dst_port));
	}
	/* IPv6 */
	else if(from_su->s.sa_family == AF_INET6) {
		/* SRC IPv6 */
		src_ip6.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		src_ip6.chunk.type_id   = htons(0x0005);
		src_ip6.data = from_su->sin6.sin6_addr;
		src_ip6.chunk.length = htonl(sizeof(src_ip6));

		/* DST IPv6 */
		dst_ip6.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		dst_ip6.chunk.type_id   = htons(0x0006);
		dst_ip6.data = from_su->sin6.sin6_addr;
		dst_ip6.chunk.length = htonl(sizeof(dst_ip6));

		iplen = sizeof(dst_ip6) + sizeof(src_ip6);

		/* SRC PORT */
		hg.src_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hg.src_port.chunk.type_id   = htons(0x0007);
		hg.src_port.data = htons(from_su->sin6.sin6_port);
		hg.src_port.chunk.length = htons(sizeof(hg.src_port));

		/* DST PORT */
		hg.dst_port.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
		hg.dst_port.chunk.type_id   = htons(0x0008);
		hg.dst_port.data = htons(to_su->sin6.sin6_port);
		hg.dst_port.chunk.length = htons(sizeof(hg.dst_port));
	}

	/* TIMESTAMP SEC */
	hg.time_sec.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.time_sec.chunk.type_id   = htons(0x0009);
	hg.time_sec.data = htonl(tvb.tv_sec);
	hg.time_sec.chunk.length = htons(sizeof(hg.time_sec));


	/* TIMESTAMP USEC */
	hg.time_usec.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.time_usec.chunk.type_id   = htons(0x000a);
	hg.time_usec.data = htonl(tvb.tv_usec);
	hg.time_usec.chunk.length = htons(sizeof(hg.time_usec));

	/* Protocol TYPE */
	hg.proto_t.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.proto_t.chunk.type_id   = htons(0x000b);
	hg.proto_t.data = HEP_PROTO_SIP;
	hg.proto_t.chunk.length = htons(sizeof(hg.proto_t));




	/* Capture ID */
	hg.capt_id.chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	hg.capt_id.chunk.type_id   = htons(0x000c);
	/* */
	hg.capt_id.data = htons(hep_capture_id);
	hg.capt_id.chunk.length = htons(sizeof(hg.capt_id));

	payload_chunk.vendor_id = htons(GENERIC_VENDOR_ID);
	payload_chunk.type_id   = payload_compression ? htons(0x0010) : htons(0x000f);


	/* compress the payload if requested */
	if (payload_compression) {
		rc=compression_api.compress((unsigned char*)payload, (unsigned long)plen,
				&compressed_payload, &compress_len, compression_api.level);
		if (compression_api.check_rc(rc)==0) {
			plen = (int)compress_len;
			/* we don't need the payload pointer in this function */
			payload = compressed_payload.s;
		} else {
			LM_ERR("payload compression failed! will send the buffer uncompressed\n");
			payload_chunk.type_id = htons(0x000f);
		}
	}

	payload_chunk.length    = htons(sizeof(hep_chunk_t) + plen);

	tlen = sizeof(struct hep_generic) + iplen + sizeof(hep_chunk_t) + plen;

	/* FIXME no tls support yet */

	/* total */
	hg.header.length = htons(tlen);

	buffer = pkg_malloc(tlen);
	if (buffer == NULL){
		LM_ERR("no more pkg\n");
		return -1;
	}

	memcpy(buffer, &hg, sizeof(struct hep_generic));
	buflen = sizeof(struct hep_generic);

	/* IPv4 */
	if(from_su->s.sa_family == AF_INET) {
		/* SRC IP */
		memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip4));
		buflen += sizeof(struct hep_chunk_ip4);

		memcpy((void*) buffer+buflen, &dst_ip4, sizeof(struct hep_chunk_ip4));
		buflen += sizeof(struct hep_chunk_ip4);
	}
	/* IPv6 */
	else if(from_su->s.sa_family == AF_INET6) {
		/* SRC IPv6 */
		memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip6));
		buflen += sizeof(struct hep_chunk_ip6);

		memcpy((void*) buffer+buflen, &dst_ip6, sizeof(struct hep_chunk_ip6));
		buflen += sizeof(struct hep_chunk_ip6);
	} else {
		LM_ERR("unknown IP family\n");
		return -1;
	}

	/* PAYLOAD CHUNK */

	memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
	buflen +=  sizeof(struct hep_chunk);

	/* Now copying payload self */
	memcpy((void*) buffer+buflen, payload, plen);
	buflen+=plen;

	*retlen = buflen;
	*retbuf  = buffer;

   return 0;

}

/*
 * pack as hepv2
 * @in1 source sockkadr
 * @in2 dest sockkadr
 * @in3 protocol
 * @in4 SIP payload
 * @in5 SIP payload length
 * @out1 packed buffer (pkg)
 * @out2 packed buffer length
 */

static int pack_hepv12(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, int hep_version,
		char **retbuf, int *retlen)
{
	char* buffer;
	unsigned int totlen=0, buflen=0;

	struct hep_hdr hdr;
	struct hep_timehdr hep_time;
	struct hep_iphdr hep_ipheader;
	struct hep_ip6hdr hep_ip6header;

	struct timeval tvb;


	gettimeofday(&tvb, NULL);
	memset(&hdr, 0, sizeof(struct hep_hdr));

	/* Version && proto */
	hdr.hp_v = hep_version;
	hdr.hp_f = from_su->s.sa_family;
	hdr.hp_p = proto;

	/* IP version */
	switch (hdr.hp_f) {
		case AF_INET:
			totlen  = sizeof(struct hep_iphdr);
			break;
		case AF_INET6:
			totlen = sizeof(struct hep_ip6hdr);
			break;
	}

	hdr.hp_l = totlen + sizeof(struct hep_hdr);

	/* COMPLETE LEN */
	totlen += sizeof(struct hep_hdr);
	totlen += plen;

	if(hep_version == 2) {
		totlen += sizeof(struct hep_timehdr);
		hep_time.tv_sec = tvb.tv_sec;
		hep_time.tv_usec = tvb.tv_usec;
		hep_time.captid = hep_capture_id;
	}

    /*buffer for ethernet frame*/
	buffer = pkg_malloc(totlen);
	if (buffer == NULL){
		LM_ERR("no more pkg\n");
		return -1;
	}

	buflen = sizeof(struct hep_hdr);

	switch (hdr.hp_f) {
		case AF_INET:
			/* Source && Destination ipaddresses*/
			hep_ipheader.hp_src = from_su->sin.sin_addr;
			hep_ipheader.hp_dst = to_su->sin.sin_addr;

			/* copy hep ipheader */
			memcpy((void*)buffer + buflen, &hep_ipheader, sizeof(struct hep_iphdr));
			buflen += sizeof(struct hep_iphdr);

			hdr.hp_sport = htons(from_su->sin.sin_port); /* src port */
			hdr.hp_dport = htons(to_su->sin.sin_port); /* dst port */

			break;
		case AF_INET6:
			/* Source && Destination ipv6addresses*/
			hep_ip6header.hp6_src = from_su->sin6.sin6_addr;
			hep_ip6header.hp6_dst = to_su->sin6.sin6_addr;

			/* copy hep6 ipheader */
			memcpy((void*)buffer + buflen, &hep_ip6header, sizeof(struct hep_ip6hdr));
			buflen += sizeof(struct hep_ip6hdr);

			hdr.hp_sport = htons(from_su->sin6.sin6_port); /* src port */
			hdr.hp_dport = htons(to_su->sin6.sin6_port); /* dst port */
			break;
     }


    /* copy hep_hdr */
	memcpy(buffer, &hdr, sizeof(struct hep_hdr));

	/* Version 2 has timestamp, captnode ID */
	if(hep_version == 2) {
		/* TIMING  */
		memcpy((void*)buffer + buflen, &hep_time, sizeof(struct hep_timehdr));
		buflen += sizeof(struct hep_timehdr);
	}

	memcpy((buffer + buflen) , payload, plen);
	buflen +=plen;

	*retbuf = buffer;
	*retlen = buflen;

	return 0;
}


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
	h12.payload = hep_payload;

	/* timming */
	if(heph->hp_v == 2) {
		offset+=sizeof(struct hep_timehdr);
		heptime_tmp = (struct hep_timehdr*) hep_payload;
		h12.payload += sizeof(struct hep_timehdr);

		heptime.tv_sec = heptime_tmp->tv_sec;
		heptime.tv_usec = heptime_tmp->tv_usec;
		heptime.captid = heptime_tmp->captid;
	}
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
			h3.hg.capt_id.data = ntohs(h3.hg.capt_id.data);

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

			gen_chunk->data =
				shm_malloc(gen_chunk->chunk.length - sizeof(hep_chunk_t));

			if (gen_chunk->data == NULL) {
				LM_ERR("no more shared memory!\n");
				return -1;
			}

			memcpy(gen_chunk->data, (char *)buf + sizeof(hep_chunk_t),
					gen_chunk->chunk.length - sizeof(hep_chunk_t));


			CONVERT_TO_HBO(gen_chunk->chunk);
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

				if (_word_start == -1 || (value.len == 0 || value.s == 0)) {
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



/*
 * parse hep id. Hep id format
 * [<name>]ip[:proto]; version=<1/2/3>; transport=<tcp/udp>;"
 * ';' can miss; version and transport are interchangeable;
 *
 */
int parse_hep_id(unsigned int type, void *val)
{
	#define PARSE_NAME(__uri, __name)                                   \
		do {                                                            \
			while (__uri.s[0]==' ')                                    \
				(__uri.s++, __uri.len--);                             \
			__name.s = __uri.s;                                        \
			while (__uri.len                                           \
					&& (__uri.s[0] != ']' && __uri.s[0] != ' '))      \
				(__uri.s++, __uri.len--, __name.len++);               \
                                                                        \
			if (*(__uri.s-1) != ']')                                   \
				while (__uri.len && __uri.s[0] != ']')                \
					(__uri.s++, __uri.len--);                         \
			                                                            \
			if (!__uri.len || __uri.s[0] != ']') {                    \
				LM_ERR("bad name [%.*s]!\n", __uri.len, __uri.s);     \
				return -1;                                              \
			}                                                           \
			(__uri.s++, __uri.len--);                                 \
		} while(0);

	#define IS_UDP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 'u' && (__url__.s[1]|0x20) == 'd' \
					&& (__url__.s[2]|0x20) == 'p'))

	#define IS_TCP(__url__) ((__url__.len == 3/*O_o*/ \
				&& (__url__.s[0]|0x20) == 't' && (__url__.s[1]|0x20) == 'c' \
					&& (__url__.s[2]|0x20) == 'p'))
	char* d;

	str uri_s;
	str name = {0, 0};

	str uri, transport={0, 0}, version={0, 0}, port_s;

	hid_list_p it, el;

	uri_s.s = val;
	uri_s.len = strlen(uri_s.s);

	str_trim_spaces_lr(uri_s);

	if (uri_s.len < 3 /* '[*]' */ || uri_s.s[0] != '[') {
		LM_ERR("bad format for uri {%.*s}\n", uri_s.len, uri_s.s);
		return -1;
	} else {
		uri_s.s++; uri_s.len--;
	}

	PARSE_NAME( uri_s, name);

	for (it=hid_list; it; it=it->next) {
		if (it->name.len == name.len &&
				!memcmp(it->name.s, name.s, it->name.len)) {
			LM_WARN("HEP ID <%.*s> redefined! Not allowed!\n",
					name.len, name.s);
			return -1;
		}
	}

	/* if here the HEP id is unique */

	LM_DBG("Parsing hep id <%.*s>!\n", uri_s.len, uri_s.s);
	if (parse_hep_uri( &uri_s, &uri, &transport, &version) < 0) {
		LM_ERR("failed to parse hep uri!\n");
		return -1;
	}

	LM_DBG("Uri succesfully parsed! Building uri structure!\n");

	el=shm_malloc(sizeof(hid_list_t));
	if (el == NULL) {
		LM_ERR("no more shm!\n");
		goto err_free;
	}

	memset(el, 0, sizeof(hid_list_t));

	el->name = name;

	/* parse ip and port */
	el->ip.s = uri.s;
	d = q_memchr(uri.s, ':', uri.len);

	/* no port provided; use default */
	if (d==NULL) {
		el->ip.len = uri.len;
		el->port_no = HEP_PORT;
		el->port.s = HEP_PORT_STR;
		el->port.len = sizeof(HEP_PORT_STR) - 1;

	} else {
		port_s.s = d+1;
		port_s.len = (uri.s+uri.len) - port_s.s;
		if (str2int(&port_s, &el->port_no)<0) {
			LM_ERR("invalid port <%.*s>!\n", port_s.len, port_s.s);
			goto err_free;
		}
		el->port = port_s;

		el->ip.len = d - el->ip.s;
	}

	/* check hep version if given; default 3 */
	if (version.s && version.len) {
		if (str2int(&version, &el->version) < 0) {
			LM_ERR("Bad version <%.*s\n>", version.len, version.s);
			goto err_free;
		}

		if (el->version < HEP_FIRST || el->version > HEP_LAST) {
			LM_ERR("invalid hep version %d!\n", el->version);
			goto err_free;
		}
	} else {
		el->version = HEP_LAST;
	}

	/* check transport if given; default TCP*/
	if (transport.len && transport.s) {
		if (IS_UDP(transport)) {
			el->transport = PROTO_HEP_UDP;
		} else if (IS_TCP(transport)) {
			el->transport = PROTO_HEP_TCP;
		} else {
			LM_ERR("Bad transport <%.*s>!\n", transport.len, transport.s);
			goto err_free;
		}
	} else {
		el->transport = PROTO_HEP_TCP;
	}

	if (el->transport == PROTO_HEP_TCP && el->version < 3) {
		LM_WARN("TCP not available for HEP version < 3! Falling back to udp!\n");
		el->transport = PROTO_HEP_UDP;
	}


	LM_DBG("Parsed hep id {%.*s} with ip {%.*s} port {%d}"
			" transport {%s} hep version {%d}!\n",
			el->name.len, el->name.s, el->ip.len, el->ip.s,
			el->port_no, el->transport == PROTO_HEP_TCP ? "tcp" : "udp",
			el->version);

	/* add the new element to the hep id list */
	if (hid_list == NULL) {
		hid_list = el;
	} else {
		for (it=hid_list; it->next; it=it->next);
		it->next = el;
	}

	LM_DBG("Added hep id <%.*s> to list!\n", el->name.len, el->name.s);


	return 0;


err_free:
	shm_free(el);
	return -1;

#undef IS_TCP
#undef IS_UDP
#undef PARSE_NAME
}


hid_list_p get_hep_id_by_name(str* name)
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

	LM_ERR("hep id <%.*s> not found!\n", name->len, name->s);
	return NULL;
}

