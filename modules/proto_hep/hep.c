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
