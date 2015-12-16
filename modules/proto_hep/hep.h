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
#ifndef _HEP_H
#define _HEP_H

#include "../../ip_addr.h"

#define HEP_HEADER_ID "\x48\x45\x50\x33"
#define HEP_HEADER_ID_LEN (sizeof(HEP_HEADER_ID) - 1)

/* HEPv3 types */

struct hep_chunk {
       u_int16_t vendor_id;
       u_int16_t type_id;
       u_int16_t length;
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       u_int8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       u_int16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       u_int32_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint32 hep_chunk_uint32_t;

struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} __attribute__((packed));

typedef struct hep_chunk_str hep_chunk_str_t;

struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip4 hep_chunk_ip4_t;

struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip6 hep_chunk_ip6_t;

struct hep_ctrl {
    char id[4];
    u_int16_t length;
} __attribute__((packed));

typedef struct hep_ctrl hep_ctrl_t;

struct hep_chunk_payload {
    hep_chunk_t chunk;
    char *data;
} __attribute__((packed));

typedef struct hep_chunk_payload hep_chunk_payload_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

typedef char        T8;
#define BINDING_REQUEST	0x0001;

#ifdef __OS_solaris
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#define IPPROTO_IPIP IPPROTO_ENCAP /* Solaris IPIP protocol has name ENCAP */
#endif


struct hep_hdr{
    u_int8_t hp_v;            /* version */
    u_int8_t hp_l;            /* length */
    u_int8_t hp_f;            /* family */
    u_int8_t hp_p;            /* protocol */
    u_int16_t hp_sport;       /* source port */
    u_int16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
   u_int32_t tv_sec;         /* seconds */
   u_int32_t tv_usec;        /* useconds */
   u_int16_t captid;          /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};


struct hep_desc {
	int version;
	union {
		/* hepv12 describing structure */
		struct hepv12 {
			struct hep_hdr hdr;
			/* only for hepv2*/
			struct hep_timehdr hep_time;

			union {
				struct hep_iphdr  hep_ipheader;
				struct hep_ip6hdr hep_ip6header;
			} addr;

			char *payload;
		} hepv12;

		/* hepv3 describing structure */
		struct hepv3 {
			struct hep_generic hg;

			union {
				struct ip4_addr {
					hep_chunk_ip4_t src_ip4;
					hep_chunk_ip4_t dst_ip4;
				} ip4_addr;
				struct ip6_addr {
					hep_chunk_ip6_t src_ip6;
					hep_chunk_ip6_t dst_ip6;
				} ip6_addr;
			} addr;

			hep_chunk_payload_t payload_chunk;
		} hepv3;
	} u;
};

int pack_hep(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, char **retbuf, int *retlen);
int unpack_hepv2(char *buf, int len, struct hep_desc* h);
int unpack_hepv3(char *buf, int len, struct hep_desc *h);
int unpack_hep(char *buf, int len, int version, struct hep_desc* h);


typedef int (*pack_hep_t)(union sockaddr_union* from_su, union sockaddr_union* to_su,
		int proto, char *payload, int plen, char **retbuf, int *retlen);
#endif

