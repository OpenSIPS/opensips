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
#ifndef _HEP_H
#define _HEP_H

#include "../../ip_addr.h"
#include "../../trace_api.h"

/* first and last version of hep protocol */
#define HEP_FIRST 1
#define HEP_LAST  3

#define HEP_PORT 9060
#define HEP_PORT_STR "9060"

#define HEP_HEADER_ID "\x48\x45\x50\x33"
#define HEP_HEADER_ID_LEN (sizeof(HEP_HEADER_ID) - 1)

#define HEP_SCRIPT_SKIP 0xFF

#define HEP_MIN_INDEX 0x0001
#define HEP_MAX_INDEX 0x0012

#define HEP_IDENTIFIER 0x0fee0faa

#define HEP_OPENSIPS_VENDOR_ID 0x0003

#define HEP_PROTO_TYPE_SIP 0x01
#define HEP_PROTO_TYPE_XLOG 0x056

enum hep_generic_chunks { HEP_PROTO_FAMILY=0x0001, HEP_PROTO_ID=0x0002,
	HEP_IPV4_SRC=0x0003, HEP_IPV4_DST=0x0004, HEP_IPV6_SRC=0x0005,
	HEP_IPV6_DST=0x0006, HEP_SRC_PORT=0x0007, HEP_DST_PORT=0x0008,
	HEP_TIMESTAMP=0x0009, HEP_TIMESTAMP_US=0x000A, HEP_PROTO_TYPE=0x000B,
	HEP_AGENT_ID=0x000C, HEP_KEEP_ALIVE=0x000D, HEP_AUTH_KEY=0x000E,
	HEP_PAYLOAD=0x000F, HEP_COMPRESSED_PAYLOAD=0x0010,
	HEP_CORRELATION_ID=0x0011, HEP_VLAN_ID=0x0012};
#define HEP_EXTRA_CORRELATION 101

#define HEP_STRUCT_CHUNKS ((1<<HEP_PROTO_FAMILY)|(1<<HEP_PROTO_ID)|           \
		(1<<HEP_IPV4_SRC)|(1<<HEP_IPV4_DST)|(1<<HEP_IPV6_SRC)|                \
		(1<<HEP_IPV6_DST)|(1<<HEP_SRC_PORT)|(1<<HEP_DST_PORT)|                \
		(1<<HEP_TIMESTAMP)|(1<<HEP_TIMESTAMP_US)|(1<<HEP_PROTO_TYPE)|         \
		(1<<HEP_AGENT_ID)|(1<<HEP_PAYLOAD)|(1<<HEP_COMPRESSED_PAYLOAD))

#define CHUNK_IS_GENERIC(_cid) (_cid>=HEP_MIN_INDEX && _cid<=HEP_MAX_INDEX)

#define CHUNK_IS_IN_HEPSTRUCT(_cid) (CHUNK_IS_GENERIC(_cid) && \
						((1<<_cid)&HEP_STRUCT_CHUNKS))

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

typedef struct _generic_chunk {
	hep_chunk_t chunk;
	void* data; /* blob data */

	struct _generic_chunk* next;
} generic_chunk_t;



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

			str payload;
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
			generic_chunk_t* chunk_list;
		} hepv3;
	} u;

	void* correlation;
	void* fPayload; /* formatted payload */
};


struct hep_context {
	struct hep_desc h;
	struct receive_info ri;
	int resume_with_sip;
};

#define hid_ref(_h) \
	do { \
		if ((_h)->dynamic) \
			(_h)->ref++; \
	} while (0)
#define hid_unref(_h) \
	do { \
		if ((_h)->dynamic) { \
			(_h)->ref--; \
			if ((_h)->ref == 0) \
				shm_free(_h); \
		} \
	} while (0)

/*
 * structure used for storing hep id's
 * hid = hep_id
 */
typedef struct _hid_list {
	str name;

	str ip;

	unsigned int port_no;
	str port;

	unsigned int version;
	unsigned int ref;
	char transport;
	char dynamic;

	struct _hid_list* next;
} hid_list_t, *hid_list_p;

int unpack_hepv12(char *buf, int len, struct hep_desc* h);
int unpack_hepv3(char *buf, int len, struct hep_desc *h);
int unpack_hep(char *buf, int len, int version, struct hep_desc* h);
void free_extra_chunks(struct hep_desc* h);

int init_hep_id(void);
void destroy_hep_id(void);
int parse_hep_id(unsigned int type, void *val);

int hep_bind_trace_api(trace_proto_t* prot);

typedef int (*get_hep_ctx_id_t)(void);
unsigned char* generate_hep_gid(char* cookie);

int correlate_w(struct sip_msg*, str* hep_id,
		str* type1, str* correlation1,
		str* type2, str* correlation2);
int correlate_fixup(void** param, int param_no);
#endif

