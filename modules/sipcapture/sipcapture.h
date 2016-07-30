/*
 * hep related structure
 *
 * Copyright (C) 2011 Alexandr Dubovikov (QSC AG) (alexandr.dubovikov@gmail.com)
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

#ifndef _SIPCAPTURE_H_
#define _SIPCAPTURE_H_

typedef char        T8;
#define BINDING_REQUEST	0x0001;

#if 0

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
#endif

#endif /* _SIPCAPTURE_H_ */
