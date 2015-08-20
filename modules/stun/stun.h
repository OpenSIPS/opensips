/*
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2009 Razvan
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
 *  2009-09-03 initial version (razvan)
 */

#ifndef _STUFF_H
#define	_STUFF_H

#include <stdio.h>	    /* printf, fprintf*/
#include <sys/socket.h>	    /* socket, bind */
#include <arpa/inet.h>	    /* sockaddr_in, inet_ntoa*/
#include <stdlib.h>	    /* atoi */
#include <string.h>	    /* memset */
#include <unistd.h>
#include <sys/socket.h>	    /* close */
#include <assert.h>
#include <sys/types.h>	    /* int16 */
#include <stdint.h>
#include <sys/socket.h>	    /* T8 T16 T32 */

/* defs */
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#define IN
#define OUT
#define IN_OUT
#define MAX_UNKNOWN_ATTRIBUTES 12

#define ADV_IP(ip, adv_ip) (adv_ip != -1 ? adv_ip : ip)
#define ADV_PORT(port, adv_port) (adv_port ? adv_port : port)

/* types */
typedef char        Bool;
typedef char        T8;
typedef uint16_t    T16;
typedef uint32_t    T32;

/* enums */
typedef enum {
                FALSE = 0,
                TRUE =1

} Boolean;

typedef enum {
                BINDING_REQUEST	    =	0x0001,
		BINDING_RESPONCE    =	0x0101,
		BINDING_ERROR	    =	0x0111,
		SHARED_REQUEST	    =	0x0002,
		SHARED_RESPONCE	    =	0x0102,
		SHARED_ERROR	    =	0x0112

} Methods;

typedef enum {
                MAPPED_ADDRESS	    =	0x0001,
		RESPONSE_ADDRESS    =	0x0002,
		CHANGE_REQUEST	    =	0x0003,
		SOURCE_ADDRESS	    =	0x0004,
		CHANGED_ADDRESS	    =	0x0005,
		USERNAME	    =	0x0006,
		PASSWORD	    =	0x0007,
		MESSAGE_INTEGRITY   =	0x0008,
		ERROR_CODE	    =	0x0009,
		UNKNOWN_ATTRIBUTES  =	0x000a,
		REFLECTED_FROM	    =	0x000b,

                /* rfc 5389 */
                REALM               =   0x0014,
                NONCE               =   0x0015,


                XOR_MAPPED_ADDRESS  =   0x8020,
                SOFTWARE            =   0x8022,
                ALTERNATE_SERVER    =   0x8023,
                FINGERPRINT         =   0x8028,

                /*BOGUS               =   0xB0B0 */
                BOGUS               =   0x00BB

} Attributes;

typedef enum{
                CHANGE_PORT	    =	0x0002,
		CHANGE_IP	    =	0x0004

}CHANGE_REQUEST_FLAGS;


/* structs */
typedef struct buffer{

    char*   buffer;
    int	    size;
}Buffer;

typedef struct family_port_ip4{

    T8	    unused;		/* host order */
    T8	    family;		/* host order */
    T16	    port;		/* host order */
    T32	    ip4;		/* host order */
}StunAddr;


typedef struct stun_message{

    T16		type;		    /* host order */
    T16		len;		    /* host order */
    char*	id;

    Bool	hasMappedAddress;
    StunAddr*	mappedAddress;	    /* host order */

    Bool	hasResponceAddress;
    StunAddr*	responceAddress;

    Bool	hasSourceAddress;
    StunAddr*	sourceAddress;

    Bool	hasChangedAddress;
    StunAddr*	changedAddress;

    Bool	hasReflectedFrom;
    StunAddr*	reflectedFromAddress;

    Bool	hasXorMappedAddress;
    StunAddr*	xorMappedAddress;

    Bool	hasChangeRequest;
    T32		changeRequestFlags;

    Bool	hasUsername;
    Buffer*	username;

    Bool	hasPassword;
    Buffer*	password;

    Bool	hasMessageIntegrity;
    Bool	hmacIsLastAttribute;
    Buffer*	hmac;


    Bool	hasUnknownAttributes;
    Buffer*	unknownAttributes;

    Bool	hasErrorCode;
    T32		errorCode;
    Buffer*	errorReason;
}StunMsg;


typedef struct stun_controll{
    /*
        inbound
            receivedFrom        sockaddr_in
            receivedWhere       sock_inbound, size

        outbound
            sendTo              sockaddr_in
            sendFrom            sock_outbound
    */
    struct sockaddr_in*	srs;
    int			srs_size;
    int			sock_inbound;


    struct sockaddr_in*	dst;
    int			sock_outbound;

    int			upd_tcp_tls;
}StunCtl;


/* init */
int bind_ip_port(int ip, int port, int* sockfd);
static int stun_mod_init(void);
void stun_loop(int rank);
static int child_init(int rank);


/* receive */
int receive(int sockfd, struct receive_info *ri, str *msg, void* param);


/* deserialize */
int getTlvAttribute(IN_OUT Buffer* buf, IN_OUT StunMsg* msg);
StunMsg* deserialize(IN Buffer* buf);


/* process */
int addError(IN unsigned int errorCode, IN char* errorName, OUT Buffer* dest);
int addTlvAttribute(IN_OUT StunMsg* msg, IN StunMsg* srs_msg, IN int type,
        IN_OUT StunCtl* ctl);
StunMsg* process(IN StunMsg* msg, IN_OUT StunCtl* ctl);


/* serialize */
int serializeStunBuffer(OUT char* b, IN T16 type, IN Buffer* buf);
int serializeStunAddr(OUT char* b, IN T16 type, IN_OUT StunAddr* addr);
Buffer* serialize(IN StunMsg* msg);


/* free */
void freeStunMsg(IN_OUT StunMsg** msg);
void freeStunBuf(IN_OUT Buffer** buffer);

/* print */
void print_hex(char* buffer, int size);
void printStunAddr(StunAddr* addr);
void printStunMsg(StunMsg* msg);

#endif	/* _STUFF_H */

