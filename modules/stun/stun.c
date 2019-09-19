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
 *  2014-03-04 added advertised IPs and ports (liviu)
 */

#include "../../sr_module.h"    /* param_export_t, proc_export_t */
#include "../../net/proto_udp/proto_udp.h"   /* register_udprecv_cb() */
#include "../../socket_info.h"  /* grep_sock_info() */
#include "../../ip_addr.h"      /* struct socket_info */
#include "../../str.h"          /* str */
#include "../../trim.h"

#include "stun.h"

/* Globals */
struct socket_info* grep1 = NULL;
struct socket_info* grep2 = NULL;
struct socket_info* grep3 = NULL;
struct socket_info* grep4 = NULL;
int assign_once = FALSE;

int sockfd1=-1;	/* ip1 port1 */
int sockfd2=-1;	/* ip1 port2 */
int sockfd3=-1;	/* ip2 port1 */
int sockfd4=-1;	/* ip2 port2 */

int ip1, ip2;
int port1 = 5060, port2 = 3478; /* default SIP and STUN ports */

/* dot representation of the above IPs - for socket matching and printing */
char *primary_ip, *alternate_ip;

/* different advertised IPs and ports, in case we're behind NAT */
int adv_ip1 = -1, adv_ip2 = -1;
int adv_port1, adv_port2;

/* Fixup functions */
int parse_primary_ip(modparam_t type, void *val);
int parse_primary_port(modparam_t type, void *val);
int parse_alternate_ip(modparam_t type, void *val);
int parse_alternate_port(modparam_t type, void *val);

/*
 * Exported parameters ip, port
 */
static param_export_t params[] = {
	{"primary_ip",      STR_PARAM | USE_FUNC_PARAM,  parse_primary_ip     },
	{"primary_port",    STR_PARAM | USE_FUNC_PARAM,  parse_primary_port   },
	{"alternate_ip",    STR_PARAM | USE_FUNC_PARAM,  parse_alternate_ip   },
	{"alternate_port",  STR_PARAM | USE_FUNC_PARAM,  parse_alternate_port },
	{ 0, 0, 0}
};

/* Extra proces for listening loop */
static proc_export_t mod_procs[] = {
	{"Stun loop",  0,  0, stun_loop, 1 , 0},
	{0,0,0,0,0,0}
};

struct module_exports exports = {
	"stun",             /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,     /* module version */
	DEFAULT_DLFLAGS,    /* dlopen flags */
	0,				    /* load function */
	NULL,            /* OpenSIPS module dependencies */
	0,                  /* exported functions */
	0,                  /* exported async functions */
	params,             /* module parameters */
	0,                  /* exported statistics */
	0,                  /* exported MI functions */
	0,                  /* exported pseudo-variables */
	0,					/* exported transformations */
	mod_procs,          /* extra processes */
	0,                  /* module pre-initialization function */
	stun_mod_init,      /* module initialization function */
	0,                  /* response function*/
	0,                  /* destroy function */
	child_init,         /* per-child init function */
	0                   /* reload confirm function */
};

/* init */
int bind_ip_port(int ip, int port, int* sockfd){

	struct sockaddr_in server;

	int rc;

	*sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(*sockfd < 0){
		LM_ERR("socket failed : %s\n",strerror(errno));
		return -1;
	}

	memset(&server, 0, sizeof(server));	    /* zero structure */
	server.sin_family = AF_INET;	    /* internet address family */
	server.sin_port = htons(port);
	server.sin_addr.s_addr = htonl(ip);

	/* bind to the local address */
	rc = bind(*sockfd, (struct sockaddr *)&server, sizeof(server));
	if(rc < 0){
		LM_ERR("bind failed : %s\n",strerror(errno));
		return -2;
	}

	return 0;
}


static int stun_mod_init(void)
{
	str s;

	if (!primary_ip || primary_ip[0] == '\0') {
		LM_ERR("Primary IP was not configured!\n");
		return -1;
	}

	if (!alternate_ip || alternate_ip[0] == '\0') {
		LM_ERR("Alternate IP was not configured!\n");
		return -1;
	}

	if (adv_ip1 != -1 && adv_port1 == 0)
		adv_port1 = port1;

	if (adv_ip2 != -1 && adv_port2 == 0)
		adv_port1 = port2;

	s.s = primary_ip; s.len = strlen(primary_ip);
	grep1 = grep_sock_info(&s, (unsigned short)port1, PROTO_UDP);
	if(!grep1){
		LM_ERR("IP1:port1 [%s:%d] not found in listening sockets\n",
			primary_ip, port1);
		return -1;
	}

	grep2 = grep_sock_info(&s, (unsigned short)port2, PROTO_UDP);
	if(!grep2){
		LM_DBG("IP1:port2 [%s:%d] not found in listening sockets\n",
			primary_ip, port2);
		if (bind_ip_port(ip1, port2, &sockfd2)!=0) {
			LM_ERR("failed to bind for IP1:port2 [%s:%d]\n",
				primary_ip, port2);
			return -1;
		}
	}

	s.s = alternate_ip; s.len = strlen(alternate_ip);
	grep3 = grep_sock_info(&s, (unsigned short)port1, PROTO_UDP);
	if(!grep3){
		LM_DBG("IP2:port1 [%s:%d] not found in listening sockets\n",
			alternate_ip, port1);
		if (bind_ip_port(ip2, port1, &sockfd3)!=0) {
			LM_ERR("failed to bind for IP2:port1 [%s:%d]\n",
				alternate_ip, port1);
			return -1;
		}
	}

	grep4 = grep_sock_info(&s, (unsigned short)port2, PROTO_UDP);
	if(!grep4){
		LM_DBG("IP2:port2 [%s:%d] not found in listening sockets\n",
			alternate_ip, port2);
		if (bind_ip_port(ip2, port2, &sockfd4)!=0) {
			LM_ERR("failed to bind for IP2:port2 [%s:%d]\n",
				alternate_ip, port2);
			return -1;
		}
	}

	/* register for BINDING_REQUEST */
	if (register_udprecv_cb(&receive, 0, (T8) (BINDING_REQUEST>>8),
	(T8)BINDING_REQUEST) != 0) {
		LM_ERR("failed to install UDP recv callback\n");
		return -1;
	}

	LM_DBG("stun init succeeded\n");
	return 0;
}


void stun_loop(int rank)
{
	fd_set read_set, all_set;
	int maxfd;
	int nready;
	char buffer[65536];
	str msg;
	unsigned int clientAddrLen;
	struct receive_info ri;

	FD_ZERO(&all_set);
	maxfd = MAX ( MAX(sockfd1, sockfd2), MAX(sockfd3, sockfd4));

	LM_DBG("created sockets fd = %i %i %i %i (max = %i)\n",
		sockfd1, sockfd2, sockfd3, sockfd4, maxfd);

	sockfd1 = grep1->socket;
	if(grep2)
		sockfd2 = grep2->socket;
	else
		FD_SET(sockfd2, &all_set);

	if(grep3)
		sockfd3 = grep3->socket;
	else
		FD_SET(sockfd3, &all_set);

	if(grep4)
		sockfd4 = grep4->socket;
	else
		FD_SET(sockfd4, &all_set);

	LM_DBG("created and gained sockets fd = %i %i %i %i\n",
		sockfd1, sockfd2, sockfd3, sockfd4);

	/* this will never change as buffer is fixed */
	msg.s = buffer;
	memset( &ri, 0, sizeof(ri) );

	for(;;){
		LM_DBG("READING\n");
		read_set = all_set;

		nready = select(maxfd+1, &read_set, NULL, NULL, NULL);
		if (nready < 0) {
			if (errno != EINTR)
				LM_ERR("error in select %d(%s)\n", errno, strerror(errno));
			continue;
		}

		if(FD_ISSET(sockfd2, &read_set)){
			clientAddrLen = sizeof(struct sockaddr);
			msg.len = recvfrom(sockfd2, buffer, 65536, 0,
				(struct sockaddr *) &ri.src_su.sin, &clientAddrLen);
			receive(sockfd2, &ri, &msg, NULL);
		}

		if(FD_ISSET(sockfd3, &read_set)){
			clientAddrLen = sizeof(struct sockaddr);
			msg.len = recvfrom(sockfd3, buffer, 65536, 0,
				(struct sockaddr *) &ri.src_su.sin, &clientAddrLen);
			receive(sockfd3, &ri, &msg, NULL);
		}

		if(FD_ISSET(sockfd4, &read_set)){
			clientAddrLen = sizeof(struct sockaddr);
			msg.len = recvfrom(sockfd4, buffer, 65536, 0,
				(struct sockaddr *) &ri.src_su.sin, &clientAddrLen);
			receive(sockfd4, &ri, &msg, NULL);
		}

	}
}

static int child_init(int rank){
    sockfd1 = grep1->socket;
    if(grep2)
	sockfd2 = grep2->socket;
    if(grep3)
	sockfd3 = grep3->socket;
    if(grep4)
	sockfd4 = grep4->socket;

    /*optimization
    if(getpid() < -5?){
	close(sockfd1);
	close(sockfd2);
	close(sockfd3);
	close(sockfd4);
    }
     */
    return 0;
}


/* receive */
int receive(int sockfd, struct receive_info *ri, str *msg, void* param)
{
	struct sockaddr_in * client;
	Buffer recv_buffer;
	Buffer* resp_buffer;
	StunMsg* recv_msg;
	StunMsg* resp_msg;
	StunCtl ctl;
	char s[32];

	client = (struct sockaddr_in *) &(ri->src_su.sin);

	/* info & checks*/
    if(sockfd == sockfd1)
	sprintf(s, "%i %s %d", sockfd1, primary_ip, port1);
    else if(sockfd == sockfd2)
	sprintf(s, "%i %s %d", sockfd2, primary_ip, port2);
    else if(sockfd == sockfd3)
	sprintf(s, "%i %s %d", sockfd3, alternate_ip, port1);
    else if(sockfd == sockfd4)
	sprintf(s, "%i %s %d", sockfd4, alternate_ip, port2);
    else{
	LM_DBG("Received: on [%i unknown %s %d] from [%s %i]; drop msg\n",
		sockfd, alternate_ip, port2, inet_ntoa(client->sin_addr),
	    ntohs(client->sin_port));
	return -1;
    }
    LM_DBG("Received: on [%s] from [%s %i]\n", s, inet_ntoa(client->sin_addr),
	    ntohs(client->sin_port));
    LM_DBG("Message: size = %i, body = \n", msg->len);
    /* print_hex(msg->s, msg->len); */

/* deserialize */
    recv_buffer.buffer = msg->s;
    recv_buffer.size = msg->len;
    recv_msg = deserialize(&recv_buffer);
    if(!recv_msg)   /* received junk or out of mem */
	return -1;
    LM_DBG("Received Message:\n"); printStunMsg(recv_msg);

	memset(&ctl,0,sizeof(StunCtl));

/* process */
    ctl.srs = client;
    ctl.srs_size = sizeof(struct sockaddr);;
    ctl.sock_inbound = sockfd;
    resp_msg = process(recv_msg, &ctl);
    if(!resp_msg){   /* process junk or out of mem */
		freeStunMsg(&recv_msg);
		if (ctl.dst && ctl.dst != client)
			pkg_free(ctl.dst);
		return -1;
    }
    LM_DBG("Send Message:\n"); printStunMsg(resp_msg);

/* serialize */
    resp_buffer = serialize(resp_msg);
	if (resp_buffer == NULL) {
		freeStunMsg(&recv_msg);
		freeStunMsg(&resp_msg);
		if (ctl.dst && ctl.dst != client)
			pkg_free(ctl.dst);
		LM_ERR("failed to get resp buffer\n");
		return -1;
	}

/* send */
    if(ctl.sock_outbound == sockfd1)
	sprintf(s, "%i %s %d", sockfd1, primary_ip, port1);
    else if(ctl.sock_outbound == sockfd2)
	sprintf(s, "%i %s %d", sockfd2, primary_ip, port2);
    else if(ctl.sock_outbound == sockfd3)
	sprintf(s, "%i %s %d", sockfd3, alternate_ip, port1);
    else if(ctl.sock_outbound == sockfd4)
	sprintf(s, "%i %s %d", sockfd4, alternate_ip, port2);
    else
	sprintf(s, "%i unknown", ctl.sock_outbound);

    LM_DBG("Sending: from [%s] to [%s %i]\n", s,
	    inet_ntoa(ctl.dst->sin_addr), ntohs(ctl.dst->sin_port));
    if (sendto(ctl.sock_outbound, resp_buffer->buffer, resp_buffer->size, 0,
			(struct sockaddr *) ctl.dst, ctl.srs_size) < 0)
		LM_DBG("error sending reply %d\n", errno);

/* free */
	if (ctl.dst && ctl.dst != client)
		pkg_free(ctl.dst);
    freeStunMsg(&recv_msg);
    freeStunMsg(&resp_msg);
    freeStunBuf(&resp_buffer);
    return 0;
}



/* deserialize */
int getTlvAttribute(IN_OUT Buffer* buf, IN_OUT StunMsg* msg){

    /*
     * return number of bytes eaten
     * 0					; ok
     * -1   attribute already exists		; will be ignored
     * -1   non-mandatory unknown attribute	; will be ignored
     * -2   responce address familly != 0x01	; drop msg
     * -3   attribute length overflows buffer	; drop msg
     * -4   attribute length does not corespond	; drop msg
     * -5   hmac attribute is not the last	; drop msg
     * -6   out of mem				; drop msg - server error
     */

    T16 type;
    T16 len;
    int rc;
    char* b;	/* iterator */
    T16 * b2;

    rc = 0;
    b = (char*) buf->buffer;

    type = ntohs(*(T16 *) b);
    b+=2;

    len = ntohs(*(T16 *) b);
    b+=2;

    if (len % 4 != 0)
        len = (len/4 + 1) * 4;

    if(4 + len > buf->size){
	LM_DBG("Attribute length overflows; drop msg\n");
	return -3;
    }

    /* HMAC must be the last attribute */
    msg->hmacIsLastAttribute = FALSE;

    switch(type){

	case CHANGE_REQUEST:
	    if(len != 4){
		LM_DBG("Attribute length doest not correspond with type "
			"CHANGE_REQUEST; drop msg\n");
		return -4;
	    }

	    if(!msg->hasChangeRequest){
		msg->hasChangeRequest = TRUE;
		msg->changeRequestFlags = ntohl(*(T32*) b);
		b+=4;
	    }else{
		LM_DBG("Attribute CHANGE_REQUEST already exists; "
			"ignore attribute\n");
		rc = -1;
	    }
	    break;

	case RESPONSE_ADDRESS:
	    if(len != 8){
		LM_DBG("Attribute length doest not correspond with type "
			"RESPONSE_ADDRESS; drop msg\n");
		return -4;
	    }

	    if(!msg->hasResponceAddress){
		msg->hasResponceAddress = TRUE;
		msg->responceAddress = (StunAddr*) pkg_malloc(sizeof(StunAddr));
		if(!msg->responceAddress)
		    return -6;
		memset(msg->responceAddress, 0, sizeof(StunAddr));

		msg->responceAddress->unused = *(char*) b;
		b+=1;

		msg->responceAddress->family = *(char*) b;
		b+=1;

		if(msg->responceAddress->family != 0x01){
		    LM_DBG("Response address familly != 0x01\n");
		    rc = -2;
		}

		msg->responceAddress->port = ntohs( *(T16*) b);
		b+=2;

		msg->responceAddress->ip4 = ntohl( *(T32*) b);
		b+=4;

	    }else{
		LM_DBG("Attribute RESPONSE_ADDRESS already exists; "
			"ignore attribute\n");
		rc = -1;
	    }
	    break;

	case MESSAGE_INTEGRITY:
	    if(len != 20){
		LM_DBG("Attribute length doest not correspond with type "
			"MESSAGE_INTEGRITY; drop msg\n");
		return -4;
	    }

	    if(!msg->hasMessageIntegrity){
		msg->hasMessageIntegrity = TRUE;
		msg->hmacIsLastAttribute = TRUE;

		/* allocate Buffer hmac */
		msg->hmac = (Buffer*) pkg_malloc(sizeof(Buffer));
		if(!msg->hmac)
		    return -6;

		memset(msg->hmac, 0, sizeof(Buffer));

		/* allocate 20 bytes */
		msg->hmac->buffer = (char*)pkg_malloc(20 * sizeof(char));
		if(!msg->hmac->buffer)
		    return -6;
		msg->hmac->size = 20;

		/* copy the 20 bytes */
		memcpy(msg->hmac->buffer, b, 20);
		b+=20;

	    }else{
		LM_DBG("Attribute already exists, will ignore attribute\n");
		rc = -1;
	    }

	    /* check SHA1 and set errror TO DO */

	    break;

	default:

	    if(type <= 0x7fff){
		LM_DBG("Unknown mandatory attribute type = %i len = %i\n",
			type, len);

		/* set the errorCode to 420 if no other error exists */
		if(!msg->hasErrorCode){
		    msg->hasErrorCode = TRUE;
		    msg->errorCode = 420;
		}

		/* allocate unknownAttributes structure if first time*/
		if(!msg->hasUnknownAttributes){
		    msg->hasUnknownAttributes = TRUE;

		    /* allocate unknownAttributes Buffer */
		    msg->unknownAttributes = (Buffer*) pkg_malloc(
			    sizeof(Buffer));
		    if(!msg->unknownAttributes)
			return -6;
		    memset(msg->unknownAttributes, 0, sizeof(Buffer));

		    /* allocate array of unknownAttributes (12 should suffice)*/
		    msg->unknownAttributes->buffer = (char*) pkg_malloc(
			    MAX_UNKNOWN_ATTRIBUTES * sizeof(T16));
		    if(!msg->unknownAttributes->buffer)
			return -6;
		    memset(msg->unknownAttributes->buffer, 0,
			    MAX_UNKNOWN_ATTRIBUTES * sizeof(T16));

		    /* size reprezents the serializable size of attributes*/
		    msg->unknownAttributes->size = 0;

		}

		/* address the buffer as a T16 array */
		b2 = (T16*) msg->unknownAttributes->buffer;
		if(msg->unknownAttributes->size / sizeof(T16)
			< MAX_UNKNOWN_ATTRIBUTES){
		    b2[msg->unknownAttributes->size / sizeof(T16)] = type;
		    msg->unknownAttributes->size += sizeof(T16);
		}
	    }else{
		LM_DBG("Unknown non-mandatory attribute type = %i len = %i; "
			"will ignore\n", type, len);
		b += len;
		rc = -1;
	    }
	    break;
    }

    /* HMAC must be the last attribute */
    if(msg->hasMessageIntegrity && !msg->hmacIsLastAttribute){
	LM_DBG("HMAC attribute is not last; drop msg\n");
	rc = -5;
    }

    /* remaining size and pointer */
    buf->size -= (4+len); /* |type + len + value| = 2 + 2 + len */
    buf->buffer	=   b;

    return rc;
}

StunMsg* deserialize(IN Buffer* buffer){

    /*
     * return NULL if out of memory or not stun message
     * return StunMsg* even if mallformed (because it must receive a reply)
     */

    int	    rc;
    char*   b;
    Buffer  remain;
    StunMsg* msg;

    /* b is iterator */
    b = (char*) buffer->buffer;

    /* allocate returned structure */
    msg = (StunMsg*) pkg_malloc(sizeof(StunMsg));
    if(!msg){
		LM_ERR("out of mem\n");
		goto error;
    }
    memset(msg, 0, sizeof(StunMsg));

    /* check if message has at least the 20 bits header */
    if(buffer->size < 20){
		LM_WARN("Buff size < 20\n");
		goto error;
    }

    /* message type */
    msg->type = ntohs(* (T16*) b);
    b+=2;

    /* message length (without header) */
    msg->len = ntohs(* (T16*)b);
    b+=2;

    /* message unique id */
    msg->id = (char*) pkg_malloc(16*sizeof(char));
    if(!msg){
		LM_DBG("out of mem\n");
		goto error;
    }
    memcpy(msg->id, b, 16);
    b+=16;

    /* remaining buffer to be parsed for the list of attributes */
    remain.buffer = b;
    remain.size = buffer->size - (b - buffer->buffer); /* = buffer->size -20 */

    /* each tlv attribute */
    while(remain.size){
	rc = getTlvAttribute(&remain, msg);

	if(-5 <= rc && rc<=-2){
	    msg->hasErrorCode = TRUE;
	    msg->errorCode = 400;   /* bad(malformed) message */
	    break;
	}else if(rc == -6){
	    LM_DBG("out of mem\n");
	    goto error;
	}
    }

    return msg;

error:
    freeStunMsg(&msg);
    return NULL;
}



/* process */
int addError(IN unsigned int errorCode, IN char* errorName, OUT Buffer* dest){

    int len = strlen(errorName);

    dest->buffer = (char*) pkg_malloc(4 + len + 1);
    if(!dest->buffer){
	LM_DBG("out of mem\n");
	return -1;
    }
    dest->size = 4 + len;

    snprintf(dest->buffer, dest->size + 1,"%c%c%c%c%.*s", 0 ,0,
	    (errorCode / 100) & 0x07, errorCode % 100, len, errorName);

    return dest->size;
}

int addTlvAttribute(IN_OUT StunMsg* msg , IN StunMsg* srs_msg,
	IN int type, IN_OUT StunCtl* ctl){

    int i;
    T16* b2;	    /* iterator */
    T32 cookie;

    int rc = -1;
    struct sockaddr_in* alternate_dst;

    switch(type){
	case MAPPED_ADDRESS:
	    msg->mappedAddress = (StunAddr* ) pkg_malloc(sizeof(StunAddr));
	    if(!msg->mappedAddress){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    msg->hasMappedAddress = TRUE;

	    msg->mappedAddress->unused = 0;
	    msg->mappedAddress->family = 0x01;
	    msg->mappedAddress->port = ntohs(ctl->srs->sin_port);
	    msg->mappedAddress->ip4 = ntohl(ctl->srs->sin_addr.s_addr);

	    return 2 + 2 + 8;


	case SOURCE_ADDRESS:
	    msg->sourceAddress = (StunAddr*) pkg_malloc(sizeof(StunAddr));
	    if(!msg->sourceAddress){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    msg->hasSourceAddress = TRUE;

	    msg->sourceAddress->unused = 0;
	    msg->sourceAddress->family = 0x01;

	    if(ctl->sock_outbound == sockfd1){
		msg->sourceAddress->ip4 = ADV_IP(ip1, adv_ip1);
		msg->sourceAddress->port = ADV_PORT(port1, adv_port1);
	    }else if(ctl->sock_outbound == sockfd2){
		msg->sourceAddress->ip4 = ADV_IP(ip1, adv_ip1);
		msg->sourceAddress->port = ADV_PORT(port2, adv_port2);
	    }else if(ctl->sock_outbound == sockfd3){
		msg->sourceAddress->ip4 = ADV_IP(ip2, adv_ip2);
		msg->sourceAddress->port = ADV_PORT(port1, adv_port1);
	    }else if(ctl->sock_outbound == sockfd4){
		msg->sourceAddress->ip4 = ADV_IP(ip2, adv_ip2);
		msg->sourceAddress->port = ADV_PORT(port2, adv_port2);
	    }
	    return 2 + 2 + 8;


	case CHANGED_ADDRESS:
	    msg->changedAddress = (StunAddr*) pkg_malloc(sizeof(StunAddr));
	    if(!msg->changedAddress){
		LM_DBG("out of mem\n");
		return -1;
	    }

	    msg->hasChangedAddress = TRUE;

	    msg->changedAddress->unused = 0;
	    msg->changedAddress->family = 0x01;
	    /*
	    		           ip  port	inverse
		t1 = sockfd1;	   0	0       1 1
		t2 = sockfd2;	   0	1       1 0
		t3 = sockfd3;	   1	0       0 1
		t4 = sockfd4;	   1	1       0 0
		it is the inverse ip and port on whitch it was received
		1 >< 4  ;  2 >< 3
	     */
	    if(ctl->sock_inbound == sockfd1){
		msg->changedAddress->ip4 = ADV_IP(ip2, adv_ip2);
		msg->changedAddress->port = ADV_PORT(port2, adv_port2);
	    }else if(ctl->sock_inbound == sockfd2){
		msg->changedAddress->ip4 = ADV_IP(ip2, adv_ip2);
		msg->changedAddress->port = ADV_PORT(port1, adv_port1);
	    }else if(ctl->sock_inbound == sockfd3){
		msg->changedAddress->ip4 = ADV_IP(ip1, adv_ip1);
		msg->changedAddress->port = ADV_PORT(port2, adv_port2);
	    }else if(ctl->sock_inbound == sockfd4){
		msg->changedAddress->ip4 = ADV_IP(ip1, adv_ip1);
		msg->changedAddress->port = ADV_PORT(port1, adv_port1);
	    }
	    return 2 + 2 + 8;


	case REFLECTED_FROM:
	    /* where the response should be sent */
	    alternate_dst = (struct sockaddr_in*) pkg_malloc(
		    sizeof(struct sockaddr_in));
	    if(!alternate_dst){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    memset(alternate_dst, 0, sizeof(struct sockaddr_in));

	    alternate_dst->sin_family = AF_INET;
	    alternate_dst->sin_port = htons(srs_msg->responceAddress->port);
	    alternate_dst->sin_addr.s_addr = htonl(
		    srs_msg->responceAddress->ip4);
	    ctl->dst = alternate_dst;


	    /* same as mapped address */
	    msg->reflectedFromAddress = (StunAddr*) pkg_malloc(
		    sizeof(StunAddr));
	    if(!msg->reflectedFromAddress){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    msg->hasReflectedFrom = TRUE;

	    msg->reflectedFromAddress->unused = 0;
	    msg->reflectedFromAddress->family = 0x01;
	    msg->reflectedFromAddress->port = ntohs(ctl->srs->sin_port);
	    msg->reflectedFromAddress->ip4 = ntohl(ctl->srs->sin_addr.s_addr);

	    return 2 + 2 + 8;


	case XOR_MAPPED_ADDRESS:
	    cookie = ntohl(*(T32*) msg->id);
	    msg->xorMappedAddress = (StunAddr* ) pkg_malloc(sizeof(StunAddr));
	    if(!msg->xorMappedAddress){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    msg->hasXorMappedAddress = TRUE;

	    msg->xorMappedAddress->unused = 0;
	    msg->xorMappedAddress->family = 0x01;
	    msg->xorMappedAddress->port = ntohs(
		    ctl->srs->sin_port) ^ (T16)(cookie>>16);
	    msg->xorMappedAddress->ip4 = ntohl(
		    ctl->srs->sin_addr.s_addr) ^ cookie;

	    return 2 + 2 + 8;


	case ERROR_CODE:
	    msg->errorReason = (Buffer*) pkg_malloc(sizeof(Buffer));
	    if(!msg->errorReason){
		LM_DBG("out of mem\n");
		return -1;
	    }
	    memset(msg->errorReason, 0, sizeof(Buffer));

	    switch(msg->errorCode){
		/* remember multiple of 4 bytes */
		case 400:
		    rc = addError(400, "Bad Request ", msg->errorReason); break;
		case 420:
		    rc = addError(420, "Unknown Attribute   ",
			    msg->errorReason); break;
		case 500:
		    rc = addError(500, "Server Error", msg->errorReason); break;
		case 600:
		    rc = addError(600, "Global Failure  ",
			    msg->errorReason); break;
	    }

	    if(rc < 0)
		return -1;
	    else
		msg->hasErrorCode = TRUE;
	    return 2 + 2 + rc;


	case UNKNOWN_ATTRIBUTES:
		/* allocate unknownAttributes buffer */
		msg->unknownAttributes = (Buffer*) pkg_malloc(sizeof(Buffer));
		if(!msg->unknownAttributes){
		    LM_DBG("out of mem\n");
		    return -1;
		}
		memset(msg->unknownAttributes, 0, sizeof(Buffer));

		/* the number of unknown attributes must be even */

		/* urmatorul numar mai mare sau egal cu X multiplu de N este
		 * (X + N -1 ) / N * N
		 */
		if((srs_msg->unknownAttributes->size / sizeof(T16)) %2 == 0 )
		    msg->unknownAttributes->size =
			    srs_msg->unknownAttributes->size;
		else
		    msg->unknownAttributes->size =
			    srs_msg->unknownAttributes->size + sizeof(T16);

		/* allocate buffer */
		msg->unknownAttributes->buffer =
			(char*) pkg_malloc(msg->unknownAttributes->size);
		if(!msg->unknownAttributes->buffer){
		    LM_DBG("out of mem\n");
		    return -1;
		}
		/* just copy the unknown from the deserialized message */
		memcpy(msg->unknownAttributes->buffer,
		srs_msg->unknownAttributes->buffer, srs_msg->unknownAttributes->size);

		/* iterator */
		b2 = (T16 *) msg->unknownAttributes->buffer;

		/* if number of unknws is not even; duplicate the last one */
		if((srs_msg->unknownAttributes->size / sizeof(T16)) % 2 == 1)
		    b2[msg->unknownAttributes->size/sizeof(T16)-1] = b2[
			    msg->unknownAttributes->size/sizeof(T16)-1 -1];

		/* convert to network order */
		for(i=0; i < msg->unknownAttributes->size/sizeof(T16); i++)
			b2[i] = ntohs(b2[i]);

		msg->hasUnknownAttributes = TRUE;

		return 2 + 2 + msg->unknownAttributes->size;
    }

    return -1;
}

void swap(IN_OUT int* a, IN_OUT int* b){
    int t = *a;
    *a = *b;
    *b = t;
}

StunMsg* process(IN StunMsg* msg, IN_OUT StunCtl* ctl){

    int	    rc;
    int	    t1, t2, t3, t4;	/* used for socket swapping */
    StunMsg* rmsg;		/* returned response message */

    if(!msg){
	LM_DBG("error NULL msg\n");
	return NULL;
    }

    /* allocate responce message */
    rmsg = (StunMsg* ) pkg_malloc(sizeof(StunMsg));
    if(!rmsg){
	LM_DBG("out of mem\n");
	return NULL;
    }
    memset(rmsg, 0, sizeof(StunMsg));


    /* this server treats just the BINDING requsts */
    if(msg->type == BINDING_REQUEST){

	/* type & id */
	rmsg->type = BINDING_RESPONCE;
	rmsg->len = 0;
	/* allocate id */
	rmsg->id = (char*) pkg_malloc(16*sizeof(char));
	if(!rmsg->id){
	    LM_DBG("out of mem\n");
	    goto error;
	}
	/* response must have the same id as request*/
	memcpy(rmsg->id, msg->id, 16);


	/* if has change ip, port request */
	if(msg->hasChangeRequest && !msg->hasErrorCode){
	    /*		    ip  port	    */
	    t1 = sockfd1;	/*  0	0   */
	    t2 = sockfd2;	/*  0	1   */
	    t3 = sockfd3;	/*  1	0   */
	    t4 = sockfd4;	/*  1	1   */

	    /* LM_DBG("process()1 t1=%i  t2=%i  t3=%i  t4=%i\n", t1, t2, t3, t4); */
	/* outbound depends on INBOUND and on REQUEST_FLAGS */

	    /* eliminate INBOUND dependency */
	    if(ctl->sock_inbound == t1){

	    }else if(ctl->sock_inbound == t2){
		/* swap ports - mentain ips */
		swap(&t1, &t2);
		swap(&t3, &t4);
	    }else if(ctl->sock_inbound == t3){
		/* swap ips -mentain port */
		swap(&t1, &t3);
		swap(&t2, &t4);
	    }else if(ctl->sock_inbound == t4){
		/* swap ips and ports */
		swap(&t1, &t2);
		swap(&t3, &t4);

		swap(&t1, &t3);
		swap(&t2, &t4);
	    }
	    /* LM_DBG("process()2 t1=%i  t2=%i  t3=%i  t4=%i\n", t1, t2, t3, t4); */
	    /* eliminate REQUEST_FLAGS dependency */
	    if(msg->changeRequestFlags & CHANGE_IP){
		/* swap ips -mentain port */
		swap(&t1, &t3);
		swap(&t2, &t4);
	    }

	    if(msg->changeRequestFlags & CHANGE_PORT){
		/* swap ports - mentain ips */
		swap(&t1, &t2);
		swap(&t3, &t4);

	    }
	    /* LM_DBG("process()3 t1=%i  t2=%i  t3=%i  t4=%i\n", t1, t2, t3, t4); */
	    ctl->sock_outbound  = t1;
	}else{
	    ctl->sock_outbound = ctl->sock_inbound;
	}

	/* if it has errors send a BINDING_ERROR responce */
	if(msg->hasErrorCode){

	    /* send back */
	    ctl->dst = ctl->srs;

	    /* type */
	    rmsg->type = BINDING_ERROR;

	    /* mandatory ERROR_CODE attribute */
	    rmsg->errorCode = msg->errorCode;
	    rc=addTlvAttribute(rmsg, msg, ERROR_CODE, ctl);
	    if(rc<0){
		LM_DBG("error at ERROR_CODE\n");
		goto error;
	    }
	    rmsg->len+=rc;

	    /* conditional list of UNKNOWN_ATTRIBUTES */
	    if(msg->hasUnknownAttributes){
		rc=addTlvAttribute(rmsg, msg, UNKNOWN_ATTRIBUTES, ctl);
		if(rc<0){
		    LM_DBG("error at UNKNOWN_ATTRIBUTES\n");
		    goto error;
		}
		rmsg->len+=rc;
	    }
	    /* even if it has CHANGE_REQUEST,
	     * the error response is send to source */
	    return rmsg;
	}

	if(msg->hasResponceAddress){
	    rc=addTlvAttribute(rmsg, msg, REFLECTED_FROM, ctl);
	    if(rc<0){
		LM_DBG("error at REFLECTED_FROM\n");
		goto error;
	    }
	    rmsg->len+=rc;
	}else{
	    ctl->dst = ctl->srs;
	}

	/* add atributes  */
	rc=addTlvAttribute(rmsg, msg, MAPPED_ADDRESS, ctl);
	if(rc<0){
	    LM_DBG("error at MAPPED_ADDRESS\n");
	    goto error;
	}
	rmsg->len+=rc;


	rc=addTlvAttribute(rmsg, msg, SOURCE_ADDRESS, ctl);
	if(rc<0){
	    LM_DBG("error at SOURCE_ADDRESS\n");
	    goto error;
	}
	rmsg->len+=rc;


	rc=addTlvAttribute(rmsg, msg, CHANGED_ADDRESS, ctl);
	if(rc<0){
	    LM_DBG("error at CHANGED_ADDRESS\n");
	    goto error;
	}
	rmsg->len+=rc;


	rc=addTlvAttribute(rmsg, msg, XOR_MAPPED_ADDRESS, ctl);
	if(rc<0){
	    LM_DBG("error at XOR_MAPPED_ADDRESS\n");
	    goto error;
	}
	rmsg->len+=rc;

    }else{
	pkg_free(rmsg);
	return NULL;
    }

    return rmsg;

error:
    freeStunMsg(&rmsg);
    return NULL;
}



/* serialize */
int serializeStunBuffer(OUT char* b, IN T16 type, IN Buffer* buf){

    T16 netorder = htons(type);
    T16 netlen = htons(buf->size);

    /* TYPE */
    memcpy(b, &netorder, 2);
    b+=2;

    /* LENGTH */
    memcpy(b, &netlen, 2);
    b+=2;

    /* VALUE */
    memcpy(b, buf->buffer, buf->size);
    b+=buf->size;

    return 4 + buf->size;
}

int serializeStunAddr(OUT char* b, IN T16 type, IN_OUT StunAddr* addr){

    T16 netorder = htons(type);
    T16 netlen = htons(8);

    /* TYPE */
    memcpy(b, &netorder, 2);
    b+=2;

    /* LENGTH */
    memcpy(b, &netlen, 2);
    b+=2;


    /* VALUE */
    memcpy(b, &addr->unused, 1);
    b+=1;

    memcpy(b, &addr->family, 1);
    b+=1;

    addr->port = htons(addr->port);
    memcpy(b, &addr->port, 2);
    b+=2;

    addr->ip4 = htonl(addr->ip4);
    memcpy(b, &addr->ip4, 4);
    b+=4;

    return 12;
}

Buffer* serialize(IN StunMsg* msg){

    char* b;
    Buffer* buffer;

    /* allocate the returned Buffer */
    buffer = (Buffer* ) pkg_malloc(sizeof(Buffer));
    if(!buffer){
	LM_DBG("out of mem\n");
	return NULL;
    }
    memset(buffer, 0 , sizeof(Buffer));

    /* set size */
    buffer->size = msg->len +20;

    /* allocate contents */
    buffer->buffer = (char*) pkg_malloc(buffer->size * sizeof(char));
    if(!buffer->buffer){
	LM_DBG("out of mem\n");
	pkg_free(buffer);
	return NULL;
    }
    memset(buffer->buffer, 0, buffer->size * sizeof(char));

    /* iterator b */
    b = buffer->buffer;

    /* type */
    msg->type = htons(msg->type);
    memcpy(b, &msg->type, 2);
    b+=2;

    /* len */
    msg->len = htons(msg->len);
    memcpy(b, &msg->len, 2);
    b+=2;

    /* id */
    memcpy(b, msg->id, 16);
    b+=16;

    /* list of attributes */
    if(msg->hasMappedAddress)
	b+=serializeStunAddr(b, MAPPED_ADDRESS, msg->mappedAddress);

    if(msg->hasSourceAddress)
	b+=serializeStunAddr(b, SOURCE_ADDRESS, msg->sourceAddress);

    if(msg->hasChangedAddress)
	b+=serializeStunAddr(b, CHANGED_ADDRESS, msg->changedAddress);

    if(msg->hasXorMappedAddress)
	b+=serializeStunAddr(b, XOR_MAPPED_ADDRESS, msg->xorMappedAddress);

    if(msg->hasReflectedFrom)
	b+=serializeStunAddr(b, REFLECTED_FROM, msg->reflectedFromAddress);

    if(msg->hasErrorCode)
	b+=serializeStunBuffer(b, ERROR_CODE, msg->errorReason);

    if(msg->hasUnknownAttributes)
	b+=serializeStunBuffer(b, UNKNOWN_ATTRIBUTES, msg->unknownAttributes);

    return buffer;
}



/* free */
void freeStunMsg(IN_OUT StunMsg** msg){
    if(*msg){
	LM_DBG("freeing\n");
	/* char* */
	if((*msg)->id){
	    pkg_free((*msg)->id);
	}

	/* StunAddr */
	if((*msg)->mappedAddress){
	    pkg_free((*msg)->mappedAddress);
	}
	if((*msg)->responceAddress){
	    pkg_free((*msg)->responceAddress);
	}
	if((*msg)->sourceAddress){
	    pkg_free((*msg)->sourceAddress);
	}
	if((*msg)->changedAddress){
	    pkg_free((*msg)->changedAddress);
	}
	if((*msg)->reflectedFromAddress){
	    pkg_free((*msg)->reflectedFromAddress);
	}
	if((*msg)->xorMappedAddress){
	    pkg_free((*msg)->xorMappedAddress);
	}

	/* Buffer */
	if((*msg)->username){
	    if((*msg)->username->buffer){
		pkg_free((*msg)->username->buffer);
	    }
	    pkg_free((*msg)->username);
	}
	if((*msg)->password){
	    if((*msg)->password->buffer){
		pkg_free((*msg)->password->buffer);
	    }
	    pkg_free((*msg)->password);
	}
	if((*msg)->hmac){
	    if((*msg)->hmac->buffer){
		pkg_free((*msg)->hmac->buffer);
	    }
	    pkg_free((*msg)->hmac);
	}
	if((*msg)->unknownAttributes){
	    if((*msg)->unknownAttributes->buffer){
		pkg_free((*msg)->unknownAttributes->buffer);
	    }
	    pkg_free((*msg)->unknownAttributes);
	}
	if((*msg)->errorReason){
	    if((*msg)->errorReason->buffer){
		pkg_free((*msg)->errorReason->buffer);
	    }
	    pkg_free((*msg)->errorReason);
	}

	/* StunMsg */
	pkg_free(*msg);
	*msg = NULL;
    }
}

void freeStunBuf(IN_OUT Buffer** buffer){
    if(*buffer){
	if((*buffer)->buffer){
	    pkg_free((*buffer)->buffer);
	}
	pkg_free(*buffer);
	*buffer = NULL;
    }
}



/* print */
void printStunAddr(StunAddr* addr){
    struct in_addr ip;
	UNUSED(ip);

    ip.s_addr = htonl(addr->ip4);

    LM_DBG("\t\t\tUnused = %02X\n", addr->unused);
    if(addr->family == 0x01){
	LM_DBG("\t\t\tFamily = %02X (IPv4)\n", addr->family);
    }else{
	LM_DBG("\t\t\tFamily = %02X\n", addr->family);
    }
    LM_DBG("\t\t\tPort = %hu\n", addr->port);
    LM_DBG("\t\t\tIPv4 = %s\n", inet_ntoa(ip));
}

void printStunMsg(StunMsg* msg){

    int	    i;
    char*   s;
    //char    s2[16];
    T16*    val;
	UNUSED(s);
	UNUSED(val);

    switch(msg->type){
	case BINDING_REQUEST:
	    s = "BINDING_REQUEST";
	    break;
	case BINDING_RESPONCE:
	    s = "BINDING_RESPONCE";
	    break;
	case BINDING_ERROR:
	    s = "BINDING_ERROR";
	    break;

	default:
	    s = "UNKNOWN_STUN_TYPE";
    }

    LM_DBG("\tType = %s\n", s);

    LM_DBG("\tLen = %i\n", msg->len);

    val = (T16*)msg->id;

    if(0x1234 == ntohs(0x3412)){
	LM_DBG("\tID = %04hX%04hX%04hX%04hX%04hX%04hX%04hX%04hX\n",
	    ntohs(val[0]),ntohs(val[1]),ntohs(val[2]),ntohs(val[3]),
	    ntohs(val[4]),ntohs(val[5]),ntohs(val[6]),ntohs(val[7]));
    }else{
	LM_DBG("\tID = %04hX%04hX%04hX%04hX%04hX%04hX%04hX%04hX\n",
	    val[0],val[1],val[2],val[3],
	    val[4],val[5],val[6],val[7]);
    }

    LM_DBG("\tAttributes:\n");

    if(msg->hasMappedAddress){
	LM_DBG("\t\tMAPPED_ADDRESS\n");
	printStunAddr(msg->mappedAddress);
    }

    if(msg->hasChangedAddress){
	LM_DBG("\t\tCHANGED_ADDRESS\n");
	printStunAddr(msg->changedAddress);
    }

    if(msg->hasSourceAddress){
	LM_DBG("\t\tSOURCE_ADDRESS\n");
	printStunAddr(msg->sourceAddress);
    }
    if(msg->hasResponceAddress){
	LM_DBG("\t\tRESPONCE_ADDRESS\n");
	printStunAddr(msg->responceAddress);
    }

    if(msg->hasChangeRequest){
	LM_DBG("\t\tCHANGE_REQUEST\n");
	if(msg->changeRequestFlags & CHANGE_IP)
	    LM_DBG("\t\t\tCHANGE_IP\n");
	if(msg->changeRequestFlags & CHANGE_PORT)
	    LM_DBG("\t\t\tCHANGE_PORT\n");
    }

    if(msg->hasXorMappedAddress){
	LM_DBG("\t\tXOR_MAPPED_ADDRESS\n");
	printStunAddr(msg->xorMappedAddress);
    }

    if(msg->hasReflectedFrom){
	LM_DBG("\t\tREFLECTED_FROM_ADDRESS\n");
	printStunAddr(msg->reflectedFromAddress);
    }

    if(msg->hasErrorCode){
	LM_DBG("\t\tERROR_CODE\n");
	if(msg->errorReason){
	    LM_DBG("\t\t\tCLASS = %u\n", msg->errorReason->buffer[2]);
	    LM_DBG("\t\t\tNUMBER = %u\n", msg->errorReason->buffer[3]);
	    LM_DBG("\t\t\tSTRING = %.*s\n", msg->errorReason->size - 4,
		    &(msg->errorReason->buffer[4]));
	}
    }

    if(msg->hasUnknownAttributes){
	LM_DBG("\t\tUNKNOWN_ATTRIBUTES\n");
	val = (T16*) msg->unknownAttributes->buffer;
	for(i=0; i< msg->unknownAttributes->size / sizeof(T16); i++){
	    LM_DBG("\t\t\tATTRIBUTE[%i] = %i\n", i, val[i]);
	}
    }
}

void print_hex(IN char* buffer, IN int size){
    int	    i;
    T16*    t16 = (T16*) buffer;
	UNUSED(t16);

    for(i=0; i<size/sizeof(T16); i++){
	LM_DBG("%04hX", ntohs(t16[i]));
    }
    LM_DBG("\n");
}

/**
 * @buf:        a "ip[ / advertised_ip]" type of string
 * @rcv_ip:     IP of a receiving interface (dot representation)
 * @rcv_ip_int: same as above (integer representation)
 * @adv_ip:     IP of an advertised interface (integer representation)
 */
static int parse_ip_modparam(char *buf, char **rcv_ip, int *rcv_ip_int,
                             int *adv_ip)
{
	char *p;
	str ip;

	p = strchr(buf, '/');

	if (p) {
		ip.s   = buf;
		ip.len = p - ip.s;
	} else {
		ip.s   = buf;
		ip.len = strlen(buf);
	}

	trim(&ip);

	if (p)
		ip.s[ip.len] = '\0';

	*rcv_ip = ip.s;

	if (inet_pton(AF_INET, ip.s, rcv_ip_int) < 1) {
		LM_ERR("Invalid ip %s : %s\n", ip.s, strerror(errno));
		return -1;
	}

	*rcv_ip_int = ntohl(*rcv_ip_int);

	LM_DBG("Parsed IP: %s %d\n", *rcv_ip, *rcv_ip_int);

	if (!p || !adv_ip)
		return 0;

	ip.s   = p + 1;
	ip.len = strlen(ip.s);
	trim(&ip);

	if (inet_pton(AF_INET, ip.s, adv_ip) < 1) {
		LM_ERR("Invalid advertised ip %s : %s\n", ip.s, strerror(errno));
		return -1;
	}

	*adv_ip = ntohl(*adv_ip);

	LM_DBG("Parsed advertised IP: %.*s %d\n", ip.len, ip.s, *adv_ip);

	return 0;
}

/**
 * @buf:        a "port[ / advertised_port]" type of string
 * @port:       STUN listening port
 * @adv_port:   STUN advertised port
 */
static int parse_port_modparam(char *buf, int *port, int *adv_port)
{
	char *p;
	str st;

	p = strchr(buf, '/');

	if (p) {
		st.s   = buf;
		st.len = p - buf;
	} else {
		st.s = buf;
		st.len = strlen(buf);
	}

	trim(&st);

	if (p)
		st.s[st.len] = '\0';

	*port = atoi(st.s);
	if (!(0 < *port && *port < 65536)) {
		LM_ERR("Invalid port %.*s\n", st.len, st.s);
		return -1;
	}

	LM_DBG("Parsed port: %d\n", *port);

	if (!p || !adv_port)
		return 0;

	st.s   = p + 1;
	st.len = strlen(st.s);
	trim(&st);

	*adv_port = atoi(st.s);
	if (!(0 < *adv_port && *adv_port < 65536)) {
		LM_ERR("Invalid port %.*s\n", st.len, st.s);
		return -1;
	}

	LM_DBG("Parsed advertised port: %d\n", *adv_port);

	return 0;
}

int parse_primary_ip(modparam_t type, void *val)
{
	return parse_ip_modparam(val, &primary_ip, &ip1, &adv_ip1);
}

int parse_primary_port(modparam_t type, void *val)
{
	return parse_port_modparam(val, &port1, &adv_port1);
}

int parse_alternate_ip(modparam_t type, void *val)
{
	return parse_ip_modparam(val, &alternate_ip, &ip2, &adv_ip2);
}

int parse_alternate_port(modparam_t type, void *val)
{
	return parse_port_modparam(val, &port2, &adv_port2);
}
