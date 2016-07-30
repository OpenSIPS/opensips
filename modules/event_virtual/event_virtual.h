#ifndef _EV_VIRTUAL_H_
#define _EV_VIRTUAL_H_

#include "../../str.h"
#include "../../evi/evi_transport.h"

#define VIRT_NAME	"virtual"
#define VIRT_STR	{ VIRT_NAME, sizeof(VIRT_NAME) - 1}
#define VIRT_FLAG	(1<<24)

#define PARALLEL_TYPE 0
#define PARALLEL_STR "PARALLEL"
#define PARALLEL_LEN 8
#define FAILOVER_TYPE 1
#define FAILOVER_STR "FAILOVER"
#define FAILOVER_LEN 8
#define RROBIN_TYPE 2
#define RROBIN_STR 	"ROUND-ROBIN"
#define RROBIN_LEN 11

#define SEP_SPACE	' '
#define SEP_TAB		'\t'

struct virtual_socket {
	unsigned int type;
	unsigned int nr_sockets;
	struct sub_socket *current_sock;	/* current socket to raise */
	struct sub_socket *list_sockets;	/* list of actual sockets */
	struct virtual_socket *next;
	struct virtual_socket *prev;
};

struct sub_socket {
	str sock_str;
	evi_export_t *trans_mod;
	evi_reply_sock *sock;
	struct sub_socket *next;
};

#endif