/*
 * $Id$
 */

#ifndef udp_server_h
#define udp_server_h



extern int udp_sock;

extern char* our_name;
extern unsigned long  our_address;
extern unsigned short our_port;

int udp_init(unsigned long ip, unsigned short port);
int udp_rcv_loop();


#endif
