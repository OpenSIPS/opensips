/*
 * $Id$
 *
 * Copyright (C) 2001-2003 Fhg Fokus
 *
 * This file is part of ser, a free SIP server.
 *
 * ser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * For a license to use the ser software under conditions
 * other than those described here, or to purchase support for this
 * software, please contact iptel.org by e-mail at the following addresses:
 *    info@iptel.org
 *
 * ser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifdef USE_TCP

#include <sys/select.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>

#include <errno.h>
#include <string.h>



#include "ip_addr.h"
#include "pass_fd.h"
#include "globals.h"
#include "mem/mem.h"


#define local_malloc pkg_malloc
#define local_free   pkg_free

#define MAX_TCP_CHILDREN 100

struct tcp_child{
	pid_t pid;
	int s; /* unix socket for comm*/
	int busy;
	int n_reqs; /* number of requests serviced so far */
};


enum { CONN_OK, CONN_ERROR };

struct tcp_connection{
	int s; /*socket */
	struct ip_addr ip;
	union sockaddr_union su;
	int refcnt;
	struct tcp_connection* next;
	struct tcp_connection* prev;
};



struct tcp_connection* conn_list=0;
struct tcp_child tcp_children[MAX_TCP_CHILDREN];



struct tcp_connection*  tcpconn_add(int sock, union sockaddr_union* su)
{
	struct tcp_connection *c;
	

	c=(struct tcp_connection*)local_malloc(sizeof(struct tcp_connection));
	if (c==0){
		LOG(L_ERR, "ERROR: tcpconn_add: mem. allocation failure\n");
		goto error;
	}
	c->s=sock;
	c->su=*su;
	c->refcnt=0;
	su2ip_addr(&c->ip, su);

	/* add it at the begining of the list*/
	c->next=conn_list;
	c->prev=0;
	if (conn_list) conn_list->prev=c;
	conn_list=c;
	return c;
	
error:
	return 0;
}



void tcpconn_rm(struct tcp_connection* c)
{
	
	if (conn_list==c) conn_list=c->next;
	if (c->next) c->next->prev=c->prev;
	if (c->prev) c->prev->next=c->next;
	local_free(c);
}



int tcp_init_sock(struct socket_info* sock_info)
{
	union sockaddr_union* addr;
	
	addr=&sock_info->su;
	sock_info->proto=SOCKET_TCP;
	if (init_su(addr, &sock_info->address, htons(sock_info->port_no))<0){
		LOG(L_ERR, "ERROR: tcp_init: could no init sockaddr_union\n");
		goto error;
	}
	sock_info->socket=socket(AF2PF(addr->s.sa_family), SOCK_STREAM, 0);
	if (sock_info->socket==-1){
		LOG(L_ERR, "ERROR: tcp_init: socket: %s\n", strerror(errno));
		goto error;
	}
	if (bind(sock_info->socket, &addr->s, sockaddru_len(*addr))==-1){
		LOG(L_ERR, "ERROR: tcp_init: bind(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s, 
				sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		goto error;
	}
	if (listen(sock_info->socket, 10)==-1){
		LOG(L_ERR, "ERROR: tcp_init: listen(%x, %p, %d) on %s: %s\n",
				sock_info->socket, &addr->s, 
				sockaddru_len(*addr),
				sock_info->address_str.s,
				strerror(errno));
		goto error;
	}
	
	return 0;
error:
	if (sock_info->socket!=-1){
		close(sock_info->socket);
		sock_info->socket=-1;
	}
	return -1;
}



static int send2child(struct tcp_connection* tcpconn)
{
	int i;
	
	for (i=0; i<tcp_children_no; i++){
		if (!tcp_children[i].busy){
			tcp_children[i].busy=1;
			tcp_children[i].n_reqs++;
			tcpconn->refcnt++;
			DBG("send2child: to child %d, %ld\n", i, (long)tcpconn);
			send_fd(tcp_children[i].s, &tcpconn, sizeof(tcpconn), tcpconn->s);
			return 0;
		}
	}
	if (i==tcp_children_no){
		return -1;
	}
	return 0; /* just to fix a warning*/
}


void tcp_main_loop()
{
	int r;
	int n;
	fd_set master_set;
	fd_set sel_set;
	int maxfd;
	int new_sock;
	union sockaddr_union su;
	struct tcp_connection* tcpconn;
	long response[2];
	int state;
	int bytes;
	socklen_t su_len;

	/*init */
	maxfd=0;
	FD_ZERO(&master_set);
	/* set all the listen addresses */
	for (r=0; r<sock_no; r++){
		if ((tcp_info[r].proto==SOCKET_TCP) &&(tcp_info[r].socket!=-1)){
			FD_SET(tcp_info[r].socket, &master_set);
			if (tcp_info[r].socket>maxfd) maxfd=tcp_info[r].socket;
		}
	}
	/* set all the unix sockets used for child comm */
	for (r=0; r<tcp_children_no; r++){
		if (tcp_children[r].s>=0){
			FD_SET(tcp_children[r].s, &master_set);
			if (tcp_children[r].s>maxfd) maxfd=tcp_children[r].s;
		}
	}
	
	
	/* main loop*/
	
	while(1){
		sel_set=master_set;
		n=select(maxfd+1, &sel_set, 0 ,0 , 0);
		if (n<0){
			/* errors */
		}
		
		for (r=0; r<sock_no && n; r++){
			if ((tcp_info[r].proto==SOCKET_TCP) &&
					(FD_ISSET(tcp_info[r].socket, &sel_set))){
				/* got a connection on r */
				su_len=sizeof(su);
				new_sock=accept(tcp_info[r].socket, &(su.s), &su_len);
				n--;
				if (new_sock<0){
					LOG(L_ERR,  "WARNING: tcp_main_loop: error while accepting"
							" connection(%d): %s\n", errno, strerror(errno));
					continue;
				}
				
				/* add socket to list */
				tcpconn=tcpconn_add(new_sock, &su);
				DBG("tcp_main_loop: new connection: %p %d\n",
						tcpconn, tcpconn->s);
				/* pass it to a child */
				if(send2child(tcpconn)<0){
					LOG(L_ERR,"ERROR: tcp_main_loop: no children available\n");
					close(tcpconn->s);
					tcpconn_rm(tcpconn);
				}
			}
		}
		
		/* check all the read fds (from the tcpconn list) */
		
		for(tcpconn=conn_list; tcpconn && n; tcpconn=tcpconn->next){
			if ((tcpconn->refcnt==0)&&(FD_ISSET(tcpconn->s, &sel_set))){
				/* new data available */
				n--;
				/* pass it to child, so remove it from select list */
				DBG("tcp_main_loop: data available on %p %d\n",
						tcpconn, tcpconn->s);
				FD_CLR(tcpconn->s, &master_set);
				if (send2child(tcpconn)<0){
					LOG(L_ERR,"ERROR: tcp_main_loop: no children available\n");
					close(tcpconn->s);
					tcpconn_rm(tcpconn);
				}
			}
		}
		
		/* check unix sockets & listen | destroy connections */
		for (r=0; r<tcp_children_no && n; r++){
			if (FD_ISSET(tcp_children[r].s, &sel_set)){
				n--;
				/* errno==EINTR !!! TODO*/
read_again:
				bytes=read(tcp_children[r].s, response, sizeof(response));
				if (bytes==0){
					/* EOF -> bad, chidl has died */
					LOG(L_CRIT, "BUG: tcp_main_loop: dead child %d\n", r);
					/* terminating everybody */
					exit(-1);
				}else if (bytes<0){
					if (errno==EINTR) goto read_again;
					else{
						LOG(L_CRIT, "ERROR: tcp_main_loop: read from child: "
								" %s\n", strerror(errno));
						/* try to continue ? */
					}
				}
					
				DBG("tcp__main_loop: read response= %lx, %ld\n",
						response[0], response[1]);
				tcp_children[r].busy=0;
				tcpconn=(struct tcp_connection*)response[0];
				state=response[1];
				if (tcpconn){
					tcpconn->refcnt--;
					if (state>=0){
						/* listen on this too */
						if (tcpconn->refcnt==0){
							FD_SET(tcpconn->s, &master_set);
							if (maxfd<tcpconn->s) maxfd=tcpconn->s;
						}
					}else{
						/*error, we should destroy it */
						if (tcpconn->refcnt==0){
							DBG("tcp_main_loop: destroying connection\n");
							close(tcpconn->s);
							tcpconn_rm(tcpconn);
						}else{
							DBG("tcp_main_loop: delaying ...\n");
						}
					}
				}else{
					LOG(L_CRIT, "BUG: tcp_main_loop: null tcp conn pointer\n");
				}
			}
		}
	
	}
}



/* starts the tcp processes */
int tcp_main()
{
	int r;
	int sockfd[2];
	pid_t pid;
	
	
	/* create the tcp sock_info structures */
	/* copy the sockets*/
	for (r=0; r<sock_no ; r++){
		tcp_info[r]=sock_info[r];
		tcp_init_sock(&tcp_info[r]);
	}
	
	/* fork children & create the socket pairs*/
	for(r=0; r<tcp_children_no; r++){
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfd)<0){
			LOG(L_ERR, "ERROR: tcp_main: socketpair failed: %s\n",
					strerror(errno));
			goto error;
		}
		
		pid=fork();
		if (pid<0){
			LOG(L_ERR, "ERROR: tcp_main: fork failed: %s\n",
					strerror(errno));
			goto error;
		}else if (pid>0){
			/* parent */
			close(sockfd[1]);
			tcp_children[r].pid=pid;
			tcp_children[r].s=sockfd[0];
			tcp_children[r].busy=0;
			tcp_children[r].n_reqs=0;
		}else{
			/* child */
			close(sockfd[0]);
			tcp_receive_loop(sockfd[1]);
		}
	}
	
	tcp_main_loop();
error:
	return -1;
}

#endif
