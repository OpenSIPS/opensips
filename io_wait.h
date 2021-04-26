/*
 * Copyright (C) 2014-2015 OpenSIPS Solutions
 * Copyright (C) 2005 iptelorg GmbH
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
 *  2005-06-13  created by andrei
 *  2005-06-26  added kqueue (andrei)
 *  2005-07-01  added /dev/poll (andrei)
 *  2014-08-25  looping functions moved to io_wait_loop.h (bogdan)
 */

/*!
 * \file
 * \brief tcp io wait common stuff used by tcp_main.c & tcp_read.c
 * - \ref TCPiowait
 */

/*! \page TCPiowait TCP io wait common stuff used by tcp_main.c & tcp_read.c
 * All the functions are inline because of speed reasons and because they are
 * used only from 2 places.
 * You also have to define:
 *   -  int handle_io(struct fd_map* fm, int idx) (see below)
 *     (this could be trivially replaced by a callback pointer entry attached
 *      to the io_wait handler if more flexibility rather then performance
 *      is needed)
 *   -   fd_type - define to some enum of you choice and define also
 *                FD_TYPE_DEFINED (if you don't do it fd_type will be defined
 *                to int). 0 has a special not set/not init. meaning
 *                (a lot of sanity checks and the sigio_rt code are based on
 *                 this assumption)
 *   -  local_malloc (defaults to pkg_malloc)
 *   -  local_free   (defaults to pkg_free)
 *
 */


#ifndef _io_wait_h
#define _io_wait_h

#include <errno.h>
#include <string.h>
#ifdef HAVE_SIGIO_RT
#define __USE_GNU /* or else F_SETSIG won't be included */
#define _GNU_SOURCE /* define this as well */
#include <sys/types.h> /* recv */
#include <sys/socket.h> /* recv */
#include <signal.h> /* sigprocmask, sigwait a.s.o */
#endif
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif
#ifdef HAVE_KQUEUE
#include <sys/types.h> /* needed on freebsd */
#include <sys/event.h>
#include <sys/time.h>
#endif
#ifdef HAVE_DEVPOLL
#include <sys/devpoll.h>
#endif
#ifdef HAVE_SELECT
/* needed on openbsd for select*/
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
/* needed according to POSIX for select*/
#include <sys/select.h>
#endif
#include <sys/poll.h>
#include <fcntl.h>

#include "dprint.h"

#include "poll_types.h" /* poll_types*/
#include "pt.h" /* mypid() */
#include "error.h"

#ifdef __OS_linux
#include <features.h>     /* for GLIBC version testing */
#endif

#ifndef FD_TYPE_DEFINED
typedef int fd_type;
#define FD_TYPE_DEFINED
#endif

/*! \brief maps a fd to some other structure; used in almost all cases
 * except epoll and maybe kqueue or /dev/poll */
struct fd_map {
	int fd;               /* fd no */
	fd_type type;         /* "data" type */
	void* data;           /* pointer to the corresponding structure */
	int flags;            /* so far used to indicate whether we should 
	                       * read, write or both ; last 4 are reserved for 
	                       * internal usage */
	int app_flags;        /* flags to be used by upper layer apps, not by
	                       * the reactor */
	unsigned int timeout;
};


#ifdef HAVE_KQUEUE
#ifndef KQ_CHANGES_ARRAY_SIZE
#define KQ_CHANGES_ARRAY_SIZE 128

#ifdef __OS_netbsd
#define KEV_UDATA_CAST (intptr_t)
#else
#define KEV_UDATA_CAST
#endif

#endif
#endif


#define IO_FD_CLOSING 16

/*! \brief handler structure */
struct io_wait_handler{
	char *name;
	int max_prio;
#ifdef HAVE_EPOLL
	struct epoll_event* ep_array;
	int epfd; /* epoll ctrl fd */
#endif
#ifdef HAVE_SIGIO_RT
	sigset_t sset; /* signal mask for sigio & sigrtmin */
	int signo;     /* real time signal used */
#endif
#ifdef HAVE_KQUEUE
	struct kevent* kq_array;   /* used for the eventlist*/
	struct kevent* kq_changes; /* used for the changelist */
	size_t kq_nchanges;
	size_t kq_changes_size; /* size of the changes array */
	int kq_fd;
#endif
#ifdef HAVE_DEVPOLL
	int dpoll_fd;
	struct pollfd* dp_changes;
#endif
#ifdef HAVE_SELECT
	fd_set master_set;
	int max_fd_select; /* maximum select used fd */
#endif
	/* common stuff for POLL, SIGIO_RT and SELECT
	 * since poll support is always compiled => this will always be compiled */
	int *prio_idx; /* size of max_prio - idxs in fd_array where prio changes*/
	struct fd_map* fd_hash;
	struct pollfd* fd_array;
	int fd_no; /*  current index used in fd_array */
	int max_fd_no; /* maximum fd no, is also the size of fd_array,
						       fd_hash  and ep_array*/
	enum poll_types poll_method;
	int flags;
};

typedef struct io_wait_handler io_wait_h;


/*! \brief get the corresponding fd_map structure pointer */
#define get_fd_map(h, fd)		(&(h)->fd_hash[(fd)])

/*! \brief remove a fd_map structure from the hash;
 * the pointer must be returned by get_fd_map or hash_fd_map
 */
#define unhash_fd_map(pfm,c_flags,sock_flags,erase)	\
	do{ \
		if ((c_flags & IO_FD_CLOSING) || pfm->flags == sock_flags) { \
			(pfm)->type=0 /*F_NONE */; \
			(pfm)->fd=-1; \
			(pfm)->flags = 0; \
			(pfm)->data = NULL; \
			erase = 1; \
		} else { \
			(pfm)->flags &= ~sock_flags; \
			erase = 0; \
		} \
	}while(0)

/*! \brief add a fd_map structure to the fd hash */
static inline struct fd_map* hash_fd_map(	io_wait_h* h,
						int fd,
						fd_type type,
						void* data,
						int flags,
						unsigned int timeout,
						int *already)
{
	if (h->fd_hash[fd].fd <= 0) {
		*already = 0;
	} else {
		*already = 1;
	}

	h->fd_hash[fd].fd=fd;
	h->fd_hash[fd].type=type;
	h->fd_hash[fd].data=data;

	h->fd_hash[fd].flags|=flags;

	h->fd_hash[fd].timeout = timeout;

	return &h->fd_hash[fd];
}


#ifdef HAVE_KQUEUE
/*
 * kqueue specific function: register a change
 * (adds a change to the kevent change array, and if full flushes it first)
 * returns: -1 on error, 0 on success
 */
static inline int kq_ev_change(io_wait_h* h, int fd, int filter, int flag,
								void* data)
{
	int n;
	struct timespec tspec;

	if (h->kq_nchanges>=h->kq_changes_size){
		/* changes array full ! */
		LM_WARN("[%s] kqueue changes array full trying to flush...\n",
			h->name);
		tspec.tv_sec=0;
		tspec.tv_nsec=0;
again:
		n=kevent(h->kq_fd, h->kq_changes, h->kq_nchanges, 0, 0, &tspec);
		if (n==-1){
			if (errno==EINTR) goto again;
			LM_ERR("[%s] kevent flush changes failed: %s [%d]\n",
				h->name, strerror(errno), errno);
			return -1;
		}
		h->kq_nchanges=0; /* changes array is empty */
	}
	EV_SET(&h->kq_changes[h->kq_nchanges], fd, filter, flag, 0, 0,
			KEV_UDATA_CAST data);
	h->kq_nchanges++;
	return 0;
}
#endif


#define IO_WATCH_READ            (1<<0)
#define IO_WATCH_WRITE           (1<<1)
#define IO_WATCH_ERROR           (1<<2)
#define IO_WATCH_TIMEOUT         (1<<3)
/* reserved, do not attempt to use */
#define IO_WATCH_PRV_CHECKED     (1<<29)
#define IO_WATCH_PRV_TRIG_READ   (1<<30)
#define IO_WATCH_PRV_TRIG_WRITE  (1<<31)

#define fd_array_print \
	do { \
		int k;\
		LM_DBG("[%s] size=%d, fd array is",h->name,h->fd_no);\
		for(k=0;k<h->fd_no;k++) LM_GEN1(L_DBG," %d flags = %d",h->fd_array[k].fd,h->fd_hash[h->fd_array[k].fd].flags);\
		LM_GEN1(L_DBG,"\n"); \
		LM_DBG("[%s] size=%d, prio array is",h->name,h->max_prio);\
		for(k=0;k<h->max_prio;k++) LM_GEN1(L_DBG," %d",h->prio_idx[k]);\
		LM_GEN1(L_DBG,"\n"); \
	}while(0)


#define check_io_data() \
	do { \
		struct fd_map* _e;\
		int _t,k;\
		check_error = 0;\
		/* iterate the fd_array and check if fd_hash is properly set for each */ \
		for(k=0;k<h->fd_no;k++) {\
			_e = get_fd_map(h, h->fd_array[k].fd); \
			if (_e->type==0 || _e->fd<=0 || \
			(_e->flags&(IO_WATCH_READ|IO_WATCH_WRITE))==0 ) {\
				LM_BUG("fd_array idx %d (fd=%d) points to bogus map "\
					"(fd=%d,type=%d,flags=%x,data=%p)\n",k,h->fd_array[k].fd,\
					_e->fd, _e->type, _e->flags, _e->data);\
					check_error = 1;\
			}\
			_e->flags |= IO_WATCH_PRV_CHECKED;\
		}\
		/* iterate the fd_map and see if all records are checked */ \
		_t = 0; \
		for(k=0;k<h->max_fd_no;k++) {\
			_e = get_fd_map(h, k); \
			if (_e->type==0) { \
				/* fd not in used, everything should be on zero */ \
				if (_e->fd>0 || _e->data!=NULL || _e->flags!=0 ) {\
					LM_BUG("unused fd_map fd=%d has bogus data "\
					"(fd=%d,flags=%x,data=%p)\n",k,\
					_e->fd, _e->flags, _e->data);\
					check_error = 1;\
				}\
			} else {\
				/* fd in used, check if in checked */ \
				if (_e->fd<=0 || \
				(_e->flags&(IO_WATCH_READ|IO_WATCH_WRITE))==0 ) {\
				LM_BUG("used fd map fd=%d has bogus data "\
					"(fd=%d,type=%d,flags=%x,data=%p)\n",k,\
					_e->fd, _e->type, _e->flags, _e->data);\
					check_error = 1;\
				}\
				/* the map is valid */ \
				if ((_e->flags&IO_WATCH_PRV_CHECKED)==0) {\
					LM_BUG("used fd map fd=%d is not present in fd_array "\
						"(fd=%d,type=%d,flags=%x,data=%p)\n",k,\
						_e->fd, _e->type, _e->flags, _e->data);\
						check_error = 1;\
				}\
				_e->flags &= ~IO_WATCH_PRV_CHECKED;\
				_t++;\
			}\
		}\
		if (_t!=h->fd_no) { \
			LM_BUG("fd_map versus fd_array size mismatch: %d versus %d\n",\
				_t, h->fd_no);\
			check_error = 1;\
		}\
	} while(0)


/*! \brief generic io_watch_add function
 * \return 0 on success, -1 on error
 *
 * this version should be faster than pointers to poll_method specific
 * functions (it avoids functions calls, the overhead being only an extra
 *  switch())
*/
inline static int io_watch_add(	io_wait_h* h, // lgtm [cpp/use-of-goto]
								int fd,
								fd_type type,
								void* data,
								int prio,
								unsigned int timeout,
								int flags)
{

	/* helper macros */
#define fd_array_setup \
	do{ \
		n = h->prio_idx[prio]; \
		if (n<h->fd_no)\
			memmove( &h->fd_array[n+1], &h->fd_array[n],\
				(h->fd_no-n)*sizeof(*(h->fd_array)) ); \
		h->fd_array[n].fd=fd; \
		h->fd_array[n].events=0; \
		if (flags & IO_WATCH_READ) \
			h->fd_array[n].events|=POLLIN; /* useless for select */ \
		if (flags & IO_WATCH_WRITE) \
			h->fd_array[n].events|=POLLOUT; /* useless for select */ \
		h->fd_array[n].revents=0;     /* useless for select */ \
		for( n=prio ; n<h->max_prio ; n++) \
			h->prio_idx[n]++; \
		h->fd_no++; \
	}while(0)

#define set_fd_flags(f) \
	do{ \
			ctl_flags=fcntl(fd, F_GETFL); \
			if (ctl_flags==-1){ \
				LM_ERR("[%s] fcntl: GETFL failed:" \
					" %s [%d]\n", h->name, strerror(errno), errno); \
				goto error; \
			} \
			if (fcntl(fd, F_SETFL, ctl_flags|(f))==-1){ \
				LM_ERR("[%s] fcntl: SETFL" \
					" failed: %s [%d]\n", h->name, strerror(errno), errno);\
				goto error; \
			} \
	}while(0)


	struct fd_map* e;
	int already=-1;
#ifdef HAVE_EPOLL
	struct epoll_event ep_event;
#endif
#ifdef HAVE_DEVPOLL
	struct pollfd pfd;
#endif
	int ctl_flags;
	int n;  //FIXME
	int check_error;
#if 0 //defined(HAVE_SIGIO_RT) || defined (HAVE_EPOLL) FIXME
	int n;
	int idx;
	int check_io;
	struct pollfd pf;

	check_io=0; /* set to 1 if we need to check for pre-existing queued
				   io/data on the fd */
	idx=-1;
#endif
	e=0;

	if (fd==-1){
		LM_CRIT("fd is -1!\n");
		goto error0;
	}
	/* check if not too big */
	if (h->fd_no >= h->max_fd_no || fd >= h->max_fd_no) {
		LM_CRIT("[%s] maximum fd number exceeded: %d, %d/%d\n",
			h->name, fd, h->fd_no, h->max_fd_no);
		goto error0;
	}
	if (prio > h->max_prio) {
		LM_BUG("[%s] priority %d requested (max is %d)\n",
			h->name, prio, h->max_prio);
		goto error0;
	}
#if defined (HAVE_EPOLL)
	LM_DBG("[%s] io_watch_add op (%d on %d) (%p, %d, %d, %p,%d), fd_no=%d/%d\n",
			h->name,fd,h->epfd, h,fd,type,data,flags,h->fd_no,h->max_fd_no);
#else
	LM_DBG("[%s] io_watch_add op (%d) (%p, %d, %d, %p,%d), fd_no=%d/%d\n",
			h->name,fd, h,fd,type,data,flags,h->fd_no,h->max_fd_no);
#endif
	//fd_array_print;
	/*  hash sanity check */
	e=get_fd_map(h, fd);

	if (e->flags & flags){
		if (e->data != data) {
			LM_BUG("[%s] BUG trying to overwrite entry %d"
					" in the hash(%d, %d, %p,%d) with (%d, %d, %p,%d)\n",
					h->name,fd, e->fd, e->type, e->data,e->flags, fd, type, data,flags);
			goto error0;
		}
		LM_DBG("[%s] Socket %d is already being listened on for flags %d\n",
			   h->name,fd,flags);
		return 0;
	}

	if (timeout)
		timeout+=get_ticks();

	if ((e=hash_fd_map(h, fd, type, data,flags, timeout, &already))==0){
		LM_ERR("[%s] failed to hash the fd %d\n",h->name, fd);
		goto error0;
	}
	switch(h->poll_method){ /* faster then pointer to functions */
		case POLL_POLL:
			set_fd_flags(O_NONBLOCK);
			break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			FD_SET(fd, &h->master_set);
			if (h->max_fd_select<fd) h->max_fd_select=fd;
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			/* re-set O_ASYNC might be needed, if not done from
			 * io_watch_del (or if somebody wants to add a fd which has
			 * already O_ASYNC/F_SETSIG set on a dupplicate)
			 */
			/* set async & signal */
			if (fcntl(fd, F_SETOWN, my_pid())==-1){
				LM_ERR("[%s] fcntl: SETOWN"
				" failed: %s [%d]\n",h->name, strerror(errno), errno);
				goto error;
			}
			if (fcntl(fd, F_SETSIG, h->signo)==-1){
				LM_ERR("[%s] fcntl: SETSIG"
					" failed: %s [%d]\n",h->name, strerror(errno), errno);
				goto error;
			}
			/* set both non-blocking and async */
			set_fd_flags(O_ASYNC| O_NONBLOCK);
#ifdef EXTRA_DEBUG
			LM_DBG("[%s] sigio_rt on f %d, signal %d to pid %d\n",
					h->name,fd,  h->signo, my_pid());
#endif
			/* empty socket receive buffer, if buffer is already full
			 * no more space to put packets
			 * => no more signals are ever generated
			 * also when moving fds, the freshly moved fd might have
			 *  already some bytes queued, we want to get them now
			 *  and not later -- andrei */
			//idx=h->fd_no;  FIXME
			//check_io=1;
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL:
			ep_event.data.ptr=e;
			ep_event.events=0;
			if (e->flags & IO_WATCH_READ)
				ep_event.events|=EPOLLIN;
			if (e->flags & IO_WATCH_WRITE)
				ep_event.events|=EPOLLOUT;
			if (!already) {
again1:
#if 0
/* This is currently broken, because when using EPOLLEXCLUSIVE, the OS will
 * send sequential events to the same process - thus our pseudo-dispatcher
 * will no longer work, since events on a pipe will be queued by a single
 * process. - razvanc
 */
#if (defined __OS_linux) && (__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 24)
				if (e->flags & IO_WATCH_READ)
					ep_event.events|=EPOLLEXCLUSIVE;
#endif
#endif
				n=epoll_ctl(h->epfd, EPOLL_CTL_ADD, fd, &ep_event);
				if (n==-1){
					if (errno==EAGAIN) goto again1;
					LM_ERR("[%s] epoll_ctl ADD failed: %s [%d]\n",
						h->name,strerror(errno), errno);
					goto error;
				}
			} else {
again11:
				n=epoll_ctl(h->epfd, EPOLL_CTL_MOD, fd, &ep_event);
				if (n==-1){
					if (errno==EAGAIN) goto again11;
					LM_ERR("[%s] epoll_ctl MOD failed: %s [%d]\n",
						h->name,strerror(errno), errno);
					goto error;
				}
			}
			break;
#endif
#ifdef HAVE_KQUEUE
		case POLL_KQUEUE:
			if (kq_ev_change(h, fd, EVFILT_READ, EV_ADD, e)==-1)
				goto error;
			break;
#endif
#ifdef HAVE_DEVPOLL
		case POLL_DEVPOLL:
			pfd.fd=fd;
			pfd.events=POLLIN;
			pfd.revents=0;
again_devpoll:
			if (write(h->dpoll_fd, &pfd, sizeof(pfd))==-1){
				if (errno==EAGAIN) goto again_devpoll;
				LM_ERR("[%s] /dev/poll write failed:"
					"%s [%d]\n",h->name, strerror(errno), errno);
				goto error;
			}
			break;
#endif

		default:
			LM_CRIT("[%s] no support for poll method "
				" %s (%d)\n",h->name, poll_method_str[h->poll_method],
				h->poll_method);
			goto error;
	}

	if (!already) {
		fd_array_setup;
	}

#if 0 //defined(HAVE_SIGIO_RT) || defined (HAVE_EPOLL) FIXME !!!
	if (check_io){
		/* handle possible pre-existing events */
		pf.fd=fd;
		pf.events=POLLIN;
check_io_again:
		while( ((n=poll(&pf, 1, 0))>0) && (handle_io(e, idx,IO_WATCH_READ)>0));
		if (n==-1){
			if (errno==EINTR) goto check_io_again;
			LM_ERR("check_io poll: %s [%d]\n",
						strerror(errno), errno);
		}
	}
#endif
	//fd_array_print;
	check_io_data();
	if (check_error) {
		LM_CRIT("[%s] check failed after successful fd add "
			"(fd=%d,type=%d,data=%p,flags=%x) already=%d\n",h->name,
			fd, type, data, flags, already);
	}
	return 0;
error:
	if (e) unhash_fd_map(e,0,flags,already);
error0:
	check_io_data();
	if (check_error) {
		LM_CRIT("[%s] check failed after failed fd add "
			"(fd=%d,type=%d,data=%p,flags=%x) already=%d\n",h->name,
			fd, type, data, flags, already);
	}
	return -1;
#undef fd_array_setup
#undef set_fd_flags
}



/*!
 * \brief
 * \param h handler
 * \param fd file descriptor
 * \param idx index in the fd_array if known, -1 if not
 *                    (if index==-1 fd_array will be searched for the
 *                     corresponding fd* entry -- slower but unavoidable in
 *                     some cases). index is not used (no fd_array) for epoll,
 *                     /dev/poll and kqueue
 * \param flags optimization flags, e.g. IO_FD_CLOSING, the fd was or will
 *                    shortly be closed, in some cases we can avoid extra
 *                    remove operations (e.g.: epoll, kqueue, sigio)
 * \return 0 if ok, -1 on error
 */
inline static int io_watch_del(io_wait_h* h, int fd, int idx,
					int flags,int sock_flags)
{
#define fix_fd_array \
	do{\
			if (idx==-1){ \
				/* fix idx if -1 and needed */ \
				for (idx=0; (idx<h->fd_no) && \
							(h->fd_array[idx].fd!=fd); idx++); \
			} \
			if (idx<h->fd_no){ \
				if (erase) { \
					memmove(&h->fd_array[idx], &h->fd_array[idx+1], \
						(h->fd_no-(idx+1))*sizeof(*(h->fd_array))); \
					for( i=0 ; i<h->max_prio && h->prio_idx[i]<=idx ; i++ ); \
					for( ; i<h->max_prio ; i++ ) h->prio_idx[i]-- ; \
					h->fd_no--; \
				} else { \
					h->fd_array[idx].events = 0; \
					if (e->flags & IO_WATCH_READ) \
						h->fd_array[idx].events|=POLLIN; /* useless for select */ \
					if (flags & IO_WATCH_WRITE) \
						h->fd_array[idx].events|=POLLOUT; /* useless for select */ \
					h->fd_array[idx].revents = 0; \
				} \
			} \
	}while(0)

	struct fd_map* e;
#ifdef HAVE_EPOLL
	int n;
	struct epoll_event ep_event;
#endif
#ifdef HAVE_DEVPOLL
	struct pollfd pfd;
#endif
#ifdef HAVE_SIGIO_RT
	int fd_flags;
#endif
	int erase = 0;
	int check_error;
	int i;

	if ((fd<0) || (fd>=h->max_fd_no)){
		LM_CRIT("[%s] invalid fd %d, not in [0, %d)\n", h->name, fd, h->fd_no);
		goto error0;
	}
	LM_DBG("[%s] io_watch_del op on index %d %d (%p, %d, %d, 0x%x,0x%x) "
		"fd_no=%d called\n", h->name,idx,fd, h, fd, idx, flags,
		sock_flags,h->fd_no);
	//fd_array_print;

	e=get_fd_map(h, fd);
	/* more sanity checks */
	if (e==0){
		LM_CRIT("[%s] no corresponding hash entry for %d\n",h->name, fd);
		goto error0;
	}
	if (e->type==0 /*F_NONE*/){
		LM_ERR("[%s] trying to delete already erased"
				" entry %d in the hash(%d, %d, %p) )\n",
				h->name,fd, e->fd, e->type, e->data);
		goto error0;
	}

	if ((e->flags & sock_flags) == 0) {
		LM_ERR("BUG - [%s] trying to del fd %d with flags %d %d\n",
			h->name, fd, e->flags,sock_flags);
		goto error0;
	}

	unhash_fd_map(e,flags,sock_flags,erase);

	switch(h->poll_method){
		case POLL_POLL:
			break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			FD_CLR(fd, &h->master_set);
			if (h->max_fd_select && (h->max_fd_select==fd))
				/* we don't know the prev. max, so we just decrement it */
				h->max_fd_select--;
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			/* the O_ASYNC flag must be reset all the time, the fd
			 *  can be changed only if  O_ASYNC is reset (if not and
			 *  the fd is a duplicate, you will get signals from the dup. fd
			 *  and not from the original, even if the dup. fd was closed
			 *  and the signals re-set on the original) -- andrei
			 */
			/*if (!(flags & IO_FD_CLOSING)){*/
				/* reset ASYNC */
				fd_flags=fcntl(fd, F_GETFL);
				if (fd_flags==-1){
					LM_ERR("[%s] fcntl: GETFL failed:"
						" %s [%d]\n",h->name, strerror(errno), errno);
					goto error;
				}
				if (fcntl(fd, F_SETFL, fd_flags&(~O_ASYNC))==-1){
					LM_ERR("[%s] fcntl: SETFL"
						" failed: %s [%d]\n",h->name, strerror(errno), errno);
					goto error;
				}
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL:
			/* epoll doesn't seem to automatically remove sockets,
			 * if the socket is a dupplicate/moved and the original
			 * is still open. The fd is removed from the epoll set
			 * only when the original (and all the  copies?) is/are
			 * closed. This is probably a bug in epoll. --andrei */
#ifdef EPOLL_NO_CLOSE_BUG
			if (!(flags & IO_FD_CLOSING)){
#endif
				if (erase) {
					n=epoll_ctl(h->epfd, EPOLL_CTL_DEL, fd, &ep_event);
					/*
					 * in some cases (fds managed by external libraries),
					 * the fd may have already been closed
					 */
					if (n==-1 && errno != EBADF && errno != ENOENT) {
						LM_ERR("[%s] removing fd from epoll (%d from %d) "
							"list failed: %s [%d]\n",h->name, fd, h->epfd,
							strerror(errno), errno);
						goto error;
					}
				} else {
					ep_event.data.ptr=e;
					ep_event.events=0;
					if (e->flags & IO_WATCH_READ)
						ep_event.events|=EPOLLIN;
					if (e->flags & IO_WATCH_WRITE)
						ep_event.events|=EPOLLOUT;
					n=epoll_ctl(h->epfd, EPOLL_CTL_MOD, fd, &ep_event);
					if (n==-1){
						LM_ERR("[%s] epoll_ctl failed: %s [%d]\n",
							h->name,strerror(errno), errno);
						goto error;
					}
				}
#ifdef EPOLL_NO_CLOSE_BUG
			}
#endif
			break;
#endif
#ifdef HAVE_KQUEUE
		case POLL_KQUEUE:
			if (!(flags & IO_FD_CLOSING)){
				if (kq_ev_change(h, fd, EVFILT_READ, EV_DELETE, 0)==-1)
					goto error;
			}
			break;
#endif
#ifdef HAVE_DEVPOLL
		case POLL_DEVPOLL:
				/* for /dev/poll the closed fds _must_ be removed
				   (they are not removed automatically on close()) */
				pfd.fd=fd;
				pfd.events=POLLREMOVE;
				pfd.revents=0;
again_devpoll:
				if (write(h->dpoll_fd, &pfd, sizeof(pfd))==-1){
					if (errno==EINTR) goto again_devpoll;
					LM_ERR("[%s] removing fd from /dev/poll failed: "
						"%s [%d]\n",h->name, strerror(errno), errno);
					goto error;
				}
				break;
#endif
		default:
			LM_CRIT("[%s] no support for poll method %s (%d)\n",
				h->name,poll_method_str[h->poll_method], h->poll_method);
			goto error;
	}

	fix_fd_array;
	//fd_array_print;

	check_io_data();
	if (check_error) {
		LM_CRIT("[%s] check failed after successful fd del "
			"(fd=%d,flags=%d, sflags=%d) over map "
			"(fd=%d,type=%d,data=%p,flags=%d) erase=%d\n",h->name,
			fd, flags, sock_flags,
			e->fd, e->type, e->data, e->flags,
			erase);
	}

	return 0;
error:
	/*
	 * although the DEL operation failed, both
	 * "fd_hash" and "fd_array" must remain consistent
	 */
	fix_fd_array;

	check_io_data();
	if (check_error) {
		LM_CRIT("[%s] check failed after failed fd del "
			"(fd=%d,flags=%d, sflags=%d) over map "
			"(fd=%d,type=%d,data=%p,flags=%d) erase=%d\n",h->name,
			fd, flags, sock_flags,
			e->fd, e->type, e->data, e->flags,
			erase);
	}
error0:

	return -1;
#undef fix_fd_array
}


/* init */


/*! \brief initializes the static vars/arrays
 * \param h pointer to the io_wait_h that will be initialized
 * \param max_fd maximum allowed fd number
 * \param poll_method poll method (0 for automatic best fit)
 */
int init_io_wait(io_wait_h* h, char *name, int max_fd,
								enum poll_types poll_method, int max_prio);

/*! \brief destroys everything init_io_wait allocated */
void destroy_io_wait(io_wait_h* h);

int io_set_app_flag( io_wait_h *h , int type, int app_flag);

int io_check_app_flag( io_wait_h *h , int app_flag);


#endif
