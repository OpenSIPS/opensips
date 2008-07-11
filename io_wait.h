/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2005-06-13  created by andrei
 *  2005-06-26  added kqueue (andrei)
 *  2005-07-01  added /dev/poll (andrei)
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
#ifdef HAVE_SIGIO_RT
#include "pt.h" /* mypid() */
#endif


#if 0
enum fd_types; /* this should be defined from the including file,
				  see tcp_main.c for an example, 
				  0 has a special meaning: not used/empty*/
#endif

#ifndef FD_TYPE_DEFINED
typedef int fd_type;
#define FD_TYPE_DEFINED
#endif

/*! \brief maps a fd to some other structure; used in almost all cases
 * except epoll and maybe kqueue or /dev/poll */
struct fd_map{
	int fd;               /* fd no */
	fd_type type;         /* "data" type */
	void* data;           /* pointer to the corresponding structure */
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


/*! \brief handler structure */
struct io_wait_handler{
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
#endif
#ifdef HAVE_SELECT
	fd_set master_set;
	int max_fd_select; /* maximum select used fd */
#endif
	/* common stuff for POLL, SIGIO_RT and SELECT
	 * since poll support is always compiled => this will always be compiled */
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
#define unhash_fd_map(pfm)	\
	do{ \
		(pfm)->type=0 /*F_NONE */; \
		(pfm)->fd=-1; \
	}while(0)

/*! \brief add a fd_map structure to the fd hash */
static inline struct fd_map* hash_fd_map(	io_wait_h* h,
						int fd,
						fd_type type,
						void* data)
{
	h->fd_hash[fd].fd=fd;
	h->fd_hash[fd].type=type;
	h->fd_hash[fd].data=data;
	return &h->fd_hash[fd];
}



#ifdef HANDLE_IO_INLINE
/*!\brief generic handle io routine
 * this must be defined in the including file
 * (faster then registering a callback pointer)
 *
 * \param fm pointer to a fd hash entry
 * \param idx index in the fd_array (or -1 if not known)
 * \return return: -1 on error
 *          0 on EAGAIN or when by some other way it is known that no more 
 *            io events are queued on the fd (the receive buffer is empty).
 *            Usefull to detect when there are no more io events queued for
 *            sigio_rt, epoll_et, kqueue.
 *         >0 on successfull read from the fd (when there might be more io
 *            queued -- the receive buffer might still be non-empty)
 */
inline static int handle_io(struct fd_map* fm, int idx);
#else
static int handle_io(struct fd_map* fm, int idx) {
	return 0;
}
#endif



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
		LM_WARN("kqueue changes array full trying to flush...\n");
		tspec.tv_sec=0;
		tspec.tv_nsec=0;
again:
		n=kevent(h->kq_fd, h->kq_changes, h->kq_nchanges, 0, 0, &tspec);
		if (n==-1){
			if (errno==EINTR) goto again;
			LM_ERR("kevent flush changes failed: %s [%d]\n", 
				strerror(errno), errno);
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



/*! \brief generic io_watch_add function
 * \return 0 on success, -1 on error
 *
 * this version should be faster than pointers to poll_method specific
 * functions (it avoids functions calls, the overhead being only an extra
 *  switch())
*/
inline static int io_watch_add(	io_wait_h* h,
								int fd,
								fd_type type,
								void* data)
{

	/* helper macros */
#define fd_array_setup \
	do{ \
		h->fd_array[h->fd_no].fd=fd; \
		h->fd_array[h->fd_no].events=POLLIN; /* useless for select */ \
		h->fd_array[h->fd_no].revents=0;     /* useless for select */ \
	}while(0)
	
#define set_fd_flags(f) \
	do{ \
			flags=fcntl(fd, F_GETFL); \
			if (flags==-1){ \
				LM_ERR("fnctl: GETFL failed:" \
						" %s [%d]\n", strerror(errno), errno); \
				goto error; \
			} \
			if (fcntl(fd, F_SETFL, flags|(f))==-1){ \
				LM_ERR("fnctl: SETFL" \
							" failed: %s [%d]\n", strerror(errno), errno); \
				goto error; \
			} \
	}while(0)
	
	
	struct fd_map* e;
	int flags;
#ifdef HAVE_EPOLL
	struct epoll_event ep_event;
#endif
#ifdef HAVE_DEVPOLL
	struct pollfd pfd;
#endif
#if defined(HAVE_SIGIO_RT) || defined (HAVE_EPOLL)
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
		goto error;
	}
	/* check if not too big */
	if (h->fd_no>=h->max_fd_no){
		LM_CRIT("maximum fd number exceeded:"
				" %d/%d\n", h->fd_no, h->max_fd_no);
		goto error;
	}
	LM_DBG("io_watch_add(%p, %d, %d, %p), fd_no=%d\n",
			h, fd, type, data, h->fd_no);
	/*  hash sanity check */
	e=get_fd_map(h, fd);
	if (e && (e->type!=0 /*F_NONE*/)){
		LM_ERR("trying to overwrite entry %d"
				" in the hash(%d, %d, %p) with (%d, %d, %p)\n",
				fd, e->fd, e->type, e->data, fd, type, data);
		goto error;
	}
	
	if ((e=hash_fd_map(h, fd, type, data))==0){
		LM_ERR("failed to hash the fd %d\n", fd);
		goto error;
	}
	switch(h->poll_method){ /* faster then pointer to functions */
		case POLL_POLL:
			fd_array_setup;
			set_fd_flags(O_NONBLOCK);
			break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			fd_array_setup;
			FD_SET(fd, &h->master_set);
			if (h->max_fd_select<fd) h->max_fd_select=fd;
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			fd_array_setup;
			/* re-set O_ASYNC might be needed, if not done from 
			 * io_watch_del (or if somebody wants to add a fd which has
			 * already O_ASYNC/F_SETSIG set on a dupplicate)
			 */
			/* set async & signal */
			if (fcntl(fd, F_SETOWN, my_pid())==-1){
				LM_ERR("fnctl: SETOWN"
				" failed: %s [%d]\n", strerror(errno), errno);
				goto error;
			}
			if (fcntl(fd, F_SETSIG, h->signo)==-1){
				LM_ERR("fnctl: SETSIG"
					" failed: %s [%d]\n", strerror(errno), errno);
				goto error;
			}
			/* set both non-blocking and async */
			set_fd_flags(O_ASYNC| O_NONBLOCK);
#ifdef EXTRA_DEBUG
			LM_DBG("sigio_rt on f %d, signal %d to pid %d\n",
					fd,  h->signo, my_pid());
#endif
			/* empty socket receive buffer, if buffer is already full
			 * no more space to put packets
			 * => no more signals are ever generated
			 * also when moving fds, the freshly moved fd might have
			 *  already some bytes queued, we want to get them now
			 *  and not later -- andrei */
			idx=h->fd_no;
			check_io=1;
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL_LT:
			ep_event.events=EPOLLIN;
			ep_event.data.ptr=e;
again1:
			n=epoll_ctl(h->epfd, EPOLL_CTL_ADD, fd, &ep_event);
			if (n==-1){
				if (errno==EAGAIN) goto again1;
				LM_ERR("epoll_ctl failed: %s [%d]\n",
					strerror(errno), errno);
				goto error;
			}
			break;
		case POLL_EPOLL_ET:
			set_fd_flags(O_NONBLOCK);
			ep_event.events=EPOLLIN|EPOLLET;
			ep_event.data.ptr=e;
again2:
			n=epoll_ctl(h->epfd, EPOLL_CTL_ADD, fd, &ep_event);
			if (n==-1){
				if (errno==EAGAIN) goto again2;
				LM_ERR("epoll_ctl failed: %s [%d]\n",
					strerror(errno), errno);
				goto error;
			}
			idx=-1;
			check_io=1;
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
				LM_ERR("/dev/poll write failed:"
							"%s [%d]\n", strerror(errno), errno);
				goto error;
			}
			break;
#endif
			
		default:
			LM_CRIT("no support for poll method "
					" %s (%d)\n", poll_method_str[h->poll_method],
					h->poll_method);
			goto error;
	}
	
	h->fd_no++; /* "activate" changes, for epoll/kqueue/devpoll it
				   has only informative value */
#if defined(HAVE_SIGIO_RT) || defined (HAVE_EPOLL)
	if (check_io){
		/* handle possible pre-existing events */
		pf.fd=fd;
		pf.events=POLLIN;
check_io_again:
		while( ((n=poll(&pf, 1, 0))>0) && (handle_io(e, idx)>0));
		if (n==-1){
			if (errno==EINTR) goto check_io_again;
			LM_ERR("check_io poll: %s [%d]\n",
						strerror(errno), errno);
		}
	}
#endif
	return 0;
error:
	if (e) unhash_fd_map(e);
	return -1;
#undef fd_array_setup
#undef set_fd_flags 
}



#define IO_FD_CLOSING 16

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
inline static int io_watch_del(io_wait_h* h, int fd, int idx, int flags)
{
	
#define fix_fd_array \
	do{\
			if (idx==-1){ \
				/* fix idx if -1 and needed */ \
				for (idx=0; (idx<h->fd_no) && \
							(h->fd_array[idx].fd!=fd); idx++); \
			} \
			if (idx<h->fd_no){ \
				memmove(&h->fd_array[idx], &h->fd_array[idx+1], \
					(h->fd_no-(idx+1))*sizeof(*(h->fd_array))); \
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
	
	if ((fd<0) || (fd>=h->max_fd_no)){
		LM_CRIT("invalid fd %d, not in [0, %d) \n", fd, h->fd_no);
		goto error;
	}
	LM_DBG("io_watch_del (%p, %d, %d, 0x%x) fd_no=%d called\n",
			h, fd, idx, flags, h->fd_no);
	e=get_fd_map(h, fd);
	/* more sanity checks */
	if (e==0){
		LM_CRIT("no corresponding hash entry for %d\n", fd);
		goto error;
	}
	if (e->type==0 /*F_NONE*/){
		LM_ERR("trying to delete already erased"
				" entry %d in the hash(%d, %d, %p) )\n",
				fd, e->fd, e->type, e->data);
		goto error;
	}
	
	unhash_fd_map(e);
	
	switch(h->poll_method){
		case POLL_POLL:
			fix_fd_array;
			break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			fix_fd_array;
			FD_CLR(fd, &h->master_set);
			if (h->max_fd_select && (h->max_fd_select==fd))
				/* we don't know the prev. max, so we just decrement it */
				h->max_fd_select--; 
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			fix_fd_array;
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
					LM_ERR("fnctl: GETFL failed:" 
							" %s [%d]\n", strerror(errno), errno); 
					goto error; 
				} 
				if (fcntl(fd, F_SETFL, fd_flags&(~O_ASYNC))==-1){ 
					LM_ERR("fnctl: SETFL" 
								" failed: %s [%d]\n", strerror(errno), errno); 
					goto error; 
				} 
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL_LT:
		case POLL_EPOLL_ET:
			/* epoll doesn't seem to automatically remove sockets,
			 * if the socket is a dupplicate/moved and the original
			 * is still open. The fd is removed from the epoll set
			 * only when the original (and all the  copies?) is/are 
			 * closed. This is probably a bug in epoll. --andrei */
#ifdef EPOLL_NO_CLOSE_BUG
			if (!(flags & IO_FD_CLOSING)){
#endif
				n=epoll_ctl(h->epfd, EPOLL_CTL_DEL, fd, &ep_event);
				if (n==-1){
					LM_ERR("removing fd from epoll "
							"list failed: %s [%d]\n", strerror(errno), errno);
					goto error;
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
					LM_ERR("removing fd from /dev/poll failed: "
						"%s [%d]\n", strerror(errno), errno);
					goto error;
				}
				break;
#endif
		default:
			LM_CRIT("no support for poll method %s (%d)\n",
				poll_method_str[h->poll_method], h->poll_method);
			goto error;
	}
	h->fd_no--;
	return 0;
error:
	return -1;
#undef fix_fd_array
}



/*! \brief io_wait_loop_x style function
 * wait for io using poll()
 * \param h io_wait handle
 * \param t timeout in s
 * \param repeat if !=0 handle_io will be called until it returns <=0
 * \return number of IO events handled on success (can be 0), -1 on error
 */
inline static int io_wait_loop_poll(io_wait_h* h, int t, int repeat)
{
	int n, r;
	int ret;
again:
		ret=n=poll(h->fd_array, h->fd_no, t*1000);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("poll: %s [%d]\n", strerror(errno), errno);
				goto error;
			}
		}
		for (r=0; (r<h->fd_no) && n; r++){
			if (h->fd_array[r].revents & (POLLIN|POLLERR|POLLHUP)){
				n--;
				/* sanity checks */
				if ((h->fd_array[r].fd >= h->max_fd_no)||
						(h->fd_array[r].fd < 0)){
					LM_CRIT("bad fd %d (no in the 0 - %d range)\n",
							h->fd_array[r].fd, h->max_fd_no);
					/* try to continue anyway */
					h->fd_array[r].events=0; /* clear the events */
					continue;
				}
				while((handle_io(get_fd_map(h, h->fd_array[r].fd), r) > 0)
						 && repeat);
			}
		}
error:
	return ret;
}



#ifdef HAVE_SELECT
/*! \brief wait for io using select */
inline static int io_wait_loop_select(io_wait_h* h, int t, int repeat)
{
	fd_set sel_set;
	int n, ret;
	struct timeval timeout;
	int r;
	
again:
		sel_set=h->master_set;
		timeout.tv_sec=t;
		timeout.tv_usec=0;
		ret=n=select(h->max_fd_select+1, &sel_set, 0, 0, &timeout);
		if (n<0){
			if (errno==EINTR) goto again; /* just a signal */
			LM_ERR("select: %s [%d]\n", strerror(errno), errno);
			n=0;
			/* continue */
		}
		/* use poll fd array */
		for(r=0; (r<h->max_fd_no) && n; r++){
			if (FD_ISSET(h->fd_array[r].fd, &sel_set)){
				while((handle_io(get_fd_map(h, h->fd_array[r].fd), r)>0)
						&& repeat);
				n--;
			}
		};
	return ret;
}
#endif



#ifdef HAVE_EPOLL
inline static int io_wait_loop_epoll(io_wait_h* h, int t, int repeat)
{
	int n, r;
	
again:
		n=epoll_wait(h->epfd, h->ep_array, h->fd_no, t*1000);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("epoll_wait(%d, %p, %d, %d): %s [%d]\n", 
						h->epfd, h->ep_array, h->fd_no, t*1000,
						strerror(errno), errno);
				goto error;
			}
		}
#if 0
		if (n>1){
			for(r=0; r<n; r++){
				LM_ERR("ep_array[%d]= %x, %p\n",
						r, h->ep_array[r].events, h->ep_array[r].data.ptr);
			}
		}
#endif
		for (r=0; r<n; r++){
			if (h->ep_array[r].events & (EPOLLIN|EPOLLERR|EPOLLHUP)){
				while((handle_io((struct fd_map*)h->ep_array[r].data.ptr,-1)>0)
					&& repeat);
			}else{
				LM_ERR("unexpected event %x on %d/%d, data=%p\n", 
					h->ep_array[r].events, r+1, n, h->ep_array[r].data.ptr);
			}
		}
error:
	return n;
}
#endif



#ifdef HAVE_KQUEUE
inline static int io_wait_loop_kqueue(io_wait_h* h, int t, int repeat)
{
	int n, r;
	struct timespec tspec;
	
	tspec.tv_sec=t;
	tspec.tv_nsec=0;
again:
		n=kevent(h->kq_fd, h->kq_changes, h->kq_nchanges,  h->kq_array,
					h->fd_no, &tspec);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("kevent: %s [%d]\n", strerror(errno), errno);
				goto error;
			}
		}
		h->kq_nchanges=0; /* reset changes array */
		for (r=0; r<n; r++){
#ifdef EXTRA_DEBUG
			LM_DBG("event %d/%d: fd=%d, udata=%lx, flags=0x%x\n",
					r, n, h->kq_array[r].ident, (long)h->kq_array[r].udata,
					h->kq_array[r].flags);
#endif
			if (h->kq_array[r].flags & EV_ERROR){
				/* error in changes: we ignore it, it can be caused by
				   trying to remove an already closed fd: race between
				   adding smething to the changes array, close() and
				   applying the changes */
				LM_INFO("kevent error on fd %u: %s [%ld]\n",
							(unsigned int)h->kq_array[r].ident,
							strerror(h->kq_array[r].data),
							(long)h->kq_array[r].data);
			}else /* READ/EOF */
				while((handle_io((struct fd_map*)h->kq_array[r].udata, -1)>0)
						&& repeat);
		}
error:
	return n;
}
#endif



#ifdef HAVE_SIGIO_RT
/*! \brief sigio rt version has no repeat (it doesn't make sense)*/
inline static int io_wait_loop_sigio_rt(io_wait_h* h, int t)
{
	int n;
	int ret;
	struct timespec ts;
	siginfo_t siginfo;
	int sigio_band;
	int sigio_fd;
	struct fd_map* fm;
	
	
	ret=1; /* 1 event per call normally */
	ts.tv_sec=t;
	ts.tv_nsec=0;
	if (!sigismember(&h->sset, h->signo) || !sigismember(&h->sset, SIGIO)){
		LM_CRIT("the signal mask is not properly set!\n");
		goto error;
	}

again:
	n=sigtimedwait(&h->sset, &siginfo, &ts);
	if (n==-1){
		if (errno==EINTR) goto again; /* some other signal, ignore it */
		else if (errno==EAGAIN){ /* timeout */
			ret=0;
			goto end;
		}else{
			LM_ERR("sigtimed_wait %s [%d]\n", strerror(errno), errno);
			goto error;
		}
	}
	if (n!=SIGIO){
#ifdef SIGINFO64_WORKARROUND
		/* on linux siginfo.si_band is defined as long in userspace
		 * and as int kernel => on 64 bits things will break!
		 * (si_band will include si_fd, and si_fd will contain
		 *  garbage)
		 *  see /usr/src/linux/include/asm-generic/siginfo.h and
		 *      /usr/include/bits/siginfo.h
		 * -- andrei */
		if (sizeof(siginfo.si_band)>sizeof(int)){
			sigio_band=*((int*)&siginfo.si_band);
			sigio_fd=*(((int*)&siginfo.si_band)+1);
		}else
#endif
		{
			sigio_band=siginfo.si_band;
			sigio_fd=siginfo.si_fd;
		}
		if (siginfo.si_code==SI_SIGIO){
			/* old style, we don't know the event (linux 2.2.?) */
			LM_WARN("old style sigio interface\n");
			fm=get_fd_map(h, sigio_fd);
			/* we can have queued signals generated by fds not watched
			 * any more, or by fds in transition, to a child => ignore them*/
			if (fm->type)
				handle_io(fm, -1);
		}else{
#ifdef EXTRA_DEBUG
			LM_DBG("siginfo: signal=%d (%d),"
					" si_code=%d, si_band=0x%x,"
					" si_fd=%d\n",
					siginfo.si_signo, n, siginfo.si_code, 
					(unsigned)sigio_band,
					sigio_fd);
#endif
			/* on some errors (e.g. when receving TCP RST), sigio_band will
			 * be set to 0x08 (undocumented, no corresp. POLL_xx), so better
			 * catch all events --andrei */
			if (sigio_band/*&(POLL_IN|POLL_ERR|POLL_HUP)*/){
				fm=get_fd_map(h, sigio_fd);
				/* we can have queued signals generated by fds not watched
			 	 * any more, or by fds in transition, to a child 
				 * => ignore them */
				if (fm->type)
					handle_io(fm, -1);
				else
					LM_ERR("ignoring event"
							" %x on fd %d (fm->fd=%d, fm->data=%p)\n",
							sigio_band, sigio_fd, fm->fd, fm->data);
			}else{
				LM_ERR("unexpected event on fd %d: %x\n", sigio_fd, sigio_band);
			}
		}
	}else{
		/* signal queue overflow 
		 * TODO: increase signal queue size: 2.4x /proc/.., 2.6x -rlimits */
		LM_WARN("signal queue overflowed- falling back to poll\n");
		/* clear real-time signal queue
		 * both SIG_IGN and SIG_DFL are needed , it doesn't work
		 * only with SIG_DFL  */
		if (signal(h->signo, SIG_IGN)==SIG_ERR){
			LM_CRIT("couldn't reset signal to IGN\n");
		}
		
		if (signal(h->signo, SIG_DFL)==SIG_ERR){
			LM_CRIT("couldn't reset signal to DFL\n");
		}
		/* falling back to normal poll */
		ret=io_wait_loop_poll(h, -1, 1);
	}
end:
	return ret;
error:
	return -1;
}
#endif



#ifdef HAVE_DEVPOLL
inline static int io_wait_loop_devpoll(io_wait_h* h, int t, int repeat)
{
	int n, r;
	int ret;
	struct dvpoll dpoll;

		dpoll.dp_timeout=t*1000;
		dpoll.dp_nfds=h->fd_no;
		dpoll.dp_fds=h->fd_array;
again:
		ret=n=ioctl(h->dpoll_fd, DP_POLL, &dpoll);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("ioctl: %s [%d]\n", strerror(errno), errno);
				goto error;
			}
		}
		for (r=0; r< n; r++){
			if (h->fd_array[r].revents & (POLLNVAL|POLLERR)){
				LM_ERR("pollinval returned for fd %d, revents=%x\n",
							h->fd_array[r].fd, h->fd_array[r].revents);
			}
			/* POLLIN|POLLHUP just go through */
			while((handle_io(get_fd_map(h, h->fd_array[r].fd), r) > 0) &&
						repeat);
		}
error:
	return ret;
}
#endif



/* init */


/*! \brief initializes the static vars/arrays
 * \param h pointer to the io_wait_h that will be initialized
 * \param max_fd maximum allowed fd number
 * \param poll_method poll method (0 for automatic best fit)
 */
int init_io_wait(io_wait_h* h, int max_fd, enum poll_types poll_method);

/*! \brief destroys everything init_io_wait allocated */
void destroy_io_wait(io_wait_h* h);


#endif
