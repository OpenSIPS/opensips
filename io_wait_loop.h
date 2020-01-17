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
 *  2014-08-25  split from io_wait.h (bogdan)
 */

/*!
 * \file
 * \brief io wait looping and triggering functions
 */


#ifndef _io_wait_loop_h
#define _io_wait_loop_h

#include "io_wait.h"


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
 *         >0 on successful read from the fd (when there might be more io
 *            queued -- the receive buffer might still be non-empty)
 */
inline static int handle_io(struct fd_map* fm, int idx,int event_type);
#else
static int handle_io(struct fd_map* fm, int idx,int event_type) {
	return 0;
}
#endif



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
	struct fd_map *e;
	unsigned int curr_time;

again:
		ret=n=poll(h->fd_array, h->fd_no, t*1000);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("[%s] poll: %s [%d]\n",h->name, strerror(errno), errno);
				goto error;
			}
		}

		curr_time = get_ticks();

		for (r=h->fd_no-1; (r>=0) ; r--){
			if (h->fd_array[r].revents & POLLOUT) {
				/* sanity checks */
				if ((h->fd_array[r].fd >= h->max_fd_no)||
						(h->fd_array[r].fd < 0)){
					LM_CRIT("[%s] bad fd %d (no in the 0 - %d range)\n",
						h->name, h->fd_array[r].fd, h->max_fd_no);
					/* try to continue anyway */
					h->fd_array[r].events=0; /* clear the events */
					continue;
				}
				handle_io(get_fd_map(h, h->fd_array[r].fd),r,IO_WATCH_WRITE);
			} else if (h->fd_array[r].revents & (POLLIN|POLLERR|POLLHUP)){
				/* sanity checks */
				if ((h->fd_array[r].fd >= h->max_fd_no)||
						(h->fd_array[r].fd < 0)){
					LM_CRIT("[%s] bad fd %d (no in the 0 - %d range)\n",
						h->name,h->fd_array[r].fd, h->max_fd_no);
					/* try to continue anyway */
					h->fd_array[r].events=0; /* clear the events */
					continue;
				}

				while((handle_io(get_fd_map(h, h->fd_array[r].fd), r,
				IO_WATCH_READ) > 0)
						 && repeat);
			} else if ( (e=get_fd_map(h, h->fd_array[r].fd))!=NULL &&
			e->timeout!=0 && e->timeout<=curr_time ) {
				e->timeout = 0;
				handle_io( e, r, IO_WATCH_TIMEOUT);
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
	struct fd_map *e;
	unsigned int curr_time;

again:
		sel_set=h->master_set;
		timeout.tv_sec=t;
		timeout.tv_usec=0;
		ret=n=select(h->max_fd_select+1, &sel_set, 0, 0, &timeout);
		if (n<0){
			if (errno==EINTR) goto again; /* just a signal */
			LM_ERR("[%s] select: %s [%d]\n",h->name, strerror(errno), errno);
			n=0;
			/* continue */
		}

		curr_time = get_ticks();

		/* use poll fd array */
		for(r=h->fd_no-1; (r>=0) ; r--){
			if (FD_ISSET(h->fd_array[r].fd, &sel_set)){
				while( (handle_io( get_fd_map(h, h->fd_array[r].fd), r,
				IO_WATCH_READ)>0) && repeat );
			} else if ( (e=get_fd_map(h, h->fd_array[r].fd))!=NULL &&
			e->timeout!=0 && e->timeout<=curr_time ) {
				e->timeout = 0;
				handle_io( e, r, IO_WATCH_TIMEOUT);
			}
		};
	return ret;
}
#endif



#ifdef HAVE_EPOLL
inline static int io_wait_loop_epoll(io_wait_h* h, int t, int repeat)
{
	int ret, n, r, i;
	struct fd_map *e;
	struct epoll_event ep_event;
	int fd;
	unsigned int curr_time;

again:
		ret=n=epoll_wait(h->epfd, h->ep_array, h->fd_no, t*1000);
		if (n==-1){
			if (errno == EINTR) {
				goto again; /* signal, ignore it */
			} else if (h->fd_no == 0) {
				sleep(t);
				return 0;
			} else {
				LM_ERR("[%s] epoll_wait(%d, %p, %d, %d): %s [%d]\n",
					h->name,h->epfd, h->ep_array, h->fd_no, t*1000,
					strerror(errno), errno);
				goto error;
			}
		}

		curr_time = get_ticks();

		for (r=0; r<n; r++) {
#if 0
			LM_NOTICE("[%s] triggering  fd %d, events %d, flags %d\n",
				h->name, ((struct fd_map*)h->ep_array[r].data.ptr)->fd,
				h->ep_array[r].events,
				((struct fd_map*)h->ep_array[r].data.ptr)->flags);
#endif
			/* do some sanity check over the triggered fd */
			e = ((struct fd_map*)h->ep_array[r].data.ptr);
			if (e->type==0 || e->fd<=0 ||
			(e->flags&(IO_WATCH_READ|IO_WATCH_WRITE))==0 ) {
				fd = e - h->fd_hash;
				LM_ERR("[%s] unset/bogus map (idx=%d) triggered for %d by "
					"epoll (fd=%d,type=%d,flags=%x,data=%p) -> removing "
					"from epoll\n", h->name,
					fd, h->ep_array[r].events,
					e->fd, e->type, e->flags, e->data);
				/* as the triggering fd has no corresponding in fd_map, better
				 * remove it from poll, to avoid un-managed reporting 
				 * on this fd */
				if (epoll_ctl(h->epfd, EPOLL_CTL_DEL, fd, &ep_event)<0) {
					LM_ERR("failed to remove from epoll %s(%d)\n",
						strerror(errno), errno);
				}
				close(fd);
				continue;
			}

			/* anything containing EPOLLIN (like HUP or ERR) goes as a READ */
			if (h->ep_array[r].events & EPOLLIN) {
				if ((e->flags&IO_WATCH_READ)==0) {
					LM_BUG("[%s] EPOLLIN triggered(%d) for non-read fd_map "
						"(fd=%d,type=%d,flags=%x,data=%p)\n",h->name,
						h->ep_array[r].events,
						e->fd, e->type, e->flags, e->data);
				}
				if (h->ep_array[r].events&EPOLLHUP) {
					LM_DBG("[%s] EPOLLHUP on IN ->"
						"connection closed by the remote peer!\n",h->name);
				}

				((struct fd_map*)h->ep_array[r].data.ptr)->flags |=
					IO_WATCH_PRV_TRIG_READ;

			/* anything containing EPOLLOUT (like HUP or ERR) goes as a WRITE*/
			} else if (h->ep_array[r].events & EPOLLOUT){
				if ((e->flags&IO_WATCH_WRITE)==0) {
					LM_BUG("[%s] EPOLLOUT triggered(%d) for non-read fd_map "
						"(fd=%d,type=%d,flags=%x,data=%p)\n",h->name,
						h->ep_array[r].events,
						e->fd, e->type, e->flags, e->data);
				}
				if (h->ep_array[r].events&EPOLLHUP) {
					LM_DBG("[%s] EPOLLHUP on OUT ->"
						"connection closed by the remote peer!\n",h->name);
				}

				((struct fd_map*)h->ep_array[r].data.ptr)->flags |=
					IO_WATCH_PRV_TRIG_WRITE;

			/* ERR or HUP without IN or OUT triggering ?? */
			} else if (h->ep_array[r].events & (EPOLLERR|EPOLLHUP) ) {
				LM_DBG("[%s] non-op event %x, using flags %x\n",h->name,
					h->ep_array[r].events,
					((struct fd_map*)h->ep_array[r].data.ptr)->flags);

				/* as the epoll did not provide any info on IN/OUT
				 * we look back the IO flags we set */
				if ( ((struct fd_map*)h->ep_array[r].data.ptr)->flags & IO_WATCH_WRITE )
					((struct fd_map*)h->ep_array[r].data.ptr)->flags |=
						IO_WATCH_PRV_TRIG_WRITE;
				else
					((struct fd_map*)h->ep_array[r].data.ptr)->flags |=
						IO_WATCH_PRV_TRIG_READ;

			} else {
				LM_ERR("[%s] unexpected event %x on %d/%d, data=%p\n",
					h->name,h->ep_array[r].events, r+1, n,
					h->ep_array[r].data.ptr);
			}
		}
		/* now do the actual running of IO handlers */
		for(r=h->fd_no-1; (r>=0) ; r--) {
			e = get_fd_map(h, h->fd_array[r].fd);
			/* test the sanity of the fd_map */
			if (e->flags & (IO_WATCH_PRV_TRIG_READ|IO_WATCH_PRV_TRIG_WRITE)) {
				/* the fd correlated to this fd_map was triggered by the
				 * reactor, so let's check if the fd_map payload is still
				 * valid */
				if (e->fd==-1 || e->type==F_NONE) {
					/* this is bogus!! */
					LM_BUG("[%s] FD %d with map (%d,%d,%p) is out of sync,"
						" removing it from reactor\n",
						h->name, h->fd_array[r].fd, e->fd, e->type, e->data);
					/* remove from epoll */
					epoll_ctl(h->epfd, EPOLL_CTL_DEL, h->fd_array[r].fd,
						&ep_event);
					close(h->fd_array[r].fd);
					/* remove from fd_array */
					memmove(&h->fd_array[r], &h->fd_array[r+1],
						(h->fd_no-(r+1))*sizeof(*(h->fd_array)));
					for( i=0 ; i<h->max_prio && h->prio_idx[i]<=r ; i++ );
					for( ; i<h->max_prio ; i++ ) h->prio_idx[i]-- ;
					h->fd_no--;
					/* no handler triggering for this FD */
					continue;
				}
			}
			if ( e->flags & IO_WATCH_PRV_TRIG_READ ) {
				e->flags &= ~IO_WATCH_PRV_TRIG_READ;
				while((handle_io( e, r, IO_WATCH_READ)>0) && repeat);
			} else if ( e->flags & IO_WATCH_PRV_TRIG_WRITE ){
				e->flags &= ~IO_WATCH_PRV_TRIG_WRITE;
				handle_io( e, r, IO_WATCH_WRITE);
			} else if ( e->timeout!=0 && e->timeout<=curr_time ) {
				e->timeout = 0;
				handle_io( e, r, IO_WATCH_TIMEOUT);
			}
		}

error:
	return ret;
}
#endif



#ifdef HAVE_KQUEUE
inline static int io_wait_loop_kqueue(io_wait_h* h, int t, int repeat)
{
	int ret, n, r;
	struct timespec tspec;
	struct fd_map *e;
	unsigned int curr_time;

	tspec.tv_sec=t;
	tspec.tv_nsec=0;
again:
		ret=n=kevent(h->kq_fd, h->kq_changes, h->kq_nchanges,  h->kq_array,
					h->fd_no, &tspec);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("[%s] kevent: %s [%d]\n", h->name,
					strerror(errno), errno);
				goto error;
			}
		}

		curr_time = get_ticks();

		h->kq_nchanges=0; /* reset changes array */
		for (r=0; r<n; r++){
#ifdef EXTRA_DEBUG
			LM_DBG("[%s] event %d/%d: fd=%d, udata=%lx, flags=0x%x\n",
				h->name, r, n, h->kq_array[r].ident,
				(long)h->kq_array[r].udata,
				h->kq_array[r].flags);
#endif
			if (h->kq_array[r].flags & EV_ERROR){
				/* error in changes: we ignore it, it can be caused by
				   trying to remove an already closed fd: race between
				   adding smething to the changes array, close() and
				   applying the changes */
				LM_INFO("[%s] kevent error on fd %u: %s [%ld]\n",
					h->name, (unsigned int)h->kq_array[r].ident,
					strerror(h->kq_array[r].data),
					(long)h->kq_array[r].data);
			}else /* READ/EOF */
				((struct fd_map*)h->kq_array[r].udata)->flags |=
					IO_WATCH_PRV_TRIG_READ;
		}
		/* now do the actual running of IO handlers */
		for(r=h->fd_no-1; (r>=0) && n ; r--) {
			e = get_fd_map(h, h->fd_array[r].fd);
			if ( e->flags & IO_WATCH_PRV_TRIG_READ ) {
				e->flags &= ~IO_WATCH_PRV_TRIG_READ;
				while((handle_io( e, r, IO_WATCH_READ)>0) && repeat);
				n--;
			} else if ( e->timeout!=0 && e->timeout<=curr_time ) {
				e->timeout = 0;
				handle_io( e, r, IO_WATCH_TIMEOUT);
			}
		}

error:
	return ret;
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
		LM_CRIT("[%s] the signal mask is not properly set!\n",h->name);
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
			LM_ERR("[%s] sigtimed_wait %s [%d]\n",h->name,
				strerror(errno), errno);
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
			LM_WARN("[%s] old style sigio interface\n",h->name);
			fm=get_fd_map(h, sigio_fd);
			/* we can have queued signals generated by fds not watched
			 * any more, or by fds in transition, to a child => ignore them*/
			if (fm->type)
				handle_io(fm, -1,IO_WATCH_READ);
		}else{
#ifdef EXTRA_DEBUG
			LM_DBG("[%s] siginfo: signal=%d (%d),"
					" si_code=%d, si_band=0x%x,"
					" si_fd=%d\n",
					h->name,siginfo.si_signo, n, siginfo.si_code,
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
					handle_io(fm, -1,IO_WATCH_READ);
				else
					LM_ERR("[%s] ignoring event"
						" %x on fd %d (fm->fd=%d, fm->data=%p)\n",
						h->name,sigio_band, sigio_fd, fm->fd, fm->data);
			}else{
				LM_ERR("[%s] unexpected event on fd %d: %x\n",h->name, sigio_fd, sigio_band);
			}
		}
	}else{
		/* signal queue overflow
		 * TODO: increase signal queue size: 2.4x /proc/.., 2.6x -rlimits */
		LM_WARN("[%s] signal queue overflowed- falling back to poll\n",h->name);
		/* clear real-time signal queue
		 * both SIG_IGN and SIG_DFL are needed , it doesn't work
		 * only with SIG_DFL  */
		if (signal(h->signo, SIG_IGN)==SIG_ERR){
			LM_CRIT("[%s] couldn't reset signal to IGN\n",h->name);
		}

		if (signal(h->signo, SIG_DFL)==SIG_ERR){
			LM_CRIT("[%s] couldn't reset signal to DFL\n",h->name);
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
	struct fd_map *e;
	unsigned int curr_time;

		dpoll.dp_timeout=t*1000;
		dpoll.dp_nfds=h->fd_no;
		dpoll.dp_fds=h->dp_changes;
again:
		ret=n=ioctl(h->dpoll_fd, DP_POLL, &dpoll);
		if (n==-1){
			if (errno==EINTR) goto again; /* signal, ignore it */
			else{
				LM_ERR("[%s] ioctl: %s [%d]\n",h->name, strerror(errno), errno);
				goto error;
			}
		}

		curr_time = get_ticks();

		for (r=0; r< n; r++){
			if (h->dp_changes[r].revents & (POLLNVAL|POLLERR)){
				LM_ERR("[%s] pollinval returned for fd %d, revents=%x\n",
					h->name,h->fd_array[r].fd, h->fd_array[r].revents);
			}
			/* POLLIN|POLLHUP just go through */
			(get_fd_map(h, h->dp_changes[r].fd))->flags |=
				IO_WATCH_PRV_TRIG_READ;
		}
		/* now do the actual running of IO handlers */
		for(r=h->fd_no-1; (r>=0) ; r--) {
			e = get_fd_map(h, h->fd_array[r].fd);
			if ( e->flags & IO_WATCH_PRV_TRIG_READ ) {
				e->flags &= ~IO_WATCH_PRV_TRIG_READ;
				while((handle_io( e, r, IO_WATCH_READ)>0) && repeat);
			} else if ( e->timeout!=0 && e->timeout<=curr_time ) {
				e->timeout = 0;
				handle_io( e, r, IO_WATCH_TIMEOUT);
			}
		}

error:
	return ret;
}
#endif


#endif
