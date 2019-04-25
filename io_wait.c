/*
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
 *  2005-06-15  created by andrei
 *  2005-06-26  added kqueue (andrei)
 *  2005-07-04  added /dev/poll (andrei)
 */

/*!
 * \file
 * \brief OpenSIPS TCP IO wait common functions
 */


#ifdef HAVE_EPOLL
#include <unistd.h> /* close() */
#endif
#ifdef HAVE_DEVPOLL
#include <sys/types.h> /* open */
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> /* close, ioctl */
#endif

#include <sys/utsname.h> /* uname() */
#include <stdlib.h> /* strtol() */
#include "io_wait.h"


#include "mem/mem.h"

#ifndef local_malloc
#define local_malloc pkg_malloc
#endif
#ifndef local_free
#define local_free pkg_free
#endif

char* poll_support="poll"
#ifdef HAVE_EPOLL
", epoll"
#endif
#ifdef HAVE_SIGIO_RT
", sigio_rt"
#endif
#ifdef HAVE_SELECT
", select"
#endif
#ifdef HAVE_KQUEUE
", kqueue"
#endif
#ifdef HAVE_DEVPOLL
", /dev/poll"
#endif
;

/*! supported poll methods */
char* poll_method_str[POLL_END]={ "none", "poll", "epoll",
								  "sigio_rt", "select", "kqueue",  "/dev/poll"
								};

#ifdef HAVE_SIGIO_RT
static int _sigio_init=0;
static int _sigio_crt_rtsig;
static sigset_t _sigio_rtsig_used;
#endif



#ifdef HAVE_SIGIO_RT
/*!
 * \brief sigio specific init
 * \param h IO handle
 * \param rsig real time signal
 * \return returns -1 on error, 0 on success
 */
static int init_sigio(io_wait_h* h, int rsig)
{
	int r;
	int n;
	int signo;
	int start_sig;
	sigset_t oldset;

	if (!_sigio_init){
		_sigio_init=1;
		_sigio_crt_rtsig=SIGRTMIN;
		sigemptyset(&_sigio_rtsig_used);
	}
	h->signo=0;

	if (rsig==0){
		start_sig=_sigio_crt_rtsig;
		n=SIGRTMAX-SIGRTMIN;
	}else{
		if ((rsig < SIGRTMIN) || (rsig >SIGRTMAX)){
			LM_CRIT("real time signal %d out of"
				" range  [%d, %d]\n", rsig, SIGRTMIN, SIGRTMAX);
			goto error;
		}
		start_sig=rsig;
		n=0;
	}

	sigemptyset(&h->sset);
	sigemptyset(&oldset);
retry1:
	/* get current block mask */
	if (sigprocmask(SIG_BLOCK, &h->sset, &oldset )==-1){
		if (errno==EINTR) goto retry1;
		LM_ERR("1st sigprocmask failed: %s [%d]\n",
				strerror(errno), errno);
		/* try to continue */
	}

	for (r=start_sig; r<=(n+start_sig); r++){
		signo=(r>SIGRTMAX)?r-SIGRTMAX+SIGRTMIN:r;
		if (! sigismember(&_sigio_rtsig_used, signo) &&
			! sigismember(&oldset, signo)){
			sigaddset(&_sigio_rtsig_used, signo);
			h->signo=signo;
			_sigio_crt_rtsig=(signo<SIGRTMAX)?signo+1:SIGRTMIN;
			break;
		}
	}

	if (h->signo==0){
			LM_CRIT("init_sigio: %s\n",
					rsig?"could not assign requested real-time signal":
						 "out of real-time signals");
			goto error;
	}

	LM_DBG("trying signal %d... \n", h->signo);

	if (sigaddset(&h->sset, h->signo)==-1){
		LM_ERR("sigaddset failed for %d: %s [%d]\n",
				h->signo, strerror(errno), errno);
		goto error;
	}
	if (sigaddset(&h->sset, SIGIO)==-1){
		LM_ERR("sigaddset failed for %d: %s [%d]\n",
				SIGIO, strerror(errno), errno);
		goto error;
	}
retry:
	if (sigprocmask(SIG_BLOCK, &h->sset, 0)==-1){
		if (errno==EINTR) goto retry;
		LM_ERR("sigprocmask failed: %s [%d]\n",
				strerror(errno), errno);
		goto error;
	}
	return 0;
error:
	h->signo=0;
	sigemptyset(&h->sset);
	return -1;
}



/*!
 * \brief sigio specific destroy
 * \param h IO handle
 */
static void destroy_sigio(io_wait_h* h)
{
	if (h->signo){
		sigprocmask(SIG_UNBLOCK, &h->sset, 0);
		sigemptyset(&h->sset);
		sigdelset(&_sigio_rtsig_used, h->signo);
		h->signo=0;
	}
}
#endif



#ifdef HAVE_EPOLL
/*!
 * \brief epoll specific init
 * \param h IO handle
 * \return -1 on error, 0 on success
 */
static int init_epoll(io_wait_h* h)
{
again:
	h->epfd=epoll_create(h->max_fd_no);
	if (h->epfd==-1){
		if (errno==EINTR) goto again;
		LM_ERR("epoll_create: %s [%d]\n",
				strerror(errno), errno);
		return -1;
	}
	return 0;
}

/*!
 * \brief epoll specific destroy
 * \param h IO handle
 */
static void destroy_epoll(io_wait_h* h)
{
	if (h->epfd!=-1){
		close(h->epfd);
		h->epfd=-1;
	}
}
#endif



#ifdef HAVE_KQUEUE
/*!
 * \brief kqueue specific init
 * \param h IO handle
 * \return -1 on error, 0 on success
 */
static int init_kqueue(io_wait_h* h)
{
again:
	h->kq_fd=kqueue();
	if (h->kq_fd==-1){
		if (errno==EINTR) goto again;
		LM_ERR("kqueue: %s [%d]\n",
				strerror(errno), errno);
		return -1;
	}
	return 0;
}


/*!
 * \brief kqueue specific destroy
 * \param h IO handle
 */
static void destroy_kqueue(io_wait_h* h)
{
	if (h->kq_fd!=-1){
		close(h->kq_fd);
		h->kq_fd=-1;
	}
}
#endif



#ifdef HAVE_DEVPOLL
/*!
 * \brief /dev/poll specific init
 * \param h IO handle
 * \return -1 on error, 0 on success */
static int init_devpoll(io_wait_h* h)
{
again:
	h->dpoll_fd=open("/dev/poll", O_RDWR);
	if (h->dpoll_fd==-1){
		if (errno==EINTR) goto again;
		LM_ERR("open: %s [%d]\n",
				strerror(errno), errno);
		return -1;
	}
	return 0;
}


/*!
 * \brief dev/poll specific destroy
 * \param h IO handle
 */
static void destroy_devpoll(io_wait_h* h)
{
	if (h->dpoll_fd!=-1){
		close(h->dpoll_fd);
		h->dpoll_fd=-1;
	}
}
#endif



#ifdef HAVE_SELECT
/*!
 * \brief select specific init
 * \param h IO handle
 * \return zero
 * \todo make this method void, and remove the check in io_wait.c
 */
static int init_select(io_wait_h* h)
{
	FD_ZERO(&h->master_set);
	return 0;
}
#endif



/*!
 * \brief return system version
 * Return system version (major.minor.minor2) as (major<<16)|(minor)<<8|(minor2)
 * (if some of them are missing, they are set to 0)
 * if the parameters are not null they are set to the coresp. part
 * \param major major version
 * \param minor minor version
 * \param minor2 minor2 version
 * \return (major<<16)|(minor)<<8|(minor2)
 */
static unsigned int get_sys_version(int* major, int* minor, int* minor2)
{
	struct utsname un;
	int m1;
	int m2;
	int m3;
	char* p;

	memset (&un, 0, sizeof(un));
	m1=m2=m3=0;
	/* get sys version */
	uname(&un);
	m1=strtol(un.release, &p, 10);
	if (*p=='.'){
		p++;
		m2=strtol(p, &p, 10);
		if (*p=='.'){
			p++;
			m3=strtol(p, &p, 10);
		}
	}
	if (major) *major=m1;
	if (minor) *minor=m2;
	if (minor2) *minor2=m3;
	return ((m1<<16)|(m2<<8)|(m3));
}



/*!
 * \brief Check preferred OS poll method
 * \param poll_method supported IO poll methods
 * \return 0 on success, and an error message on error
 */
char* check_poll_method(enum poll_types poll_method)
{
	char* ret;
	unsigned int os_ver;

	ret=0;
	os_ver=get_sys_version(0,0,0);
	(void)os_ver;
	switch(poll_method){
		case POLL_NONE:
			break;
		case POLL_POLL:
			/* always supported */
			break;
		case POLL_SELECT:
			/* should be always supported */
#ifndef HAVE_SELECT
			ret="select not supported, try re-compiling with -DHAVE_SELECT";
#endif
			break;
		case POLL_EPOLL:
#ifndef HAVE_EPOLL
			ret="epoll not supported, try re-compiling with -DHAVE_EPOLL";
#else
			/* only on 2.6 + */
			if (os_ver<0x020542) /* if ver < 2.5.66 */
			 	ret="epoll not supported on kernels < 2.6";
#endif
			break;
		case POLL_SIGIO_RT:
#ifndef HAVE_SIGIO_RT
			ret="sigio_rt not supported, try re-compiling with"
				" -DHAVE_SIGIO_RT";
#else
			/* only on 2.2 +  ?? */
			if (os_ver<0x020200) /* if ver < 2.2.0 */
			 	ret="epoll not supported on kernels < 2.2 (?)";
#endif
			break;
		case POLL_KQUEUE:
#ifndef HAVE_KQUEUE
			ret="kqueue not supported, try re-compiling with -DHAVE_KQUEUE";
#else
		/* only in FreeBSD 4.1, NETBSD 2.0, OpenBSD 2.9, Darwin */
	#ifdef __OS_freebsd
			if (os_ver<0x0401) /* if ver < 4.1 */
				ret="kqueue not supported on FreeBSD < 4.1";
	#elif defined (__OS_netbsd)
			if (os_ver<0x020000) /* if ver < 2.0 */
				ret="kqueue not supported on NetBSD < 2.0";
	#elif defined (__OS_openbsd)
			if (os_ver<0x0209) /* if ver < 2.9 ? */
				ret="kqueue not supported on OpenBSD < 2.9 (?)";
	#endif /* assume that the rest support kqueue ifdef HAVE_KQUEUE */
#endif
			break;
		case POLL_DEVPOLL:
#ifndef HAVE_DEVPOLL
			ret="/dev/poll not supported, try re-compiling with"
					" -DHAVE_DEVPOLL";
#else
	/* only in Solaris >= 7.0 (?) */
	#ifdef __OS_solaris
		if (os_ver<0x0507) /* ver < 5.7 */
			ret="/dev/poll not supported on Solaris < 7.0 (SunOS 5.7)";
	#endif
#endif
			break;

		default:
			ret="unknown not supported method";
	}
	return ret;
}


/*!
 * \brief Choose a IO poll method
 * \return the choosen poll method
 */
enum poll_types choose_poll_method(void)
{
	enum poll_types poll_method;
	unsigned int os_ver;

	os_ver=get_sys_version(0,0,0);
	(void)os_ver;
	poll_method=0;
#ifdef HAVE_EPOLL
	if (os_ver>=0x020542) /* if ver >= 2.5.66 */
		poll_method=POLL_EPOLL;

#endif
#ifdef HAVE_KQUEUE
	if (poll_method==0)
		/* only in FreeBSD 4.1, NETBSD 2.0, OpenBSD 2.9, Darwin */
	#ifdef __OS_freebsd
		if (os_ver>=0x0401) /* if ver >= 4.1 */
	#elif defined (__OS_netbsd)
		if (os_ver>=0x020000) /* if ver >= 2.0 */
	#elif defined (__OS_openbsd)
		if (os_ver>=0x0209) /* if ver >= 2.9 (?) */
	#endif /* assume that the rest support kqueue ifdef HAVE_KQUEUE */
			poll_method=POLL_KQUEUE;
#endif
#ifdef HAVE_DEVPOLL
	#ifdef __OS_solaris
	if (poll_method==0)
		/* only in Solaris >= 7.0 (?) */
		if (os_ver>=0x0507) /* if ver >=SunOS 5.7 */
			poll_method=POLL_DEVPOLL;
	#endif
#endif
#ifdef  HAVE_SIGIO_RT
		if (poll_method==0)
			if (os_ver>=0x020200) /* if ver >= 2.2.0 */
				poll_method=POLL_SIGIO_RT;
#endif
		if (poll_method==0) poll_method=POLL_POLL;
	return poll_method;
}


/*!
 * \brief output the IO poll method name
 * \param poll_method used poll method
 */
char* poll_method_name(enum poll_types poll_method)
{
	if ( poll_method<POLL_END )
		return poll_method_str[poll_method];
	else
		return "invalid poll method";
}




/*!
 * \brief converts a string into a poll_method
 * \param s converted string
 * \return POLL_NONE (0) on error, else the corresponding poll type
 */
enum poll_types get_poll_type(char* s)
{
	int r;
	unsigned int l;

	l=strlen(s);
	for (r=POLL_END-1; r>POLL_NONE; r--)
		if ((strlen(poll_method_str[r])==l) &&
			(strncasecmp(poll_method_str[r], s, l)==0))
			break;
	return r;
}



/*!
 * \brief initializes the static vars/arrays
 * \param  h - pointer to the io_wait_h that will be initialized
 * \param  max_fd - maximum allowed fd number
 * \param  poll_method - poll method (0 for automatic best fit)
 */
int init_io_wait(io_wait_h* h, char *name, int max_fd,
								enum poll_types poll_method, int max_prio)
{
	char * poll_err;

	memset(h, 0, sizeof(*h));
	h->name = name;
	h->max_prio = max_prio;
	h->max_fd_no=max_fd;
#ifdef HAVE_EPOLL
	h->epfd=-1;
#endif
#ifdef HAVE_KQUEUE
	h->kq_fd=-1;
#endif
#ifdef HAVE_DEVPOLL
	h->dpoll_fd=-1;
#endif
	poll_err=check_poll_method(poll_method);

	/* set an appropiate poll method */
	if (poll_err || (poll_method==0)){
		poll_method=choose_poll_method();
		if (poll_err){
			LM_ERR("%s, using %s instead\n",
					poll_err, poll_method_str[poll_method]);
		}else{
			LM_INFO("using %s as the io watch method"
					" (auto detected)\n", poll_method_str[poll_method]);
		}
	}

	h->poll_method=poll_method;

	/* common stuff, everybody has fd_hash */
	h->fd_hash=local_malloc(sizeof(*(h->fd_hash))*h->max_fd_no);
	if (h->fd_hash==0){
		LM_CRIT("could not alloc fd hashtable (%ld bytes)\n",
					(long)sizeof(*(h->fd_hash))*h->max_fd_no );
		goto error;
	}
	memset((void*)h->fd_hash, 0, sizeof(*(h->fd_hash))*h->max_fd_no);

	/* init the fd array as needed for priority ordering */
	h->fd_array=local_malloc(sizeof(*(h->fd_array))*h->max_fd_no);
	if (h->fd_array==0){
		LM_CRIT("could not alloc fd array (%ld bytes)\n",
					(long)sizeof(*(h->fd_hash))*h->max_fd_no);
		goto error;
	}
	memset((void*)h->fd_array, 0, sizeof(*(h->fd_array))*h->max_fd_no);
	/* array with indexes in fd_array where the priority changes */
	h->prio_idx=local_malloc(sizeof(*(h->prio_idx))*h->max_prio);
	if (h->prio_idx==0){
		LM_CRIT("could not alloc fd array (%ld bytes)\n",
					(long)sizeof(*(h->prio_idx))*h->max_prio);
		goto error;
	}
	memset((void*)h->prio_idx, 0, sizeof(*(h->prio_idx))*h->max_prio);

	switch(poll_method){
		case POLL_POLL:
			break;
#ifdef HAVE_SELECT
		case POLL_SELECT:
			if ((poll_method==POLL_SELECT) && (init_select(h)<0)){
				LM_CRIT("select init failed\n");
				goto error;
			}
			break;
#endif
#ifdef HAVE_DEVPOLL
		case POLL_DEVPOLL:
			if ((poll_method==POLL_DEVPOLL) && (init_devpoll(h)<0)){
				LM_CRIT("/dev/poll init failed\n");
				goto error;
			}
			h->dp_changes=local_malloc(sizeof(*(h->dp_changes))*h->max_fd_no);
			if (h->dp_changes==0){
				LM_CRIT("could not alloc db changes array (%ld bytes)\n",
							(long)sizeof(*(h->dp_changes))*h->max_fd_no);
				goto error;
			}
			memset((void*)h->dp_changes, 0,
				sizeof(*(h->dp_changes))*h->max_fd_no);
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			if ((poll_method==POLL_SIGIO_RT) && (init_sigio(h, 0)<0)){
				LM_CRIT("sigio init failed\n");
				goto error;
			}
			break;
#endif
#ifdef HAVE_EPOLL
		case POLL_EPOLL:
			h->ep_array=local_malloc(sizeof(*(h->ep_array))*h->max_fd_no);
			if (h->ep_array==0){
				LM_CRIT("could not alloc epoll array\n");
				goto error;
			}
			memset((void*)h->ep_array, 0, sizeof(*(h->ep_array))*h->max_fd_no);
			if (init_epoll(h)<0){
				LM_CRIT("epoll init failed\n");
				goto error;
			}
			break;
#endif
#ifdef HAVE_KQUEUE
		case POLL_KQUEUE:
			h->kq_array=local_malloc(sizeof(*(h->kq_array))*h->max_fd_no);
			if (h->kq_array==0){
				LM_CRIT("could not alloc kqueue event array\n");
				goto error;
			}
			h->kq_changes_size=KQ_CHANGES_ARRAY_SIZE;
			h->kq_changes=local_malloc(sizeof(*(h->kq_changes))*
										h->kq_changes_size);
			if (h->kq_changes==0){
				LM_CRIT("could not alloc kqueue changes array\n");
				goto error;
			}
			h->kq_nchanges=0;
			memset((void*)h->kq_array, 0, sizeof(*(h->kq_array))*h->max_fd_no);
			memset((void*)h->kq_changes, 0,
						sizeof(*(h->kq_changes))* h->kq_changes_size);
			if (init_kqueue(h)<0){
				LM_CRIT("kqueue init failed\n");
				goto error;
			}
			break;
#endif
		default:
			LM_CRIT("unknown/unsupported poll method %s (%d)\n",
						poll_method_str[poll_method], poll_method);
			goto error;
	}
	return 0;
error:
	return -1;
}



/*!
 * \brief destroys everything init_io_wait allocated
 * \param h IO handle
 */
void destroy_io_wait(io_wait_h* h)
{
	switch(h->poll_method){
#ifdef HAVE_EPOLL
		case POLL_EPOLL:
			destroy_epoll(h);
			if (h->ep_array){
				local_free(h->ep_array);
				h->ep_array=0;
			}
		break;
#endif
#ifdef HAVE_KQUEUE
		case POLL_KQUEUE:
			destroy_kqueue(h);
			if (h->kq_array){
				local_free(h->kq_array);
				h->kq_array=0;
			}
			if (h->kq_changes){
				local_free(h->kq_changes);
				h->kq_changes=0;
			}
			break;
#endif
#ifdef HAVE_SIGIO_RT
		case POLL_SIGIO_RT:
			destroy_sigio(h);
			break;
#endif
#ifdef HAVE_DEVPOLL
		case POLL_DEVPOLL:
			destroy_devpoll(h);
			if (h->dp_changes){
				local_free(h->dp_changes);
				h->dp_changes=0;
			}
			break;
#endif
		default: /*do  nothing*/
			;
	}
		if (h->fd_array){
			local_free(h->fd_array);
			h->fd_array=0;
		}
		if (h->fd_hash){
			local_free(h->fd_hash);
			h->fd_hash=0;
		}
		if (h->prio_idx){
			local_free(h->prio_idx);
			h->prio_idx=0;
		}

}


void fix_poll_method( enum poll_types *poll_method )
{
	char* poll_err;

	/* fix config variables */
	/* they can have only positive values due the config parser so we can
	 * ignore most of them */
	poll_err=check_poll_method(*poll_method);

	/* set an appropiate poll method */
	if (poll_err || (*poll_method==0)){
		*poll_method=choose_poll_method();
		if (poll_err){
			LM_ERR("%s, using %s instead\n",
					poll_err, poll_method_name(*poll_method));
		}else{
			LM_INFO("using %s as the IO watch method"
					" (auto detected)\n", poll_method_name(*poll_method));
		}
	}else{
			LM_INFO("using %s as the IO watch method (config)\n",
					poll_method_name(*poll_method));
	}

	return;
}


int io_set_app_flag( io_wait_h *h , int type, int app_flag)
{
	int i;
	int res=0;

	for( i=0 ; i<h->fd_no ; i++) {
			if (h->fd_hash[i].fd<=0 && h->fd_hash[i].type==type) {
				h->fd_hash[i].app_flags |= app_flag;
				res = 1;
			}
	}
	return res;
}


int io_check_app_flag( io_wait_h *h , int app_flag)
{
	int i;

	for( i=0 ; i<h->fd_no ; i++) {
			if ( h->fd_hash[i].fd<=0 &&
			(h->fd_hash[i].app_flags & app_flag) )
				return 1;
	}
	/* nothing found, return false*/
	return 0;

}

