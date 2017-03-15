/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2006-09-25  first version (bogdan)
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../mi/mi.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "mi_fifo.h"
#include "fifo_fnc.h"
#include "mi_parser.h"
#include "mi_writer.h"

#define INTERNAL_ERR_CODE 500
#define PARSE_ERR_CODE 400
#define ERR_BUF_SIZE 256

static char *mi_buf = 0;
static char *reply_fifo_s = 0;
static int  reply_fifo_len = 0;
static char *mi_fifo_name = NULL;
static int mi_fifo_mode;
static int mi_fifo_uid;
static int mi_fifo_gid;
static str backend = str_init("fifo");

static int volatile mi_reload_fifo = 0;

str correlation_value;
extern int mi_trace_mod_id;

FILE* mi_create_fifo(void)
{
	static int  mi_fifo_read = 0;
	static int  mi_fifo_write = 0;
	FILE *fifo_stream = 0;
	long opt;

	/* create FIFO ... */
	if ((mkfifo(mi_fifo_name, mi_fifo_mode)<0)) {
		LM_ERR("can't create FIFO: %s (mode=%d)\n", strerror(errno), mi_fifo_mode);
		return 0;
	}

	LM_DBG("FIFO created @ %s\n", mi_fifo_name );

	if ((chmod(mi_fifo_name, mi_fifo_mode)<0)) {
		LM_ERR("can't chmod FIFO: %s (mode=%d)\n", strerror(errno), mi_fifo_mode);
		return 0;
	}

	if ((mi_fifo_uid!=-1) || (mi_fifo_gid!=-1)){
		if (chown(mi_fifo_name, mi_fifo_uid, mi_fifo_gid)<0){

#include "../../mi/mi_trace.h"
			LM_ERR("failed to change the owner/group for %s to %d.%d; %s[%d]\n",
				mi_fifo_name, mi_fifo_uid, mi_fifo_gid, strerror(errno), errno);
			return 0;
		}
	}

	LM_DBG("fifo %s opened, mode=%o\n", mi_fifo_name, mi_fifo_mode );

	/* open it non-blocking or else wait here until someone
	 * opens it for writing */
	mi_fifo_read=open(mi_fifo_name, O_RDONLY|O_NONBLOCK, 0);
	if (mi_fifo_read<0) {
		LM_ERR("mi_fifo_read did not open: %s\n", strerror(errno));
		return 0;
	}

	fifo_stream = fdopen(mi_fifo_read, "r");
	if (fifo_stream==NULL) {
		LM_ERR("fdopen failed: %s\n", strerror(errno));
		return 0;
	}

	/* make sure the read fifo will not close */
	mi_fifo_write=open(mi_fifo_name, O_WRONLY|O_NONBLOCK, 0);
	if (mi_fifo_write<0) {
		fclose(fifo_stream);
		close(mi_fifo_read);
		LM_ERR("fifo_write did not open: %s\n", strerror(errno));
		return 0;
	}
	/* set read fifo blocking mode */
	if ((opt=fcntl(mi_fifo_read, F_GETFL))==-1){
		fclose(fifo_stream);
		close(mi_fifo_read);
		close(mi_fifo_write);
		LM_ERR("fcntl(F_GETFL) failed: %s [%d]\n", strerror(errno), errno);
		return 0;
	}
	if (fcntl(mi_fifo_read, F_SETFL, opt & (~O_NONBLOCK))==-1){
		fclose(fifo_stream);
		close(mi_fifo_read);
		close(mi_fifo_write);
		LM_ERR("cntl(F_SETFL) failed: %s [%d]\n", strerror(errno), errno);
		return 0;
	}
	return fifo_stream;
}

static void mi_sig_hup(int signo)
{
	mi_reload_fifo = 1;
}

FILE* mi_init_fifo_server(char *fifo_name, int fifo_mode,
						int fifo_uid, int fifo_gid, char* fifo_reply_dir)
{
	FILE *fifo_stream;


	/* allocate all static buffers */
	mi_buf = pkg_malloc(MAX_MI_FIFO_BUFFER);
	reply_fifo_s = pkg_malloc(MAX_MI_FILENAME);
	if ( mi_buf==NULL|| reply_fifo_s==NULL) {
		LM_ERR("no more private memory\n");
		return 0;
	}
	mi_fifo_name = fifo_name;
	mi_fifo_mode = fifo_mode;
	mi_fifo_uid = fifo_uid;
	mi_fifo_gid = fifo_gid;

	fifo_stream = mi_create_fifo();
	if (!fifo_stream) {
		LM_ERR("cannot create fifo\n");
		return 0;
	}

	/* init fifo reply dir buffer */
	reply_fifo_len = strlen(fifo_reply_dir);
	memcpy( reply_fifo_s, fifo_reply_dir, reply_fifo_len);

	if (signal(SIGHUP, mi_sig_hup) == SIG_ERR ) {
		LM_ERR("cannot install SIGHUP signal\n");
		fclose(fifo_stream);
		pkg_free(reply_fifo_s);
		return 0;
	}

	return fifo_stream;
}



/* reply fifo security checks:
 * checks if fd is a fifo, is not hardlinked and it's not a softlink
 * opened file descriptor + file name (for soft link check)
 * returns 0 if ok, <0 if not */
static int mi_fifo_check(int fd, char* fname)
{
	struct stat fst;
	struct stat lst;

	if (fstat(fd, &fst)<0){
		LM_ERR("fstat failed: %s\n", strerror(errno));
		return -1;
	}
	/* check if fifo */
	if (!S_ISFIFO(fst.st_mode)){
		LM_ERR("%s is not a fifo\n", fname);
		return -1;
	}
	/* check if hard-linked */
	if (fst.st_nlink>1){
		LM_ERR("security: fifo_check: %s is hard-linked %d times\n", fname, (unsigned)fst.st_nlink);
		return -1;
	}

	/* lstat to check for soft links */
	if (lstat(fname, &lst)<0){
		LM_ERR("lstat failed: %s\n", strerror(errno));
		return -1;
	}
	if (S_ISLNK(lst.st_mode)){
		LM_ERR("security: fifo_check: %s is a soft link\n", fname);
		return -1;
	}
	/* if this is not a symbolic link, check to see if the inode didn't
	 * change to avoid possible sym.link, rm sym.link & replace w/ fifo race
	 */
	if ((lst.st_dev!=fst.st_dev)||(lst.st_ino!=fst.st_ino)){
		LM_ERR("security: fifo_check: inode/dev number differ: %d %d (%s)\n",
			(int)fst.st_ino, (int)lst.st_ino, fname);
		return -1;
	}
	/* success */
	return 0;
}


static inline FILE* get_fifo_stream(FILE *old_stream)
{
	int fd, n;
	struct stat fst;

	if (mi_reload_fifo == 0) {
		fd = fileno(old_stream);
		if (!mi_fifo_check(fd, mi_fifo_name))
			return old_stream;
		LM_INFO("invalid FIFO file: creating a new one (%s)\n", mi_fifo_name);
	} else {
		LM_INFO("Forcefully replacing FIFO file (%s)\n", mi_fifo_name);
	}
	/* here we are either forced to reload or the check did not pass */
	n = stat(mi_fifo_name, &fst);
	if (n == 0) {
		if (unlink(mi_fifo_name) < 0) {
			LM_ERR("cannot delete fifo file %s\n", mi_fifo_name);
			return NULL;
		}
		LM_INFO("deleted FIFO file (%s)\n", mi_fifo_name);
	} else if (n < 0 && errno != ENOENT) {
		LM_ERR("stat failed: %s\n", strerror(errno));
		return NULL;
	}
	mi_reload_fifo = 0;
	return mi_create_fifo();
}


static FILE *mi_open_reply_pipe( char *pipe_name )
{
	int fifofd;
	FILE *file_handle;
	int flags;

	int retries=FIFO_REPLY_RETRIES;

	if (!pipe_name || *pipe_name==0) {
		LM_DBG("no file to write to about missing cmd\n");
		return 0;
	}

tryagain:
	/* open non-blocking to make sure that a broken client will not
	 * block the FIFO server forever */
	fifofd=open( pipe_name, O_WRONLY | O_NONBLOCK );
	if (fifofd==-1) {
		/* retry several times if client is not yet ready for getting
		   feedback via a reply pipe
		*/
		if (errno==ENXIO) {
			/* give up on the client - we can't afford server blocking */
			if (retries==0) {
				LM_ERR("no client at %s\n",pipe_name );
				return 0;
			}
			/* don't be noisy on the very first try */
			if (retries!=FIFO_REPLY_RETRIES)
				LM_DBG("retry countdown: %d\n", retries );
			sleep_us( FIFO_REPLY_WAIT );
			retries--;
			goto tryagain;
		}
		/* some other opening error */
		LM_ERR("open error (%s): %s\n", pipe_name, strerror(errno));
		return 0;
	}
	/* security checks: is this really a fifo?, is
	 * it hardlinked? is it a soft link? */
	if (mi_fifo_check(fifofd, pipe_name)<0) goto error;

	/* we want server blocking for big writes */
	if ( (flags=fcntl(fifofd, F_GETFL, 0))<0) {
		LM_ERR("pipe (%s): getfl failed: %s\n", pipe_name, strerror(errno));
		goto error;
	}
	flags&=~O_NONBLOCK;
	if (fcntl(fifofd, F_SETFL, flags)<0) {
		LM_ERR("pipe (%s): setfl cntl failed: %s\n", pipe_name, strerror(errno));
		goto error;
	}

	/* create an I/O stream */
	file_handle=fdopen( fifofd, "w");
	if (file_handle==NULL) {
		LM_ERR("open error (%s): %s\n",
			pipe_name, strerror(errno));
		goto error;
	}
	return file_handle;
error:
	close(fifofd);
	return 0;
}

static FILE *mi_init_read(FILE *stream, int *fd, fd_set *fds)
{
	FILE *new_stream = get_fifo_stream(stream);
	if (!new_stream)
		return NULL;
	*fd = fileno(new_stream);
	FD_ZERO(fds);
	FD_SET(*fd, fds);
	return new_stream;
}


int mi_read_line( char *b, int max, FILE **stream, int *read_len)
{
	int ret = 0;
	int done, i, fd;
	struct timeval tv;
	fd_set fds, init_fds;
	FILE *new_stream;

	/* first check if we need to update our fifo file */
	if (!(new_stream = mi_init_read(*stream, &fd, &init_fds)))
		return -1;

	done = 0;
	for (i = 0; !done && i < max; i++) {
		fds = init_fds;
		tv.tv_sec = FIFO_CHECK_WAIT;
		tv.tv_usec = 0;
retry:
		ret = select(fd + 1, &fds, NULL, NULL, &tv);
		if (ret < 0)  {
			if (errno == EAGAIN)
				goto retry;
			/* interrupted by signal or ... */
			if (errno == EINTR) {
				if (!(new_stream = mi_init_read(new_stream, &fd, &init_fds)))
					return -1;
			} else {
				kill(0, SIGTERM);
			}
		} else if (ret == 0) {
			if (!(new_stream = mi_init_read(new_stream, &fd, &init_fds)))
				return -1;
			--i;
			continue;
		}
		ret = read(fd, &b[i], 1);
		if (ret < 0)
			return ret;
		else if (ret == 0 || b[i] == '\n')
			done = 1;
	}

	if (!done) {
		LM_ERR("request line too long\n");
		fclose(new_stream);
		return -1;
	}
	*read_len = i;
	*stream = new_stream;

	return 0;
}



static inline char *get_reply_filename( char * file, int len )
{
	if ( strchr(file,'.') || strchr(file,'/') || strchr(file, '\\') ) {
		LM_ERR("forbidden filename: %s\n", file);
		return 0;
	}

	if (reply_fifo_len + len + 1 > MAX_MI_FILENAME) {
		LM_ERR("reply fifoname too long %d\n",reply_fifo_len + len);
		return 0;
	}

	memcpy( reply_fifo_s+reply_fifo_len, file, len );
	reply_fifo_s[reply_fifo_len+len]=0;


	return reply_fifo_s;
}


static inline void free_async_handler( struct mi_handler *hdl )
{
	if (hdl)
		shm_free(hdl);
}


static void fifo_close_async( struct mi_root *mi_rpl, struct mi_handler *hdl,
																	int done)
{
	FILE *reply_stream;
	char *name;

	static const int code = 500;
	static str reason = str_init("command failed");

	name = (char*)hdl->param;

	if ( mi_rpl!=0 || done ) {
		/*open fifo reply*/
		reply_stream = mi_open_reply_pipe( name );
		if (reply_stream==NULL) {
			LM_ERR("cannot open reply pipe %s\n", name );
			return;
		}

		if (mi_rpl!=0) {
			mi_write_tree( reply_stream, mi_rpl, 0);
			free_mi_tree( mi_rpl );
		} else {
			mi_fifo_reply( reply_stream, "%d %.*s\n", code, reason.len, reason.s);
			mi_trace_reply( 0, 0, code, &reason, 0, t_dst);
		}

		fclose(reply_stream);
	}

	if (done)
		free_async_handler( hdl );
	return;
}


static inline struct mi_handler* build_async_handler( char *name, int len)
{
	struct mi_handler *hdl;
	char *p;

	hdl = (struct mi_handler*)shm_malloc( sizeof(struct mi_handler) + len + 1);
	if (hdl==0) {
		LM_ERR("no more shared memory\n");
		return 0;
	}

	p = (char*)(hdl) + sizeof(struct mi_handler);
	memcpy( p, name, len+1 );

	hdl->handler_f = fifo_close_async;
	hdl->param = (void*)p;

	return hdl;
}


#define mi_do_consume() \
	do { \
		LM_DBG("entered consume\n"); \
		/* consume the rest of the fifo request */ \
		do { \
			mi_read_line(mi_buf,MAX_MI_FIFO_BUFFER,&fifo_stream,&line_len); \
		} while(line_len>1); \
		LM_DBG("**** done consume\n"); \
	} while(0)


#define mi_open_reply(_name,_file,_err) \
	do { \
		_file = mi_open_reply_pipe( _name ); \
		if (_file==NULL) { \
			LM_ERR("cannot open reply pipe %s\n", _name); \
			goto _err; \
		} \
	} while(0)

#define mi_write_err2buf( _buf, _max_size, _err, ...) \
	do { \
		_buf.len = snprintf( _buf.s, _max_size, __VA_ARGS__); \
		if ( _buf.len >= _max_size ) { \
			LM_ERR("can't fit message in reply buffer!\n"); \
			goto _err; \
		} \
	} while(0);

#define mi_throw_error( f, _stream, _buf, _code, _err, ...) \
	do { \
		mi_write_err2buf( _buf, _code, _err, __VA_ARGS__); \
		mi_fifo_reply(_stream, "%d %.*s\n", _code, _buf.len, _buf.s); \
		if ( (f && is_mi_cmd_traced( mi_trace_mod_id, f)) || !f ) \
			mi_trace_reply( 0, 0, _code, &_buf, 0, t_dst); \
	} while(0);




void mi_fifo_server(FILE *fifo_stream)
{
	struct mi_root *mi_cmd;
	struct mi_root *mi_rpl;
	struct mi_handler *hdl;
	int line_len;
	char *file_sep, *command, *file;
	struct mi_cmd *f;
	FILE *reply_stream;

	static char err_rpl_buf[ERR_BUF_SIZE];
	static str err_reason = { err_rpl_buf, 0};

	while(1) {
		reply_stream = NULL;

		/* commands must look this way ':<command>:[filename]' */
		if (mi_read_line(mi_buf,MAX_MI_FIFO_BUFFER,&fifo_stream, &line_len)) {
			LM_ERR("failed to read command\n");
			continue;
		}

		/* trim from right */
		while(line_len) {
			if(mi_buf[line_len-1]=='\n' || mi_buf[line_len-1]=='\r'
				|| mi_buf[line_len-1]==' ' || mi_buf[line_len-1]=='\t' ) {
				line_len--;
				mi_buf[line_len]=0;
			} else break;
		}

		if (line_len==0) {
			LM_DBG("command empty\n");
			continue;
		}
		if (line_len<3) {
			LM_ERR("command must have at least 3 chars\n");
			continue;
		}
		if (*mi_buf!=MI_CMD_SEPARATOR) {
			LM_ERR("command must begin with %c: %.*s\n", MI_CMD_SEPARATOR, line_len, mi_buf );
			goto consume1;
		}
		command = mi_buf+1;
		file_sep=strchr(command, MI_CMD_SEPARATOR );
		if (file_sep==NULL) {
			LM_ERR("file separator missing\n");
			goto consume1;
		}
		if (file_sep==command) {
			LM_ERR("empty command\n");
			goto consume1;
		}
		if (*(file_sep+1)==0) {
			file = NULL;
		} else {
			file = file_sep+1;
			file = get_reply_filename(file, mi_buf+line_len-file);
			if (file==NULL) {
				LM_ERR("trimming filename\n");
				goto consume1;
			}
		}
		/* make command zero-terminated */
		*file_sep=0;

		f=lookup_mi_cmd( command, strlen(command) );
		if (f==0) {
			LM_ERR("command %s is not available\n", command);
			mi_open_reply( file, reply_stream, consume1);

			mi_trace_request( 0, 0, command, strlen(command),
											0, &backend, t_dst);
			mi_throw_error( 0, reply_stream, err_reason, INTERNAL_ERR_CODE,
				consume2, "command '%s' not available", command);

			goto consume2;
		}

		/* if asyncron cmd, build the async handler */
		if (f->flags&MI_ASYNC_RPL_FLAG) {
			hdl = build_async_handler( file, strlen(file) );
			if (hdl==0) {
				LM_ERR("failed to build async handler\n");
				mi_open_reply( file, reply_stream, consume1);

				mi_throw_error( f, reply_stream, err_reason, INTERNAL_ERR_CODE,
					consume2, "Internal server error");

				goto consume2;
			}
		} else {
			hdl = 0;
			mi_open_reply( file, reply_stream, consume1);
		}

		if (f->flags&MI_NO_INPUT_FLAG) {
			mi_cmd = 0;
			mi_do_consume();
		} else {
			mi_cmd = mi_parse_tree(fifo_stream);
			if (mi_cmd==NULL){
				LM_ERR("error parsing MI tree\n");
				if (!reply_stream)
					mi_open_reply( file, reply_stream, consume3);

				mi_throw_error( f, reply_stream, err_reason, PARSE_ERR_CODE,
					consume3, "Parse error in command '%s'", command);
				goto consume3;
			}
			mi_cmd->async_hdl = hdl;
		}

		LM_DBG("done parsing the mi tree\n");

		if ( (is_mi_cmd_traced(mi_trace_mod_id, f)) || !f ) {
			mi_trace_request( 0, 0, command, file_sep - command,
											mi_cmd, &backend, t_dst);
		}

		if ( (mi_rpl=run_mi_cmd(f, mi_cmd,
		(mi_flush_f *)mi_flush_tree, reply_stream))==0 ) {
			if (!reply_stream)
				mi_open_reply( file, reply_stream, failure);

			mi_throw_error( f, reply_stream, err_reason, INTERNAL_ERR_CODE,
					consume3, "command '%s' failed", command);
		} else if (mi_rpl!=MI_ROOT_ASYNC_RPL) {
			if (!reply_stream)
				mi_open_reply( file, reply_stream, failure);
			mi_write_tree( reply_stream, mi_rpl,
					( f && is_mi_cmd_traced( mi_trace_mod_id, f) ) );

			free_mi_tree( mi_rpl );
		} else {
			if (mi_cmd) free_mi_tree( mi_cmd );
			continue;
		}

		free_async_handler(hdl);
		/* close reply fifo */
		fclose(reply_stream);
		/* destroy request tree */
		if (mi_cmd) free_mi_tree( mi_cmd );
		continue;

failure:
		free_async_handler(hdl);
		/* destroy request tree */
		if (mi_cmd) free_mi_tree( mi_cmd );
		/* destroy the reply tree */
		if (mi_rpl) free_mi_tree(mi_rpl);
		continue;

consume3:
		free_async_handler(hdl);
		if (reply_stream)
consume2:
		fclose(reply_stream);
consume1:
		mi_do_consume();
	}
}
