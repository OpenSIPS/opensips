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
int mi_fifo_pp;

FILE* mi_create_fifo(void)
{
	static int  mi_fifo_read = 0;
	static int  mi_fifo_write = 0;
	FILE *fifo_stream = 0;
	long opt;

	/* create FIFO ... */
	if ((mkfifo(mi_fifo_name, mi_fifo_mode)<0)) {
		LM_ERR("can't create FIFO: %s (mode=%o)\n", strerror(errno), mi_fifo_mode);
		return 0;
	}

	LM_DBG("FIFO created @ %s\n", mi_fifo_name );

	if ((chmod(mi_fifo_name, mi_fifo_mode)<0)) {
		LM_ERR("can't chmod FIFO: %s (mode=%o)\n", strerror(errno), mi_fifo_mode);
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
	mi_buf = pkg_malloc(MAX_MI_FIFO_BUFFER + 1);
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
				LM_NOTICE("no client at %s\n", pipe_name );
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


static int mi_read_fifo(char *b, int max, FILE **stream, int *read_len)
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
		ret = read(fd, b, max);
		if (ret < 0)
			return ret;
		else
			done = 1;
	}

	if (!done) {
		LM_ERR("request line too long\n");
		fclose(new_stream);
		return -1;
	}
	*read_len = ret;
	*stream = new_stream;

	return 0;
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
	if (memchr(file,'.',len) || memchr(file,'/',len) || memchr(file,'\\', len)) {
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


#define mi_open_reply(_name,_file,_err) \
	do { \
		if (!(_file) && (_name)) { \
			_file = mi_open_reply_pipe( _name ); \
			if (!(_file)) { \
				LM_NOTICE("cannot open reply pipe %s\n", _name); \
				goto _err; \
			} \
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

#define mi_trace_fifo_request(method, params) \
	do { \
		if ((!cmd || is_mi_cmd_traced(mi_trace_mod_id, cmd))) { \
			mi_trace_request(0, 0, method, strlen(method), \
						params, &backend, t_dst); \
		} \
	} while(0)

#define mi_trace_fifo_reply(message) \
	do { \
		if ((!cmd || is_mi_cmd_traced(mi_trace_mod_id, cmd))) { \
			mi_trace_reply(0, 0, message, t_dst); \
		} \
	} while(0)

#define mi_throw_error(_stream, _file, _err, _msg) \
	do { \
		if (_file) { \
			str _s = str_init(_msg); \
			mi_open_reply( _file, _stream, _err); \
			if (mi_fifo_write(_file, _stream, &_s, cmd) < 0) { \
				LM_ERR("cannot reply %s error\n", _msg); \
				goto _err; \
			} \
			mi_trace_fifo_reply(&_s); \
		} \
	} while(0);

struct mi_fifo_flush_params {
	FILE *stream;
	char *file;
	struct mi_cmd *cmd;
};

static int mi_fifo_write(char *file, FILE *stream, str *msg, struct mi_cmd *cmd)
{
	int ret, written;
	FILE *old_stream = stream;

	mi_open_reply(file, stream, error);

	written = 0;
	do {
		ret = fwrite(msg->s + written, 1, msg->len - written, stream);
		if (ret <= 0) {
			if (errno!=EINTR && errno!=EAGAIN && errno!=EWOULDBLOCK)
				goto error;
		} else
			written += ret;
	} while (msg->len > written);

	mi_trace_fifo_reply(msg);

	if (!old_stream && stream)
		fclose(stream);
	return written;

error:
	if (stream)
		fclose(stream);
	return -1;
}

static int mi_fifo_flush(unsigned char *buf, int len, void *param)
{
	str msg;
	struct mi_fifo_flush_params *params =
		(struct mi_fifo_flush_params *)param;

	if (!params)
		return len;

	msg.s = (char *)buf;
	msg.len = len;

	return mi_fifo_write(params->file, params->stream, &msg, params->cmd);
}

struct mi_async_param {
	mi_item_t *id;
	char *file;
};

static inline void free_async_handler(struct mi_handler *hdl)
{
	if (hdl) {
		free_shm_mi_item(((struct mi_async_param *)hdl->param)->id);
		shm_free(hdl);
	}
}

static int mi_fifo_reply(FILE *reply_stream, char *file, str *buf,
		mi_response_t *response, mi_item_t *id, struct mi_cmd *cmd)
{
	struct mi_fifo_flush_params params;

	params.cmd = cmd;
	params.file = file;
	params.stream = reply_stream;

	return print_mi_response_flush(response, id,
			mi_fifo_flush, &params, buf, mi_fifo_pp);
}

static void fifo_close_async(mi_response_t *resp, struct mi_handler *hdl, int done)
{
	FILE *reply_stream = NULL;
	struct mi_async_param *p;
	int rc;
	char buffer[MAX_MI_FIFO_BUFFER];
	str buf;
	buf.s = buffer;
	buf.len = MAX_MI_FIFO_BUFFER;
	struct mi_cmd *cmd = NULL; /* used by mi_throw_error */

	p = (struct mi_async_param *)hdl->param;

	if (resp || done) {
		if (resp!=0) {
			rc = mi_fifo_reply(NULL, p->file, &buf, resp, p->id, NULL);
			if (rc == MI_NO_RPL) {
				LM_DBG("No reply for jsonrpc notification\n");
			} else if (rc < 0) {
				LM_ERR("failed to print json response\n");
				mi_throw_error(reply_stream, p->file, free_request,
						"failed to print response");
			} else
				free_mi_response(resp);
		} else {
			mi_throw_error(reply_stream, p->file, free_request,
					"failed to build response");
		}

		if (reply_stream)
			fclose(reply_stream);
	}

free_request:
	if (done)
		free_async_handler(hdl);
	return;
}


static inline struct mi_handler* build_async_handler(char *name, int len, mi_item_t *id)
{
	struct mi_handler *hdl;
	struct mi_async_param *p;
	char *file;

	hdl = (struct mi_handler*)shm_malloc(sizeof(struct mi_handler) +
			sizeof(struct mi_async_param) + len + 1);
	if (hdl==0) {
		LM_ERR("no more shared memory\n");
		return 0;
	}
	p = (struct mi_async_param*)((char *)hdl + sizeof(struct mi_handler));
	file = (char *)(p + 1);
	p->file = file;
	p->id = shm_clone_mi_item(id);

	memcpy(file, name, len+1 );

	hdl->handler_f = fifo_close_async;
	hdl->param = (void*)p;

	return hdl;
}


void mi_fifo_server(FILE *fifo_stream)
{
	const char *parse_end;
	mi_request_t request;
	int read_len, parse_len;
	char *req_method = NULL;
	char *file_sep, *file, *p, *f;
	struct mi_cmd *cmd = NULL;
	FILE *reply_stream;
	int remain_len = 0;
	struct mi_handler *hdl = NULL;
	mi_response_t *response = NULL;
	int rc;
	str buf;

	while(1) {

		/* commands must look this way ':[filename]:' */
		if (mi_read_fifo(mi_buf + remain_len,
				MAX_MI_FIFO_BUFFER - remain_len,
				&fifo_stream, &read_len)) {
			LM_ERR("failed to read command\n");
			goto skip_unparsed;
		}
		parse_len = remain_len + read_len;

retry:
		reply_stream = NULL;
		p = mi_buf;

		while (parse_len && is_ws(*p)) {
			p++;
			parse_len--;
		}

		if (parse_len==0) {
			LM_DBG("command file is empty\n");
			goto skip_unparsed;
		}
		if (parse_len<3) {
			LM_DBG("command must have at least 3 chars (has %d)\n", parse_len);
			continue;
		}
		if (*p!=MI_CMD_SEPARATOR) {
			LM_ERR("command must begin with '%c': [%.*s]\n", MI_CMD_SEPARATOR, parse_len, p);
			goto skip_unparsed;
		}
		p++;
		parse_len--;
		file = p;
		file_sep=memchr(p, MI_CMD_SEPARATOR , parse_len);
		if (file_sep==NULL) {
			LM_DBG("file separator missing: %.*s\n", read_len, mi_buf);
			continue;
		}
		if (file_sep - file + 1 >= parse_len) {
			LM_DBG("no command specified yet: %.*s\n", read_len, mi_buf);
			continue;
		}
		p = file_sep + 1;
		parse_len -= file_sep - file + 1;
		if (file_sep==file) {
			file = NULL; /* no reply expected */
		} else {
			f = get_reply_filename(file, file_sep - file);
			if (f==NULL) {
				LM_ERR("error trimming filename: %.*s\n", (int)(file_sep - file), file);
				file = f;
				goto skip_unparsed;
			}
			file = f;
		}

		/* make the command null terminated */
		p[parse_len] = '\0';
		memset(&request, 0, sizeof request);
		if (parse_mi_request(p, &parse_end, &request) < 0) {
			LM_ERR("cannot parse command: %.*s\n", parse_len, p);
			continue;
		}
		if (parse_end)
			LM_DBG("running command [%.*s]\n", (int)(parse_end - p), p);
		else
			LM_DBG("running command [%s]\n", p);

		if (parse_end) {
			parse_len -= parse_end - p;
			p = (char *)parse_end;
			memmove(mi_buf, p, parse_len);
		} else
			parse_len = 0;
		remain_len = parse_len;

		req_method = mi_get_req_method(&request);
		if (req_method)
			cmd = lookup_mi_cmd(req_method, strlen(req_method));
		/* if asyncron cmd, build the async handler */
		if (cmd && cmd->flags&MI_ASYNC_RPL_FLAG) {
			hdl = build_async_handler(file, strlen(file), request.id);
			if (hdl==0) {
				LM_ERR("failed to build async handler\n");

				mi_throw_error(reply_stream, file, free_request,
						"failed to build async handler");

				goto free_request;
			}
		} else {
			hdl = 0;
			mi_open_reply( file, reply_stream, free_request);
			if (!cmd)
				LM_INFO("command %s not found!\n", req_method);
		}

		mi_trace_fifo_request(req_method, request.params);
		response = handle_mi_request(&request, cmd, hdl);
		LM_DBG("got mi response = [%p]\n", response);

		if (response == NULL) {
			LM_ERR("failed to build response!\n");
			mi_throw_error(reply_stream, file, free_request,
					"failed to build response");
		} else if (response != MI_ASYNC_RPL) {
			buf.s = mi_buf + remain_len;
			buf.len = MAX_MI_FIFO_BUFFER - remain_len;
			if (file) {
				rc = mi_fifo_reply(reply_stream, file, &buf,
						response, request.id, cmd);
				if (rc == MI_NO_RPL) {
					LM_DBG("No reply for jsonrpc notification\n");
				} else if (rc < 0) {
					LM_ERR("failed to print json response\n");
					mi_throw_error(reply_stream, file, free_request,
							"failed to print response");
				} else
					free_mi_response(response);
			}
			/* if there is no file specified, there is nothing to reply */
		} else
			goto end;

free_request:
		free_async_handler(hdl);
		free_mi_request_parsed(&request);
		if (reply_stream)
			fclose(reply_stream);
end:
		if (parse_len)
			goto retry;
		continue;
skip_unparsed:
		remain_len = 0;
	}
}
