/*
 * $Id$
 *
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
 *
 * Fifo server is a very powerful tool used to access easily
 * ser's internals via textual interface, similarly to
 * how internals of many operating systems are accessible
 * via the proc file system. This might be used for
 * making ser do things for you (such as initiating new
 * transaction from webpages) or inspect server's health.
 * 
 * FIFO server allows new functionality to be registered
 * with it -- thats what register_fifo_cmd is good for.
 * Remember, the initialization must take place before
 * forking; best in init_module functions. When a function
 * is registered, it can be always evoked by sending its
 * name prefixed by colon to the FIFO.
 *
 * There are few commands already implemented in core.
 * These are 'uptime' for looking at how long the server
 * is alive and 'print' for debugging purposes.
 *
 * Every command sent to FIFO must be sent atomically to
 * avoid intermixing with other commands and MUST be
 * terminated by empty line so that the server is to able
 * to find its end if it does not understand the command.
 *
 * File test/transaction.fifo illustrates example of use
 * of t_uac command (part of TM module).
 */


#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include "dprint.h"
#include "ut.h"
#include "error.h"
#include "config.h"
#include "globals.h"
#include "fifo_server.h"
#include "mem/mem.h"
#include "sr_module.h"
#include "pt.h"

/* FIFO server vars */
char *fifo="/tmp/ser_fifo"; /* FIFO name */
int fifo_mode=S_IRUSR | S_IWUSR | S_IRGRP | 
	S_IWGRP | S_IROTH | S_IWOTH;
pid_t fifo_pid;
/* file descriptors */
static int fifo_read=0;
static int fifo_write=0;
static FILE *fifo_stream;

/* list of fifo command */
static struct fifo_command *cmd_list=0;

/* up time */
static time_t up_since;
static char up_since_ctime[MAX_CTIME_LEN];

static struct fifo_command *lookup_fifo_cmd( char *name )
{
	struct fifo_command *c;
	for(c=cmd_list; c; c=c->next) {
		if (strcasecmp(c->name, name)==0) return c;
	}
	return 0;
}

int register_fifo_cmd(fifo_cmd f, char *cmd_name, void *param)
{
	struct fifo_command *new_cmd;

	if (lookup_fifo_cmd(cmd_name)) {
		LOG(L_ERR, "ERROR: register_fifo_cmd: attempt to register synonyms\n");
		return E_BUG;
	}
	new_cmd=malloc(sizeof(struct fifo_command));
	if (new_cmd==0) {
		LOG(L_ERR, "ERROR: register_fifo_cmd: out of mem\n");
		return E_OUT_OF_MEM;
	}
	new_cmd->f=f;
	new_cmd->name=cmd_name;
	new_cmd->param=param;

	new_cmd->next=cmd_list;
	cmd_list=new_cmd;
	
	DBG("DEBUG: register_fifo_cmd: new command (%s) registered\n", cmd_name );

	return 1;
}


int read_line( char *b, int max, FILE *stream, int *read )
{
	int len;
	int retry_cnt;

	retry_cnt=0;

retry:
	if (fgets(b, max, stream)==NULL) {
		LOG(L_ERR, "ERROR: fifo_server fgets failed: %s\n",
			strerror(errno));
		/* on Linux, fgets sometimes returns ESPIPE -- give
		   it few more chances
		*/
		if (errno==ESPIPE) {
			retry_cnt++;
			if (retry_cnt<4) goto retry;
		}
		kill(0, SIGTERM);
	}
	/* if we did not read whole line, our buffer is too small
	   and we cannot process the request; consume the remainder of 
	   request
	*/
	len=strlen(b);
	if (len && !(b[len-1]=='\n' || b[len-1]=='\r')) {
		LOG(L_ERR, "ERROR: read_line: request  line too long\n");
		return 0;
	}
	/* trim from right */
	while(len) {
		if(b[len-1]=='\n' || b[len-1]=='\r'
				|| b[len-1]==' ' || b[len-1]=='\t' ) {
			len--;
			b[len]=0;
		} else break;
	}
	*read=len;
	return 1;
}

static void consume_request( FILE *stream )
{
	int len;
	char buffer[MAX_CONSUME_BUFFER];

	while(!read_line(buffer, MAX_CONSUME_BUFFER, stream, &len));

#ifdef _OBSOLETED
	int eol_count;

	eol_count=0;

	/* each request must be terminated by two EoLs */
	while(eol_count!=2) {
		/* read until EoL is encountered */
		while(!read_line(buffer, MAX_CONSUME_BUFFER, stream, &len));
		eol_count=len==0?eol_count+1:1;
	}
#endif
}

int read_eol( FILE *stream )
{
	int len;
	char buffer[MAX_CONSUME_BUFFER];
	if (!read_line(buffer, MAX_CONSUME_BUFFER, stream, &len) || len!=0) {
		LOG(L_ERR, "ERROR: read_eol: EOL expected: %.10s...\n",
			buffer );
		return 0;
	}
	return 1;
}

/* read from input until empty line is encountered */	
int read_line_set(char *buf, int max_len, FILE *fifo, int *len)
{
	int set_len;
	char *c;
	int line_len;

	c=buf;set_len=0;
	while(1) {
		if (!read_line(c,max_len,fifo,&line_len)) {
			LOG(L_ERR, "ERROR: fifo_server: line expected\n");
			return 0;
		}
		/* end encountered ... return */
		if (line_len==0) {
			*len=set_len;
			return 1;
		}
		max_len-=line_len; c+=line_len; set_len+=line_len;
		if (max_len<CRLF_LEN) {
			LOG(L_ERR, "ERROR: fifo_server: no place for CRLF\n");
			return 0;
		}
		memcpy(c, CRLF, CRLF_LEN);
		max_len-=CRLF_LEN; c+=CRLF_LEN; set_len+=CRLF_LEN;
	}
}

/* read from input until line with only dot in it is encountered */
int read_body(char *buf, int max_len, FILE *fifo, int *len)
{
	int set_len;
	char *c;
	int line_len;

	c=buf;set_len=0;
	while(1) {
		if (!read_line(c,max_len,fifo,&line_len)) {
			LOG(L_ERR, "ERROR: fifo_server: line expected\n");
			return 0;
		}
		/* end encountered ... return */
		if (line_len==1 && *c=='.') {
			*len=set_len;
			return 1;
		}
		max_len-=line_len; c+=line_len; set_len+=line_len;
		if (max_len<CRLF_LEN) {
			LOG(L_ERR, "ERROR: fifo_server: no place for CRLF\n");
			return 0;
		}
		memcpy(c, CRLF, CRLF_LEN);
		max_len-=CRLF_LEN; c+=CRLF_LEN; set_len+=CRLF_LEN;
	}
}

static char *trim_filename( char * file )
{
	int prefix_len, fn_len;
	char *new_fn;

	/* we only allow files in "/tmp" -- any directory
	   changes are not welcome
	*/
	if (strchr(file,'.') || strchr(file,'/')
				|| strchr(file, '\\')) {
		LOG(L_ERR, "ERROR: trim_filename: forbidden filename: %s\n"
			, file);
		return 0;
	}
	prefix_len=strlen(FIFO_DIR); fn_len=strlen(file);
	new_fn=pkg_malloc(prefix_len+fn_len+1);
	if (new_fn==0) {
		LOG(L_ERR, "ERROR: trim_filename: no mem\n");
		return 0;
	}

	memcpy(new_fn, FIFO_DIR, prefix_len);
	memcpy(new_fn+prefix_len, file, fn_len );
	new_fn[prefix_len+fn_len]=0;

	return new_fn;
}

/* tell FIFO client what happened via reply pipe */
void fifo_reply( char *reply_fifo, char *reply_fmt, ... )
{
	FILE *file_handle;
	int r;
	va_list ap;

	file_handle=open_reply_pipe(reply_fifo);
	if (file_handle==0) {
		LOG(L_ERR, "ERROR: fifo_reply: no reply pipe %s\n",
			fifo);
		return;
	}
retry:
	va_start(ap, reply_fmt);
	r=vfprintf(file_handle, reply_fmt, ap);
	va_end(ap);
	if (r<=0) {
		LOG(L_ERR, "ERROR: fifo_error: write error (%s): %s\n",
			fifo, strerror(errno));
		if ((errno==EINTR)||(errno==EAGAIN)||(errno==EWOULDBLOCK)) {
			goto retry;
		}
	}
	fclose(file_handle);
}

FILE *open_reply_pipe( char *pipe_name )
{

	int fifofd;
	FILE *file_handle;

	int retries=FIFO_REPLY_RETRIES;

	if (!pipe_name || *pipe_name==0) {
		DBG("DEBUG: open_reply_pipe: no file to write to about missing cmd\n");
		return 0;
	}

tryagain:
	fifofd=open( pipe_name, O_WRONLY | O_NONBLOCK );
	if (fifofd==-1) {
		/* retry several times if client is not yet ready for getting
		   feedback via a reply pipe
		*/
		if (errno==ENXIO) {
			/* give up on the client - we can't afford server blocking */
			if (retries==0) {
				LOG(L_ERR, "ERROR: open_reply_pipe: no client at %s\n",
					pipe_name );
				return 0;
			}
			/* don't be noisy on the very first try */
			if (retries!=FIFO_REPLY_RETRIES)
				DBG("DEBUG: open_reply_pipe: retry countdown: %d\n", retries );
			sleep_us( FIFO_REPLY_WAIT );
			retries--;
			goto tryagain;
		}
		/* some other opening error */
		LOG(L_ERR, "ERROR: open_reply_pipe: open error (%s): %s\n",
			pipe_name, strerror(errno));
		return 0;
	}
	file_handle=fdopen( fifofd, "w");
	if (file_handle==NULL) {
		LOG(L_ERR, "ERROR: open_reply_pipe: open error (%s): %s\n",
			pipe_name, strerror(errno));
		return 0;
	}
	return file_handle;
}

static void fifo_server(FILE *fifo_stream)
{
	char buf[MAX_FIFO_COMMAND];
	int line_len;
	char *file_sep, *command, *file;
	struct fifo_command *f;

	file_sep=command=file=0;

	while(1) {

		/* commands must look this way ':<command>:[filename]' */
		if (!read_line(buf, MAX_FIFO_COMMAND, fifo_stream, &line_len)) {
			/* line breaking must have failed -- consume the rest
			   and proceed to a new request
			*/
			LOG(L_ERR, "ERROR: fifo_server: command expected\n");
			goto consume;
		}
		if (line_len==0) {
			LOG(L_INFO, "INFO: fifo_server: command empty\n");
			continue;
		}
		if (line_len<3) {
			LOG(L_ERR, "ERROR: fifo_server: command must have at least 3 chars\n");
			goto consume;
		}
		if (*buf!=CMD_SEPARATOR) {
			LOG(L_ERR, "ERROR: fifo_server: command must begin with %c: %.*s\n", 
				CMD_SEPARATOR, line_len, buf );
			goto consume;
		}
		command=buf+1;
		file_sep=strchr(command, CMD_SEPARATOR );
		if (file_sep==NULL) {
			LOG(L_ERR, "ERROR: fifo_server: file separator missing\n");
			goto consume;
		}
		if (file_sep==command) {
			LOG(L_ERR, "ERROR: fifo_server: empty command\n");
			goto consume;
		}
		if (*(file_sep+1)==0) file=NULL; 
		else {
			file=file_sep+1;
			file=trim_filename(file);
			if (file==0) {
				LOG(L_ERR, "ERROR: fifo_server: trimming filename\n");
				goto consume;
			}
		}
		/* make command zero-terminated */
		*file_sep=0;

		f=lookup_fifo_cmd( command );
		if (f==0) {
			LOG(L_ERR, "ERROR: fifo_server: command %s is not available\n",
				command);
			fifo_reply(file, "[%s not available]\n", command);
			goto consume;
		}
		if (f->f(fifo_stream, file)<0) {
			LOG(L_ERR, "ERROR: fifo_server: command (%s) "
				"processing failed\n", command );
			goto consume;
		}

consume:
		if (file) { pkg_free(file); file=0;}
		consume_request(fifo_stream);
	}
}

int open_fifo_server()
{
	char *t;

	if (fifo==NULL) {
		DBG("TM: open_uac_fifo: no fifo will be opened\n");
		/* everything is ok, we just do not want to start */
		return 1;
	}
	if (strlen(fifo)==0) {
		DBG("TM: open_uac_fifo: fifo disabled\n");
		return 1;
	}
	DBG("TM: open_uac_fifo: opening fifo...\n");
	if ((mkfifo(fifo, fifo_mode)<0) && (errno!=EEXIST)) {
		LOG(L_ERR, "ERROR: open_fifo_server; can't create FIFO: "
			"%s (mode=%d)\n",
			strerror(errno), fifo_mode);
		return -1;
	} 
	DBG("DEBUG: fifo %s opened, mode=%d\n", fifo, fifo_mode );
	time(&up_since);
	t=ctime(&up_since);
	if (strlen(t)+1>=MAX_CTIME_LEN) {
		LOG(L_ERR, "ERROR: open_fifo_server: "
			"too long date %d\n", strlen(t));
		return -1;
	}
	memcpy(up_since_ctime,t,strlen(t)+1);
	process_no++;
	fifo_pid=fork();
	if (fifo_pid<0) {
		LOG(L_ERR, "ERROR: open_fifo_server: failure to fork: %s\n",
			strerror(errno));
		return -1;
	}
	if (fifo_pid==0) { /* child == FIFO server */
		LOG(L_INFO, "INFO: fifo process starting: %d\n", getpid());
		/* call per-child module initialization too -- some
		   FIFO commands may need it
		*/
		if (init_child(process_no) < 0 ) {
			LOG(L_ERR, "ERROR: open_uac_fifo: init_child failed\n");
			return -1;
		}
		fifo_read=open(fifo, O_RDONLY, 0);
		if (fifo_read<0) {
			LOG(L_ERR, "ERROR: open_uac_fifo: fifo_read did not open: %s\n",
				strerror(errno));
			return -1;
		}
		fifo_stream=fdopen(fifo_read, "r"	);
		if (fifo_stream==NULL) {
			LOG(L_ERR, "SER: open_uac_fifo: fdopen failed: %s\n",
				strerror(errno));
			return -1;
		}
		/* a real server doesn't die if writing to reply fifo fails */
		signal(SIGPIPE, SIG_IGN);
		LOG(L_INFO, "SER: open_uac_fifo: fifo server up at %s...\n",
			fifo);
		fifo_server( fifo_stream ); /* never retruns */
	}
	/* dad process */
	pt[process_no].pid=fifo_pid;
	strncpy(pt[process_no].desc, "fifo server", MAX_PT_DESC );
	/* make sure the read fifo will not close */
	fifo_write=open(fifo, O_WRONLY, 0);
	if (fifo_write<0) {
		LOG(L_ERR, "SER: open_uac_fifo: fifo_write did not open: %s\n",
			strerror(errno));
		return -1;
	}
	return 1;
}

static int print_version_cmd( FILE *stream, char *response_file )
{
	if (response_file) {
		fifo_reply(response_file, SERVER_HDR CRLF );
	} else {
		LOG(L_ERR, "ERROR: no file for print_version_cmd\n");
	}
	return 1;
}
	

/* diagnostic and hello-world FIFO command */
static int print_fifo_cmd( FILE *stream, char *response_file )
{
	char text[MAX_PRINT_TEXT];
	int text_len;
	
	/* expect one line which will be printed out */
	if (response_file==0 || *response_file==0 ) { 
		LOG(L_ERR, "ERROR: print_fifo_cmd: null file\n");
		return -1;
	}
	if (!read_line(text, MAX_PRINT_TEXT, stream, &text_len)) {
		fifo_reply(response_file, 
			"ERROR: print_fifo_cmd: too big text");
		return -1;
	}
	/* now the work begins */
	if (response_file) {
		fifo_reply(response_file, text );
	} else {
		LOG(L_INFO, "INFO: print_fifo_cmd: %.*s\n", 
			text_len, text );
	}
	return 1;
}

static int uptime_fifo_cmd( FILE *stream, char *response_file )
{
	time_t now;

	if (response_file==0 || *response_file==0 ) { 
		LOG(L_ERR, "ERROR: uptime_fifo_cmd: null file\n");
		return -1;
	}

	time(&now);
	fifo_reply( response_file, "Now: %sUp Since: %sUp time: %.0f [sec]\n",
		ctime(&now), up_since_ctime, difftime(now, up_since) );

	return 1;
}

static int which_fifo_cmd(FILE *stream, char *response_file )
{
	FILE *reply_pipe;
	struct fifo_command *c;

	if (response_file==0 || *response_file==0 ) {
		 LOG(L_ERR, "ERROR: which_fifo_cmd: null file\n");
		return -1;
	}

	reply_pipe=open_reply_pipe(response_file);
	if (reply_pipe==NULL) {
		LOG(L_ERR, "ERROR: which_fifo_cmd: opening reply pipe (%s) failed\n",
			response_file );
		return -1;
	}
	fputs( "------ Begin of registered FIFO commands -----------\n", reply_pipe);
	for(c=cmd_list; c; c=c->next) {
		fprintf( reply_pipe, "%s\n", c->name );
	}
	fputs( "------ End of registered FIFO commands -----------\n", reply_pipe);

	fclose(reply_pipe);
	return 1;
}

static int ps_fifo_cmd(FILE *stream, char *response_file )
{
	FILE *reply_pipe;
	int p;

	if (response_file==0 || *response_file==0 ) {
		 LOG(L_ERR, "ERROR: ps_fifo_cmd: null file\n");
		return -1;
	}
	reply_pipe=open_reply_pipe(response_file);
	if (reply_pipe==NULL) {
		LOG(L_ERR, "ERROR: ps_fifo_cmd: opening reply pipe (%s) failed\n",
			response_file );
		return -1;
	}

	for (p=0; p<process_count();p++) 
		fprintf( reply_pipe, "%d\t%d\t%s\n",
			p, pt[p].pid, pt[p].desc );

	fclose(reply_pipe);
	return 1;
}


int register_core_fifo()
{
	if (register_fifo_cmd(print_fifo_cmd, FIFO_PRINT, 0)<0) {
		LOG(L_CRIT, "unable to register '%s' FIFO cmd\n", FIFO_PRINT);
		return -1;
	}
	if (register_fifo_cmd(uptime_fifo_cmd, FIFO_UPTIME, 0)<0) {
		LOG(L_CRIT, "unable to register '%s' FIFO cmd\n", FIFO_UPTIME);
		return -1;
	}
	if (register_fifo_cmd(print_version_cmd, FIFO_VERSION, 0)<0) {
		LOG(L_CRIT, "unable to register '%s' FIFO cmd\n", FIFO_VERSION);
		return -1;
	}
	if (register_fifo_cmd(which_fifo_cmd, FIFO_WHICH, 0)<0) {
		LOG(L_CRIT, "unable to register '%s' FIFO cmd\n", FIFO_WHICH);
		return -1;
	}
	if (register_fifo_cmd(ps_fifo_cmd, FIFO_PS, 0)<0) {
		LOG(L_CRIT, "unable to register '%s' FIFO cmd\n", FIFO_PS);
		return -1;
	}
	return 1;
}
