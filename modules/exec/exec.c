/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * History
 * --------
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-28 scratchpad removed
 * 2004-07-21 rewrite uri done via action() (bogdan)
 */


#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
/*
#include <sys/resource.h>
*/
#include <sys/wait.h>
#include "../../mem/mem.h"
#include "../../error.h"
#include "../../config.h"
#include "../../parser/msg_parser.h"
#include "../../dprint.h"
#include "../../dset.h"
#include "../../action.h"
#include "../../usr_avp.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../mod_fix.h"

#include "exec.h"
#include "kill.h"

#define SLEEP_INTERVAL		300


int exec_msg(struct sip_msg *msg, char *cmd )
{
	FILE *pipe;
	int exit_status;
	int ret;
	pid_t pid;

	ret=-1; /* pessimist: assume error */
	pid = __popen3(cmd, &pipe, NULL, NULL);
	if (pid < 0) {
		LM_ERR("cannot open pipe: %s\n", cmd);
		ser_error=E_EXEC;
		return -1;
	}

	LM_DBG("Forked pid %d\n", pid);

	if (fwrite(msg->buf, 1, msg->len, pipe)!=msg->len || fflush(pipe)) {
		LM_ERR("failed to write to pipe\n");
		ser_error=E_EXEC;
		goto error01;
	}

	schedule_to_kill(pid);
	wait(&exit_status);

	/* success */
	ret=1;

error01:
	if (ferror(pipe)) {
		LM_ERR("pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}

	pclose(pipe);
	if (WIFEXITED(exit_status)) { /* exited properly .... */
		/* return false if script exited with non-zero status */
		if (WEXITSTATUS(exit_status)!=0) ret=-1;
	} else { /* exited erroneously */
		LM_ERR("cmd %s failed. exit_status=%d, errno=%d: %s\n",
			cmd, exit_status, errno, strerror(errno) );
		ret=-1;
	}
	return ret;
}

int exec_write_input(FILE** stream, str* input)
{
	if (fwrite(input->s, 1, input->len, *stream) != input->len) {
		LM_ERR("failed to write to pipe\n");
		ser_error=E_EXEC;
		return -1;
	}

	if (ferror(*stream)) {
		LM_ERR("writing pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		return -1;
	}

	pclose(*stream);

	return 0;
}


int exec_str(struct sip_msg *msg, char *cmd, char *param, int param_len) {

	int cmd_len;
	FILE *pipe;
	char *cmd_line;
	int ret;
	int l1;
	static char uri_line[MAX_URI_SIZE+1];
	int uri_cnt;
	str uri;
	int exit_status;
	pid_t pid;

	/* pessimist: assume error by default */
	ret=-1;

	l1=strlen(cmd);
	if(param_len>0)
		cmd_len=l1+param_len+4;
	else
		cmd_len=l1+1;
	cmd_line=pkg_malloc(cmd_len);
	if (cmd_line==0) {
		ret=ser_error=E_OUT_OF_MEM;
		LM_ERR("no pkg mem for command\n");
		goto error00;
	}

	/* 'command parameter \0' */
	memcpy(cmd_line, cmd, l1);
	if(param_len>0)
	{
		cmd_line[l1]=' ';
		cmd_line[l1+1]='\'';
		memcpy(cmd_line+l1+2, param, param_len);
		cmd_line[l1+param_len+2]='\'';
		cmd_line[l1+param_len+3]=0;
	} else {
		cmd_line[l1] = 0;
	}

	pid = __popen3(cmd_line, NULL, &pipe, NULL);
	if (pid < 0) {
		LM_ERR("failed to run command: %s\n", cmd_line);
		ser_error=E_EXEC;
		goto error01;
	}

	LM_DBG("Forked pid %d\n", pid);
	schedule_to_kill(pid);
	wait(&exit_status);

	/* read now line by line */
	uri_cnt=0;
	while (fgets(uri_line, MAX_URI_SIZE, pipe)) {
		uri.s = uri_line;
		uri.len=strlen(uri.s);
		trim_trailing(&uri);

		/* skip empty line */
		if (uri.len==0) continue;
		/* ZT */
		uri.s[uri.len]=0;
		if (uri_cnt==0) {
			if (set_ruri(msg, &uri)==-1 ) {
				LM_ERR("failed to set new RURI\n");
				ser_error=E_OUT_OF_MEM;
				goto error02;
			}
		} else {
			if (append_branch(msg, &uri, 0, 0, Q_UNSPECIFIED, 0, 0)==-1) {
				LM_ERR("append_branch failed; too many or too long URIs?\n");
				goto error02;
			}
		}
		uri_cnt++;
	}
	if (uri_cnt==0) {
		LM_ERR("no uri from %s\n", cmd_line );
		goto error02;
	}
	/* success */
	ret=1;

error02:
	if (ferror(pipe)) {
		LM_ERR("in pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}

	pclose(pipe);
	if (WIFEXITED(exit_status)) { /* exited properly .... */
		/* return false if script exited with non-zero status */
		if (WEXITSTATUS(exit_status)!=0) ret=-1;
	} else { /* exited erroneously */
		LM_ERR("cmd %s failed. exit_status=%d, errno=%d: %s\n",
			cmd, exit_status, errno, strerror(errno) );
		ret=-1;
	}
error01:
	pkg_free(cmd_line);
error00:
	return ret;
}


int exec_avp(struct sip_msg *msg, char *cmd, pvname_list_p avpl)
{
	int_str avp_val;
	int_str avp_name;
	unsigned short avp_type;
	FILE *pipe;
	int ret;
	char res_line[MAX_URI_SIZE+1];
	str res;
	int exit_status;
	int i;
	pvname_list_t* crt;
	pid_t pid;

	/* pessimist: assume error by default */
	ret=-1;

	pid = __popen3(cmd, NULL, &pipe, NULL);
	if (pid < 0) {
		LM_ERR("failed to run command: %s\n", cmd);
		ser_error=E_EXEC;
		return ret;
	}

	LM_DBG("Forked pid %d\n", pid);
	schedule_to_kill(pid);
	wait(&exit_status);

	/* read now line by line */
	i=0;
	crt = avpl;
	while (fgets(res_line, MAX_URI_SIZE, pipe)) {
		res.s = res_line;
		res.len=strlen(res.s);
		trim_trailing(&res);

		/* skip empty line */
		if (res.len==0) continue;
		/* ZT */
		res.s[res.len]=0;

		avp_type = 0;
		if(crt==NULL)
		{
			avp_name.s.s = int2str(i + 1, &avp_name.s.len);
			if (!avp_name.s.s) {
				LM_ERR("cannot convert %d to string\n", i + 1);
				goto error;
			}
			avp_name.n = get_avp_id(&avp_name.s);
			if (avp_name.n < 0) {
				LM_ERR("cannot get avp id\n");
				goto error;
			}
		} else {
			if(pv_get_avp_name(msg, &(crt->sname.pvp), &avp_name.n, &avp_type)!=0)
			{
				LM_ERR("can't get item name [%d]\n",i);
				goto error;
			}
		}

		avp_type |= AVP_VAL_STR;
		avp_val.s = res;

		if(add_avp(avp_type, avp_name.n, avp_val)!=0)
		{
			LM_ERR("unable to add avp\n");
			goto error;
		}

		if(crt)
			crt = crt->next;

		i++;
	}
	if (i==0)
		LM_DBG("no result from %s\n", cmd);
	/* success */
	ret=1;

error:
	if (ferror(pipe)) {
		LM_ERR("pipe: %d/%s\n",	errno, strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}

	pclose(pipe);
	if (WIFEXITED(exit_status)) { /* exited properly .... */
		/* return false if script exited with non-zero status */
		if (WEXITSTATUS(exit_status)!=0) ret=-1;
	} else { /* exited erroneously */
		LM_ERR("cmd %s failed. exit_status=%d, errno=%d: %s\n",
			cmd, exit_status, errno, strerror(errno) );
		ret=-1;
	}
	return ret;
}


int exec_getenv(struct sip_msg *msg, char *cmd, pvname_list_p avpl)
{
	int_str avp_val;
	int_str avp_name;
	unsigned short avp_type;
	int ret;
	str res;
	pvname_list_t* crt;

	/* pessimist: assume error by default */
	ret=-1;

	res.s=getenv(cmd);
	if (res.s==NULL)
	{
		goto error;
	}
	res.len=strlen(res.s);

	crt = avpl;

	avp_type = 0;
	if(crt==NULL)
	{
		avp_name.s.s = int2str(1, &avp_name.s.len);
		if (!avp_name.s.s) {
			LM_ERR("cannot convert 1 to string\n");
			goto error;
		}
		avp_name.n = get_avp_id(&avp_name.s);
		if (avp_name.n < 0) {
			LM_ERR("cannot get avp id\n");
			goto error;
		}
	} else {
		if(pv_get_avp_name(msg, &(crt->sname.pvp), &avp_name.n, &avp_type)!=0)
		{
			LM_ERR("can't get item name\n");
			goto error;
		}
	}

	avp_type |= AVP_VAL_STR;
	avp_val.s = res;

	if(add_avp(avp_type, avp_name.n, avp_val)!=0)
	{
		LM_ERR("unable to add avp\n");
		goto error;
	}

	/* success */
	ret=1;

error:
	return ret;
}


static int read_and_write2var(struct sip_msg* msg, FILE** strm, gparam_p outvar)
{
	#define MAX_LINE_SIZE 1024
	#define MAX_BUF_SIZE 32 * MAX_LINE_SIZE

	int buflen=0, tmplen;
	pv_value_t outval;
	char buf[MAX_BUF_SIZE], tmpbuf[MAX_LINE_SIZE];


	while((tmplen=fread(tmpbuf, 1, MAX_LINE_SIZE, *strm))) {
		if ((buflen + tmplen) >= MAX_BUF_SIZE) {
			LM_WARN("no more space in output buffer\n");
			break;
		}
		memcpy(buf+buflen, tmpbuf, tmplen);
		buflen += tmplen;
	}

	outval.flags = PV_VAL_STR;
	outval.rs.s = buf;
	outval.rs.len = buflen;

	if (buflen &&
		pv_set_value(msg, outvar->v.pvs, 0, &outval) < 0) {
		LM_ERR("cannot set output pv value\n");
		return -1;
	}

	return 0;

	#undef MAX_LINE_SIZE
	#undef MAX_BUF_SIZE
}

int exec_sync(struct sip_msg* msg, str* command, str* input, gparam_p outvar, gparam_p errvar)
{

	pid_t pid;
	int ret = -1;
	FILE *pin = NULL, *pout, *perr;

	if ((input && input->len && input->s) || outvar || errvar) {
		pid =  __popen3(command->s, (input&&input->len&&input->s) ? &pin : NULL,
									outvar ? &pout : NULL,
									errvar ? &perr : NULL);
	} else {
		pid = fork();
		if (pid == 0) {
			execl("/bin/sh", "/bin/sh", "-c", command->s, NULL);
			exit(-1);
		} else if (pid < 0) {
			LM_ERR("fork failed\n");
			return -1;
		}
	}

	if (input && input->len && pin) {
		if (fwrite(input->s, 1, input->len, pin) != input->len) {
			LM_ERR("failed to write to pipe\n");
			ser_error=E_EXEC;
			goto error;
		}

		if (ferror(pin)) {
			ser_error=E_EXEC;
			goto error;
		}

		pclose(pin);
	}

	schedule_to_kill(pid);

	if (outvar) {
		if (read_and_write2var(msg, &pout, outvar) < 0) {
			LM_ERR("failed reading stdout from pipe\n");
			goto error;
		}
	}

	if (errvar) {
		if (read_and_write2var(msg, &perr, errvar) < 0) {
			LM_ERR("failed reading stderr from pipe\n");
			goto error;
		}
	}

	ret=1;

error:
	if (outvar && ferror(pout)) {
		LM_ERR("stdout reading pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}

	if (errvar && ferror(perr)) {
		LM_ERR("stderr reading pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}

	if (outvar)
		pclose(pout);
	if (errvar)
		pclose(perr);

	return ret;
}


int start_async_exec(struct sip_msg* msg, str* command, str* input,
													gparam_p outvar, int *fd)
{
	pid_t pid;
	FILE *pin = NULL, *pout;
	int val;

	if ((input&&input->s&&input->len) || outvar) {
		pid =  __popen3(command->s, (input&&input->s&&input->len) ? &pin : NULL,
									outvar ? &pout : NULL,
									NULL);
	} else {
		pid = fork();
		if (pid == 0) {
			/* child process*/
			execl("/bin/sh", "/bin/sh", "-c", command->s, NULL);
			exit(-1);
		}
		if (pid<0) {
			/*error of fork*/
			LM_ERR("failed to fork (%s)\n",strerror(errno));
			goto error;
		}
	}

	if (input && input->len && pin) {
		if ( (val=fwrite(input->s, 1, input->len, pin)) != input->len) {
			LM_ERR("failed to write all (%d needed, %d written) to input pipe,"
				" but continuing\n",input->len,val);
		}

		if (ferror(pin)) {
			LM_ERR("failure detected (%s), continuing..\n",strerror(errno));
		}
		pclose(pin);
	}

	/* set time to kill on the new process */
	schedule_to_kill(pid);

	if (outvar==NULL) {
		/* nothing to wait for, no I/O */
		return 2;
	}

	/* prepare the read FD and make it non-blocking */
	if ( (*fd=dup( fileno( pout ) ))<0 ) {
		LM_ERR("dup failed: (%d) %s\n", errno, strerror(errno));
		goto error;
	}
	val = fcntl( *fd, F_GETFL);
	if (val==-1){
		LM_ERR("fcntl failed: (%d) %s\n", errno, strerror(errno));
		goto error2;
	}
	if (fcntl( *fd , F_SETFL, val|O_NONBLOCK)==-1){
		LM_ERR("set non-blocking failed: (%d) %s\n",
			errno, strerror(errno));
		goto error2;
	}

	pclose(pout);

	/* async started with success */
	return 1;

error2:
	close(*fd);
error:
	/* async failed */
	if (outvar)
		pclose(pout);
	return -1;
}


int resume_async_exec(int fd, struct sip_msg *msg, void *param)
{
	#define MAX_LINE_SIZE 1024
	char buf[MAX_LINE_SIZE+1];
	exec_async_param *p = (exec_async_param*)param;
	pv_value_t outval;
	char *s1, *s2;
	int n, len;

	if (p->buf) {
		memcpy( buf, p->buf, p->buf_len);
		len = p->buf_len;
		shm_free(p->buf);
		p->buf = NULL;
	} else {
		len = 0;
	}

	do {
		n=read( fd, buf+len, MAX_LINE_SIZE-len);
		LM_DBG(" read %d [%.*s] \n",n, n<0?0:n,buf+len);
		if (n<0) {
			if (errno==EINTR) continue;
			if (errno==EAGAIN || errno==EWOULDBLOCK) {
				/* nothing more to read */
				if (len) {
					/* store what is left */
					if ((p->buf=(char*)shm_malloc(len))==NULL) {
						LM_ERR("failed to allocate buffer\n");
						goto error;
					}
					memcpy( p->buf, buf, len);
					p->buf_len = len;
					LM_DBG(" storing %d [%.*s] \n", p->buf_len, p->buf_len, p->buf);
				}
				/* async should continue */
				async_status = ASYNC_CONTINUE;
				return 1;
			}
			LM_ERR("read failed with %d (%s)\n",errno, strerror(errno));
			/* terminate everything */
			goto error;
		}
		/* EOF ? */
		if (n==0) {
			if (len) {
				/* take whatever is left in buffer and push it as var */
				outval.flags = PV_VAL_STR;
				outval.rs.s = buf;
				outval.rs.len = len;
				LM_DBG("setting var [%.*s]\n",outval.rs.len,outval.rs.s);
				if (pv_set_value(msg, p->outvar->v.pvs, 0, &outval) < 0) {
					LM_ERR("failed to set variable :(, continuing \n");
				}
			}
			break;
		}
		/* successful reading  ( n>0 ) */
		LM_DBG(" having %d [%.*s] \n", len+n, len+n, buf);
		if (n+len==MAX_LINE_SIZE) {
			/* we have full buffer, pack it as a line */
			buf[n+len] = '\n';
			n++;
		}
		/* search for '\n' in the newly read data */
		s1 = buf;
		while ( (buf+len+n-s1>0) && ((s2=q_memchr(s1, '\n', buf+len+n-s1))!=NULL) ) {
			/* push it as var */
			outval.flags = PV_VAL_STR;
			outval.rs.s = s1;
			outval.rs.len = s2-s1;
			LM_DBG("setting var [%.*s]\n",outval.rs.len,outval.rs.s);
			if (pv_set_value(msg, p->outvar->v.pvs, 0, &outval) < 0) {
				LM_ERR("failed to set variable :(, continuing \n");
			}
			s1 = s2+1;
		}
		/* any data consumed ? */
		if ( s1!=buf+len ) {
			/* yes -> shift the whole buffer to left */
			len = buf+len+n-s1;
			if (len) memmove( buf, s1, len);
		} else {
			/* no -> increase the len of the buffer */
			len += n;
		}
	}while(1);

	/* done with the async */
	shm_free(param);

	/* make sure our fd is closed by the async engine */
	async_status = ASYNC_DONE_CLOSE_FD;
	return 1;

error:
	shm_free(param);
	/* stay with default async status ASYNC_DONE */
	return -1;
	#undef MAX_LINE_SIZE
}

