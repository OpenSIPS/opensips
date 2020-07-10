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

static int read_and_write2var(struct sip_msg* msg, FILE** strm, pv_spec_t *outvar)
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
		pv_set_value(msg, outvar, 0, &outval) < 0) {
		LM_ERR("cannot set output pv value\n");
		return -1;
	}

	return 0;

	#undef MAX_LINE_SIZE
	#undef MAX_BUF_SIZE
}

int exec_sync(struct sip_msg* msg, str* command, str* input,
		pv_spec_t *outvar, pv_spec_t *errvar)
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

		fclose(pin);
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
		fclose(pout);
	if (errvar)
		fclose(perr);

	return ret;
}


int start_async_exec(struct sip_msg* msg, str* command, str* input,
													pv_spec_t *outvar, int *fd)
{
	pid_t pid;
	FILE *pin = NULL, *pout = NULL;
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
		fclose(pin);
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

	fclose(pout);

	/* async started with success */
	return 1;

error2:
	close(*fd);
error:
	/* async failed */
	if (outvar)
		fclose(pout);
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
		if (n<0) {
			LM_DBG("read error: %d\n", n);
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

		buf[len+n] = '\0';
		LM_DBG("read %d [%.*s]\n", n, n, buf+len);

		/* EOF ? */
		if (n==0) {
			if (len) {
				/* take whatever is left in buffer and push it as var */
				outval.flags = PV_VAL_STR;
				outval.rs.s = buf;
				outval.rs.len = len;
				LM_DBG("setting var [%.*s]\n",outval.rs.len,outval.rs.s);
				if (pv_set_value(msg, p->outvar, 0, &outval) < 0) {
					LM_ERR("failed to set variable :(, continuing \n");
				}
			}
			break;
		}
		/* successful reading  ( n>0 ) */
		LM_DBG("buf is now %d [%.*s] \n", len+n, len+n, buf);
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
			if (pv_set_value(msg, p->outvar, 0, &outval) < 0) {
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

