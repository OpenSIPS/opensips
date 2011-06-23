/*
 *
 * $Id$
 *
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "exec.h"

#define SLEEP_INTERVAL		300

/* used by async process */
exec_list_p exec_async_list;

int exec_msg(struct sip_msg *msg, char *cmd )
{
	FILE *pipe;
	int exit_status;
	int ret;

	ret=-1; /* pessimist: assume error */
	pipe=popen( cmd, "w" );
	if (pipe==NULL) {
		LM_ERR("cannot open pipe: %s\n", cmd);
		ser_error=E_EXEC;
		return -1;
	}

	if (fwrite(msg->buf, 1, msg->len, pipe)!=msg->len) {
		LM_ERR("failed to write to pipe\n");
		ser_error=E_EXEC;
		goto error01;
	}
	/* success */
	ret=1;

error01:
	if (ferror(pipe)) {
		LM_ERR("pipe: %s\n", strerror(errno));
		ser_error=E_EXEC;
		ret=-1;
	}
	exit_status=pclose(pipe);
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

void exec_async_proc(int rank)
{
	int pid, status;
	exec_cmd_t *cmd, *prev;
	const char *argv[] = { NULL };

	LM_DBG("started asyncronous process with rank %d\n", rank);

	/* never stops listening */
	for (;;) {
		/* checks to see if there is anything in queue */
		lock_get(exec_async_list->lock);
		for (cmd = exec_async_list->first; cmd && cmd->pid; cmd = cmd->next);
		lock_release(exec_async_list->lock);

		if (cmd) {
			if ((pid = fork()) < 0) {
				LM_ERR("failed to fork\n");
			} else if (pid) {
				exec_async_list->active_childs++;
				cmd->pid = pid;
			} else {
				LM_DBG("running command %s (%d)\n", cmd->cmd, getpid());
				/* call command */
				execv(cmd->cmd, (char * const *)argv);
				LM_ERR("failed to run command\n");
				exit(0);
			}
		}

		/* wait for child processes if any */
		if (exec_async_list->active_childs) {
			pid = waitpid(-1, &status, WNOHANG);
			if (pid > 0) {
				/* search for ended child and delete it */
				lock_get(exec_async_list->lock);
				for (cmd = exec_async_list->first, prev = NULL;
						cmd && cmd->pid != pid;
						prev = cmd, cmd = cmd->next);
				if (!cmd) {
					LM_ERR("[BUG] child %d not present anymore\n", pid);
				} else {
					/* if not the first element */
					if (prev) {
						prev->next = cmd->next;
						if (!prev->next)
							exec_async_list->last = prev;
					} else {
						exec_async_list->first = cmd->next;
						if (!cmd->next)
							exec_async_list->last = NULL;
					}
					/* check for status */
					if (!WIFEXITED(status) || WEXITSTATUS(status)) {
						LM_ERR("cmd %s failed. exit_status=%d, errno=%d: %s\n",
									cmd->cmd, status, errno, strerror(errno));
					} else {
						LM_DBG("cmd %s successfully ended (%d)\n", cmd->cmd, cmd->pid);
					}
					shm_free(cmd);
					exec_async_list->active_childs--;
				}
				lock_release(exec_async_list->lock);
			}
		}
		/* if nothing to do - sleep */
		if (!exec_async_list->first && !exec_async_list->active_childs)
			usleep(SLEEP_INTERVAL);
	}
}

int exec_async(struct sip_msg *msg, char *cmd )
{
	exec_cmd_t *elem;

	/* alloc memory for command */
	elem = shm_malloc(sizeof(exec_cmd_t) + strlen(cmd) + 1);
	if (!elem) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memset(elem, 0, sizeof(exec_cmd_t));
	elem->cmd = (char *)(elem + 1);
	memcpy(elem->cmd, cmd, strlen(cmd) + 1);

	/* add command in list at the end */
	lock_get(exec_async_list->lock);
	if (exec_async_list->last) {
		exec_async_list->last->next = elem;
		exec_async_list->last = elem;
	} else {
		exec_async_list->first = exec_async_list->last = elem;
	}
	lock_release(exec_async_list->lock);

	return 1;
error:
	LM_ERR("cmd %s failed to execute, errno=%d: %s\n", cmd, errno, strerror(errno));
	return -1;
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
	
	pipe=popen( cmd_line, "r" );
	if (pipe==NULL) {
		LM_ERR("cannot open pipe: %s\n", cmd_line);
		ser_error=E_EXEC;
		goto error01;
	}

	/* read now line by line */
	uri_cnt=0;
	while( fgets(uri_line, MAX_URI_SIZE, pipe)!=NULL){
		uri.s = uri_line;
		uri.len=strlen(uri.s);
		/* trim from right */
		while(uri.len && (uri.s[uri.len-1]=='\r' 
				|| uri.s[uri.len-1]=='\n' 
				|| uri.s[uri.len-1]=='\t'
				|| uri.s[uri.len-1]==' ' )) {
			LM_DBG("rtrim\n");
			uri.len--;
		}
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
	exit_status=pclose(pipe);
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

	/* pessimist: assume error by default */
	ret=-1;
	
	pipe=popen( cmd, "r" );
	if (pipe==NULL) {
		LM_ERR("cannot open pipe: %s\n", cmd);
		ser_error=E_EXEC;
		return ret;
	}

	/* read now line by line */
	i=0;
	crt = avpl;
	while( fgets(res_line, MAX_URI_SIZE, pipe)!=NULL){
		res.s = res_line;
		res.len=strlen(res.s);
		/* trim from right */
		while(res.len && (res.s[res.len-1]=='\r' 
				|| res.s[res.len-1]=='\n' 
				|| res.s[res.len-1]=='\t'
				|| res.s[res.len-1]==' ' )) {
			res.len--;
		}
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
	exit_status=pclose(pipe);
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


