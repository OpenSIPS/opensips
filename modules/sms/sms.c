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
 * History:
 * --------
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-02  port_no_str does not contain a leading ':' anymore (andrei)
 *  2003-04-06  Only child 1 will execute child init (janakj)
 *  2003-10-24  updated to the new socket_info lists (andrei)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "../../sr_module.h"
#include "../../error.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../globals.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../socket_info.h"
#include "../tm/tm_load.h"
#include "sms_funcs.h"
#include "sms_report.h"
#include "libsms_modem.h"





static int sms_init(void);
static int sms_exit(void);
static int w_sms_send_msg(struct sip_msg*, char*, char* );
static int w_sms_send_msg_to_net(struct sip_msg*, char*, char*);
static int fixup_sms_send_msg_to_net(void** param, int param_no);
static void sms_process(int);



/* parameters */
char *networks_config = 0;
char *modems_config   = 0;
char *links_config    = 0;
char *default_net_str = 0;
char *domain_str      = 0;

/*global variables*/
int    default_net    = 0;
int    max_sms_parts  = MAX_SMS_PARTS;
str    domain;
int    *queued_msgs    = 0;
int    use_contact     = 0;
int    sms_report_type = NO_REPORT;
struct tm_binds tmb;


static proc_export_t sms_procs[] = {
	{"SMS receiver",  0,  0, sms_process, 0 , 0},
	{0,0,0,0,0,0}
};


static cmd_export_t cmds[]={
	{"sms_send_msg_to_net", (cmd_function)w_sms_send_msg_to_net, 1,
	     fixup_sms_send_msg_to_net, 0, REQUEST_ROUTE},
	{"sms_send_msg",        (cmd_function)w_sms_send_msg,        0,
	     0, 0,                         REQUEST_ROUTE},
	{0,0,0,0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

static param_export_t params[]={
	{"networks",        STR_PARAM, &networks_config },
	{"modems",          STR_PARAM, &modems_config   },
	{"links",           STR_PARAM, &links_config    },
	{"default_net",     STR_PARAM, &default_net_str },
	{"max_sms_parts",   INT_PARAM, &max_sms_parts   },
	{"domain",          STR_PARAM, &domain_str      },
	{"use_contact",     INT_PARAM, &use_contact     },
	{"sms_report_type", INT_PARAM, &sms_report_type },
	{0,0,0}
};


struct module_exports exports= {
	"sms",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	sms_procs,  /* extra processes */
	sms_init,   /* module initialization function */
	(response_function) 0,
	(destroy_function) sms_exit,   /* module exit function */
	0           /* per-child init function */
};




static int fixup_sms_send_msg_to_net(void** param, int param_no)
{
	long net_nr,i;

	if (param_no==1) {
		for(net_nr=-1,i=0;i<nr_of_networks&&net_nr==-1;i++)
			if (!strcasecmp(networks[i].name,*param))
				net_nr = i;
		if (net_nr==-1) {
			LM_ERR("etwork \"%s\" not found in net list!\n",(char*)*param);
			return E_UNSPEC;
		} else {
			pkg_free(*param);
			*param=(void*)net_nr;
			return 0;
		}
	}
	return 0;
}





#define eat_spaces(_p) \
	while( *(_p)==' ' || *(_p)=='\t' ){\
	(_p)++;}




int set_modem_arg(struct modem *mdm, char *arg, char *arg_end)
{
	int err, foo;

	if (*(arg+1)!='=') {
		LM_ERR("invalid parameter syntax near [=]\n");
		goto error;
	}
	switch (*arg)
	{
		case 'd':  /* device */
			memcpy(mdm->device,arg+2,arg_end-arg-2);
			mdm->device[arg_end-arg-2] = 0;
			break;
		case 'p':  /* pin */
			memcpy(mdm->pin,arg+2,arg_end-arg-2);
			mdm->pin[arg_end-arg-2] = 0;
			break;
		case 'm':  /* mode */
			if (!strncasecmp(arg+2,"OLD",3)
			&& arg_end-arg-2==3) {
				mdm->mode = MODE_OLD;
			} else if (!strncasecmp(arg+2,"DIGICOM",7)
			&& arg_end-arg-2==7) {
				mdm->mode = MODE_DIGICOM;
			} else if (!strncasecmp(arg+2,"ASCII",5)
			&& arg_end-arg-2==5) {
				mdm->mode = MODE_ASCII;
			} else if (!strncasecmp(arg+2,"NEW",3)
			&& arg_end-arg-2==3) {
				mdm->mode = MODE_NEW;
			} else {
				LM_ERR("invalid value \"%.*s\" for param [m]\n",
					(int)(arg_end-arg-2),arg+2);
				goto error;
			}
			break;
		case 'c':  /* sms center number */
			memcpy(mdm->smsc,arg+2,arg_end-arg-2);
			mdm->smsc[arg_end-arg-2] = 0;
			break;
		case 'r':  /* retry time */
			foo=str2s(arg+2,arg_end-arg-2,&err);
			if (err) {
				LM_ERR("failed to convert [r] arg to integer!\n");
				goto error;
			}
			mdm->retry = foo;
			break;
		case 'l':  /* looping interval */
			foo=str2s(arg+2,arg_end-arg-2,&err);
			if (err) {
				LM_ERR("failed to convert [l] arg to integer!\n");
				goto error;
			}
			mdm->looping_interval = foo;
			break;
		case 'b':  /* baudrate */
			foo=str2s(arg+2,arg_end-arg-2,&err);
			if (err) {
				LM_ERR("failed to convert [b] arg to integer!\n");
				goto error;
			}
			switch (foo) {
				case   300: foo=B300; break;
				case  1200: foo=B1200; break;
				case  2400: foo=B2400; break;
				case  9600: foo=B9600; break;
				case 19200: foo=B19200; break;
				case 38400: foo=B38400; break;
				case 57600: foo=B57600; break;
				default:
					LM_ERR("unsupported value %d for [b] arg!\n",foo);
					goto error;
			}
			mdm->baudrate = foo;
			break;
		default:
			LM_ERR("unknown param name [%c]\n",*arg);
			goto error;
	}

	return 1;
error:
	return -1;
}




int set_network_arg(struct network *net, char *arg, char *arg_end)
{
	int err,foo;

	if (*(arg+1)!='=') {
		LM_ERR("invalid parameter syntax near [=]\n");
		goto error;
	}
	switch (*arg)
	{
		case 'm':  /* maximum sms per one call */
			foo=str2s(arg+2,arg_end-arg-2,&err);
			if (err) {
				LM_ERR("cannot convert [m] arg to integer!\n");
				goto error;
			}
			net->max_sms_per_call = foo;
			break;
		default:
			LM_ERR("unknown param name [%c]\n",*arg);
			goto error;
	}

	return 1;
error:
	return -1;
}




int parse_config_lines(void)
{
	char *p,*start;
	int  i, k, step;
	int  mdm_nr, net_nr;

	nr_of_networks = 0;
	nr_of_modems = 0;

	step = 1;
	/* parsing modems configuration string */
	if ( (p = modems_config)==0) {
		LM_ERR("param \"modems\" not found\n");
		goto error;
	}
	while (*p)
	{
		eat_spaces(p);
		/*get modem's name*/
		start = p;
		while (*p!=' ' && *p!='\t' && *p!='[' && *p!=0)
			p++;
		if ( p==start || *p==0 )
			goto parse_error;
		memcpy(modems[nr_of_modems].name, start, p-start);
		modems[nr_of_modems].name[p-start] = 0;
		modems[nr_of_modems].smsc[0] = 0;
		modems[nr_of_modems].device[0] = 0;
		modems[nr_of_modems].pin[0] = 0;
		modems[nr_of_modems].mode = MODE_NEW;
		modems[nr_of_modems].retry = 4;
		modems[nr_of_modems].looping_interval = 20;
		modems[nr_of_modems].baudrate = B9600;
		memset(modems[nr_of_modems].net_list,0XFF,
			sizeof(modems[nr_of_modems].net_list) );
		/*get modem parameters*/
		eat_spaces(p);
		if (*p!='[')
			goto parse_error;
		p++;
		while (*p!=']')
		{
			eat_spaces(p);
			start = p;
			while(*p!=' ' && *p!='\t' && *p!=']' && *p!=';' && *p!=0)
				p++;
			if ( p==start || *p==0 )
				goto parse_error;
			if (set_modem_arg( &(modems[nr_of_modems]), start, p)==-1)
				goto error;
			eat_spaces(p);
			if (*p==';') {
				p++;
				eat_spaces(p);
			}
		}
		if (*p!=']')
			goto parse_error;
		p++;
		/* end of element */
		if (modems[nr_of_modems].device[0]==0) {
			LM_ERR("modem %s has no device associated\n",
					modems[nr_of_modems].name);
			goto error;
		}
		if (modems[nr_of_modems].smsc[0]==0) {
			LM_WARN("modem %s has no sms center associated -> using"
				" the default one from modem\n",modems[nr_of_modems].name);
		}
		nr_of_modems++;
		eat_spaces(p);
		if (*p==';') {
			p++;
			eat_spaces(p);
		}
	}
	if (nr_of_modems==0)
	{
		LM_ERR("failed to parse config modems - no modem found!\n");
		goto error;
	}

	step++;
	/* parsing networks configuration string */
	if ( (p = networks_config)==0) {
		LM_ERR("param \"networks\" not found\n");
		goto error;
	}
	while (*p)
	{
		eat_spaces(p);
		/*get network name*/
		start = p;
		while (*p!=' ' && *p!='\t' && *p!='[' && *p!=0)
			p++;
		if ( p==start || *p==0 )
			goto parse_error;
		memcpy(networks[nr_of_networks].name, start, p-start);
		networks[nr_of_networks].name[p-start] = 0;
		networks[nr_of_networks].max_sms_per_call = 10;
		/*get network parameters*/
		eat_spaces(p);
		if (*p!='[')
			goto parse_error;
		p++;
		while (*p!=']')
		{
			eat_spaces(p);
			start = p;
			while(*p!=' ' && *p!='\t' && *p!=']' && *p!=';' && *p!=0)
				p++;
			if ( p==start || *p==0 )
				goto parse_error;
			if (set_network_arg( &(networks[nr_of_networks]), start, p)==-1)
				goto error;
			eat_spaces(p);
			if (*p==';') {
				p++;
				eat_spaces(p);
			}
		}
		if (*p!=']')
			goto parse_error;
		p++;
		/* end of element */
		nr_of_networks++;
		eat_spaces(p);
		if (*p==';')
			p++;
		eat_spaces(p);
	}
	if (nr_of_networks==0)
	{
		LM_ERR("no network found!\n");
		goto error;
	}

	step++;
	/* parsing links configuration string */
	if ( (p = links_config)==0) {
		LM_ERR("param \"links\" not found\n");
		goto error;
	}
	while (*p)
	{
		eat_spaces(p);
		/*get modem's device*/
		start = p;
		while (*p!=' ' && *p!='\t' && *p!='[' && *p!=0)
			p++;
		if ( p==start || *p==0 )
			goto parse_error;
		/*looks for modem index*/
		for(mdm_nr=-1,i=0;i<nr_of_modems && mdm_nr==-1;i++)
			if (!strncasecmp(modems[i].name,start,p-start)&&
			modems[i].name[p-start]==0)
				mdm_nr = i;
		if (mdm_nr==-1) {
			LM_ERR("unknown modem %.*s \n,",(int)(p-start), start);
			goto error;
		}
		/*get associated networks list*/
		eat_spaces(p);
		if (*p!='[')
			goto parse_error;
		p++;
		k=0;
		while (*p!=']')
		{
			eat_spaces(p);
			start = p;
			while(*p!=' ' && *p!='\t' && *p!=']' && *p!=';' && *p!=0)
				p++;
			if ( p==start || *p==0 )
				goto parse_error;
			/* lookup for the network -> get its index */
			for(net_nr=-1,i=0;i<nr_of_networks&&net_nr==-1;i++)
				if (!strncasecmp(networks[i].name,start,p-start)
				&& networks[i].name[p-start]==0)
					net_nr = i;
			if (net_nr==-1) {
				LM_ERR("associated net <%.*s> not found in net list\n",
					(int)(p-start), start);
				goto error;
			}
			LM_DBG("linking net \"%s\" to modem \"%s\" on pos %d.\n",
					networks[net_nr].name,modems[mdm_nr].name,k);
			modems[mdm_nr].net_list[k++]=net_nr;
			eat_spaces(p);
			if (*p==';') {
				p++;
				eat_spaces(p);
			}
		}
		if (*p!=']')
			goto parse_error;
		p++;
		/* end of element */
		eat_spaces(p);
		if (*p==';') {
			p++;
			eat_spaces(p);
		}
	}

	/* resolving default network name - if any*/
	if (default_net_str) {
		for(net_nr=-1,i=0;i<nr_of_networks&&net_nr==-1;i++)
			if (!strcasecmp(networks[i].name,default_net_str))
				net_nr = i;
		if (net_nr==-1) {
			LM_ERR("network \"%s\" not found in net list!\n",default_net_str);
			goto error;
		}
		default_net = net_nr;
	}

	return 0;
parse_error:
	LM_ERR("SMS %s config: parse error before chr %d [%.*s]\n",
		(step==1)?"modems":(step==2?"networks":"links"),
		(int)(p - ((step==1)?modems_config:
				   (step==2?networks_config:links_config))),
		(*p==0)?4:1,(*p==0)?"NULL":p );

error:
	return -1;
}




int global_init(void)
{
	int   i, net_pipe[2], foo;
	char  *p;
	struct socket_info* si;

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("failed to load TM API\n");
		goto error;
	}

	/*fix domain length*/
	if (domain_str) {
		domain.s = domain_str;
		domain.len = strlen(domain_str);
	} else {
		si=get_first_socket();
		if (si==0){
			LM_CRIT("null listen socket list\n");
			goto error;
		}
		/*do I have to add port?*/
		i = (si->port_no_str.len && si->port_no!=5060);
		domain.len = si->name.len + i*(si->port_no_str.len+1);
		domain.s = (char*)pkg_malloc(domain.len);
		if (!domain.s) {
			LM_ERR("no more pkg memory!\n");
			goto error;
		}
		p = domain.s;
		memcpy(p,si->name.s,si->name.len);
		p += si->name.len;
		if (i) {
			*p=':'; p++;
			memcpy(p,si->port_no_str.s, si->port_no_str.len);
			p += si->port_no_str.len;
		}
	}

	/* creates pipes for networks */
	for(i=0;i<nr_of_networks;i++)
	{
		/* create the pipe*/
		if (pipe(net_pipe)==-1) {
			LM_ERR("failed create pipe!\n");
			goto error;
		}
		networks[i].pipe_out = net_pipe[0];
		net_pipes_in[i] = net_pipe[1];
		/* sets reading from pipe to non blocking */
		if ((foo=fcntl(net_pipe[0],F_GETFL,0))<0) {
			LM_ERR("failed to get flag for pipe - fcntl\n");
			goto error;
		}
		foo |= O_NONBLOCK;
		if (fcntl(net_pipe[0],F_SETFL,foo)<0) {
			LM_ERR("failed to set flag for pipe"
				" - fcntl\n");
			goto error;
		}
	}

	/* if report will be used, init the report queue */
	if (sms_report_type!=NO_REPORT && !init_report_queue()) {
		LM_ERR("no more share memory!\n");
		goto error;
	}

	/* alloc in shm for queued_msgs */
	queued_msgs = (int*)shm_malloc(sizeof(int));
	if (!queued_msgs) {
		LM_ERR("no more share memory!\n");
		goto error;
	}
	*queued_msgs = 0;

	return 1;
error:
	return -1;
}



void sms_process(int rank)
{
	modem_process(&(modems[rank]));
	exit(-1);
}



static int sms_init(void)
{
	LM_INFO("SMS - initializing\n");

	if (parse_config_lines()==-1)
		return -1;
	if (global_init()==-1)
		return -1;
	/* update the number of required processes */
	sms_procs[0].no = nr_of_modems;
	return 0;
}




static int sms_exit(void)
{
	if ((!domain_str) && (domain.s))
		pkg_free(domain.s);

	if (queued_msgs)
		shm_free(queued_msgs);

	if (sms_report_type!=NO_REPORT)
		destroy_report_queue();

	return 0;
}




static int w_sms_send_msg(struct sip_msg *msg, char *foo, char *bar)
{
	return push_on_network(msg, default_net);
}




static int w_sms_send_msg_to_net(struct sip_msg *msg, char *net_nr, char *foo)
{
	return push_on_network(msg,(unsigned int)(unsigned long)net_nr);
}

