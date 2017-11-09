/*
 * Copyright (C) 2003-2008 Sippy Software, Inc., http://www.sippysoft.com
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
 * ---------
 * 2014-06-17 Imported from rtpproxy module
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#ifndef __USE_BSD
#define  __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../str.h"
#include "../../flags.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../error.h"
#include "../../forward.h"
#include "../../context.h"
#include "../../mem/mem.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parser_f.h"
#include "../../parser/sdp/sdp.h"
#include "../../resolve.h"
#include "../../timer.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../pvar.h"
#include "../../msg_translator.h"
#include "../../usr_avp.h"
#include "../../socket_info.h"
#include "../../mod_fix.h"
#include "../../dset.h"
#include "../../route.h"
#include "../../modules/tm/tm_load.h"
#include "rtpengine.h"
#include "rtpengine_funcs.h"
#include "bencode.h"

#if !defined(AF_LOCAL)
#define	AF_LOCAL AF_UNIX
#endif
#if !defined(PF_LOCAL)
#define	PF_LOCAL PF_UNIX
#endif

#define DEFAULT_RTPE_SET_ID		0

#define MI_ENABLE_RTP_ENGINE			"rtpengine_enable"
#define MI_MIN_RECHECK_TICKS		0
#define MI_MAX_RECHECK_TICKS		(unsigned int)-1

#define MI_SHOW_RTP_ENGINES			"rtpengine_show"

#define MI_RTP_ENGINE_NOT_FOUND		"RTP engine not found"
#define MI_RTP_ENGINE_NOT_FOUND_LEN	(sizeof(MI_RTP_ENGINE_NOT_FOUND)-1)
#define MI_SET						"Set"
#define MI_SET_LEN					(sizeof(MI_SET)-1)
#define MI_NODE						"node"
#define MI_NODE_LEN					(sizeof(MI_NODE)-1)
#define MI_INDEX					"index"
#define MI_INDEX_LEN				(sizeof(MI_INDEX)-1)
#define MI_DISABLED					"disabled"
#define MI_DISABLED_LEN				(sizeof(MI_DISABLED)-1)
#define MI_WEIGHT					"weight"
#define MI_WEIGHT_LEN				(sizeof(MI_WEIGHT)-1)
#define MI_RECHECK_TICKS			"recheck_ticks"
#define MI_RECHECK_T_LEN			(sizeof(MI_RECHECK_TICKS)-1)


#define	CPORT		"22222"

#define ctx_rtpeset_get() \
	((struct rtpe_set*)context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, ctx_rtpeset_idx))

#define ctx_rtpeset_set(_set) \
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, ctx_rtpeset_idx, _set)




enum rtpe_operation {
	OP_OFFER = 1,
	OP_ANSWER,
	OP_DELETE,
	OP_START_RECORDING,
	OP_QUERY,
};

struct ng_flags_parse {
	int via, to, packetize, transport;
	bencode_item_t *dict, *flags, *direction, *replace, *rtcp_mux;
};

typedef struct rtpe_set_link {
	struct rtpe_set *rset;
	pv_spec_t rpv;
} rtpe_set_link_t;

static const char *command_strings[] = {
	[OP_OFFER]		= "offer",
	[OP_ANSWER]		= "answer",
	[OP_DELETE]		= "delete",
	[OP_START_RECORDING]	= "start recording",
	[OP_QUERY]		= "query",
};

static char *gencookie();
static int rtpe_test(struct rtpe_node*, int, int);
static int start_recording_f(struct sip_msg *);
static int rtpengine_answer1_f(struct sip_msg *, gparam_p str1);
static int rtpengine_offer1_f(struct sip_msg *, gparam_p str1);
static int rtpengine_delete1_f(struct sip_msg *, gparam_p str1);
static int rtpengine_manage1_f(struct sip_msg *, gparam_p str1);

static int parse_flags(struct ng_flags_parse *, struct sip_msg *, enum rtpe_operation *, const char *);

static int rtpengine_offer_answer(struct sip_msg *msg, const char *flags, int op);
static int add_rtpengine_socks(struct rtpe_set * rtpe_list, char * rtpengine);
static int fixup_set_id(void ** param, int param_no);
static int set_rtpengine_set_f(struct sip_msg * msg, rtpe_set_link_t *set_param);
static struct rtpe_set * select_rtpe_set(int id_set);
static struct rtpe_node *select_rtpe_node(str, int, struct rtpe_set *);
static char *send_rtpe_command(struct rtpe_node *, bencode_item_t *, int *);
static int get_extra_id(struct sip_msg* msg, str *id_str);

static int rtpengine_set_store(modparam_t type, void * val);
static int rtpengine_add_rtpengine_set( char * rtp_proxies);

static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

/* Pseudo-Variables */
static int pv_get_rtpstat_f(struct sip_msg *, pv_param_t *, pv_value_t *);

/*mi commands*/
static struct mi_root* mi_enable_rtp_proxy(struct mi_root* cmd_tree,
		void* param );
static struct mi_root* mi_show_rtpengines(struct mi_root* cmd_tree,
		void* param);


static int rtpengine_disable_tout = 60;
static int rtpengine_retr = 5;
static int rtpengine_tout = 1;
static pid_t mypid;
static unsigned int myseqn = 0;
static str extra_id_pv_param = {NULL, 0};
static char *setid_avp_param = NULL;

static char ** rtpe_strings=0;
static int rtpe_sets=0; /*used in rtpengine_set_store()*/
static int rtpe_set_count = 0;
static int ctx_rtpeset_idx = -1;
/* RTP proxy balancing list */
struct rtpe_set_head * rtpe_set_list =0;
struct rtpe_set * default_rtpe_set=0;

/* array with the sockets used by rtpengine (per process)*/
static unsigned int rtpe_no = 0;
static int *rtpe_socks = 0;

static int     setid_avp_type;
static int_str setid_avp;

/* tm */
static struct tm_binds tmb;

/*0-> disabled, 1 ->enabled*/
unsigned int *natping_state=0;

static pv_elem_t *extra_id_pv = NULL;

#define ANY_ROUTE     (REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE)
static cmd_export_t cmds[] = {
	{"rtpengine_use_set",  (cmd_function)set_rtpengine_set_f,    1,
		fixup_set_id, 0,
		ANY_ROUTE},
	{"rtpengine_start_recording", (cmd_function)start_recording_f,      0,
		0, 0,
		ANY_ROUTE },
	{"rtpengine_offer",	(cmd_function)rtpengine_offer1_f,     0,
		0, 0,
		ANY_ROUTE},
	{"rtpengine_offer",	(cmd_function)rtpengine_offer1_f,     1,
		fixup_spve_null, 0,
		ANY_ROUTE},
	{"rtpengine_answer",	(cmd_function)rtpengine_answer1_f,    0,
		0, 0,
		ANY_ROUTE},
	{"rtpengine_answer",	(cmd_function)rtpengine_answer1_f,    1,
		fixup_spve_null, 0,
		ANY_ROUTE},
	{"rtpengine_manage",	(cmd_function)rtpengine_manage1_f,     0,
		0, 0,
		ANY_ROUTE},
	{"rtpengine_manage",	(cmd_function)rtpengine_manage1_f,     1,
		fixup_spve_null, 0,
		ANY_ROUTE},
	{"rtpengine_delete",  (cmd_function)rtpengine_delete1_f,    0,
		0, 0,
		ANY_ROUTE},
	{"rtpengine_delete",  (cmd_function)rtpengine_delete1_f,    1,
		fixup_spve_null, 0,
		ANY_ROUTE},
	{0, 0, 0, 0, 0, 0}
};

static pv_export_t mod_pvs[] = {
    {{"rtpstat", (sizeof("rtpstat")-1)}, /* RTP-Statistics */
     1000, pv_get_rtpstat_f, 0, 0, 0, 0, 0},
    {{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
	{"rtpengine_sock",         STR_PARAM|USE_FUNC_PARAM,
				 (void*)rtpengine_set_store          },
	{"rtpengine_disable_tout", INT_PARAM, &rtpengine_disable_tout },
	{"rtpengine_retr",         INT_PARAM, &rtpengine_retr         },
	{"rtpengine_tout",         INT_PARAM, &rtpengine_tout         },
	{"extra_id_pv",           STR_PARAM, &extra_id_pv_param.s },
	{"setid_avp",             STR_PARAM, &setid_avp_param },
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{MI_ENABLE_RTP_ENGINE,     0, mi_enable_rtp_proxy,  0,                0, 0},
	{MI_SHOW_RTP_ENGINES,      0, mi_show_rtpengines,   MI_NO_INPUT_FLAG, 0, 0},
	{ 0, 0, 0, 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"rtpengine",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_pvs,     /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,
	0,           /* reply processing */
	mod_destroy, /* destroy function */
	child_init
};

int msg_has_sdp(struct sip_msg *msg)
{
	str body;
	struct part *p;
	struct multi_body *m;

	if(parse_headers(msg, HDR_CONTENTLENGTH_F,0) < 0) {
		LM_ERR("cannot parse cseq header");
		return 0;
	}

	body.len = get_content_length(msg);
	if (!body.len)
		return 0;

	m = get_all_bodies(msg);
	if (!m) {
		LM_DBG("cannot parse body\n");
		return 0;
	}

	for (p = m->first; p; p = p->next) {
		if (p->content_type == ((TYPE_APPLICATION << 16) + SUBTYPE_SDP))
			return 1;
	}

	return 0;
}



static inline int str_eq(const str *p, const char *q) {
	int l = strlen(q);
	if (p->len != l)
		return 0;
	if (memcmp(p->s, q, l))
		return 0;
	return 1;
}


static int rtpengine_set_store(modparam_t type, void * val){

	char * p;
	int len;

	p = (char* )val;

	if(p==0 || *p=='\0'){
		return 0;
	}

	if(rtpe_sets==0){
		rtpe_strings = (char**)pkg_malloc(sizeof(char*));
		if(!rtpe_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	} else {/*realloc to make room for the current set*/
		rtpe_strings = (char**)pkg_realloc(rtpe_strings,
										  (rtpe_sets+1)* sizeof(char*));
		if(!rtpe_strings){
			LM_ERR("no pkg memory left\n");
			return -1;
		}
	}

	/*allocate for the current set of urls*/
	len = strlen(p);
	rtpe_strings[rtpe_sets] = (char*)pkg_malloc((len+1)*sizeof(char));

	if(!rtpe_strings[rtpe_sets]){
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy(rtpe_strings[rtpe_sets], p, len);
	rtpe_strings[rtpe_sets][len] = '\0';
	rtpe_sets++;

	return 0;
}


static int add_rtpengine_socks(struct rtpe_set * rtpe_list,
										char * rtpengine){
	/* Make rtp proxies list. */
	char *p, *p1, *p2, *plim;
	struct rtpe_node *pnode;
	int weight;

	p = rtpengine;
	plim = p + strlen(p);

	for(;;) {
			weight = 1;
		while (*p && isspace((int)*p))
			++p;
		if (p >= plim)
			break;
		p1 = p;
		while (*p && !isspace((int)*p))
			++p;
		if (p <= p1)
			break; /* may happen??? */
		/* Have weight specified? If yes, scan it */
		p2 = memchr(p1, '=', p - p1);
		if (p2 != NULL) {
			weight = strtoul(p2 + 1, NULL, 10);
		} else {
			p2 = p;
		}
		pnode = shm_malloc(sizeof(struct rtpe_node));
		if (pnode == NULL) {
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(pnode, 0, sizeof(*pnode));
		pnode->idx = rtpe_no++;
		pnode->rn_recheck_ticks = 0;
		pnode->rn_weight = weight;
		pnode->rn_umode = 0;
		pnode->rn_disabled = 0;
		pnode->rn_url.s = shm_malloc(p2 - p1 + 1);
		if (pnode->rn_url.s == NULL) {
			shm_free(pnode);
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memmove(pnode->rn_url.s, p1, p2 - p1);
		pnode->rn_url.s[p2 - p1]	= 0;
		pnode->rn_url.len			= p2-p1;

		LM_DBG("url is %s, len is %i\n", pnode->rn_url.s, pnode->rn_url.len);
		/* Leave only address in rn_address */
		pnode->rn_address = pnode->rn_url.s;
		if (strncasecmp(pnode->rn_address, "udp:", 4) == 0) {
			pnode->rn_umode = 1;
			pnode->rn_address += 4;
		} else if (strncasecmp(pnode->rn_address, "udp6:", 5) == 0) {
			pnode->rn_umode = 6;
			pnode->rn_address += 5;
		} else if (strncasecmp(pnode->rn_address, "unix:", 5) == 0) {
			pnode->rn_umode = 0;
			pnode->rn_address += 5;
		}

		if (rtpe_list->rn_first == NULL) {
			rtpe_list->rn_first = pnode;
		} else {
			rtpe_list->rn_last->rn_next = pnode;
		}

		rtpe_list->rn_last = pnode;
		rtpe_list->rtpe_node_count++;
	}
	return 0;
}


/*	0-succes
 *  -1 - erorr
 * */
static int rtpengine_add_rtpengine_set( char * rtp_proxies)
{
	char *p,*p2;
	struct rtpe_set * rtpe_list;
	unsigned int my_current_id;
	str id_set;
	int new_list;

	/* empty definition? */
	p= rtp_proxies;
	if(!p || *p=='\0'){
		return 0;
	}

	for(;*p && isspace(*p);p++);
	if(*p=='\0'){
		return 0;
	}

	rtp_proxies = strstr(p, "==");
	if(rtp_proxies){
		if(*(rtp_proxies +2)=='\0'){
			LM_ERR("script error -invalid rtp proxy list!\n");
			return -1;
		}

		*rtp_proxies = '\0';
		p2 = rtp_proxies-1;
		for(;isspace(*p2); *p2 = '\0',p2--);
		id_set.s = p;	id_set.len = p2 - p+1;

		if(id_set.len <= 0 ||str2int(&id_set, &my_current_id)<0 ){
		LM_ERR("script error -invalid set_id value!\n");
			return -1;
		}

		rtp_proxies+=2;
	}else{
		rtp_proxies = p;
		my_current_id = DEFAULT_RTPE_SET_ID;
	}

	for(;*rtp_proxies && isspace(*rtp_proxies);rtp_proxies++);

	if(!(*rtp_proxies)){
		LM_ERR("script error -empty rtp_proxy list\n");
		return -1;;
	}

	/*search for the current_id*/
	rtpe_list = rtpe_set_list ? rtpe_set_list->rset_first : 0;
	while( rtpe_list != 0 && rtpe_list->id_set!=my_current_id)
		rtpe_list = rtpe_list->rset_next;

	if(rtpe_list==NULL){	/*if a new id_set : add a new set of rtpe*/
		rtpe_list = shm_malloc(sizeof(struct rtpe_set));
		if(!rtpe_list){
			LM_ERR("no shm memory left\n");
			return -1;
		}
		memset(rtpe_list, 0, sizeof(struct rtpe_set));
		rtpe_list->id_set = my_current_id;
		new_list = 1;
	} else {
		new_list = 0;
	}

	if(add_rtpengine_socks(rtpe_list, rtp_proxies)!= 0){
		/*if this list will not be inserted, clean it up*/
		goto error;
	}

	if (new_list) {
		if(!rtpe_set_list){/*initialize the list of set*/
			rtpe_set_list = shm_malloc(sizeof(struct rtpe_set_head));
			if(!rtpe_set_list){
				LM_ERR("no shm memory left\n");
				return -1;
			}
			memset(rtpe_set_list, 0, sizeof(struct rtpe_set_head));
		}

		/*update the list of set info*/
		if(!rtpe_set_list->rset_first){
			rtpe_set_list->rset_first = rtpe_list;
		}else{
			rtpe_set_list->rset_last->rset_next = rtpe_list;
		}

		rtpe_set_list->rset_last = rtpe_list;
		rtpe_set_count++;

		if(my_current_id == DEFAULT_RTPE_SET_ID){
			default_rtpe_set = rtpe_list;
		}
	}

	return 0;
error:
	return -1;
}


static int fixup_set_id(void ** param, int param_no)
{
	int int_val, err;
	struct rtpe_set* rtpe_list;
	rtpe_set_link_t *rtpl = NULL;
	str s;

	rtpl = (rtpe_set_link_t*)pkg_malloc(sizeof(rtpe_set_link_t));
	if(rtpl==NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(rtpl, 0, sizeof(rtpe_set_link_t));
	s.s = (char*)*param;
	s.len = strlen(s.s);

	if(s.s[0] == PV_MARKER) {
		if ( pv_parse_spec(&s, &rtpl->rpv) == NULL ) {
			LM_ERR("invalid parameter %s\n", s.s);
			return -1;
		}
	} else {
		int_val = str2s(*param, strlen(*param), &err);
		if (err == 0) {
			pkg_free(*param);
			if((rtpe_list = select_rtpe_set(int_val)) ==0){
				LM_ERR("rtpe_proxy set %i not configured\n", int_val);
				return E_CFG;
			}
			rtpl->rset = rtpe_list;
		} else {
			LM_ERR("bad number <%s>\n",	(char *)(*param));
			return E_CFG;
		}
	}
	*param = (void*)rtpl;
	return 0;
}

static struct mi_root* mi_enable_rtp_proxy(struct mi_root* cmd_tree,
												void* param )
{	struct mi_node* node;
	str rtpe_url;
	unsigned int enable;
	struct rtpe_set * rtpe_list;
	struct rtpe_node * crt_rtpe;
	int found;

	found = 0;

	if(rtpe_set_list ==NULL)
		goto end;

	node = cmd_tree->node.kids;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if(node->value.s == NULL || node->value.len ==0)
		return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

	rtpe_url = node->value;

	node = node->next;
	if(node == NULL)
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	enable = 0;
	if( strno2int( &node->value, &enable) <0)
		goto error;

	for(rtpe_list = rtpe_set_list->rset_first; rtpe_list != NULL;
					rtpe_list = rtpe_list->rset_next){

		for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next){
			/*found a matching rtpe*/

			if(crt_rtpe->rn_url.len == rtpe_url.len){

				if(strncmp(crt_rtpe->rn_url.s, rtpe_url.s, rtpe_url.len) == 0){
					/*set the enabled/disabled status*/
					found = 1;
					crt_rtpe->rn_recheck_ticks =
						enable? MI_MIN_RECHECK_TICKS : MI_MAX_RECHECK_TICKS;
					crt_rtpe->rn_disabled = enable?0:1;
				}
			}
		}
	}

end:
	if(found)
		return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	return init_mi_tree(404,MI_RTP_ENGINE_NOT_FOUND,MI_RTP_ENGINE_NOT_FOUND_LEN);
error:
	return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);
}



#define add_rtpe_node_int_info(_parent, _name, _name_len, _value, _attr,\
								_len, _string, _error)\
	do {\
		(_string) = int2str((_value), &(_len));\
		if((_string) == 0){\
			LM_ERR("cannot convert int value\n");\
				goto _error;\
		}\
		if(((_attr) = add_mi_attr((_parent), MI_DUP_VALUE, (_name), \
				(_name_len), (_string), (_len))   ) == 0)\
			goto _error;\
	}while(0);

static struct mi_root* mi_show_rtpengines(struct mi_root* cmd_tree,
												void* param)
{
	struct mi_node* node, *crt_node, *set_node;
	struct mi_root* root;
	struct mi_attr * attr;
	struct rtpe_set * rtpe_list;
	struct rtpe_node * crt_rtpe;
	char * string, *id;
	int id_len, len;

	string = id = 0;

	root = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (!root) {
		LM_ERR("the MI tree cannot be initialized!\n");
		return 0;
	}

	if(rtpe_set_list ==NULL)
		return root;

	node = &root->node;
	node->flags |= MI_IS_ARRAY;

	for(rtpe_list = rtpe_set_list->rset_first; rtpe_list != NULL;
					rtpe_list = rtpe_list->rset_next){

		id =  int2str(rtpe_list->id_set, &id_len);
		if(!id){
			LM_ERR("cannot convert set id\n");
			goto error;
		}

		if(!(set_node = add_mi_node_child(node, MI_IS_ARRAY|MI_DUP_VALUE, MI_SET, MI_SET_LEN,
									id, id_len))) {
			LM_ERR("cannot add the set node to the tree\n");
			goto error;
		}

		for(crt_rtpe = rtpe_list->rn_first; crt_rtpe != NULL;
						crt_rtpe = crt_rtpe->rn_next){

			if(!(crt_node = add_mi_node_child(node, MI_DUP_VALUE,
					MI_NODE, MI_NODE_LEN,
					crt_rtpe->rn_url.s, crt_rtpe->rn_url.len)) ) {
				LM_ERR("cannot add the child node to the tree\n");
				goto error;
			}

			LM_DBG("adding node name %s \n",crt_rtpe->rn_url.s );

			add_rtpe_node_int_info(crt_node, MI_INDEX, MI_INDEX_LEN,
				crt_rtpe->idx, attr, len,string,error);
			add_rtpe_node_int_info(crt_node, MI_DISABLED, MI_DISABLED_LEN,
				crt_rtpe->rn_disabled, attr, len,string,error);
			add_rtpe_node_int_info(crt_node, MI_WEIGHT, MI_WEIGHT_LEN,
				crt_rtpe->rn_weight, attr, len, string,error);
			add_rtpe_node_int_info(crt_node, MI_RECHECK_TICKS,MI_RECHECK_T_LEN,
				crt_rtpe->rn_recheck_ticks, attr, len, string, error);
		}
	}

	return root;
error:
	if (root)
		free_mi_tree(root);
	return 0;
}


static int
mod_init(void)
{
	int i;
	pv_spec_t avp_spec;
	unsigned short avp_flags;
	str s;

	ctx_rtpeset_idx = context_register_ptr(CONTEXT_GLOBAL, NULL);

	/* any rtpengine configured? */
	if(rtpe_set_list)
		default_rtpe_set = select_rtpe_set(DEFAULT_RTPE_SET_ID);

	/* storing the list of rtp proxy sets in shared memory*/
	for(i=0;i<rtpe_sets;i++){
		if(rtpengine_add_rtpengine_set(rtpe_strings[i]) !=0){
			for(;i<rtpe_sets;i++)
				if(rtpe_strings[i])
					pkg_free(rtpe_strings[i]);
			pkg_free(rtpe_strings);
			return -1;
		}
		if(rtpe_strings[i])
			pkg_free(rtpe_strings[i]);
	}

	if (extra_id_pv_param.s && *extra_id_pv_param.s) {
		extra_id_pv_param.len = strlen(extra_id_pv_param.s);
		if(pv_parse_format(&extra_id_pv_param, &extra_id_pv) < 0) {
			LM_ERR("malformed PV string: %s\n", extra_id_pv_param.s);
			return -1;
		}
	} else {
		extra_id_pv = NULL;
	}

	if (setid_avp_param) {
		s.s = setid_avp_param; s.len = strlen(s.s);
		pv_parse_spec(&s, &avp_spec);
		if (avp_spec.type != PVT_AVP) {
			LM_ERR("malformed or non AVP definition <%s>\n",
					setid_avp_param);
			return -1;
		}
		if (pv_get_avp_name(0, &(avp_spec.pvp), &(setid_avp.n),
					&avp_flags) != 0) {
			LM_ERR("invalid AVP definition <%s>\n", setid_avp_param);
			return -1;
		}
		setid_avp_type = avp_flags;
	}

	if (rtpe_strings)
		pkg_free(rtpe_strings);

	if (load_tm_api( &tmb ) < 0)
	{
		LM_DBG("could not load the TM-functions - answer-offer model"
				" auto-detection is disabled\n");
		memset(&tmb, 0, sizeof(struct tm_binds));
	}

	return 0;
}


static int
child_init(int rank)
{
	int n;
	char *cp;
	struct addrinfo hints, *res;
	struct rtpe_set  *rtpe_list;
	struct rtpe_node *pnode;

	if(rtpe_set_list==NULL )
		return 0;

	/* Iterate known RTP proxies - create sockets */
	mypid = getpid();

	rtpe_socks = (int*)pkg_malloc( sizeof(int)*rtpe_no );
	if (rtpe_socks==NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	for(rtpe_list = rtpe_set_list->rset_first; rtpe_list != 0;
		rtpe_list = rtpe_list->rset_next){

		for (pnode=rtpe_list->rn_first; pnode!=0; pnode = pnode->rn_next){
			char *hostname;

			if (pnode->rn_umode == 0) {
				rtpe_socks[pnode->idx] = -1;
				goto rptest;
			}

			/*
			 * This is UDP or UDP6. Detect host and port; lookup host;
			 * do connect() in order to specify peer address
			 */
			hostname = (char*)pkg_malloc(sizeof(char) * (strlen(pnode->rn_address) + 1));
			if (hostname==NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			strcpy(hostname, pnode->rn_address);

			cp = strrchr(hostname, ':');
			if (cp != NULL) {
				*cp = '\0';
				cp++;
			}
			if (cp == NULL || *cp == '\0')
				cp = CPORT;

			memset(&hints, 0, sizeof(hints));
			hints.ai_flags = 0;
			hints.ai_family = (pnode->rn_umode == 6) ? AF_INET6 : AF_INET;
			hints.ai_socktype = SOCK_DGRAM;
			if ((n = getaddrinfo(hostname, cp, &hints, &res)) != 0) {
				LM_ERR("%s\n", gai_strerror(n));
				pkg_free(hostname);
				return -1;
			}
			pkg_free(hostname);

			rtpe_socks[pnode->idx] = socket((pnode->rn_umode == 6)
			    ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
			if ( rtpe_socks[pnode->idx] == -1) {
				LM_ERR("can't create socket\n");
				freeaddrinfo(res);
				return -1;
			}

			if (connect( rtpe_socks[pnode->idx], res->ai_addr, res->ai_addrlen) == -1) {
				LM_ERR("can't connect to a RTP proxy\n");
				close( rtpe_socks[pnode->idx] );
				rtpe_socks[pnode->idx] = -1;
				freeaddrinfo(res);
				return -1;
			}
			freeaddrinfo(res);
rptest:
			pnode->rn_disabled = rtpe_test(pnode, 0, 1);
		}
	}

	return 0;
}


static void mod_destroy(void)
{
	struct rtpe_set * crt_list, * last_list;
	struct rtpe_node * crt_rtpe, *last_rtpe;

	/*free the shared memory*/
	if (natping_state)
		shm_free(natping_state);

	if(rtpe_set_list == NULL)
		return;

	for(crt_list = rtpe_set_list->rset_first; crt_list != NULL; ){

		for(crt_rtpe = crt_list->rn_first; crt_rtpe != NULL;  ){

			if(crt_rtpe->rn_url.s)
				shm_free(crt_rtpe->rn_url.s);

			last_rtpe = crt_rtpe;
			crt_rtpe = last_rtpe->rn_next;
			shm_free(last_rtpe);
		}

		last_list = crt_list;
		crt_list = last_list->rset_next;
		shm_free(last_list);
	}

	shm_free(rtpe_set_list);
}



static char * gencookie(void)
{
	static char cook[34];

	sprintf(cook, "%d_%u ", (int)mypid, myseqn);
	myseqn++;
	return cook;
}



static const char *transports[] = {
	[0x00]	= "RTP/AVP",
	[0x01]	= "RTP/SAVP",
	[0x02]	= "RTP/AVPF",
	[0x03]	= "RTP/SAVPF",
	[0x04]  = "UDP/TLS/RTP/SAVP",
	[0x05]  = "UDP/TLS/RTP/SAVPF"

};

static int parse_flags(struct ng_flags_parse *ng_flags, struct sip_msg *msg, enum rtpe_operation *op,
		const char *flags_str)
{
	char *e;
	const char *err;
	str key, val;

	if (!flags_str)
		return 0;

	while (1) {
		while (*flags_str == ' ')
			flags_str++;

		key.s = (void *) flags_str;
		val.len = key.len = -1;
		val.s = NULL;

		e = strpbrk(key.s, " =");
		if (!e)
			e = key.s + strlen(key.s);
		else if (*e == '=') {
			key.len = e - key.s;
			val.s = e + 1;
			e = strchr(val.s, ' ');
			if (!e)
				e = val.s + strlen(val.s);
			val.len = e - val.s;
		}

		if (key.len == -1)
			key.len = e - key.s;
		if (!key.len)
			break;

		/* XXX make this prettier */
		err = "unknown flag";
		switch (key.len) {
			case 3:
				if (str_eq(&key, "ICE")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (str_eq(&val, "force") || str_eq(&val, "force-relay") || str_eq(&val, "remove"))
						bencode_dictionary_add_str(ng_flags->dict, "ICE", &val);
					else
						goto error;
				}
				else if (str_eq(&key, "RTP")) {
					ng_flags->transport |= 0x100;
					ng_flags->transport &= ~0x001;
				}
				else if (str_eq(&key, "AVP")) {
					ng_flags->transport |= 0x100;
					ng_flags->transport &= ~0x002;
				}
				else
					goto error;
				break;

			case 4:
				if (str_eq(&key, "SRTP"))
					ng_flags->transport |= 0x101;
				else if (str_eq(&key, "AVPF"))
					ng_flags->transport |= 0x102;
				else if (str_eq(&key, "DTLS")){
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (str_eq(&val, "passive"))
						bencode_dictionary_add_str(ng_flags->dict, "DTLS", &val);
					else
						goto error;
				}
				else
					goto error;
				break;

			case 5:
				if (str_eq(&key, "force"))
					bencode_list_add_string(ng_flags->flags, "force");
				else
					goto error;
				break;

			case 6:
				if (str_eq(&key, "to-tag"))
					ng_flags->to = 1;
				else
					goto error;
				break;

			case 7:
				if (str_eq(&key, "RTP/AVP"))
					ng_flags->transport = 0x100;
				else
					goto error;
				break;

			case 8:
				if (str_eq(&key, "internal"))
					bencode_list_add_string(ng_flags->direction, "internal");
				else if (str_eq(&key, "external"))
					bencode_list_add_string(ng_flags->direction, "external");
				else if (str_eq(&key, "RTP/AVPF"))
					ng_flags->transport = 0x102;
				else if (str_eq(&key, "RTP/SAVP"))
					ng_flags->transport = 0x101;
				else
					goto error;
				break;

			case 9:
				if (str_eq(&key, "symmetric"))
					bencode_list_add_string(ng_flags->flags, "symmetric");
				else if (str_eq(&key, "RTP/SAVPF"))
					ng_flags->transport = 0x103;
				else
					goto error;
				break;

			case 10:
				if (str_eq(&key, "via-branch")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (*val.s == '1' || *val.s == '2')
						ng_flags->via = *val.s - '0';
					else if (str_eq(&val, "auto"))
						ng_flags->via = 3;
					else if (str_eq(&val, "extra"))
						ng_flags->via = -1;
					else
						goto error;
				}
				else if (str_eq(&key, "asymmetric"))
					bencode_list_add_string(ng_flags->flags, "asymmetric");
				else
					goto error;
				break;

			case 11:
				if (str_eq(&key, "auto-bridge"))
					bencode_list_add_string(ng_flags->flags, "auto-bridge");
				else if (str_eq(&key, "repacketize")) {
					err = "missing value";
					if (!val.s)
						goto error;
					ng_flags->packetize = 0;
					while (isdigit(*val.s)) {
						ng_flags->packetize *= 10;
						ng_flags->packetize += *val.s - '0';
						val.s++;
					}
					err = "invalid value";
					if (!ng_flags->packetize)
						goto error;
					bencode_dictionary_add_integer(ng_flags->dict, "repacketize", ng_flags->packetize);
				}
				else
					goto error;
				break;

			case 12:
				if (str_eq(&key, "force-answer")) {
					err = "cannot force answer in non-offer command";
					if (*op != OP_OFFER)
						goto error;
					*op = OP_ANSWER;
				}
				else
					goto error;
				break;
			case 13:
				if (str_eq(&key, "trust-address"))
					bencode_list_add_string(ng_flags->flags, "trust-address");
				else if (str_eq(&key, "media-address")) {
					err = "missing value";
					if (!val.s)
						goto error;
				}
				else
					goto error;
				break;

			case 14:
				if (str_eq(&key, "replace-origin")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						bencode_list_add_string(ng_flags->replace, "origin");
				} else if (str_eq(&key, "address-family")) {
					err = "missing value";
					if (!val.s)
						goto error;
					err = "invalid value";
					if (str_eq(&val, "IP4") || str_eq(&val, "IP6"))
						bencode_dictionary_add_str(ng_flags->dict, "address family", &val);
					else
						goto error;
				}
				else if (str_eq(&key, "rtcp-mux-demux"))
					bencode_list_add_string(ng_flags->rtcp_mux, "demux");
				else if (str_eq(&key, "rtcp-mux-offer"))
					bencode_list_add_string(ng_flags->rtcp_mux, "offer");
				else
					goto error;
				break;

			case 15:
				if (str_eq(&key, "rtcp-mux-reject"))
					bencode_list_add_string(ng_flags->rtcp_mux, "reject");
				else if (str_eq(&key, "rtcp-mux-accept"))
					bencode_list_add_string(ng_flags->rtcp_mux, "accept");
				else
					goto error;
				break;

			case 16:
				if (str_eq(&key, "UDP/TLS/RTP/SAVP"))
					ng_flags->transport = 0x104;
				else
					goto error;
				break;

			case 17:
				if (str_eq(&key, "UDP/TLS/RTP/SAVPF"))
					ng_flags->transport = 0x105;
				else
					goto error;
				break;

			case 26:
				if (str_eq(&key, "replace-session-connection")) {
					if (!ng_flags->replace)
						LM_DBG("%.*s not supported for %d op\n", key.len, key.s, *op);
					else
						bencode_list_add_string(ng_flags->replace, "session-connection");
				} else
					goto error;
				break;

			default:
				goto error;
		}

		flags_str = e;
	}

	return 0;

error:
	if (val.s)
		LM_ERR("error processing flag `%.*s' (value '%.*s'): %s\n", key.len, key.s,
				val.len, val.s, err);
	else
		LM_ERR("error processing flag `%.*s': %s\n", key.len, key.s, err);
	return -1;
}

static bencode_item_t *rtpe_function_call(bencode_buffer_t *bencbuf, struct sip_msg *msg,
	enum rtpe_operation op, const char *flags_str, str *body_out)
{
	struct ng_flags_parse ng_flags;
	bencode_item_t *item, *resp;
	str callid, from_tag, to_tag, viabranch, error;
	str body = { 0, 0 };
	int ret;
	struct rtpe_node *node;
	struct rtpe_set *set;
	char *cp;

	/*** get & init basic stuff needed ***/

	memset(&ng_flags, 0, sizeof(ng_flags));

	if (get_callid(msg, &callid) == -1 || callid.len == 0) {
		LM_ERR("can't get Call-Id field\n");
		return NULL;
	}
	if (get_to_tag(msg, &to_tag) == -1) {
		LM_ERR("can't get To tag\n");
		return NULL;
	}
	if (get_from_tag(msg, &from_tag) == -1 || from_tag.len == 0) {
		LM_ERR("can't get From tag\n");
		return NULL;
	}
	if (bencode_buffer_init(bencbuf)) {
		LM_ERR("could not initialize bencode_buffer_t\n");
		return NULL;
	}
	ng_flags.dict = bencode_dictionary(bencbuf);

	if (op == OP_OFFER || op == OP_ANSWER) {
		ng_flags.flags = bencode_list(bencbuf);
		ng_flags.direction = bencode_list(bencbuf);
		ng_flags.replace = bencode_list(bencbuf);
		ng_flags.rtcp_mux = bencode_list(bencbuf);

		if (extract_body(msg, &body) == -1) {
			LM_ERR("can't extract body from the message\n");
			goto error;
		}
		bencode_dictionary_add_str(ng_flags.dict, "sdp", &body);
	}

	/*** parse flags & build dictionary ***/

	ng_flags.to = (op == OP_DELETE) ? 0 : 1;

	if (parse_flags(&ng_flags, msg, &op, flags_str))
		goto error;

	/* only add those if any flags were given at all */
	if (ng_flags.direction && ng_flags.direction->child)
		bencode_dictionary_add(ng_flags.dict, "direction", ng_flags.direction);
	if (ng_flags.flags && ng_flags.flags->child)
		bencode_dictionary_add(ng_flags.dict, "flags", ng_flags.flags);
	if (ng_flags.replace && ng_flags.replace->child)
		bencode_dictionary_add(ng_flags.dict, "replace", ng_flags.replace);
	if ((ng_flags.transport & 0x100))
		bencode_dictionary_add_string(ng_flags.dict, "transport-protocol",
				transports[ng_flags.transport & 0x007]);
	if (ng_flags.rtcp_mux && ng_flags.rtcp_mux->child)
		bencode_dictionary_add(ng_flags.dict, "rtcp-mux", ng_flags.rtcp_mux);

	bencode_dictionary_add_str(ng_flags.dict, "call-id", &callid);

	if (ng_flags.via) {
		if (ng_flags.via == 1 || ng_flags.via == 2)
			ret = get_via_branch(msg, ng_flags.via, &viabranch);
		else if (ng_flags.via == -1 && extra_id_pv)
			ret = get_extra_id(msg, &viabranch);
		else
			ret = -1;
		if (ret == -1 || viabranch.len == 0) {
			LM_ERR("can't get Via branch/extra ID\n");
			goto error;
		}
		bencode_dictionary_add_str(ng_flags.dict, "via-branch", &viabranch);
	}

	item = bencode_list(bencbuf);
	bencode_dictionary_add(ng_flags.dict, "received-from", item);
	bencode_list_add_string(item, (msg->rcv.src_ip.af == AF_INET) ? "IP4" : (
		(msg->rcv.src_ip.af == AF_INET6) ? "IP6" :
		"?"
	) );
	bencode_list_add_string(item, ip_addr2a(&msg->rcv.src_ip));

	if ((msg->first_line.type == SIP_REQUEST && op != OP_ANSWER)
		|| (msg->first_line.type == SIP_REPLY && op == OP_ANSWER))
	{
		bencode_dictionary_add_str(ng_flags.dict, "from-tag", &from_tag);
		if (ng_flags.to && to_tag.s && to_tag.len)
			bencode_dictionary_add_str(ng_flags.dict, "to-tag", &to_tag);
	}
	else {
		if (!to_tag.s || !to_tag.len) {
			LM_ERR("No to-tag present\n");
			goto error;
		}
		bencode_dictionary_add_str(ng_flags.dict, "from-tag", &to_tag);
		bencode_dictionary_add_str(ng_flags.dict, "to-tag", &from_tag);
	}

	bencode_dictionary_add_string(ng_flags.dict, "command", command_strings[op]);

	/*** send it out ***/

	if (bencbuf->error) {
		LM_ERR("out of memory - bencode failed\n");
		goto error;
	}

	if ( (set=ctx_rtpeset_get())==NULL )
		set = default_rtpe_set;

	do {
		node = select_rtpe_node(callid, 1, set);
		if (!node) {
			LM_ERR("no available proxies\n");
			goto error;
		}

		cp = send_rtpe_command(node, ng_flags.dict, &ret);
	} while (cp == NULL);
	LM_DBG("proxy reply: %.*s\n", ret, cp);

	/*** process reply ***/

	resp = bencode_decode_expect(bencbuf, cp, ret, BENCODE_DICTIONARY);
	if (!resp) {
		LM_ERR("failed to decode bencoded reply from proxy: %.*s\n", ret, cp);
		goto error;
	}
	if (!bencode_dictionary_get_strcmp(resp, "result", "error")) {
		if (!bencode_dictionary_get_str(resp, "error-reason", &error))
			LM_ERR("proxy return error but didn't give an error reason: %.*s\n", ret, cp);
		else
			LM_ERR("proxy replied with error: %.*s\n", error.len, error.s);
		goto error;
	}

	if (body_out)
		*body_out = body;

	return resp;

error:
	bencode_buffer_free(bencbuf);
	return NULL;
}

static int rtpe_function_call_simple(struct sip_msg *msg, enum rtpe_operation op, const char *flags_str)
{
	bencode_buffer_t bencbuf;

	if (!rtpe_function_call(&bencbuf, msg, op, flags_str, NULL))
		return -1;

	bencode_buffer_free(&bencbuf);
	return 1;
}

static bencode_item_t *rtpe_function_call_ok(bencode_buffer_t *bencbuf, struct sip_msg *msg,
		enum rtpe_operation op, const char *flags_str, str *body)
{
	bencode_item_t *ret;

	ret = rtpe_function_call(bencbuf, msg, op, flags_str, body);
	if (!ret)
		return NULL;

	if (bencode_dictionary_get_strcmp(ret, "result", "ok")) {
		LM_ERR("proxy didn't return \"ok\" result\n");
		bencode_buffer_free(bencbuf);
		return NULL;
	}

	return ret;
}



static int
rtpe_test(struct rtpe_node *node, int isdisabled, int force)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	char *cp;
	int ret;

	if(node->rn_recheck_ticks == MI_MAX_RECHECK_TICKS){
	    LM_DBG("rtpe %s disabled for ever\n", node->rn_url.s);
		return 1;
	}
	if (force == 0) {
		if (isdisabled == 0)
			return 0;
		if (node->rn_recheck_ticks > get_ticks())
			return 1;
	}

	if (bencode_buffer_init(&bencbuf)) {
		LM_ERR("could not initialized bencode_buffer_t\n");
		return 1;
	}
	dict = bencode_dictionary(&bencbuf);
	bencode_dictionary_add_string(dict, "command", "ping");
	if (bencbuf.error)
		goto benc_error;

	cp = send_rtpe_command(node, dict, &ret);
	if (!cp) {
		LM_ERR("proxy did not respond to ping\n");
		goto error;
	}

	dict = bencode_decode_expect(&bencbuf, cp, ret, BENCODE_DICTIONARY);
	if (!dict || bencode_dictionary_get_strcmp(dict, "result", "pong")) {
		LM_ERR("proxy responded with invalid response\n");
		goto error;
	}

	LM_INFO("rtp proxy <%s> found, support for it %senabled\n",
	    node->rn_url.s, force == 0 ? "re-" : "");

	bencode_buffer_free(&bencbuf);
	return 0;

benc_error:
        LM_ERR("out of memory - bencode failed\n");
error:
	bencode_buffer_free(&bencbuf);
	return 1;
}

static char *
send_rtpe_command(struct rtpe_node *node, bencode_item_t *dict, int *outlen)
{
	struct sockaddr_un addr;
	int fd, len, i, vcnt;
	char *cp;
	static char buf[0x10000];
	struct pollfd fds[1];
	struct iovec *v;

	v = bencode_iovec(dict, &vcnt, 1, 0);
	if (!v) {
		LM_ERR("error converting bencode to iovec\n");
		return NULL;
	}

	len = 0;
	cp = buf;
	if (node->rn_umode == 0) {
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strncpy(addr.sun_path, node->rn_address,
		    sizeof(addr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SA_LEN
		addr.sun_len = strlen(addr.sun_path);
#endif

		fd = socket(AF_LOCAL, SOCK_STREAM, 0);
		if (fd < 0) {
			LM_ERR("can't create socket\n");
			goto badproxy;
		}
		if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			close(fd);
			LM_ERR("can't connect to RTP proxy\n");
			goto badproxy;
		}

		do {
			len = writev(fd, v + 1, vcnt);
		} while (len == -1 && errno == EINTR);
		if (len <= 0) {
			close(fd);
			LM_ERR("can't send command to a RTP proxy (%s)\n",strerror(errno));
			goto badproxy;
		}
		do {
			len = read(fd, buf, sizeof(buf) - 1);
		} while (len == -1 && errno == EINTR);
		close(fd);
		if (len <= 0) {
			LM_ERR("can't read reply from a RTP proxy\n");
			goto badproxy;
		}
	} else {
		fds[0].fd = rtpe_socks[node->idx];
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		/* Drain input buffer */
		while ((poll(fds, 1, 0) == 1) &&
		    ((fds[0].revents & POLLIN) != 0)) {
			recv(rtpe_socks[node->idx], buf, sizeof(buf) - 1, 0);
			fds[0].revents = 0;
		}
		v[0].iov_base = gencookie();
		v[0].iov_len = strlen(v[0].iov_base);
		for (i = 0; i < rtpengine_retr; i++) {
			do {
				len = writev(rtpe_socks[node->idx], v, vcnt + 1);
			} while (len == -1 && (errno == EINTR || errno == ENOBUFS || errno == EMSGSIZE));
			if (len <= 0) {
				LM_ERR("can't send command to a RTP proxy\n");
				goto badproxy;
			}
			while ((poll(fds, 1, rtpengine_tout * 1000) == 1) &&
			    (fds[0].revents & POLLIN) != 0) {
				do {
					len = recv(rtpe_socks[node->idx], buf, sizeof(buf)-1, 0);
				} while (len == -1 && errno == EINTR);
				if (len <= 0) {
					LM_ERR("can't read reply from a RTP proxy\n");
					goto badproxy;
				}
				if (len >= (v[0].iov_len - 1) &&
				    memcmp(buf, v[0].iov_base, (v[0].iov_len - 1)) == 0) {
					len -= (v[0].iov_len - 1);
					cp += (v[0].iov_len - 1);
					if (len != 0) {
						len--;
						cp++;
					}
					goto out;
				}
				fds[0].revents = 0;
			}
		}
		if (i == rtpengine_retr) {
			LM_ERR("timeout waiting reply from a RTP proxy\n");
			goto badproxy;
		}
	}

out:
	cp[len] = '\0';
	*outlen = len;
	return cp;
badproxy:
	LM_ERR("proxy <%s> does not respond, disable it\n", node->rn_url.s);
	node->rn_disabled = 1;
	node->rn_recheck_ticks = get_ticks() + rtpengine_disable_tout;

	return NULL;
}

/*
 * select the set with the id_set id
 */

static struct rtpe_set * select_rtpe_set(int id_set ){

	struct rtpe_set * rtpe_list;
	/*is it a valid set_id?*/

	if(!rtpe_set_list || !rtpe_set_list->rset_first){
		LM_ERR("no rtp_proxy configured\n");
		return 0;
	}

	for(rtpe_list=rtpe_set_list->rset_first; rtpe_list!=0 &&
		rtpe_list->id_set!=id_set; rtpe_list=rtpe_list->rset_next);
	if(!rtpe_list){
		LM_ERR(" script error-invalid id_set to be selected\n");
	}

	return rtpe_list;
}
/*
 * Main balancing routine. This does not try to keep the same proxy for
 * the call if some proxies were disabled or enabled; proxy death considered
 * too rare. Otherwise we should implement "mature" HA clustering, which is
 * too expensive here.
 */
static struct rtpe_node *
select_rtpe_node(str callid, int do_test, struct rtpe_set *set)
{
	unsigned sum, sumcut, weight_sum;
	struct rtpe_node* node;
	int was_forced;

	if(!set){
		LM_ERR("script error -no valid set selected\n");
		return NULL;
	}
	/* Most popular case: 1 proxy, nothing to calculate */
	if (set->rtpe_node_count == 1) {
		node = set->rn_first;
		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks())
			node->rn_disabled = rtpe_test(node, 1, 0);
		return node->rn_disabled ? NULL : node;
	}

	/* XXX Use quick-and-dirty hashing algo */
	for(sum = 0; callid.len > 0; callid.len--)
		sum += callid.s[callid.len - 1];
	sum &= 0xff;

	was_forced = 0;
retry:
	weight_sum = 0;
	for (node=set->rn_first; node!=NULL; node=node->rn_next) {

		if (node->rn_disabled && node->rn_recheck_ticks <= get_ticks()){
			/* Try to enable if it's time to try. */
			node->rn_disabled = rtpe_test(node, 1, 0);
		}
		if (!node->rn_disabled)
			weight_sum += node->rn_weight;
	}
	if (weight_sum == 0) {
		/* No proxies? Force all to be redetected, if not yet */
		if (was_forced)
			return NULL;
		was_forced = 1;
		for(node=set->rn_first; node!=NULL; node=node->rn_next) {
			node->rn_disabled = rtpe_test(node, 1, 1);
		}
		goto retry;
	}
	sumcut = sum % weight_sum;
	/*
	 * sumcut here lays from 0 to weight_sum-1.
	 * Scan proxy list and decrease until appropriate proxy is found.
	 */
	for (node=set->rn_first; node!=NULL; node=node->rn_next) {
		if (node->rn_disabled)
			continue;
		if (sumcut < node->rn_weight)
			goto found;
		sumcut -= node->rn_weight;
	}
	/* No node list */
	return NULL;
found:
	if (do_test) {
		node->rn_disabled = rtpe_test(node, node->rn_disabled, 0);
		if (node->rn_disabled)
			goto retry;
	}
	return node;
}

static int
get_extra_id(struct sip_msg* msg, str *id_str) {
	if(msg==NULL || extra_id_pv==NULL || id_str==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}
	if (pv_printf_s(msg, extra_id_pv, id_str)<0) {
		LM_ERR("cannot print the additional id\n");
		return -1;
	}

	return 1;

}

static int
set_rtpengine_set_from_avp(struct sip_msg *msg)
{
	struct usr_avp *avp;
	int_str setid_val;
	struct rtpe_set *set;

	if ((setid_avp_param == NULL) ||
			(avp = search_first_avp(setid_avp_type, setid_avp.n, &setid_val, 0))
			== NULL)
		return 1;

	if (avp->flags&AVP_VAL_STR) {
		LM_ERR("setid_avp must hold an integer value\n");
		return -1;
	}

	if ( (set=select_rtpe_set(setid_val.n)) == NULL) {
		LM_ERR("could not locate rtpengine set %d\n", setid_val.n);
		return -1;
	}

	ctx_rtpeset_set( set );
	LM_DBG("using rtpengine set %d\n", setid_val.n);

	return 1;
}

static int rtpengine_delete(struct sip_msg *msg, const char *flags) {
	return rtpe_function_call_simple(msg, OP_DELETE, flags);
}

static int
rtpengine_delete1_f(struct sip_msg* msg, gparam_p str1)
{
	str flags;

	if (set_rtpengine_set_from_avp(msg) == -1)
		return -1;

	flags.s = NULL;
	if (str1)
		fixup_get_svalue(msg, str1, &flags);

	return rtpengine_delete(msg, flags.s);
}

/* This function assumes p points to a line of requested type. */

static int
set_rtpengine_set_f(struct sip_msg * msg, rtpe_set_link_t *set_param)
{
	rtpe_set_link_t *rtpl;
	pv_value_t val;
	struct rtpe_set *set;

	rtpl = set_param;

	if(rtpl->rset != NULL) {
		ctx_rtpeset_set( rtpl->rset );
	} else {
		if(pv_get_spec_value(msg, &rtpl->rpv, &val)<0) {
			LM_ERR("cannot evaluate pv param\n");
			return -1;
		}
		if(!(val.flags & PV_VAL_INT)) {
			LM_ERR("pv param must hold an integer value\n");
			return -1;
		}
		set = select_rtpe_set(val.ri);
		if(set==NULL) {
			LM_ERR("could not locate rtpengine set %d\n", val.ri);
			return -1;
		}
		ctx_rtpeset_set( set );
	}
	return 1;
}

static int
rtpengine_manage(struct sip_msg *msg, const char *flags)
{
	int method;
	int nosdp;

	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1)
				|| (msg->cseq==NULL)))
	{
		LM_ERR("no CSEQ header\n");
		return -1;
	}

	method = get_cseq(msg)->method_id;

	if(!(method==METHOD_INVITE || method==METHOD_ACK || method==METHOD_CANCEL
				|| method==METHOD_BYE || method==METHOD_UPDATE))
		return -1;

	if(method==METHOD_CANCEL || method==METHOD_BYE)
		return rtpengine_delete(msg, flags);

	if(msg_has_sdp(msg))
		nosdp = 0;
	else
		nosdp = parse_sdp(msg);

	if(msg->first_line.type == SIP_REQUEST) {
		if(method==METHOD_ACK && nosdp==0)
			return rtpengine_offer_answer(msg, flags, OP_ANSWER);
		if(method==METHOD_UPDATE && nosdp==0)
			return rtpengine_offer_answer(msg, flags, OP_OFFER);
		if(method==METHOD_INVITE && nosdp==0) {
			if(route_type==FAILURE_ROUTE)
				return rtpengine_delete(msg, flags);
			return rtpengine_offer_answer(msg, flags, OP_OFFER);
		}
	} else if(msg->first_line.type == SIP_REPLY) {
		if(msg->first_line.u.reply.statuscode>=300)
			return rtpengine_delete(msg, flags);
		if(nosdp==0) {
			if(method==METHOD_UPDATE)
				return rtpengine_offer_answer(msg, flags, OP_ANSWER);
			if(tmb.t_gett==NULL || tmb.t_gett()==NULL
					|| tmb.t_gett()==T_UNDEFINED)
				return rtpengine_offer_answer(msg, flags, OP_ANSWER);
			return rtpengine_offer_answer(msg, flags, OP_OFFER);
		}
	}
	return -1;
}

static int
rtpengine_manage1_f(struct sip_msg *msg, gparam_p str1)
{
	str flags;

	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	flags.s = NULL;
	if (str1)
		fixup_get_svalue(msg, str1, &flags);

	return rtpengine_manage(msg, flags.s);
}

static int
rtpengine_offer1_f(struct sip_msg *msg, gparam_p str1)
{
	str flags;

	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	flags.s = NULL;
	if (str1)
		fixup_get_svalue(msg, str1, &flags);
	return rtpengine_offer_answer(msg, flags.s, OP_OFFER);
}

static int
rtpengine_answer1_f(struct sip_msg *msg, gparam_p str1)
{
	str flags;

	if (set_rtpengine_set_from_avp(msg) == -1)
	    return -1;

	if (msg->first_line.type == SIP_REQUEST)
		if (msg->first_line.u.request.method_value != METHOD_ACK)
			return -1;

	flags.s = NULL;
	if (str1)
		fixup_get_svalue(msg, str1, &flags);
	return rtpengine_offer_answer(msg, flags.s, OP_ANSWER);
}

static int
rtpengine_offer_answer(struct sip_msg *msg, const char *flags, int op)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict;
	str body, newbody;
	struct lump *anchor;

	dict = rtpe_function_call_ok(&bencbuf, msg, op, flags, &body);
	if (!dict)
		return -1;

	if (!bencode_dictionary_get_str_dup(dict, "sdp", &newbody)) {
		LM_ERR("failed to extract sdp body from proxy reply\n");
		goto error;
	}

	anchor = del_lump(msg, body.s - msg->buf, body.len, 0);
	if (!anchor) {
		LM_ERR("del_lump failed\n");
		goto error_free;
	}
	if (!insert_new_lump_after(anchor, newbody.s, newbody.len, 0)) {
		LM_ERR("insert_new_lump_after failed\n");
		goto error_free;
	}

	bencode_buffer_free(&bencbuf);
	return 1;

error_free:
	pkg_free(newbody.s);
error:
	bencode_buffer_free(&bencbuf);
	return -1;
}


static int
start_recording_f(struct sip_msg* msg)
{
	return rtpe_function_call_simple(msg, OP_START_RECORDING, NULL);
}

/*
 * Returns the current RTP-Statistics from the RTP-Proxy
 */
static int
pv_get_rtpstat_f(struct sip_msg *msg, pv_param_t *param,
		  pv_value_t *res)
{
	bencode_buffer_t bencbuf;
	bencode_item_t *dict, *tot, *rtp, *rtcp;
	static char buf[256];
	str ret;

	dict = rtpe_function_call_ok(&bencbuf, msg, OP_QUERY, NULL, NULL);
	if (!dict)
		return -1;

	tot = bencode_dictionary_get_expect(dict, "totals", BENCODE_DICTIONARY);
	rtp = bencode_dictionary_get_expect(tot, "RTP", BENCODE_DICTIONARY);
	rtcp = bencode_dictionary_get_expect(tot, "RTCP", BENCODE_DICTIONARY);
	if (!rtp || !rtcp)
		goto error;
	ret.s = buf;
	ret.len = snprintf(buf, sizeof(buf),
		"RTP: %lli bytes, %lli packets, %lli errors; "
		"RTCP: %lli bytes, %lli packets, %lli errors",
		bencode_dictionary_get_integer(rtp, "bytes", -1),
		bencode_dictionary_get_integer(rtp, "packets", -1),
		bencode_dictionary_get_integer(rtp, "errors", -1),
		bencode_dictionary_get_integer(rtcp, "bytes", -1),
		bencode_dictionary_get_integer(rtcp, "packets", -1),
		bencode_dictionary_get_integer(rtcp, "errors", -1));

	bencode_buffer_free(&bencbuf);
	return pv_get_strval(msg, param, res, &ret);

error:
	bencode_buffer_free(&bencbuf);
	return -1;
}

