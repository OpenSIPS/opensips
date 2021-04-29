/*
 *  cfg grammar
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2005-2009 Voice Sistem S.R.L.
 * Copyright (C) 2006 enum.at
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
 */
 /*
 * History:
 * ---------
 * 2003-01-29  src_port added (jiri)
 * 2003-01-23  mhomed added (jiri)
 * 2003-03-19  replaced all mallocs/frees with pkg_malloc/pkg_free (andrei)
 * 2003-03-19  Added support for route type in find_export (janakj)
 * 2003-03-20  Regex support in modparam (janakj)
 * 2003-04-01  added dst_port, proto , af (andrei)
 * 2003-04-05  s/reply_route/failure_route, onreply_route introduced (jiri)
 * 2003-04-12  added force_rport, chroot and wdir (andrei)
 * 2003-04-15  added tcp_children, disable_tcp (andrei)
 * 2003-04-22  strip_tail added (jiri)
 * 2003-07-03  tls* (disable, certificate, private_key, ca_list, verify,
 *              require_certificate added (andrei)
 * 2003-07-06  more tls config. vars added: tls_method, tls_port_no (andrei)
 * 2003-10-02  added {,set_}advertised_{address,port} (andrei)
 * 2003-10-10  added <,>,<=,>=, != operators support
 *             added msg:len (andrei)
 * 2003-10-11  if(){} doesn't require a ';' after it anymore (andrei)
 * 2003-10-13  added FIFO_DIR & proto:host:port listen/alias support (andrei)
 * 2003-10-24  converted to the new socket_info lists (andrei)
 * 2003-10-28  added tcp_accept_aliases (andrei)
 * 2003-11-20  added {tcp_connect, tcp_send, tls_*}_timeout (andrei)
 * 2004-03-30  added DISABLE_CORE and OPEN_FD_LIMIT (andrei)
 * 2004-04-29  added SOCK_MODE, SOCK_USER & SOCK_GROUP (andrei)
 * 2004-05-03  applied multicast support patch (MCAST_LOOPBACK) from janakj
               added MCAST_TTL (andrei)
 * 2004-07-05  src_ip & dst_ip will detect ip addresses between quotes
 *              (andrei)
 * 2004-10-19  added FROM_URI, TO_URI (andrei)
 * 2004-11-30  added force_send_socket (andrei)
 * 2005-07-08  added TCP_CON_LIFETIME, TCP_POLL_METHOD, TCP_MAX_CONNECTIONS
 *              (andrei)
 * 2005-07-26  default onreply route added (andrei)
 * 2005-11-22  added tos configurability (thanks to Andreas Granig)
 * 2005-11-29  added serialize_branches and next_branches (bogdan)
 * 2006-03-02  MODULE_T action points to a cmd_export_t struct instead to
 *              a function address - more info is accessible (bogdan)
 * 2006-03-02  store the cfg line into the action struct to be able to
 *              give more hints if fixups fail (bogdan)
 * 2006-05-22  forward(_udp,_tcp,_tls) and send(_tcp) merged in forward() and
 *              send() (bogdan)
 *  2006-12-22  functions for script and branch flags added (bogdan)
 *  2007-01-11  auto_aliases option added (bogdan)
 *  2007-01-25  disable_dns_failover option added (bogdan)
 *  2012-01-19  added TCP keepalive support
 *  2012-12-06  added event_route (razvanc)
 *  2013-05-23  added NAPTR lookup option (dsandras)
 *	2013-09-25	added TLS_CA_DIR option (chris_secusmart)
 *	2013-10-06	added TLS_DH_PARAM option (mehmet_secusmart)
 *	2013-10-30	added TLS_EC_CURVE option (yrjoe_secusmart)
 */


%{

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include "route_struct.h"
#include "globals.h"
#include "route.h"
#include "dprint.h"
#include "cfg_pp.h"
#include "sr_module.h"
#include "modparam.h"
#include "ip_addr.h"
#include "resolve.h"
#include "socket_info.h"
#include "name_alias.h"
#include "ut.h"
#include "pt_scaling.h"
#include "dset.h"
#include "pvar.h"
#include "blacklists.h"
#include "xlog.h"
#include "db/db_insertq.h"
#include "bin_interface.h"
#include "net/trans.h"
#include "config.h"
#include "mem/rpm_mem.h"

#ifdef SHM_EXTRA_STATS
#include "mem/module_info.h"
#endif

#ifdef DEBUG_DMALLOC
#include <dmalloc.h>
#endif

/* hack to avoid alloca usage in the generated C file (needed for compiler
 with no built in alloca, like icc*/
#undef _ALLOCA_H

#undef MIN
#undef MAX

extern int yylex();
static void yyerror(char* s);
static void yyerrorf(char* fmt, ...);
static char* tmp;
static int i_tmp, rc;
static void* cmd_tmp;
static struct socket_id* lst_tmp;
static int rt;  /* Type of route block for find_export */
static str s_tmp;
static str tstr;
static struct net* net_tmp;
static pv_spec_t *spec;
static pv_elem_t *elem;
static struct bl_rule *bl_head = 0;
static struct bl_rule *bl_tail = 0;

action_elem_t elems[MAX_ACTION_ELEMS];
static action_elem_t route_elems[MAX_ACTION_ELEMS];
action_elem_t *a_tmp;

static inline void warn(char* s);
static struct socket_id* mk_listen_id(char*, enum sip_protos, int);
static struct socket_id* set_listen_id_adv(struct socket_id *, char *, int);
static struct multi_str *new_string(char *s);
static int parse_ipnet(char *in, int len, struct net **ipnet);

extern int line;
extern int column;
extern int startcolumn;
extern char *finame;

struct listen_param {
	enum si_flags flags;
	int workers;
	struct socket_id *socket;
	char *tag;
	char *auto_scaling_profile;
} p_tmp;
static void fill_socket_id(struct listen_param *param, struct socket_id *s);

union route_name_var {
	int iname;
	struct _pv_spec *sname;
	struct _pv_elem *ename;
	void *data;
} rn_tmp;

#ifndef SHM_EXTRA_STATS
struct multi_str{
	char *s;
	struct multi_str* next;
};
#else 
static struct multi_str *tmp_mod;
#endif

#define get_cfg_file_name \
	((finame) ? finame : cfg_file ? cfg_file : "default")



#define mk_action_(_res, _type, _no, _elems) \
	do { \
		_res = mk_action(_type, _no, _elems, line, get_cfg_file_name); \
	} while(0)
#define mk_action0(_res, _type) \
	do { \
		_res = mk_action(_type, 0, 0, line, get_cfg_file_name); \
	} while(0)
#define mk_action1(_res, _type, _p1_type, _p1) \
	do { \
		elems[0].type = _p1_type; \
		elems[0].u.data = _p1; \
		_res = mk_action(_type, 1, elems, line, get_cfg_file_name); \
	} while(0)
#define	mk_action2(_res, _type, _p1_type, _p2_type, _p1, _p2) \
	do { \
		elems[0].type = _p1_type; \
		elems[0].u.data = _p1; \
		elems[1].type = _p2_type; \
		elems[1].u.data = _p2; \
		_res = mk_action(_type, 2, elems, line, get_cfg_file_name); \
	} while(0)
#define mk_action3(_res, _type, _p1_type, _p2_type, _p3_type, _p1, _p2, _p3) \
	do { \
		elems[0].type = _p1_type; \
		elems[0].u.data = _p1; \
		elems[1].type = _p2_type; \
		elems[1].u.data = _p2; \
		elems[2].type = _p3_type; \
		elems[2].u.data = _p3; \
		_res = mk_action(_type, 3, elems, line, get_cfg_file_name); \
	} while(0)

extern int cfg_parse_only_routes;
#define IFOR(_instr) \
	if (cfg_parse_only_routes==1) {_instr;break;}

%}


%union {
	long intval;
	unsigned long uval;
	char* strval;
	struct expr* expr;
	struct action* action;
	struct net* ipnet;
	struct ip_addr* ipaddr;
	struct socket_id* sockid;
	struct listen_param* listen_param;
	struct _pv_spec *specval;
	struct multi_str* multistr;
}

/* terminals */


/* keywords */
%token DROP
%token ASSERT
%token EXIT
%token RETURN
%token LOG_TOK
%token ERROR
%token ROUTE
%token ROUTE_FAILURE
%token ROUTE_ONREPLY
%token ROUTE_BRANCH
%token ROUTE_ERROR
%token ROUTE_LOCAL
%token ROUTE_STARTUP
%token ROUTE_TIMER
%token ROUTE_EVENT
%token IF
%token ELSE
%token SWITCH
%token CASE
%token DEFAULT
%token BREAK
%token WHILE
%token FOR
%token IN
%token NULLV
%token XDBG
%token XLOG
%token XLOG_BUF_SIZE
%token XLOG_FORCE_COLOR
%token XLOG_PRINT_LEVEL
%token XLOG_LEVEL
%token PV_PRINT_BUF_SIZE

/* config vars. */
%token DEBUG_MODE
%token ENABLE_ASSERTS
%token ABORT_ON_ASSERT
%token LOGLEVEL
%token LOGSTDERROR
%token LOGFACILITY
%token LOGNAME
%token AVP_ALIASES
%token LISTEN
%token SOCKET
%token MEMGROUP
%token ALIAS
%token AUTO_ALIASES
%token TAG
%token DNS
%token REV_DNS
%token DNS_TRY_IPV6
%token DNS_TRY_NAPTR
%token DNS_RETR_TIME
%token DNS_RETR_NO
%token DNS_SERVERS_NO
%token DNS_USE_SEARCH
%token MAX_WHILE_LOOPS
%token UDP_WORKERS
%token CHECK_VIA
%token SHM_HASH_SPLIT_PERCENTAGE
%token SHM_SECONDARY_HASH_SIZE
%token MEM_WARMING_ENABLED
%token MEM_WARMING_PATTERN_FILE
%token MEM_WARMING_PERCENTAGE
%token RPM_MEM_FILE
%token RPM_MEM_SIZE
%token MEMLOG
%token MEMDUMP
%token EXECMSGTHRESHOLD
%token EXECDNSTHRESHOLD
%token TCPTHRESHOLD
%token EVENT_SHM_THRESHOLD
%token EVENT_PKG_THRESHOLD
%token QUERYBUFFERSIZE
%token QUERYFLUSHTIME
%token SIP_WARNING
%token SERVER_SIGNATURE
%token SERVER_HEADER
%token USER_AGENT_HEADER
%token LOADMODULE
%token MPATH
%token MODPARAM
%token MAXBUFFER
%token CHROOT
%token WDIR
%token MHOMED
%token POLL_METHOD
%token TCP_ACCEPT_ALIASES
%token TCP_WORKERS
%token TCP_CONNECT_TIMEOUT
%token TCP_CON_LIFETIME
%token TCP_LISTEN_BACKLOG
%token TCP_SOCKET_BACKLOG
%token TCP_MAX_CONNECTIONS
%token TCP_NO_NEW_CONN_BFLAG
%token TCP_NO_NEW_CONN_RPLFLAG
%token TCP_KEEPALIVE
%token TCP_KEEPCOUNT
%token TCP_KEEPIDLE
%token TCP_KEEPINTERVAL
%token TCP_MAX_MSG_TIME
%token ADVERTISED_ADDRESS
%token ADVERTISED_PORT
%token DISABLE_CORE
%token OPEN_FD_LIMIT
%token MCAST_LOOPBACK
%token MCAST_TTL
%token TOS
%token DISABLE_DNS_FAILOVER
%token DISABLE_DNS_BLACKLIST
%token DST_BLACKLIST
%token DISABLE_STATELESS_FWD
%token DB_VERSION_TABLE
%token DB_DEFAULT_URL
%token DB_MAX_ASYNC_CONNECTIONS
%token DISABLE_503_TRANSLATION
%token SYNC_TOKEN
%token ASYNC_TOKEN
%token LAUNCH_TOKEN
%token AUTO_SCALING_PROFILE
%token AUTO_SCALING_CYCLE
%token TIMER_WORKERS




/* operators */
%nonassoc EQUAL
%nonassoc EQUAL_T
%nonassoc GT
%nonassoc LT
%nonassoc GTE
%nonassoc LTE
%nonassoc DIFF
%nonassoc MATCH
%nonassoc NOTMATCH
%nonassoc COLONEQ
%nonassoc PLUSEQ
%nonassoc MINUSEQ
%nonassoc SLASHEQ
%nonassoc MULTEQ
%nonassoc MODULOEQ
%nonassoc BANDEQ
%nonassoc BOREQ
%nonassoc BXOREQ

%left OR AND
%left BOR BAND BXOR BLSHIFT BRSHIFT
%left PLUS MINUS SLASH MULT MODULO
%right NOT BNOT
%right RPAREN ELSE /* solves the classic if-if-else ambiguity */

/* values */
%token <intval> NUMBER
%token <intval> ZERO
%token <strval> ID
%token <strval> STRING
%token <strval> SCRIPTVAR
%token <strval> IPV6ADDR
%token <strval> IPV4ADDR
%token <strval> IPNET

/* other */
%token COMMA
%token SEMICOLON
%token RPAREN
%token LPAREN
%token LBRACE
%token RBRACE
%token LBRACK
%token RBRACK
%token SLASH
%token AS
%token USE_WORKERS
%token USE_AUTO_SCALING_PROFILE
%token MAX
%token MIN
%token DOT
%token CR
%token COLON
%token ANY
%token ANYCAST
%token SCRIPTVARERR
%token SCALE_UP_TO
%token SCALE_DOWN_TO
%token ON
%token CYCLES
%token CYCLES_WITHIN
%token PERCENTAGE


/*non-terminals */
%type <expr> exp exp_elem exp_cond assignexp /*, condition*/
%type <action> action actions brk_action brk_actions cmd if_cmd stm brk_stm
%type <action> exp_stm assign_cmd while_cmd foreach_cmd async_func brk_if_cmd
%type <action> switch_cmd switch_stm case_stms case_stm default_stm
%type <intval> func_param
%type <ipaddr> ipv4 ipv6 ipv6addr ip
%type <ipnet> ipnet
%type <specval> script_var
%type <strval> host
%type <strval> listen_id
%type <sockid> socket_def
%type <sockid> id_lst
%type <sockid> alias_def
%type <sockid> listen_id_def
%type <sockid> phostport panyhostport
%type <intval> proto port any_proto
%type <strval> host_sep
%type <intval> equalop compop matchop strop intop
%type <intval> assignop
%type <intval> snumber
%type <strval> route_name
%type <intval> route_name_var
%type <intval> route_param
%type <strval> folded_string
%type <multistr> multi_string

/*
 * known shift/reduce conflicts (the default action, shift, is correct):
 *   - RETURN PLUS NUMBER
 *   - RETURN MINUS NUMBER
 *      (reason: MINUS has left associativity, but for both "return -1;" and
 *         "return;" to work, it would need right assoc;  same idea for PLUS)
 */
%expect 2


%%


cfg:	statements
	;

statements:	statements statement {}
		| statement {}
		| statements error { yyerror(""); YYABORT;}
	;

statement: assign_stm
		| module_stm
		| {rt=REQUEST_ROUTE;} route_stm
		| {rt=FAILURE_ROUTE;} failure_route_stm
		| {rt=ONREPLY_ROUTE;} onreply_route_stm
		| {rt=BRANCH_ROUTE;} branch_route_stm
		| {rt=ERROR_ROUTE;} error_route_stm
		| {rt=LOCAL_ROUTE;} local_route_stm
		| {rt=STARTUP_ROUTE;} startup_route_stm
		| {rt=TIMER_ROUTE;} timer_route_stm
		| {rt=EVENT_ROUTE;} event_route_stm

		| CR	/* null statement*/
	;

listen_id:	ip			{ IFOR();
							tmp=ip_addr2a($1);
							if(tmp==0){
								LM_CRIT("cfg. parser: bad ip address.\n");
								$$=0;
							}else{
								$$=pkg_malloc(strlen(tmp)+1);
								if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
									YYABORT;
								}else{
									memcpy($$, tmp, strlen(tmp)+1);
								}
							}
						}
		|	STRING		{ IFOR();
							$$=pkg_malloc(strlen($1)+1);
							if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
									YYABORT;
							}else{
									memcpy($$, $1, strlen($1)+1);
							}
						}
		|	host		{ IFOR();
							if ($1==0) {
								$$ = 0;
							} else {
								$$=pkg_malloc(strlen($1)+1);
								if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
									YYABORT;
								}else{
									memcpy($$, $1, strlen($1)+1);
								}
							}
						}
	;

host_sep:	DOT {$$=".";}
		|	MINUS {$$="-"; }
		;

host:	ID				{ $$=$1; }
	| host host_sep ID	{ IFOR();
						$$=(char*)pkg_malloc(strlen($1)+1+strlen($3)+1);
						if ($$==0){
							LM_CRIT("cfg. parser: memory allocation"
										" failure while parsing host\n");
							YYABORT;
						}else{
							memcpy($$, $1, strlen($1));
							$$[strlen($1)]=*$2;
							memcpy($$+strlen($1)+1, $3, strlen($3));
							$$[strlen($1)+1+strlen($3)]=0;
						}
						pkg_free($1); pkg_free($3);
					}
	| host DOT error { $$=0; pkg_free($1);
					yyerror("invalid hostname (use quotes if hostname "
						"has config keywords)"); }
	;

proto:	ID { IFOR();
		if (parse_proto((unsigned char *)$1, strlen($1), &i_tmp) < 0) {
			yyerrorf("cannot handle protocol <%s>\n", $1);
			YYABORT;
		}
		pkg_free($1);
		$$ = i_tmp;
	 }
;

port:	  NUMBER	{ $$=$1; }
		| ANY		{ $$=0; }
;

snumber:	NUMBER	{ $$=$1; }
		| PLUS NUMBER	{ $$=$2; }
		| MINUS NUMBER	{ $$=-$2; }
;


phostport: proto COLON listen_id	{ IFOR();
				$$=mk_listen_id($3, $1, 0); }
			| proto COLON listen_id COLON port	{ IFOR();
				$$=mk_listen_id($3, $1, $5);}
			| proto COLON listen_id COLON error {
				$$=0;
				yyerror("port number expected");
				YYABORT;
				}
			| NUMBER error { $$=0;
				yyerror("protocol expected");
				YYABORT;
			}
			;

panyhostport: proto COLON MULT				{ IFOR();
				$$=mk_listen_id(0, $1, 0); }
			| proto COLON MULT COLON port	{ IFOR();
				$$=mk_listen_id(0, $1, $5); }
			;

alias_def:	listen_id						{ IFOR();
				$$=mk_listen_id($1, PROTO_NONE, 0); }
		 |	ANY COLON listen_id				{ IFOR();
		 		$$=mk_listen_id($3, PROTO_NONE, 0); }
		 |	ANY COLON listen_id COLON port	{ IFOR();
		 		$$=mk_listen_id($3, PROTO_NONE, $5); }
		 |	ANY COLON listen_id COLON error {
				$$=0;
				yyerror(" port number expected");
				}
		 | phostport
		 ;

id_lst:		alias_def		{ IFOR();  $$=$1 ; }
		| alias_def id_lst	{ IFOR(); $$=$1; $$->next=$2; }
		;

listen_id_def:	listen_id					{ IFOR();
					$$=mk_listen_id($1, PROTO_NONE, 0); }
			 |	listen_id COLON port		{ IFOR();
			 		$$=mk_listen_id($1, PROTO_NONE, $3); }
			 |	listen_id COLON error {
					$$=0;
					yyerror(" port number expected");
					}
			 ;

socket_def_param: ANYCAST { IFOR();
					p_tmp.flags |= SI_IS_ANYCAST;
					}
				| USE_WORKERS NUMBER { IFOR();
					p_tmp.workers=$2;
					}
				| AS listen_id_def { IFOR();
					p_tmp.socket = $2;
					}
				| TAG ID { IFOR();
					p_tmp.tag = $2;
					}
				| USE_AUTO_SCALING_PROFILE ID { IFOR();
					p_tmp.auto_scaling_profile=$2;
					}
				;

socket_def_params:	socket_def_param
				 |	socket_def_param socket_def_params
				 ;

socket_def:	panyhostport			{ $$=$1; }
			| phostport				{ $$=$1; }
			| panyhostport { IFOR();
					memset(&p_tmp, 0, sizeof(p_tmp));
				} socket_def_params	{ IFOR();
					$$=$1; fill_socket_id(&p_tmp, $$);
				}
			| phostport { IFOR();
					memset(&p_tmp, 0, sizeof(p_tmp));
				} socket_def_params	{ IFOR();
					$$=$1; fill_socket_id(&p_tmp, $$);
				}
			;

any_proto:	  ANY	{ $$=PROTO_NONE; }
			| proto	{ $$=$1; }

multi_string: 	STRING {  IFOR(); $$=new_string($1); }
		| STRING multi_string { IFOR(); $$=new_string($1); $$->next=$2; }
		;

blst_elem: LPAREN  any_proto COMMA ipnet COMMA port COMMA STRING RPAREN {
				IFOR(pkg_free($4));
				s_tmp.s=$8;
				s_tmp.len=strlen($8);
				if (add_rule_to_list(&bl_head,&bl_tail,$4,&s_tmp,$6,$2,0)) {
					yyerror("failed to add backlist element\n");YYABORT;
				}
			}
		| NOT  LPAREN  any_proto COMMA ipnet COMMA port COMMA STRING RPAREN {
				IFOR(pkg_free($5));
				s_tmp.s=$9;
				s_tmp.len=strlen($9);
				if (add_rule_to_list(&bl_head,&bl_tail,$5,&s_tmp,
				$7,$3,BLR_APPLY_CONTRARY)) {
					yyerror("failed to add backlist element\n");YYABORT;
				}
			}
		;

blst_elem_list: blst_elem_list COMMA blst_elem {}
		| blst_elem {}
		| blst_elem_list error { yyerror("bad black list element");}
		;

auto_scale_profile_def:
		  ID SCALE_UP_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES_WITHIN NUMBER
		  SCALE_DOWN_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES { IFOR();
			if (create_auto_scaling_profile($1,$3,$5,$8,$10,
			$12, $14, $17,10*$17)<0)
				yyerror("failed to create auto scaling profile");
		 }
		| ID SCALE_UP_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES
		  SCALE_DOWN_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES { IFOR();
			if (create_auto_scaling_profile($1,$3,$5,$8,$8,
			$11, $13, $16, 10*$16)<0)
				yyerror("failed to create auto scaling profile");
		 }
		| ID SCALE_UP_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES_WITHIN NUMBER { IFOR();
			if (create_auto_scaling_profile($1,$3,$5,$8,$10,
			0, 0, 0, 0)<0)
				yyerror("failed to create auto scaling profile");
		}
		| ID SCALE_UP_TO NUMBER ON NUMBER MODULO FOR
				NUMBER CYCLES { IFOR();
			if (create_auto_scaling_profile($1,$3,$5,$8,$8,
			0, 0, 0, 0)<0)
				yyerror("failed to create auto scaling profile");
		}
		;

assign_stm: LOGLEVEL EQUAL snumber { IFOR();
			/* in debug mode, force logging to DEBUG level*/
			*log_level = debug_mode?L_DBG:$3;
			}
		| ENABLE_ASSERTS EQUAL NUMBER  { IFOR(); enable_asserts=$3; }
		| ENABLE_ASSERTS EQUAL error  { yyerror("boolean value expected"); }
		| ABORT_ON_ASSERT EQUAL NUMBER  { IFOR(); abort_on_assert=$3; }
		| ABORT_ON_ASSERT EQUAL error  { yyerror("boolean value expected"); }
		| DEBUG_MODE EQUAL NUMBER  { IFOR();
			debug_mode=$3;
			if (debug_mode) { *log_level = L_DBG;log_stderr=1;}
			}
		| DEBUG_MODE EQUAL error
			{ yyerror("boolean value expected for debug_mode"); }
		| LOGSTDERROR EQUAL NUMBER 
			/* in config-check or debug mode we force logging 
			 * to standard error */
			{ IFOR(); if (!config_check && !debug_mode) log_stderr=$3; }
		| LOGSTDERROR EQUAL error { yyerror("boolean value expected"); }
		| LOGFACILITY EQUAL ID { IFOR();
			if ( (i_tmp=str2facility($3))==-1)
				yyerror("bad facility (see syslog(3) man page)");
			if (!config_check)
				log_facility=i_tmp;
			}
		| LOGFACILITY EQUAL error { yyerror("ID expected"); }
		| LOGNAME EQUAL STRING { IFOR(); log_name=$3; }
		| LOGNAME EQUAL error { yyerror("string value expected"); }
		| DNS EQUAL NUMBER   { IFOR(); received_dns|= ($3)?DO_DNS:0; }
		| DNS EQUAL error { yyerror("boolean value expected"); }
		| REV_DNS EQUAL NUMBER { IFOR(); received_dns|= ($3)?DO_REV_DNS:0; }
		| REV_DNS EQUAL error { yyerror("boolean value expected"); }
		| DNS_TRY_IPV6 EQUAL NUMBER   { IFOR(); dns_try_ipv6=$3; }
		| DNS_TRY_IPV6 error { yyerror("boolean value expected"); }
		| DNS_TRY_NAPTR EQUAL NUMBER   { IFOR(); dns_try_naptr=$3; }
		| DNS_TRY_NAPTR error { yyerror("boolean value expected"); }
		| DNS_RETR_TIME EQUAL NUMBER   { IFOR(); dns_retr_time=$3; }
		| DNS_RETR_TIME error { yyerror("number expected"); }
		| DNS_RETR_NO EQUAL NUMBER   { IFOR(); dns_retr_no=$3; }
		| DNS_RETR_NO error { yyerror("number expected"); }
		| DNS_SERVERS_NO EQUAL NUMBER   { IFOR(); dns_servers_no=$3; }
		| DNS_SERVERS_NO error { yyerror("number expected"); }
		| DNS_USE_SEARCH EQUAL NUMBER   { IFOR(); dns_search_list=$3; }
		| DNS_USE_SEARCH error { yyerror("boolean value expected"); }
		| MAX_WHILE_LOOPS EQUAL NUMBER { IFOR(); max_while_loops=$3; }
		| MAX_WHILE_LOOPS EQUAL error { yyerror("number expected"); }
		| MAXBUFFER EQUAL NUMBER { IFOR(); maxbuffer=$3; }
		| MAXBUFFER EQUAL error { yyerror("number expected"); }
		| UDP_WORKERS EQUAL NUMBER { IFOR(); udp_workers_no=$3; }
		| UDP_WORKERS EQUAL NUMBER USE_AUTO_SCALING_PROFILE ID { IFOR();
				udp_workers_no=$3;
				udp_auto_scaling_profile=$5;
		}
		| UDP_WORKERS EQUAL error { yyerror("number expected"); }
		| TIMER_WORKERS EQUAL NUMBER { IFOR();
				timer_workers_no=$3;
		}
		| TIMER_WORKERS EQUAL NUMBER USE_AUTO_SCALING_PROFILE ID { IFOR();
				timer_workers_no=$3;
				timer_auto_scaling_profile=$5;
		}
		| CHECK_VIA EQUAL NUMBER { check_via=$3; }
		| CHECK_VIA EQUAL error { yyerror("boolean value expected"); }
		| SHM_HASH_SPLIT_PERCENTAGE EQUAL NUMBER { IFOR();
			#ifdef HP_MALLOC
			shm_hash_split_percentage=$3;
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
			}
		| SHM_HASH_SPLIT_PERCENTAGE EQUAL error {
			#ifdef HP_MALLOC
			yyerror("number expected");
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
				}
		| SHM_SECONDARY_HASH_SIZE EQUAL NUMBER { IFOR();
			#ifdef HP_MALLOC
			shm_secondary_hash_size=$3;
			#else
			LM_ERR("Cannot set parameter; Please recompile with support"
				" for HP_MALLOC\n");
			#endif
			}
		| SHM_SECONDARY_HASH_SIZE EQUAL error {
			#ifdef HP_MALLOC
			yyerror("number expected");
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_ENABLED EQUAL NUMBER { IFOR();
			#ifdef HP_MALLOC
			mem_warming_enabled = $3;
			#else
			LM_ERR("Cannot set parameter; Please recompile with support"
				" for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_ENABLED EQUAL error {
			#ifdef HP_MALLOC
			yyerror("number expected");
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_PATTERN_FILE EQUAL STRING { IFOR();
			#ifdef HP_MALLOC
			mem_warming_pattern_file = $3;
			#else
			LM_ERR("Cannot set parameter; Please recompile with "
				"support for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_PATTERN_FILE EQUAL error {
			#ifdef HP_MALLOC
			yyerror("string expected");
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_PERCENTAGE EQUAL NUMBER { IFOR();
			#ifdef HP_MALLOC
			mem_warming_percentage = $3;
			#else
			LM_ERR("Cannot set parameter; Please recompile with "
				"support for HP_MALLOC\n");
			#endif
			}
		| MEM_WARMING_PERCENTAGE EQUAL error {
			#ifdef HP_MALLOC
			yyerror("number expected");
			#else
			LM_ERR("Cannot set parameter; Please recompile with support "
				"for HP_MALLOC\n");
			#endif
			}
		| RPM_MEM_FILE EQUAL STRING { IFOR();
			rpm_mem_file = $3;
			}
		| RPM_MEM_FILE EQUAL error { yyerror("string value expected"); }
		| RPM_MEM_SIZE EQUAL NUMBER { IFOR();
			rpm_mem_size = $3 * 1024 * 1024;
			}
		| RPM_MEM_SIZE EQUAL error { yyerror("int value expected"); }
		| MEMLOG EQUAL snumber { IFOR(); memlog=$3; memdump=$3; }
		| MEMLOG EQUAL error { yyerror("int value expected"); }
		| MEMDUMP EQUAL snumber { IFOR(); memdump=$3; }
		| MEMDUMP EQUAL error { yyerror("int value expected"); }
		| EXECMSGTHRESHOLD EQUAL NUMBER {  IFOR();execmsgthreshold=$3; }
		| EXECMSGTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| EXECDNSTHRESHOLD EQUAL NUMBER { IFOR(); execdnsthreshold=$3; }
		| EXECDNSTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| TCPTHRESHOLD EQUAL NUMBER { IFOR(); tcpthreshold=$3; }
		| TCPTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| EVENT_SHM_THRESHOLD EQUAL NUMBER { IFOR();
			#ifdef STATISTICS
			if ($3 < 0 || $3 > 100)
				yyerror("SHM threshold has to be a percentage between"
					" 0 and 100");
			event_shm_threshold=$3;
			#else
			yyerror("statistics support not compiled in");
			#endif /* STATISTICS */
			}
		| EVENT_SHM_THRESHOLD EQUAL error { yyerror("int value expected"); }
		| EVENT_PKG_THRESHOLD EQUAL NUMBER { IFOR();
			#ifdef PKG_MALLOC
			#ifdef STATISTICS
			if ($3 < 0 || $3 > 100)
				yyerror("PKG threshold has to be a percentage between "
					"0 and 100");
			event_pkg_threshold=$3;
			#else
			yyerror("statistics support not compiled in");
			#endif
			#else
			yyerror("pkg_malloc support not compiled in");
			#endif
			}
		| EVENT_PKG_THRESHOLD EQUAL error { yyerror("int value expected"); }
		| QUERYBUFFERSIZE EQUAL NUMBER { IFOR(); query_buffer_size=$3; }
		| QUERYBUFFERSIZE EQUAL error { yyerror("int value expected"); }
		| QUERYFLUSHTIME EQUAL NUMBER { IFOR(); query_flush_time=$3; }
		| QUERYFLUSHTIME EQUAL error { yyerror("int value expected"); }
		| SIP_WARNING EQUAL NUMBER { IFOR(); sip_warning=$3; }
		| SIP_WARNING EQUAL error { yyerror("boolean value expected"); }
		| CHROOT EQUAL STRING     { IFOR(); chroot_dir=$3; }
		| CHROOT EQUAL ID         { IFOR(); chroot_dir=$3; }
		| CHROOT EQUAL error      { yyerror("string value expected"); }
		| WDIR EQUAL STRING     { IFOR(); working_dir=$3; }
		| WDIR EQUAL ID         { IFOR(); working_dir=$3; }
		| WDIR EQUAL error      { yyerror("string value expected"); }
		| MHOMED EQUAL NUMBER { IFOR(); mhomed=$3; }
		| MHOMED EQUAL error { yyerror("boolean value expected"); }
		| POLL_METHOD EQUAL ID { IFOR();
									io_poll_method=get_poll_type($3);
									if (io_poll_method==POLL_NONE){
										LM_CRIT("bad poll method name:"
											" %s\n, try one of %s.\n",
											$3, poll_support);
										yyerror("bad poll_method "
											"value");
									}
								}
		| POLL_METHOD EQUAL STRING { IFOR();
									io_poll_method=get_poll_type($3);
									if (io_poll_method==POLL_NONE){
										LM_CRIT("bad poll method name:"
											" %s\n, try one of %s.\n",
											$3, poll_support);
										yyerror("bad poll_method "
											"value");
									}
									}
		| POLL_METHOD EQUAL error { yyerror("poll method name expected"); }
		| TCP_ACCEPT_ALIASES EQUAL NUMBER { IFOR();
				tcp_accept_aliases=$3;
		}
		| TCP_ACCEPT_ALIASES EQUAL error { yyerror("boolean value expected"); }
		| TCP_WORKERS EQUAL NUMBER { IFOR();
				tcp_workers_no=$3;
		}
		| TCP_WORKERS EQUAL NUMBER USE_AUTO_SCALING_PROFILE ID{ IFOR();
				tcp_workers_no=$3;
				tcp_auto_scaling_profile=$5;
		}
		| TCP_WORKERS EQUAL error { yyerror("number expected"); }
		| TCP_CONNECT_TIMEOUT EQUAL NUMBER { IFOR();
				tcp_connect_timeout=$3;
		}
		| TCP_CONNECT_TIMEOUT EQUAL error { yyerror("number expected"); }
		| TCP_CON_LIFETIME EQUAL NUMBER { IFOR();
				tcp_con_lifetime=$3;
		}
		| TCP_CON_LIFETIME EQUAL error { yyerror("number expected"); }
		| TCP_LISTEN_BACKLOG EQUAL NUMBER { IFOR();
				warn("tcp_listen_backlog is deprecated, use tcp_socket_backlog");
				tcp_socket_backlog=$3;
		}
		| TCP_LISTEN_BACKLOG EQUAL error { yyerror("number expected"); }
		| TCP_SOCKET_BACKLOG EQUAL NUMBER { IFOR();
				tcp_socket_backlog=$3;
		}
		| TCP_SOCKET_BACKLOG EQUAL error { yyerror("number expected"); }
		| TCP_MAX_CONNECTIONS EQUAL NUMBER { IFOR();
				tcp_max_connections=$3;
		}
		| TCP_MAX_CONNECTIONS EQUAL error { yyerror("number expected"); }
		| TCP_NO_NEW_CONN_BFLAG EQUAL ID { IFOR();
				tcp_no_new_conn_bflag =
					get_flag_id_by_name(FLAG_TYPE_BRANCH, $3, 0);
				if (!flag_in_range( (flag_t)tcp_no_new_conn_bflag ) )
					yyerror("invalid TCP no_new_conn Branch Flag");
				flag_idx2mask( &tcp_no_new_conn_bflag );
		}
		| TCP_NO_NEW_CONN_BFLAG EQUAL error { yyerror("number value expected"); }
		| TCP_NO_NEW_CONN_RPLFLAG EQUAL ID { IFOR();
				tcp_no_new_conn_rplflag =
					get_flag_id_by_name(FLAG_TYPE_MSG, $3, 0);
				if (!flag_in_range( (flag_t)tcp_no_new_conn_rplflag ) )
					yyerror("invalid TCP no_new_conn RePLy Flag");
				flag_idx2mask( &tcp_no_new_conn_rplflag );
		}
		| TCP_NO_NEW_CONN_RPLFLAG EQUAL error { yyerror("number value expected"); }

		| TCP_KEEPALIVE EQUAL NUMBER { IFOR();
				tcp_keepalive=$3;
		}
		| TCP_KEEPALIVE EQUAL error { yyerror("boolean value expected"); }
		| TCP_MAX_MSG_TIME EQUAL NUMBER { IFOR();
				tcp_max_msg_time=$3;
		}
		| TCP_MAX_MSG_TIME EQUAL error { yyerror("boolean value expected"); }
		| TCP_KEEPCOUNT EQUAL NUMBER 		{ IFOR();
			#ifndef HAVE_TCP_KEEPCNT
				warn("cannot be enabled TCP_KEEPCOUNT (no OS support)");
			#else
				tcp_keepcount=$3;
			#endif
		}
		| TCP_KEEPCOUNT EQUAL error { yyerror("int value expected"); }
		| TCP_KEEPIDLE EQUAL NUMBER 		{ IFOR();
			#ifndef HAVE_TCP_KEEPIDLE
				warn("cannot be enabled TCP_KEEPIDLE (no OS support)");
			#else
				tcp_keepidle=$3;
			#endif
		}
		| TCP_KEEPIDLE EQUAL error { yyerror("int value expected"); }
		| TCP_KEEPINTERVAL EQUAL NUMBER { IFOR();
			#ifndef HAVE_TCP_KEEPINTVL
				warn("cannot be enabled TCP_KEEPINTERVAL (no OS support)");
			#else
				tcp_keepinterval=$3;
			 #endif
		}
		| TCP_KEEPINTERVAL EQUAL error { yyerror("int value expected"); }
		| SERVER_SIGNATURE EQUAL NUMBER { IFOR();
							server_signature=$3; }
		| SERVER_SIGNATURE EQUAL error { yyerror("boolean value expected"); }
		| SERVER_HEADER EQUAL STRING { IFOR();
							server_header.s=$3;
							server_header.len=strlen($3);
							}
		| SERVER_HEADER EQUAL error { yyerror("string value expected"); }
		| USER_AGENT_HEADER EQUAL STRING { user_agent_header.s=$3;
									user_agent_header.len=strlen($3);
									}
		| USER_AGENT_HEADER EQUAL error { yyerror("string value expected"); }
		| PV_PRINT_BUF_SIZE EQUAL NUMBER { IFOR();
							pv_print_buf_size = $3; }
		| PV_PRINT_BUF_SIZE EQUAL error { yyerror("number expected"); }
		| XLOG_BUF_SIZE EQUAL NUMBER { IFOR();
							xlog_buf_size = $3; }
		| XLOG_FORCE_COLOR EQUAL NUMBER { IFOR();
							xlog_force_color = $3; }
		| XLOG_PRINT_LEVEL EQUAL NUMBER { IFOR();
							xlog_print_level = $3; }
		| XLOG_BUF_SIZE EQUAL error { yyerror("number expected"); }
		| XLOG_FORCE_COLOR EQUAL error { yyerror("boolean value expected"); }
		| XLOG_PRINT_LEVEL EQUAL error { yyerror("number expected"); }
		| XLOG_LEVEL EQUAL NUMBER { IFOR();
							*xlog_level = $3; }
		| XLOG_LEVEL EQUAL error { yyerror("number expected"); }
		| SOCKET EQUAL socket_def { IFOR();
							if (add_listening_socket($3)!=0){
								LM_CRIT("cfg. parser: failed"
										" to add listening socket\n");
								break;
							}
						}
		| SOCKET EQUAL  error { yyerror("ip address or hostname "
						"expected (use quotes if the hostname includes"
						" config keywords)"); }
		| LISTEN EQUAL socket_def { IFOR();
							warn("'listen' is deprecated, use 'socket' instead");
							if (add_listening_socket($3)!=0){
								LM_CRIT("cfg. parser: failed"
										" to add listen address\n");
								break;
							}
						}
		| LISTEN EQUAL  error { yyerror("ip address or hostname "
						"expected (use quotes if the hostname includes"
						" config keywords)"); }
		| MEMGROUP EQUAL STRING COLON multi_string { IFOR();
							/* convert STIRNG ($3) to an ID */
							/* update the memstats type for each module */
							#ifndef SHM_EXTRA_STATS
								LM_CRIT("SHM_EXTRA_STATS not defined");
								YYABORT;
							#else

							#ifdef SHM_SHOW_DEFAULT_GROUP
							if(strcmp($3, "default") == 0){
								LM_CRIT("default group  name is not allowed");
								YYABORT;
							}
							#endif

							for(tmp_mod = mod_names; tmp_mod; tmp_mod=tmp_mod->next){
								if(strcmp($3, tmp_mod->s) == 0){
									LM_CRIT("The same mem-group name is used twice: [%s] [%s]\n", $3, tmp_mod->s);
									YYABORT;
								}
							}

							tmp_mod = pkg_malloc(sizeof(struct multi_str));
							if(!tmp_mod){
								LM_CRIT("out of pkg memory");
								YYABORT;
							}

							tmp_mod->s = $3;
							tmp_mod->next = mod_names;
							mod_names = tmp_mod;
							for (tmp_mod = $5; tmp_mod; tmp_mod = tmp_mod->next){
								if(set_mem_idx(tmp_mod->s, mem_free_idx)){
									YYABORT;
								}
							}

							mem_free_idx++;	

							if(alloc_group_stat()){
								YYABORT;
							}
							#endif
						}
		| MEMGROUP EQUAL STRING COLON error { yyerror("invalid or no module specified"); }
		| ALIAS EQUAL  id_lst { IFOR();
							for(lst_tmp=$3; lst_tmp; lst_tmp=lst_tmp->next)
								add_alias(lst_tmp->name, strlen(lst_tmp->name),
											lst_tmp->port, lst_tmp->proto);
							  }
		| ALIAS  EQUAL error  { yyerror("hostname expected (use quotes"
							" if the hostname includes config keywords)"); }
		| AUTO_ALIASES EQUAL NUMBER { IFOR();
								auto_aliases=$3; }
		| AUTO_ALIASES EQUAL error  { yyerror("number  expected"); }
		| ADVERTISED_ADDRESS EQUAL listen_id { IFOR();
								if ($3) {
									default_global_address.s=$3;
									default_global_address.len=strlen($3);
								}
								}
		| ADVERTISED_ADDRESS EQUAL error {yyerror("ip address or hostname "
												"expected"); }
		| ADVERTISED_PORT EQUAL NUMBER { IFOR();
								tmp = int2str($3, &i_tmp);
								if (i_tmp > default_global_port.len)
									default_global_port.s =
									pkg_realloc(default_global_port.s, i_tmp);
								if (!default_global_port.s) {
									LM_CRIT("cfg. parser: out of memory.\n");
									YYABORT;
								} else {
									default_global_port.len = i_tmp;
									memcpy(default_global_port.s, tmp,
											default_global_port.len);
								}
								}
		|ADVERTISED_PORT EQUAL error {yyerror("ip address or hostname "
												"expected"); }
		| DISABLE_CORE EQUAL NUMBER { IFOR();
										disable_core_dump=$3;
									}
		| DISABLE_CORE EQUAL error { yyerror("boolean value expected"); }
		| OPEN_FD_LIMIT EQUAL NUMBER { IFOR();
										open_files_limit=$3;
									}
		| OPEN_FD_LIMIT EQUAL error { yyerror("number expected"); }
		| MCAST_LOOPBACK EQUAL NUMBER { IFOR();
								#ifdef USE_MCAST
										mcast_loopback=$3;
								#else
									warn("no multicast support compiled in");
								#endif
		  }
		| MCAST_LOOPBACK EQUAL error { yyerror("boolean value expected"); }
		| MCAST_TTL EQUAL NUMBER { IFOR();
								#ifdef USE_MCAST
										mcast_ttl=$3;
								#else
									warn("no multicast support compiled in");
								#endif
		  }
		| MCAST_TTL EQUAL error { yyerror("number expected as tos"); }
		| TOS EQUAL NUMBER { IFOR(); tos = $3;
							if (tos<=0)
								yyerror("invalid tos value");
		 }
		| TOS EQUAL ID { IFOR();
							if (strcasecmp($3,"IPTOS_LOWDELAY")) {
								tos=IPTOS_LOWDELAY;
							} else if (strcasecmp($3,"IPTOS_THROUGHPUT")) {
								tos=IPTOS_THROUGHPUT;
							} else if (strcasecmp($3,"IPTOS_RELIABILITY")) {
								tos=IPTOS_RELIABILITY;
#if defined(IPTOS_MINCOST)
							} else if (strcasecmp($3,"IPTOS_MINCOST")) {
								tos=IPTOS_MINCOST;
#endif
#if defined(IPTOS_LOWCOST)
							} else if (strcasecmp($3,"IPTOS_LOWCOST")) {
								tos=IPTOS_LOWCOST;
#endif
							} else {
								yyerror("invalid tos value - allowed: "
									"IPTOS_LOWDELAY,IPTOS_THROUGHPUT,"
									"IPTOS_RELIABILITY"
#if defined(IPTOS_LOWCOST)
									",IPTOS_LOWCOST"
#endif
#if defined(IPTOS_MINCOST)
									",IPTOS_MINCOST"
#endif
									"\n");
							}
		 }
		| TOS EQUAL error { yyerror("number expected"); }
		| MPATH EQUAL STRING {IFOR();
				set_mpath($3); }
		| MPATH EQUAL error  { yyerror("string value expected"); }
		| DISABLE_DNS_FAILOVER EQUAL NUMBER { IFOR();
										disable_dns_failover=$3;
									}
		| DISABLE_DNS_FAILOVER error { yyerror("boolean value expected"); }
		| DISABLE_DNS_BLACKLIST EQUAL NUMBER { IFOR();
										disable_dns_blacklist=$3;
									}
		| DISABLE_DNS_BLACKLIST error { yyerror("boolean value expected"); }
		| DST_BLACKLIST EQUAL ID COLON LBRACE blst_elem_list RBRACE { IFOR();
				s_tmp.s = $3;
				s_tmp.len = strlen($3);
				if (create_bl_head( BL_CORE_ID, BL_READONLY_LIST,
				    bl_head, bl_tail, &s_tmp)==0) {
					yyerror("failed to create blacklist\n");
					YYABORT;
				}
				bl_head = bl_tail = NULL;
				}
		| DISABLE_STATELESS_FWD EQUAL NUMBER { IFOR();
				sl_fwd_disabled=$3; }
		| DB_VERSION_TABLE EQUAL STRING { IFOR();
				db_version_table=$3; }
		| DB_VERSION_TABLE EQUAL error { yyerror("string value expected"); }
		| DB_DEFAULT_URL EQUAL STRING { IFOR();
				db_default_url=$3; }
		| DB_DEFAULT_URL EQUAL error { yyerror("string value expected"); }
		| DB_MAX_ASYNC_CONNECTIONS EQUAL NUMBER { IFOR();
				db_max_async_connections=$3; }
		| DB_MAX_ASYNC_CONNECTIONS EQUAL error {
				yyerror("integer value expected");
				}
		| DISABLE_503_TRANSLATION EQUAL NUMBER { IFOR();
				disable_503_translation=$3; }
		| DISABLE_503_TRANSLATION EQUAL error {
				yyerror("integer value expected");
				}
		| AUTO_SCALING_PROFILE EQUAL auto_scale_profile_def {}
		| AUTO_SCALING_PROFILE EQUAL error {
				yyerror("bad auto-scaling profile definition");
				}
		| AUTO_SCALING_CYCLE EQUAL NUMBER { IFOR();
				auto_scaling_cycle=$3; }
		| AUTO_SCALING_CYCLE EQUAL error {
				yyerror("integer value expected");
				}
		| error EQUAL { yyerror("unknown config variable"); }
	;

module_stm:	LOADMODULE STRING	{ IFOR();
			if (load_module($2) < 0)
				yyerrorf("failed to load module %s\n", $2);
		}
		| LOADMODULE error	{ yyerror("string expected");  }
		| MODPARAM LPAREN STRING COMMA STRING COMMA STRING RPAREN { IFOR();
				if (set_mod_param_regex($3, $5, STR_PARAM, $7) != 0) {
					yyerrorf("Parameter <%s> not found in module <%s> - "
						"can't set", $5, $3);
				}
			}
		| MODPARAM LPAREN STRING COMMA STRING COMMA snumber RPAREN { IFOR();
				if (set_mod_param_regex($3, $5, INT_PARAM, (void*)$7) != 0) {
					yyerrorf("Parameter <%s> not found in module <%s> - "
						"can't set", $5, $3);
				}
			}
		| MODPARAM error { yyerror("Invalid arguments"); }
		;


ip:		 ipv4  { $$=$1; }
		|ipv6  { $$=$1; }
		;

ipv4:	IPV4ADDR {
					$$=pkg_malloc(sizeof(struct ip_addr));
					if ($$==0){
						LM_CRIT("ERROR: cfg. parser: out of memory.\n");
						YYABORT;
					}else{
						memset($$, 0, sizeof(struct ip_addr));
						$$->af=AF_INET;
						$$->len=16;
						if (inet_pton(AF_INET, $1, $$->u.addr)<=0){
							yyerror("bad ipv4 address");
						}
					}
				}
	;

ipv6addr:	IPV6ADDR {
					$$=pkg_malloc(sizeof(struct ip_addr));
					if ($$==0){
						LM_CRIT("ERROR: cfg. parser: out of memory.\n");
						YYABORT;
					}else{
						memset($$, 0, sizeof(struct ip_addr));
						$$->af=AF_INET6;
						$$->len=16;
						if (inet_pton(AF_INET6, $1, $$->u.addr)<=0){
							yyerror("bad ipv6 address");
						}
					}
				}
	;

ipv6:	ipv6addr { $$=$1; }
	| LBRACK ipv6addr RBRACK {$$=$2; }
;

ipnet:	IPNET	{
				if (parse_ipnet($1, strlen($1), &net_tmp) < 0)
					yyerror("unable to parse ip and/or netmask\n");

				$$ = net_tmp;
			}
		| ip	{
				$$=mk_net_bitlen($1, $1->len*8);
				pkg_free($1);
			}
		;





folded_string:	STRING STRING {
				$$ = pkg_malloc( strlen($1) + strlen($2) + 1);
				if ($$==0){
					yyerror("cfg. parser: out of memory");
					YYABORT;
				} else {
					strcpy($$,$1); strcat($$,$2);
					pkg_free($1); pkg_free($2);
				}
			}
		| folded_string STRING {
				$$ = pkg_malloc( strlen($1) + strlen($2) + 1);
				if ($$==0){
					LM_CRIT("ERROR: cfg. parser: out of memory.\n");
					YYABORT;
				} else {
					strcpy($$,$1); strcat($$,$2);
					pkg_free($1); pkg_free($2);
				}
			}

route_name:  ID {
				$$ = $1;
				}
		| NUMBER {
				tmp=int2str($1, &i_tmp);
				if (($$=pkg_malloc(i_tmp+1))==0) {
					yyerror("cfg. parser: out of memory.\n");
					YYABORT;
				}
				memcpy( $$, tmp, i_tmp);
				$$[i_tmp] = 0;
				}
		|STRING {
				$$ = $1;
		}
;

route_name_var: route_name {
				/* check to see if there are any "$" in the string name */
				tmp = strchr($1, '$');
				if (!tmp) {
					/* route name is a cosntant string - search for the route */
					rn_tmp.data = 0;
					rn_tmp.iname = get_script_route_idx($1, sroutes->request,
							RT_NO, 0);
					if (rn_tmp.iname==-1)
						yyerror("too many script routes");
					$$ = NUMBER_ST;
				} else {
					tstr.s = $1;
					tstr.len = strlen(tstr.s);
					if (pv_parse_format(&tstr, &elem) < 0) {
						yyerror("cannot parse format");
						YYABORT;
					}
					/* the route name is a format, so we can't evaluate it now */
					rn_tmp.ename = elem;
					$$ = SCRIPTVAR_ELEM_ST;
				}
			}
		| script_var {
				rn_tmp.sname = $1;
				$$ = SCRIPTVAR_ST;
		}

route_stm:  ROUTE LBRACE actions RBRACE {
						if (sroutes->request[DEFAULT_RT].a!=0) {
							yyerror("overwriting default "
								"request routing table");
							YYABORT;
						}
						push($3, &sroutes->request[DEFAULT_RT].a);
					}
		| ROUTE LBRACK route_name RBRACK LBRACE actions RBRACE {
						if ( strtol($3,&tmp,10)==0 && *tmp==0) {
							/* route[0] detected */
							if (sroutes->request[DEFAULT_RT].a!=0) {
								yyerror("overwriting(2) default "
									"request routing table");
								YYABORT;
							}
							push($6, &sroutes->request[DEFAULT_RT].a);
						} else {
							i_tmp = get_script_route_idx( $3,
								sroutes->request, RT_NO,1);
							if (i_tmp==-1) YYABORT;
							push($6, &sroutes->request[i_tmp].a);
						}
					}
		| ROUTE error { yyerror("invalid  route  statement"); }
	;

failure_route_stm: ROUTE_FAILURE LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx( $3, sroutes->failure,
							FAILURE_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &sroutes->failure[i_tmp].a);
					}
		| ROUTE_FAILURE error { yyerror("invalid failure_route statement"); }
	;

onreply_route_stm: ROUTE_ONREPLY LBRACE actions RBRACE {
						if (sroutes->onreply[DEFAULT_RT].a!=0) {
							yyerror("overwriting default "
								"onreply routing table");
							YYABORT;
						}
						push($3, &sroutes->onreply[DEFAULT_RT].a);
					}
		| ROUTE_ONREPLY LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx( $3, sroutes->onreply,
							ONREPLY_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &sroutes->onreply[i_tmp].a);
					}
		| ROUTE_ONREPLY error { yyerror("invalid onreply_route statement"); }
	;

branch_route_stm: ROUTE_BRANCH LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx( $3, sroutes->branch,
							BRANCH_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &sroutes->branch[i_tmp].a);
					}
		| ROUTE_BRANCH error { yyerror("invalid branch_route statement"); }
	;

error_route_stm:  ROUTE_ERROR LBRACE actions RBRACE {
						if (sroutes->error.a!=0) {
							yyerror("overwriting default "
								"error routing table");
							YYABORT;
						}
						push($3, &sroutes->error.a);
					}
		| ROUTE_ERROR error { yyerror("invalid error_route statement"); }
	;

local_route_stm:  ROUTE_LOCAL LBRACE actions RBRACE {
						if (sroutes->local.a!=0) {
							yyerror("re-definition of local "
								"route detected");
							YYABORT;
						}
						push($3, &sroutes->local.a);
					}
		| ROUTE_LOCAL error { yyerror("invalid local_route statement"); }
	;

startup_route_stm:  ROUTE_STARTUP LBRACE actions RBRACE {
						if (sroutes->startup.a!=0) {
							yyerror("re-definition of startup "
								"route detected");
							YYABORT;
						}
						push($3, &sroutes->startup.a);
					}
		| ROUTE_STARTUP error { yyerror("invalid startup_route statement"); }
	;

timer_route_stm:  ROUTE_TIMER LBRACK route_name COMMA NUMBER RBRACK LBRACE actions RBRACE {
						i_tmp = 0;
						while(sroutes->timer[i_tmp].a!=0 && i_tmp<TIMER_RT_NO){
							i_tmp++;
						}
						if(i_tmp == TIMER_RT_NO) {
							yyerror("Too many timer routes defined\n");
							YYABORT;
						}
						sroutes->timer[i_tmp].interval = $5;
						push($8, &sroutes->timer[i_tmp].a);
					}
		| ROUTE_TIMER error { yyerror("invalid timer_route statement"); }
	;

event_route_stm: ROUTE_EVENT LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx($3, sroutes->event,
								EVENT_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &sroutes->event[i_tmp].a);
					}
		| ROUTE_EVENT error { yyerror("invalid event_route statement"); }
	;



exp:	exp AND exp 	{ $$=mk_exp(AND_OP, $1, $3); }
	| exp OR  exp		{ $$=mk_exp(OR_OP, $1, $3);  }
	| NOT exp 			{ $$=mk_exp(NOT_OP, $2, 0);  }
	| LPAREN exp RPAREN	{ $$=mk_exp(EVAL_OP, $2, 0); }
	| LBRACK assignexp RBRACK { $$=$2; }
	| exp_elem			{ $$=$1; }
	;

equalop:	  EQUAL_T {$$=EQUAL_OP; }
			| DIFF	{$$=DIFF_OP; }
		;

compop:	GT	{$$=GT_OP; }
		| LT	{$$=LT_OP; }
		| GTE	{$$=GTE_OP; }
		| LTE	{$$=LTE_OP; }
	;
matchop: MATCH	{$$=MATCH_OP; }
		| NOTMATCH	{$$=NOTMATCH_OP; }
	;

intop:	equalop	{$$=$1; }
	 | compop	{$$=$1; }
	;

strop:	equalop	{$$=$1; }
	    | compop {$$=$1; }
		| matchop	{$$=$1; }
	;

script_var:	SCRIPTVAR	{
				spec = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
				if (spec==NULL){
					yyerror("no more pkg memory\n");
					YYABORT;
				}
				memset(spec, 0, sizeof(pv_spec_t));
				tstr.s = $1;
				tstr.len = strlen(tstr.s);
				if(pv_parse_spec(&tstr, spec)==NULL)
				{
					yyerror("unknown script variable");
				}

				$$ = spec;
			}
		| SCRIPTVARERR {
			$$=0; yyerror("invalid script variable name");
		}
		;

exp_elem: exp_cond		{$$=$1; }
		| exp_stm		{$$=mk_elem( NO_OP, ACTION_O, 0, ACTIONS_ST, $1 ); }
		| snumber		{$$=mk_elem( NO_OP, NUMBER_O, 0, NUMBER_ST,
											(void*)$1 ); }
		| script_var    {
				$$=mk_elem(NO_OP, SCRIPTVAR_O,0,SCRIPTVAR_ST,(void*)$1);
			}
	;

exp_cond: script_var strop script_var {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,SCRIPTVAR_ST,(void*)$3);
			}
		| script_var strop STRING {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,STR_ST,$3);
			}
		| script_var intop snumber {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,NUMBER_ST,(void *)$3);
			}
		| script_var equalop NULLV	{
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1, NULLV_ST, 0);
			}
		| script_var equalop ipnet {
				$$=mk_elem($2, SCRIPTVAR_O, (void*)$1, NET_ST, $3);
			}
	;

assignop:
	EQUAL { $$ = EQ_T; }
	| COLONEQ { $$ = COLONEQ_T; }
	| PLUSEQ { $$ = PLUSEQ_T; }
	| MINUSEQ { $$ = MINUSEQ_T;}
	| SLASHEQ { $$ = DIVEQ_T; }
	| MULTEQ { $$ = MULTEQ_T; }
	| MODULOEQ { $$ = MODULOEQ_T; }
	| BANDEQ { $$ = BANDEQ_T; }
	| BOREQ { $$ = BOREQ_T; }
	| BXOREQ { $$ = BXOREQ_T; }
	;

assignexp :
	snumber { $$ = mk_elem(VALUE_OP, NUMBERV_O, (void*)$1, 0, 0); }
	| STRING { $$ = mk_elem(VALUE_OP, STRINGV_O, $1, 0, 0); }
	| script_var { $$ = mk_elem(VALUE_OP, SCRIPTVAR_O, $1, 0, 0); }
	| exp_cond { $$= $1; }
	| cmd { $$=mk_elem( NO_OP, ACTION_O, 0, ACTIONS_ST, $1 ); }
	| assignexp PLUS assignexp {
				$$ = mk_elem(PLUS_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp MINUS assignexp {
				$$ = mk_elem(MINUS_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp MULT assignexp {
				$$ = mk_elem(MULT_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp SLASH assignexp {
				$$ = mk_elem(DIV_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp MODULO assignexp {
				$$ = mk_elem(MODULO_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp BAND assignexp {
				$$ = mk_elem(BAND_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp BOR assignexp {
				$$ = mk_elem(BOR_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp BXOR assignexp {
				$$ = mk_elem(BXOR_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp BLSHIFT assignexp {
				$$ = mk_elem(BLSHIFT_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| assignexp BRSHIFT assignexp {
				$$ = mk_elem(BRSHIFT_OP, EXPR_O, $1, EXPR_ST, $3);
			}
	| BNOT assignexp {
				$$ = mk_elem(BNOT_OP, EXPR_O, $2, 0, 0);
			}
	| LPAREN assignexp RPAREN { $$ = $2; }
	;

assign_cmd: script_var assignop assignexp {
			if(!pv_is_w($1))
				yyerror("invalid left operand in assignment");
			if($1->trans!=0)
				yyerror("transformations not accepted in left side "
					"of assignment");

			mk_action2( $$, $2,
					SCRIPTVAR_ST,
					EXPR_ST,
					$1,
					$3);
		}
	|  script_var EQUAL NULLV {
			if(!pv_is_w($1))
				yyerror("invalid left operand in assignment");
			if($1->trans!=0)
				yyerror("transformations not accepted in left side "
					"of assignment");

			mk_action2( $$, EQ_T,
					SCRIPTVAR_ST,
					NULLV_ST,
					$1,
					0);
		}
	|  script_var COLONEQ NULLV {
			if(!pv_is_w($1))
				yyerror("invalid left operand in assignment");
			/* not all can get NULL with := */
			switch($1->type) {
				case PVT_AVP:
				break;
				default:
					yyerror("invalid left operand in NULL assignment");
			}
			if($1->trans!=0)
				yyerror("transformations not accepted in left side "
					"of assignment");

			mk_action2( $$, COLONEQ_T,
					SCRIPTVAR_ST,
					NULLV_ST,
					$1,
					0);
		}
	;

exp_stm:	cmd						{ $$=$1; }
		|	if_cmd					{ $$=$1; }
		|	assign_cmd				{ $$=$1; }
		|	LBRACE actions RBRACE	{ $$=$2; }
		|	LBRACE RBRACE			{ $$=0; }
	;

brk_stm:	brk_action					{ $$=$1; }
		|	LBRACE brk_actions RBRACE	{ $$=$2; }
		|	LBRACE RBRACE			{ $$=0; }
	;

stm:		action					{ $$=$1; }
		|	LBRACE actions RBRACE	{ $$=$2; }
		|	LBRACE RBRACE			{ $$=0; }
	;

actions:	actions action	{$$=append_action($1, $2); }
		| action			{$$=$1;}
		| actions error { $$=0; yyerror("bad command!)"); }
	;

/* breakable actions, within a switch / while / for-each */
brk_actions:	brk_actions brk_action	{$$=append_action($1, $2); }
		| brk_action			{$$=$1;}
		| brk_actions error { $$=0; yyerror("bad command!)"); }
	;

action:		cmd SEMICOLON {$$=$1;}
		| if_cmd {$$=$1;}
		| while_cmd {$$=$1;}
		| foreach_cmd {$$=$1;}
		| switch_cmd {$$=$1;}
		| assign_cmd SEMICOLON {$$=$1;}
		| SEMICOLON /* null action */ {$$=0;}
		| cmd error { $$=0; yyerror("bad command: missing ';'?"); }
	;

brk_action: BREAK SEMICOLON { mk_action0($$, BREAK_T);}
		| cmd SEMICOLON {$$=$1;}
		| brk_if_cmd {$$=$1;}
		| while_cmd {$$=$1;}
		| foreach_cmd {$$=$1;}
		| switch_cmd {$$=$1;}
		| assign_cmd SEMICOLON {$$=$1;}
		| SEMICOLON /* null action */ {$$=0;}
		| cmd error { $$=0; yyerror("bad command: missing ';'?"); }
	;

brk_if_cmd:		IF LPAREN exp RPAREN brk_stm		{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 NOSUBTYPE,
													 $3,
													 $5,
													 0);
									}
		| IF LPAREN exp RPAREN brk_stm ELSE brk_stm		{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 ACTIONS_ST,
													 $3,
													 $5,
													 $7);
									}
	;

if_cmd:		IF LPAREN exp RPAREN stm				{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 NOSUBTYPE,
													 $3,
													 $5,
													 0);
									}
		| IF LPAREN exp RPAREN stm ELSE stm		{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 ACTIONS_ST,
													 $3,
													 $5,
													 $7);
									}
	;

while_cmd:		WHILE LPAREN exp RPAREN brk_stm	{ mk_action2( $$, WHILE_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 $3,
													 $5);
									}
	;

foreach_cmd:	FOR LPAREN script_var IN script_var RPAREN brk_stm {
					if ($3->type != PVT_SCRIPTVAR &&
					    $3->type != PVT_AVP &&
						pv_type($3->type) != PVT_JSON) {
						yyerror("\nfor-each statement: only \"var\", \"avp\" "
					            "and \"json\" iterators are supported!");
					}

					mk_action3( $$, FOR_EACH_T,
					            SCRIPTVAR_ST,
					            SCRIPTVAR_ST,
					            ACTIONS_ST,
					            $3,
					            $5,
					            $7);
					}
	;

switch_cmd:		SWITCH LPAREN script_var RPAREN LBRACE switch_stm RBRACE	{
											mk_action2( $$, SWITCH_T,
														SCRIPTVAR_ST,
														ACTIONS_ST,
														$3,
														$6);
									}
	;

switch_stm: case_stms default_stm { $$=append_action($1, $2); }
		|	case_stms		{ $$=$1; }
	;
case_stms:	case_stms case_stm	{$$=append_action($1, $2); }
		| case_stm			{$$=$1;}
	;

case_stm: CASE snumber COLON brk_actions { mk_action2( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													(void*)$2,
													$4);
											}
		| CASE snumber COLON { mk_action2( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													(void*)$2,
													NULL);
							}
		| CASE STRING COLON brk_actions { mk_action2( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													(void*)$2,
													$4);
											}
		| CASE STRING COLON { mk_action2( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													(void*)$2,
													NULL);
							}
	;

default_stm: DEFAULT COLON brk_actions { mk_action1( $$, DEFAULT_T,
													ACTIONS_ST, $3);
									}
		| DEFAULT COLON { mk_action1( $$, DEFAULT_T, ACTIONS_ST, NULL); }
	;

func_param: STRING {
										elems[1].type = STR_ST;
										elems[1].u.data = $1;
										$$=1;
										}
		| func_param COMMA STRING {
										if ($1+1>=MAX_ACTION_ELEMS) {
											yyerror("too many arguments "
												"in function\n");
											$$=0;
										}
										elems[$1+1].type = STR_ST;
										elems[$1+1].u.data = $3;
										$$=$1+1;
										}
		| COMMA {
										elems[1].type = NULLV_ST;
										elems[1].u.data = NULL;
										elems[2].type = NULLV_ST;
										elems[2].u.data = NULL;
										$$=2;
										}
		| COMMA STRING {
										elems[1].type = NULLV_ST;
										elems[1].u.data = NULL;
										elems[2].type = STR_ST;
										elems[2].u.data = $2;
										$$=2;
										}
		| func_param COMMA {
										if ($1+1>=MAX_ACTION_ELEMS) {
											yyerror("too many arguments "
												"in function\n");
											$$=0;
										}
										elems[$1+1].type = NULLV_ST;
										elems[$1+1].u.data = NULL;
										$$=$1+1;
										}
		| snumber {
										elems[1].type = NUMBER_ST;
										elems[1].u.number = $1;
										$$=1;
										}
		| COMMA snumber {
										elems[1].type = NULLV_ST;
										elems[1].u.data = NULL;
										elems[2].type = NUMBER_ST;
										elems[2].u.number = $2;
										$$=2;
										}
		| func_param COMMA snumber {
										if ($1+1>=MAX_ACTION_ELEMS) {
											yyerror("too many arguments "
												"in function\n");
											$$=0;
										}
										elems[$1+1].type = NUMBER_ST;
										elems[$1+1].u.number = $3;
										$$=$1+1;
										}
		| script_var {
										elems[1].type = SCRIPTVAR_ST;
										elems[1].u.data = $1;
										$$=1;
										}
		| COMMA script_var {
										elems[1].type = NULLV_ST;
										elems[1].u.data = NULL;
										elems[2].type = SCRIPTVAR_ST;
										elems[2].u.data = $2;
										$$=2;
										}
		| func_param COMMA script_var {
										if ($1+1>=MAX_ACTION_ELEMS) {
											yyerror("too many arguments "
												"in function\n");
											$$=0;
										}
										elems[$1+1].type = SCRIPTVAR_ST;
										elems[$1+1].u.data = $3;
										$$=$1+1;
										}
	;

route_param: STRING {
						route_elems[0].type = STRING_ST;
						route_elems[0].u.string = $1;
						$$=1;
			}
		| snumber {
						route_elems[0].type = NUMBER_ST;
						route_elems[0].u.number = (long)$1;
						$$=1;
			}
		| NULLV {
						route_elems[0].type = NULLV_ST;
						route_elems[0].u.data = 0;
						$$=1;
			}
		| script_var {
						route_elems[0].type = SCRIPTVAR_ST;
						route_elems[0].u.data = $1;
						$$=1;
			}
		| route_param COMMA STRING {
						if ($1>=MAX_ACTION_ELEMS) {
							yyerror("too many arguments in function\n");
							$$=-1;
						} else {
							route_elems[$1].type = STRING_ST;
							route_elems[$1].u.data = $3;
							$$=$1+1;
						}
			}
		| route_param COMMA snumber {
						if ($1>=MAX_ACTION_ELEMS) {
							yyerror("too many arguments in function\n");
							$$=-1;
						} else {
							route_elems[$1].type = NUMBER_ST;
							route_elems[$1].u.data = (void*)(long)$3;
							$$=$1+1;
						}
			}
		| route_param COMMA script_var {
						if ($1+1>=MAX_ACTION_ELEMS) {
							yyerror("too many arguments in function\n");
							$$=-1;
						} else {
							route_elems[$1].type = SCRIPTVAR_ST;
							route_elems[$1].u.data = $3;
							$$=$1+1;
						}
			}
		| route_param COMMA NULLV {
						if ($1+1>=MAX_ACTION_ELEMS) {
							yyerror("too many arguments in function\n");
							$$=-1;
						} else {
							route_elems[$1].type = NULLV_ST;
							route_elems[$1].u.data = 0;
							$$=$1+1;
						}
			}
	;

async_func: ID LPAREN RPAREN {
				cmd_tmp=(void*)find_mod_acmd_export_t($1);
				if (cmd_tmp==0){
					yyerrorf("unknown async command <%s>, "
						"missing loadmodule?", $1);
					$$=0;
				}else{
					if (check_acmd_call_params(cmd_tmp,elems,0)<0) {
						yyerrorf("too few parameters "
							"for command <%s>\n", $1);
						$$=0;
					} else {
						elems[0].type = ACMD_ST;
						elems[0].u.data = cmd_tmp;
						mk_action_($$, AMODULE_T, 1, elems);
					}
				}
			}
			| ID LPAREN func_param RPAREN {
				cmd_tmp=(void*)find_mod_acmd_export_t($1);
				if (cmd_tmp==0){
					yyerrorf("unknown async command <%s>, "
						"missing loadmodule?", $1);
					$$=0;
				}else{
					rc = check_acmd_call_params(cmd_tmp,elems,$3);
					switch (rc) {
					case -1:
						yyerrorf("too few parameters "
							"for async command <%s>\n", $1);
						$$=0;
						break;
					case -2:
						yyerrorf("too many parameters "
							"for async command <%s>\n", $1);
						$$=0;
						break;
					case -3:
						yyerrorf("mandatory parameter "
							" omitted for async command <%s>\n", $1);
						$$=0;
						break;
					default:
						elems[0].type = ACMD_ST;
						elems[0].u.data = cmd_tmp;
						mk_action_($$, AMODULE_T, $3+1, elems);
					}
				}
			}
			| ID LPAREN error RPAREN {
				$$=0;
				yyerrorf("bad arguments for command <%s>", $1);
			}
			| ID error {
				$$=0;
				yyerrorf("bare word <%s> found, command calls need '()'", $1);
			}
	;

cmd:	 ASSERT LPAREN exp COMMA STRING RPAREN	 {
			mk_action2( $$, ASSERT_T, EXPR_ST, STRING_ST, $3, $5);
			}
		| DROP				 {mk_action0( $$, DROP_T); }
		| DROP LPAREN RPAREN {mk_action0( $$, DROP_T); }
		| EXIT				 {mk_action0( $$, EXIT_T); }
		| EXIT LPAREN RPAREN {mk_action0( $$, EXIT_T); }
		| RETURN script_var
							 {mk_action1( $$, RETURN_T, SCRIPTVAR_ST, (void*)$2); }
		| RETURN LPAREN script_var RPAREN
							 {mk_action1( $$, RETURN_T, SCRIPTVAR_ST, (void*)$3); }
		| RETURN snumber
							 {mk_action1( $$, RETURN_T, NUMBER_ST, (void*)$2); }
		| RETURN LPAREN snumber	RPAREN
							 {mk_action1( $$, RETURN_T, NUMBER_ST, (void*)$3); }
		| RETURN LPAREN RPAREN
							 {mk_action1( $$, RETURN_T, NUMBER_ST, (void*)1); }
		| RETURN			 {mk_action1( $$, RETURN_T, NUMBER_ST, (void*)1); }
		| LOG_TOK LPAREN STRING RPAREN	{mk_action2( $$, LOG_T, NUMBER_ST,
													STRING_ST,(void*)4,$3);
									}
		| LOG_TOK LPAREN snumber COMMA STRING RPAREN	{mk_action2( $$, LOG_T,
																NUMBER_ST,
																STRING_ST,
																(void*)$3,
																$5);
												}
		| LOG_TOK error { $$=0; yyerror("missing '(' or ')' ?"); }
		| LOG_TOK LPAREN error RPAREN { $$=0; yyerror("bad log"
									"argument"); }
		| ERROR LPAREN STRING COMMA STRING RPAREN {mk_action2( $$, ERROR_T,
																STRING_ST,
																STRING_ST,
																$3,
																$5);
												  }
		| ERROR error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ERROR LPAREN error RPAREN { $$=0; yyerror("bad error"
														"argument"); }
		| ROUTE LPAREN route_name_var RPAREN	{
						mk_action2( $$, ROUTE_T, $3, 0, rn_tmp.data, 0);
					}

		| ROUTE LPAREN route_name_var COMMA route_param RPAREN	{
						if ($5 <= 0) yyerror("too many route parameters");

						/* duplicate the list */
						a_tmp = pkg_malloc($5 * sizeof(action_elem_t));
						if (!a_tmp) {
							yyerror("no more pkg memory");
							YYABORT;
						}
						memcpy(a_tmp, route_elems, $5*sizeof(action_elem_t));

						mk_action3( $$, ROUTE_T, $3,	/* route idx */
							NUMBER_ST,					/* number of params */
							SCRIPTVAR_ST,				/* parameters */
							rn_tmp.data,
							(void*)(long)$5,
							(void*)a_tmp);
					}

		| ROUTE error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ROUTE LPAREN error RPAREN { $$=0; yyerror("bad route"
						"argument"); }
		| ID LPAREN RPAREN	{
								cmd_tmp=(void*)find_cmd_export_t($1, rt);
								if (cmd_tmp==0){
									if (find_cmd_export_t($1, 0)) {
										yyerrorf("Command <%s> cannot be "
											"used in the block\n", $1);
									} else {
										yyerrorf("unknown command <%s>, "
											"missing loadmodule?", $1);
									}
									$$=0;
								}else{
									if (check_cmd_call_params(cmd_tmp,elems,0)<0) {
										yyerrorf("too few parameters "
											"for command <%s>\n", $1);
										$$=0;
									} else {
										elems[0].type = CMD_ST;
										elems[0].u.data = cmd_tmp;
										mk_action_($$, CMD_T, 1, elems);
									}
								}
							}
		| ID LPAREN func_param RPAREN	{
								cmd_tmp=(void*)find_cmd_export_t($1, rt);
								if (cmd_tmp==0){
									if (find_cmd_export_t($1, 0)) {
										yyerrorf("Command <%s> cannot be "
											"used in the block\n", $1);
									} else {
										yyerrorf("unknown command <%s>, "
											"missing loadmodule?", $1);
									}
									$$=0;
								}else{
									rc = check_cmd_call_params(cmd_tmp,elems,$3);
									switch (rc) {
									case -1:
										yyerrorf("too few parameters "
											"for command <%s>\n", $1);
										$$=0;
										break;
									case -2:
										yyerrorf("too many parameters "
											"for command <%s>\n", $1);
										$$=0;
										break;
									case -3:
										yyerrorf("mandatory parameter "
											"omitted for command <%s>\n", $1);
										$$=0;
										break;
									default:
										elems[0].type = CMD_ST;
										elems[0].u.data = cmd_tmp;
										mk_action_($$, CMD_T, $3+1, elems);
									}
								}
							}
		| ID LPAREN error RPAREN { $$=0; yyerrorf("bad arguments for "
												"command <%s>", $1); }
		| ID error { $$=0;
			yyerrorf("bare word <%s> found, command calls need '()'", $1);
			}
		| XDBG LPAREN STRING RPAREN {
				mk_action1($$, XDBG_T, STR_ST, $3);	}
		| XDBG LPAREN folded_string RPAREN {
				mk_action1($$, XDBG_T, STR_ST, $3);	}
		| XLOG LPAREN STRING RPAREN {
				mk_action1($$, XLOG_T, STR_ST, $3); }
		| XLOG LPAREN folded_string RPAREN {
				mk_action1($$, XLOG_T, STR_ST, $3); }
		| XLOG LPAREN STRING COMMA STRING RPAREN {
				mk_action2($$, XLOG_T, STR_ST, STR_ST, $3, $5); }
		| XLOG LPAREN STRING COMMA folded_string RPAREN {
				mk_action2($$, XLOG_T, STR_ST, STR_ST, $3, $5); }
		| ASYNC_TOKEN LPAREN async_func COMMA route_name RPAREN {
				i_tmp = get_script_route_idx( $5, sroutes->request, RT_NO, 0);
				if (i_tmp==-1) yyerror("too many script routes");
				mk_action2($$, ASYNC_T, ACTIONS_ST, NUMBER_ST,
						$3, (void*)(long)i_tmp);
				}
		| ASYNC_TOKEN LPAREN async_func COMMA route_name COMMA NUMBER RPAREN {
				i_tmp = get_script_route_idx( $5, sroutes->request, RT_NO, 0);
				if (i_tmp==-1) yyerror("too many script routes");
				mk_action3($$, ASYNC_T, ACTIONS_ST, NUMBER_ST, NUMBER_ST,
						$3, (void*)(long)i_tmp, (void*)(long)$7);
				}
		| LAUNCH_TOKEN LPAREN async_func COMMA route_name RPAREN {
				i_tmp = get_script_route_idx( $5, sroutes->request, RT_NO, 0);
				if (i_tmp==-1) yyerror("too many script routes");
				mk_action2($$, LAUNCH_T, ACTIONS_ST, NUMBER_ST,
						$3, (void*)(long)i_tmp);
				}
		| LAUNCH_TOKEN LPAREN async_func RPAREN {
				mk_action2($$, LAUNCH_T, ACTIONS_ST, NUMBER_ST,
						$3, (void*)(long)-1);
				}
	;


%%

static inline void ALLOW_UNUSED warn(char* s)
{
	LM_WARN("warning in config file %s, line %d, column %d-%d: %s\n",
			get_cfg_file_name, line, startcolumn, column, s);
}

static void yyerror(char* s)
{
	cfg_dump_backtrace();
	LM_CRIT("parse error in %s:%d:%d-%d: %s\n",
			get_cfg_file_name, line, startcolumn, column, s);
	_cfg_dump_context(get_cfg_file_name, line, startcolumn, column, 1);
	cfg_errors++;
}

#define ERROR_MAXLEN 1024
static void yyerrorf(char *fmt, ...)
{
	char *tmp = pkg_malloc(ERROR_MAXLEN);
	va_list ap;
	va_start(ap, fmt);

	vsnprintf(tmp, ERROR_MAXLEN, fmt, ap);
	yyerror(tmp);

	pkg_free(tmp);
	va_end(ap);
}


static struct socket_id* mk_listen_id(char* host, enum sip_protos proto,
																	int port)
{
	struct socket_id* l;
	l=pkg_malloc(sizeof(struct socket_id));
	if (l==0){
		LM_CRIT("cfg. parser: out of memory.\n");
	}else{
		memset(l, 0, sizeof(*l));
		l->name     = host;
		l->proto    = proto;
		l->port     = port;
	}

	return l;
}

static void fill_socket_id(struct listen_param *param, struct socket_id *s)
{
	s->flags |= param->flags;
	s->workers = param->workers;
	s->auto_scaling_profile = param->auto_scaling_profile;
	if (param->socket)
		set_listen_id_adv(s, param->socket->name, param->socket->port);
	s->tag = param->tag;
}

static struct multi_str *new_string(char *s)
{
	struct multi_str *ms = pkg_malloc(sizeof(struct multi_str));
	if (!ms) {
		LM_CRIT("cfg. parser: out of memory.\n");
	}else{
		ms->s    = s;
		ms->next = NULL;
	}
	return ms;
}

static struct socket_id* set_listen_id_adv(struct socket_id* sock,
											char *adv_name,
											int adv_port)
{
	sock->adv_name=adv_name;
	sock->adv_port=adv_port;
	return sock;
}

static int parse_ipnet(char *in, int len, struct net **ipnet)
{
	char *p = NULL;
	str ip_s, mask_s;
	struct ip_addr *ip = NULL, *mask = NULL, *ip_tmp;
	int af;
	unsigned int bitlen;

	p = q_memchr(in, '.', len);
	if (p)
		af = AF_INET;
	else if (q_memchr(in, ':', len)) {
		af = AF_INET6;
	} else {
		LM_ERR("Not an IP");
		return -1;
	}

	p = q_memchr(in, '/', len);
	if (!p) {
		LM_ERR("No netmask\n");
		return -1;
	}
	ip_s.s = in;
	ip_s.len = p - in;

	mask_s.s = p + 1;
	mask_s.len = len - ip_s.len - 1;
	if (!mask_s.s || mask_s.len == 0) {
		LM_ERR("Empty netmask\n");
		return -1;
	}

	ip_tmp = (af == AF_INET) ? str2ip(&ip_s) : str2ip6(&ip_s);
	if (!ip_tmp) {
		LM_ERR("Invalid IP\n");
		return -1;
	}
	ip = pkg_malloc(sizeof *ip);
	if (!ip) {
		LM_CRIT("No more pkg memory\n");
		return -1;
	}
	memcpy(ip, ip_tmp, sizeof *ip);

	p = (af == AF_INET) ? q_memchr(p, '.', len-(p-in)+1) : q_memchr(p, ':', len-(p-in)+1);
	if (p) {
		ip_tmp = (af == AF_INET) ? str2ip(&mask_s) : str2ip6(&mask_s);
		if (!ip_tmp) {
			LM_ERR("Invalid netmask\n");
			return -1;
		}
		mask = pkg_malloc(sizeof *mask);
		if (!mask) {
			LM_CRIT("No more pkg memory\n");
			return -1;
		}
		memcpy(mask, ip_tmp, sizeof *mask);

		*ipnet = mk_net(ip, mask);
	} else {
		if (str2int(&mask_s, &bitlen) < 0) {
			LM_ERR("Invalid netmask bitlen\n");
			return -1;
		}

		*ipnet = mk_net_bitlen(ip, bitlen);
	}

	pkg_free(ip);
	pkg_free(mask);

	if (*ipnet == NULL)
			return -1;

	return 0;
}
