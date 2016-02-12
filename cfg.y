/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include "sr_module.h"
#include "modparam.h"
#include "ip_addr.h"
#include "resolve.h"
#include "socket_info.h"
#include "name_alias.h"
#include "ut.h"
#include "dset.h"
#include "pvar.h"
#include "blacklists.h"
#include "xlog.h"
#include "tcp_server.h"
#include "tcp_conn.h"
#include "db/db_insertq.h"
#include "bin_interface.h"


#include "config.h"
#ifdef USE_TLS
#include "tls/tls_config.h"
#include "tls/tls_domain.h"
#endif

#ifdef DEBUG_DMALLOC
#include <dmalloc.h>
#endif

/* hack to avoid alloca usage in the generated C file (needed for compiler
 with no built in alloca, like icc*/
#undef _ALLOCA_H


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
static struct ip_addr* ip_tmp;
static pv_spec_t *spec;
static pv_elem_t *pvmodel;
static struct bl_rule *bl_head = 0;
static struct bl_rule *bl_tail = 0;
static struct stat statf;

action_elem_t elems[MAX_ACTION_ELEMS];
static action_elem_t route_elems[MAX_ACTION_ELEMS];
action_elem_t *a_tmp;

static inline void warn(char* s);
static struct socket_id* mk_listen_id(char*, int, int);
static struct socket_id* set_listen_id_adv(struct socket_id *, char *, int);

static char *mpath=NULL;
static char mpath_buf[256];
static int  mpath_len = 0;

extern int line;
extern int column;
extern int startcolumn;
extern char *finame;

#define get_cfg_file_name \
	((finame) ? finame : cfg_file ? cfg_file : "default")



#define mk_action_(_res, _type, _no, _elems) \
	do { \
		_res = mk_action(_type, _no, _elems, line, get_cfg_file_name); \
	} while(0)
#define mk_action0(_res, _type, _p1_type, _p2_type, _p1, _p2) \
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
	struct _pv_spec *specval;
}

/* terminals */


/* keywords */
%token FORWARD
%token SEND
%token DROP
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
%token SET_HOST
%token SET_HOSTPORT
%token PREFIX
%token STRIP
%token STRIP_TAIL
%token APPEND_BRANCH
%token REMOVE_BRANCH
%token PV_PRINTF
%token SET_USER
%token SET_USERPASS
%token SET_PORT
%token SET_URI
%token REVERT_URI
%token SET_DSTURI
%token RESET_DSTURI
%token ISDSTURISET
%token FORCE_RPORT
%token FORCE_LOCAL_RPORT
%token FORCE_TCP_ALIAS
%token IF
%token ELSE
%token SWITCH
%token CASE
%token DEFAULT
%token SBREAK
%token WHILE
%token FOR
%token IN
%token SET_ADV_ADDRESS
%token SET_ADV_PORT
%token FORCE_SEND_SOCKET
%token SERIALIZE_BRANCHES
%token NEXT_BRANCHES
%token USE_BLACKLIST
%token UNUSE_BLACKLIST
%token MAX_LEN
%token SETDEBUG
%token SETFLAG
%token RESETFLAG
%token ISFLAGSET
%token SETBFLAG
%token RESETBFLAG
%token ISBFLAGSET
%token SETSFLAG
%token RESETSFLAG
%token ISSFLAGSET
%token METHOD
%token URI
%token FROM_URI
%token TO_URI
%token SRCIP
%token SRCPORT
%token DSTIP
%token DSTPORT
%token PROTO
%token AF
%token MYSELF
%token MSGLEN 
%token UDP
%token TCP
%token TLS
%token SCTP
%token NULLV
%token CACHE_STORE
%token CACHE_FETCH
%token CACHE_COUNTER_FETCH
%token CACHE_REMOVE
%token CACHE_ADD
%token CACHE_SUB
%token CACHE_RAW_QUERY
%token XDBG
%token XLOG
%token XLOG_BUF_SIZE
%token XLOG_FORCE_COLOR
%token RAISE_EVENT
%token SUBSCRIBE_EVENT
%token CONSTRUCT_URI
%token GET_TIMESTAMP
%token SCRIPT_TRACE

/* config vars. */
%token DEBUG
%token FORK
%token LOGSTDERROR
%token LOGFACILITY
%token LOGNAME
%token AVP_ALIASES
%token LISTEN
%token BIN_LISTEN
%token BIN_CHILDREN
%token ALIAS
%token AUTO_ALIASES
%token DNS
%token REV_DNS
%token DNS_TRY_IPV6
%token DNS_TRY_NAPTR
%token DNS_RETR_TIME
%token DNS_RETR_NO
%token DNS_SERVERS_NO
%token DNS_USE_SEARCH
%token MAX_WHILE_LOOPS
%token PORT
%token CHILDREN
%token CHECK_VIA
%token SHM_HASH_SPLIT_PERCENTAGE
%token SHM_SECONDARY_HASH_SIZE
%token MEM_WARMING_ENABLED
%token MEM_WARMING_PATTERN_FILE
%token MEM_WARMING_PERCENTAGE
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
%token SOCK_MODE
%token SOCK_USER
%token SOCK_GROUP
%token UNIX_SOCK
%token UNIX_SOCK_CHILDREN
%token UNIX_TX_TIMEOUT
%token SERVER_SIGNATURE
%token SERVER_HEADER
%token USER_AGENT_HEADER
%token LOADMODULE
%token MPATH
%token MODPARAM
%token MAXBUFFER
%token USER
%token GROUP
%token CHROOT
%token WDIR
%token MHOMED
%token DISABLE_TCP
%token ASYNC_TCP
%token ASYNC_TCP_LOCAL_CON_TIMEOUT
%token ASYNC_TCP_LOCAL_WRITE_TIMEOUT
%token ASYNC_TCP_MAX_POSTPONED_CHUNKS
%token TCP_ACCEPT_ALIASES
%token TCP_CHILDREN
%token TCP_CONNECT_TIMEOUT
%token TCP_SEND_TIMEOUT
%token TCP_CON_LIFETIME
%token TCP_LISTEN_BACKLOG
%token TCP_POLL_METHOD
%token TCP_MAX_CONNECTIONS
%token TCP_OPT_CRLF_PINGPONG
%token TCP_NO_NEW_CONN_BFLAG
%token TCP_KEEPALIVE
%token TCP_KEEPCOUNT
%token TCP_KEEPIDLE
%token TCP_KEEPINTERVAL
%token TCP_MAX_MSG_CHUNKS
%token TCP_MAX_MSG_TIME
%token DISABLE_TLS
%token TLSLOG
%token TLS_PORT_NO
%token TLS_METHOD
%token TLS_HANDSHAKE_TIMEOUT
%token TLS_SEND_TIMEOUT
%token TLS_SERVER_DOMAIN
%token TLS_CLIENT_DOMAIN
%token TLS_CLIENT_DOMAIN_AVP
%token SSLv23
%token SSLv2
%token SSLv3
%token TLSv1
%token TLSv1_2
%token TLS_VERIFY_CLIENT
%token TLS_VERIFY_SERVER
%token TLS_REQUIRE_CLIENT_CERTIFICATE
%token TLS_CERTIFICATE
%token TLS_PRIVATE_KEY
%token TLS_CA_LIST
%token TLS_CA_DIR 
%token TLS_CIPHERS_LIST
%token TLS_DH_PARAMS
%token TLS_EC_CURVE
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
%token DISABLE_503_TRANSLATION




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

/* values */
%token <intval> NUMBER
%token <intval> ZERO
%token <strval> ID
%token <strval> STRING
%token <strval> SCRIPTVAR
%token <strval> IPV6ADDR

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
%token USE_CHILDREN
%token DOT
%token CR
%token COLON
%token ANY
%token SCRIPTVARERR


/*non-terminals */
%type <expr> exp exp_elem exp_cond assignexp /*, condition*/
%type <action> action actions cmd if_cmd stm exp_stm assign_cmd while_cmd
			   foreach_cmd
%type <action> switch_cmd switch_stm case_stms case_stm default_stm
%type <intval> module_func_param
%type <ipaddr> ipv4 ipv6 ipv6addr ip
%type <ipnet> ipnet
%type <specval> script_var
%type <strval> host
%type <strval> listen_id
%type <sockid> listen_lst
%type <sockid> listen_def
%type <sockid> id_lst
%type <sockid> phostport
%type <intval> proto port
%type <strval> host_sep
%type <intval> uri_type
%type <intval> equalop compop matchop strop intop
%type <intval> assignop
%type <intval> snumber
%type <strval> route_name
%type <intval> route_param

/*
 * since "if_cmd" is inherently ambiguous,
 * skip 1 harmless shift/reduce conflict when compiling our grammar
 */
%expect 1


%%


cfg:	statements
	;

statements:	statements statement {}
		| statement {}
		| statements error { yyerror(""); YYABORT;}
	;

statement:	assign_stm 
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

listen_id:	ip			{	tmp=ip_addr2a($1);
							if(tmp==0){
								LM_CRIT("cfg. parser: bad ip address.\n");
								$$=0;
							}else{
								$$=pkg_malloc(strlen(tmp)+1);
								if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
								}else{
									strncpy($$, tmp, strlen(tmp)+1);
								}
							}
						}
		|	STRING			{	$$=pkg_malloc(strlen($1)+1);
							if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
							}else{
									strncpy($$, $1, strlen($1)+1);
							}
						}
		|	host		{	if ($1==0) {
								$$ = 0;
							} else {
								$$=pkg_malloc(strlen($1)+1);
								if ($$==0){
									LM_CRIT("cfg. parser: out of memory.\n");
								}else{
									strncpy($$, $1, strlen($1)+1);
								}
							}
						}
	;

proto:	  UDP	{ $$=PROTO_UDP; }
		| TCP	{ $$=PROTO_TCP; }
		| TLS	{
			#ifdef USE_TLS
				$$=PROTO_TLS;
			#else
				$$=PROTO_TCP;
				warn("tls support not compiled in");
			#endif
			}
		| SCTP  { 
			#ifdef USE_SCTP
				$$=PROTO_SCTP;
			#else
				yyerror("sctp support not compiled in\n");YYABORT;
			#endif
			}
		| ANY	{ $$=0; }
		;

port:	  NUMBER	{ $$=$1; }
		| ANY		{ $$=0; }
;

snumber:	NUMBER	{ $$=$1; }
		| PLUS NUMBER	{ $$=$2; }
		| MINUS NUMBER	{ $$=-$2; }
;


phostport:	listen_id				{ $$=mk_listen_id($1, 0, 0); }
			| listen_id COLON port	{ $$=mk_listen_id($1, 0, $3); }
			| proto COLON listen_id	{ $$=mk_listen_id($3, $1, 0); }
			| proto COLON listen_id COLON port	{ $$=mk_listen_id($3, $1, $5);}
			| listen_id COLON error { $$=0; yyerror(" port number expected"); }
			;

id_lst:		phostport		{  $$=$1 ; }
		| phostport id_lst	{ $$=$1; $$->next=$2; }
		;


listen_def:	phostport				{ $$=$1; }
			| phostport USE_CHILDREN NUMBER { $$=$1; $$->children=$3; }
			| phostport AS listen_id { $$=$1; set_listen_id_adv((struct socket_id *)$1, $3, 5060); }
			| phostport AS listen_id USE_CHILDREN NUMBER { $$=$1; set_listen_id_adv((struct socket_id *)$1, $3, 5060); $1->children=$5; }
			| phostport AS listen_id COLON port{ $$=$1; set_listen_id_adv((struct socket_id *)$1, $3, $5); }
			| phostport AS listen_id COLON port USE_CHILDREN NUMBER { $$=$1; set_listen_id_adv((struct socket_id *)$1, $3, $5); $1->children=$7; }
			;

listen_lst:		listen_def		{  $$=$1 ; }
		| listen_def listen_lst	{ $$=$1; $$->next=$2; }
		;


blst_elem: LPAREN  proto COMMA ipnet COMMA port COMMA STRING RPAREN {
				s_tmp.s=$8;
				s_tmp.len=strlen($8);
				if (add_rule_to_list(&bl_head,&bl_tail,$4,&s_tmp,$6,$2,0)) {
					yyerror("failed to add backlist element\n");YYABORT;
				}
			}
		| NOT  LPAREN  proto COMMA ipnet COMMA port COMMA STRING RPAREN {
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


assign_stm: DEBUG EQUAL snumber { 
#ifdef CHANGEABLE_DEBUG_LEVEL
					*debug=$3;
#else
					debug=$3;
#endif
			}
		| DEBUG EQUAL error  { yyerror("number  expected"); }
		| FORK  EQUAL NUMBER { dont_fork= !dont_fork ? ! $3:1; }
		| FORK  EQUAL error  { yyerror("boolean value expected"); }
		| LOGSTDERROR EQUAL NUMBER { if (!config_check) log_stderr=$3; }
		| LOGSTDERROR EQUAL error { yyerror("boolean value expected"); }
		| LOGFACILITY EQUAL ID {
					if ( (i_tmp=str2facility($3))==-1)
						yyerror("bad facility (see syslog(3) man page)");
					if (!config_check)
						log_facility=i_tmp;
									}
		| LOGFACILITY EQUAL error { yyerror("ID expected"); }
		| LOGNAME EQUAL STRING { log_name=$3; }
		| LOGNAME EQUAL error { yyerror("string value expected"); }
		| AVP_ALIASES EQUAL STRING { 
				yyerror("AVP_ALIASES shouldn't be used anymore\n");
			}
		| AVP_ALIASES EQUAL error { yyerror("string value expected"); }
		| DNS EQUAL NUMBER   { received_dns|= ($3)?DO_DNS:0; }
		| DNS EQUAL error { yyerror("boolean value expected"); }
		| REV_DNS EQUAL NUMBER { received_dns|= ($3)?DO_REV_DNS:0; }
		| REV_DNS EQUAL error { yyerror("boolean value expected"); }
		| DNS_TRY_IPV6 EQUAL NUMBER   { dns_try_ipv6=$3; }
		| DNS_TRY_IPV6 error { yyerror("boolean value expected"); }
		| DNS_TRY_NAPTR EQUAL NUMBER   { dns_try_naptr=$3; }
		| DNS_TRY_NAPTR error { yyerror("boolean value expected"); }
		| DNS_RETR_TIME EQUAL NUMBER   { dns_retr_time=$3; }
		| DNS_RETR_TIME error { yyerror("number expected"); }
		| DNS_RETR_NO EQUAL NUMBER   { dns_retr_no=$3; }
		| DNS_RETR_NO error { yyerror("number expected"); }
		| DNS_SERVERS_NO EQUAL NUMBER   { dns_servers_no=$3; }
		| DNS_SERVERS_NO error { yyerror("number expected"); }
		| DNS_USE_SEARCH EQUAL NUMBER   { dns_search_list=$3; }
		| DNS_USE_SEARCH error { yyerror("boolean value expected"); }
		| PORT EQUAL NUMBER   { port_no=$3; }
		| PORT EQUAL error    { yyerror("number expected"); } 
		| MAX_WHILE_LOOPS EQUAL NUMBER { max_while_loops=$3; }
		| MAX_WHILE_LOOPS EQUAL error { yyerror("number expected"); } 
		| MAXBUFFER EQUAL NUMBER { maxbuffer=$3; }
		| MAXBUFFER EQUAL error { yyerror("number expected"); }
		| CHILDREN EQUAL NUMBER { children_no=$3; }
		| CHILDREN EQUAL error { yyerror("number expected"); } 
		| CHECK_VIA EQUAL NUMBER { check_via=$3; }
		| CHECK_VIA EQUAL error { yyerror("boolean value expected"); }
		| SHM_HASH_SPLIT_PERCENTAGE EQUAL NUMBER {
			#ifdef HP_MALLOC
			shm_hash_split_percentage=$3;
			#else
			yyerror("Cannot set parameter; Please recompile with support for HP_MALLOC");
			#endif
			}
		| SHM_HASH_SPLIT_PERCENTAGE EQUAL error { yyerror("number expected"); }
		| SHM_SECONDARY_HASH_SIZE EQUAL NUMBER {
			#ifdef HP_MALLOC
			shm_secondary_hash_size=$3;
			#else
			yyerror("Cannot set parameter; Please recompile with support for HP_MALLOC");
			#endif
			}
		| SHM_SECONDARY_HASH_SIZE EQUAL error { yyerror("number expected"); }
		| MEM_WARMING_ENABLED EQUAL NUMBER {
			#ifdef HP_MALLOC
			mem_warming_enabled = $3;
			#else
			yyerror("Cannot set parameter; Please recompile with support for HP_MALLOC");
			#endif
			}
		| MEM_WARMING_ENABLED EQUAL error { yyerror("number expected"); }
		| MEM_WARMING_PATTERN_FILE EQUAL STRING {
			#ifdef HP_MALLOC
			mem_warming_pattern_file = $3;
			#else
			yyerror("Cannot set parameter; Please recompile with support for HP_MALLOC");
			#endif
			}
		| MEM_WARMING_PATTERN_FILE EQUAL error { yyerror("string expected"); }
		| MEM_WARMING_PERCENTAGE EQUAL NUMBER {
			#ifdef HP_MALLOC
			mem_warming_percentage = $3;
			#else
			yyerror("Cannot set parameter; Please recompile with support for HP_MALLOC");
			#endif
			}
		| MEM_WARMING_PERCENTAGE EQUAL error { yyerror("number expected"); }
		| MEMLOG EQUAL NUMBER { memlog=$3; memdump=$3; }
		| MEMLOG EQUAL error { yyerror("int value expected"); }
		| MEMDUMP EQUAL NUMBER { memdump=$3; }
		| MEMDUMP EQUAL error { yyerror("int value expected"); }
		| EXECMSGTHRESHOLD EQUAL NUMBER { execmsgthreshold=$3; }
		| EXECMSGTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| EXECDNSTHRESHOLD EQUAL NUMBER { execdnsthreshold=$3; }
		| EXECDNSTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| TCPTHRESHOLD EQUAL NUMBER { tcpthreshold=$3; }
		| TCPTHRESHOLD EQUAL error { yyerror("int value expected"); }
		| EVENT_SHM_THRESHOLD EQUAL NUMBER {
			#ifdef SHM_MEM
				#ifdef STATISTICS
					if ($3 < 0 || $3 > 100)
						yyerror("SHM threshold has to be a percentage between 0 and 100");
					event_shm_threshold=$3;
				#else
					yyerror("statistics support not compiled in");
				#endif /* STATISTICS */
			#else /* SHM_MEM */
				yyerror("shm memory support not compiled in");
			#endif
			}
		| EVENT_SHM_THRESHOLD EQUAL error { yyerror("int value expected"); }
		| EVENT_PKG_THRESHOLD EQUAL NUMBER {
			#ifdef PKG_MALLOC
                                #ifdef STATISTICS
                                        if ($3 < 0 || $3 > 100)
                                                yyerror("PKG threshold has to be a percentage between 0 and 100");
                                        event_pkg_threshold=$3;
                                #else
                                        yyerror("statistics support not compiled in");
                                #endif
			#else /* PKG_MALLOC */
				yyerror("pkg memory support not compiled in");
			#endif
			}
		| EVENT_PKG_THRESHOLD EQUAL error { yyerror("int value expected"); }
		| QUERYBUFFERSIZE EQUAL NUMBER { query_buffer_size=$3; }
		| QUERYBUFFERSIZE EQUAL error { yyerror("int value expected"); }
		| QUERYFLUSHTIME EQUAL NUMBER { query_flush_time=$3; }
		| QUERYFLUSHTIME EQUAL error { yyerror("int value expected"); }
		| SIP_WARNING EQUAL NUMBER { sip_warning=$3; }
		| SIP_WARNING EQUAL error { yyerror("boolean value expected"); }
		| USER EQUAL STRING     { user=$3; }
		| USER EQUAL ID         { user=$3; }
		| USER EQUAL error      { yyerror("string value expected"); }
		| GROUP EQUAL STRING     { group=$3; }
		| GROUP EQUAL ID         { group=$3; }
		| GROUP EQUAL error      { yyerror("string value expected"); }
		| CHROOT EQUAL STRING     { chroot_dir=$3; }
		| CHROOT EQUAL ID         { chroot_dir=$3; }
		| CHROOT EQUAL error      { yyerror("string value expected"); }
		| WDIR EQUAL STRING     { working_dir=$3; }
		| WDIR EQUAL ID         { working_dir=$3; }
		| WDIR EQUAL error      { yyerror("string value expected"); }
		| MHOMED EQUAL NUMBER { mhomed=$3; }
		| MHOMED EQUAL error { yyerror("boolean value expected"); }
		| DISABLE_TCP EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_disable=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| DISABLE_TCP EQUAL error { yyerror("boolean value expected"); }
		| ASYNC_TCP EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_async=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| ASYNC_TCP EQUAL error { yyerror("boolean value expected"); }
		| ASYNC_TCP_LOCAL_CON_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_async_local_connect_timeout=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| ASYNC_TCP_LOCAL_CON_TIMEOUT EQUAL error { yyerror("boolean value expected"); }
		| ASYNC_TCP_LOCAL_WRITE_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_async_local_write_timeout=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| ASYNC_TCP_LOCAL_WRITE_TIMEOUT EQUAL error { yyerror("boolean value expected"); }
		| ASYNC_TCP_MAX_POSTPONED_CHUNKS EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_async_max_postponed_chunks=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| ASYNC_TCP_MAX_POSTPONED_CHUNKS EQUAL error { yyerror("boolean value expected"); }
		| TCP_ACCEPT_ALIASES EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_accept_aliases=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_ACCEPT_ALIASES EQUAL error { yyerror("boolean value expected"); }
		| TCP_CHILDREN EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_children_no=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_CHILDREN EQUAL error { yyerror("number expected"); }
		| TCP_CONNECT_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_connect_timeout=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_CONNECT_TIMEOUT EQUAL error { yyerror("number expected"); }
		| TCP_SEND_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_send_timeout=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_SEND_TIMEOUT EQUAL error { yyerror("number expected"); }
		| TCP_CON_LIFETIME EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_con_lifetime=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_CON_LIFETIME EQUAL error { yyerror("number expected"); }
		| TCP_LISTEN_BACKLOG EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_listen_backlog=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_LISTEN_BACKLOG EQUAL error { yyerror("number expected"); }
		| TCP_POLL_METHOD EQUAL ID {
									#ifdef USE_TCP
										tcp_poll_method=get_poll_type($3);
										if (tcp_poll_method==POLL_NONE){
											LM_CRIT("bad poll method name:"
												" %s\n, try one of %s.\n",
												$3, poll_support);
											yyerror("bad tcp_poll_method "
												"value");
										}
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_POLL_METHOD EQUAL STRING {
									#ifdef USE_TCP
										tcp_poll_method=get_poll_type($3);
										if (tcp_poll_method==POLL_NONE){
											LM_CRIT("bad poll method name:"
												" %s\n, try one of %s.\n",
												$3, poll_support);
											yyerror("bad tcp_poll_method "
												"value");
										}
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_POLL_METHOD EQUAL error { yyerror("poll method name expected"); }
		| TCP_MAX_CONNECTIONS EQUAL NUMBER {
									#ifdef USE_TCP
										tcp_max_connections=$3;
									#else
										warn("tcp support not compiled in");
									#endif
									}
		| TCP_MAX_CONNECTIONS EQUAL error { yyerror("number expected"); }
		| TCP_OPT_CRLF_PINGPONG EQUAL NUMBER {
			#ifdef USE_TCP
				tcp_crlf_pingpong=$3;
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_OPT_CRLF_PINGPONG EQUAL error { yyerror("boolean value expected"); }
		| TCP_NO_NEW_CONN_BFLAG EQUAL NUMBER {
			#ifdef USE_TCP
				tmp = NULL;
				fix_flag_name(tmp, $3);
				tcp_no_new_conn_bflag = get_flag_id_by_name(FLAG_TYPE_BRANCH, tmp);
				if (!flag_in_range( (flag_t)tcp_no_new_conn_bflag ) )
					yyerror("invalid TCP no_new_conn Branch Flag");
				flag_idx2mask( &tcp_no_new_conn_bflag );
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_NO_NEW_CONN_BFLAG EQUAL ID {
			#ifdef USE_TCP
				tcp_no_new_conn_bflag = get_flag_id_by_name(FLAG_TYPE_BRANCH, $3);
				if (!flag_in_range( (flag_t)tcp_no_new_conn_bflag ) )
					yyerror("invalid TCP no_new_conn Branch Flag");
				flag_idx2mask( &tcp_no_new_conn_bflag );
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_NO_NEW_CONN_BFLAG EQUAL error { yyerror("number value expected"); }
		| TCP_KEEPALIVE EQUAL NUMBER {
			#ifdef USE_TCP
			        tcp_keepalive=$3;
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_KEEPALIVE EQUAL error { yyerror("boolean value expected"); }
		| TCP_MAX_MSG_CHUNKS EQUAL NUMBER {
			#ifdef USE_TCP
			        tcp_max_msg_chunks=$3;
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_MAX_MSG_CHUNKS EQUAL error { yyerror("boolean value expected"); }
		| TCP_MAX_MSG_TIME EQUAL NUMBER {
			#ifdef USE_TCP
			        tcp_max_msg_time=$3;
			#else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_MAX_MSG_TIME EQUAL error { yyerror("boolean value expected"); }
		| TCP_KEEPCOUNT EQUAL NUMBER 		{ 
			#ifdef USE_TCP
			    #ifndef HAVE_TCP_KEEPCNT
				warn("cannot be enabled (no OS support)");
			    #else
			        tcp_keepcount=$3;
			    #endif
		        #else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_KEEPCOUNT EQUAL error { yyerror("int value expected"); }
		| TCP_KEEPIDLE EQUAL NUMBER 		{ 
			#ifdef USE_TCP
			    #ifndef HAVE_TCP_KEEPIDLE
				warn("cannot be enabled (no OS support)");
			    #else
			        tcp_keepidle=$3;
			    #endif
		        #else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_KEEPIDLE EQUAL error { yyerror("int value expected"); }
		| TCP_KEEPINTERVAL EQUAL NUMBER 		{ 
			#ifdef USE_TCP
			    #ifndef HAVE_TCP_KEEPINTVL
				warn("cannot be enabled (no OS support)");
			    #else
			        tcp_keepinterval=$3;
			    #endif
		        #else
				warn("tcp support not compiled in");
			#endif
		}
		| TCP_KEEPINTERVAL EQUAL error { yyerror("int value expected"); }
		| DISABLE_TLS EQUAL NUMBER {
									#ifdef USE_TLS
										tls_disable=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| DISABLE_TLS EQUAL error { yyerror("boolean value expected"); }
		| TLSLOG EQUAL NUMBER 		{ 
									#ifdef USE_TLS
										tls_log=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLSLOG EQUAL error { yyerror("int value expected"); }
		| TLS_PORT_NO EQUAL NUMBER {
									#ifdef USE_TLS
										tls_port_no=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_PORT_NO EQUAL error { yyerror("number expected"); }
		| TLS_METHOD EQUAL SSLv23 {
									#ifdef USE_TLS
										tls_default_server_domain->method =
											TLS_USE_SSLv23;
										tls_default_client_domain->method =
											TLS_USE_SSLv23;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_METHOD EQUAL SSLv2 {
									#ifdef USE_TLS
										tls_default_server_domain->method =
											TLS_USE_SSLv2;
										tls_default_client_domain->method =
											TLS_USE_SSLv2;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_METHOD EQUAL SSLv3 {
									#ifdef USE_TLS
										tls_default_server_domain->method =
											TLS_USE_SSLv3;
										tls_default_client_domain->method =
											TLS_USE_SSLv3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_METHOD EQUAL TLSv1 {
									#ifdef USE_TLS
										tls_default_server_domain->method =
											TLS_USE_TLSv1;
										tls_default_client_domain->method =
											TLS_USE_TLSv1;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_METHOD EQUAL TLSv1_2 {
									#ifdef USE_TLS
										tls_default_server_domain->method =
											TLS_USE_TLSv1_2;
										tls_default_client_domain->method =
											TLS_USE_TLSv1_2;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_METHOD EQUAL error {
									#ifdef USE_TLS
										yyerror("SSLv23, SSLv2, SSLv3, TLSv1 or TLSv1_2"
													" expected");
									#else
										warn("tls support not compiled in");
									#endif
									}
										
		| TLS_VERIFY_CLIENT EQUAL NUMBER {
									#ifdef USE_TLS
										tls_default_server_domain->verify_cert
											= $3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_VERIFY_CLIENT EQUAL error { yyerror("boolean value expected"); }
		| TLS_VERIFY_SERVER EQUAL NUMBER {
									#ifdef USE_TLS
										tls_default_client_domain->verify_cert
											=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_VERIFY_SERVER EQUAL error { yyerror("boolean value expected"); }
		| TLS_REQUIRE_CLIENT_CERTIFICATE EQUAL NUMBER {
									#ifdef USE_TLS
										tls_default_server_domain->require_client_cert=$3;
									#else
										warn( "tls support not compiled in");
									#endif
									}
		| TLS_REQUIRE_CLIENT_CERTIFICATE EQUAL error { yyerror("boolean value expected"); }
		| TLS_CERTIFICATE EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->cert_file=
											$3;
										tls_default_client_domain->cert_file=
											$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_CERTIFICATE EQUAL error { yyerror("string value expected"); }
		| TLS_PRIVATE_KEY EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->pkey_file=
											$3;
										tls_default_client_domain->pkey_file=
											$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_PRIVATE_KEY EQUAL error { yyerror("string value expected"); }
		| TLS_CA_LIST EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->ca_file =
											$3;
										tls_default_client_domain->ca_file =
											$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_CA_LIST EQUAL error { yyerror("string value expected"); }
  	        | TLS_CA_DIR EQUAL STRING {
                                                                        #ifdef USE_TLS
                                                                                tls_default_server_domain->ca_directory =
                                                                                        $3;
                                                                                tls_default_client_domain->ca_directory =
                                                                                        $3;
                                                                        #else
                                                                                warn("tls support not compiled in");
                                                                        #endif
                                                                        }
                | TLS_CA_DIR EQUAL error { yyerror("string value expected"); }
		| TLS_CIPHERS_LIST EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->ciphers_list
											= $3;
										tls_default_client_domain->ciphers_list
											= $3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_CIPHERS_LIST EQUAL error { yyerror("string value expected"); }
		| TLS_DH_PARAMS EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->tmp_dh_file =
											$3;
										tls_default_client_domain->tmp_dh_file =
											$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_DH_PARAMS EQUAL error { yyerror("string value expected"); }
		| TLS_EC_CURVE EQUAL STRING { 
									#ifdef USE_TLS
										tls_default_server_domain->tls_ec_curve =
											$3;
										tls_default_client_domain->tls_ec_curve =
											$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_EC_CURVE EQUAL error { yyerror("string value expected"); }
		| TLS_HANDSHAKE_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TLS
										tls_handshake_timeout=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_HANDSHAKE_TIMEOUT EQUAL error { yyerror("number expected"); }
		| TLS_SEND_TIMEOUT EQUAL NUMBER {
									#ifdef USE_TLS
										tls_send_timeout=$3;
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_SEND_TIMEOUT EQUAL error { yyerror("number expected"); }
		| TLS_CLIENT_DOMAIN_AVP EQUAL STRING {
									#ifdef USE_TLS
										tstr.s = $3;
										tstr.len = strlen(tstr.s);
										if (parse_avp_spec(&tstr, &tls_client_domain_avp)) {
											yyerror("cannot parse tls_client_avp");
										}
									#else
										warn("tls support not compiled in");
									#endif
									}
		| TLS_CLIENT_DOMAIN_AVP EQUAL error { yyerror("number expected"); }
		| tls_server_domain_stm
		| tls_client_domain_stm
		| SERVER_SIGNATURE EQUAL NUMBER { server_signature=$3; }
		| SERVER_SIGNATURE EQUAL error { yyerror("boolean value expected"); }
		| SERVER_HEADER EQUAL STRING { server_header.s=$3;
									server_header.len=strlen($3);
									}
		| SERVER_HEADER EQUAL error { yyerror("string value expected"); }
		| USER_AGENT_HEADER EQUAL STRING { user_agent_header.s=$3;
									user_agent_header.len=strlen($3);
									}
		| USER_AGENT_HEADER EQUAL error { yyerror("string value expected"); }
		| XLOG_BUF_SIZE EQUAL NUMBER { xlog_buf_size = $3; }
		| XLOG_FORCE_COLOR EQUAL NUMBER { xlog_force_color = $3; } 
		| XLOG_BUF_SIZE EQUAL error { yyerror("number expected"); }
		| XLOG_FORCE_COLOR EQUAL error { yyerror("boolean value expected"); }
		| LISTEN EQUAL listen_lst {
							for(lst_tmp=$3; lst_tmp; lst_tmp=lst_tmp->next){
								if (add_listen_iface(	lst_tmp->name,
														lst_tmp->port,
														lst_tmp->proto,
														lst_tmp->adv_name,
														lst_tmp->adv_port,
														lst_tmp->children,
														0
													)!=0){
									LM_CRIT("cfg. parser: failed"
											" to add listen address\n");
									break;
								}
							}
							 }
		| LISTEN EQUAL  error { yyerror("ip address or hostname "
						"expected (use quotes if the hostname includes"
						" config keywords)"); }
		| BIN_LISTEN EQUAL listen_id COLON port {
					if (bin) {
						yyerror("can only define one binary packet interface");
						YYABORT;
					}

					lst_tmp = mk_listen_id($3, PROTO_UDP, $5);
					bin = new_sock_info(lst_tmp->name,
										lst_tmp->port,
										lst_tmp->proto,
										lst_tmp->adv_name,
										lst_tmp->adv_port,
										lst_tmp->children,
										0);
					if (!bin) {
						LM_CRIT("Failed to create new socket info!\n");
						YYABORT;
					}
							}
		| BIN_LISTEN EQUAL  error { yyerror("ip address or hostname "
						"expected (use quotes if the hostname includes"
						" config keywords)"); }
		| BIN_CHILDREN EQUAL NUMBER { bin_children=$3; }
		| BIN_CHILDREN EQUAL error { yyerror("number expected"); }
		| ALIAS EQUAL  id_lst { 
							for(lst_tmp=$3; lst_tmp; lst_tmp=lst_tmp->next)
								add_alias(lst_tmp->name, strlen(lst_tmp->name),
											lst_tmp->port, lst_tmp->proto);
							  }
		| ALIAS  EQUAL error  { yyerror("hostname expected (use quotes"
							" if the hostname includes config keywords)"); }
		| AUTO_ALIASES EQUAL NUMBER { auto_aliases=$3; }
		| AUTO_ALIASES EQUAL error  { yyerror("number  expected"); }
		| ADVERTISED_ADDRESS EQUAL listen_id {
								if ($3) {
									default_global_address.s=$3;
									default_global_address.len=strlen($3);
								}
								}
		| ADVERTISED_ADDRESS EQUAL error {yyerror("ip address or hostname "
												"expected"); }
		| ADVERTISED_PORT EQUAL NUMBER {
								tmp = int2str($3, &i_tmp);
								if (i_tmp > default_global_port.len)
									default_global_port.s =
										pkg_realloc(default_global_port.s, i_tmp);

								if (!default_global_port.s) {
									LM_CRIT("cfg. parser: out of memory.\n");
									default_global_port.len = 0;
								} else {
									default_global_port.len = i_tmp;
									memcpy(default_global_port.s, tmp,
											default_global_port.len);
								}
								}
		|ADVERTISED_PORT EQUAL error {yyerror("ip address or hostname "
												"expected"); }
		| DISABLE_CORE EQUAL NUMBER {
										disable_core_dump=$3;
									}
		| DISABLE_CORE EQUAL error { yyerror("boolean value expected"); }
		| OPEN_FD_LIMIT EQUAL NUMBER {
										open_files_limit=$3;
									}
		| OPEN_FD_LIMIT EQUAL error { yyerror("number expected"); }
		| MCAST_LOOPBACK EQUAL NUMBER {
								#ifdef USE_MCAST
										mcast_loopback=$3;
								#else
									warn("no multicast support compiled in");
								#endif
		  }
		| MCAST_LOOPBACK EQUAL error { yyerror("boolean value expected"); }
		| MCAST_TTL EQUAL NUMBER {
								#ifdef USE_MCAST
										mcast_ttl=$3;
								#else
									warn("no multicast support compiled in");
								#endif
		  }
		| MCAST_TTL EQUAL error { yyerror("number expected as tos"); }
		| TOS EQUAL NUMBER { tos = $3;
							if (tos<=0)
								yyerror("invalid tos value");
		 }
		| TOS EQUAL ID { if (strcasecmp($3,"IPTOS_LOWDELAY")) {
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
		| MPATH EQUAL STRING { mpath=$3; strcpy(mpath_buf, $3);
								mpath_len=strlen($3); 
								if(mpath_buf[mpath_len-1]!='/') {
									mpath_buf[mpath_len]='/';
									mpath_len++;
									mpath_buf[mpath_len]='\0';
								}
							}
		| MPATH EQUAL error  { yyerror("string value expected"); }
		| DISABLE_DNS_FAILOVER EQUAL NUMBER {
										disable_dns_failover=$3;
									}
		| DISABLE_DNS_FAILOVER error { yyerror("boolean value expected"); }
		| DISABLE_DNS_BLACKLIST EQUAL NUMBER {
										disable_dns_blacklist=$3;
									}
		| DISABLE_DNS_BLACKLIST error { yyerror("boolean value expected"); }
		| DST_BLACKLIST EQUAL ID COLON LBRACE blst_elem_list RBRACE {
				s_tmp.s = $3;
				s_tmp.len = strlen($3);
				if ( create_bl_head( BL_CORE_ID, BL_READONLY_LIST,
				bl_head, bl_tail, &s_tmp)==0) {
					yyerror("failed to create blacklist\n");
					YYABORT;
				}
				bl_head = bl_tail = 0;
				}
		| DISABLE_STATELESS_FWD EQUAL NUMBER {
				sl_fwd_disabled=$3;
				}
		| DB_VERSION_TABLE EQUAL STRING { db_version_table=$3; }
		| DB_VERSION_TABLE EQUAL error { yyerror("string value expected"); }
		| DB_DEFAULT_URL EQUAL STRING { db_default_url=$3; }
		| DB_DEFAULT_URL EQUAL error { yyerror("string value expected"); }
		| DISABLE_503_TRANSLATION EQUAL NUMBER { disable_503_translation=$3; }
		| DISABLE_503_TRANSLATION EQUAL error {
				yyerror("string value expected");
				}
		| error EQUAL { yyerror("unknown config variable"); }
	;

module_stm:	LOADMODULE STRING	{
			if(*$2!='/' && mpath!=NULL
					&& strlen($2)+mpath_len<255)
			{
				strcpy(mpath_buf+mpath_len, $2);
				if (stat(mpath_buf, &statf) == -1) {
					i_tmp = strlen(mpath_buf);
					if(strchr($2, '/')==NULL &&
							strncmp(mpath_buf+i_tmp-3, ".so", 3)==0)
					{
						if(i_tmp+strlen($2)<255)
						{
							strcpy(mpath_buf+i_tmp-3, "/");
							strcpy(mpath_buf+i_tmp-2, $2);
							if (stat(mpath_buf, &statf) == -1) {
								mpath_buf[mpath_len]='\0';
								LM_ERR("module '%s' not found in '%s'\n",
									$2, mpath_buf);
								yyerror("failed to load module");
							}
						} else {
							yyerror("failed to load module - path too long");
						}
					} else {
						yyerror("failed to load module - not found");
					}
				}
				LM_DBG("loading module %s\n", mpath_buf);
				if (sr_load_module(mpath_buf)!=0){
					yyerror("failed to load module");
				}
				mpath_buf[mpath_len]='\0';
			} else {
				LM_DBG("loading module %s\n", $2);
				if (sr_load_module($2)!=0){
					yyerror("failed to load module");
				}
			}
		}
		| LOADMODULE error	{ yyerror("string expected");  }
		| MODPARAM LPAREN STRING COMMA STRING COMMA STRING RPAREN {
				if (set_mod_param_regex($3, $5, STR_PARAM, $7) != 0) {
					yyerrorf("Parameter <%s> not found in module <%s> - can't set",
						$5, $3);
				}
			}
		| MODPARAM LPAREN STRING COMMA STRING COMMA snumber RPAREN {
				if (set_mod_param_regex($3, $5, INT_PARAM, (void*)$7) != 0) {
					yyerrorf("Parameter <%s> not found in module <%s> - can't set",
						$5, $3);
				}
			}
		| MODPARAM error { yyerror("Invalid arguments"); }
		;


ip:		 ipv4  { $$=$1; }
		|ipv6  { $$=$1; }
		;

ipv4:	NUMBER DOT NUMBER DOT NUMBER DOT NUMBER { 
											$$=pkg_malloc(
													sizeof(struct ip_addr));
											if ($$==0){
												LM_CRIT("cfg. "
													"parser: out of memory.\n"
													);
											}else{
												memset($$, 0, 
													sizeof(struct ip_addr));
												$$->af=AF_INET;
												$$->len=4;
												if (($1>255) || ($1<0) ||
													($3>255) || ($3<0) ||
													($5>255) || ($5<0) ||
													($7>255) || ($7<0)){
													yyerror("invalid ipv4"
															"address");
													$$->u.addr32[0]=0;
													/* $$=0; */
												}else{
													$$->u.addr[0]=$1;
													$$->u.addr[1]=$3;
													$$->u.addr[2]=$5;
													$$->u.addr[3]=$7;
													/*
													$$=htonl( ($1<<24)|
													($3<<16)| ($5<<8)|$7 );
													*/
												}
											}
												}
	;

ipv6addr:	IPV6ADDR {
					$$=pkg_malloc(sizeof(struct ip_addr));
					if ($$==0){
						LM_CRIT("ERROR: cfg. parser: out of memory.\n");
					}else{
						memset($$, 0, sizeof(struct ip_addr));
						$$->af=AF_INET6;
						$$->len=16;
					#ifdef USE_IPV6
						if (inet_pton(AF_INET6, $1, $$->u.addr)<=0){
							yyerror("bad ipv6 address");
						}
					#else
						yyerror("ipv6 address & no ipv6 support compiled in");
						YYABORT;
					#endif
					}
				}
	;

ipv6:	ipv6addr { $$=$1; }
	| LBRACK ipv6addr RBRACK {$$=$2; }
;

tls_server_domain_stm : TLS_SERVER_DOMAIN LBRACK ip COLON port RBRACK { 
						#ifdef USE_TLS
							if (tls_new_server_domain($3, $5)) 
								yyerror("tls_new_server_domain failed");
						#else	
							warn("tls support not compiled in");
						#endif
							}
	         LBRACE tls_server_decls RBRACE
;

tls_client_domain_stm : TLS_CLIENT_DOMAIN LBRACK ip COLON port RBRACK { 
						#ifdef USE_TLS
							if (tls_new_client_domain($3, $5))
								yyerror("tls_new_client_domain failed");
						#else	
							warn("tls support not compiled in");
						#endif
							}
	         LBRACE tls_client_decls RBRACE
;

tls_client_domain_stm : TLS_CLIENT_DOMAIN LBRACK STRING RBRACK { 
						#ifdef USE_TLS
							if (tls_new_client_domain_name($3, strlen($3)))
								yyerror("tls_new_client_domain_name failed");
						#else	
							warn("tls support not compiled in");
						#endif
							}
	         LBRACE tls_client_decls RBRACE
;

tls_server_decls : tls_server_var
          | tls_server_decls tls_server_var
;

tls_client_decls : tls_client_var
          | tls_client_decls tls_client_var
;
	
tls_server_var : TLS_METHOD EQUAL SSLv23 { 
						#ifdef USE_TLS
									tls_server_domains->method=TLS_USE_SSLv23;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL SSLv2 { 
						#ifdef USE_TLS
									tls_server_domains->method=TLS_USE_SSLv2;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL SSLv3 { 
						#ifdef USE_TLS
									tls_server_domains->method=TLS_USE_SSLv3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL TLSv1 { 
						#ifdef USE_TLS
									tls_server_domains->method=TLS_USE_TLSv1;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL TLSv1_2 { 
						#ifdef USE_TLS
									tls_server_domains->method=TLS_USE_TLSv1_2;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL error { yyerror("SSLv23, SSLv2, SSLv3, TLSv1 or TLSV1_2 expected"); }
	| TLS_CERTIFICATE EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->cert_file=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_CERTIFICATE EQUAL error { yyerror("string value expected"); }

	| TLS_PRIVATE_KEY EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->pkey_file=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_PRIVATE_KEY EQUAL error { yyerror("string value expected"); }

	| TLS_CA_LIST EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->ca_file=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_CA_LIST EQUAL error { yyerror("string value expected"); }
	| TLS_CA_DIR EQUAL STRING {
                                                #ifdef USE_TLS
                                                                        tls_server_domains->ca_directory=$3;
                                                #else
                                                                        warn("tls support not compiled in");
                                                #endif
                                                                }
        | TLS_CA_DIR EQUAL error { yyerror("string value expected"); }
	| TLS_CIPHERS_LIST EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->ciphers_list=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_CIPHERS_LIST EQUAL error { yyerror("string value expected"); }
	| TLS_DH_PARAMS EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->tmp_dh_file=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_DH_PARAMS EQUAL error { yyerror("string value expected"); }
	| TLS_EC_CURVE EQUAL STRING { 
						#ifdef USE_TLS
									tls_server_domains->tls_ec_curve=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_EC_CURVE EQUAL error { yyerror("string value expected"); }
	| TLS_VERIFY_CLIENT EQUAL NUMBER {
						#ifdef USE_TLS
									tls_server_domains->verify_cert=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_VERIFY_CLIENT EQUAL error { yyerror("boolean value expected"); }
	| TLS_REQUIRE_CLIENT_CERTIFICATE EQUAL NUMBER {
						#ifdef USE_TLS
									tls_server_domains->require_client_cert=$3;
						#else
									warn( "tls support not compiled in");
						#endif
								}
	| TLS_REQUIRE_CLIENT_CERTIFICATE EQUAL error { 
						yyerror("boolean value expected"); }
;

tls_client_var : TLS_METHOD EQUAL SSLv23 { 
						#ifdef USE_TLS
									tls_client_domains->method=TLS_USE_SSLv23;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL SSLv2 { 
						#ifdef USE_TLS
									tls_client_domains->method=TLS_USE_SSLv2;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL SSLv3 { 
						#ifdef USE_TLS
									tls_client_domains->method=TLS_USE_SSLv3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL TLSv1 { 
						#ifdef USE_TLS
									tls_client_domains->method=TLS_USE_TLSv1;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL TLSv1_2 { 
						#ifdef USE_TLS
									tls_client_domains->method=TLS_USE_TLSv1_2;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_METHOD EQUAL error {
						yyerror("SSLv23, SSLv2, SSLv3, TLSv1 or TLSv1_2 expected"); }
	| TLS_CERTIFICATE EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->cert_file=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_CERTIFICATE EQUAL error { yyerror("string value expected"); }

	| TLS_PRIVATE_KEY EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->pkey_file=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_PRIVATE_KEY EQUAL error { yyerror("string value expected"); }

	| TLS_CA_LIST EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->ca_file=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_CA_LIST EQUAL error { yyerror("string value expected"); }
	| TLS_CA_DIR EQUAL STRING {
                                                #ifdef USE_TLS
                                                                        tls_client_domains->ca_directory=$3;
                                                #else
                                                                        warn("tls support not compiled in");
                                                #endif
                                                                }
        | TLS_CA_DIR EQUAL error { yyerror("string value expected"); }
	| TLS_CIPHERS_LIST EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->ciphers_list=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_CIPHERS_LIST EQUAL error { yyerror("string value expected"); }
	| TLS_DH_PARAMS EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->tmp_dh_file=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_DH_PARAMS EQUAL error { yyerror("string value expected"); }
	| TLS_EC_CURVE EQUAL STRING { 
						#ifdef USE_TLS
									tls_client_domains->tls_ec_curve=$3; 
						#else
									warn("tls support not compiled in");
						#endif
								}	
	| TLS_EC_CURVE EQUAL error { yyerror("string value expected"); }
	| TLS_VERIFY_SERVER EQUAL NUMBER {
						#ifdef USE_TLS
									tls_client_domains->verify_cert=$3;
						#else
									warn("tls support not compiled in");
						#endif
								}
	| TLS_VERIFY_SERVER EQUAL error { yyerror("boolean value expected"); }
;

route_name:  ID {
				$$ = $1;
				}
		| NUMBER {
				tmp=int2str($1, &i_tmp);
				if (($$=pkg_malloc(i_tmp+1))==0)
					yyerror("cfg. parser: out of memory.\n");
				memcpy( $$, tmp, i_tmp);
				$$[i_tmp] = 0;
				}
		|STRING {
				$$ = $1;
		}
;

route_stm:  ROUTE LBRACE actions RBRACE {
						if (rlist[DEFAULT_RT].a!=0) {
							yyerror("overwriting default "
								"request routing table");
							YYABORT;
						}
						push($3, &rlist[DEFAULT_RT].a);
					}
		| ROUTE LBRACK route_name RBRACK LBRACE actions RBRACE { 
						if ( strtol($3,&tmp,10)==0 && *tmp==0) {
							/* route[0] detected */
							if (rlist[DEFAULT_RT].a!=0) {
								yyerror("overwriting(2) default "
									"request routing table");
								YYABORT;
							}
							push($6, &rlist[DEFAULT_RT].a);
						} else {
							i_tmp = get_script_route_idx($3,rlist,RT_NO,1);
							if (i_tmp==-1) YYABORT;
							push($6, &rlist[i_tmp].a);
						}
					}
		| ROUTE error { yyerror("invalid  route  statement"); }
	;

failure_route_stm: ROUTE_FAILURE LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx($3,failure_rlist,
								FAILURE_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &failure_rlist[i_tmp].a);
					}
		| ROUTE_FAILURE error { yyerror("invalid failure_route statement"); }
	;

onreply_route_stm: ROUTE_ONREPLY LBRACE actions RBRACE {
						if (onreply_rlist[DEFAULT_RT].a!=0) {
							yyerror("overwriting default "
								"onreply routing table");
							YYABORT;
						}
						push($3, &onreply_rlist[DEFAULT_RT].a);
					}
		| ROUTE_ONREPLY LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx($3,onreply_rlist,
								ONREPLY_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &onreply_rlist[i_tmp].a);
					}
		| ROUTE_ONREPLY error { yyerror("invalid onreply_route statement"); }
	;

branch_route_stm: ROUTE_BRANCH LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx($3,branch_rlist,
								BRANCH_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &branch_rlist[i_tmp].a);
					}
		| ROUTE_BRANCH error { yyerror("invalid branch_route statement"); }
	;

error_route_stm:  ROUTE_ERROR LBRACE actions RBRACE {
						if (error_rlist.a!=0) {
							yyerror("overwriting default "
								"error routing table");
							YYABORT;
						}
						push($3, &error_rlist.a);
					}
		| ROUTE_ERROR error { yyerror("invalid error_route statement"); }
	;

local_route_stm:  ROUTE_LOCAL LBRACE actions RBRACE {
						if (local_rlist.a!=0) {
							yyerror("re-definition of local "
								"route detected");
							YYABORT;
						}
						push($3, &local_rlist.a);
					}
		| ROUTE_LOCAL error { yyerror("invalid local_route statement"); }
	;

startup_route_stm:  ROUTE_STARTUP LBRACE actions RBRACE {
						if (startup_rlist.a!=0) {
							yyerror("re-definition of startup "
								"route detected");
							YYABORT;
						}
						push($3, &startup_rlist.a);
					}
		| ROUTE_STARTUP error { yyerror("invalid startup_route statement"); }
	;

timer_route_stm:  ROUTE_TIMER LBRACK route_name COMMA NUMBER RBRACK LBRACE actions RBRACE {
						i_tmp = 0;
						while (timer_rlist[i_tmp].a!=0 && i_tmp < TIMER_RT_NO) {
							i_tmp++;
						}
						if(i_tmp == TIMER_RT_NO) {
							yyerror("Too many timer routes defined\n");
							YYABORT;
						}
						timer_rlist[i_tmp].interval = $5;
						push($8, &timer_rlist[i_tmp].a);
					}
		| ROUTE_TIMER error { yyerror("invalid timer_route statement"); }
	;

event_route_stm: ROUTE_EVENT LBRACK route_name RBRACK LBRACE actions RBRACE {
						i_tmp = get_script_route_idx($3,event_rlist,
								EVENT_RT_NO,1);
						if (i_tmp==-1) YYABORT;
						push($6, &event_rlist[i_tmp].a);
					}
		| ROUTE_EVENT error { yyerror("invalid timer_route statement"); }
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

uri_type:	URI			{$$=URI_O;}
		|	FROM_URI	{$$=FROM_URI_O;}
		|	TO_URI		{$$=TO_URI_O;}
		;

script_var:	SCRIPTVAR	{ 
				spec = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
				if (spec==NULL){
					yyerror("no more pkg memory\n");
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
		| uri_type strop host 	{$$ = mk_elem($2, $1, 0, STR_ST, $3); 
				 			}
		| DSTIP equalop ipnet	{ $$=mk_elem($2, DSTIP_O, 0, NET_ST, $3);
								}
		| DSTIP strop host	{ $$=mk_elem($2, DSTIP_O, 0, STR_ST, $3);
								}
		| SRCIP equalop ipnet	{ $$=mk_elem($2, SRCIP_O, 0, NET_ST, $3);
								}
		| SRCIP strop host	{ $$=mk_elem($2, SRCIP_O, 0, STR_ST, $3);
								}
	;

exp_cond:	METHOD strop STRING	{$$= mk_elem($2, METHOD_O, 0, STR_ST, $3);
									}
		| METHOD strop  ID	{$$ = mk_elem($2, METHOD_O, 0, STR_ST, $3); 
				 			}
		| METHOD strop error { $$=0; yyerror("string expected"); }
		| METHOD error	{ $$=0; yyerror("invalid operator,"
										"== , !=, or =~ expected");
						}
		| script_var strop script_var {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,SCRIPTVAR_ST,(void*)$3);
			}
		| script_var strop STRING {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,STR_ST,$3);
			}
		| script_var strop ID {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,STR_ST,$3);
			}
		| script_var intop snumber {
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1,NUMBER_ST,(void *)$3);
			}
		| script_var equalop MYSELF	{ 
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1, MYSELF_ST, 0);
			}
		| script_var equalop NULLV	{ 
				$$=mk_elem( $2, SCRIPTVAR_O,(void*)$1, NULLV_ST, 0);
			}
		| uri_type strop STRING	{$$ = mk_elem($2, $1, 0, STR_ST, $3); 
				 				}
		| uri_type equalop MYSELF	{ $$=mk_elem($2, $1, 0, MYSELF_ST, 0);
								}
		| uri_type strop error { $$=0; yyerror("string or MYSELF expected"); }
		| uri_type error	{ $$=0; yyerror("invalid operator,"
									" == , != or =~ expected");
					}
		| SRCPORT intop NUMBER	{ $$=mk_elem($2, SRCPORT_O, 0, NUMBER_ST,
												(void *) $3 ); }
		| SRCPORT intop error { $$=0; yyerror("number expected"); }
		| SRCPORT error { $$=0; yyerror("==, !=, <,>, >= or <=  expected"); }
		| DSTPORT intop NUMBER	{ $$=mk_elem($2, DSTPORT_O, 0, NUMBER_ST,
												(void *) $3 ); }
		| DSTPORT intop error { $$=0; yyerror("number expected"); }
		| DSTPORT error { $$=0; yyerror("==, !=, <,>, >= or <=  expected"); }
		| PROTO intop proto	{ $$=mk_elem($2, PROTO_O, 0, NUMBER_ST,
												(void *) $3 ); }
		| PROTO intop error { $$=0;
								yyerror("protocol expected (udp, tcp or tls)");
							}
		| PROTO error { $$=0; yyerror("equal/!= operator expected"); }
		| AF intop NUMBER	{ $$=mk_elem($2, AF_O, 0, NUMBER_ST,
												(void *) $3 ); }
		| AF intop error { $$=0; yyerror("number expected"); }
		| AF error { $$=0; yyerror("equal/!= operator expected"); }
		| MSGLEN intop NUMBER	{ $$=mk_elem($2, MSGLEN_O, 0, NUMBER_ST,
												(void *) $3 ); }
		| MSGLEN intop MAX_LEN	{ $$=mk_elem($2, MSGLEN_O, 0, NUMBER_ST,
												(void *) BUF_SIZE); }
		| MSGLEN intop error { $$=0; yyerror("number expected"); }
		| MSGLEN error { $$=0; yyerror("equal/!= operator expected"); }
		| SRCIP strop STRING	{	s_tmp.s=$3;
									s_tmp.len=strlen($3);
									ip_tmp=str2ip(&s_tmp);
									if (ip_tmp==0)
										ip_tmp=str2ip6(&s_tmp);
									if (ip_tmp){
										$$=mk_elem($2, SRCIP_O, 0, NET_ST,
												mk_net_bitlen(ip_tmp, 
														ip_tmp->len*8) );
									}else{
										$$=mk_elem($2, SRCIP_O, 0, STR_ST,
												$3);
									}
								}
		| SRCIP equalop MYSELF  { $$=mk_elem($2, SRCIP_O, 0, MYSELF_ST, 0);
								}
		| SRCIP strop error { $$=0; yyerror( "ip address or hostname"
						 "expected" ); }
		| SRCIP error  { $$=0; 
						 yyerror("invalid operator, ==, != or =~ expected");}
		| DSTIP strop STRING	{	s_tmp.s=$3;
									s_tmp.len=strlen($3);
									ip_tmp=str2ip(&s_tmp);
									if (ip_tmp==0)
										ip_tmp=str2ip6(&s_tmp);
									if (ip_tmp){
										$$=mk_elem($2, DSTIP_O, 0, NET_ST,
												mk_net_bitlen(ip_tmp, 
														ip_tmp->len*8) );
									}else{
										$$=mk_elem($2, DSTIP_O, 0, STR_ST,
												$3);
									}
								}
		| DSTIP equalop MYSELF  { $$=mk_elem($2, DSTIP_O, 0, MYSELF_ST, 0);
								}
		| DSTIP strop error { $$=0; yyerror( "ip address or hostname"
						 			"expected" ); }
		| DSTIP error { $$=0; 
						yyerror("invalid operator, ==, != or =~ expected");}
		| MYSELF equalop uri_type	{ $$=mk_elem($2, $3, 0, MYSELF_ST, 0);
								}
		| MYSELF equalop SRCIP  { $$=mk_elem($2, SRCIP_O, 0, MYSELF_ST, 0);
								}
		| MYSELF equalop DSTIP  { $$=mk_elem($2, DSTIP_O, 0, MYSELF_ST, 0);
								}
		| MYSELF equalop error {	$$=0; 
									yyerror(" URI, SRCIP or DSTIP expected"); }
		| MYSELF error	{ $$=0; 
							yyerror ("invalid operator, == or != expected");
						}
	;

ipnet:	ip SLASH ip	{ $$=mk_net($1, $3); } 
	| ip SLASH NUMBER 	{	if (($3<0) || ($3>(long)$1->len*8)){
								yyerror("invalid bit number in netmask");
								$$=0;
							}else{
								$$=mk_net_bitlen($1, $3);
							/*
								$$=mk_net($1, 
										htonl( ($3)?~( (1<<(32-$3))-1 ):0 ) );
							*/
							}
						}
	| ip				{ $$=mk_net_bitlen($1, $1->len*8); }
	| ip SLASH error	{ $$=0;
						 yyerror("netmask (eg:255.0.0.0 or 8) expected");
						}
	;



host_sep:	DOT {$$=".";}
		|	MINUS {$$="-"; }
		;

host:	ID				{ $$=$1; }
	| host host_sep ID	{ $$=(char*)pkg_malloc(strlen($1)+1+strlen($3)+1);
						  if ($$==0){
							LM_CRIT("cfg. parser: memory allocation"
										" failure while parsing host\n");
						  }else{
							memcpy($$, $1, strlen($1));
							$$[strlen($1)]=*$2;
							memcpy($$+strlen($1)+1, $3, strlen($3));
							$$[strlen($1)+1+strlen($3)]=0;
						  }
						  pkg_free($1); pkg_free($3);
						}
	| host DOT error { $$=0; pkg_free($1); yyerror("invalid hostname (use quotes if hostname has config keywords)"); }
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
	| ID { $$ = mk_elem(VALUE_OP, STRINGV_O, $1, 0, 0); }
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
				yyerror(
					"transformations not accepted in right side of assignment");

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
				yyerror(
					"transformations not accepted in right side of assignment");

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
				yyerror(
					"transformations not accepted in right side of assignment");

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

stm:		action					{ $$=$1; }
		|	LBRACE actions RBRACE	{ $$=$2; }
		|	LBRACE RBRACE			{ $$=0; }
	;

actions:	actions action	{$$=append_action($1, $2); }
		| action			{$$=$1;}
		| actions error { $$=0; yyerror("bad command!)"); }
	;

action:		cmd SEMICOLON {$$=$1;}
		| if_cmd {$$=$1;}
		| while_cmd { $$=$1;}
		| foreach_cmd { $$=$1;}
		| switch_cmd {$$=$1;}
		| assign_cmd SEMICOLON {$$=$1;}
		| SEMICOLON /* null action */ {$$=0;}
		| cmd error { $$=0; yyerror("bad command: missing ';'?"); }
	;

if_cmd:		IF exp stm				{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 NOSUBTYPE,
													 $2,
													 $3,
													 0);
									}
		| IF exp stm ELSE stm		{ mk_action3( $$, IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 ACTIONS_ST,
													 $2,
													 $3,
													 $5);
									}

	;
while_cmd:		WHILE exp stm				{ mk_action2( $$, WHILE_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 $2,
													 $3);
									}
	;

foreach_cmd:	FOR LPAREN script_var IN script_var RPAREN stm {
					if ($3->type != PVT_SCRIPTVAR &&
					    $3->type != PVT_AVP) {
						yyerror("\nfor-each statement: only \"var\" "
					            "and \"avp\" iterators are supported");
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

switch_cmd:		SWITCH LPAREN script_var RPAREN LBRACE switch_stm	RBRACE	{
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

case_stm: CASE snumber COLON actions SBREAK SEMICOLON 
										{ mk_action3( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													$4,
													(void*)1);
											}
		| CASE snumber COLON SBREAK SEMICOLON 
										{ mk_action3( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													0,
													(void*)1);
											}
		| CASE snumber COLON actions { mk_action3( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													$4,
													(void*)0);
									}
		| CASE snumber COLON { mk_action3( $$, CASE_T,
													NUMBER_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													0,
													(void*)0);
							}
		| CASE STRING COLON actions SBREAK SEMICOLON 
										{ mk_action3( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													$4,
													(void*)1);
											}
		| CASE STRING COLON SBREAK SEMICOLON 
										{ mk_action3( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													0,
													(void*)1);
											}
		| CASE STRING COLON actions { mk_action3( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													$4,
													(void*)0);
									}
		| CASE STRING COLON { mk_action3( $$, CASE_T,
													STR_ST,
													ACTIONS_ST,
													NUMBER_ST,
													(void*)$2,
													0,
													(void*)0);
							}

	;

default_stm: DEFAULT COLON actions { mk_action2( $$, DEFAULT_T,
													ACTIONS_ST,
													0,
													$3,
													0);
									}
		| DEFAULT COLON { mk_action2( $$, DEFAULT_T,
													ACTIONS_ST,
													0,
													0,
													0);
									}
	;

module_func_param: STRING {
										elems[1].type = STRING_ST;
										elems[1].u.data = $1;
										$$=1;
										}
		| module_func_param COMMA STRING {
										if ($1+1>=MAX_ACTION_ELEMS) {
											yyerror("too many arguments in function\n");
											$$=0;
										}
										elems[$1+1].type = STRING_ST;
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
										elems[2].type = STRING_ST;
										elems[2].u.data = $2;
										$$=2;
										}
		| module_func_param COMMA {
										if ($1+1>=MAX_ACTION_ELEMS) {
										 	   yyerror("too many arguments in function\n");
										 	   $$=0;
										}
										elems[$1+1].type = NULLV_ST;
										elems[$1+1].u.data = NULL;
										$$=$1+1;
										}
		| NUMBER {
										$$=0;
										yyerror("numbers used as parameters - they should be quoted");
										}
		| COMMA NUMBER {
									   $$=0;
									   yyerror("numbers used as parameters - they should be quoted");
									   }
		| module_func_param COMMA NUMBER {
										$$=0;
										yyerror("numbers used as parameters - they should be quoted");
										}
	;

route_param: STRING {
						route_elems[0].type = STRING_ST;
						route_elems[0].u.data = $1;
						$$=1;
			}
		| NUMBER {
						route_elems[0].type = NUMBER_ST;
						route_elems[0].u.data = (void*)(long)$1;
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
		| route_param COMMA NUMBER {
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
	;

cmd:	 FORWARD LPAREN STRING RPAREN	{ mk_action2( $$, FORWARD_T,
											STRING_ST,
											0,
											$3,
											0);
										}
		| FORWARD LPAREN RPAREN {
										mk_action2( $$, FORWARD_T,
											0,
											0,
											0,
											0);
										}
		| FORWARD error { $$=0; yyerror("missing '(' or ')' ?"); }
		| FORWARD LPAREN error RPAREN { $$=0; yyerror("bad forward "
										"argument"); }
		
		| SEND LPAREN STRING RPAREN { mk_action2( $$, SEND_T,
											STRING_ST,
											0,
											$3,
											0);
										}
		| SEND LPAREN STRING COMMA STRING RPAREN { mk_action2( $$, SEND_T,
											STRING_ST,
											STRING_ST,
											$3,
											$5);
										}
		| SEND error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SEND LPAREN error RPAREN { $$=0; yyerror("bad send"
													"argument"); }
		| DROP LPAREN RPAREN	{mk_action2( $$, DROP_T,0, 0, 0, 0); }
		| DROP					{mk_action2( $$, DROP_T,0, 0, 0, 0); }
		| EXIT LPAREN RPAREN	{mk_action2( $$, EXIT_T,0, 0, 0, 0); }
		| EXIT					{mk_action2( $$, EXIT_T,0, 0, 0, 0); }
		| RETURN LPAREN snumber RPAREN	{mk_action2( $$, RETURN_T,
																NUMBER_ST, 
																0,
																(void*)$3,
																0);
												}
		| RETURN LPAREN script_var RPAREN	{mk_action2( $$, RETURN_T,
																SCRIPTVAR_ST, 
																0,
																(void*)$3,
																0);
												}
		| RETURN LPAREN RPAREN	{mk_action2( $$, RETURN_T,
																NUMBER_ST, 
																0,
																(void*)1,
																0);
												}
		| RETURN				{mk_action2( $$, RETURN_T,
																NUMBER_ST, 
																0,
																(void*)1,
																0);
												}
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
		| SETDEBUG LPAREN snumber RPAREN {mk_action2($$, SET_DEBUG_T, NUMBER_ST,
									0, (void *)$3, 0 ); }
		| SETDEBUG LPAREN RPAREN {mk_action2( $$, SET_DEBUG_T, 0, 0, 0, 0 ); }
		| SETDEBUG error { $$=0; yyerror("missing '(' or ')'?"); }
		| SETFLAG LPAREN NUMBER RPAREN {mk_action2($$, SETFLAG_T, NUMBER_ST, 0,
													(void *)$3, 0 ); }
		| SETFLAG LPAREN ID RPAREN {mk_action2($$, SETFLAG_T, STR_ST, 0,
													(void *)$3, 0 ); }
		| SETFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| RESETFLAG LPAREN NUMBER RPAREN {mk_action2( $$, RESETFLAG_T,
										NUMBER_ST, 0, (void *)$3, 0 ); }
		| RESETFLAG LPAREN ID RPAREN {mk_action2( $$, RESETFLAG_T,
										STR_ST, 0, (void *)$3, 0 ); }
		| RESETFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| ISFLAGSET LPAREN NUMBER RPAREN {mk_action2( $$, ISFLAGSET_T,
										NUMBER_ST, 0, (void *)$3, 0 ); }
		| ISFLAGSET LPAREN ID RPAREN {mk_action2( $$, ISFLAGSET_T,
										STR_ST, 0, (void *)$3, 0 ); }
		| ISFLAGSET error { $$=0; yyerror("missing '(' or ')'?"); }
		| SETSFLAG LPAREN NUMBER RPAREN {mk_action2( $$, SETSFLAG_T, NUMBER_ST,
										0, (void *)$3, 0 ); }
		| SETSFLAG LPAREN ID RPAREN {mk_action2( $$, SETSFLAG_T, STR_ST,
										0, (void *)$3, 0 ); }
		| SETSFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| RESETSFLAG LPAREN NUMBER RPAREN {mk_action2( $$, RESETSFLAG_T,
										NUMBER_ST, 0, (void *)$3, 0 ); }
		| RESETSFLAG LPAREN ID RPAREN {mk_action2( $$, RESETSFLAG_T,
										STR_ST, 0, (void *)$3, 0 ); }
		| RESETSFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| ISSFLAGSET LPAREN NUMBER RPAREN {mk_action2( $$, ISSFLAGSET_T,
										NUMBER_ST, 0, (void *)$3, 0 ); }
		| ISSFLAGSET LPAREN ID RPAREN {mk_action2( $$, ISSFLAGSET_T,
										STR_ST, 0, (void *)$3, 0 ); }
		| ISSFLAGSET error { $$=0; yyerror("missing '(' or ')'?"); }
		| SETBFLAG LPAREN NUMBER COMMA NUMBER RPAREN {mk_action2( $$,
													SETBFLAG_T,
													NUMBER_ST, NUMBER_ST,
													(void *)$3, (void *)$5 ); }
		| SETBFLAG LPAREN NUMBER COMMA ID RPAREN {mk_action2( $$,
													SETBFLAG_T,
													NUMBER_ST, STR_ST,
													(void *)$3, (void *)$5 ); }
		| SETBFLAG LPAREN NUMBER RPAREN {mk_action2( $$, SETBFLAG_T,
													NUMBER_ST, NUMBER_ST,
													0, (void *)$3 ); }
		| SETBFLAG LPAREN ID RPAREN {mk_action2( $$, SETBFLAG_T,
													NUMBER_ST, STR_ST,
													0, (void *)$3 ); }
		| SETBFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| RESETBFLAG LPAREN NUMBER COMMA NUMBER RPAREN {mk_action2( $$, 
													RESETBFLAG_T,
													NUMBER_ST, NUMBER_ST,
													(void *)$3, (void *)$5 ); }
		| RESETBFLAG LPAREN NUMBER COMMA ID RPAREN {mk_action2( $$, 
													RESETBFLAG_T,
													NUMBER_ST, STR_ST,
													(void *)$3, (void *)$5 ); }
		| RESETBFLAG LPAREN NUMBER RPAREN {mk_action2( $$, 
													RESETBFLAG_T,
													NUMBER_ST, NUMBER_ST,
													0, (void *)$3 ); }
		| RESETBFLAG LPAREN ID RPAREN {mk_action2( $$, 
													RESETBFLAG_T,
													NUMBER_ST, STR_ST,
													0, (void *)$3 ); }
		| RESETBFLAG error { $$=0; yyerror("missing '(' or ')'?"); }
		| ISBFLAGSET LPAREN NUMBER COMMA NUMBER RPAREN {mk_action2( $$, 
													ISBFLAGSET_T,
													NUMBER_ST, NUMBER_ST,
													(void *)$3, (void *)$5 ); }
		| ISBFLAGSET LPAREN NUMBER COMMA ID RPAREN {mk_action2( $$, 
													ISBFLAGSET_T,
													NUMBER_ST, STR_ST,
													(void *)$3, (void *)$5 ); }
		| ISBFLAGSET LPAREN NUMBER RPAREN {mk_action2( $$, 
													ISBFLAGSET_T,
													NUMBER_ST, NUMBER_ST,
													0, (void *)$3 ); }
		| ISBFLAGSET LPAREN ID RPAREN {mk_action2( $$, 
													ISBFLAGSET_T,
													NUMBER_ST, STR_ST,
													0, (void *)$3 ); }
		| ISBFLAGSET error { $$=0; yyerror("missing '(' or ')'?"); }
		| ERROR LPAREN STRING COMMA STRING RPAREN {mk_action2( $$, ERROR_T,
																STRING_ST, 
																STRING_ST,
																$3,
																$5);
												  }
		| ERROR error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ERROR LPAREN error RPAREN { $$=0; yyerror("bad error"
														"argument"); }
		| ROUTE LPAREN route_name RPAREN	{ 
						i_tmp = get_script_route_idx( $3, rlist, RT_NO, 0);
						if (i_tmp==-1) yyerror("too many script routes");
						mk_action2( $$, ROUTE_T, NUMBER_ST,
							0, (void*)(long)i_tmp, 0);
					}

		| ROUTE LPAREN route_name COMMA route_param RPAREN	{ 
						i_tmp = get_script_route_idx( $3, rlist, RT_NO, 0);
						if (i_tmp==-1) yyerror("too many script routes");
						if ($5 <= 0) yyerror("too many route parameters");

						/* duplicate the list */
						a_tmp = pkg_malloc($5 * sizeof(action_elem_t));
						if (!a_tmp) yyerror("no more pkg memory");
						memcpy(a_tmp, route_elems, $5*sizeof(action_elem_t));

						mk_action3( $$, ROUTE_T, NUMBER_ST,	/* route idx */
							NUMBER_ST,						/* number of params */
							SCRIPTVAR_ELEM_ST,				/* parameters */
							(void*)(long)i_tmp,
							(void*)(long)$5,
							(void*)a_tmp);
					}
	
		| ROUTE error { $$=0; yyerror("missing '(' or ')' ?"); }
		| ROUTE LPAREN error RPAREN { $$=0; yyerror("bad route"
						"argument"); }
		| SET_HOST LPAREN STRING RPAREN { mk_action2( $$, SET_HOST_T, STR_ST,
														0, $3, 0); }
		| SET_HOST error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_HOST LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }

		| PREFIX LPAREN STRING RPAREN { mk_action2( $$, PREFIX_T, STR_ST,
														0, $3, 0); }
		| PREFIX error { $$=0; yyerror("missing '(' or ')' ?"); }
		| PREFIX LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }
		| STRIP_TAIL LPAREN NUMBER RPAREN { mk_action2( $$, STRIP_TAIL_T, 
									NUMBER_ST, 0, (void *) $3, 0); }
		| STRIP_TAIL error { $$=0; yyerror("missing '(' or ')' ?"); }
		| STRIP_TAIL LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"number expected"); }

		| STRIP LPAREN NUMBER RPAREN { mk_action2( $$, STRIP_T, NUMBER_ST,
														0, (void *) $3, 0); }
		| STRIP error { $$=0; yyerror("missing '(' or ')' ?"); }
		| STRIP LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"number expected"); }
		| APPEND_BRANCH LPAREN STRING COMMA STRING RPAREN {
			{
				qvalue_t q;

				rc = str2q(&q, $5, strlen($5));
				if (rc < 0)
					yyerrorf("bad qvalue (%.*s): %s",
							 strlen($5), $5, qverr2str(rc));

				mk_action2( $$, APPEND_BRANCH_T, STR_ST, NUMBER_ST, $3,
						(void *)(long)q);
			}
		}
		| APPEND_BRANCH LPAREN STRING RPAREN { mk_action2( $$, APPEND_BRANCH_T,
						STR_ST, NUMBER_ST, $3, (void *)Q_UNSPECIFIED) ; }
		| APPEND_BRANCH LPAREN RPAREN { mk_action2( $$, APPEND_BRANCH_T,
						STR_ST, NUMBER_ST, 0, (void *)Q_UNSPECIFIED) ; }
		| APPEND_BRANCH { mk_action2( $$, APPEND_BRANCH_T,
						STR_ST, NUMBER_ST, 0, (void *)Q_UNSPECIFIED ) ; }
		| REMOVE_BRANCH LPAREN NUMBER RPAREN {
						mk_action1($$, REMOVE_BRANCH_T, NUMBER_ST, (void*)$3);}
		| REMOVE_BRANCH LPAREN script_var RPAREN {
						mk_action1( $$, REMOVE_BRANCH_T, SCRIPTVAR_ST, $3);}

		| PV_PRINTF LPAREN STRING COMMA STRING RPAREN {
				spec = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t));
				memset(spec, 0, sizeof(pv_spec_t));
				tstr.s = $3;
				tstr.len = strlen(tstr.s);
				if(pv_parse_spec(&tstr, spec)==NULL)
				{
					yyerror("unknown script variable in first parameter");
				}
				if(!pv_is_w(spec))
					yyerror("read-only script variable in first parameter");

				pvmodel = 0;
				tstr.s = $5;
				tstr.len = strlen(tstr.s);
				if(pv_parse_format(&tstr, &pvmodel)<0)
				{
					yyerror("error in second parameter");
				}

				mk_action2( $$, PV_PRINTF_T,
						SCRIPTVAR_ST, SCRIPTVAR_ELEM_ST, spec, pvmodel) ;
			}
		| PV_PRINTF LPAREN script_var COMMA STRING RPAREN {
				if(!pv_is_w($3))
					yyerror("read-only script variable in first parameter");
				pvmodel = 0;
				tstr.s = $5;
				tstr.len = strlen(tstr.s);
				if(pv_parse_format(&tstr, &pvmodel)<0)
				{
					yyerror("error in second parameter");
				}

				mk_action2( $$, PV_PRINTF_T,
						SCRIPTVAR_ST, SCRIPTVAR_ELEM_ST, $3, pvmodel) ;
			}

		| SET_HOSTPORT LPAREN STRING RPAREN { mk_action2( $$, SET_HOSTPORT_T, 
														STR_ST, 0, $3, 0); }
		| SET_HOSTPORT error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_HOSTPORT LPAREN error RPAREN { $$=0; yyerror("bad argument,"
												" string expected"); }
		| SET_PORT LPAREN STRING RPAREN { mk_action2( $$, SET_PORT_T, STR_ST,
														0, $3, 0); }
		| SET_PORT error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_PORT LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }
		| SET_USER LPAREN STRING RPAREN { mk_action2( $$, SET_USER_T,
														STR_ST, 0, $3, 0); }
		| SET_USER error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_USER LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }
		| SET_USERPASS LPAREN STRING RPAREN { mk_action2( $$, SET_USERPASS_T, 
														STR_ST, 0, $3, 0); }
		| SET_USERPASS error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_USERPASS LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }
		| SET_URI LPAREN STRING RPAREN { mk_action2( $$, SET_URI_T, STR_ST, 
														0, $3, 0); }
		| SET_URI error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_URI LPAREN error RPAREN { $$=0; yyerror("bad argument, "
										"string expected"); }
		| REVERT_URI LPAREN RPAREN { mk_action2( $$, REVERT_URI_T, 0,0,0,0); }
		| REVERT_URI { mk_action2( $$, REVERT_URI_T, 0,0,0,0); }
		| SET_DSTURI LPAREN STRING RPAREN { mk_action2( $$, SET_DSTURI_T,
													STR_ST, 0, $3, 0); }
		| SET_DSTURI error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SET_DSTURI LPAREN error RPAREN { $$=0; yyerror("bad argument, "
										"string expected"); }
		| RESET_DSTURI LPAREN RPAREN { mk_action2( $$, RESET_DSTURI_T,
															0,0,0,0); }
		| RESET_DSTURI { mk_action2( $$, RESET_DSTURI_T, 0,0,0,0); }
		| ISDSTURISET LPAREN RPAREN { mk_action2( $$, ISDSTURISET_T, 0,0,0,0); }
		| ISDSTURISET { mk_action2( $$, ISDSTURISET_T, 0,0,0,0); }
		| FORCE_RPORT LPAREN RPAREN	{ mk_action2( $$, FORCE_RPORT_T,
															0, 0, 0, 0); }
		| FORCE_RPORT		{ mk_action2( $$, FORCE_RPORT_T,0, 0, 0, 0); }
		| FORCE_LOCAL_RPORT LPAREN RPAREN	{
					mk_action2( $$, FORCE_LOCAL_RPORT_T,0, 0, 0, 0); }
		| FORCE_LOCAL_RPORT				{
					mk_action2( $$, FORCE_LOCAL_RPORT_T,0, 0, 0, 0); }
		| FORCE_TCP_ALIAS LPAREN NUMBER RPAREN	{
					#ifdef USE_TCP
						mk_action2( $$, FORCE_TCP_ALIAS_T,NUMBER_ST, 0,
										(void*)$3, 0);
					#else
						yyerror("tcp support not compiled in");
					#endif
												}
		| FORCE_TCP_ALIAS LPAREN RPAREN	{
					#ifdef USE_TCP
						mk_action2( $$, FORCE_TCP_ALIAS_T,0, 0, 0, 0); 
					#else
						yyerror("tcp support not compiled in");
					#endif
										}
		| FORCE_TCP_ALIAS				{
					#ifdef USE_TCP
						mk_action2( $$, FORCE_TCP_ALIAS_T,0, 0, 0, 0);
					#else
						yyerror("tcp support not compiled in");
					#endif
										}
		| FORCE_TCP_ALIAS LPAREN error RPAREN	{$$=0; 
					yyerror("bad argument, number expected");
					}
		| SET_ADV_ADDRESS LPAREN listen_id RPAREN {
								mk_action2( $$, SET_ADV_ADDR_T, STR_ST,
											0, $3, 0);
								}
		| SET_ADV_ADDRESS LPAREN error RPAREN { $$=0; yyerror("bad argument, "
														"string expected"); }
		| SET_ADV_ADDRESS error {$$=0; yyerror("missing '(' or ')' ?"); }
		| SET_ADV_PORT LPAREN NUMBER RPAREN {
								tstr.s = int2str($3, &tstr.len);
								if (!(tmp = pkg_malloc(tstr.len + 1))) {
										LM_CRIT("cfg. parser: out of memory.\n");
										$$ = 0;
								} else {
									memcpy(tmp, tstr.s, tstr.len);
									tmp[tstr.len] = '\0';
									mk_action2($$, SET_ADV_PORT_T, STR_ST,
											   0, tmp, 0);
								}
								            }
		| SET_ADV_PORT LPAREN STRING RPAREN {
								mk_action2($$, SET_ADV_PORT_T,
										   STR_ST, NOSUBTYPE,
										   $3, NULL);
								}
		| SET_ADV_PORT LPAREN error RPAREN { $$=0; yyerror("bad argument "
						"(string or integer expected)"); }
		| SET_ADV_PORT  error {$$=0; yyerror("missing '(' or ')' ?"); }
		| FORCE_SEND_SOCKET LPAREN phostport RPAREN {
								mk_action2( $$, FORCE_SEND_SOCKET_T,
									SOCKID_ST, 0, $3, 0);
								}
		| FORCE_SEND_SOCKET LPAREN error RPAREN { $$=0; yyerror("bad argument,"
								" [proto:]host[:port] expected");
								}
		| FORCE_SEND_SOCKET error {$$=0; yyerror("missing '(' or ')' ?"); }
		| SERIALIZE_BRANCHES LPAREN NUMBER RPAREN {
								mk_action2( $$, SERIALIZE_BRANCHES_T,
									NUMBER_ST, 0, (void*)(long)$3, 0);
								}
		| SERIALIZE_BRANCHES LPAREN error RPAREN {$$=0; yyerror("bad argument,"
								" number expected");
								}
		| SERIALIZE_BRANCHES error {$$=0; yyerror("missing '(' or ')' ?"); }
		| NEXT_BRANCHES LPAREN RPAREN {
								mk_action2( $$, NEXT_BRANCHES_T, 0, 0, 0, 0);
								}
		| NEXT_BRANCHES LPAREN error RPAREN {$$=0; yyerror("no argument is"
								" expected");
								}
		| NEXT_BRANCHES error {$$=0; yyerror("missing '(' or ')' ?"); }
		| USE_BLACKLIST LPAREN STRING RPAREN {
								mk_action2( $$, USE_BLACKLIST_T,
									STRING_ST, 0, $3, 0);
								}
		| USE_BLACKLIST LPAREN error RPAREN {$$=0; yyerror("bad argument,"
								" string expected");
								}
		| USE_BLACKLIST error {$$=0; yyerror("missing '(' or ')' ?"); }
		| UNUSE_BLACKLIST LPAREN STRING RPAREN {
								mk_action2( $$, UNUSE_BLACKLIST_T,
									STRING_ST, 0, $3, 0);
								}
		| UNUSE_BLACKLIST LPAREN error RPAREN {$$=0; yyerror("bad argument,"
								" string expected");
								}
		| UNUSE_BLACKLIST error {$$=0; yyerror("missing '(' or ')' ?"); }
		| CACHE_STORE LPAREN STRING COMMA STRING COMMA STRING RPAREN { 
									mk_action3( $$, CACHE_STORE_T,
													STR_ST,
													STR_ST,
													STR_ST,
													$3,
													$5,
													$7);
							}
		| CACHE_STORE LPAREN STRING COMMA STRING COMMA STRING COMMA NUMBER 
								RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = STR_ST; 
								elems[2].u.data = $7; 
								elems[3].type = NUMBER_ST; 
								elems[3].u.number = $9;
								mk_action_($$, CACHE_STORE_T, 4, elems);
							}
		| CACHE_STORE LPAREN STRING COMMA STRING COMMA STRING COMMA script_var
								RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = STR_ST; 
								elems[2].u.data = $7; 
								elems[3].type = SCRIPTVAR_ST; 
								elems[3].u.data = $9;
								mk_action_($$, CACHE_STORE_T, 4, elems);
							}

		| CACHE_REMOVE LPAREN STRING COMMA STRING RPAREN { 
									mk_action2( $$, CACHE_REMOVE_T,
													STR_ST,
													STR_ST,
													$3,
													$5);
							}
		| CACHE_FETCH LPAREN STRING COMMA STRING COMMA script_var RPAREN { 
									mk_action3( $$, CACHE_FETCH_T,
													STR_ST,
													STR_ST,
													SCRIPTVAR_ST,
													$3,
													$5,
													$7);
							}
		| CACHE_COUNTER_FETCH LPAREN STRING COMMA STRING COMMA script_var RPAREN { 
									mk_action3( $$, CACHE_COUNTER_FETCH_T,
													STR_ST,
													STR_ST,
													SCRIPTVAR_ST,
													$3,
													$5,
													$7);
							}
		| CACHE_ADD LPAREN STRING COMMA STRING COMMA NUMBER COMMA NUMBER RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = NUMBER_ST; 
								elems[2].u.number = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								mk_action_($$, CACHE_ADD_T, 4, elems);
							}
		| CACHE_ADD LPAREN STRING COMMA STRING COMMA script_var COMMA NUMBER RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = SCRIPTVAR_ST; 
								elems[2].u.data = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								mk_action_($$, CACHE_ADD_T, 4, elems);
							}
		| CACHE_ADD LPAREN STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA script_var RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = NUMBER_ST;
								elems[2].u.number = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								elems[4].type = SCRIPTVAR_ST;
								elems[4].u.data = $11;
								mk_action_($$, CACHE_ADD_T, 5, elems);
							}
		| CACHE_ADD LPAREN STRING COMMA STRING COMMA script_var COMMA NUMBER COMMA script_var RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = SCRIPTVAR_ST;
								elems[2].u.data = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								elems[4].type = SCRIPTVAR_ST;
								elems[4].u.data = $11;
								mk_action_($$, CACHE_ADD_T, 5, elems);
							}
		| CACHE_SUB LPAREN STRING COMMA STRING COMMA NUMBER COMMA NUMBER RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = NUMBER_ST; 
								elems[2].u.number = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								mk_action_($$, CACHE_SUB_T, 4, elems);
							}
		| CACHE_SUB LPAREN STRING COMMA STRING COMMA script_var COMMA NUMBER RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = SCRIPTVAR_ST; 
								elems[2].u.data = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								mk_action_($$, CACHE_SUB_T, 4, elems);
							}
		| CACHE_SUB LPAREN STRING COMMA STRING COMMA NUMBER COMMA NUMBER COMMA script_var RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = NUMBER_ST;
								elems[2].u.number = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								elems[4].type = SCRIPTVAR_ST;
								elems[4].u.data = $11;
								mk_action_($$, CACHE_SUB_T, 5, elems);
							}
		| CACHE_SUB LPAREN STRING COMMA STRING COMMA script_var COMMA NUMBER COMMA script_var RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = SCRIPTVAR_ST;
								elems[2].u.data = $7;
								elems[3].type = NUMBER_ST;
								elems[3].u.number = $9;
								elems[4].type = SCRIPTVAR_ST;
								elems[4].u.data = $11;
								mk_action_($$, CACHE_SUB_T, 5, elems);
							}
		| CACHE_RAW_QUERY LPAREN STRING COMMA STRING COMMA STRING RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								elems[2].type = STR_ST; 
								elems[2].u.data = $7;
								mk_action_($$, CACHE_RAW_QUERY_T, 3, elems);
							}
		| CACHE_RAW_QUERY LPAREN STRING COMMA STRING RPAREN { 
								elems[0].type = STR_ST; 
								elems[0].u.data = $3; 
								elems[1].type = STR_ST; 
								elems[1].u.data = $5; 
								mk_action_($$, CACHE_RAW_QUERY_T, 2, elems);
							}
		| ID LPAREN RPAREN		{
						 			cmd_tmp=(void*)find_cmd_export_t($1, 0, rt);
									if (cmd_tmp==0){
										if (find_cmd_export_t($1, 0, 0)) {
											yyerror("Command cannot be "
												"used in the block\n");
										} else {
											yyerrorf("unknown command <%s>, "
												"missing loadmodule?", $1);
										}
										$$=0;
									}else{
										elems[0].type = CMD_ST;
										elems[0].u.data = cmd_tmp;
										mk_action_($$, MODULE_T, 1, elems);
									}
								}
		| ID LPAREN module_func_param RPAREN		{
									cmd_tmp=(void*)find_cmd_export_t($1, $3, rt);
									if (cmd_tmp==0){
										if (find_cmd_export_t($1, $3, 0)) {
											yyerror("Command cannot be "
												"used in the block\n");
										} else {
											yyerrorf("unknown command <%s>, "
												"missing loadmodule?", $1);
										}
										$$=0;
									}else{
										elems[0].type = CMD_ST;
										elems[0].u.data = cmd_tmp;
										mk_action_($$, MODULE_T, $3+1, elems);
									}
								}
		| ID LPAREN error RPAREN { $$=0; yyerrorf("bad arguments for "
												"command <%s>", $1); }
		| ID error { $$=0; yyerrorf("bare word <%s> found, command calls need '()'", $1); }

		| XDBG LPAREN STRING RPAREN {
				mk_action1($$, XDBG_T, STR_ST, $3);	}
		| XLOG LPAREN STRING RPAREN {
				mk_action1($$, XLOG_T, STR_ST, $3); }
		| XLOG LPAREN STRING COMMA STRING RPAREN {
				mk_action2($$, XLOG_T, STR_ST, STR_ST, $3, $5); }
		| RAISE_EVENT LPAREN STRING RPAREN {
				mk_action1($$, RAISE_EVENT_T, STR_ST, $3); }
		| RAISE_EVENT LPAREN STRING COMMA script_var RPAREN {
				mk_action2($$, RAISE_EVENT_T, STR_ST, SCRIPTVAR_ST, $3, $5); }
		| RAISE_EVENT LPAREN STRING COMMA script_var COMMA script_var RPAREN {
				mk_action3($$, RAISE_EVENT_T, STR_ST, SCRIPTVAR_ST, SCRIPTVAR_ST, $3, $5, $7); }
		| SUBSCRIBE_EVENT LPAREN STRING COMMA STRING RPAREN {
				mk_action2($$, SUBSCRIBE_EVENT_T, STR_ST, STR_ST, $3, $5); }
		| SUBSCRIBE_EVENT LPAREN STRING COMMA STRING COMMA NUMBER RPAREN {
				mk_action3($$, SUBSCRIBE_EVENT_T, STR_ST, STR_ST, NUMBER_ST, $3, $5, (void*)(long)$7); }
		| CONSTRUCT_URI LPAREN STRING COMMA STRING COMMA STRING COMMA STRING COMMA STRING COMMA script_var RPAREN {
				elems[0].type = STR_ST; 
				elems[0].u.data = $3; 
				elems[1].type = STR_ST; 
				elems[1].u.data = $5; 
				elems[2].type = STR_ST; 
				elems[2].u.data = $7; 
				elems[3].type = STR_ST; 
				elems[3].u.data = $9;
				elems[4].type = STR_ST; 
				elems[4].u.data = $11;
				elems[5].type = SCRIPTVAR_ST; 
				elems[5].u.data = $13;
				mk_action_($$, CONSTRUCT_URI_T,6,elems); }
		| GET_TIMESTAMP LPAREN script_var COMMA script_var RPAREN {
				elems[0].type = SCRIPTVAR_ST;
				elems[0].u.data = $3;
				elems[1].type = SCRIPTVAR_ST;
				elems[1].u.data = $5; 
				mk_action_($$, GET_TIMESTAMP_T,2,elems); }
		| SCRIPT_TRACE LPAREN RPAREN {
				mk_action2($$, SCRIPT_TRACE_T, 0, 0, 0, 0); }
		| SCRIPT_TRACE LPAREN NUMBER COMMA STRING RPAREN {
				pvmodel = 0;
				tstr.s = $5;
				tstr.len = strlen(tstr.s);
				if(pv_parse_format(&tstr, &pvmodel)<0)
					yyerror("error in second parameter");
				mk_action2($$, SCRIPT_TRACE_T, NUMBER_ST,
						   SCRIPTVAR_ELEM_ST, (void *)$3, pvmodel); }
		| SCRIPT_TRACE LPAREN NUMBER COMMA STRING COMMA STRING RPAREN {
				pvmodel = 0;
				tstr.s = $5;
				tstr.len = strlen(tstr.s);
				if(pv_parse_format(&tstr, &pvmodel)<0)
					yyerror("error in second parameter");
				mk_action3($$, SCRIPT_TRACE_T, NUMBER_ST,
						   SCRIPTVAR_ELEM_ST, STR_ST, (void *)$3, pvmodel, $7); }

	;


%%

static inline void warn(char* s)
{
	LM_WARN("warning in config file %s, line %d, column %d-%d: %s\n",
			get_cfg_file_name, line, startcolumn, column, s);
}

static void yyerror(char* s)
{
	LM_CRIT("parse error in config file %s, line %d, column %d-%d: %s\n",
			get_cfg_file_name, line, startcolumn, column, s);
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


static struct socket_id* mk_listen_id(char* host, int proto, int port)
{
	struct socket_id* l;
	l=pkg_malloc(sizeof(struct socket_id));
	if (l==0){
		LM_CRIT("cfg. parser: out of memory.\n");
	}else{
		l->name     = host;
		l->adv_name = NULL;
		l->adv_port = 0;
		l->proto    = proto;
		l->port     = port;
		l->children = 0;
		l->next     = NULL;
	}

	return l;
}

static struct socket_id* set_listen_id_adv(struct socket_id* sock,
											char *adv_name,
											int adv_port)
{
	sock->adv_name=adv_name;
	sock->adv_port=adv_port;
	return sock;
}
