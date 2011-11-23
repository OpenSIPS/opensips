/*
 * $Id$
 *
 * scanner for cfg files
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
 *
 * History:
 * -------
 *  2003-01-29  src_port added (jiri)
 *  2003-01-23  mhomed added (jiri)
 *  2003-03-19  replaced all the mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-01  added dst_port, proto (tcp, udp, tls), af(inet, inet6) (andrei)
 *  2003-04-05  s/reply_route/failure_route, onreply_route introduced (jiri)
 *  2003-04-12  added force_rport, chdir and wdir (andrei)
 *  2003-04-22  strip_tail added (jiri)
 *  2003-07-03  tls* (disable, certificate, private_key, ca_list, verify, 
 *               require_certificate added (andrei)
 *  2003-07-06  more tls config. vars added: tls_method, tls_port_no (andrei)
 *  2003-10-02  added {,set_}advertised_{address,port} (andrei)
 *  2003-10-07  added hex and octal numbers support (andrei)
 *  2003-10-10  replaced len_gt w/ msg:len (andrei)
 *  2003-10-13  added fifo_dir (andrei)
 *  2003-10-28  added tcp_accept_aliases (andrei)
 *  2003-11-29  added {tcp_send, tcp_connect, tls_*}_timeout (andrei)
 *  2004-03-30  added DISABLE_CORE and OPEN_FD_LIMIT (andrei)
 *  2004-04-28  added sock_mode (replaces fifo_mode), sock_user &
 *               sock_group  (andrei)
 *  2004-05-03  applied multicast support patch from janakj
 *              added MCAST_TTL (andrei)
 *  2005-07-08  added tcp_connection_lifetime, tcp_poll_method,
 *               tcp_max_connections (andrei)
 *  2004-10-08  more escapes: \", \xHH, \nnn and minor optimizations (andrei)
 *  2004-10-19  added FROM_URI and TO_URI (andrei)
 *  2004-11-30  added force_send_socket
 *  2005-11-22  added tos configurability (thanks to Andreas Granig)
 *  2005-11-29  added serialize_branches and next_branches (bogdan)
 *  2006-12-22  functions for script and branch flags added (bogdan)
 *  2007-01-11  auto_aliases option added (bogdan)
 *  2007-01-25  disable_dns_failover option added (bogdan)
 */


%{
	#include "cfg.tab.h"
	#include "dprint.h"
	#include "globals.h"
	#include "mem/mem.h"
	#include <string.h>
	#include <stdlib.h>
	#include "ip_addr.h"


	/* states */
	#define INITIAL_S		0
	#define COMMENT_S		1
	#define COMMENT_LN_S	2
	#define STRING_S		3
	#define SCRIPTVAR_S		4

	#define STR_BUF_ALLOC_UNIT	128
	struct str_buf{
		char* s;
		char* crt;
		int left;
	};

	
	static int comment_nest=0;
	static int state=0;
	static struct str_buf s_buf;
	int line=1;
	int np=0;
	int svar_tlen=0;
	int column=1;
	int startcolumn=1;

	static char* addchar(struct str_buf *, char);
	static char* addstr(struct str_buf *, char*, int);
	static void count();

	/* hack to solve the duplicate declaration of 'isatty' function */
	#define YY_NO_UNISTD_H

	/* hack to skip the declaration of lex unused function 'input' */
	#define YY_NO_INPUT

%}

/* start conditions */
%x STRING1 STRING2 COMMENT COMMENT_LN SCRIPTVARS

/* action keywords */
FORWARD	forward
DROP	"drop"
EXIT	"exit"
RETURN	"return"
SEND	send
SEND_TCP	send_tcp
LOG		log
ERROR	error
ROUTE	route
ROUTE_FAILURE failure_route
ROUTE_ONREPLY onreply_route
ROUTE_BRANCH branch_route
ROUTE_ERROR error_route
ROUTE_LOCAL local_route
ROUTE_STARTUP startup_route
ROUTE_TIMER timer_route
FORCE_RPORT		"force_rport"|"add_rport"
FORCE_LOCAL_RPORT		"force_local_rport"|"add_local_rport"
FORCE_TCP_ALIAS		"force_tcp_alias"|"add_tcp_alias"
SETDEBUG	"setdebug"
SETFLAG		setflag
RESETFLAG	resetflag
ISFLAGSET	isflagset
SETBFLAG		"setbflag"|"setbranchflag"
RESETBFLAG		"resetbflag"|"resetbranchflag"
ISBFLAGSET		"isbflagset"|"isbranchflagset"
SETSFLAG		"setsflag"|"setscriptflag"
RESETSFLAG		"resetsflag"|"resetscriptflag"
ISSFLAGSET		"issflagset"|"isscriptflagset"
SET_HOST		"rewritehost"|"sethost"|"seth"
SET_HOSTPORT	"rewritehostport"|"sethostport"|"sethp"
SET_USER		"rewriteuser"|"setuser"|"setu"
SET_USERPASS	"rewriteuserpass"|"setuserpass"|"setup"
SET_PORT		"rewriteport"|"setport"|"setp"
SET_URI			"rewriteuri"|"seturi"
REVERT_URI		"revert_uri"
SET_DSTURI		"setdsturi"|"setduri"
RESET_DSTURI	"resetdsturi"|"resetduri"
ISDSTURISET		"isdsturiset"|"isduriset"
PREFIX			"prefix"
STRIP			"strip"
STRIP_TAIL		"strip_tail"
APPEND_BRANCH	"append_branch"
REMOVE_BRANCH	"remove_branch"
PV_PRINTF		"pv_printf"|"avp_printf"
IF				"if"
ELSE			"else"
SWITCH			"switch"
CASE			"case"
DEFAULT			"default"
SBREAK			"break"|"esac"
WHILE			"while"
SET_ADV_ADDRESS	"set_advertised_address"
SET_ADV_PORT	"set_advertised_port"
FORCE_SEND_SOCKET	"force_send_socket"
SERIALIZE_BRANCHES	"serialize_branches"
NEXT_BRANCHES	"next_branches"
USE_BLACKLIST	"use_blacklist"
UNUSE_BLACKLIST	"unuse_blacklist"
CACHE_STORE		"cache_store"
CACHE_FETCH		"cache_fetch"
CACHE_REMOVE	"cache_remove"
XDBG			"xdbg"
XLOG_BUF_SIZE	"xlog_buf_size"
XLOG_FORCE_COLOR	"xlog_force_color"
XLOG			"xlog"
RAISE_EVENT		"raise_event"
CONSTRUCT_URI	"construct_uri"
GET_TIMESTAMP	"get_timestamp"

/*ACTION LVALUES*/
URIHOST			"uri:host"
URIPORT			"uri:port"

MAX_LEN			"max_len"


/* condition keywords */
METHOD	method
/* hack -- the second element in first line is referable
   as either uri or status; it only would makes sense to
   call it "uri" from route{} and status from onreply_route{}
*/
URI		"uri"|"status"
FROM_URI	"from_uri"
TO_URI		"to_uri"
SRCIP	src_ip
SRCPORT	src_port
DSTIP	dst_ip
DSTPORT	dst_port
PROTO	proto
AF		af
MYSELF	myself
MSGLEN			"msg:len"

/* operators */
EQUAL	=
EQUAL_T	==
GT	>
LT	<
GTE	>=
LTE	<=
DIFF	!=
MATCH		=~
NOTMATCH	!~
BAND	"&"
BOR		"|"
BXOR	"^"
BNOT	"~"
BLSHIFT	"<<"
BRSHIFT	">>"
NOT		!|"not"
AND		"and"|"&&"
OR		"or"|"||"
PLUS	"+"
MINUS	"-"
MULT	"*"
MODULO	"%"
COLONEQ	":="
PLUSEQ	"+="
MINUSEQ	"-="
SLASHEQ	"/="
MULTEQ	"*="
MODULOEQ	"%="
BANDEQ	"&="
BOREQ	"|="
BXOREQ	"^="

ASSIGNOP	{EQUAL}|{COLONEQ}|{PLUSEQ}|{MINUSEQ}|{SLASHEQ}|{MULTEQ}|{MODULOEQ}|{BANDEQ}|{BOREQ}|{BXOREQ}
BITOP		{BAND}|{BOR}|{BXOR}|{BNOT}|{BLSHIFT}|{BRSHIFT}
ARITHOP		{PLUS}|{MINUS}|{SLASH}|{MULT}|{MODULO}
LOGOP		{EQUAL_T}|{GT}|{LT}|{GTE}|{LTE}|{DIFF}|{MATCH}|{NOTMATCH}|{NOT}|{AND}|{OR}

/* variables */
SCRIPTVAR_START	"$"

/* config vars. */
DEBUG	debug
FORK	fork
LOGSTDERROR	log_stderror
LOGFACILITY	log_facility
LOGNAME		log_name
AVP_ALIASES	avp_aliases
LISTEN		listen
ALIAS		alias
AUTO_ALIASES	auto_aliases
DNS		 dns
REV_DNS	 rev_dns
DNS_TRY_IPV6    dns_try_ipv6
DNS_RETR_TIME   dns_retr_time
DNS_RETR_NO     dns_retr_no
DNS_SERVERS_NO  dns_servers_no
DNS_USE_SEARCH  dns_use_search_list
PORT	port
MAXBUFFER maxbuffer
CHILDREN children
CHECK_VIA	check_via
MEMLOG		"memlog"|"mem_log"
MEMDUMP		"memdump"|"mem_dump"
EXECMSGTHRESHOLD		"execmsgthreshold"|"exec_msg_threshold"
EXECDNSTHRESHOLD		"execdnsthreshold"|"exec_dns_threshold"
TCPTHRESHOLD			"tcpthreshold"|"tcp_threshold"
QUERYBUFFERSIZE			query_buffer_size
QUERYFLUSHTIME			query_flush_time
SIP_WARNING sip_warning
SERVER_SIGNATURE server_signature
SERVER_HEADER server_header
USER_AGENT_HEADER user_agent_header
USER		"user"|"uid"
GROUP		"group"|"gid"
CHROOT		"chroot"
WDIR		"workdir"|"wdir"
MHOMED		mhomed
DISABLE_TCP		"disable_tcp"
TCP_CHILDREN	"tcp_children"
TCP_ACCEPT_ALIASES	"tcp_accept_aliases"
TCP_SEND_TIMEOUT	"tcp_send_timeout"
TCP_CONNECT_TIMEOUT	"tcp_connect_timeout"
TCP_CON_LIFETIME    "tcp_connection_lifetime"
TCP_POLL_METHOD     "tcp_poll_method"
TCP_MAX_CONNECTIONS "tcp_max_connections"
TCP_OPT_CRLF_PINGPONG   "tcp_crlf_pingpong"
TCP_NO_NEW_CONN_BFLAG "tcp_no_new_conn_bflag"
DISABLE_TLS		"disable_tls"
TLSLOG			"tlslog"|"tls_log"
TLS_PORT_NO		"tls_port_no"
TLS_METHOD		"tls_method"
TLS_VERIFY_CLIENT	"tls_verify_client"
TLS_VERIFY_SERVER	"tls_verify_server"
TLS_REQUIRE_CLIENT_CERTIFICATE "tls_require_client_certificate"
TLS_CERTIFICATE	"tls_certificate"
TLS_PRIVATE_KEY "tls_private_key"
TLS_CA_LIST		"tls_ca_list"
TLS_CIPHERS_LIST	"tls_ciphers_list"
TLS_HANDSHAKE_TIMEOUT	"tls_handshake_timeout"
TLS_SEND_TIMEOUT	"tls_send_timeout"
TLS_SERVER_DOMAIN	"tls_server_domain"
TLS_CLIENT_DOMAIN	"tls_client_domain"
TLS_CLIENT_DOMAIN_AVP	"tls_client_domain_avp"
ADVERTISED_ADDRESS	"advertised_address"
ADVERTISED_PORT		"advertised_port"
DISABLE_CORE		"disable_core_dump"
OPEN_FD_LIMIT		"open_files_limit"
MCAST_LOOPBACK		"mcast_loopback"
MCAST_TTL			"mcast_ttl"
TOS					"tos"
DISABLE_DNS_FAILOVER  "disable_dns_failover"
DISABLE_DNS_BLACKLIST "disable_dns_blacklist"
DST_BLACKLIST		"dst_blacklist"
MAX_WHILE_LOOPS "max_while_loops"
DISABLE_STATELESS_FWD	"disable_stateless_fwd"
DB_VERSION_TABLE "db_version_table"
DB_DEFAULT_URL "db_default_url"
DISABLE_503_TRANSLATION "disable_503_translation"

MPATH	mpath
LOADMODULE	loadmodule
MODPARAM        modparam

/* values */
YES			"yes"|"true"|"on"|"enable"
NO			"no"|"false"|"off"|"disable"
UDP			"udp"|"UDP"
TCP			"tcp"|"TCP"
TLS			"tls"|"TLS"
SCTP		"sctp"|"SCTP"
INET		"inet"|"INET"
INET6		"inet6"|"INET6"
SSLv23			"sslv23"|"SSLv23"|"SSLV23"
SSLv2			"sslv2"|"SSLv2"|"SSLV2"
SSLv3			"sslv3"|"SSLv3"|"SSLV3"
TLSv1			"tlsv1"|"TLSv1"|"TLSV1"
NULLV			"null"|"NULL"

LETTER		[a-zA-Z]
DIGIT		[0-9]
ALPHANUM	{LETTER}|{DIGIT}|[_]
NUMBER		0|([1-9]{DIGIT}*)
/*NUMBER		0|(([-+])?[1-9]{DIGIT}*)*/
ID			{LETTER}{ALPHANUM}*
HEX			[0-9a-fA-F]
HEXNUMBER	0x{HEX}+
OCTNUMBER	0[0-7]+
HEX4		{HEX}{1,4}
IPV6ADDR	({HEX4}":"){7}{HEX4}|({HEX4}":"){1,7}(":"{HEX4}){1,7}|":"(":"{HEX4}){1,7}|({HEX4}":"){1,7}":"|"::"
QUOTES		\"
TICK		\'
SLASH		"/"
AS			{EAT_ABLE}("as"|"AS"){EAT_ABLE}
SEMICOLON	;
RPAREN		\)
LPAREN		\(
LBRACE		\{
RBRACE		\}
LBRACK		\[
RBRACK		\]
COMMA		","
COLON		":"
DOT			\.
CR			\n

ANY		"any"


COM_LINE	#
COM_START	"/\*"
COM_END		"\*/"

EAT_ABLE	[\ \t\b\r]
WHITESPACE	[ \t\r\n]

%%


<INITIAL>{EAT_ABLE}	{ count(); }

<INITIAL>{FORWARD}	{count(); yylval.strval=yytext; return FORWARD; }
<INITIAL>{DROP}	{ count(); yylval.strval=yytext; return DROP; }
<INITIAL>{EXIT}	{ count(); yylval.strval=yytext; return EXIT; }
<INITIAL>{RETURN}	{ count(); yylval.strval=yytext; return RETURN; }
<INITIAL>{SEND}	{ count(); yylval.strval=yytext; return SEND; }
<INITIAL>{LOG}	{ count(); yylval.strval=yytext; return LOG_TOK; }
<INITIAL>{ERROR}	{ count(); yylval.strval=yytext; return ERROR; }
<INITIAL>{SETDEBUG}	{ count(); yylval.strval=yytext; return SETDEBUG; }
<INITIAL>{SETFLAG}	{ count(); yylval.strval=yytext; return SETFLAG; }
<INITIAL>{RESETFLAG}	{ count(); yylval.strval=yytext; return RESETFLAG; }
<INITIAL>{ISFLAGSET}	{ count(); yylval.strval=yytext; return ISFLAGSET; }
<INITIAL>{SETBFLAG}	{ count(); yylval.strval=yytext; return SETBFLAG; }
<INITIAL>{RESETBFLAG}	{ count(); yylval.strval=yytext; return RESETBFLAG; }
<INITIAL>{ISBFLAGSET}	{ count(); yylval.strval=yytext; return ISBFLAGSET; }
<INITIAL>{SETSFLAG}	{ count(); yylval.strval=yytext; return SETSFLAG; }
<INITIAL>{RESETSFLAG}	{ count(); yylval.strval=yytext; return RESETSFLAG; }
<INITIAL>{ISSFLAGSET}	{ count(); yylval.strval=yytext; return ISSFLAGSET; }
<INITIAL>{MSGLEN}	{ count(); yylval.strval=yytext; return MSGLEN; }
<INITIAL>{ROUTE}	{ count(); yylval.strval=yytext; return ROUTE; }
<INITIAL>{ROUTE_ONREPLY}	{ count(); yylval.strval=yytext;
								return ROUTE_ONREPLY; }
<INITIAL>{ROUTE_FAILURE}	{ count(); yylval.strval=yytext;
								return ROUTE_FAILURE; }
<INITIAL>{ROUTE_BRANCH} { count(); yylval.strval=yytext; return ROUTE_BRANCH; }
<INITIAL>{ROUTE_ERROR} { count(); yylval.strval=yytext; return ROUTE_ERROR; }
<INITIAL>{ROUTE_LOCAL} { count(); yylval.strval=yytext; return ROUTE_LOCAL; }
<INITIAL>{ROUTE_STARTUP}	{ count(); yylval.strval=yytext;
								return ROUTE_STARTUP; }
<INITIAL>{ROUTE_TIMER}	{ count(); yylval.strval=yytext;
								return ROUTE_TIMER; }
<INITIAL>{SET_HOST}	{ count(); yylval.strval=yytext; return SET_HOST; }
<INITIAL>{SET_HOSTPORT}	{ count(); yylval.strval=yytext; return SET_HOSTPORT; }
<INITIAL>{SET_USER}	{ count(); yylval.strval=yytext; return SET_USER; }
<INITIAL>{SET_USERPASS}	{ count(); yylval.strval=yytext; return SET_USERPASS; }
<INITIAL>{SET_PORT}	{ count(); yylval.strval=yytext; return SET_PORT; }
<INITIAL>{SET_URI}	{ count(); yylval.strval=yytext; return SET_URI; }
<INITIAL>{REVERT_URI}	{ count(); yylval.strval=yytext; return REVERT_URI; }
<INITIAL>{SET_DSTURI}	{ count(); yylval.strval=yytext; return SET_DSTURI; }
<INITIAL>{RESET_DSTURI}	{ count(); yylval.strval=yytext; return RESET_DSTURI; }
<INITIAL>{ISDSTURISET}	{ count(); yylval.strval=yytext; return ISDSTURISET; }
<INITIAL>{PREFIX}	{ count(); yylval.strval=yytext; return PREFIX; }
<INITIAL>{STRIP}	{ count(); yylval.strval=yytext; return STRIP; }
<INITIAL>{STRIP_TAIL}	{ count(); yylval.strval=yytext; return STRIP_TAIL; }
<INITIAL>{APPEND_BRANCH}	{ count(); yylval.strval=yytext; 
								return APPEND_BRANCH; }
<INITIAL>{REMOVE_BRANCH}	{ count(); yylval.strval=yytext; 
								return REMOVE_BRANCH; }
<INITIAL>{PV_PRINTF}	{ count(); yylval.strval=yytext; 
								return PV_PRINTF; }
<INITIAL>{FORCE_RPORT}	{ count(); yylval.strval=yytext; return FORCE_RPORT; }
<INITIAL>{FORCE_LOCAL_RPORT}	{ count(); yylval.strval=yytext; return FORCE_LOCAL_RPORT; }
<INITIAL>{FORCE_TCP_ALIAS}	{ count(); yylval.strval=yytext;
								return FORCE_TCP_ALIAS; }
<INITIAL>{IF}	{ count(); yylval.strval=yytext; return IF; }
<INITIAL>{ELSE}	{ count(); yylval.strval=yytext; return ELSE; }

<INITIAL>{SWITCH}	{ count(); yylval.strval=yytext; return SWITCH; }
<INITIAL>{CASE}		{ count(); yylval.strval=yytext; return CASE; }
<INITIAL>{DEFAULT}	{ count(); yylval.strval=yytext; return DEFAULT; }
<INITIAL>{SBREAK}	{ count(); yylval.strval=yytext; return SBREAK; }
<INITIAL>{WHILE}	{ count(); yylval.strval=yytext; return WHILE; }

<INITIAL>{SET_ADV_ADDRESS}	{ count(); yylval.strval=yytext;
										return SET_ADV_ADDRESS; }
<INITIAL>{SET_ADV_PORT}	{ count(); yylval.strval=yytext;
										return SET_ADV_PORT; }
<INITIAL>{FORCE_SEND_SOCKET}	{	count(); yylval.strval=yytext;
									return FORCE_SEND_SOCKET; }
<INITIAL>{SERIALIZE_BRANCHES}	{	count(); yylval.strval=yytext;
									return SERIALIZE_BRANCHES; }
<INITIAL>{NEXT_BRANCHES}	{	count(); yylval.strval=yytext;
									return NEXT_BRANCHES; }
<INITIAL>{USE_BLACKLIST}	{	count(); yylval.strval=yytext;
									return USE_BLACKLIST; }
<INITIAL>{UNUSE_BLACKLIST}	{	count(); yylval.strval=yytext;
									return UNUSE_BLACKLIST; }

<INITIAL>{CACHE_STORE}		{	count(); yylval.strval=yytext;
									return CACHE_STORE; }
<INITIAL>{CACHE_FETCH}		{	count(); yylval.strval=yytext;
									return CACHE_FETCH; }
<INITIAL>{CACHE_REMOVE}		{	count(); yylval.strval=yytext;
									return CACHE_REMOVE; }

<INITIAL>{XDBG}				{	count(); yylval.strval=yytext;
									return XDBG; }
<INITIAL>{XLOG}				{	count(); yylval.strval=yytext;
									return XLOG; }
<INITIAL>{XLOG_BUF_SIZE}	{	count(); yylval.strval=yytext;
									return XLOG_BUF_SIZE; }
<INITIAL>{XLOG_FORCE_COLOR}	{	count(); yylval.strval=yytext;
									return XLOG_FORCE_COLOR;}
<INITIAL>{RAISE_EVENT}		{	count(); yylval.strval=yytext;
									return RAISE_EVENT;}
<INITIAL>{CONSTRUCT_URI}	{	count(); yylval.strval=yytext;
									return CONSTRUCT_URI;}
<INITIAL>{GET_TIMESTAMP}	{	count(); yylval.strval=yytext;
									return GET_TIMESTAMP;}
<INITIAL>{MAX_LEN}	{ count(); yylval.strval=yytext; return MAX_LEN; }

<INITIAL>{METHOD}	{ count(); yylval.strval=yytext; return METHOD; }
<INITIAL>{URI}	{ count(); yylval.strval=yytext; return URI; }
<INITIAL>{FROM_URI}	{ count(); yylval.strval=yytext; return FROM_URI; }
<INITIAL>{TO_URI}	{ count(); yylval.strval=yytext; return TO_URI; }
<INITIAL>{SRCIP}	{ count(); yylval.strval=yytext; return SRCIP; }
<INITIAL>{SRCPORT}	{ count(); yylval.strval=yytext; return SRCPORT; }
<INITIAL>{DSTIP}	{ count(); yylval.strval=yytext; return DSTIP; }
<INITIAL>{DSTPORT}	{ count(); yylval.strval=yytext; return DSTPORT; }
<INITIAL>{PROTO}	{ count(); yylval.strval=yytext; return PROTO; }
<INITIAL>{AF}	{ count(); yylval.strval=yytext; return AF; }
<INITIAL>{MYSELF}	{ count(); yylval.strval=yytext; return MYSELF; }

<INITIAL>{DEBUG}	{ count(); yylval.strval=yytext; return DEBUG; }
<INITIAL>{FORK}		{ count(); yylval.strval=yytext; return FORK; }
<INITIAL>{LOGSTDERROR}	{ yylval.strval=yytext; return LOGSTDERROR; }
<INITIAL>{LOGFACILITY}	{ yylval.strval=yytext; return LOGFACILITY; }
<INITIAL>{LOGNAME}	{ yylval.strval=yytext; return LOGNAME; }
<INITIAL>{AVP_ALIASES}	{ yylval.strval=yytext; return AVP_ALIASES; }
<INITIAL>{LISTEN}	{ count(); yylval.strval=yytext; return LISTEN; }
<INITIAL>{ALIAS}	{ count(); yylval.strval=yytext; return ALIAS; }
<INITIAL>{AUTO_ALIASES}	{ count(); yylval.strval=yytext; return AUTO_ALIASES; }
<INITIAL>{DNS}	{ count(); yylval.strval=yytext; return DNS; }
<INITIAL>{REV_DNS}	{ count(); yylval.strval=yytext; return REV_DNS; }
<INITIAL>{DNS_TRY_IPV6}		{ count(); yylval.strval=yytext;
								return DNS_TRY_IPV6; }
<INITIAL>{DNS_RETR_TIME}	{ count(); yylval.strval=yytext;
								return DNS_RETR_TIME; }
<INITIAL>{DNS_RETR_NO}		{ count(); yylval.strval=yytext;
								return DNS_RETR_NO; }
<INITIAL>{DNS_SERVERS_NO}	{ count(); yylval.strval=yytext;
								return DNS_SERVERS_NO; }
<INITIAL>{DNS_USE_SEARCH}	{ count(); yylval.strval=yytext;
								return DNS_USE_SEARCH; }
<INITIAL>{PORT}	{ count(); yylval.strval=yytext; return PORT; }
<INITIAL>{MAX_WHILE_LOOPS}	{ count(); yylval.strval=yytext;
								return MAX_WHILE_LOOPS; }
<INITIAL>{MAXBUFFER}	{ count(); yylval.strval=yytext; return MAXBUFFER; }
<INITIAL>{CHILDREN}	{ count(); yylval.strval=yytext; return CHILDREN; }
<INITIAL>{CHECK_VIA}	{ count(); yylval.strval=yytext; return CHECK_VIA; }
<INITIAL>{MEMLOG}	{ count(); yylval.strval=yytext; return MEMLOG; }
<INITIAL>{MEMDUMP}	{ count(); yylval.strval=yytext; return MEMDUMP; }
<INITIAL>{EXECMSGTHRESHOLD}	{ count(); yylval.strval=yytext; return EXECMSGTHRESHOLD; }
<INITIAL>{EXECDNSTHRESHOLD}	{ count(); yylval.strval=yytext; return EXECDNSTHRESHOLD; }
<INITIAL>{TCPTHRESHOLD}	{ count(); yylval.strval=yytext; return TCPTHRESHOLD; }
<INITIAL>{QUERYBUFFERSIZE}	{ count(); yylval.strval=yytext; return QUERYBUFFERSIZE; }
<INITIAL>{QUERYFLUSHTIME}	{ count(); yylval.strval=yytext; return QUERYFLUSHTIME; }
<INITIAL>{SIP_WARNING}	{ count(); yylval.strval=yytext; return SIP_WARNING; }
<INITIAL>{USER}		{ count(); yylval.strval=yytext; return USER; }
<INITIAL>{GROUP}	{ count(); yylval.strval=yytext; return GROUP; }
<INITIAL>{CHROOT}	{ count(); yylval.strval=yytext; return CHROOT; }
<INITIAL>{WDIR}	{ count(); yylval.strval=yytext; return WDIR; }
<INITIAL>{MHOMED}	{ count(); yylval.strval=yytext; return MHOMED; }
<INITIAL>{TCP_OPT_CRLF_PINGPONG}    { count(); yylval.strval=yytext; return TCP_OPT_CRLF_PINGPONG; }
<INITIAL>{TCP_NO_NEW_CONN_BFLAG}    { count(); yylval.strval=yytext; return TCP_NO_NEW_CONN_BFLAG; }
<INITIAL>{DISABLE_TCP}	{ count(); yylval.strval=yytext; return DISABLE_TCP; }
<INITIAL>{TCP_CHILDREN}	{ count(); yylval.strval=yytext; return TCP_CHILDREN; }
<INITIAL>{TCP_ACCEPT_ALIASES}	{ count(); yylval.strval=yytext;
									return TCP_ACCEPT_ALIASES; }
<INITIAL>{TCP_SEND_TIMEOUT}		{ count(); yylval.strval=yytext;
									return TCP_SEND_TIMEOUT; }
<INITIAL>{TCP_CONNECT_TIMEOUT}		{ count(); yylval.strval=yytext;
									return TCP_CONNECT_TIMEOUT; }
<INITIAL>{TCP_CON_LIFETIME}		{ count(); yylval.strval=yytext;
									return TCP_CON_LIFETIME; }
<INITIAL>{TCP_POLL_METHOD}		{ count(); yylval.strval=yytext;
									return TCP_POLL_METHOD; }
<INITIAL>{TCP_MAX_CONNECTIONS}  { count(); yylval.strval=yytext;
									return TCP_MAX_CONNECTIONS; }
<INITIAL>{DISABLE_TLS}	{ count(); yylval.strval=yytext; return DISABLE_TLS; }
<INITIAL>{TLSLOG}		{ count(); yylval.strval=yytext; return TLS_PORT_NO; }
<INITIAL>{TLS_PORT_NO}	{ count(); yylval.strval=yytext; return TLS_PORT_NO; }
<INITIAL>{TLS_METHOD}	{ count(); yylval.strval=yytext; return TLS_METHOD; }
<INITIAL>{TLS_VERIFY_CLIENT}	{ count(); yylval.strval=yytext; return TLS_VERIFY_CLIENT; }
<INITIAL>{TLS_VERIFY_SERVER}	{ count(); yylval.strval=yytext; return TLS_VERIFY_SERVER; }
<INITIAL>{TLS_REQUIRE_CLIENT_CERTIFICATE}	{ count(); yylval.strval=yytext;
										return TLS_REQUIRE_CLIENT_CERTIFICATE;}
<INITIAL>{TLS_CERTIFICATE}	{ count(); yylval.strval=yytext; 
										return TLS_CERTIFICATE; }
<INITIAL>{TLS_PRIVATE_KEY}	{ count(); yylval.strval=yytext; 
										return TLS_PRIVATE_KEY; }
<INITIAL>{TLS_CA_LIST}	{ count(); yylval.strval=yytext; 
										return TLS_CA_LIST; }
<INITIAL>{TLS_CIPHERS_LIST}	{ count(); yylval.strval=yytext; 
										return TLS_CIPHERS_LIST; }
<INITIAL>{TLS_HANDSHAKE_TIMEOUT}	{ count(); yylval.strval=yytext;
										return TLS_HANDSHAKE_TIMEOUT; }
<INITIAL>{TLS_SEND_TIMEOUT}	{ count(); yylval.strval=yytext;
										return TLS_SEND_TIMEOUT; }
<INITIAL>{TLS_SERVER_DOMAIN}		{ count(); yylval.strval=yytext;
									return TLS_SERVER_DOMAIN; }
<INITIAL>{TLS_CLIENT_DOMAIN}		{ count(); yylval.strval=yytext;
									return TLS_CLIENT_DOMAIN; }
<INITIAL>{TLS_CLIENT_DOMAIN_AVP}	{ count(); yylval.strval=yytext;
										return TLS_CLIENT_DOMAIN_AVP; }
<INITIAL>{SERVER_SIGNATURE}	{ count(); yylval.strval=yytext; return SERVER_SIGNATURE; }
<INITIAL>{SERVER_HEADER}	{ count(); yylval.strval=yytext; return SERVER_HEADER; }
<INITIAL>{USER_AGENT_HEADER}	{ count(); yylval.strval=yytext; return USER_AGENT_HEADER; }
<INITIAL>{ADVERTISED_ADDRESS}	{	count(); yylval.strval=yytext;
									return ADVERTISED_ADDRESS; }
<INITIAL>{ADVERTISED_PORT}		{	count(); yylval.strval=yytext;
									return ADVERTISED_PORT; }
<INITIAL>{DISABLE_CORE}		{	count(); yylval.strval=yytext;
									return DISABLE_CORE; }
<INITIAL>{OPEN_FD_LIMIT}	{	count(); yylval.strval=yytext;
									return OPEN_FD_LIMIT; }
<INITIAL>{MCAST_LOOPBACK}	{	count(); yylval.strval=yytext;
									return MCAST_LOOPBACK; }
<INITIAL>{MCAST_TTL}		{	count(); yylval.strval=yytext;
									return MCAST_TTL; }
<INITIAL>{TOS}				{	count(); yylval.strval=yytext;
									return TOS; }
<INITIAL>{DISABLE_DNS_FAILOVER}	{	count(); yylval.strval=yytext;
									return DISABLE_DNS_FAILOVER; }
<INITIAL>{DISABLE_DNS_BLACKLIST}	{	count(); yylval.strval=yytext;
									return DISABLE_DNS_BLACKLIST; }
<INITIAL>{DST_BLACKLIST}	{	count(); yylval.strval=yytext;
									return DST_BLACKLIST; }
<INITIAL>{DISABLE_STATELESS_FWD}	{	count(); yylval.strval=yytext;
									return DISABLE_STATELESS_FWD; }
<INITIAL>{DB_VERSION_TABLE}	{	count(); yylval.strval=yytext;
									return DB_VERSION_TABLE; }
<INITIAL>{DB_DEFAULT_URL}	{	count(); yylval.strval=yytext;
									return DB_DEFAULT_URL; }
<INITIAL>{DISABLE_503_TRANSLATION}	{	count(); yylval.strval=yytext;
									return DISABLE_503_TRANSLATION; }

<INITIAL>{MPATH}	   { count(); yylval.strval=yytext; return MPATH; }
<INITIAL>{LOADMODULE}  { count(); yylval.strval=yytext; return LOADMODULE; }
<INITIAL>{MODPARAM}    { count(); yylval.strval=yytext; return MODPARAM; }

<INITIAL>{EQUAL}	{ count(); return EQUAL; }
<INITIAL>{EQUAL_T}	{ count(); return EQUAL_T; }
<INITIAL>{GT}	{ count(); return GT; }
<INITIAL>{LT}	{ count(); return LT; }
<INITIAL>{GTE}	{ count(); return GTE; }
<INITIAL>{LTE}	{ count(); return LTE; }
<INITIAL>{DIFF}	{ count(); return DIFF; }
<INITIAL>{MATCH}	{ count(); return MATCH; }
<INITIAL>{NOTMATCH}	{ count(); return NOTMATCH; }
<INITIAL>{NOT}		{ count(); return NOT; }
<INITIAL>{AND}		{ count(); return AND; }
<INITIAL>{OR}		{ count(); return OR;  }
<INITIAL>{PLUS}		{ count(); return PLUS; }
<INITIAL>{MINUS}	{ count(); return MINUS; }
<INITIAL>{BAND}	{ count(); return BAND; }
<INITIAL>{BOR}	{ count(); return BOR; }
<INITIAL>{BXOR}	{ count(); return BXOR; }
<INITIAL>{BNOT}	{ count(); return BNOT; }
<INITIAL>{BLSHIFT}	{ count(); return BLSHIFT; }
<INITIAL>{BRSHIFT}	{ count(); return BRSHIFT; }
<INITIAL>{MULT}	{ count(); return MULT; }
<INITIAL>{MODULO}	{ count(); return MODULO; }
<INITIAL>{COLONEQ}	{ count(); return COLONEQ; }
<INITIAL>{PLUSEQ}	{ count(); return PLUSEQ; }
<INITIAL>{MINUSEQ}	{ count(); return MINUSEQ; }
<INITIAL>{SLASHEQ}	{ count(); return SLASHEQ; }
<INITIAL>{MULTEQ}	{ count(); return MULTEQ; }
<INITIAL>{MODULOEQ}	{ count(); return MODULOEQ; }
<INITIAL>{BANDEQ}	{ count(); return BANDEQ; }
<INITIAL>{BOREQ}	{ count(); return BOREQ; }
<INITIAL>{BXOREQ}	{ count(); return BXOREQ; }



<INITIAL>{IPV6ADDR}		{ count(); yylval.strval=yytext; return IPV6ADDR; }
<INITIAL>{NUMBER}		{ count(); yylval.intval=atoi(yytext);return NUMBER; }
<INITIAL>{HEXNUMBER}	{ count(); yylval.intval=(int)strtol(yytext, 0, 16);
							return NUMBER; }
<INITIAL>{OCTNUMBER}	{ count(); yylval.intval=(int)strtol(yytext, 0, 8);
							return NUMBER; }
<INITIAL>{YES}			{ count(); yylval.intval=1; return NUMBER; }
<INITIAL>{NO}			{ count(); yylval.intval=0; return NUMBER; }
<INITIAL>{NULLV}		{ count(); yylval.intval=0; return NULLV; }
<INITIAL>{TCP}			{ count(); return TCP; }
<INITIAL>{UDP}			{ count(); return UDP; }
<INITIAL>{TLS}			{ count(); return TLS; }
<INITIAL>{SCTP}			{ count(); return SCTP; }
<INITIAL>{INET}			{ count(); yylval.intval=AF_INET; return NUMBER; }
<INITIAL>{INET6}		{ count();
						#ifdef USE_IPV6
						  yylval.intval=AF_INET6;
						#else
						  yylval.intval=-1; /* no match*/
						#endif
						  return NUMBER; }
<INITIAL>{SSLv23}		{ count(); yylval.strval=yytext; return SSLv23; }
<INITIAL>{SSLv2}		{ count(); yylval.strval=yytext; return SSLv2; }
<INITIAL>{SSLv3}		{ count(); yylval.strval=yytext; return SSLv3; }
<INITIAL>{TLSv1}		{ count(); yylval.strval=yytext; return TLSv1; }

<INITIAL>{COMMA}		{ count(); return COMMA; }
<INITIAL>{SEMICOLON}	{ count(); return SEMICOLON; }
<INITIAL>{COLON}	{ count(); return COLON; }
<INITIAL>{RPAREN}	{ count(); return RPAREN; }
<INITIAL>{LPAREN}	{ count(); return LPAREN; }
<INITIAL>{LBRACE}	{ count(); return LBRACE; }
<INITIAL>{RBRACE}	{ count(); return RBRACE; }
<INITIAL>{LBRACK}	{ count(); return LBRACK; }
<INITIAL>{RBRACK}	{ count(); return RBRACK; }
<INITIAL>{AS}       { count(); return AS; }
<INITIAL>{DOT}		{ count(); return DOT; }
<INITIAL>\\{CR}		{count(); } /* eat the escaped CR */
<INITIAL>{CR}		{ count();/* return CR;*/ }
<INITIAL>{ANY}	{ count(); return ANY; }
<INITIAL>{SLASH}	{ count(); return SLASH; }

<INITIAL>{SCRIPTVAR_START} { count(); np=0; state=SCRIPTVAR_S;
								svar_tlen = yyleng;
								yymore();
								BEGIN(SCRIPTVARS);
							}
<SCRIPTVARS>{LPAREN} { count(); np++; yymore(); svar_tlen = yyleng; }
<SCRIPTVARS>{RPAREN} { 
			count();
			if(np==0 || np==1) {
				if(np==0)
				{
					addstr(&s_buf, yytext, yyleng-1);
					unput(yytext[yyleng-1]);
					yyleng--;
				} else {
					addstr(&s_buf, yytext, yyleng);
					np--;
				}
				state=INITIAL_S;
				BEGIN(INITIAL);
				yylval.strval=s_buf.s;
				memset(&s_buf, 0, sizeof(s_buf));
				return SCRIPTVAR;
			} else {
				np--;
				yymore();
				svar_tlen = yyleng;
			}
		}
<SCRIPTVARS>{WHITESPACE} {
			count();
			if(np==0) {
				addstr(&s_buf, yytext, yyleng-1);
				unput(yytext[yyleng-1]);
				yyleng--;
				state=INITIAL_S;
				BEGIN(INITIAL);
				yylval.strval=s_buf.s;
				memset(&s_buf, 0, sizeof(s_buf));
				return SCRIPTVAR;
			} else {
				yymore();
				svar_tlen = yyleng;
			}
		}
<SCRIPTVARS>{SEMICOLON}|{ASSIGNOP}|{ARITHOP}|{BITOP}|{LOGOP} {
						count();
						if(np==0) {
							addstr(&s_buf, yytext, svar_tlen);
							while(yyleng>svar_tlen) {
								unput(yytext[yyleng-1]);
								yyleng--;
							}
							state=INITIAL_S;
							BEGIN(INITIAL);
							yylval.strval=s_buf.s;
							memset(&s_buf, 0, sizeof(s_buf));
							return SCRIPTVAR;
						} else {
							yymore();
							svar_tlen = yyleng;
						}
				}
<SCRIPTVARS>.	{ yymore(); svar_tlen = yyleng; }

<INITIAL>{QUOTES} { count(); state=STRING_S; BEGIN(STRING1); }
<INITIAL>{TICK} { count(); state=STRING_S; BEGIN(STRING2); }


<STRING1>{QUOTES} { count(); state=INITIAL_S; BEGIN(INITIAL); 
						yytext[yyleng-1]=0; yyleng--;
						addstr(&s_buf, yytext, yyleng);
						yylval.strval=s_buf.s;
						memset(&s_buf, 0, sizeof(s_buf));
						return STRING;
					}
<STRING2>{TICK}  { count(); state=INITIAL_S; BEGIN(INITIAL); 
						yytext[yyleng-1]=0; yyleng--;
						addstr(&s_buf, yytext, yyleng);
						yylval.strval=s_buf.s;
						memset(&s_buf, 0, sizeof(s_buf));
						return STRING;
					}
<STRING2>.|{EAT_ABLE}|{CR}	{ yymore(); }

<STRING1>\\n		{ count(); addchar(&s_buf, '\n'); }
<STRING1>\\r		{ count(); addchar(&s_buf, '\r'); }
<STRING1>\\a		{ count(); addchar(&s_buf, '\a'); }
<STRING1>\\t		{ count(); addchar(&s_buf, '\t'); }
<STRING1>\\{QUOTES}	{ count(); addchar(&s_buf, '"');  }
<STRING1>\\\\		{ count(); addchar(&s_buf, '\\'); } 
<STRING1>\\x{HEX}{1,2}	{ count(); addchar(&s_buf, 
											(char)strtol(yytext+2, 0, 16)); }
 /* don't allow \[0-7]{1}, it will eat the backreferences from
    subst_uri if allowed (although everybody should use '' in subt_uri) */
<STRING1>\\[0-7]{2,3}	{ count(); addchar(&s_buf, 
											(char)strtol(yytext+1, 0, 8));  }
<STRING1>\\{CR}		{ count(); } /* eat escaped CRs */
<STRING1>{CR}	{ count();addchar(&s_buf, *yytext); }
<STRING1>.|{EAT_ABLE}|{CR}	{ addchar(&s_buf, *yytext); }


<INITIAL,COMMENT>{COM_START}	{ count(); comment_nest++; state=COMMENT_S;
										BEGIN(COMMENT); }
<COMMENT>{COM_END}				{ count(); comment_nest--;
										if (comment_nest==0){
											state=INITIAL_S;
											BEGIN(INITIAL);
										}
								}
<COMMENT>.|{EAT_ABLE}|{CR}				{ count(); };

<INITIAL>{COM_LINE}.*{CR}	{ count(); } 

<INITIAL>{ID}			{ count(); addstr(&s_buf, yytext, yyleng); 
									yylval.strval=s_buf.s;
									memset(&s_buf, 0, sizeof(s_buf));
									return ID; }


<<EOF>>							{
									switch(state){
										case STRING_S: 
											LM_CRIT("cfg. parser: unexpected EOF in"
														" unclosed string\n");
											if (s_buf.s){
												pkg_free(s_buf.s);
												memset(&s_buf, 0,
															sizeof(s_buf));
											}
											break;
										case COMMENT_S:
											LM_CRIT("cfg. parser: unexpected EOF:"
														" %d comments open\n", comment_nest);
											break;
										case COMMENT_LN_S:
											LM_CRIT("unexpected EOF:"
														"comment line open\n");
											break;
									}
									return 0;
								}
			
%%


static char* addchar(struct str_buf* dst, char c)
{
	return addstr(dst, &c, 1);
}



static char* addstr(struct str_buf* dst_b, char* src, int len)
{
	char *tmp;
	unsigned size;
	unsigned used;
	
	if (dst_b->left<(len+1)){
		used=(unsigned)(dst_b->crt-dst_b->s);
		size=used+len+1;
		/* round up to next multiple */
		size+= STR_BUF_ALLOC_UNIT-size%STR_BUF_ALLOC_UNIT;
		tmp=pkg_malloc(size);
		if (tmp==0) goto error;
		if (dst_b->s){
			memcpy(tmp, dst_b->s, used); 
			pkg_free(dst_b->s);
		}
		dst_b->s=tmp;
		dst_b->crt=dst_b->s+used;
		dst_b->left=size-used;
	}
	memcpy(dst_b->crt, src, len);
	dst_b->crt+=len;
	*(dst_b->crt)=0;
	dst_b->left-=len;
	
	return dst_b->s;
error:
	LM_CRIT("lex:addstr: memory allocation error\n");
	return 0;
}



static void count(void)
{
	int i;
	
	startcolumn=column;
	for (i=0; i<yyleng;i++){
		if (yytext[i]=='\n'){
			line++;
			column=startcolumn=1;
		}else if (yytext[i]=='\t'){
			column++;
			/*column+=8 -(column%8);*/
		}else{
			column++;
		}
	}
}

int yywrap(void) { return 1; }

