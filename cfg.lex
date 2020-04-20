/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
	#include "cfg_pp.h"
	#include "dprint.h"
	#include "globals.h"
	#include "mem/mem.h"
	#include <string.h>
	#include <stdlib.h>
	#include "ip_addr.h"
	#include "ut.h"


	/* states */
	#define INITIAL_S		0
	#define COMMENT_S		1
	#define COMMENT_LN_S	2
	#define STRING_S		3
	#define SCRIPTVAR_S		4

	#define STR_BUF_ALLOC_UNIT	128

	static int comment_nest=0;
	static int state=0;
	static str st;
	static struct str_buf s_buf;
	int line=1;
	int np=0;
	int svar_tlen=0;
	int column=1;
	int startcolumn=1;
	int startline=1;
	char *finame = 0;

	static char* addchar(struct str_buf *, char);
	static char* addstr(struct str_buf *, char*, int);
	static void count();

	/* hack to solve the duplicate declaration of 'isatty' function */
#if YY_FLEX_MAJOR_VERSION <= 2 && YY_FLEX_MINOR_VERSION <= 5 && YY_FLEX_SUBMINOR_VERSION < 36
	#define YY_NO_UNISTD_H
#else
	#include <unistd.h>
#endif

	/* hack to skip the declaration of lex unused function 'input' */
	#define YY_NO_INPUT

%}

/* start conditions */
%x STRING1 STRING2 COMMENT COMMENT_LN SCRIPTVARS
%x PPTOK_LINE PPTOK_FILEBEG PPTOK_FILEEND

/* action keywords */
ASSERT	"assert"
DROP	"drop"
EXIT	"exit"
RETURN	"return"
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
ROUTE_EVENT event_route
IF				"if"
ELSE			"else"
SWITCH			"switch"
CASE			"case"
DEFAULT			"default"
BREAK			"break"
WHILE			"while"
FOR             "for"
IN              "in"
XDBG			"xdbg"
PV_PRINT_BUF_SIZE	"pv_print_buf_size"
XLOG_BUF_SIZE	"xlog_buf_size"
XLOG_FORCE_COLOR	"xlog_force_color"
XLOG_PRINT_LEVEL	"xlog_print_level"
XLOG_LEVEL		"xlog_level"
XLOG			"xlog"
SYNC_TOKEN      "sync"
ASYNC_TOKEN     "async"
LAUNCH_TOKEN    "launch"
PPTOK_LINE      "__OSSPP_LINE__"
PPTOK_FILEBEG   "__OSSPP_FILEBEGIN__"
PPTOK_FILEEND   "__OSSPP_FILEEND__"

/*ACTION LVALUES*/
URIHOST			"uri:host"
URIPORT			"uri:port"

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
DEBUG_MODE	debug_mode
UDP_WORKERS	udp_workers
CHROOT		"chroot"
WDIR		"workdir"|"wdir"
DISABLE_CORE		"disable_core_dump"
OPEN_FD_LIMIT		"open_files_limit"
ENABLE_ASSERTS	enable_asserts
ABORT_ON_ASSERT	abort_on_assert
LOGLEVEL	log_level
LOGSTDERROR	log_stderror
LOGFACILITY	log_facility
LOGNAME		log_name
LISTEN		listen
SOCKET		socket
MEMGROUP	mem-group
ALIAS		alias
AUTO_ALIASES	auto_aliases
TAG		 tag
DNS		 dns
REV_DNS	 rev_dns
DNS_TRY_IPV6    dns_try_ipv6
DNS_TRY_NAPTR   dns_try_naptr
DNS_RETR_TIME   dns_retr_time
DNS_RETR_NO     dns_retr_no
DNS_SERVERS_NO  dns_servers_no
DNS_USE_SEARCH  dns_use_search_list
MAXBUFFER maxbuffer
CHECK_VIA	check_via
SHM_HASH_SPLIT_PERCENTAGE "shm_hash_split_percentage"
SHM_SECONDARY_HASH_SIZE "shm_secondary_hash_size"
MEM_WARMING_ENABLED "mem_warming"|"mem_warming_enabled"
MEM_WARMING_PATTERN_FILE "mem_warming_pattern_file"
MEM_WARMING_PERCENTAGE "mem_warming_percentage"
RPM_MEM_FILE "restart_persistency_cache_file"
RPM_MEM_SIZE "restart_persistency_size"
MEMLOG		"memlog"|"mem_log"
MEMDUMP		"memdump"|"mem_dump"
EXECMSGTHRESHOLD		"execmsgthreshold"|"exec_msg_threshold"
EXECDNSTHRESHOLD		"execdnsthreshold"|"exec_dns_threshold"
TCPTHRESHOLD			"tcpthreshold"|"tcp_threshold"
EVENT_SHM_THRESHOLD		"event_shm_threshold"
EVENT_PKG_THRESHOLD		"event_pkg_threshold"
QUERYBUFFERSIZE			query_buffer_size
QUERYFLUSHTIME			query_flush_time
SIP_WARNING sip_warning
SERVER_SIGNATURE server_signature
SERVER_HEADER server_header
USER_AGENT_HEADER user_agent_header
MHOMED		mhomed
POLL_METHOD		"poll_method"
TCP_WORKERS		"tcp_workers"
TCP_ACCEPT_ALIASES	"tcp_accept_aliases"
TCP_CONNECT_TIMEOUT	"tcp_connect_timeout"
TCP_CON_LIFETIME    "tcp_connection_lifetime"
TCP_LISTEN_BACKLOG   "tcp_listen_backlog"
TCP_SOCKET_BACKLOG   "tcp_socket_backlog"
TCP_MAX_CONNECTIONS "tcp_max_connections"
TCP_NO_NEW_CONN_BFLAG "tcp_no_new_conn_bflag"
TCP_NO_NEW_CONN_RPLFLAG "tcp_no_new_conn_rplflag"
TCP_KEEPALIVE           "tcp_keepalive"
TCP_KEEPCOUNT           "tcp_keepcount"
TCP_KEEPIDLE            "tcp_keepidle"
TCP_KEEPINTERVAL        "tcp_keepinterval"
TCP_MAX_MSG_TIME		"tcp_max_msg_time"
ADVERTISED_ADDRESS	"advertised_address"
ADVERTISED_PORT		"advertised_port"
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
DB_MAX_ASYNC_CONNECTIONS "db_max_async_connections"
DISABLE_503_TRANSLATION "disable_503_translation"
AUTO_SCALING_PROFILE "auto_scaling_profile"
AUTO_SCALING_CYCLE "auto_scaling_cycle"
TIMER_WORKERS "timer_workers"

MPATH	mpath
LOADMODULE	loadmodule
MODPARAM        modparam

/* values */
YES			"yes"|"true"|"on"|"enable"
NO			"no"|"false"|"off"|"disable"
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
IPV4ADDR	{NUMBER}\.{NUMBER}\.{NUMBER}\.{NUMBER}
QUOTES		\"
TICK		\'
SLASH		"/"
AS			{EAT_ABLE}("as"|"AS"){EAT_ABLE}
USE_WORKERS	{EAT_ABLE}("use_workers"|"USE_WORKERS"){EAT_ABLE}
USE_AUTO_SCALING_PROFILE {EAT_ABLE}("use_auto_scaling_profile"|"USE_AUTO_SCALING_PROFILE"){EAT_ABLE}
SCALE_UP_TO		{EAT_ABLE}("scale"|"SCALE"){EAT_ABLE}+("up"|"UP"){EAT_ABLE}+("to"|"TO"){EAT_ABLE}
SCALE_DOWN_TO	{EAT_ABLE}("scale"|"SCALE"){EAT_ABLE}+("down"|"DOWN"){EAT_ABLE}+("to"|"TO"){EAT_ABLE}
ON			{EAT_ABLE}("on"|"ON"){EAT_ABLE}
CYCLES		{EAT_ABLE}("cycles"|"CYCLES")
CYCLES_WITHIN	{EAT_ABLE}("cycles"|"CYCLES"){EAT_ABLE}+("within"|"WITHIN"){EAT_ABLE}
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
ANYCAST "anycast"


COM_LINE	#
COM_START	"/\*"
COM_END		"\*/"

EAT_ABLE	[\ \t\b\r]
WHITESPACE	[ \t\r\n]
SPACE		[ ]

%%


<INITIAL>{EAT_ABLE}	{ count(); }

<INITIAL>{ASSERT}	{count(); yylval.strval=yytext; return ASSERT; }
<INITIAL>{DROP}	{ count(); yylval.strval=yytext; return DROP; }
<INITIAL>{EXIT}	{ count(); yylval.strval=yytext; return EXIT; }
<INITIAL>{RETURN}	{ count(); yylval.strval=yytext; return RETURN; }
<INITIAL>{LOG}	{ count(); yylval.strval=yytext; return LOG_TOK; }
<INITIAL>{ERROR}	{ count(); yylval.strval=yytext; return ERROR; }
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
<INITIAL>{ROUTE_EVENT}	{ count(); yylval.strval=yytext;
								return ROUTE_EVENT; }
<INITIAL>{IF}	{ count(); yylval.strval=yytext; return IF; }
<INITIAL>{ELSE}	{ count(); yylval.strval=yytext; return ELSE; }

<INITIAL>{SWITCH}	{ count(); yylval.strval=yytext; return SWITCH; }
<INITIAL>{CASE}		{ count(); yylval.strval=yytext; return CASE; }
<INITIAL>{DEFAULT}	{ count(); yylval.strval=yytext; return DEFAULT; }
<INITIAL>{BREAK}	{ count(); yylval.strval=yytext; return BREAK; }
<INITIAL>{WHILE}	{ count(); yylval.strval=yytext; return WHILE; }
<INITIAL>{FOR}		{ count(); yylval.strval=yytext; return FOR; }
<INITIAL>{IN}		{ count(); yylval.strval=yytext; return IN; }

<INITIAL>{PPTOK_LINE}  { count(); BEGIN(PPTOK_LINE); }
<INITIAL>{PPTOK_FILEBEG}  { count(); BEGIN(PPTOK_FILEBEG); }
<INITIAL>{PPTOK_FILEEND}  { count(); BEGIN(PPTOK_FILEEND); }

<INITIAL>{XDBG}				{	count(); yylval.strval=yytext;
									return XDBG; }
<INITIAL>{PV_PRINT_BUF_SIZE}	{	count(); yylval.strval=yytext;
									return PV_PRINT_BUF_SIZE; }
<INITIAL>{XLOG}				{	count(); yylval.strval=yytext;
									return XLOG; }
<INITIAL>{XLOG_BUF_SIZE}	{	count(); yylval.strval=yytext;
									return XLOG_BUF_SIZE; }
<INITIAL>{XLOG_FORCE_COLOR}	{	count(); yylval.strval=yytext;
									return XLOG_FORCE_COLOR;}
<INITIAL>{XLOG_PRINT_LEVEL}	{	count(); yylval.strval=yytext;
									return XLOG_PRINT_LEVEL;}
<INITIAL>{XLOG_LEVEL}		{	count(); yylval.strval=yytext;
									return XLOG_LEVEL;}
<INITIAL>{SYNC_TOKEN}		{ count(); yylval.strval=yytext;
									return SYNC_TOKEN;}
<INITIAL>{ASYNC_TOKEN}		{ count(); yylval.strval=yytext;
									return ASYNC_TOKEN;}
<INITIAL>{LAUNCH_TOKEN}		{ count(); yylval.strval=yytext;
									return LAUNCH_TOKEN;}

<INITIAL>{DEBUG_MODE}	{ count(); yylval.strval=yytext; return DEBUG_MODE; }
<INITIAL>{UDP_WORKERS}	{ count(); yylval.strval=yytext; return UDP_WORKERS; }
<INITIAL>{CHROOT}	{ count(); yylval.strval=yytext; return CHROOT; }
<INITIAL>{WDIR}	{ count(); yylval.strval=yytext; return WDIR; }
<INITIAL>{DISABLE_CORE}		{	count(); yylval.strval=yytext;
									return DISABLE_CORE; }
<INITIAL>{OPEN_FD_LIMIT}	{	count(); yylval.strval=yytext;
									return OPEN_FD_LIMIT; }

<INITIAL>{ENABLE_ASSERTS}	{ count(); yylval.strval=yytext; return ENABLE_ASSERTS; }
<INITIAL>{ABORT_ON_ASSERT}	{ count(); yylval.strval=yytext; return ABORT_ON_ASSERT; }
<INITIAL>{LOGLEVEL} { count(); yylval.strval=yytext; return LOGLEVEL; }
<INITIAL>{LOGSTDERROR}	{ yylval.strval=yytext; return LOGSTDERROR; }
<INITIAL>{LOGFACILITY}	{ yylval.strval=yytext; return LOGFACILITY; }
<INITIAL>{LOGNAME}	{ yylval.strval=yytext; return LOGNAME; }
<INITIAL>{LISTEN}	{ count(); yylval.strval=yytext; return LISTEN; }
<INITIAL>{SOCKET}	{ count(); yylval.strval=yytext; return SOCKET; }
<INITIAL>{MEMGROUP}	{ count(); yylval.strval=yytext; return MEMGROUP; }
<INITIAL>{ALIAS}	{ count(); yylval.strval=yytext; return ALIAS; }
<INITIAL>{AUTO_ALIASES}	{ count(); yylval.strval=yytext; return AUTO_ALIASES; }
<INITIAL>{DNS}	{ count(); yylval.strval=yytext; return DNS; }
<INITIAL>{TAG}	{ count(); yylval.strval=yytext; return TAG; }
<INITIAL>{REV_DNS}	{ count(); yylval.strval=yytext; return REV_DNS; }
<INITIAL>{DNS_TRY_IPV6}		{ count(); yylval.strval=yytext;
								return DNS_TRY_IPV6; }
<INITIAL>{DNS_TRY_NAPTR}	{ count(); yylval.strval=yytext;
								return DNS_TRY_NAPTR; }
<INITIAL>{DNS_RETR_TIME}	{ count(); yylval.strval=yytext;
								return DNS_RETR_TIME; }
<INITIAL>{DNS_RETR_NO}		{ count(); yylval.strval=yytext;
								return DNS_RETR_NO; }
<INITIAL>{DNS_SERVERS_NO}	{ count(); yylval.strval=yytext;
								return DNS_SERVERS_NO; }
<INITIAL>{DNS_USE_SEARCH}	{ count(); yylval.strval=yytext;
								return DNS_USE_SEARCH; }
<INITIAL>{MAX_WHILE_LOOPS}	{ count(); yylval.strval=yytext;
								return MAX_WHILE_LOOPS; }
<INITIAL>{MAXBUFFER}	{ count(); yylval.strval=yytext; return MAXBUFFER; }
<INITIAL>{CHECK_VIA}	{ count(); yylval.strval=yytext; return CHECK_VIA; }
<INITIAL>{SHM_HASH_SPLIT_PERCENTAGE}	{ count(); yylval.strval=yytext; return SHM_HASH_SPLIT_PERCENTAGE; }
<INITIAL>{SHM_SECONDARY_HASH_SIZE}	{ count(); yylval.strval=yytext; return SHM_SECONDARY_HASH_SIZE; }
<INITIAL>{MEM_WARMING_ENABLED}	{ count(); yylval.strval=yytext; return MEM_WARMING_ENABLED; }
<INITIAL>{MEM_WARMING_PATTERN_FILE}	{ count(); yylval.strval=yytext; return MEM_WARMING_PATTERN_FILE; }
<INITIAL>{MEM_WARMING_PERCENTAGE}	{ count(); yylval.strval=yytext; return MEM_WARMING_PERCENTAGE; }
<INITIAL>{RPM_MEM_FILE}	{ count(); yylval.strval=yytext; return RPM_MEM_FILE; }
<INITIAL>{RPM_MEM_SIZE}	{ count(); yylval.strval=yytext; return RPM_MEM_SIZE; }
<INITIAL>{MEMLOG}	{ count(); yylval.strval=yytext; return MEMLOG; }
<INITIAL>{MEMDUMP}	{ count(); yylval.strval=yytext; return MEMDUMP; }
<INITIAL>{EXECMSGTHRESHOLD}	{ count(); yylval.strval=yytext; return EXECMSGTHRESHOLD; }
<INITIAL>{EXECDNSTHRESHOLD}	{ count(); yylval.strval=yytext; return EXECDNSTHRESHOLD; }
<INITIAL>{TCPTHRESHOLD}	{ count(); yylval.strval=yytext; return TCPTHRESHOLD; }
<INITIAL>{EVENT_SHM_THRESHOLD}	{ count(); yylval.strval=yytext; return EVENT_SHM_THRESHOLD; }
<INITIAL>{EVENT_PKG_THRESHOLD}	{ count(); yylval.strval=yytext; return EVENT_PKG_THRESHOLD; }
<INITIAL>{QUERYBUFFERSIZE}	{ count(); yylval.strval=yytext; return QUERYBUFFERSIZE; }
<INITIAL>{QUERYFLUSHTIME}	{ count(); yylval.strval=yytext; return QUERYFLUSHTIME; }
<INITIAL>{SIP_WARNING}	{ count(); yylval.strval=yytext; return SIP_WARNING; }
<INITIAL>{MHOMED}	{ count(); yylval.strval=yytext; return MHOMED; }
<INITIAL>{TCP_NO_NEW_CONN_BFLAG}    { count(); yylval.strval=yytext; return TCP_NO_NEW_CONN_BFLAG; }
<INITIAL>{TCP_NO_NEW_CONN_RPLFLAG}    { count(); yylval.strval=yytext; return TCP_NO_NEW_CONN_RPLFLAG; }
<INITIAL>{TCP_WORKERS}	{ count(); yylval.strval=yytext; return TCP_WORKERS; }
<INITIAL>{TCP_ACCEPT_ALIASES}	{ count(); yylval.strval=yytext;
									return TCP_ACCEPT_ALIASES; }
<INITIAL>{TCP_CONNECT_TIMEOUT}		{ count(); yylval.strval=yytext;
									return TCP_CONNECT_TIMEOUT; }
<INITIAL>{TCP_CON_LIFETIME}		{ count(); yylval.strval=yytext;
									return TCP_CON_LIFETIME; }
<INITIAL>{TCP_LISTEN_BACKLOG}   { count(); yylval.strval=yytext;
									return TCP_LISTEN_BACKLOG; }
<INITIAL>{TCP_SOCKET_BACKLOG}   { count(); yylval.strval=yytext;
									return TCP_SOCKET_BACKLOG; }
<INITIAL>{POLL_METHOD}			{ count(); yylval.strval=yytext;
									return POLL_METHOD; }
<INITIAL>{TCP_MAX_CONNECTIONS}  { count(); yylval.strval=yytext;
									return TCP_MAX_CONNECTIONS; }
<INITIAL>{TCP_KEEPALIVE}       { count(); yylval.strval=yytext; return TCP_KEEPALIVE; }
<INITIAL>{TCP_KEEPCOUNT}       { count(); yylval.strval=yytext; return TCP_KEEPCOUNT; }
<INITIAL>{TCP_KEEPIDLE}        { count(); yylval.strval=yytext; return TCP_KEEPIDLE; }
<INITIAL>{TCP_KEEPINTERVAL}    { count(); yylval.strval=yytext; return TCP_KEEPINTERVAL; }
<INITIAL>{TCP_MAX_MSG_TIME}    { count(); yylval.strval=yytext; return TCP_MAX_MSG_TIME; }
<INITIAL>{SERVER_SIGNATURE}	{ count(); yylval.strval=yytext; return SERVER_SIGNATURE; }
<INITIAL>{SERVER_HEADER}	{ count(); yylval.strval=yytext; return SERVER_HEADER; }
<INITIAL>{USER_AGENT_HEADER}	{ count(); yylval.strval=yytext; return USER_AGENT_HEADER; }
<INITIAL>{ADVERTISED_ADDRESS}	{	count(); yylval.strval=yytext;
									return ADVERTISED_ADDRESS; }
<INITIAL>{ADVERTISED_PORT}		{	count(); yylval.strval=yytext;
									return ADVERTISED_PORT; }
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
<INITIAL>{DB_MAX_ASYNC_CONNECTIONS}	{	count(); yylval.strval=yytext;
									return DB_MAX_ASYNC_CONNECTIONS; }
<INITIAL>{DISABLE_503_TRANSLATION}	{	count(); yylval.strval=yytext;
									return DISABLE_503_TRANSLATION; }
<INITIAL>{AUTO_SCALING_PROFILE}	{	count(); yylval.strval=yytext;
									return AUTO_SCALING_PROFILE; }
<INITIAL>{AUTO_SCALING_CYCLE}	{	count(); yylval.strval=yytext;
									return AUTO_SCALING_CYCLE; }
<INITIAL>{TIMER_WORKERS}	{	count(); yylval.strval=yytext;
									return TIMER_WORKERS; }

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
<INITIAL>{IPV4ADDR}		{ count(); yylval.strval=yytext; return IPV4ADDR; }

<INITIAL>{IPV4ADDR}{SLASH}{NUMBER}|{IPV4ADDR}{SLASH}{IPV4ADDR}|{IPV6ADDR}{SLASH}{NUMBER}|{IPV6ADDR}{SLASH}{IPV6ADDR} {
				count(); yylval.strval=yytext; return IPNET; }

<INITIAL>{NUMBER}		{ count(); yylval.intval=atoi(yytext);return NUMBER; }
<INITIAL>{HEXNUMBER}	{ count(); yylval.intval=(int)strtol(yytext, 0, 16);
							return NUMBER; }
<INITIAL>{OCTNUMBER}	{ count(); yylval.intval=(int)strtol(yytext, 0, 8);
							return NUMBER; }
<INITIAL>{YES}			{ count(); yylval.intval=1; return NUMBER; }
<INITIAL>{NO}			{ count(); yylval.intval=0; return NUMBER; }
<INITIAL>{NULLV}		{ count(); yylval.intval=0; return NULLV; }

<INITIAL>{COMMA}		{ count(); return COMMA; }
<INITIAL>{SEMICOLON}	{ count(); return SEMICOLON; }
<INITIAL>{USE_WORKERS}  { count(); return USE_WORKERS; }
<INITIAL>{USE_AUTO_SCALING_PROFILE}  { count(); return USE_AUTO_SCALING_PROFILE; }
<INITIAL>{COLON}	{ count(); return COLON; }
<INITIAL>{RPAREN}	{ count(); return RPAREN; }
<INITIAL>{LPAREN}	{ count(); return LPAREN; }
<INITIAL>{LBRACE}	{ count(); return LBRACE; }
<INITIAL>{RBRACE}	{ count(); return RBRACE; }
<INITIAL>{LBRACK}	{ count(); return LBRACK; }
<INITIAL>{RBRACK}	{ count(); return RBRACK; }
<INITIAL>{AS}		{ count(); return AS; }
<INITIAL>{DOT}		{ count(); return DOT; }
<INITIAL>\\{CR}		{count(); } /* eat the escaped CR */
<INITIAL>{CR}		{ count();/* return CR;*/ }
<INITIAL>{ANY}		{ count(); return ANY; }
<INITIAL>{ANYCAST}	{ count(); return ANYCAST; }
<INITIAL>{SLASH}	{ count(); return SLASH; }
<INITIAL>{SCALE_UP_TO}		{ count(); return SCALE_UP_TO; }
<INITIAL>{SCALE_DOWN_TO}	{ count(); return SCALE_DOWN_TO; }
<INITIAL>{ON}				{ count(); return ON; }
<INITIAL>{CYCLES}			{ count(); return CYCLES; }
<INITIAL>{CYCLES_WITHIN}	{ count(); return CYCLES_WITHIN; }

<INITIAL>{SCRIPTVAR_START} { np=0; state=SCRIPTVAR_S;
								svar_tlen = yyleng;
								yymore();
								BEGIN(SCRIPTVARS);
							}
<SCRIPTVARS>{LPAREN} { np++; yymore(); svar_tlen = yyleng; }
<SCRIPTVARS>{RPAREN} {
			if(np==0 || np==1) {
				count();
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
			if(np==0) {
				count();
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
<SCRIPTVARS>{SEMICOLON}|{COMMA}|{ASSIGNOP}|{ARITHOP}|{BITOP}|{LOGOP} {
						if(np==0) {
							count();
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
<STRING2>.|{EAT_ABLE}	{ addchar(&s_buf, *yytext); }
<STRING2>{CR}	{ count(); if (!eatback_pp_tok(&s_buf))
								addchar(&s_buf, *yytext); }

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
<STRING1>\\{CR}		{ count(); eatback_pp_tok(&s_buf); } /* eat escaped CRs */
<STRING1>{CR}	{ count(); if (!eatback_pp_tok(&s_buf))
								addchar(&s_buf, *yytext); }
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
<PPTOK_LINE>{SPACE}[^\n]+ { /* grab the line number */
		st.s = yytext + 1;
		st.len = yyleng - 1;
		if (str2int(&st, (unsigned int *)&line) != 0) {
			LM_CRIT("bad line number integer: '%.*s'\n", st.len, st.s);
			exit(-1);
		}
		BEGIN(INITIAL);
}

<PPTOK_FILEBEG>{SPACE}{QUOTES}.*{QUOTES} { /* grab the file path */
		st.s = yytext + 2;
		st.len = yyleng - 3;
		if (cfg_push(&st) != 0) {
			LM_ERR("max nested includes reached!\n");
			exit(-1);
		}
		BEGIN(INITIAL);
}

<PPTOK_FILEEND>{CR} {
		if (cfg_pop() != 0) {
			LM_ERR("internal error during cfg_pop()\n");
			exit(-1);
		}
		BEGIN(INITIAL);
}

<<EOF>>							{
									switch(state){
										case STRING_S:
											LM_CRIT("unexpected EOF in"
														" unclosed string\n");
											if (s_buf.s){
												pkg_free(s_buf.s);
												memset(&s_buf, 0,
															sizeof(s_buf));
											}
											break;
										case COMMENT_S:
											LM_CRIT("unexpected EOF in"
														" %d comments open\n", comment_nest);
											break;
										case COMMENT_LN_S:
											LM_CRIT("unexpected EOF in"
														"comment line open\n");
											break;
										case SCRIPTVAR_S:
											LM_CRIT("unexpected EOF in"
														" unclosed variable\n");
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
