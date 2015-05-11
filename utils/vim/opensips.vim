" Vim syntax file
" Language:	OpenSIPS script
" Maintainer:	Liviu Chircu <liviu@opensips.org>
" Last Change:	2015 May 10

" Quit when a (custom) syntax file was already loaded
"if exists("b:current_syntax")
"  finish
"endif

"let s:cpo_save = &cpo
"set cpo&vim
"
" Useful scripting keywords
syn keyword	osStatement	return break exit
syn keyword	osLabel		case default esac
syn keyword	osConditional	if else switch
syn keyword	osRepeat		while for in
syn keyword osAction loadmodule modparam async

syn keyword osRoute route onreply_route failure_route branch_route
syn keyword osRoute startup_route timer_route event_route error_route

syn keyword specialOperand NULL null myself yes no true false enable disable on off
syn keyword specialOperand af INET inet INET6 inet6 uri status from_uri to_uri
syn keyword specialOperand src_ip src_port dst_ip dst_port proto method max_len

syn keyword osGlobalParam debug memdump memlog log_stderror log_facility log_name
syn keyword osGlobalParam fork children auto_aliases listen mpath
syn keyword osGlobalParam disable_tcp disable_tls check_via dns rev_dns tcp_children
syn keyword osGlobalParam tcp_send_timeout tcp_connect_timeout tcp_no_new_conn_bflag
syn keyword osGlobalParam disable_dns_failover disable_dns_blacklist dst_blacklist
syn keyword osGlobalParam exec_dns_threshold exec_msg_threshold tcpthreshold server_header
syn keyword osGlobalParam user_agent_header db_version_table use_children
syn keyword osGlobalParam advertised_address advertised_port disable_core_dump

" String constants
syn match	osSpecial		display contained "\\\(x\x\+\|\o\{1,3}\|.\|$\)"
syn match	osScriptVarC	/\$(\=[a-zA-Z_0-9]*/ contained
syn match	osScriptVar		/\$(\=[a-zA-Z_0-9]*/
syn region	osString	start=+"+ skip=+\\\\\|\\"+ end=+"+ extend contains=osSpecial,osScriptVarC

" Comments
"psyn region osScriptVar start='\$' end="\s\|(" nokeepend
"syn match osRouteStatement /route/
"syntax region osRouteStatement start=/route\s*\(\[\|{\)/ end=/\[\|{/me=s-1
syn region osCommentL start="#"		skip="\\$"	end="$" keepend
syn region osComment  start="/\*"				end="\*/" extend

"syn region osInteger start="/[0-9]+/" end="/[^\d]+/" keepend extend
syn match   osNumber     display "\<\d\+\>"
"syn region osIpAddr start="/[0-9]\{1,3}\.[0-9]\{1,3}\.[0-9]\{1,3}\.[0-9]\{1,3}/" end="" keepend extend

" Define the default highlighting.
" Only used when an item doesn't have highlighting yet
"hi def link osRouteStmt	Statement
"hi def link osIpAddr		String
hi def link osCommentL		osComment
hi def link osAction		osStatement
hi def link osStatement		Statement
hi def link osLabel			Label
hi def link osConditional	Conditional
hi def link osRepeat		Repeat
hi def link osRoute			Type
hi def link osGlobalParam	Statement
hi def link osComment		Comment
hi def link osString		String
hi def link osNumber		String
hi def link specialOperand	String
hi def link osScriptVarC	Type
hi def link osScriptVar   	Type
hi def link osSpecial   	SpecialChar


"let &cpo = s:cpo_save
"unlet s:cpo_save
