" Vim syntax file
" Language:	OpenSIPS 2.4 script
" Maintainer:	Liviu Chircu <liviu@opensips.org>
" Last Change:	2017 Jul 30

" Quit when a (custom) syntax file was already loaded
"if exists("b:current_syntax")
"  finish
"endif

"let s:cpo_save = &cpo
"set cpo&vim
"
" Useful scripting keywords
syn keyword	osStatement	return break exit drop
syn keyword	osLabel		case default esac
syn keyword	osConditional	if else switch and or not
syn keyword	osRepeat		while for in
syn keyword osAction loadmodule modparam async launch

syn keyword specialOperand yes no true false enable disable on off NULL null
syn keyword specialOperand UDP TCP TLS SCTP WS WSS HEP_TCP HEP_UDP INET inet INET6 inet6

syn keyword osGlobalParam log_level memdump memlog log_stderror log_facility log_name
syn keyword osGlobalParam debug_mode children auto_aliases listen mpath tcp_children
syn keyword osGlobalParam disable_tcp disable_tls check_via dns rev_dns
syn keyword osGlobalParam tcp_send_timeout tcp_connect_timeout tcp_no_new_conn_bflag
syn keyword osGlobalParam disable_dns_failover disable_dns_blacklist dst_blacklist
syn keyword osGlobalParam exec_dns_threshold exec_msg_threshold tcpthreshold
syn keyword osGlobalParam xlog_buf_size xlog_force_color enable_asserts
syn keyword osGlobalParam user_agent_header db_version_table use_children
syn keyword osGlobalParam advertised_address advertised_port disable_core_dump
syn keyword osGlobalParam db_max_async_connections include_file avp_aliases
syn keyword osGlobalParam bin_listen bin_children alias dns_try_ipv6 dns_try_naptr
syn keyword osGlobalParam dns_retr_time dns_retr_no dns_servers_no maxbuffer
syn keyword osGlobalParam dns_use_search_list shm_hash_split_percentage
syn keyword osGlobalParam shm_secondary_hash_size mem_warming mem_warming_enabled
syn keyword osGlobalParam mem_warming_pattern_file mem_warming_percentage
syn keyword osGlobalParam mem_log mem_dump execmsgthreshold execdnsthreshold
syn keyword osGlobalParam dns_use_search_list shm_hash_split_percentage
syn keyword osGlobalParam tcp_threshold tcpthreshold event_shm_threshold
syn keyword osGlobalParam event_pkg_threshold query_buffer_size tcp_children
syn keyword osGlobalParam query_flush_time sip_warning server_signature
syn keyword osGlobalParam user uid group gid chroot workdir wdir mhomed
syn keyword osGlobalParam poll_method tcp_accept_aliases tcp_connection_lifetime
syn keyword osGlobalParam tcp_listen_backlog tcp_max_connections tcp_keepalive
syn keyword osGlobalParam tcp_keepcount tcp_keepidle tcp_keepinterval
syn keyword osGlobalParam open_files_limit mcast_loopback mcast_ttl tos
syn keyword osGlobalParam max_while_loops disable_stateless_fwd db_default_url
syn keyword osGlobalParam disable_503_translation import_file server_header
syn keyword osGlobalParam tcp_max_msg_time abort_on_assert

" String constants
syn match	osSpecial	contained 	display "\\\(x\x\+\|\o\{1,3}\|.\|$\)"

" OpenSIPS-specific constructs
syn match	osLogFacility	/LOG_\(AUTH\|CRON\|DAEMON\|KERN\|LOCAL[0-7]\|LPR\|MAIL\|NEWS\|USER\|UUCP\|AUTHPRIV\|FTP\|SYSLOG\)/
syn match	osRouteStmt	/^\s*\(\(onreply\|failure\|branch\|local\|startup\|timer\|event\|error\)_\)\=route\(\s\|\n\)*\(\[\|{\)/he=e-1
syn match	osTransfm	contained /{[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z]\+[a-zA-Z0-9]*[^}]*}\+/
syn region	osVarCtx	contained	matchgroup=ctxHi start="<" end="\(request\|reply\)>"
syn region	osVarIndex	contained	start="\[" end="]" contains=osNumber,osVarNamed,osVarNamedS,osVarCon,osVarCtx,osTransfm

" OpenSIPS variables
"	TODO: fix me with full list of OS vars (for better validation!)
syn region	osVarCon	contained matchgroup=varHi start="[a-zA-Z_0-9]\+(" end=")"

syn region	osVar		matchgroup=varHi start="\$(" end=")" contains=osVarCtx,osVarCon,osTransfm,osVarIndex
syn region	osVarNamed	matchgroup=varHi start="\$[a-zA-Z_0-9]\+(" end=")"
syn match	osVarNamedS	/\$[a-zA-Z_0-9]\+[^a-zA-Z_0-9(]/me=e-1,he=e-1

syn region	osString	start=+"+ skip=+\\\\\|\\"+ end=+"+ extend contains=osSpecial,osVar,osVarNamed,osVarNamedS

" Comments
syn region	osCommentL	keepend start="#"	skip="\\$"	end="$"
syn region	osComment	extend start="/\*"				end="\*/"

syn match	osNumber	display "\<\d\+\>"

" Define the default highlighting.
" Only used when an item doesn't have highlighting yet
hi def link varHi			Type
hi def link ctxHi			Comment
hi def link osVarSimple		Type
hi def link osVar			Type
hi def link osVarNamedS   	Type
hi def link osVarIndex   	Type
hi def link osRouteStmt		Type
hi def link osLogFacility	specialOperand
hi def link osTransfm		Special
hi def link osCommentL		osComment
hi def link osAction		osStatement
hi def link osStatement		Statement
hi def link osLabel			Label
hi def link osConditional	Conditional
hi def link osRepeat		Repeat
hi def link osGlobalParam	Statement
hi def link osComment		Comment
hi def link osString		String
hi def link osNumber		String
hi def link specialOperand	String
hi def link osSpecial   	SpecialChar


"let &cpo = s:cpo_save
"unlet s:cpo_save
