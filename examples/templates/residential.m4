#
# OpenSIPS residential configuration script
#     by OpenSIPS Solutions <team@opensips-solutions.com>
#
# Edit the feature definitions below to customize this configuration.
# Start OpenSIPS with:
#   opensips -f examples/templates/residential.m4 -p m4
#
# Please refer to the OpenSIPS Manuals at:
#      https://opensips.org/Documentation/Manuals
# for an explanation of available statements, functions and parameters.
#

divert(-1)
define(`LISTEN_IP', `127.0.0.1') # IP address or interface used by the SIP sockets
define(`DB_URL', `mysql://opensips:opensipsrw@localhost/opensips') # Database URL used by modules
define(`NATPING_FROM', `sip:pinger@127.0.0.1') # From URI used by NAT keepalive requests
define(`RTPPROXY_SOCKET', `udp:localhost:12221') # RTPProxy control socket
define(`PSTN_IP', `11.22.33.44') # Statically configured PSTN gateway address
define(`PSTN_PORT', `5060') # Statically configured PSTN gateway port
define(`VOICEMAIL_URI', `sip:127.0.0.2:5060') # Voicemail server destination
define(`TLS_DOMAIN_1', `tls_domain1.net') # First domain routed over the forced TLS socket
define(`TLS_DOMAIN_2', `tls_domain2.net') # Second domain routed over the forced TLS socket
define(`TLS_SEND_SOCKET', `tls:LISTEN_IP:5061') # Forced socket for interdomain TLS traffic
define(`ENABLE_TCP', `no') # OpenSIPS will listen on TCP for SIP requests
define(`ENABLE_TLS', `no') # OpenSIPS will listen on TLS for SIP requests
define(`USE_ALIASES', `no') # OpenSIPS will allow the use of Aliases for SIP users
define(`USE_AUTH', `no') # OpenSIPS will authenticate Register & Invite requests
define(`USE_DBACC', `no') # OpenSIPS will save ACC entries in DB for all calls
define(`USE_DBUSRLOC', `no') # OpenSIPS will store UsrLoc entries in the DB
define(`USE_DIALOG', `no') # OpenSIPS will keep track of active dialogs
define(`USE_MULTIDOMAIN', `no') # OpenSIPS will handle multiple domains for subscribers
define(`USE_NAT', `no') # OpenSIPS will try to cope with NAT by fixing SIP msgs and engaging RTPProxy
define(`USE_PRESENCE', `no') # OpenSIPS will act as a Presence server
define(`USE_DIALPLAN', `no') # OpenSIPS will use dialplan for transformation of local numbers
define(`VM_DIVERSION', `no') # OpenSIPS will redirect to VM calls not reaching the subscribers
define(`HAVE_INBOUND_PSTN', `no') # OpenSIPS will accept calls from PSTN gateways (with static IP authentication)
define(`HAVE_OUTBOUND_PSTN', `no') # OpenSIPS will send numerical dials to PSTN gateways (with static IP definition)
define(`USE_DR_PSTN', `no') # OpenSIPS will use Dynamic Routing Support for PSTN interconnection
define(`USE_HTTP_MANAGEMENT_INTERFACE', `no') # OpenSIPS will provide a WEB Management Interface on port 8888
divert(0)dnl

####### Global Parameters #########

/* uncomment the following lines to enable debugging */
#debug_mode=yes

log_level=3
xlog_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0

udp_workers=4

/* uncomment the next line to enable the auto temporary blacklisting of 
   not available destinations (default disabled) */
#disable_dns_blacklist=no

/* uncomment the next line to enable IPv6 lookup after IPv4 dns 
   lookup failures (default disabled) */
#dns_try_ipv6=yes


socket=udp:LISTEN_IP:5060
ifelse(ENABLE_TCP, `yes', `socket=tcp:LISTEN_IP:5060', `')
ifelse(ENABLE_TLS,`yes',`socket=tls:LISTEN_IP:5061', `')

####### Modules Section ########

#set module path
mpath="/usr/local/lib/opensips/modules/"

#### SIGNALING module
loadmodule "signaling.so"

#### StateLess module
loadmodule "sl.so"

#### Transaction Module
loadmodule "tm.so"
modparam("tm", "fr_timeout", 5)
modparam("tm", "fr_inv_timeout", 30)
modparam("tm", "restart_fr_on_each_reply", 0)
modparam("tm", "onreply_avp_mode", 1)

#### Record Route Module
loadmodule "rr.so"
/* do not append from tag to the RR (no need for this script) */
modparam("rr", "append_fromtag", 0)

#### MAX ForWarD module
loadmodule "maxfwd.so"

#### SIP MSG OPerationS module
loadmodule "sipmsgops.so"

#### FIFO Management Interface
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")
modparam("mi_fifo", "fifo_mode", 0666)

ifelse(USE_DR_PSTN,`yes',`ifelse(HAVE_INBOUND_PSTN,`yes',`define(`USE_DR_MODULE',`yes')',HAVE_OUTBOUND_PSTN,`yes',`define(`USE_DR_MODULE',`yes')',)',`')dnl
ifelse(USE_AUTH,`yes',`define(`DB_NEEDED',`yes')',USE_MULTIDOMAIN,`yes',`define(`DB_NEEDED',`yes')',USE_PRESENCE,`yes',`define(`DB_NEEDED',`yes')',USE_DBACC,`yes',`define(`DB_NEEDED',`yes')',USE_DBUSRLOC,`yes',`define(`DB_NEEDED',`yes')',USE_DIALOG,`yes',`define(`DB_NEEDED',`yes')',USE_DIALPLAN,`yes',`define(`DB_NEEDED',`yes')',USE_DR_MODULE,`yes',`define(`DB_NEEDED',`yes')',)dnl
ifelse(USE_HTTP_MANAGEMENT_INTERFACE,`yes',`define(`HTTPD_NEEDED',`yes')',`')dnl
ifdef(`DB_NEEDED',`#### MYSQL module
loadmodule "db_mysql.so"

')dnl
ifdef(`HTTPD_NEEDED',`#### HTTPD module
loadmodule "httpd.so"
modparam("httpd", "port", 8888)

')dnl
#### USeR LOCation module
loadmodule "usrloc.so"
modparam("usrloc", "nat_bflag", "NAT")
ifelse(USE_DBUSRLOC,`yes',`modparam("usrloc", "working_mode_preset", "single-instance-sql-write-back")
modparam("usrloc", "db_url", "DB_URL")
', `modparam("usrloc", "working_mode_preset", "single-instance-no-db")')

#### REGISTRAR module
loadmodule "registrar.so"
modparam("registrar", "tcp_persistent_flag", "TCP_PERSISTENT")
ifelse(USE_NAT,`yes',`modparam("registrar", "received_avp", "$avp(received_nh)")',`')dnl
/* uncomment the next line not to allow more than 10 contacts per AOR */
#modparam("registrar", "max_contacts", 10)

#### ACCounting module
loadmodule "acc.so"
/* what special events should be accounted ? */
modparam("acc", "early_media", 0)
modparam("acc", "report_cancels", 0)
/* by default we do not adjust the direct of the sequential requests.
   if you enable this parameter, be sure to enable "append_fromtag"
   in "rr" module */
modparam("acc", "detect_direction", 0)
ifelse(USE_DBACC,`yes',`modparam("acc", "db_url", "DB_URL")
', `')dnl

ifelse(USE_AUTH,`yes',`#### AUTHentication modules
loadmodule "auth.so"
loadmodule "auth_db.so"
modparam("auth_db", "calculate_ha1", yes)
modparam("auth_db", "password_column", "password")
modparam("auth_db", "db_url", "DB_URL")
modparam("auth_db", "load_credentials", "")

', `')dnl
ifelse(USE_ALIASES,`yes',`#### ALIAS module
loadmodule "alias_db.so"
modparam("alias_db", "db_url", "DB_URL")

', `')dnl
ifelse(USE_MULTIDOMAIN,`yes',`#### DOMAIN module
loadmodule "domain.so"
modparam("domain", "db_url", "DB_URL")
modparam("domain", "db_mode", 1)   # Use caching
modparam("auth_db|usrloc", "use_domain", 1)

', `')dnl
ifelse(USE_PRESENCE,`yes',`#### PRESENCE modules
loadmodule "xcap.so"
loadmodule "presence.so"
loadmodule "presence_xml.so"
modparam("xcap|presence", "db_url", "DB_URL")
modparam("presence_xml", "force_active", 1)
modparam("presence", "fallback2db", 0)

', `')dnl
ifelse(USE_DIALOG,`yes',`#### DIALOG module
loadmodule "dialog.so"
modparam("dialog", "dlg_match_mode", 1)
modparam("dialog", "default_timeout", 21600)  # 6 hours timeout
modparam("dialog", "db_mode", 2)
modparam("dialog", "db_url", "DB_URL")

',`')dnl
ifelse(USE_NAT,`yes',`####  NAT modules
loadmodule "nathelper.so"
modparam("nathelper", "natping_interval", 10)
modparam("nathelper", "ping_nated_only", 1)
modparam("nathelper", "sipping_bflag", "SIP_PING_FLAG")
modparam("nathelper", "sipping_from", "NATPING_FROM")
modparam("nathelper", "received_avp", "$avp(received_nh)")

loadmodule "rtpproxy.so"
modparam("rtpproxy", "rtpproxy_sock", "RTPPROXY_SOCKET")

',`')dnl
ifelse(USE_DIALPLAN,`yes',`####  DIALPLAN module
loadmodule "dialplan.so"
modparam("dialplan", "db_url", "DB_URL")

',`')dnl
ifelse(USE_DR_MODULE,`yes',`####  DYNAMMIC ROUTING module
loadmodule "drouting.so"
modparam("drouting", "db_url", "DB_URL")

',`')dnl
ifelse(USE_HTTP_MANAGEMENT_INTERFACE,`yes',`####  MI_HTTP module
loadmodule "mi_http.so"

',`')dnl
loadmodule "proto_udp.so"
ifelse(ENABLE_TCP, `yes', `loadmodule "proto_tcp.so"' , `')
ifelse(ENABLE_TLS, `yes', `loadmodule "proto_tls.so"
loadmodule "tls_wolfssl.so"
loadmodule "tls_mgm.so"
modparam("tls_mgm","server_domain", "default")
modparam("tls_mgm","match_ip_address", "[default]*")
modparam("tls_mgm","verify_cert", "[default]1")
modparam("tls_mgm","require_cert", "[default]0")
modparam("tls_mgm","tls_method", "[default]TLSv1")
modparam("tls_mgm","certificate", "[default]/etc/opensips/tls/user/user-cert.pem")
modparam("tls_mgm","private_key", "[default]/etc/opensips/tls/user/user-privkey.pem")
modparam("tls_mgm","ca_list", "[default]/etc/opensips/tls/user/user-calist.pem")
' , `')dnl

####### Routing Logic ########

# main request routing logic

route{
ifelse(USE_NAT,`yes',`
	# initial NAT handling; detect if the request comes from behind a NAT
	# and apply contact fixing
	force_rport();
	if (nat_uac_test("diff-port-src-via,private-via,diff-ip-src-via,private-contact")) {
		if (is_method("REGISTER")) {
			fix_nated_register();
			setbflag("NAT");
		} else {
			fix_nated_contact();
			setflag("NAT");
		}
	}
',`')dnl

	if (!mf_process_maxfwd_header(10)) {
		send_reply(483,"Too Many Hops");
		exit;
	}

	if (has_totag()) {

		# handle hop-by-hop ACK (no routing required)
		if ( is_method("ACK") && t_check_trans() ) {
			t_relay();
			exit;
		}

		# sequential request within a dialog should
		# take the path determined by record-routing
		if ( !loose_route() ) {
ifelse(USE_PRESENCE,`yes',
`			if (is_method("SUBSCRIBE") && is_myself("$rd")) {
				# in-dialog subscribe requests
				route(handle_presence);
				exit;
			}
',`')dnl
			# we do record-routing for all our traffic, so we should not
			# receive any sequential requests without Route hdr.
			send_reply(404,"Not here");
			exit;
		}
ifelse(USE_DIALOG,`yes',`
		# validate the sequential request against dialog
		if ( $DLG_status!=NULL && !validate_dialog() ) {
			xlog("In-Dialog $rm from $si (callid=$ci) is not valid according to dialog\n");
			## exit;
		}
',`')dnl

		if (is_method("BYE")) {
			# do accounting even if the transaction fails
			ifelse(USE_DBACC,`yes',`do_accounting("db","failed");
			', `do_accounting("log","failed");')
		}

ifelse(USE_NAT,`yes',`
		if (check_route_param("nat=yes")) 
			setflag("NAT");
',`')dnl
		# route it out to whatever destination was set by loose_route()
		# in $du (destination URI).
		route(relay);
		exit;
	}

	# CANCEL processing
	if (is_method("CANCEL")) {
		if (t_check_trans())
			t_relay();
		exit;
	}

	# absorb retransmissions, but do not create transaction
	t_check_trans();

	if ( !(is_method("REGISTER") ifelse(HAVE_INBOUND_PSTN,`yes',` ifelse(USE_DR_MODULE,`yes',`|| is_from_gw()',`|| ($si==PSTN_IP && $sp=PSTN_PORT)')',`') ) ) {
		ifelse(USE_MULTIDOMAIN,`yes',`
		if (is_from_local()) {',`
		if (is_myself("$fd")) {
		')dnl
			ifelse(USE_AUTH,`yes',`
			# authenticate if from local subscriber
			# authenticate all initial non-REGISTER request that pretend to be
			# generated by local subscriber (domain from FROM URI is local)
			if (!proxy_authorize("", "subscriber")) {
				proxy_challenge("", "auth");
				exit;
			}
			if ($au!=$fU) {
				send_reply(403,"Forbidden auth ID");
				exit;
			}

			consume_credentials();
			# caller authenticated
			',`')
		} else {
			# if caller is not local, then called number must be local
			ifelse(USE_MULTIDOMAIN,`yes',`
			if (!is_uri_host_local())',`
			if (!is_myself("$rd"))') {
				send_reply(403,"Relay Forbidden");
				exit;
			}
		}

	}

	# preloaded route checking
	if (loose_route()) {
		xlog("L_ERR",
			"Attempt to route with preloaded Route's [$fu/$tu/$ru/$ci]");
		if (!is_method("ACK"))
			send_reply(403,"Preload Route denied");
		exit;
	}

	# record routing
	if (!is_method("REGISTER|MESSAGE"))
		record_route();

	# account only INVITEs
	if (is_method("INVITE")) {
		ifelse(USE_DIALOG,`yes',`
		# create dialog with timeout
		if ( !create_dialog("bye-on-timeout") ) {
			send_reply(500,"Internal Server Error");
			exit;
		}
		',`')
		ifelse(USE_DBACC,`yes',`do_accounting("db");
		', `do_accounting("log");')
	}

	ifelse(USE_MULTIDOMAIN,`yes',`
	if (!is_uri_host_local())',`
	if (!is_myself("$rd"))') {
		append_hf("P-hint: outbound\r\n"); 
		ifelse(ENABLE_TLS,`yes',`
		# if you have some interdomain connections via TLS
		##if ($rd=="TLS_DOMAIN_1"
		## || $rd=="TLS_DOMAIN_2"
		##) {
		##	force_send_socket("TLS_SEND_SOCKET");
		##}
		',`')
		route(relay);
	}

	# requests for my domain
	ifelse(USE_PRESENCE,`yes',`
	if( is_method("PUBLISH|SUBSCRIBE"))
			route(handle_presence);',`
	if (is_method("PUBLISH|SUBSCRIBE")) {
		send_reply(503, "Service Unavailable");
		exit;
	}')

	if (is_method("REGISTER")) {
		ifelse(USE_AUTH,`yes',`# authenticate the REGISTER requests
		if (!www_authorize("", "subscriber")) {
			www_challenge("", "auth");
			exit;
		}
		
		if ($au!=$tU) {
			send_reply(403,"Forbidden auth ID");
			exit;
		}',`')dnl
ifelse(ENABLE_TCP, `yes', ifelse(ENABLE_TLS, `yes', `
		if ($socket_in(proto) == "tcp" || $socket_in(proto) == "tls")
			setflag("TCP_PERSISTENT");
', `
		if ($socket_in(proto) == "tcp")
			setflag("TCP_PERSISTENT");
'), ifelse(ENABLE_TLS, `yes', `
		if ($socket_in(proto) == "tls")
			setflag("TCP_PERSISTENT");
',
`'))dnl
		ifelse(USE_NAT,`yes',`if (isflagset("NAT")) {
			setbflag("SIP_PING_FLAG");
		}',`')dnl

		# store the registration and generate a SIP reply
		if (!save("location"))
			xlog("failed to register AoR $tu\n");

		exit;
	}

	if ($rU==NULL) {
		# request with no Username in RURI
		send_reply(484,"Address Incomplete");
		exit;
	}

	ifelse(USE_ALIASES,`yes',`
	# apply DB based aliases
	alias_db_lookup("dbaliases");',`')

	ifelse(USE_DIALPLAN,`yes',`
	# apply transformations from dialplan table
	dp_translate( 0, "$rU", $rU);',`')

	ifelse(HAVE_OUTBOUND_PSTN,`yes',`
	if ($rU=~"^\+[1-9][0-9]+$") {
		ifelse(USE_DR_MODULE,`yes',`
		strip(1);
		if (!do_routing(0)) {
			send_reply(500,"No PSTN Route found");
			exit;
		}
		',`
		$rd="PSTN_IP";
		$rp=PSTN_PORT;
		')
		route(relay);
		exit;
	}
	',`') 

	# do lookup with method filtering
	if (!lookup("location", "method-filtering")) {
		ifelse(USE_AUTH,`yes',`if (!db_does_uri_exist("$ru","subscriber")) {
			send_reply(420,"Bad Extension");
			exit;
		}',`')
		ifelse(VM_DIVERSION,`yes',`
		# redirect to a different VM system
		$du = "VOICEMAIL_URI";
		route(relay);
		',`
		t_reply(404, "Not Found");
		exit;')
	} 

	ifelse(USE_NAT,`yes',`if (isbflagset("NAT")) setflag("NAT");',`')

	# when routing via usrloc, log the missed calls also
	ifelse(USE_DBACC,`yes',`do_accounting("db","missed");
	', `do_accounting("log","missed");')
	route(relay);
}


route[relay] {
	# for INVITEs enable some additional helper routes
	if (is_method("INVITE")) {
		
		ifelse(USE_NAT,`yes',`if (isflagset("NAT") && has_body("application/sdp")) {
			rtpproxy_offer("ro");
		}',`')

		t_on_branch("per_branch_ops");
		t_on_reply("handle_nat");
		t_on_failure("missed_call");
	}

	ifelse(USE_NAT,`yes',`if (isflagset("NAT")) {
		add_rr_param(";nat=yes");
	}',`')

	if (!t_relay()) {
		send_reply(500,"Internal Error");
	}
	exit;
}

ifelse(USE_PRESENCE,`yes',`
# Presence route
route[handle_presence]
{
	if (!t_newtran()) {
		sl_reply_error();
		exit;
	}

	if(is_method("PUBLISH")) {
		handle_publish();
	} else
	if( is_method("SUBSCRIBE")) {
		handle_subscribe();
	}

	exit;
}',`')


branch_route[per_branch_ops] {
	xlog("new branch at $ru\n");
}


onreply_route[handle_nat] {
	ifelse(USE_NAT,`yes',`if (nat_uac_test("private-contact"))
		fix_nated_contact();
	if ( isflagset("NAT") && has_body("application/sdp") )
		rtpproxy_answer("ro");',`')
	xlog("incoming reply\n");
}


failure_route[missed_call] {
	if (t_was_cancelled()) {
		exit;
	}

	# uncomment the following lines if you want to block client 
	# redirect based on 3xx replies.
	##if (t_check_status("3[0-9][0-9]")) {
	##t_reply(404,"Not found");
	##	exit;
	##}

	ifelse(VM_DIVERSION,`yes',`
	# redirect the failed to a different VM system
	if (t_check_status("486|408")) {
		$du = "VOICEMAIL_URI";
		# do not set the missed call flag again
		route(relay);
	}',`')
}


ifelse(USE_DIALOG,`yes',`
local_route {
	if (is_method("BYE") && $DLG_dir=="UPSTREAM") {
		ifelse(USE_DBACC,`yes',`
		acc_db_request("200 Dialog Timeout", "acc");
		',`
		acc_log_request("200 Dialog Timeout");
		')
	}
}',`')
