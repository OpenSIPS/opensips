#
# OpenSIPS residential configuration script
#     by OpenSIPS Solutions <team@opensips-solutions.com>
#
# This script was generated via "make menuconfig", from
#   the "Residential" scenario.
# You can enable / disable more features / functionalities by
#   re-generating the scenario with different options.#
#
# Please refer to the Core CookBook at:
#      http://www.opensips.org/Resources/DocsCookbooks
# for a explanation of possible statements, functions and parameters.
#


####### Global Parameters #########

log_level=3
log_stderror=no
log_facility=LOG_LOCAL0

children=4

/* uncomment the following lines to enable debugging */
#debug_mode=yes

/* uncomment the next line to enable the auto temporary blacklisting of 
   not available destinations (default disabled) */
#disable_dns_blacklist=no

/* uncomment the next line to enable IPv6 lookup after IPv4 dns 
   lookup failures (default disabled) */
#dns_try_ipv6=yes

/* comment the next line to enable the auto discovery of local aliases
   based on revers DNS on IPs */
auto_aliases=no


listen=udp:127.0.0.1:5060   # CUSTOMIZE ME

ifelse(ENABLE_TCP, `yes', `listen=tcp:127.0.0.1:5060   # CUSTOMIZE ME' , `')
ifelse(ENABLE_TLS,`yes',`listen=tls:127.0.0.1:5061   # CUSTOMIZE ME' , `')

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


#### URI module
loadmodule "uri.so"
modparam("uri", "use_uri_table", 0)

ifelse(USE_DR_PSTN,`yes',` ifelse(HAVE_INBOUND_PSTN,`yes',`define(`USE_DR_MODULE',`yes')',HAVE_OUTBOUND_PSTN,`yes',`define(`USE_DR_MODULE',`yes')',) ', `')

ifelse(USE_AUTH,`yes',`define(`DB_NEEDED',`yes')',USE_MULTIDOMAIN,`yes',`define(`DB_NEEDED',`yes')',USE_PRESENCE,`yes',`define(`DB_NEEDED',`yes')',USE_DBACC,`yes',`define(`DB_NEEDED',`yes')',USE_DBUSRLOC,`yes',`define(`DB_NEEDED',`yes')',USE_DIALOG,`yes',`define(`DB_NEEDED',`yes')',USE_DIALPLAN,`yes',`define(`DB_NEEDED',`yes')',USE_DR_MODULE,`yes',`define(`DB_NEEDED',`yes')',)

ifelse(USE_HTTP_MANAGEMENT_INTERFACE,`yes',`define(`HTTPD_NEEDED',`yes')', `')

ifdef(`DB_NEEDED',`#### MYSQL module
loadmodule "db_mysql.so"')

ifdef(`HTTPD_NEEDED',`#### HTTPD module
loadmodule "httpd.so"
modparam("httpd", "port", 8888)')

#### USeR LOCation module
loadmodule "usrloc.so"
modparam("usrloc", "nat_bflag", "NAT")
ifelse(USE_DBUSRLOC,`yes',`modparam("usrloc", "db_mode",   2)
modparam("usrloc", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
', `modparam("usrloc", "db_mode",   0)')

#### REGISTRAR module
loadmodule "registrar.so"
modparam("registrar", "tcp_persistent_flag", "TCP_PERSISTENT")
ifelse(USE_NAT,`yes',`modparam("registrar", "received_avp", "$avp(received_nh)")',`')
/* uncomment the next line not to allow more than 10 contacts per AOR */
#modparam("registrar", "max_contacts", 10)

#### ACCounting module
loadmodule "acc.so"
/* what special events should be accounted ? */
modparam("acc", "early_media", 0)
modparam("acc", "report_cancels", 0)
/* by default we do not adjust the direct of the sequential requests.
   if you enable this parameter, be sure the enable "append_fromtag"
   in "rr" module */
modparam("acc", "detect_direction", 0)
ifelse(USE_DBACC,`yes',`modparam("acc", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
', `')

ifelse(USE_AUTH,`yes',`#### AUTHentication modules
loadmodule "auth.so"
loadmodule "auth_db.so"
modparam("auth_db", "calculate_ha1", yes)
modparam("auth_db", "password_column", "password")
modparam("auth_db|uri", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
modparam("auth_db", "load_credentials", "")
', `')

ifelse(USE_ALIASES,`yes',`#### ALIAS module
loadmodule "alias_db.so"
modparam("alias_db", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
', `')

ifelse(USE_MULTIDOMAIN,`yes',`#### DOMAIN module
loadmodule "domain.so"
modparam("domain", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
modparam("domain", "db_mode", 1)   # Use caching
modparam("auth_db|usrloc|uri", "use_domain", 1)
', `')

ifelse(USE_PRESENCE,`yes',`#### PRESENCE modules
loadmodule "xcap.so"
loadmodule "presence.so"
loadmodule "presence_xml.so"
modparam("xcap|presence", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
modparam("presence_xml", "force_active", 1)
modparam("presence", "server_address", "sip:127.0.0.1:5060") # CUSTOMIZE ME
', `')

ifelse(USE_DIALOG,`yes',`#### DIALOG module
loadmodule "dialog.so"
modparam("dialog", "dlg_match_mode", 1)
modparam("dialog", "default_timeout", 21600)  # 6 hours timeout
modparam("dialog", "db_mode", 2)
modparam("dialog", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
',`')

ifelse(USE_NAT,`yes',`####  NAT modules
loadmodule "nathelper.so"
modparam("nathelper", "natping_interval", 10)
modparam("nathelper", "ping_nated_only", 1)
modparam("nathelper", "sipping_bflag", "SIP_PING_FLAG")
modparam("nathelper", "sipping_from", "sip:pinger@127.0.0.1") #CUSTOMIZE ME
modparam("nathelper", "received_avp", "$avp(received_nh)")

loadmodule "rtpproxy.so"
modparam("rtpproxy", "rtpproxy_sock", "udp:localhost:12221") # CUSTOMIZE ME
',`')

ifelse(USE_DIALPLAN,`yes',`####  DIALPLAN module
loadmodule "dialplan.so"
modparam("dialplan", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
',`')

ifelse(USE_DR_MODULE,`yes',`####  DYNAMMIC ROUTING module
loadmodule "drouting.so"
modparam("drouting", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
',`')

ifelse(USE_HTTP_MANAGEMENT_INTERFACE,`yes',`####  MI_HTTP module
loadmodule "mi_http.so"
',`')

loadmodule "proto_udp.so"

ifelse(ENABLE_TCP, `yes', `loadmodule "proto_tcp.so"' , `')
ifelse(ENABLE_TLS, `yes', `loadmodule "proto_tls.so"
loadmodule "tls_mgm.so"
modparam("tls_mgm","verify_cert", "1")
modparam("tls_mgm","require_cert", "0")
modparam("tls_mgm","tls_method", "TLSv1")
modparam("tls_mgm","certificate", "/usr/local/etc/opensips/tls/user/user-cert.pem")
modparam("tls_mgm","private_key", "/usr/local/etc/opensips/tls/user/user-privkey.pem")
modparam("tls_mgm","ca_list", "/usr/local/etc/opensips/tls/user/user-calist.pem")

' , `')

####### Routing Logic ########

# main request routing logic

route{
	ifelse(USE_NAT,`yes',`force_rport();
	if (nat_uac_test("23")) {
		if (is_method("REGISTER")) {
			fix_nated_register();
			setbflag(NAT);
		} else {
			fix_nated_contact();
			setflag(NAT);
		}
	}
 	',`')

	if (!mf_process_maxfwd_header("10")) {
		sl_send_reply("483","Too Many Hops");
		exit;
	}

	if (has_totag()) {
		# sequential request withing a dialog should
		# take the path determined by record-routing
		if (loose_route()) {
			ifelse(USE_DIALOG,`yes',`
			# validate the sequential request against dialog
			if ( $DLG_status!=NULL && !validate_dialog() ) {
				xlog("In-Dialog $rm from $si (callid=$ci) is not valid according to dialog\n");
				## exit;
			}
			',`')
			if (is_method("BYE")) {
				# do accounting even if the transaction fails
				ifelse(USE_DBACC,`yes',`do_accounting("db","failed");
				', `do_accounting("log","failed");')
			} else if (is_method("INVITE")) {
				# even if in most of the cases is useless, do RR for
				# re-INVITEs alos, as some buggy clients do change route set
				# during the dialog.
				record_route();
			}

			ifelse(USE_NAT,`yes',`if (check_route_param("nat=yes")) 
				setflag(NAT);',`')

			# route it out to whatever destination was set by loose_route()
			# in $du (destination URI).
			route(relay);
		} else {
			ifelse(USE_PRESENCE,`yes',
			`if (is_method("SUBSCRIBE") && $rd == "127.0.0.1:5060") { # CUSTOMIZE ME
				# in-dialog subscribe requests
				route(handle_presence);
				exit;
			}',`')
			if ( is_method("ACK") ) {
				if ( t_check_trans() ) {
					# non loose-route, but stateful ACK; must be an ACK after 
					# a 487 or e.g. 404 from upstream server
					t_relay();
					exit;
				} else {
					# ACK without matching transaction ->
					# ignore and discard
					exit;
				}
			}
			sl_send_reply("404","Not here");
		}
		exit;
	}

	# CANCEL processing
	if (is_method("CANCEL"))
	{
		if (t_check_trans())
			t_relay();
		exit;
	}

	t_check_trans();

	if ( !(is_method("REGISTER") ifelse(HAVE_INBOUND_PSTN,`yes',` ifelse(USE_DR_MODULE,`yes',`|| is_from_gw()',`|| (src_ip==11.22.33.44 && src_port=5060 /* CUSTOMIZE ME */)')',`') ) ) {
		ifelse(USE_MULTIDOMAIN,`yes',`
		if (is_from_local())',`
		if (from_uri==myself)
		')
		{
			ifelse(USE_AUTH,`yes',`
			# authenticate if from local subscriber
			# authenticate all initial non-REGISTER request that pretend to be
			# generated by local subscriber (domain from FROM URI is local)
			if (!proxy_authorize("", "subscriber")) {
				proxy_challenge("", "0");
				exit;
			}
			if (!db_check_from()) {
				sl_send_reply("403","Forbidden auth ID");
				exit;
			}
		
			consume_credentials();
			# caller authenticated
			',`')
		} else {
			# if caller is not local, then called number must be local
			ifelse(USE_MULTIDOMAIN,`yes',`
			if (!is_uri_host_local())',`
			if (!uri==myself)') {
				send_reply("403","Rely forbidden");
				exit;
			}
		}

	}

	# preloaded route checking
	if (loose_route()) {
		xlog("L_ERR",
		"Attempt to route with preloaded Route's [$fu/$tu/$ru/$ci]");
		if (!is_method("ACK"))
			sl_send_reply("403","Preload Route denied");
		exit;
	}

	# record routing
	if (!is_method("REGISTER|MESSAGE"))
		record_route();

	# account only INVITEs
	if (is_method("INVITE")) {
		ifelse(USE_DIALOG,`yes',`
		# create dialog with timeout
		if ( !create_dialog("B") ) {
			send_reply("500","Internal Server Error");
			exit;
		}
		',`')
		ifelse(USE_DBACC,`yes',`do_accounting("db");
		', `do_accounting("log");')
	}

	ifelse(USE_MULTIDOMAIN,`yes',`
	if (!is_uri_host_local())',`
	if (!uri==myself)') {
		append_hf("P-hint: outbound\r\n"); 
		ifelse(ENABLE_TLS,`yes',`
		# if you have some interdomain connections via TLS
		## CUSTOMIZE IF NEEDED
		##if ($rd=="tls_domain1.net"
		## || $rd=="tls_domain2.net"
		##) {
		##	force_send_socket(tls:127.0.0.1:5061); # CUSTOMIZE
		##}
		',`')
		route(relay);
	}

	# requests for my domain
	ifelse(USE_PRESENCE,`yes',`
	if( is_method("PUBLISH|SUBSCRIBE"))
			route(handle_presence);',`
	if (is_method("PUBLISH|SUBSCRIBE"))
	{
		sl_send_reply("503", "Service Unavailable");
		exit;
	}')

	if (is_method("REGISTER"))
	{
		ifelse(USE_AUTH,`yes',`# authenticate the REGISTER requests
		if (!www_authorize("", "subscriber"))
		{
			www_challenge("", "0");
			exit;
		}
		
		if (!db_check_to()) 
		{
			sl_send_reply("403","Forbidden auth ID");
			exit;
		}',`')

		if ( ifelse(ENABLE_TCP,`yes',`proto==TCP ||',`') ifelse(ENABLE_TLS,`yes',`proto==TLS ||',`') 0 ) setflag(TCP_PERSISTENT);

		ifelse(USE_NAT,`yes',`if (isflagset(NAT)) {
			setbflag(SIP_PING_FLAG);
		}',`')

		if (!save("location"))
			sl_reply_error();

		exit;
	}

	if ($rU==NULL) {
		# request with no Username in RURI
		sl_send_reply("484","Address Incomplete");
		exit;
	}

	ifelse(USE_ALIASES,`yes',`
	# apply DB based aliases
	alias_db_lookup("dbaliases");',`')

	ifelse(USE_DIALPLAN,`yes',`
	# apply transformations from dialplan table
	dp_translate("0","$rU/$rU");',`')

	ifelse(HAVE_OUTBOUND_PSTN,`yes',`
	if ($rU=~"^\+[1-9][0-9]+$") {
		ifelse(USE_DR_MODULE,`yes',`
		if (!do_routing("0")) {
			send_reply("500","No PSTN Route found");
			exit;
		}
		',`
		$rd="11.22.33.44"; CUSTOMIZE ME
		$rp=5060;
		')
		route(relay);
		exit;
	}
	',`') 

	# do lookup with method filtering
	if (!lookup("location","m")) {
		ifelse(USE_AUTH,`yes',`if (!db_does_uri_exist()) {
			send_reply("420","Bad Extension");
			exit;
		}',`')
		ifelse(VM_DIVERSION,`yes',`
		# redirect to a different VM system
		$du = "sip:127.0.0.2:5060"; # CUSTOMIZE ME
		route(relay);
		',`
		t_newtran();
		t_reply("404", "Not Found");
		exit;')
	} 

	ifelse(USE_NAT,`yes',`if (isbflagset(NAT)) setflag(NAT);',`')

	# when routing via usrloc, log the missed calls also
	ifelse(USE_DBACC,`yes',`do_accounting("db","missed");
	', `do_accounting("log","missed");')
	route(relay);
}


route[relay] {
	# for INVITEs enable some additional helper routes
	if (is_method("INVITE")) {
		
		ifelse(USE_NAT,`yes',`if (isflagset(NAT)) {
			rtpproxy_offer("ro");
		}',`')

		t_on_branch("per_branch_ops");
		t_on_reply("handle_nat");
		t_on_failure("missed_call");
	}

	ifelse(USE_NAT,`yes',`if (isflagset(NAT)) {
		add_rr_param(";nat=yes");
		}',`')

	if (!t_relay()) {
		send_reply("500","Internal Error");
	};
	exit;
}

ifelse(USE_PRESENCE,`yes',`
# Presence route
route[handle_presence]
{
	if (!t_newtran())
	{
		sl_reply_error();
		exit;
	}

	if(is_method("PUBLISH"))
	{
		handle_publish();
	}
	else
	if( is_method("SUBSCRIBE"))
	{
		handle_subscribe();
	}

	exit;
}',`')


branch_route[per_branch_ops] {
	xlog("new branch at $ru\n");
}


onreply_route[handle_nat] {
	ifelse(USE_NAT,`yes',`if (nat_uac_test("1"))
		fix_nated_contact();
	if ( isflagset(NAT) )
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
	##t_reply("404","Not found");
	##	exit;
	##}

	ifelse(VM_DIVERSION,`yes',`
	# redirect the failed to a different VM system
	if (t_check_status("486|408")) {
		$du = "sip:127.0.0.2:5060"; # CUSTOMIZE ME
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
