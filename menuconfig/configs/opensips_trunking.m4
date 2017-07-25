#
# OpenSIPS trunking script
#     by OpenSIPS Solutions <team@opensips-solutions.com>
#
# This script was generated via "make menuconfig", from
#   the "Trunking" scenario.
# You can enable / disable more features / functionalities by
#   re-generating the scenario with different options.
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

ifelse(USE_HTTP_MANAGEMENT_INTERFACE,`yes',`define(`HTTPD_NEEDED',`yes')', `')

####### Modules Section ########

#set module path
mpath="/usr/local/lib/opensips/modules/"

ifdef(`HTTPD_NEEDED',`#### HTTPD module
loadmodule "httpd.so"
modparam("httpd", "port", 8888)')

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

#### SIP MSG OPerations module
loadmodule "sipmsgops.so"

#### FIFO Management Interface
loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/tmp/opensips_fifo")
modparam("mi_fifo", "fifo_mode", 0666)

#### URI module
loadmodule "uri.so"
modparam("uri", "use_uri_table", 0)

#### MYSQL module
loadmodule "db_mysql.so"

#### AVPOPS module
loadmodule "avpops.so"

####  DYNAMIC ROUTING module
loadmodule "drouting.so"
modparam("drouting", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME

####  PERMISSIONS module
loadmodule "permissions.so"
modparam("permissions", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME

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

ifelse(USE_DIALOG,`yes',`#### DIALOG module
loadmodule "dialog.so"
modparam("dialog", "dlg_match_mode", 1)
modparam("dialog", "default_timeout", 21600)  # 6 hours timeout
modparam("dialog", "db_mode", 2)
modparam("dialog", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips") # CUSTOMIZE ME
ifelse(DO_CALL_LIMITATION,`yes',`
modparam("dialog", "profiles_with_value", "trunkCalls")
',`')
',`')

ifelse(USE_DIALPLAN,`yes',`####  DIALPLAN module
loadmodule "dialplan.so"
modparam("dialplan", "db_url",
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

	if (!mf_process_maxfwd_header("10")) {
		sl_send_reply("483","Too Many Hops");
		exit;
	}

	if ( check_source_address("1","$avp(trunk_attrs)") ) {
		# request comes from trunks
		setflag(IS_TRUNK);
	} else if ( is_from_gw() ) {
		# request comes from GWs
	} else {
		send_reply("403","Forbidden");
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

			# route it out to whatever destination was set by loose_route()
			# in $du (destination URI).
			route(RELAY);
		} else {
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

	#### INITIAL REQUESTS

	if ( !isflagset(IS_TRUNK) ) {
		## accept new calls only from trunks
		send_reply("403","Not from trunk");
		exit;
	}

	# CANCEL processing
	if (is_method("CANCEL")) {
		if (t_check_trans())
			t_relay();
		exit;
	} else if (!is_method("INVITE")) {
		send_reply("405","Method Not Allowed");
		exit;
	}

	if ($rU==NULL) {
		# request with no Username in RURI
		sl_send_reply("484","Address Incomplete");
		exit;
	}

	t_check_trans();

	# preloaded route checking
	if (loose_route()) {
		xlog("L_ERR",
		"Attempt to route with preloaded Route's [$fu/$tu/$ru/$ci]");
		if (!is_method("ACK"))
			sl_send_reply("403","Preload Route denied");
		exit;
	}

	# record routing
	record_route();

	ifelse(USE_DBACC,`yes',`do_accounting("db");
	', `do_accounting("log");')

	ifelse(USE_DIALOG,`yes',`
	# create dialog with timeout
	if ( !create_dialog("B") ) {
		send_reply("500","Internal Server Error");
		exit;
	}

	ifelse(DO_CALL_LIMITATION,`yes',`
	if (is_avp_set("$avp(trunk_attrs)") && $avp(trunk_attrs)=~"^[0-9]+$") {
		get_profile_size("trunkCalls","$si","$var(size)");
		if ( $(var(size){s.int}) >= $(avp(trunk_attrs){s.int}) ) {
			send_reply("486","Busy Here");
			exit;
		}
	}
	set_dlg_profile("trunkCalls","$si");
	',`')
	',`')

	ifelse(USE_DIALPLAN,`yes',`
	# apply transformations from dialplan table
	dp_translate("0","$rU/$rU");',`')

	# route calls based on prefix
	if ( !do_routing("1") ) {
		send_reply("404","No Route found");
		exit;
	}

	t_on_failure("GW_FAILOVER");

	route(RELAY);
}


route[RELAY] {
	if (!t_relay()) {
		sl_reply_error();
	};
	exit;
}


failure_route[GW_FAILOVER] {
	if (t_was_cancelled()) {
		exit;
	}

	# detect failure and redirect to next available GW
	if (t_check_status("(408)|([56][0-9][0-9])")) {
		xlog("Failed GW $rd detected \n");

		if ( use_next_gw() ) {
			t_on_failure("GW_FAILOVER");
			t_relay();
			exit;
		}
		
		send_reply("500","All GW are down");
	}
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
