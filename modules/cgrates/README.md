---
title: "CGRateS Module"
description: "[*CGRateS*](http://www.cgrates.org/) is an open-source rating engine used for carrier-grade, multi-tenant, real-time billing. It is able to do both postpaid and prepaid rating for multiple concurrent sessions with different balance units (eg: Monetary, SMS, Internet Traffic). CGRateS can ..."
---

## Admin Guide


### Overview


[*CGRateS*](http://www.cgrates.org/)
		is an open-source rating engine used for carrier-grade, multi-tenant,
		real-time billing. It is able to do both postpaid and prepaid rating
		for multiple concurrent sessions with different balance units (eg: Monetary,
		SMS, Internet Traffic). CGRateS can also export accurate CDRs in various
		formats.


This module can be used to communicate with the CGRates engine in order to do
		call authorization and accounting for billing purposes. The OpenSIPS module does
		not do any billing by itself, but provides an interface to communicate with the
		CGRateS engine using efficient [JSON-RPC](http://json-rpc.org/)
		APIs in both synchronous and asynchronous ways. For each command the user can
		provide a set of parameters that will be forwarded to the CGRateS engine, using
		the *$cgr()* variable. You can find usage examples in the
		following sections.


The module also has support for multiple parallel billing sessions to CGRateS.
		This can be useful in scenarios that involve complex billing logic, such as
		double billing (both customer and carrier billing), or multi-leg calls
		(serial/parallel forking). Each billing session is independent and
		has a specific *tag* that can be use throughout the call
		lifetime.


The module can be used to implement the following features:


### Authorization


The authorization is used to check if an account is allowed to start a new call
		and it has enough credit to call to that destination. This is done using the
		*cgrates_auth()* command, which returns the number of seconds
		a call is allowed to run in the *$cgr_ret* pseudo-variable.


Usage example:


```opensips
		...
		if (cgrates_auth("$fU", "$rU"))
			xlog("Call is allowed to run $cgr_ret seconds\n");
		}
		...
		
```


### Accounting


The accounting mode is used to start and stop a CGRateS session. This can be
		used for both prepaid and postpaid billing. The *cgrates_acc()*
		function starts the CGRateS session when the call is answered (the 200 OK message
		is received) and ends it when the call is ended (a BYE message is received). This
		is done automatically using the *dialog* module.


Note that it is important to first authorize the call (using the
		*cgrates_auth()* command) before starting accounting. If you do
		not do this and the user is not authorized to call, the dialog will be immediately
		closed, resulting in a 0-duration call. If the call is allowed to go on, the
		dialog lifetime will be set to the duration indicated by the CGRateS engine.
		Therefore, the dialog will be automatically ended if the call would have been longer.


After the call is ended (by a BYE message), the CGRateS session is also ended.
		At this point, you can generate a CDR. To do this, you have to set the
		*cdr* flag to the *cgrates_acc()* command.
		CDRs can also be generated for missed calls by using the *missed*
		flag.


Usage example:


```opensips
		...
		if (!cgrates_auth("$fU", "$rU")) {
			sl_send_reply(403, "Forbidden");
			exit;
		}
		xlog("Call is allowed to run $cgr_ret seconds\n");
		# do accounting for this call
		cgrates_acc("cdr", "$fU", "$rU");
		...
		
```


Note that when using the *cdr* flag, CDRs are exported by
		the CGRateS engine in various formats, not by OpenSIPS. Check the CGRateS
		documentation for more information.


### Other Commands


You can use the *cgrates_cmd()* to send arbitrary
		commands to the CGRateS engine, and use the *$cgr_ret*
		pseudo-variable to retrieve the response.


The following example simulates the *cgrates_auth()* CGRateS call:


```opensips
		...
		$cgr_opt(Tenant) = $fd; # or $cgr(Tenant) = $fd; /* in compat mode */
		$cgr(Account) = $fU;
		$cgr(OriginID) = $ci;
		$cgr(SetupTime) = "" + $Ts;
		$cgr(RequestType) = "*prepaid";
		$cgr(Destination) = $rU;
		cgrates_cmd("SessionSv1.AuthorizeEvent");
		xlog("Call is allowed to run $cgr_ret(MaxUsage) seconds\n");
		...
		
```


### CGRateS Failover


Multiple CGRateS engines can be provisioned to use in a failover manner: in
		case one engine is down, the next one is used. Currently there is no load
		balancing logic between the servers, but this is a feature one of the CGRateS
		component does starting with newer versions.


Each CGRateS engine has assigned up to 
		*max_async_connections* connections, plus one
		used for synchronous commands. If a connection fails (due to network
		issues, or server issues), it is marked as closed and a new one is
		tried. If all connections to that engine are down, then the entire
		engine is marked as disabled, and a new engine is queried. After an
		engine is down for more than *retry_timeout*
		seconds, OpenSIPS tries to connect once again to that server. If it
		succeeds, that server is enabled. Otherwise, the other engines are
		used, until none is available and the command fails.


### CGRateS Compatibility


The module supports two different versions of CGRateS: the
		*compat_mode* one, which works with pre-rc8 releases, and a
		new one which works with the post-rc8 releases. The difference between the two
		versions consist in the way the requests and responses to and from CGRateS
		are built. In the non-*compat_mode*/new version, a new
		variable, *$cgr_opt()*, is available, and can be used to
		tune the request options. This variable should not be used in
		*compat_mode* mode to avoid abiguities, but if it is used,
		it behaves exactly as *$cgr()*. By default
		*compat_mode* is disabled.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *dialog* -- in case CGRateS
				accounting is used.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *libjson*


### Exported Parameters


#### cgrates_engine (string)


This parameter is used to specify a CGRateS engine connection.
			The format is *IP[:port]*. The port is optional,
			and if missing, *2014* is used.


This parameter can have multiple values, for each server
			used for failover. At least one server should be provisioned.


*Default value is "None".*


```opensips title="Set cgrates_engine parameter"
...
modparam("cgrates", "cgrates_engine", "127.0.0.1")
modparam("cgrates", "cgrates_engine", "127.0.0.1:2013")
...
```


#### bind_ip (string)


IP used to bind the socket that communicates with the
			CGRateS engines. This is useful to set when the engine
			is runing in a local, secure LAN, and you want to use
			that network to communicate with your servers.
			The parameter is optional.


*Default value is "not set - any IP is used".*


```opensips title="Set bind_ip parameter"
...
modparam("cgrates", "bind_ip", "10.0.0.100")
...
```


#### max_async_connections (integer)


The maximum number of simultaneous asynchronous connections
			to a CGRateS engine.


*Default value is "10".*


```opensips title="Set max_async_connections parameter"
...
modparam("cgrates", "max_async_connections", 20)
...
```


#### retry_timeout (integer)


The number of seconds after which a disabled connection/engine
			is retried.


*Default value is "60".*


```opensips title="Set retry_timeout parameter"
...
modparam("cgrates", "retry_timeout", 120)
...
```


#### compat_mode (integer)


Indicates whether OpenSIPS should use the old (compat_mode)
			CGRateS version API (pre-rc8).


*Default value is "false (0)".*


```opensips title="Set compat_mode parameter"
...
modparam("cgrates", "compat_mode", 1)
...
```


### Exported Functions


#### cgrates_acc([flags[, account[, destination[, session]]]])


`cgrates_acc()` starts an accounting
			session on the CGRateS engine for the current dialog. It also ends the
			session when the dialog is ended. This function requires a dialog, so in
			case create_dialog() was not previously used, it will internally call
			that function.


Note that the `cgrates_acc()` function
			does not send any message to the CGRateS engine when it is called, but only
			when the call is answered and the CGRateS session should be started (a 200
			OK message is received).


When called in *REQUEST_ROUTE* or
			*FAILURE_ROUTE*, accounting for this session is done
			for all the branches created. When called in *BRANCH_ROUTE*
			or *ONREPLY_ROUTE*, acccounting is done only if that
			branch is successful (terminates with a 2xx reply code).


The `cgrates_acc()` function should
			only be called on initial INVITEs. For more infirmation check
			[accounting](#accounting).


Meaning of the parameters is as follows:


- *flags* (string, optional) - indicates whether OpenSIPS
				should generate a CDR at the end of the call. If the parameter is missing,
				no CDR is generated - the session is only passed through CGRateS.
				The following values can be used, separated by '|':

  - *cdr* - also generate a CDR;
  - *missed* - generate a CDR even for missed
						calls; this flag only makes sense if the *cdr*
						flag is used;
- *account* (string, optional) - the account that will be charged
				in CGrateS. If not specified, the user in the From header is used.
- *destination* (string, optional) - the dialled number.
			If not present the request URI user is used.
- *session* (string, optional) - the tag of the session that
				will be started if the branch/call completes with success. This parameter
				indicates what set of data from the *$cgr()* variable
				should be considered. If missing, the default set is used.


The function can return the following values:


- *1* - successful call - the CGRateS accouting
				was successfully setup for the call.
- *-1* - OpenSIPS returned an internal error
				(i.e. the dialog cannot be created, or the server is out of memory).
- *-2* - the SIP message is invalid: either
				it has missing headers, or it is not an initial INVITE.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```opensips title="cgrates_acc() usage"
		...
		if (!has_totag()) {
			...
			if (cgrates_auth($fU, $rU))
				cgrates_acc("cdr|missed", $fU, $rU);
			...
		}
		...
		
```


#### cgrates_auth([account[, destination[, session]]])


`cgrates_auth()` does call authorization
			through using the CGRateS engine.


Meaning of the parameters is as follows:


- *account* (string, optional) - the account that will be checked
				in CGrateS. If not specified, the user in the From header is used.
- *destination* (string, optional) - the dialled number.
			If not present the request URI user is used.
- *session* (string, optional) - the tag of the session that
				will be started if the branch/call completes with success. This parameter
				indicates what set of data from the *$cgr()* variable
				should be considered. If missing, the default set is used.


The function can return the following values:


- *1* - successful call - the CGRateS account
				is allowed to make the call.
- *-1* - OpenSIPS returned an internal error
				(i.e. server is out of memory).
- *-2* - the CGRateS engine returned error.
- *-3* - No suitable CGRateS server found.
				message type (not an initial INVITE).
- *-4* - the SIP message is invalid: either
				it has missing headers, or it is not an initial INVITE.
- *-5* - CGRateS returned an invalid message.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
			BRANCH_ROUTE and LOCAL_ROUTE.


```opensips title="cgrates_auth() usage"
		...
		if (!has_totag()) {
			...
			if (!cgrates_auth($fU, $rU)) {
				sl_send_reply(403, "Forbidden");
				exit;
			}
			...
		}
		...
		
```


```opensips title="cgrates_auth() usage with attributes parsing"
		...
		if (!has_totag()) {
			...
			$cgr_opt(GetAttributes) = 1;
			if (!cgrates_auth($fU, $rU)) {
				sl_send_reply(403, "Forbidden");
				exit;
			}
			# move attributes from AttributesDigest variable to plain AVPs
			$var(idx) = 0;
			while ($(cgr_ret(AttributesDigest){s.select,$var(idx),,}) != NULL) {
				$avp($(cgr_ret(AttributesDigest){s.select,$var(idx),,}{s.select,0,:}))
					= $(cgr_ret(AttributesDigest){s.select,$var(idx),,}{s.select,1,:});
				$var(idx) = $var(idx) + 1;
			}
			...
		}
		...
		
```


#### cgrates_cmd(command[, session])


`cgrates_cmd()` can send
			arbitrary commands to the CGRateS engine.


Meaning of the parameters is as follows:


- *command* (string) - the command sent to the
				CGRateS engine.
- *session* (string, optional) - the tag of the session that
				will be started if the branch/call completes with success. This parameter
				indicates what set of data from the *$cgr()* variable
				should be considered. If missing, the default set is used.


The function can return the following values:


- *1* - successful call - the CGRateS account
				is allowed to make the call.
- *-1* - OpenSIPS returned an internal error
				(i.e. server is out of memory).
- *-2* - the CGRateS engine returned error.
- *-3* - No suitable CGRateS server found.
				message type (not an initial INVITE).


This function can be used from any route.


```opensips title="cgrates_cmd() usage"
		...
		# cgrates_auth($fU, $rU); simulation
		$cgr_opt(Tenant) = $fd;
		$cgr(Account) = $fU;
		$cgr(OriginID) = $ci;
		$cgr(SetupTime) = "" + $Ts;
		$cgr(RequestType) = "*prepaid";
		$cgr(Destination) = $rU;
		cgrates_cmd("SessionSv1.AuthorizeEvent");
		xlog("Call is allowed to run $cgr_ret seconds\n");
		...
		
```


### Exported Pseudo-Variables


#### $cgr(name) / $(cgr(name)[session])


Pseudo-variable used to set different parameters for the
				CGRateS command. Each name-value pair will be encoded as
				a *string - value* attribute in the
				JSON message sent to CGRateS.


The name-values pairs are stored in the transaction (if
				tm module is loaded). Therefore the values are accessible
				in the reply.


When the *cgrates_acc()* function is
				called, all the name-value pairs are moved in the dialog.
				Therefore the values will be accessible along the dialog's
				lifetime.


This variable consists of serveral sets of name-value pairs.
				Each set corresponds to a session. The variable can be
				indexed by a *session tag*. The sets
				are completely indepdendent from one another. if the
				*session tag* does not exist, the default
				(no name) one is used.


When assigned with the *:=* operator,
				the value is treated as a JSON, rather than a string/integer.
				However, the evaluation of the JSON is late, therefore when
				the CGRateS request is built, if the module is unable to parse
				the JSON, the value is sent as a string.


```opensips title="$cgr(name) simple usage"
		...
		if (!has_totag()) {
			...
			$cgr_opt(Tenant) = $fd; # set the From domain as a tenant
			$cgr(RequestType) = "*prepaid"; # do prepaid accounting
			$cgr(AttributeIDs) := '["+5551234"]'; # treat as array
			if (!cgrates_auth("$fU", "$rU")) {
				sl_send_reply(403, "Forbidden");
				exit;
			}
		}
		...
		
```


```opensips title="$cgr(name) multiple sessions usage"
		...
		if (!has_totag()) {
			...
			# first session - authorize the user
			$cgr_opt(Tenant) = $fd; # set the From domain as a tenant
			$cgr(RequestType) = "*prepaid"; # do prepaid accounting
			if (!cgrates_auth("$fU", "$rU")) {
				sl_send_reply(403, "Forbidden");
				exit;
			}

			# second session - authorize the carrier
			$(cgr_opt(Tenant)[carrier]) = $td;
			$(cgr(RequestType)[carrier]) = "*postpaid";
			if (!cgrates_auth("$tU", "$fU", "carrier")) {
				# use a different carrier
				return;
			}

			# if everything is successful start accounting on both
			cgrates_acc("cdr", "$fU", "rU");
			cgrates_acc("cdr", "$tU", "$fU", "carrier");
		}
		...
		
```


#### $cgr_opt(name) / $(cgr_opt(name)[session])


Used to tune the request parameter of a CGRateS request when used in
				non-*compat_mode*.


*Note:* for all request options integer values act as
				boolean values: *0* disables the feature and
				*1*(or different than 0 value) enables it. String
				variables are passed just as they are set.


Possible values at the time the documentation was written:


- *Tenant* - tune CGRateS Tenant.
- *GetAttributes* - requests the account
						attributes from the CGRateS DB.
- *GetMaxUsage* - request the maximum time
						the call is allowed to run.
- *GetSuppliers* - request an array with
						all the suppliers for that can terminate that call.


```opensips title="$cgr_opt(name) usage"
		...
		$cgr_opt(Tenant) = "cgrates.org";
		$cgr_opt(GetMaxUsage) = 1; # also retrieve the max usage
		if (!cgrates_auth("$fU", "$rU")) {
			# call rejected
		}
		...
		
```


#### $cgr_ret(name)


Returns the reply message of a CGRateS command in script,
				or when used in the non-compat mode, one of the objects
				within the reply.


```opensips title="$cgr_ret(name) usage"
		...
		cgrates_auth("$fU", "$rU");

		# in compat mode
		xlog("Call is allowed to run $cgr_ret seconds\n");

		# in non-compat mode
		xlog("Call is allowed to run $cgr_ret(MaxUsage) seconds\n");
		...
		
```


### Exported Asynchronous Functions


#### cgrates_auth([account[, destination[, session]]])


Does the CGRateS authorization call in an asynchronous way. Script
			execution is suspended until the CGRateS engine sends the reply back.


Meaning of the parameters is as follows:


- *account* - the account that will be checked
				in CGRateS. This parameter is optional, and if not specified,
				the user in the From header is used.
- *destination* - the dialled number. Optional
				parameter, if not present the request URI user is used.
- *session* - the tag of the session that
				will be started if the branch/call completes with success. This parameter
				indicates what set of data from the *$cgr()* variable
				should be considered. If missing, the default set is used.


The function can return the following values:


- *1* - successful call - the CGRateS account
				is allowed to make the call.
- *-1* - OpenSIPS returned an internal error
				(i.e. server is out of memory).
- *-2* - the CGRateS engine returned error.
- *-3* - No suitable CGRateS server found.
				message type (not an initial INVITE).
- *-4* - the SIP message is invalid: either
				it has missing headers, or it is not an initial INVITE.
- *-5* - CGRateS returned an invalid message.


```opensips title="async cgrates_auth usage"
route {
	...
	async(cgrates_auth("$fU", "$rU"), auth_reply);
}

route [auth_reply]
{
	if ($rc < 0) {
		xlog("Call not authorized: code=$cgr_ret!\n");
		send_reply(403, "Forbidden");
		exit;
	}
	...
}
```


#### cgrates_cmd(command[, session])


Can run an arbitrary CGRateS command in an asynchronous way. The
			execution is suspended until the CGRateS engine sends the reply back.


Meaning of the parameters is as follows:


- *command* - the command sent to the
				CGRateS engine. This is a mandatory parameter.
- *session* - the tag of the session that
				will be started if the branch/call completes with success. This parameter
				indicates what set of data from the *$cgr()* variable
				should be considered. If missing, the default set is used.


The function can return the following values:


- *1* - successful call - the CGRateS account
				is allowed to make the call.
- *-1* - OpenSIPS returned an internal error
				(i.e. server is out of memory).
- *-2* - the CGRateS engine returned error.
- *-3* - No suitable CGRateS server found.
				message type (not an initial INVITE).


```opensips title="async cgrates_cmd compat_mode usage"
route {
	...
	$cgr(Tenant) = $fd;
	$cgr(Account) = $fU;
	$cgr(OriginID) = $ci;
	$cgr(SetupTime) = "" + $Ts;
	$cgr(RequestType) = "*prepaid";
	$cgr(Destination) = $rU;
	async(cgrates_cmd("SMGenericV1.GetMaxUsage"), auth_reply);
}

route [auth_reply]
{
	if ($rc < 0) {
		xlog("Call not authorized: code=$cgr_ret!\n");
		send_reply(403, "Forbidden");
		exit;
	}
	...
}
```


```opensips title="async cgrates_cmd new usage"
route {
	...
	$cgr_opt(Tenant) = $fd;
	$cgr(Account) = $fU;
	$cgr(OriginID) = $ci;
	$cgr(SetupTime) = "" + $Ts;
	$cgr(RequestType) = "*prepaid";
	$cgr(Destination) = $rU;
	async(cgrates_cmd("SessionSv1.AuthorizeEventWithDigest"), auth_reply);
}

route [auth_reply]
{
	if ($rc < 0) {
		xlog("Call not authorized: MaxUsage=$cgr_ret(MaxUsage)!\n");
		send_reply(403, "Forbidden");
		exit;
	}
	...
}
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
