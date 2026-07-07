---
title: "LCR (Least Cost Routing) Module"
description: "Least cost routing (LCR) module implements two vaguely related capabilities:"
---

## Admin Guide


### Overview


Least cost routing (LCR) module implements two vaguely
	related capabilities:


- sequential forwarding of a request to one or more gateways
				(functions load_gws and next_gw)
- sequential forwarding to contacts
	according to their q value (functions load_contacts and
	next_contacts).


For the purpose of facilitating least cost routing of requests,
	each gateway belongs to a gateway group and each gateway group
	is associated with one or more <prefix, from pattern, priority>
	tuples.  A gateway matches a request if	user part of Request URI
	matches a prefix and caller's URI matches a from pattern in a
	tuple that belongs to the group of the gateway.


Matching gateways are then ordered for forwarding
	purpose (1) according to longest user part match, (2) according to 
	tuple's priority, and (3) randomly (prefix_mode = 0) or (1)
	according to gateway's priority and (2) randomly (prefix_mode =
	1).  In prefix_mode 0, prefix is a string of characters and in
	prefix_mode 1, prefix is a regular expression.  From pattern
	is always a regular expression or empty.  Empty from pattern
	matches anything. Smaller priority value means higher priority
	(highest priority value being 0).


When a gateway is selected, Request URI user part is stripped by 
	the number of characters as specified by the gateways strip
	count. Subsequently, Request URI is rewritten based on gateway's
	URI scheme, tag, IP address, port, and transport protocol.  Valid
	URI scheme values are NULL = sip, 1 = sip and 2 = sips.  Tag is
	inserted in front of Request URI user part. Currently valid transport
	protocol values are NULL = none, 1 = udp, 2 = tcp, and 3 = tls.


As a side effect of gateway selection, gateway's flags (that may
	contain information about capabilities of the gateway)
	are stored into an AVP.


### Dependencies


#### OpenSIPS modules


The following modules must be loaded before this module:


- *TM module*
- *A database module like mysql, postgres or 
			dbtext*.


#### External libraries or applications


The following libraries or applications must be installed before
		running OpenSIPS with this module:


- *none*.


### Exported Parameters


#### db_url (string)


URL of the database table to be used.


*Default value is 
			"mysql://opensipsro:opensipsro@localhost/opensips".*


```opensips title="Setting db_url module parameter"
...
modparam("lcr","db_url","dbdriver://username:password@dbhost/dbname")
...
```


#### gw_table (string)


Name of the table holding the gateways definitions.


*Default value is "gw".*


```opensips title="Setting gw_table module parameter"
...
modparam("lcr","gw_table","gw")
...
```


#### gw_name_column (string)


Name of the column holding the gateway name.


*Default value is "gw_name".*


```opensips title="Setting gw_name_column module parameter"
...
modparam("lcr","gw_name_column","gw_name")
...
```


#### grp_id_column (string)


Name of the column holding the group ID of gateway both
		in gw and lcr tables.


*Default value is "grp_id".*


```opensips title="Setting grp_id_column module parameter"
...
modparam("lcr","grp_id_column","grp_id")
...
```


#### ip_addr_column (string)


Name of the column holding the IP address of the gateway.


*Default value is "ip_addr".*


```opensips title="Setting ip_addr_column module parameter"
...
modparam("lcr","ip_addr_column","ip_addr")
...
```


#### port_column (string)


Name of the column holding the port number of the gateway.


*Default value is "port".*


```opensips title="Setting port_column module parameter"
...
modparam("lcr","port_column","port")
...
```


#### uri_scheme_column (string)


Name of the column holding the uri scheme of the gateway.


*Default value is "uri_scheme".*


```opensips title="Setting uri_scheme_column module parameter"
...
modparam("lcr","uri_scheme_column","scheme")
...
```


#### transport_column (string)


Name of the column holding the transport type to be used for 
		the gateway.


*Default value is "transport".*


```opensips title="Setting transport_column module parameter"
...
modparam("lcr","transport_column","transport")
...
```


#### strip_column (string)


Name of the column holding the number of characters
		to be stripped from the front of Request URI user part
		before inserting tag.


*Default value is "strip".*


```opensips title="Setting strip_column module parameter"
...
modparam("lcr","strip_column","strip_count")
...
```


#### tag_column (string)


Name of the column holding gateway specific tag string.


*Default value is "tag".*


```opensips title="Setting tag_column module parameter"
...
modparam("lcr","tag_column","gw_tag")
...
```


#### flags_column (string)


Name of the column holding gateway specific flag values.


*Default value is "flags".*


```opensips title="Setting flags_column module parameter"
...
modparam("lcr","flags_column","gw_flags")
...
```


#### lcr_table (string)


Name of the table holding the LCR rules.


*Default value is "lcr".*


```opensips title="Setting lcr_table module parameter"
...
modparam("lcr","lcr_table","lcr")
...
```


#### prefix_column (string)


Name of the column holding prefix of Request URI user
		part.


*Default value is "prefix".*


```opensips title="Setting prefix_column module parameter"
...
modparam("lcr","prefix_column","prefix")
...
```


#### from_uri_column (string)


Name of the column holding the FROM (source) URI.


*Default value is "from_uri".*


```opensips title="Setting from_uri_column module parameter"
...
modparam("lcr","from_uri_column","from_uri")
...
```


#### priority_column (string)


Name of the column holding the priority of the rule.


*Default value is "priority".*


```opensips title="Setting priority_column module parameter"
...
modparam("lcr","priority_column","priority")
...
```


#### contact_avp (AVP string)


Internal AVP that load_contacts function uses to store
		contacts of the destination set.


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting contact_avp module parameter"
...
modparam("lcr", "contact_avp", "$avp(i:711)")
...
```


#### fr_inv_timer_avp (AVP string)


An AVP that contains a final response timeout
		for INVITEs.  Its value must be the same as that of the
		corresponding tm module parameter.


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting fr_inv_timer_avp module parameter"
...
modparam("lcr|tm", "fr_inv_timer_avp", "$avp(i:704)")
...
```


#### gw_uri_avp (AVP string)


Internal AVP that load_gws function uses to store information of
   matching gateways.


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting gw_uri_avp module parameter"
...
modparam("lcr", "gw_uri_avp", "$avp(i:709)")
...
```


#### rpid_avp (AVP string)


An AVP that contains caller's RPID (if any).


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting rpid_avp module parameter"
...
modparam("^auth$|lcr", "rpid_avp", "$avp(i:302)")
...
```


#### ruri_user_avp (AVP string)


Internal AVP that next_gw function uses to store Request-URI user for
   subsequent next_gw calls.


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting ruri_user_avp module parameter"
...
modparam("lcr", "ruri_user_avp", "$avp(i:500)")
...
```


#### fr_inv_timer (integer)


Sets the value of the fist INVITE's Final Response timeout to be used 
		during sequential forwarding:


*Default value is 90.*


```opensips title="Setting fr_inv_timer module parameter"
...
modparam("lcr","fr_inv_timer",90)
...
```


#### fr_inv_timer_next (integer)


Sets the value of the next INVITE's Final Response timeouts to be used 
		during sequential forwarding:


Function next_contacts() sets tm fr_inv_timer to fr_inv_timer_next
		value if, after next contacts, there are still lower qvalue
		contacts available, and to fr_inv_timer value if next contacts are
		the last ones left.


*Default value is 30.*


```opensips title="Setting fr_inv_timer_next module parameter"
...
modparam("lcr","fr_inv_timer_next",30)
...
```


#### flags_avp (AVP string)


An AVP where successful next_gw and from_gw functions
		store gateway's flags.


*There is NO default value, thus this variable must
			be defined in opensips.cfg.*


```opensips title="Setting flags_avp module parameter"
...
modparam("lcr", "flags_avp", "$avp(i:712)")
...
```


#### prefix_mode (integer)


Defines the prefix mode: string or regular expression.
		When set to 0, the prefix mode is set to string and
		matching is implemented as a simple string comparison. 
		When set to 1, the prefix mode is
		set to regex and matching is implemented as regular
		expression match.


*Default value is 0.*


```opensips title="Setting prefix_mode module parameter"
...
/* Turning on the regex mode for prefix */
modparam("lcr", "prefix_mode", 1)
...
```


### Exported Functions


#### load_gws([pvar])


Loads URI schemes, addresses, ports, and transports of
		matching gateways to gw_uri_avp AVPs
		(see Overview section). If optional pseudo variable
		argument is included, caller's URI is taken from it.
		If pseudo variable argument is not included, caller's
		URI is taken from rpid_avp AVP or, if rpid_avp value is
		empty, from From URI. Returns 1 or -1 depending on success.


This function can be used from REQUEST_ROUTE.


```opensips title="load_gws usage"
...
if (!load_gws("$var(caller_uri)")) {
	sl_send_reply("500", "Server Internal Error - Cannot load gateways");
	exit;
};
...
```


#### load_gws_from_grp(group-id)


Loads URI schemes, addresses, ports, and transports of
		matching gateways to gw_uri_avp AVPs
		(see Overview section), but only gateways belonging to the
		group given in group-id argument are loaded.  group-id
		argument is
		a string and may contain pseudo-variables that are
		replaced at runtime.  Caller's
		URI is taken from rpid_avp AVP or, if rpid_avp value is
		empty, from From URI. Returns 1 or -1 depending on success.


This function can be used from REQUEST_ROUTE.


```opensips title="load_gws_from_grp usage"
...
if (!load_gws_from_grp("1")) {
	sl_send_reply("500", "Server Internal Error - Cannot load gateways from group 1");
	exit;
};
...

if (!load_gws_from_grp("$avp(s:gateway_group)")) {
	sl_send_reply("500", "Server Internal Error - Cannot load gateways");
	exit;
};
...
```


#### next_gw()


If called from a route block, replaces URI scheme, host, port, and
		transport of Request-URI by the values stored in first gw_uri_avp AVP
		and destroys that AVP.  Saves user part of Request-URI into
		ruri_user_avp AVP for use in subsequent next_gw() calls.


If called from a failure route block, appends a new branch to
		request, where  URI scheme, host, port, and transport of Request-URI
		is replaced by the values stored in the first gw_uri_avp AVP and
		destroys that AVP.  Request-URI user is taken from ruri_user_avp
		AVP.


As a side effect, stores gateway's flags to flags_avp.


Returns 1 on success and -1 if there were no gateways left or if an
		error occurred (see syslog).


Must be preceded by successful load_gws() call.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="next_gw usage from a route block"
...
if (!next_gw()) {
	sl_send_reply("503", "Service not available - No gateways");
	exit;
};
...
```


```opensips title="next_gw usage from a failure route block"
...
if (!next_gw()) {
	t_reply("503", "Service not available - No more gateways");
	exit;
};
...
```


#### from_gw([pvar])


Checks if request came from IP address of a
			gateway.  IP address to be checked is either
			taken from source IP address of the request or
			(if present) from pseudo variable argument.
			As a side effect, stores gateway's flags to
			flags_avp.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		ONREPLY_ROUTE.


```opensips title="from_gw usage"
...
if (from_gw()) {
	...
};
...
```


```opensips title="from_gw usage with pseudo variable argument"
...
if (from_gw("$si")) {
	...
};
...
```


#### from_gw_grp(group-id)


Checks if request came from IP address of a
			gateway that belongs to the given group.  Sets
			or resets a message flag depending on whether
			the gateway supports directed media.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		ONREPLY_ROUTE.


```opensips title="from_gw_grp usage"
...
if (from_gw_grp("1")) {
	...
};
...
```


#### to_gw([group-id])


Checks if in-dialog request goes to a gateway. If an optional
			group-id is given, only gateways belonging to this group
			are checked.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="to_gw usage"
...
if (to_gw()) {
	...
	exit;
};
...
```


```opensips title="to_gw usage with group-id"
...
if (to_gw("1")) {
	...
	exit;
};
...
```


#### load_contacts()


Loads contacts in destination set in increasing qvalue order as
		values of lcr_contact AVP.  If all contacts in the destination set
		have the same qvalue, load_contacts() does not do anything thus
		minimizing performance impact of sequential forking capability when
		it is not needed.  Returns 1 if loading of contacts succeeded or
		there was nothing to do.  Returns -1 on error (see syslog).


This function can be used from REQUEST_ROUTE.


```opensips title="load_contacts usage"
...
if (!load_contacts()) {
	sl_send_reply("500", "Server Internal Error - Cannot load contacts");
	exit;
};
...
```


#### next_contacts()


If called from a route block, replaces Request-URI with the first
		lcr_contact AVP value, adds the remaining lcr_contact AVP values 
		with the same qvalue as branches, and destroys those AVPs. It does
		nothing if there are no lcr_contact AVPs.  Returns 1 if there were 
		no errors and -1 if an error occurred (see syslog).


If called from a failure route block, adds the first lcr_contact 
		AVP value and all following lcr_contact AVP values with the same 
		qvalue as new branches to request and destroys those AVPs. 
		Returns 1 if new branches were successfully added and -1 on error 
		(see syslog) or if there were no more lcr_contact AVPs.


Must be preceded by successful load_contacts() call.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="next_contacts usage from route block"
...
if (!next_contacts()) {
	sl_send_reply("500", "Server Internal Error");
	exit;
} else {
	t_relay();
};
...
```


```opensips title="next_contacts usage from failure route block"
if (next_contacts()) {
	t_relay();
};
```


### Exported MI Commands


#### lcr_reload


Causes lcr module to re-read the contents of gateway table
			into memory.


Name: *lcr_reload*


Parameters: *none*


MI FIFO Command Format:


```c
		:lcr_reload:_reply_fifo_file_
		_empty_line_
		
```


#### lcr_dump


Causes lcr module to dump the contents of its in-memory gateway
			table.


Name: *lcr_dump*


Parameters: *none*


MI FIFO Command Format:


```c
		:lcr_dump:_reply_fifo_file_
		_empty_line_
		
```


### Known Limitations


There is an unlikely race condition on lcr reload. If a process uses
		in memory gw table, which is reloaded at the same time twice through
		FIFO, the second reload will delete the original table still in use
		by the process.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
