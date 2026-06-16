---
title: "permissions Module"
---

## Admin Guide


### Overview


#### Call Routing


The module can be used to determine if a call has appropriate
		permission to be established.
		Permission rules are stored in plaintext configuration files similar to
		`hosts.allow` and `hosts.deny` files used by tcpd.


When `allow_routing` function is
		called it tries to find a rule that matches selected fields of the
		message.


OpenSIPS is a forking proxy and therefore a single message can be sent
		to different destinations simultaneously. When checking permissions
		all the destinations must be checked and if one of them fails, the
		forwarding will fail.


The matching algorithm is as follows, first match wins:


- Create a set of pairs of form (From, R-URI of branch 1),
			(From, R-URI of branch 2), etc.
- Routing will be allowed when all pairs match an entry in the
			allow file.
- Otherwise routing will be denied when one of pairs matches an
			entry in the deny file.
- Otherwise, routing will be allowed.


A non-existing permission control file is treated as if it were an
		empty file. Thus, permission control can be turned off by providing
		no permission control files.


From header field and Request-URIs are always compared with regular
		expressions! For the syntax see the sample file:
		`config/permissions.allow`.


#### Registration Permissions


In addition to call routing it is also possible to check REGISTER
		messages and decide--based on the configuration files--whether the
		message should be allowed and the registration accepted or not.


Main purpose of the function is to prevent registration of "prohibited"
		IP addresses. One example, when a malicious user registers a contact
		containing IP address of a PSTN gateway, he might be able to bypass
		authorization checks performed by the SIP proxy. That is undesirable
		and therefore attempts to register IP address of a PSTN gateway should
		be rejected. Files `config/register.allow` and `config/register.deny` contain an example
		configuration.


Function for registration checking is called `allow_register` and the algorithm is very
		similar to the algorithm described in
		[sec call routing](#call_routing). The only difference is in the way
		how pairs are created.


Instead of From header field the function uses To header field because
		To header field in REGISTER messages contains the URI of the person
		being registered. Instead of the Request-URI of branches the function
		uses Contact header field.


Thus, pairs used in matching will look like this: (To, Contact 1),
		(To, Contact 2), (To, Contact 3), and so on..


The algorithm of matching is same as described in
		[sec call routing](#call_routing).


#### URI Permissions


The module can be used to determine if request is
		allowed to the destination specified by an URI stored in
		a pvar.  Permission rules are stored in
		plaintext configuration files similar to
		`hosts.allow` and
		`hosts.deny` used by tcpd.


When `allow_uri`
		function is called, it tries to find a rule that matches
		selected fields of the message.
		The matching algorithm is as follows, first match wins:


- Create a pair <From URI, URI stored in pvar>.
- Request will be allowed when the pair matches
			an entry in the allow file.
- Otherwise request will be denied when the pair
			matches an entry in the	deny file.
- Otherwise, request will be allowed.


A non-existing permission control file is treated as if it were an
		empty file. Thus, permission control can be turned off by providing
		no permission control files.


From URI and URI stored in pvar are always compared with regular
		expressions! For the syntax see the sample file:
		`config/permissions.allow`.


#### Address Permissions


The module can be used to determine if an address (IP
		address and port) matches any of the IP subnets
		stored in cached OpenSIPS database table.
		Port 0 in cached database table matches any port.  Group ID, IP
		address, port and transport protocol values to be matched can be either taken from
		the request (`check_source_address`) or given as pvar
		arguments or directly as strings(`check_address`).


Addresses stored in cached database table can be grouped
		together into one or more groups specified by a group
		identifier (unsigned integer). Group identifier is given as
		argument to `check_address` and
		`check_source_address`.


Otherwise the request is rejected.


The address database table is specified by module parameters.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### default_allow_file (string)


Default allow file used by functions without parameters. If you
		don't specify full pathname then the directory in which is the main
		config file is located will be used.


*Default value is "permissions.allow".*


```c title="Set default_allow_file parameter"
...
modparam("permissions", "default_allow_file", "/etc/permissions.allow")
...
```


#### default_deny_file (string)


Default file containing deny rules. The file is used by functions
		without parameters. If you don't specify full pathname then the
		directory in which the main config file is located will be used.


*Default value is "permissions.deny".*


```c title="Set default_deny_file parameter"
...
modparam("permissions", "default_deny_file", "/etc/permissions.deny")
...
```


#### check_all_branches (integer)


If set then allow_routing functions will check Request-URI of all
		branches (default). If disabled then only Request-URI of the first
		branch will be checked.


> [!WARNING]
> Do not disable this parameter unless you really know what you
		are doing.


*Default value is 1.*


```c title="Set check_all_branches parameter"
...
modparam("permissions", "check_all_branches", 0)
...
```


#### allow_suffix (string)


Suffix to be appended to basename to create filename of the allow
		file when version with one parameter of either
		`allow_routing` or
		`allow_register` is used.


> [!NOTE]
> Including leading dot.


*Default value is ".allow".*


```c title="Set allow_suffix parameter"
...
modparam("permissions", "allow_suffix", ".allow")
...
```


#### deny_suffix (string)


Suffix to be appended to basename to create filename of the deny file
		when version with one parameter of either
		`allow_routing` or
		`allow_register` is used.


> [!NOTE]
> Including leading dot.


*Default value is ".deny".*


```c title="Set deny_suffix parameter"
...
modparam("permissions", "deny_suffix", ".deny")
...
```


#### db_url (string)


The URL of the database to be used for loading the data related to
		IP-based checking ("address" table).


This parameter is optional and it is needed only if you use
		functions related to IP-based checking. If you do so, you need to
		explicitly set this parameter (it will not inherit from 
		"db_default_url")


Since version 2.2, this URL represents the db_url for the 
		"default" partition.


*Default value is "NULL".*


```c title="Set db_url parameter"
...
modparam("permissions", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### address_table (string)


Name of database table containing matching rules used by
		`allow_register` function.
		Since version 2.2, this table name also represents the default table
		name for partitions without a 'table_name' setting.


*Default value is "address".*


```c title="Set address_table parameter"
...
modparam("permissions", "address_table", "pbx")
...
```


#### partition (string)


Specify a new IP-based checking partition (data source).  This
		parameter may be set multiple times.  Each partition may have a
		specific "db_url" and "table_name".  If not specified, these values
		will be inherited from [db url](#param_db_url), db_default_url
		or [address table](#param_address_table), respectively.  The name of
		the default partition is 'default'.


```c title="Set partition parameter"
...
modparam("permissions", "partition", "
	inbound:
		db_url = postgres://opensips:opensipsrw@127.0.0.1/opensips;
		table_name = address")
...
```


#### grp_col (string)


Name of address table column containing group
		identifier of the address.


*Default value is "grp".*


```c title="Set grp_col parameter"
...
modparam("permissions", "grp_col", "group_id")
...
```


#### ip_col (string)


Name of address table column containing IP address
		part of the address.


*Default value is "ip".*


```c title="Set ip_col parameter"
...
modparam("permissions", "ip_col", "ipess")
...
```


#### mask_col (string)


Name of address table column containing network mask of
		the address.  Possible values are 0-128. It should be up to 32 if 
		the IP is v4 and up to 128 if the IP is v6.


*Default value is "mask".*


```c title="Set mask_col parameter"
...
modparam("permissions", "mask_col", "subnet_length")
...
```


#### port_col (string)


Name of address table column containing port
		part of the address.


*Default value is "port".*


```c title="Set port_col parameter"
...
modparam("permissions", "port_col", "prt")
...
```


#### proto_col (string)


Name of address table column containing transport
		protocol that is matched against transport protocol of
		received request.  Possible values that can be stored in
		proto_col are "any", "udp",
		"tcp", "tls",
		"sctp", and "none".  Value
		"any" matches always and value
		"none" never.


*Default value is "proto".*


```c title="Set proto_col parameter"
...
modparam("permissions", "proto_col", "transport")
...
```


#### pattern_col (string)


Name of address table column containinga a pattern (a shell wildcard
		pattern, like the ones used for file name matching) that is matched 
		against the arguments received by
		`check_address`
		or `check_source_address`.


*Default value is "pattern".*


```c title="Set pattern_col parameter"
...
modparam("permissions", "pattern_col", "wildcard_col")
...
```


#### info_col (string)


Name of address table column containing a string
		that is added as value to a pvar given as argument
		to `check_address`
		or `check_source_address` in
		case the function succedes.


*Default value is "context_info".*


```c title="Set info_col parameter"
...
modparam("permissions", "info_col", "info_col")
...
```


### Exported Functions


#### check_address(group_id, ip, port, proto [, context_info], [pattern], [partition])


Returns 1 if group id, IP address, port and protocol given as
		arguments match an IP subnet found in cached address table,
		as described in [sec address permissions](#address_permissions) .
		The function takes 4 mandatory arguments and 3 optional ones.


This function can be useful to check if a request can be allowed
		without authentication.


Meaning of the parameter is as follows:


- group_id (int)
This argument represents the group id to be matched.
			If the group_id argument is "0", the query can match any group
			in the cached address table.
- ip (string)
This argument represents the ip address to be matched.
			This argument cannot be null/empty.
- port (int)
This argument represents the port to be matched.
			Cached address table entry containing port value 0
			matches any port.
			Also, a *0* value for the argument will match any port in the
			address table.
- proto (string)
This argument represents the protocol used for transport;
			Transport protocol is either "ANY" or any
			valid transport protocol value: "UDP, "TCP", "TLS", and "SCTP".
- context_info (var, optional)
This argument represents the variable in wich the context_info field
			from the cached address table will be stored in case of match.
- pattern (string, optional)
This argument is a string to be matched against the wildcard
			pattern field from the address table.
- partition (string, optional)
An optional parition name for the group id. If no partition
			specified, the "default" one will be used.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, BRANCH_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE.


```c title="check_address() usage"
...

// Checks if the tuple IP address/port (given as strings) and source protocol
// (given as pvar), belongs to group 4, verifies if the string "texttest"
// matches the wildcard pattern field in the database table and stores the
// context information in $avp(ctx)
if (check_address( 4, "192.168.2.135", 5700, "$socket_in(proto)", $avp(ctx), "texttest")) {
	t_relay();
	xlog("$avp(ctx)\n");
}

if (check_address( 4, "192.168.2.135", 5700, "$socket_in(proto)", , , "my_part")) {
	t_relay();
	xlog("$avp(ctx)\n");
}
...

// Checks if the tuple IP address/port/protocol of the source message is in group 4
if (check_address( 4, "$si", "$sp", "$socket_in(proto)")) {
	t_relay();
}

...

// Checks if the tuple IP address/port/protocol stored in AVPs s:ip/s:port/s:proto
// is in group 4 and stores context information in $avp(ctx)
$avp(ip) = "192.168.2.135";
$avp(port) = 5061;
$avp(proto) = "any";
$avp(partition)="my_part";
if (check_address( 4, $avp(ip), $avp(port), $avp(proto), $avp(ctx), , $avp(partition))) {
	t_relay();
	xlog("$avp(ctx)\n");
}

...

// Checks if the tuple IP address/port (given as strings) and source protocol
// (given as pvar) is in group 4, verifies if string the "texttest" matches
// the wildcard pattern field in the database table, without storing any
// context information
if (check_address( 4,$si, 5700, $socket_in(proto), ,"texttest")) {
	t_relay();
}

...
```


#### check_source_address(group_id , [context_info], [pattern], [partition])


Equivalent to check_address(group_id, "$si", "$sp", "$socket_in(proto)", context_info, pattern, partition).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, BRANCH_ROUTE, STARTUP_ROUTE, TIMER_ROUTE, EVENT_ROUTE.


```c title="check_source_address() usage"
...
// Check if source address/port/proto is in group 4 and stores
// context information in $avp(ctx)
if (check_source_address( 4,$avp(ctx), , , $avp(my_partition))) {
	xlog("$avp(ctx)\n");
}else {
	sl_send_reply(403, "Forbidden");
}
...
```


#### get_source_group(var,[partition])


Checks if an entry with the source ip/port/protocol is
		found in cached address or subnet table in any group.
		If yes, returns that group in the variable parameter.
		If not returns -1.  Port value 0 in cached address and
		subnet table matches any port. Optionally, you can also
		specify the partition. If no partition
		specified, the "default" one will be used.


Parameters:


- *var* (var)
- *partition* (string, optional)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		LOCAL_ROUTE, BRANCH_ROUTE.


```c title="get_source_group() usage"
...

if ( get_source_group( $var(group)) ) {
   # do something with $var(group)
   xlog("group is $var(group)\n");
};
...
```


#### allow_routing()


Returns true if all pairs constructed as described in [sec call routing](#call_routing) have appropriate permissions according to
		the configuration files. This function uses default configuration
		files specified in `default_allow_file` and
		`default_deny_file`.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="allow_routing usage"
...
if (allow_routing()) {
	t_relay();
};
...
```


#### allow_routing(basename)


Returns true if all pairs constructed as described in [sec call routing](#call_routing) have appropriate permissions according
		to the configuration files given as parameters.


Meaning of the parameters is as follows:


- *basename* (string) - Basename from which allow
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function
			expects the file to be located in the same directory as the main
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="allow_routing(basename) usage"
...
if (allow_routing("basename")) {
	t_relay();
};
...
```


#### allow_register(basename)


The function returns true if all pairs constructed as described in [sec registration permissions](#registration_permissions) have appropriate permissions
		according to the configuration files given as parameters.


Meaning of the parameters is as follows:


- *basename* (string) - Basename from which allow
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function
			expects the file to be located in the same directory as the main
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="allow_register(basename) usage"
...
if ($rm=="REGISTER") {
	if (allow_register("register")) {
		save("location");
		exit;
	} else {
		sl_send_reply(403, "Forbidden");
	};
};
...
```


#### allow_uri(basename, uri)


Returns true if the pair constructed as described in [sec uri permissions](#uri_permissions) have appropriate permissions
		according to the configuration files specified by the parameter.


Meaning of the parameter is as follows:


- *basename* (string) - Basename from which allow
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function
			expects the file to be located in the same directory as the main
			configuration file of the server.
- *uri* (string) - SIP URI to be checked.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="allow_uri(basename, uri) usage"
...
if (allow_uri("basename", $rt)) {  // Check Refer-To URI
	t_relay();
};
if (allow_uri("basename", $avp(uri)) {  // Check URI stored in $avp(uri)
	t_relay();
};
...
```


### Exported MI Functions


#### address_reload


Causes permissions module to re-read the contents of
				the address database table into cache
				memory.  In cache memory the entries are
				for performance reasons stored in two
                                different tables:  address table and
				subnet table depending on the value of
				the mask field (32 or smaller).


Parameters:


- *partition* -
					the name of the partition to be reloaded. If none
					specified all the partitions shall be reloaded.


#### address_dump


Causes permissions module to dump contents of
				the address table from cache memory.


Parameters:


- *partition* -
					the name of the partition to be dumped. If none
					specified all the partitions shall be dumped.


#### subnet_dump


Causes permissions module to dump
				contents of cache memory subnet table.


Parameters:


- *partition* -
					the name of the partition to be dumped. If none
					specified all the partitions shall be dumped.


#### allow_uri


Tests if (URI, Contact) pair is allowed according to
		allow/deny files.  The files must already have been
		 loaded by OpenSIPS.


Parameters:


- *basename* -
						Basename from
		which allow and deny filenames will be created by
		appending contents of allow_suffix and deny_suffix
		parameters.
- *URI* - URI to be tested
- *Contact* - Contact
						to be tested
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
