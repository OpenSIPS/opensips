---
title: "permissions Module"
---

## Admin Guide


### Overview


#### Call Routing


The module can be used to determine if a call has appropriate 
		permission to be established. Permission rules are stored in 
		plaintext configuration files similar to
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
		Port 0 in cached database table matches any port.  IP
		address and port to be matched can be either taken from
		the request (allow_source_address) or given as pvar
		arguments (allow_address).


Addresses stored in cached database table can be grouped
		together into one or more groups specified by a group
		identifier (unsigned integer).  Group
		identifier is given as argument to allow_address and
		allow_source_address functions.


#### Trusted Requests


The module can be used to determine if an incoming
		request can be trusted without authentication.


When `allow_trusted`
		function is called, it tries to find a rule that matches
		the request.  Rules contain the following fields:
		<source address, transport protocol, regular
		expression>.


A requests is accepted if there exists a rule, where


- source address is equal to source address of
			request or source address given in pvar,
- transport protocol is either "ANY" or equal to
			transport protocol of request or transport
			protocol given in pvar, and
- regular expression is either empty (NULL in
			database) or matches From URI of request.


Otherwise the request is rejected.


Rules are stored in a database table specified by module
		parameters.  There also exists a module parameter
	        `dm_mode` that
		determines if rules are cached into memory for faster
		matching or if database is consulted for each invocation
		of allow_trusted function call.


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


```opensips title="Set default_allow_file parameter"
...
modparam("permissions", "default_allow_file", "/etc/permissions.allow")
...
```


#### default_deny_file (string)


Default file containing deny rules. The file is used by functions
		without parameters. If you don't specify full pathname then the 
		directory in which the main config file is located will be used.


*Default value is "permissions.deny".*


```opensips title="Set default_deny_file parameter"
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


```opensips title="Set check_all_branches parameter"
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


```opensips title="Set allow_suffix parameter"
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


```opensips title="Set deny_suffix parameter"
...
modparam("permissions", "deny_suffix", ".deny")
...
```


#### db_url (string)


This is URL of the database to be used to store rules used by 
		`allow_trusted` function.


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("permissions", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### address_table (string)


Name of database table containing IP subnet information used by
		`allow_address` and
                `allow_source_address`
                functions.


*Default value is "address".*


```opensips title="Set address_table parameter"
...
modparam("permissions", "address_table", "addr")
...
```


#### grp_col (string)


Name of address table column containing group
		identifier of the address.


*Default value is "grp".*


```opensips title="Set grp_col parameter"
...
modparam("permissions", "grp_col", "group_id")
...
```


#### ip_addr_col (string)


Name of address table column containing IP address
		part of the address.


*Default value is "ip_addr".*


```opensips title="Set ip_addr_col parameter"
...
modparam("permissions", "ip_addr_col", "ip_address")
...
```


#### mask_col (string)


Name of address table column containing network mask of
		the address.  Possible values are 0-32.


*Default value is "mask".*


```opensips title="Set mask_col parameter"
...
modparam("permissions", "mask_col", "subnet_length")
...
```


#### port_col (string)


Name of address table column containing port
		part of the address.


*Default value is "port".*


```opensips title="Set port_col parameter"
...
modparam("permissions", "port_col", "prt")
...
```


#### db_mode (integer)


Database mode. 0 means non-caching, 1 means caching.
		Valid only for allow_trusted function.


*Default value is 0 (non-caching).*


```opensips title="Set db_mode parameter"
...
modparam("permissions", "db_mode", 1)
...
```


#### trusted_table (string)


Name of database table containing matching rules used by
		`allow_register` function.


*Default value is "trusted".*


```opensips title="Set trusted_table parameter"
...
modparam("permissions", "trusted_table", "pbx")
...
```


#### source_col (string)


Name of trusted table column containing source IP
		address that is matched against source IP address of
		received request.


*Default value is "src_ip".*


```opensips title="Set source_col parameter"
...
modparam("permissions", "source_col", "source_ip_address")
...
```


#### proto_col (string)


Name of trusted table column containing transport
		protocol that is matched against transport protocol of
		received request.  Possible values that can be stored in
		proto_col are "any", "udp",
		"tcp", "tls",
		"sctp", and "none".  Value
		"any" matches always and value
		"none" never.


*Default value is "proto".*


```opensips title="Set proto_col parameter"
...
modparam("permissions", "proto_col", "transport")
...
```


#### from_col (string)


Name of trusted table column containing regular
		expression that is matched against From URI.


*Default value is "from_pattern".*


```opensips title="Set from_col parameter"
...
modparam("permissions", "from_col", "regexp")
...
```


#### tag_col (string)


Name of trusted table column containing a string
		that is added as value to peer_tag AVP if peer_tag AVP
                has been defined and if the peer matches.


*Default value is "tag".*


```opensips title="Set tag_col parameter"
...
modparam("permissions", "tag_col", "peer_tag")
...
```


#### peer_tag_avp (AVP string)


If defined, the AVP will be
                set as side effect of allow_trusted() call to not NULL
                tag column value of the matching peer.


*Default value is "undefined".*


```opensips title="Set peer_tag_avp parameter"
...
modparam("permissions", "peer_tag_avp", "$avp(i:707)")
...
```


### Exported Functions


#### allow_routing()


Returns true if all pairs constructed as described in [sec call routing](#call_routing) have appropriate permissions according to 
		the configuration files. This function uses default configuration 
		files specified in `default_allow_file` and
		`default_deny_file`.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_routing usage"
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


- *basename* - Basename from which allow 
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_routing(basename) usage"
...
if (allow_routing("basename")) {
	t_relay();
};
...
```


#### allow_routing(allow_file,deny_file)


Returns true if all pairs constructed as described in 
		[sec call routing](#call_routing) have appropriate permissions 
		according to the configuration files given as parameters.


Meaning of the parameters is as follows:


- *allow_file* - File containing allow rules.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.
- *deny_file* - File containing deny rules.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_routing(allow_file, deny_file) usage"
...
if (allow_routing("rules.allow", "rules.deny")) {
	t_relay();
};
...
```


#### allow_register(basename)


The function returns true if all pairs constructed as described in [sec registration permissions](#registration_permissions) have appropriate permissions 
		according to the configuration files given as parameters.


Meaning of the parameters is as follows:


- *basename* - Basename from which allow 
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_register(basename) usage"
...
if (method=="REGISTER") {
	if (allow_register("register")) {
		save("location");
		exit;
	} else {
		sl_send_reply("403", "Forbidden");
	};
};
...
```


#### allow_register(allow_file, deny_file)


The function returns true if all pairs constructed as described in 
		[sec registration permissions](#registration_permissions) have appropriate 
		permissions according to the configuration files given as parameters.


Meaning of the parameters is as follows:


- *allow_file* - File containing allow rules.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.
- *deny_file* - File containing deny rules.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_register(allow_file, deny_file) usage"
...
if (method=="REGISTER") {
	if (allow_register("register.allow", "register.deny")) {
		save("location");
		exit;
	} else {
		sl_send_reply("403", "Forbidden");
	};
};
...
```


#### allow_uri(basename, pvar)


Returns true if the pair constructed as described in [sec uri permissions](#uri_permissions) have appropriate permissions 
		according to the configuration files specified by the parameter.


Meaning of the parameter is as follows:


- *basename* - Basename from which allow 
			and deny filenames will be created by appending contents of
			`allow_suffix` and `deny_suffix`
			parameters.
If the parameter doesn't contain full pathname then the function 
			expects the file to be located in the same directory as the main 
			configuration file of the server.
- *pvar* - Any
			pseudo-variable defined in OpenSIPS.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_uri(basename, pvar) usage"
...
if (allow_uri("basename", "$rt")) {  // Check Refer-To URI
	t_relay();
};
if (allow_uri("basename", "$avp(i:705)") {  // Check URI stored in $avp(i:705)
	t_relay();
};
...
```


#### allow_address(group_id, ip_addr_pvar, port_pvar)


Returns true if IP address and port given as values of pvar
		arguments belonging to a group given as group_id argument
		matches an IP subnet found in cached address table.
		Cached address table entry containing port value 0
		matches any port.  group_id argument can be an integer
		string or a pseudo variable.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_address() usage"
...

// Check if source address/port is in group 1
if (!allow_address("1", "$si", "$sp")) {
	sl_send_reply("403", "Forbidden");
};
// Check IP address/port stored in AVPs i:704/i:705 is in group 2
if (!allow_address("2", "$avp(i:704)", "$avp(i:705)") {
	sl_send_reply("403", "Forbidden");
};
...
```


#### allow_source_address(group_id)


Equal to allow_address(group_id, "$si", "$sp").


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_source_address(group_id) usage"
...

// Check source address/port of request
if (!allow_source_address("0")) {
	sl_send_reply("403", "Forbidden");
};
...
```


#### allow_source_address_group()


Checks if source address/port is found in cached address or
		subnet table in any group. If yes, returns that group.
		If not returns -1.  Port value 0 in cached address and
		group table matches any port.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_source_address_group() usage"
...

$var(group) = allow_source_address_group();
if ($var(group) != -1) {
   # do something with $var(group)
};
...
```


#### allow_trusted([src_ip_pvar, proto_pvar])


Checks based either on request's source address and transport
		protocol or source address and transport protocol given
		in pvar arguments, and From URI of request
		if request can be trusted without
		authentication.  Returns 1 if a match is found
		as described in [sec trusted requests](#trusted_requests)
		and -1 otherwise.  If a match is found
		and peer_tag_avp has been defined, adds a
                non-NULL tag column value of the
		matching peer to AVP peer_tag_avp.


Source address and transport protocol given in pvar
		arguments must be in string format.  Valid transport
		protocol values are "UDP, "TCP", "TLS", and "SCTP". (case insensitive)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```opensips title="allow_trusted() usage"
...
if (allow_trusted()) {
	t_relay();
};
...
if (allow_trusted("$si", "$proto")) {
	t_relay();
};
...
```


### Exported MI Functions


#### address_reload


Causes permissions module to re-read the contents of
				address database table into cache
				memory.  In cache memory the entries are
				for performance reasons stored in two
                                different tables:  address table and
				subnet table depending on the value of
				the mask field (32 or smaller).


Parameters: *none*


#### address_dump


Causes permissions module to dump
                   contents of cache memory address table.


Parameters: *none*


#### subnet_dump


Causes permissions module to dump
                   contents of cache memory subnet table.


Parameters: *none*


#### trusted_reload


Causes permissions module to re-read the contents of
				trusted table into cache memory.


Parameters: *none*


#### trusted_dump


Causes permissions module to dump contents of trusted
				table from cache memory.


Parameters: *none*


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
