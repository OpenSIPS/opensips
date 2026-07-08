---
title: "Dynamic Routing Module"
---

## Admin Guide


### Overview


#### Introduction


Dynamic Routing is a module for selecting (based on multiple
	criteria) the best gateway/destination to be used for delivering a
	certain call. Least Cost Routing (LCR) is a special case of dynamic
	routing - when the rules are ordered based on costs. Dynamic Routing
	comes with many features regarding routing rule selection:


- prefix based
- caller/group based
- time based
- priority based


, processing :


- stripping and prefixing
- default rules
- inbound and outbound processing
- script route triggering


and failure handling:


- serial forking
- weight based GW selection
- random GW selection
- GW probing for crashes


#### Features


The dynamic routing implementation for OpenSIPS is designed with the
	following properties:


- The routing info (destinations, carriers, rules, groups) is stored in a
	database and loaded into memory at start up time; reload at runtime via
	a Management Interface command.
- weight-based or random selection of the destinations (from a rule or
	 from a carrier), failure detection of gateways (with switching to next
	 available gateway).
- able to handle large volume of routing info (10M of rules) with minimal
	speed/time and memory consumption penalties
- script integration - Pseudo-variable support in functions; scripting
	route triggering when rules are matched
- bidirectional behavior - inbound and outbound processing (strip and
	prefixing when sending and receiving from a destination/GW)
- blacklisting - the module allows definition of blacklists based on the
	destination IPs. This blacklists are to be used to prevent malicious
	forwarding to GWs (based on DNS lookups) when the script logic does
	none-GE forwarding (like foreign domains).
- loading routing information from multiple databases - the gateways, rules, groups and
	carriers can be grouped by partitions, and each partition may be loaded
	from different databases/tables. This makes the routing process partition
	based. In order to be able to use a table from a partition, its name must
	be found in the "version" table belonging to the database defined in the
	partition's db_url.


#### Performance


There were several tests performed regarding the performance of the module
	when dealing with a large number of routing rules.


The tests were performed with a set of 383000 rules and measured:


- time to load from DB
- used shared memory


The time to load was varying between 4 seconds and 8 seconds, depending of
	the caching of the DB client - the first load was the slowest (as the DB
	query hits the disk drive); the following are faster as data is already
	cached in the DB client. So technically speaking, the time to load (without
	the time to query which is DB type dependent) is ~4 seconds


After loading the data into shared memory ~ 96M of memory were used
	exclusively for the DR data.


#### Dynamic Routing Concepts


DR engine uses several concepts in order to define how the routing
	should be done (describing all the dependencies between destinations
	and routing rules).


##### Destination/Gateways


These are the end SIP entities where actually the traffic needs to be sent
	after routing. They are stored in a table called "dr_gateways".
	Gateway addresses are stored in a separate table because of the need to access them
	independent of Dynamic Routing processing (e.g., adding/ removing gateway PRI
	prefix before/after performing other operation -- receiving/relaying to gateway).


In DR, a gateway is defined by:


- id (string)
- SIP address (SIP URI)
- type (integer which allows GWs to be grouped by purpose,
	e.g. inbound, outbound, etc.)
- strip value (number of digits) from dialled
	number
- prefix (string) to be added to dialled
	number
- attributes (not used by DR engine, but only pushed
	to script level when routing to this GW)
- probing mode (how the GW should be probed at SIP level
	- see the probing chapter)


The Gateways are to be used from the routing rule or from the carrier
	definition. They are all the time referred by their ID.


##### Carriers


The carrier concept is used if you need to group gateways in order to
	have a better control on how the GWs will be used by DR rules; like
	in what order the GWs will be used.


Basically, a carrier is a set of gateways which have its own sorting
	algorithm and its own attribute string. They are by default defined
	in the "dr_carriers" table.


In DR, a carrier is defined by:


- id (string)
- list of gateways with/without weights (string)
	(Ex:"gw1=10,gw4=10" or "gw1,gw2"
- flags : 0x1 - use only the first gateway from the carrier
	(depending on the sorting); 0x2 - disable the usage of this
	carrier
- sort algorithm : how the list of the gateways should be
	sorted before being used, NULL - use the DB given order, W - do weight
	based re-ordering, Q - do quality based sorting (requires the qrouting 
	module)
- attributes (not used by DR engine, but only pushed
	to script level when routing to this carrier)


The Carriers are to be used only from the routing rule definition.
	They are all the time referred by their ID.


##### Routing Rules


These are the actual rules which control the routing. Using
	different criterias (prefix, time, priority, etc), they will decide
	to which gateways the call will be sent.


Default name for the table storing rule definitions is
	"dr_rules".


In DR, a routing rule is defined by:


- group (list of numbers) - rules can be grouped (a rule may
	belong to multiple groups in the same time ) and you can
	use only a certain group at a point; like having a "premium" or
	"standard" or "interstate" or
	"intrastate" groups of rules to be used in different
	cases
- prefix (string with digits only) - prefix to be used for
	matching this rule (longest prefix matching)
- time validity (time recurrence string) - when this rule is
	valid from time point of view (see RFC 2445)
- priority (number) - priority of the rule - higher value,
	higher priority (see rule section alg)
- script route ID (string) - if defined, then execute the
	route with the specified ID when this rule is matched. That's it, a route
	which can be used to perform custom operations on message. NOTE that no
	modification is performed at signaling level and you must NOT do
	any signaling operations in that script route
- list of GWs/carriers (string) - a comma separated list
	of gateways or carriers (defined by IDs) to be used for this rule; the
	carrier IDs are prefixed with "#" sign. For each ID (GW or
	carrier) you may specify a weight. For how this list will be interpreted
	(as order) see the rule selection section. Example of list:
	"gw1,gw4,#cr3" or "gw1=10,gw4=10,#cr3=80"
- attributes (not used by DR engine, but only pushed
	to script level when this rule matched and been used)


More on time recurrence:


- A date-time expression that defines the time recurrence to be matched for
	current rule. Time recurrences are based closely on the recurring time
	intervals from the Internet Calendaring and Scheduling Core Object
	Specification (calendar COS), RFC 2445. The set of attributes used in
	a routing rule specification is a subset of time recurrence attributes.
- The value stored in database has the basic format of:
	
	<timezone>|<dtstart>|<dtend>|<duration>|<freq>|<until>|<interval>|<byday>|<bymonthday>|<byyearday>|<byweekno>|<bymonth>
	
	, identical to the input of the [check_time_rec()](../cfgutils#func_check_time_rec)
	function of the *cfgutils* module, including the optional
	use of logical operators linking multiple such strings into a larger expression.
- When an attribute is not specified, the corresponding place must be left
	empty, whenever another attribute that follows in the list has to be
	specified.


#### Routing Rule Processing


The module can be used to find out which is the best gateway to use for new
	calls terminated to PSTN. The algorithm to select the rule is as follows:


- the module discovers the routing group of the originating user. This
	step is skipped if a routing group is passed from the script as parameter.
- once the group is known, in the subset of the rules for this group the
	module looks for the one that matches the destination based on "prefix"
	column. The set of rules with the longest prefix is chosen. If no digit
	from the prefix matches, the default rules are used (rules with no prefix)
- within the set of rules is applied the time criteria, and the rule which
	has the highest priority and matches the time criteria is selected to drive
	the routing.
- Once found the rule, it may contain a route ID to execute. If a certain
	flag is set, then the processing is stopped after executing the route
	block.
- The rule must contain a chain of gateways and carriers. The module will
	execute serial forking for each address in the chain (ordering is either done
	by simply using the definition order or it may weight-based - weight selection must be
	enabled). The next address in chain is used only if the previously has failed.
- With the right gateway address found, the prefix (PRI) of the gateway is
	added to the request URI and then the request is forwarded.


If no rule is found to match the selection criteria an default action must
	be taken (e.g., error response sent back). If the gateway in the chain has
	no prefix the request is forwarded without adding any prefix to the request
	URI.


#### Probing and Disabling destinations


The module has the capability to monitor the status of the destinations by
	doing SIP probing (sending SIP requests like OPTIONS).


For each destination, you can configure what kind of probing should be
	done (probe_mode column):


- *(0)* - no probing at all;
- *(1)* - probing only when the destination is
		in disabled mode (disabling via MI command will completely stop the
		probing also). The destination will be automatically re-enabled
		when the probing will succeed next time;
- *(2)* - probing all the time. If disabled,
		the destination will be automatically re-enabled when the probing
		will succeed next time;


A destination can become disabled in two ways:


- script detection
- MI command


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.


- *tm module*.
- *clusterer* - only if "cluster_id"
				option is enabled.


#### External Libraries or Applications


- *none*.


### Exported Parameters


#### db_url(str)


The database url.


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("drouting", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### drd_table(str)


The name of the db table storing gateway addresses.


*Default value is "dr_gateways".*


```opensips title="Set drd_table parameter"
...
modparam("drouting", "drd_table", "dr_gateways")
...
```


#### drr_table(str)


The name of the db table storing routing rules.


*Default value is "dr_rules".*


```opensips title="Set drr_table parameter"
...
modparam("drouting", "drr_table", "rules")
...
```


#### drg_table(str)


The name of the db table storing groups.


*Default value is "dr_groups".*


```opensips title="Set drg_table parameter"
...
modparam("drouting", "drg_table", "groups")
...
```


#### drc_table(str)


The name of the db table storing definitions of the carriers that will
		be used directly by the routing rules.


*Default value is "dr_carriers".*


```opensips title="Set drc_table parameter"
...
modparam("drouting", "drc_table", "my_dr_carriers")
...
```


#### ruri_avp (str)


The name of the avp for storing Request URIs to be later used
		(alternative destiantions for the current one).


*Default value is "$avp(___dr_ruri__)" if `use_partitions` parameter is 0
		or "$avp(___dr_ruri__partition_name)" where partition_name is the name of the partition
		containing the AVP (as fetched from the database) if `use_partitions` parameter is 1.*


```opensips title="Set ruri_avp parameter"
...
modparam("drouting", "ruri_avp", '$avp(dr_ruri)')
modparam("drouting", "ruri_avp", '$avp(33)')
...
	
```


#### gw_id_avp (str)


The name of the avp for storing the id of the current selected
		gateway/destination - once a new destination is selected (via the
		use_next_gw() function), the AVP will be updated with the ID of the
		new selected gateway/destination.


*Default value is "$avp(___dr_gw_id__)" if `use_partitions` parameter is 0
		or "$avp(___dr_gw_id__partition_name)" where partition_name is the name of the partition
		containing the AVP (as fetched from the database) if `use_partitions` parameter is 1.*


```opensips title="Set gw_id_avp parameter"
...
modparam("drouting", "gw_id_avp", '$avp(gw_id)')
modparam("drouting", "gw_id_avp", '$avp(334)')
...
	
```


#### gw_priprefix_avp (str)


The name of the avp for storing the PRI prefix of the current selected
		destination/gateway - once a new destination is selected (via the
		use_next_gw() function), the AVP will be updated with the PRI prefix of the
		new used destination.


*Default value is "NULL".*


```opensips title="Set gw_priprefix_avp parameter"
...
modparam("drouting", "gw_priprefix_avp", '$avp(gw_priprefix)')
...
	
```


#### rule_id_avp (str)


The name of the avp for storing the id of the current matched
		routing rule (see dr_rules table).


*Default value is "NULL".*


```opensips title="Set rule_id_avp parameter"
...
modparam("drouting", "rule_id_avp", '$avp(rule_id)')
modparam("drouting", "rule_id_avp", '$avp(335)')
...
	
```


#### rule_prefix_avp (str)


The actual prefix that matched the routing rule (the part from RURI
		username that matched the routing rule).


*Default value is "NULL".*


```opensips title="Set rule_prefix_avp parameter"
...
modparam("drouting", "rule_prefix_avp", '$avp(dr_prefix)')
...
	
```


#### carrier_id_avp (str)


AVP to be populate with the ID string for the carrier the
		current GW belongs to.


*Default value is "NULL".*


```opensips title="Set carrier_id_avp parameter"
...
modparam("drouting", "carrier_id_avp", '$avp(carrier_id)')
...
	
```


#### gw_sock_avp (str)


The name of the avp for storing sockets for alternative destinations
		defined by ruri_avp.


*Default value is "$avp(___dr_sock__)" if `use_partitions` parameter is 0
		or "$avp(___dr_sock__partition_name)" where partition_name is the name of the partition
		containing the AVP (as fetched from the database) if `use_partitions` parameter is 1.*


```opensips title="Set gw_sock_avp parameter"
...
modparam("drouting", "gw_sock_avp", '$avp(dr_sock)')
modparam("drouting", "gw_sock_avp", '$avp(77)')
...
	
```


#### define_blacklist (str)


Defines a blacklist based on a list of GW types - the blacklist will 
		be populated with the IPs (no port, all protocols) of the GWs having 
		the specified types.


If partitions are used, prefix the blacklist definition string with 
		the name of the partition followed by ":" separator.


Multiple instances of this param are allowed.


*Default value is "NULL".*


```opensips title="Set define_blacklist parameter"
...
modparam("drouting", "define_blacklist", 'bl_name= 3,5,25,23')
modparam("drouting", "define_blacklist", 'list= 4,2')
modparam("drouting", "define_blacklist", 'pstn:list2 = 5,6')
modparam("drouting", "define_blacklist", 'pstn:list3 = 7,8')
...
	
```


#### default_group (int)


Group to be used if the caller (FROM user) is not found in the GROUP
		table.


*Default value is "NONE".*


```opensips title="Set default_group parameter"
...
modparam("drouting", "default_group", 4)
...
```


#### force_dns (int)


Force DNS resolving of GW/destination names (if not IPs) during
		startup. If not enabled, the GW name will be blindly used during
		routing.


*Default value is "1 (enabled)".*


```opensips title="Set force_dns parameter"
...
modparam("drouting", "force_dns", 0)
...
	
```


#### persistent_state (int)


Specifies whether the *state* column
		should be loaded at startup and flushed during runtime or not.


*Default value is "1" (enabled).*


```opensips title="Set the persistent_state parameter"
...
# disable all DB operations with the state of a gateway
modparam("drouting", "persistent_state", 0)
...
```


#### no_concurrent_reload (int)


If enabled, the module will not allow do run multiple drouting:reload
			MI commands in parallel (with overlapping)  Any new reload will
			be rejected (and discarded) while an existing reload is in
			progress.


If you have a large routing set (millions of rules/prefixes), you
			should consider disabling concurrent reload as they will exhaust
			the shared memory (by reloading into memory, in the same time,
			multiple instances of routing data).


*Default value is "0 (disabled)".*


```opensips title="Set no_concurrent_reload parameter"
...
# do not allow parallel reload operations
modparam("drouting", "no_concurrent_reload", 1)
...
```


#### probing_interval (integer)


How often (in seconds) the probing of a destination should be done. If
		set to 0, the probing will be disabled as functionality (for all
		destinations)


*Default value is "30".*


```opensips title="Set probing_interval parameter"
...
modparam("drouting", "probing_interval", 60)
...
```


#### probing_method (string)


The SIP method to be used for the probing requests.


*Default value is ""OPTIONS"".*


```opensips title="Set probing_method parameter"
...
modparam("drouting", "probing_method", "INFO")
...
```


#### probing_from (string)


The FROM SIP URI to be advertised in the SIP probing requests.


*Default value is ""sip:prober@localhost"".*


```opensips title="Set probing_from parameter"
...
modparam("drouting", "probing_from", "sip:pinger@192.168.2.10")
...
```


#### probing_reply_codes (string)


A comma separted list of SIP reply codes. The codes defined here
		will be considered as valid reply codes for probing messages,
		apart for 200.


*Default value is "NULL".*


```opensips title="Set probing_reply_codes parameter"
...
modparam("drouting", "probing_reply_codes", "501, 403")
...
```


#### probing_socket (string)


A socket description [proto:]host[:port] of the local socket
		(which is used by OpenSIPS for SIP traffic) to be used
		(if multiple) for sending the probing messages from.


For probing gateway the highest priority has socket from gateway
		configuration in dr_gateways table. Then socket from global
		`probing_socket` parameter and the lowest
		priority is default behaviour with auto selected socket wich
		OpenSIPS listens on.


*Default value is "NULL".*


```opensips title="Set probing_socket parameter"
...
modparam("drouting", "probing_socket", "udp:192.168.1.100:5060")
...
```


#### gw_socket_filter_mode (string)


This parameter controls the gateway filtering during DB loading, or which
		gateways are loaded or not into memory depending on the configured
		socket they have.


The supported filtering modes are:


- **"all"** - all the gateways
			defined in DB are loaded into memory, disregarding what socket
			value they have. NOTE: for the gw sockets not matching any OpenSIPS
			listeners/sockets, the GW will be loaded with NULL/no socket.
- **"ignore"** - all the gateways
			defined in DB are loaded into memory, but ignoring the socket
			value they have (the socket will be set to NULL/NONE with no 
			attempt to check it against the OpenSIPS listeners/sockets).
- **"matched-only"** - in this mode
			the module will load from DB only the gateways that have a
			configured a socket matching any of the  the OpenSIPS
			listeners/sockets. If the gateways socket does not match, it will
			be discards, not loaded into memory at all.


*Default value is ""all"".*


```opensips title="Set gw_socket_filter_mode parameter"
...
# multiple OpenSIPS instances sharing a DR setting, so each should
# load only the GWs they have sockets for.
modparam("drouting", "gw_socket_filter_mode", "matched-only")
...
# an OpenSIPs instance not doing routing, but needing to be
# aware of all the gws, so load them all ignoring the sockets
modparam("drouting", "gw_socket_filter_mode", "ignore")
...
```


#### cluster_id (integer)


The ID of the cluster the module is part of. The clustering support is 
		used in drouting module for two purposes: for sharing the status of 
		the gateways/carriers and for controlling the pinging to gateways.


If clustering enbled, the module will automatically share changes
		over the status of the gateways/destinations/carriers with the other 
		OpenSIPS instances that are part of a cluster. Whenever such a status 
		changes (following an MI command, a probing result, a script command),
		the module will replicate this status change to all the nodes in this 
		given cluster.


The clustering with sharing tag support may be used to control which 
		node in the cluster will perform the pinging/probing to 
		gateways. See the
		[cluster sharing tag](#param_cluster_sharing_tag) option.


This OpenSIPS cluster exposes the **"drouting-status-repl"**
capability in order to mark nodes as eligible for becoming data donors during an
arbitrary sync request. Consequently, the cluster must have *at least
one node* marked with the **"seed"** value
as the *clusterer.flags* column/property in order to be fully functional.
Consult the [clusterer - Capabilities](../clusterer#capabilities)
chapter for more details.


For more info on how to define and populate a cluster (with OpenSIPS 
		nodes) see the [clusterer](../clusterer) module.


*Default value is "0 (none)".*


```opensips title="Set cluster_id parameter"
...
# replicate gw/carrier status with all OpenSIPS in cluster ID 9
modparam("drouting", "cluster_id", 9)
...
```


#### cluster_sharing_tag (string)


The name of the sharing tag (as defined per clusterer modules) to 
		control which node is responsible for perform the self-triggered
		actions in the module. Such actions may be the gateway probing (see
		also the [cluster probing mode](#param_cluster_probing_mode) parameter)  or
		sharing the gateway/carrier status changes.
		If defined, only the node with active status of this tag will 
		perform the actions (pinging and sharing status).


The [cluster id](#param_cluster_id) must be defined for this option
		to work.


This is an optional parameter. If not set, all the nodes in the cluster
		will share the status changes.


*Default value is "empty (none)".*


```opensips title="Set cluster_sharing_tag parameter"
...
# only the node with the active "vip" sharing tag will perform pinging
# and broadcast the status changes
modparam("drouting", "cluster_id", 9)
modparam("drouting", "cluster_sharing_tag", "vip")
...
```


#### cluster_probing_mode (string)


This paramter controls how the probing/pinging should be done when
		using the clustering support. It is about which node in the cluster
		pings which gateway/destination.


The [cluster id](#param_cluster_id) must be defined for this option
		to work.


The supported probing modes are:


- **"all"** - all the nodes in the
			cluster will independetly ping all the defined gateways,
			an "all" pings "all" mode.
- **"by-shtag"** - all the gateways
			are pinged by only one node in the cluster, the node having the
			[cluster sharing tag](#param_cluster_sharing_tag) active. By 
			activating the sharing tag on a different node, the pinging
			duty will be transfered to another node in the cluster.
- **"distributed"** - the pinging
			effort is distributed across all the nodes in the cluster, so each
			node will ping a sub-set of the overall set of gateway. Still all
			the gateways will get pinged (and only once per pinging cycle).
			The re-partitioning of the pinging effort over the available nodes
			in the cluster is automatically done when new nodes are joining or
			nodes are dropping out. Still there is no guaratee on which node
			will be responsible for pinging which gateway.


*Default value is ""all"".*


```opensips title="Set cluster_probing_mode parameter"
...
# only the node with the active "vip" sharing tag will perform pinging
modparam("drouting", "cluster_id", 9)
modparam("drouting", "cluster_sharing_tag", "vip")
modparam("drouting", "cluster_probing_mode", "by-shtag")
...
# the pinging effort is distributed across all the nodes
modparam("drouting", "cluster_id", 9)
modparam("drouting", "cluster_probing_mode", "distributed")
...
```


#### use_domain (int)


Flag to configure whether to use domain match when querying
			database for user's routing group.


*Default value is "1".*


```opensips title="Set use_domain parameter"
...
modparam("drouting", "use_domain", 0)
...
```


#### drg_user_col (str)


The name of the column in group db table where the username is stored.


*Default value is "username".*


```opensips title="Set drg_user_col parameter"
...
modparam("drouting", "drg_user_col", "user")
...
```


#### drg_domain_col (str)


The name of the column in group db table where the domain is stored.


*Default value is "domain".*


```opensips title="Set drg_domain_col parameter"
...
modparam("drouting", "drg_domain_col", "host")
...
```


#### drg_grpid_col (str)


The name of the column in group db table where the
			group id is stored.


*Default value is "groupid".*


```opensips title="Set drg_grpid_col parameter"
...
modparam("drouting", "drg_grpid_col", "grpid")
...
```


#### use_partitions (int)


Flag to configure whether to use partitions for routing. If this
		flag is set then the `db_partitions_url` and
		`db_partitions_table`
		variables become mandatory.


*Default value is "0".*


```opensips title="Set use_partitions parameter"
...
modparam("drouting", "use_partitions", 1)
...
```


#### db_partitions_url (str)


The url to the database containing partition-specific
		information. (partition-specific information includes
		partition name, url to the database where information about
		the partition is preserved, the names of the tables in which it
		is preserved and the AVPs that can be accessed using the .cfg
		script). The `use_partitions` parameter
	    must be set to 1.


*Default value is ""NULL"".*


```opensips title="Set db_partitions_url parameter"
...
modparam("drouting", "db_partitions_url", "mysql://user:password@localhost/opensips_partitions")
...
```


#### db_partitions_table (str)


The name of the table containing partition definitions. To be
		used with `use_partitions` and `db_partitions_url`.


*Default value is "dr_partitions".*


```opensips title="Set db_partitions_table parameter"
...
modparam("drouting", "db_partitions_table", "partition_defs")
...
```


#### partition_id_pvar (pvar)


Variable which will store the name of the name partition when
			*wildcard(*)* operatior is used.
			*Use_partitions* must be set in order to
			use this parameter.


NOTE: The variable must be WRITABLE!


*Default value is "null(not used)".*


```opensips title="Set partition_id_pvar parameter"
...
modparam("drouting", "partition_id_pvar", "$var(matched_partition)")
...
```


#### enable_restart_persistency (int)


Parameter set to enable restart persistency for the Dynamic Routing module.
			When this parameter is set, the drouting module no longer loads the data
			from the database after restart, but uses the persistent storage file, and loads
			data from it "on demand", improving the startup performance.


NOTE: If the restart persistent cache is not populated from a previous run,
			then the data will be loaded from database at startup!


NOTE: A reload will update the cached data.


*Default value is "0 (disabled)".*


```opensips title="Set enable_restart_persistency parameter"
...
modparam("drouting", "enable_restart_persistency", yes)
...
```


#### extra_prefix_chars (str)


List of ASCII (0-127) characters to be additionally accepted in
			the prefixes. By default only '0' - '9' chars (digits) are
			accepted.


*Default value is "NULL".*


```opensips title="Set extra_prefix_chars parameter"
...
modparam("drouting", "extra_prefix_chars", "#-%")
...
```


#### extra_id_chars (str)


A set of extra characters to be allowed in both Gateway and Carrier
			unique string identifiers, on top of alphanumeric characters.


*Default value is "_-.".*


```opensips title="Set extra_id_chars parameter"
...
modparam("drouting", "extra_id_chars", ":_-.")
...
```


#### rule_tables_query (str)


This parameter offers a dynamic, SQL-based way of building a set of
			*dr_rules*-compatible table names, to be
			each loaded and then merged into a single "dr_rules" table,
			for any given partition.


The syntax of the parameter is:
			"**token** : **query**",
			where **token** is a special name
			given to a "dr_rules" table, so OpenSIPS can match it against
			the custom queries defined using this parameter.


This parameter may be set multiple times (each definition creates
			a new mapping).


```opensips title="Set the rule_tables_query parameter"
...
# first, set the "dr_rules" table name to the name of your query
modparam("drouting", "drr_table", "MY_RULES_QUERY")

# next, instruct drouting to load both 'dr_rules_a' and 'dr_rules_b',
# then merge all of their rules
modparam("drouting", "rule_tables_query", "
	MY_RULES_QUERY:
		SELECT 'dr_rules_a' UNION SELECT 'dr_rules_b'")
...
```


#### generate_data_checksum (int)


If enabled, it will generate a checksum ( MD5 ) for drouting loaded data, attach that to the reload_status MI command output and to the reload generated status reports


```opensips title="Set the generate_data_checksum parameter"
...
modparam("drouting", "generate_data_checksum", 1)
...
		
```


### Exported Functions


#### do_routing([groupID], [flags], [gw_whitelist], [rule_attrs_pvar], [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


Function to trigger routing of the message according to the
		rules in the database table and the configured parameters.


This function can be used from all routes.


If you set `use_partitions` to 1 the 
		**partition** last parameter becomes 
		mandatory.


All parameters are optional. Any of them may be ignored, provided
		the necessary separation marks "," are properly placed.


- **groupID** (int, optional) - number to 
			specify the group of the caller for routing purposes.
			If none specified the function will automatically try to query
			the dr_group table to get this
- **flags** (string, optional) - a list
			of letter-like flags for controlling the routing behavior.
			Possible flags are:

  - **F** - Enable rule fallback; 
				normally the engine is using a single rule for routing a call;
				by setting this flag, the engine will fallback and use
				rules with less priority or shorter prefix when all the
				destination from the current rules failed.
  - **L** - Do strict length matching
				over the prefix - actually DR engine will do full number 
				matching and not prefix matching anymore.
  - **C** - Only check if the dialed
				number matches any routing rule, without loading / applying any
				routing info (no GW is set, the RURI is not altered)
- **gw_whitelist** (string, optional) - a
			comma separated white list of gateways. This will force routing over,
			at most, this list of carriers or gateways (in other words, 
			the whitelist will be intersected with the results of the search 
			through the rules).
- **rule_attrs_pvar** (var, optional) - a
			writable variable which will be  populated with the attributes of the
			matched dynamic routing rule.
- **gw_attrs_pvar** (var, optional) - a
			writable variable which will be 
			populated with the attributes of the matched gateway.
- **carrier_attrs_pvar** (var, optional) - a
			a writable variable which will be
			populated with the attributes of the matched carrier.
- **partition** (string, optional) - the name
			of the DR partition to be used. This parameter is to be defined
			ONLY if the "use_partition" module parameter is turned on.
			Besides specifing the name of one partition, you can use the "*" 
			wildcard sign to force routing over all partitions.


```c title="do_routing usage"
...
# all groups, sort on order, 
```


#### route_to_carrier( carriers, [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


Function to trigger the direct routing to a given set carriers (one 
		or more). So, the routing is not done prefix based, but carrier based 
		(call will be sent to the GWs of that carrier, based on carrier 
		policy).


This function can be used from all routes.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter also (where the carrier are to be
		found).


- **carriers** (string) - comma separated
					carrier IDs (names)
- **gw_attrs_pvar** (var, optional) -
					an output writable variable which will be populated
					with the attributes of the currently matched gateway of 
					this carrier.
- **carrier_attrs_pvar** (var, 
					optional) - an output writable variable which will be populated 
					with the attributes of this carrier.
- **partition** (string, optional) -
					the name of the DR partition to be used. This parameter is
					to be defined ONLY if the "use_partition" module parameter
					is turned on. Wildcard sign is not accepted by the 
					function.


```opensips title="route_to_carrier usage"
...
# use_partitions is not set
if ( route_to_carrier("my_top_carrier, def_carrier", , $var(carrier_att)) ) {
	xlog("Routing to \"my_top_carrier\" - $var(carrier_att)\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
# use_partitions is enabled
if ( route_to_carrier("my_top_carrier", , $var(carrier_att), "part") ) {
	xlog("Routing to \"my_top_carrier\" - $var(carrier_att)\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
# use_partitions is enabled
if ( route_to_carrier($var(carrierId), , , $var(my_partition)) ) {
	xlog("Routing to \"my_top_carrier\"\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
```


#### route_to_gw(gw_id, [gw_attrs_var], [carrier_attrs_var], [partition])


Function to trigger the direct routing to a given gateway (or list of
		gateways). Attributes and per-gw processing will be available.


This function can be used from all routes.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


- **gw_id** (string) - comma
					separated list of gateway IDs to be used.
- **gw_attrs_pvar**  (var, optional)
					- an output writable variable which will be populated
					with the attributes of the currently matched gateway.
- **carrier_attrs_pvar** (var, 
					optional) - an output writable variable which will be 
					populated with the attributes of this carrier. NOTE: the
					first carrier pointing to the GW(s) will be considered!
- **partition** (string, optional) -
					the name of the DR partition to be used. This parameter is
					to be defined ONLY if the "use_partition" module parameter
					is turned on. Wildcard sign is not accepted by the 
					function.


```opensips title="route_to_gw usage"
...
# use_partitions is not set
if ( route_to_gw("gw_europe") ) {
	t_relay();
	exit;
}
...
# use_partitions is not set
if ( route_to_gw("gw1,gw2,gw3", $var(gw_attrs)) ) {
	xlog("Relaying to first gateway from our list - $var(gw_attrs)\n");
	t_relay();
	exit;
}
...
# use_partitions is enabled
if ( route_to_gw("gw_europe", , , "my_partition") ) {
	t_relay();
	exit;
}
...
# use_partitions is enabled
if ( route_to_gw("gw1,gw2,gw3", $var(gw_attrs), , "my_partition") ) {
	xlog("Relaying to first gateway from our list - $var(gw_attrs)\n");
	t_relay();
	exit;
}
...
```


#### use_next_gw( [rule_attrs_pvar], [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


The function takes the next available destination (set by do_routing,
		as alternative destinations) and pushes it into the RURI. Note that the
		function just sets the RURI (nothing more).


If a new RURI is set, the used destination is removed from the
		pending set of alternative destinations.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


The function returns true only if a new RURI was set. False
		is returned is no other alternative destinations are found or in case
		of an internal processing error. It may take the following optional 
		parameters:


- **rule_attrs_pvar** (var, optional)
					- an output writable variable which will be populated
					with the attributes of the matched dynamic routing rule.
- **gw_attrs_pvar** (var, optional) - an
					output writable variable which will be populated
					with the attributes of the matched gateway.
- **carrier_attrs_pvar** (var, optional) 
					- an output writable variable which will be populated
					with the attributes of the matched carrier.
- **partition** (optinal, string) -
					the name of the DR partition to be used. This parameter is
					to be defined ONLY if the "use_partition" module parameter
					is turned on. Wildcard sign is not accepted by the 
					function.


```opensips title="use_next_gw usage"
...
# use_partitions is not set
if (use_next_gw()) {
	t_relay();
	exit;
}
...
# Also fetch the carrier attributes, if any
if (use_next_gw(, , $var(carrier_attrs))) {
	xlog("Carrier attributes of current gateway: $var(carrier_attrs)\n");
	t_relay();
	exit;
}
...
# use_partitions is enabled
if (use_next_gw( , , ,"my_partition")) {
	t_relay();
	exit;
}
...
# Also fetch the carrier attributes, if any
if (use_next_gw( , ,$var(carrier_attrs), "my_partition")) {
	xlog("Carrier attributes of current gateway: $var(carrier_attrs)\n");
	t_relay();
	exit;
}
...
```


#### goes_to_gw( [type], [flags], [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


Function returns true if the destination of the current request
		(destination URI or Request URI) points (as IP) to one of the gateways.
		There no DNS lookups done if the domain part of the URI is not an IP.


This function does not change anything in the message.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE, ONREPLY_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


It may take the following optional parameters:


- **type** (int, optional) - number for
				the GW/destination type to be checked; when omitting this 
				parameter or specifying the special value *-1*, matching will 
				be done against all types.
- **flags** (string, optional) - 
				letter like flags for controlling what operations should be 
				performed when a GW matches:

  - **'s'** (Strip) - apply
						to the username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply
						to the username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - 
						return the gateway id into gw_id_avp AVP
  - **'n'** (Ignore port) -
						ignores port number during matching
  - **'c'** (Carrier ID) - 
						return the carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (var, optional) -
				an  output writable variable which will be populated with
				the attributes of the matched gateway.
- **carrier_attrs_pvar** (var, optional) - an 
				output writable variable which will be populated with
				the attributes of the matched carrier.
- **partition** (string, optional) - 
				the name of the DR partition to be used. This parameter is
				to be defined ONLY if the "use_partition" module parameter
				is turned on. Wildcard sign is accepted by this 
				function.


```opensips title="goes_to_gw usage"
...
# use_partitions is not set
if (goes_to_gw( 1, , $var(gw_attrs))) {
	sl_send_reply(403,"Forbidden");
	exit;
}
...
# use_partitions is enabledt
if (goes_to_gw(1, , $var(gw_attrs), , "my_partition")) {
	sl_send_reply(403,"Forbidden");
	exit;
}
...
```


#### is_from_gw([type], [flags], [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


The function checks if the sender of the message (source IP + source
		port) is a gateway from a certain group.


This function does not change anything in the message.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE and ONREPLY_ROUTE.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


It may take the following optional parameters:


- **type** (int, optional) - number for
				the GW/destination type to be checked; when omitting this 
				parameter or specifying the special value *-1*, matching will 
				be done against all types.
- **flags** (string, optional) - 
				letter like flags for controlling what operations should be 
				performed when a GW matches:

  - **'s'** (Strip) - apply
						to the username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply
						to the username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - 
						return the gateway id into gw_id_avp AVP
  - **'n'** (Ignore port) -
						ignores port number during matching
  - **'r'** (Check protocol) - check protocol
  - **'c'** (Carrier ID) - 
					return the carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (var, optional) - an 
				output writable variable which will be populated with
				the attributes of the matched gateway.
- **carrier_attrs_pvar** (var, optional) - an 
				output writable variable which will be populated with
				the attributes of the matched carrier.
- **partition** (string, optional) - 
				the name of the DR partition to be used. This parameter is
				to be defined ONLY if the "use_partition" module parameter
				is turned on. Wildcard sign is accepted by this 
				function.


```opensips title="is_from_gw usage"
# use_partitions is not set
# match the source IP (only) against all gateways
if (is_from_gw(-1, "n")) {
	...
}

# use_partitions is enabled
# match the source IP and port against all gateways from the "outbound"
# partition and return the matched gateway's carrier
if (is_from_gw(, "c", , , "outbound")) {
	...
}
```


#### dr_is_gw( sip_uri, [type], [flags], [gw_attrs_pvar], [carrier_attrs_pvar], [partition])


The function checks if the SIP URI hostname part stored inside the
		"src_pv" pseudo-variable is a gateway from a certain group.


This function does not change anything in the message.


This function can be used from all routes.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


It may take the following optional parameters:


- **sip_uri** (string) - SIP URI.
				If the URI hostname part is a FQDN,
				it will be resolved prior to matching.
- **type** (int, optional) - number for
				the GW/destination type to be checked; when omitting this 
				parameter or specifying the special value *-1*, matching will 
				be done against all types.
- **flags** (string, optional) - 
				letter like flags for controlling what operations should be 
				performed when a GW matches:

  - **'s'** (Strip) - apply
						to the username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply
						to the username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - 
						return the gateway id into gw_id_avp AVP
  - **'n'** (Ignore port) -
						ignores port number during matching
  - **'c'** (Carrier ID) - 
						return the carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (var, optional) - an  
				output writable variable which will be populated with
				the attributes of the matched gateway.
- **carrier_attrs_pvar** (var, optional) - an 
				output writable variable which will be populated with
				the attributes of the matched carrier.
- **partition** (string, optional) - 
				the name of the DR partition to be used. This parameter is
				to be defined ONLY if the "use_partition" module parameter
				is turned on. Wildcard sign is accepted by this 
				function.


```opensips title="dr_is_gw usage"
# match the SIP URI host within $var(uac) against all gateways
if (dr_is_gw( $var(uac), , "n")) {
	...
}


# match the SIP URI host within $var(uac) against
# all gws in "outbound" partition
if (dr_is_gw( $avp(uac), , "n", , , "partition")) {
	...
}
```


#### dr_disable([partition])


Marks as disabled the last destination that was used for the current
		call. The disabling done via this function will prevent the
		destination to be used for usage from now on. The probing mechanism
		can re-enable this peer (see the probing section in the beginning)


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE, ONREPLY_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` parameter to 1 you must 
		supply the "partition" parameter to instruct on the partition where the
		gateway has been defined.


It may take the following parameters:


- **partition** (string, optional) - 
				the name of the DR partition to be used. This parameter is
				to be defined ONLY if the "use_partition" module parameter
				is turned on. Wildcard sign is accepted by this 
				function.


```opensips title="dr_disable() usage"
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	dr_disable();

}
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	dr_disable("my_partition");

}
...
```


#### dr_match(groupID, [flags], number, [rule_attrs_pvar], [partition])


The function tries to match/check the given number against the
		rules from the database.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE, ONREPLY_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` to 1 the 
		**partition** last parameter becomes 
		mandatory.


The parameters are:


- **groupID** (int) - number to 
			specify the dr group (set of rules) to perform the check against
- **flags** (string, optional) - a list
			of letter-like flags for controlling the checking/matching behavior.
			Possible flags are:

  - **L** - Do strict length matching
				over the prefix - actually DR engine will do full number 
				matching and not prefix matching anymore.
- **number** (string) - the number to check
- **rule_attrs_pvar** (var, optional) - a
			writable variable which will be  populated with the attributes of the
			matched dynamic routing rule.
- **partition** (string, optional) - the name
			of the DR partition to be used. This parameter is to be defined
			ONLY if the "use_partition" module parameter is turned on.


```opensips title="dr_match usage"
...
if ( dr_match( 1, "L" , $fU, ,"dids") )
	xlog("Full From Username $fU found in group 1 partition DIDS\n");
...
if ( dr_match( 1, , $var(did) ) )
	xlog("DID $var(did) matches rules in group 1\n");
...
```


### Exported MI Functions


#### drouting:reload


Replaces obsolete MI command: *dr_reload*.


Command to reload routing rules from database.


- if `use_partition` is set to 0 - all routing rules will be reloaded.

					
						*inherit_state* (optional) : whether inherit old state of the gateway , default is y.
							
								"n": no inherit state
								"y": inherit state
- if `use_partition` is set to 1, the parameters are:
					
						*partition_name* (optional) - if not provided
							all the partitions will be reloaded, otherwise just the partition given as parameter will be reloaded.
					

					
						*inherit_state* (optional) : whether inherit old state of the gateway , default is y.
							
								"n": no inherit state
								"y": inherit state


MI FIFO Command Format:


```bash
		opensips-cli -x mi drouting:reload part_1
		
```


#### drouting:gw_status


Replaces obsolete MI command: *dr_gw_status*.


Gets the status (enabled or disabled) of one or multiple gateways. The function
		can also be used to set the status of a single gateway.


- if `use_partitions` is set to 0, the parameters are:
				
					*gw_id* (optional) - the id of
					a gateway. If provided, the function will return/set (depnding if the second
					parameter is given) the status of that gateway, otherwise it will list all
					gateways along with their statuses.
					*status* (optional) - the new status
					to be forced for a GW (0 - disable, 1 - enable). Only makes sense if
					*gw_id* is provided.
- if `use_partitions` is set to 1, the parameters are:
				
					*partition_name*
					*gw_id* (optional) - the id of
					a gateway. If provided, the function will return/set (depnding if the third
					parameter is given) the status of that gateway, otherwise it will list all
					gateways in the given partition along with their statuses.
					*status* (optional) - the new status
					to be forced for a GW (0 - disable, 1 - enable). Only makes sense if
					*gw_id* is provided.


```bash title="drouting:gw_status usage when use_partitions is set to 0"
$ opensips-cli -x mi drouting:gw_status gw_id=2
State:: Active
$ opensips-cli -x mi drouting:gw_status gw_id=2 status=0
$ opensips-cli -x mi drouting:gw_status gw_id=2
Enabled:: Disabled MI
$ opensips-cli -x mi drouting:gw_status gw_id=3
Enabled:: Inactive
```


```bash title="drouting:gw_status usage when use_partitionsis set to 1"
$ opensips-cli -x mi drouting:gw_status partition_name=part_1 gw_id=my_gw
State:: Active
$ opensips-cli -x mi drouting:gw_status partition_name=part_1 gw_id=my_gw status=0
$ opensips-cli -x mi drouting:gw_status partition_name=part_1 gw_id=my_gw
enabled:: disabled mi
$ opensips-cli -x mi drouting:gw_status partition_name=partition8 status=3
enabled:: inactive
```


#### drouting:carrier_status


Replaces obsolete MI command: *dr_carrier_status*.


Gets the status (enabled or disabled) of one or multiple carriers. The function
		can also be used to set the status of a single carrier.


- if `use_partitions` is set to 0, the parameters are:
				
					*carrier_id* (optional) - the id of
					a carrier. If provided, the function will return/set (depnding if the second
					parameter is given) the status of that carrier, otherwise it will list all
					carriers along with their statuses.
					*status* (optional) - the new status
					to be forced for a carrier (0 - disable, 1 - enable). Only makes sense if
					*carrier_id* is provided.
- if `use_partitions` is set to 1, the parameters are:
				
					*partition_name*
					*carrier_id* (optional) - the id of
					a carrier. If provided, the function will return/set (depnding if the third
					parameter is given) the status of that carrier, otherwise it will list all
					carriers contained in the given partition along with their statuses.
					*status* (optional) - the new status
					to be forced for a carrier (0 - disable, 1 - enable). Only makes sense if
					*carrier_id* is provided.


```bash title="drouting:carrier_status usage when use_partitions is 0"
$ opensips-cli -x mi drouting:carrier_status carrier_id=CR1
Enabled:: no
$ opensips-cli -x mi drouting:carrier_status carrier_id=CR1 status=1
$ opensips-cli -x mi drouting:carrier_status carrier_id=CR1
Enabled:: yes
```


```bash title="drouting:carrier_status usage when use_partitions is 1"
$ opensips-cli -x mi drouting:carrier_status partition_name=my_partition carrier_id=CR1
Enabled:: no
$ opensips-cli -x mi drouting:carrier_status partition_name=partition_1 carrier_id=CR1 status=1
$ opensips-cli -x mi drouting:carrier_status partition_name=partition_3 carrier_id=CR1
Enabled:: yes
```


#### drouting:reload_status


Replaces obsolete MI command: *dr_reload_status*.


Gets the time of the last reload for any partition.


- if `use_partition` is set to 0 - the function
					doesn't receive any parameter. It will list the date of the
					last reload for the default (and only) partition.
- if `use_partition` is set to 1, the parameters are:
					
						*partition_name* (optional) - if not provided
							the function will list the time of the last update for every
							partition. Otherwise, the function will list the time of the last
							reload for the given partition.


```bash title="drouting:reload_status usage when use_partitions is 0"
$ opensips-cli -x mi drouting:reload_status
Date:: Tue Aug 12 12:26:00 2014
```


```bash title="drouting:reload_status usage when use_partitions is 1"
$ opensips-cli -x mi drouting:reload_status
Partition:: part_test Date=Tue Aug 12 12:24:13 2014
Partition:: part_2 Date=Tue Aug 12 12:24:13 2014
$ opensips-cli -x mi drouting:reload_status part_test
Partition:: part_test Date=Tue Aug 12 12:24:13 2014
```


#### drouting:number_routing


Replaces obsolete MI command: *dr_number_routing*.


Gets the matched prefix along with the list of the gateways / carriers to which a number
			would be routed when using the do_routing function.


- if `use_partition` is set to 1 the function
					will have 3 parameters:
					
						
							*partition_name*
						
						
							*group_id* (optional) - the group id of the rules to
								check against
						
						
							*number* - the number to test against
- if `use_partition` is set to 0 the function will have 2 parameters:
					
						*group_id* (optional) - the group id of the rules to check against
						*number* - the number to test against


MI FIFO Command Format:


```bash
		opensips-cli -x mi drouting:number_routing partition_name=part1 group_id=3 number=012340987
		
```


#### drouting:enable_probing


Replaces obsolete MI command: *dr_enable_probing*.


Enables/disables gateway probing or returns the current gateway
		probing status.


Parameters:


- *status* (optional) - 1 - enable,
				0 - disable gateway probing


```bash title="drouting:enable_probing usage"
$ opensips-cli -x mi drouting:enable_probing
Status:: 1
$ opensips-cli -x mi drouting:enable_probing 0
$ opensips-cli -x mi drouting:enable_probing
Status:: 0
		
```


### Exported Events


#### E_DROUTING_STATUS


This event is raised when the module changes the state of a gateway,
			either through an MI command, probing or script function.


Parameters:


- *partition* - the name of the partition.
- *gwid* - the gateway identifier.
- *address* - the address of the gateway.
- *status* - *disabled MI* if
				the gateway was disabled using MI commands,
				*probing* if the gateway is being pinged,
				*inactive* if it was disabled from the script or
				*active* if the gateway is enabled.


### Exported Status/Report Identifiers


The module provides the "drouting" Status/Report group, where each
	routing partition is defined as a separate SR identifier.


#### [partition_name]


The status of these identifiers reflects the readiness/status of the 
	cached data (if available or not when being loaded from DB):


- *-2* - no data at all (initial status)
- *-1* - no data, initial loading in progress
- *1* - data loaded, partition ready
- *2* - data available, a reload in progress


Reload reporting:


In terms of data reloading, the following logs will be reported:


- starting DB data loading
- DB data loading failed, discarding
- DB data loading successfully completed
- N gateways loaded (N discarded), N carriers loaded (N discarded), N rules loaded (N discarded)


```json
    {
        "Name": "Default",
        "Reports": [
            {
                "Timestamp": 1652353940,
                "Date": "Thu May 12 14:12:20 2022",
                "Log": "starting DB data loading"
            },
            {
                "Timestamp": 1652353940,
                "Date": "Thu May 12 14:12:20 2022",
                "Log": "DB data loading successfully completed"
            },
            {
                "Timestamp": 1652353940,
                "Date": "Thu May 12 14:12:20 2022",
                "Log": "2 gateways loaded (0 discarded), 2 carriers loaded (0 discarded), 1 rules loaded (0 discarded)"
            }
        ]
    }
	
```


#### [partition_name];events


GW/Carrier switching reporting:


For reporting events related to the state changes of the
	gateways and carriers, the module provides separate identifiers (still
	one per partition).
	Why separate ones? The reports on state changing may be verbose and there
	is the risk of loose/discard important reports on reloads due to the high
	number of logs on state changes;


So, each partition will provide the identified "partition_name;events" for
	reporting state changes of gateways and carriers, along with the reason
	of the change. This identifiers have a 200 records history before 
	discarding the old ones.


```json
    {
        "Name": "Default;events",
        "Reports": [
            {
                "Timestamp": 1652353976,
                "Date": "Thu May 12 14:12:56 2022",
                "Log": "GW <gw1_1>/127.0.1.1 switched to [inactive] due probing reply\n"
            },
            {
                "Timestamp": 1652353976,
                "Date": "Thu May 12 14:12:56 2022",
                "Log": "GW <gw2_1>/127.0.1.2 switched to [inactive] due probing reply\n"
            }
        ]
    }
	
```


For how to access and use the Status/Report information, please see
	[https://www.opensips.org/Documentation/Interface-StatusReport-3-3](>https://www.opensips.org/Documentation/Interface-StatusReport-3-3).


### Installation


The module requires 4 tables in the OpenSIPS database: dr_groups,
	dr_gateways, dr_carriers, dr_rules. The SQL syntax to create them can be
	found in the drouting-create.sql script, located in the database directories
	of the opensips/scripts folder. You can also find the complete
	database documentation on the project webpage, [https://opensips.org/docs/db/db-schema-devel.html](https://opensips.org/docs/db/db-schema-devel.html).


## Developer Guide


The module provides no function to be used
		by other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
