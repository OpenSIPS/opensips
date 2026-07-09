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
- type (positive integer which allows GWs to be grouped by purpose,
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
- flags : 0x1 - use weight for sorting the list and
	not definition order; 0x2 - use only the first gateway from the carrier
	(depending on the sorting); 0x4 - disable the usage of this
	carrier
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
	intervals from the Internet Calendaring and Scheduling
	Core Object Specification (calendar COS), RFC 2445. The set of attributes
	used in routing rule specification is a subset of time recurrence attributes.
- The value stored in database has the format of:
	
	<dtstart>|<duration>|<freq>|<until>|<interval>|<byday>|<bymonthday>|<byyearday>|<byweekno>|<bymonth>
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


#### rule_attrs_avp (str)


The name of the avp for storing rule attrs in case they are requested at least
		once in the script.


*Default value is "$avp(___dr_ru_att__)" if `use_partitions` parameter is 0
		or "$avp(___dr_ru_att__partition_name)" where partition_name is the name of the partition
		containing the AVP (as fetched from the database) if `use_partitions` parameter is 1.*


```opensips title="Set rule_attrs_avp parameter"
...
modparam("drouting", "rule_attrs_avp", '$avp(dr_rule_attr)')
modparam("drouting", "rule_attrs_avp", '$avp(11)')
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


If enabled, the module will not allow do run multiple dr_reload
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


#### db_partitions_url (int)


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


#### db_partitions_table (int)


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


### Exported Functions


#### do_routing([part_and_or_groupID], [flags], [gw_whitelist], [rule_attrs_pvar], [gw_attrs_pvar], [carrier_attrs_pvar])


Function to trigger routing of the message according to the
		rules in the database table and the configured parameters.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` to 1 the **part_or_groupID** parameter becomes mandatory.


All parameters are optional. Any of them may be ignored, provided
			the necessary separation marks "," are properly placed.


- **part_and_or_groupID** - Specifies the group of the caller
					for routing purposes. Depending on the value of the `use_partitions`
					parameter, it contains:

  - the routing group the caller belongs to if `use_partitions`
						is 0 - this may be a statical numerical value or an AVP specification (value
						must be numerical type, string types are ignored!). If none specified the
						function will automatically try to query the dr_group table to get this information
  - the partition and routing group the caller belongs to, the format is:
						"partition':'[groupID]" if `use_partitions`
						parameter is 1 - both the partition name and the groupId may be statical
						values or AVP specifications. If no group is specified the function will
						try to query the dr_group table for the given partition to get this information.
						If ** (wildcard)* operator is used all partitions shall be checked.
- **flags** - Controls the behavior of the
					function. Possible flags are:

  - **W** - Instead of using the destination
						(from the rule definition) in the given order, sort them
						based on their weight.
  - **F** - Enable rule fallback; normally
						the engine is using a single rule for routing a call; by
						setting this flag, the engine will fallback and use
						rules with less priority or shorter prefix when all the
						destination from the current rules failed.
  - **L** - Do strict length matching over the
						prefix - actually DR engine will do full number matching and
						not prefix matching anymore.
  - **C** - Only check if the dialed number
						matches any routing rule, without loading / applying any
						routing info (no GW is set, the RURI is not altered)
- **gw_whitelist** - a comma separated white
					list of gateways. This will force routing over, at most, this
					list of carriers or gateways (in other words, the whitelist
					will be intersected with the results of the search through the rules).
- **rule_attrs_pvar** (output, optional)- a writable
					pseudo-variable which will be populated with the attributes
					of the matched dynamic routing rule.
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the matched gateway.
- **carrier_attrs_pvar** (output, optional) - a writable
					pseudo-variable which will be populated with the attributes
					of the matched carrier.


```c title="do_routing usage"
...
# all groups, sort on order, 
```


#### route_to_carrier(part_and_or_carrier_id, [gw_attrs_pvar], [carrier_attrs_pvar])


Function to trigger the direct routing to a given carrier. In this case
		the routing is not done prefix based, but carrier based (call will be
		sent to the GWs of that carrier, based on carrier policy).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE and LOCAL_ROUTE..


If you set `use_partitions` parameter to 1 you must supply
		the partition in which the carrier has been defined.


- **part_and_or_carrier_id** (mandatory):

  - the ID (name) of the carrier to be used, if `use_partitions`
								parameter is 0; pseudo-variables are accepted.
  - the partition and carrier to be used, if `use_partitions` parameter
								is 1. The format is "partition_name':'carrierId"; pseudo-variables are accepted.
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the currently matched gateway of this carrier.
- **carrier_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with the attributes
					of this carrier.


```opensips title="route_to_carrier usage when use_partitions parameter is 0"
...
if ( route_to_carrier("my_top_carrier", , "$var(carrier_att)") ) {
	xlog("Routing to \"my_top_carrier\" - $var(carrier_att)\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
```


```opensips title="route_to_carrier usage when use_partitions parameter is 1"
...
if ( route_to_carrier("my_partition:my_top_carrier", , "$var(carrier_att)") ) {
	xlog("Routing to \"my_top_carrier\" - $var(carrier_att)\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
```


```opensips title="route_to_carrier usage when use_partitions parameter is 1 with pseudovariables"
...
if ( route_to_carrier("$var(my_partition):$var(carrierId)") ) {
	xlog("Routing to \"my_top_carrier\" - $var(carrier_att)\n");
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
```


#### route_to_gw(gw_id, [gw_attrs_pvar])


Function to trigger the direct routing to a given gateway (or list of gateways).
		Attributes and per-gw processing will be available.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE and LOCAL_ROUTE.


If you set `use_partitions` parameter to 1 you must supply
		the partition in which the gateway has been defined.


- **gw_id** (mandatory) - the list
					of gateways to be used.
					
						
							a comma separated list of gateway ID's to be used, if
								no `use_partition` parameter is 0. Pseudo-variables
								are accepted.
						
						
							the desired partition, followed by a comma separated list of gateway ID's
								from that partition to be used, if `use_partition` parameter
								is 1. The format is: "partition_name':'gwId1, gwId2, gwId3". Pseudo-variables
								are accepted.
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the currently matched gateway.


```opensips title="route_to_gw usage when use_partition parameter is 0"
...
if ( route_to_gw("gw_europe") ) {
	t_relay();
	exit;
}
...
if ( route_to_gw("gw1,gw2,gw3", "$var(gw_attrs)") ) {
	xlog("Relaying to first gateway from our list - $var(gw_attrs)\n");
	t_relay();
	exit;
}
...
```


```opensips title="route_to_gw usage when use_partition parameter is 1"
...
if ( route_to_gw("my_partition:gw_europe") ) {
	t_relay();
	exit;
}
...
if ( route_to_gw("my_partition:gw1,gw2,gw3", "$var(gw_attrs)") ) {
	xlog("Relaying to first gateway from our list - $var(gw_attrs)\n");
	t_relay();
	exit;
}
...
```


#### use_next_gw([partition','] [rule_attrs_pvar], [gw_attrs_pvar], [carrier_attrs_pvar])/next_routing()


The function takes the next available destination (set by do_routing,
		as alternative destinations) and pushes it into the RURI. Note that the
		function just sets the RURI (nothing more).


If a new RURI is set, the used destination is removed from the
		pending set of alternative destinations.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE and LOCAL_ROUTE.


The function returns true only if a new RURI was set. False
		is returned is no other alternative destinations are found or in case
		of an internal processing error. It may take the following optional parameters:


If you set `use_partitions` parameter to 1 you must supply
			the partition (the partition becomes mandatory) in which the gateways have been defined.


- **partition** (mandatory if `use_partitions
					` parameter is 1, otherwise it will be omitted altogether) It is
					the partition in which the gateways have been defined.
- **rule_attrs_pvar** (output, optional) - a writable
					pseudo-variable which will be populated with the attributes
					of the matched dynamic routing rule.
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the matched gateway.
- **carrier_attrs_pvar** (output, optional) - a writable
					pseudo-variable which will be populated with the attributes
					of the matched carrier.


```opensips title="use_next_gw usage"
...
if (use_next_gw()) {
	t_relay();
	exit;
}
...
# Also fetch the carrier attributes, if any
if (use_next_gw(, , "$var(carrier_attrs)")) {
	xlog("Carrier attributes of current gateway: $var(carrier_attrs)\n");
	t_relay();
	exit;
}
...
```


```opensips title="use_next_gw usage when use_partition parameter is 1"
...
if (use_next_gw("my_partition")) {
	t_relay();
	exit;
}
...
# Also fetch the carrier attributes, if any
if (use_next_gw("my_partition", , "$var(carrier_attrs)")) {
	xlog("Carrier attributes of current gateway: $var(carrier_attrs)\n");
	t_relay();
	exit;
}
...
```


#### goes_to_gw([partition','] [type], [flags], [gw_attrs_pvar])


Function returns true if the destination of the current request
		(destination URI or Request URI) points (as IP) to one of the gateways.
		There no DNS lookups done if the domain part of the URI is not an IP.


This function does not change anything in the message.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE
		and LOCAL_ROUTE.


If you set `use_partitions` parameter to 1 you must supply
			the partition (the partition becomes mandatory) in which the gateways have been defined.


If `use_partitions` parameter is 0
			all parameters are optional. Any of them may be ignored, provided
			the necessary separation marks "," are properly placed.


- **partition** (mandatory if `use_partitions
					` parameter is 1, otherwise it will be omitted altogether) - the name
					of the partition containing the gateway/destination to be checked.
- **type** (optional) - GW/destination
					type to be checked; when omitting this parameter or specifying
					a special value ("-1" or "0"), matching will be done against all types.
					(in a given partition if `use_partition` parameter is 1; if
					`use_partitions` is 1 the partition being mandatory at this
					point, it is not possible to do matching against all the partitions)
- **flags** (optional) - what operations
					should be performed when a GW matches:

  - **'s'** (Strip) - apply to the
							username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply to the
							username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - return the
							gateway id into gw_id_avp AVP
  - **'n'** (Ignore port) - ignores port
							number during matching
  - **'c'** (Carrier ID) - return the
							carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the matched gateway.


```opensips title="goes_to_gw usage when use_partitions parameter is 0"
...
if (goes_to_gw("1", , "$var(gw_attrs)")) {
	sl_send_reply("403","Forbidden");
	exit;
}
...
```


```opensips title="goes_to_gw usage, when use_partitions parameter is 1"
...
if (goes_to_gw("my_partition", "1", , "$var(gw_attrs)")) {
	sl_send_reply("403","Forbidden");
	exit;
}
...
```


#### is_from_gw([partition','] [type], [flag], [gw_attrs_pvar])


The function checks if the sender of the message (source IP + source
		port) is a gateway from a certain group.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE
		and ONREPLY_ROUTE.


If you set `use_partitions` parameter to 1 you must supply
			the partition (the partition becomes mandatory) in which the gateways have been defined.


If `use_partitions` parameter is 0
			all parameters are optional. Any of them may be ignored, provided
			the necessary separation marks "," are properly placed.


- **partition** (mandatory if `use_partitions
					` parameter is 1, otherwise it will be omitted altogether) - Partition
					containing the destination/gw to be checked. If **(wildcard)*
					operator is used all partitions shall be checked.
- **type** (optional) - GW/destination
					type to be checked; when omitting this parameter or specifying
					a special value ("-1" or "0"), matching will be done against all types.
- **flags** (optional) - what operations
					should be performed when a GW matches:

  - **'s'** (Strip) - apply to the
							username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply to the
							username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - return the
							gateway id into gw_id_avp AVP
  - **'n'** (Ignore port) - ignore the
							source port during matching
  - **'c'** (Carrier ID) - return the
							carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the matched gateway.


```opensips title="is_from_gw usage when use_partitions is 0"
# match the source IP (only) against all gateways
if (is_from_gw("3", "n")) {
	...
}
```


```opensips title="is_from_gw usage when use_partitions is 1"
# match the source IP and port against all "outbound" gateways and return its carrier
if (is_from_gw("outbound", "3", "c")) {
	...
}
```


#### dr_is_gw([partition,] src_pv, [type], [flag], [gw_attrs_pvar])


The function checks if the SIP URI hostname part stored inside the
		"src_pv" pseudo-variable is a gateway from a certain group.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, FAILURE_ROUTE,
		BRANCH_ROUTE, LOCAL_ROUTE, STARTUP_ROUTE, TIMER_ROUTE and EVENT_ROUTE.


If you set `use_partitions` parameter to 1 you must supply
			the partition (the partition becomes mandatory) in which the gateways have been defined.


Meaning of the parameters is as follows:


- **partition** (mandatory if `use_partitions
					` parameter is 1, otherwise it will be omitted altogether) - Partition
					containing the destinations/gateways to be checked.
- **src_pv** (mandatory) -
					pseudo-variable containing a SIP URI.  If the URI hostname
					part is a FQDN, it will be resolved prior to matching.
- **type** (optional) - GW/destination
					type to be checked; when omitting this parameter or specifying
					a special value ("-1" or "0"), matching will be done against all types.
- **flags** (optional) - what operations
					should be performed when a GW matches:

  - **'s'** (Strip) - apply to the
							username of RURI the strip defined by the GW
  - **'p'** (Prefix) - apply to the
							username of RURI the prefix defined by the GW
  - **'i'** (Gateway ID) - return the gateway id into gw_id_avp pvar
  - **'n'** (Ignore port) - ignores port number
  - **'c'** (Carrier ID) - return the
							carrier id into carrier_id_avp AVP
- **gw_attrs_pvar** (output, optional)
					- a writable pseudo-variable which will be populated with
					the attributes of the matched gateway.


```opensips title="dr_is_gw usage when use_partitions is 0"
# match the SIP URI host within $var(uac) against all gateways
if (dr_is_gw("$var(uac)", "n")) {
	...
}
```


```opensips title="dr_is_gw usage when use_partitions is 1"
# match the SIP URI host within $var(uac) against all "outbound" gateways
if (dr_is_gw("outbound", "$avp(uac)", "n")) {
	...
}
```


#### dr_disable()


Marks as disabled the last destination that was used for the current
		call. The disabling done via this function will prevent the
		destination to be used for usage from now on. The probing mechanism
		can re-enable this peer (see the probing section in the beginning)


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


If you set `use_partitions` parameter to 1 you must supply
			the partition (the partition becomes mandatory) in which the gateway to be
			disabled is defined.


- **partition** (mandatory if `use_partitions
				` parameter is 1, otherwise it will be omitted altogether) - Partition
					containing the destination/gateway to be disabled.


```opensips title="dr_disable() usage when use_partitions is 0"
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	dr_disable();

}

...
```


```opensips title="dr_disable() usage when use_partitions is 1"
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	dr_disable("my_partition");

}

...
```


### Exported MI Functions


#### dr_reload


Command to reload routing rules from database. If `use_partitions` is set to 1
		you can reload just a partition given a parameter, if no parameter is supplied then all the
		partitions will be reloaded.


If `use_partitions` is 0 it takes no parameter.


MI FIFO Command Format:


```bash
		:dr_reload:fifo_reply
		partition_name (optional)
		_empty_line_
		
```


#### dr_gw_status


Gets or sets the status (enabled or disabled) of a gateway. The
		function may take from 0 to 3 parameters.


- if `use_partitions` is set to 0 - if no parameter
				is provided, it will list all
				gateways along with their status. If one parameter is provided, that
				must be the id of a gateway and the function will return the status
				of that gateway. If 2 parameters are provided, first must be the ID of
				the ID of a GW and the second must be the new status to be forced for
				that GW (0 - disable, 1 - enable).
- if `use_partitions` is set to 1 - the first parameter
				must be the partition (the partition is mandatory). If just one parameter
				is provided it will the display the statuses of all the gateways in the
				given partition. If two parameters are provided,
				the first must be the partition, and the second must be the gateway Id. If three
				parameters are provided, the first must be the partition, the second must be the gateway
				and the third will be the new status to be forced for tat GW (0 - disable, 1 - enable)


MI FIFO Command Format:


```bash
		:dr_gw_status:_reply_fifo_file_
		partition_name (mandatory if 
```


```bash title="dr_gw_status usage when use_partitions is set to 0"
$ ./opensipsctl fifo dr_gw_status 2
State:: Active
$ ./opensipsctl fifo dr_gw_status 2 0
$ ./opensipsctl fifo dr_gw_status 2
Enabled:: Disabled MI
$ ./opensipsctl fifo dr_gw_status 3
Enabled:: Inactive
```


```bash title="dr_gw_status usage when use_partitionsis set to 1"
$ ./opensipsctl fifo dr_gw_status part_1 my_gw
State:: Active
$ ./opensipsctl fifo dr_gw_status my_partition 3 0
$ ./opensipsctl fifo dr_gw_status partition7 dsbl_gw 2
Enabled:: Disabled MI
$ ./opensipsctl fifo dr_gw_status partition8 gw3
Enabled:: Inactive
```


#### dr_carrier_status


Gets or sets the status (enabled or disabled) of a carrier. The
		function may take from 0 to 3 parameters.


- if `use_partition` is set to 0 - if no parameter
					is provided it will list all the carriers along with their status. If
					one parameter is provided, that must be the id of carrier and the function
					will return the status of that carrier. If 2 parameters are provided, first
					must be the Id of a carrier and the second must be the new status to be
					forced for that carrier
- if `use_partition` is set to 1 - the first parameter
					must be the partition (the partition becomes mandatory). If one parameter
					is supplied, it will be the partition, and it will display the statuses
					of the carriers contained in that partition. If two parameters are supplied,
					the second must be the carrierId, and the command will display the status
					of the selected carrier. If three parameters are supplied, the first two
					will be the partition name and the carrierId while the third parameter will be
					the new status to be forced for that carrier.


MI FIFO Command Format:


```bash
		:dr_carrier_status:_reply_fifo_file_
		partition_name (mandatory if 
```


```bash title="dr_carrier_status usage when use_partitions is 0"
$ ./opensipsctl fifo dr_carrier_status CR1
Enabled:: no
$ ./opensipsctl fifo dr_carrier_status CR1 1
$ ./opensipsctl fifo dr_carrier_status CR1
Enabled:: yes
```


```bash title="dr_carrier_status usage when use_partitions is 1"
$ ./opensipsctl fifo dr_carrier_status my_partition CR1
Enabled:: no
$ ./opensipsctl fifo dr_carrier_status partition_1 CR1 1
$ ./opensipsctl fifo dr_carrier_status partition_3 CR1
Enabled:: yes
```


#### dr_reload_status


Gets the time of the last reload for any partition. The function
			may take at most one parameter.


- if `use_partition` is set to 0 - the function
					doesn't receive any parameter. It will list the date of the
					last reload for the default (and only) partition.
- if `use_partition` is set to 1 - if no parameter
					is supplied it will list the time of the last update for every
					partition. If one parameter is supplied, then this must be the
					partition name, and the function will list the time of the last
					reload for that given partition.


MI FIFO Command Format:


```bash
		:dr_reload_status:_reply_fifo_file_
		partition_name (if 
```


```bash title="dr_reload_status usage when use_partitions is 0"
$ ./opensipsctl fifo dr_reload_status
Date:: Tue Aug 12 12:26:00 2014
```


```bash title="dr_reload_status usage when use_partitions is 1"
$ ./opensipsctl fifo dr_reload_status
Partition:: part_test Date=Tue Aug 12 12:24:13 2014
Partition:: part_2 Date=Tue Aug 12 12:24:13 2014
$ ./opensipsctl fifo dr_reload_status part_test
Partition:: part_test Date=Tue Aug 12 12:24:13 2014
```


#### dr_number_routing


Gets the matched prefix along with the  list of the gateways / carriers to which a number
			would be routed when using the do_routing function


- if `use_partition` is set to 1 the function will have 3 parameters:
	* partition name
	* group id - the group id of the rules to check against
	* number - the number to test against
- if `use_partition` is set to 0 the function will have 2 parameters:
	* group id - the group id of the rules to check against
	* number - the number to test against


Note: The group id may be omitted - just as with the do_routing function.


### Exported Events


#### E_DROUTING_STATUS


This event is raised when the module changes the state of a gateway,
			either through MI or probing.


Parameters:


- *gwid* - the gateway identifier.
- *address* - the address of the gateway.
- *status* - *disabled MI* if
				the gateway was disabled using MI commands,
				*probing* if the gateway is being pinged,
				*inactive* if it was disabled from the script or
				*active* if the gateway is enabled.


### Installation


The module requires 4 tables in the OpenSIPS database: dr_groups,
	dr_gateways, dr_carriers, dr_rules. The SQL syntax to create them can be
	found in the drouting-create.sql script, located in the database directories
	of the opensips/scripts folder. You can also find the complete
	database documentation on the project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


## Developer Guide


The module provides no function to be used
		by other OpenSIPS modules.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
