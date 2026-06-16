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


- routing info (destinations, carriers, rules, groups) are stored in a 
	database and loaded into memory at start up time; reload at runtime via
	an Management Interface command.
- weigth-based or random selection of the destinations (from a rule or
	 from a carrier), failure detection of gateways (with switching to next
	 available gateway).
- able to handle large volume of routing info (10M of rules) with minimal
	speed/time and memory consumption penalties
- script integration - Pseudo variables support in functions; scripting
	route triggering when rules are matched
- bidirectional behavior - inbound and outbound processing (strip and 
	prefixing when sending and receiving from a destination/GW)
- blacklisting - the module allows definition of backlists based on the
	destination IPs. This blacklists are to be used to prevent malicious 
	forwarding to GWs (based on DNS lookups) when the script logic does
	none-GE forwarding (like foreign domains).


#### Performance


There were several tests performed regarding the performance of the module
	when dealing with a large number of routing rules.


The tests were performed with a set of 383000 rules and to values were
	measured:


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
	should be done (describing all the dependecies between destinations
	and routing rules).


##### Destination/Gateways


These are the end SIP entities where actually the traffic needs to be sent
	after routing. They are stored in a table called "dr_gateways".
	Gateway addresses are stored in a separate table because of need to access them
	independent of Dynamic Routing processing (e.g., adding/ removing gateway PRI
	prefix before/after performing other operation -- receiving/relaying to gateway).


In DR, a gateway is defined by:


- id (string)
- SIP address (SIP URI)
- type (number to allow to group GW based on purpose,
	like inbound, outbound, etc)
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


These are the actual rule which control the routing - like based on
	different criterias (prefix, time, priority, etc) they will decide
	to which gateways the call will be sent.


Default name for the table storing rule definitions is 
	"dr_rules".


In DR, a carrier is defined by:


- group (list of numbers) - rules can be grouped (a rule may
	belong to multiple groups in the same time ) and you can
	use only a certian group at a point; like having a "premium" or
	"standard" or "interstate" or 
	"intrastate" groups of rules to be used in different 
	cases
- prefix (string with digits only) - prefix to be used for
	matching this rule (longest prefix matching)
- time validity (time recurrence string) - when this rule is
	valid from time point of view (see RFC 2445)
- priority (number) - prority off the rule - higher value, 
	higher priority (see rule section alg)
- script route ID (string) - if defined, then execute the 
	route with the specified ID when this rule is matched. That's it, a route
	which can be used to perform custom operations on message. NOTE that no 
	modification is performed at signaling level and you must NOT do
	any signalling operations in that script route
- list of GWs/carriers (string) - a comma separated list
	of gateways or carriers (defined by IDs) to be used for this rule; the 
	carrier IDs are prefixed with "#" sign. For each ID (GW or
	carrier) you may specify a weight. For how this list will be interpreted 
	(as order) see the rule selection section. Example of list: 
	"gw1,gw4,#cr3" or "gw1=10,gw4=10,#cr3=80"
- attributes (not used by DR engine, but only pushed
	to script level when this rule matched and been used)


More on time recurrence:


- A date-time expression that defines the time recurrence to match for
	current rule. Time recurrences are based closely on the specification
	of recurring intervals of time in the Internet Calendaring and Scheduling
	Core Object Specification (calendar COS), RFC 2445. The set of attributes
	used in routing rule specification is subset of time recurrence attributes.
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
	execute serial forking for each address in chain (in which order the 
	destinations will be tried, depends on the defintion order or depends on
	the weights (weights selection must be enabled). The next address in chain
	is used only if the previously has failed.
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
		in disabled mode (disabling via MI command will competely stop the
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


```c title="Set db_url parameter"
...
modparam("drouting", "db_url", 
	"mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### drd_table(str)


The name of the db table storing gateway addresses.


*Default value is "dr_gateways".*


```c title="Set drd_table parameter"
...
modparam("drouting", "drd_table", "dr_gateways")
...
```


#### drr_table(str)


The name of the db table storing routing rules.


*Default value is "dr_rules".*


```c title="Set drr_table parameter"
...
modparam("drouting", "drr_table", "rules")
...
```


#### drg_table(str)


The name of the db table storing groups.


*Default value is "dr_groups".*


```c title="Set drg_table parameter"
...
modparam("drouting", "drg_table", "groups")
...
```


#### drc_table(str)


The name of the db table storing definitions of the carriers that will 
		be used directly by the routing rules.


*Default value is "dr_carriers".*


```c title="Set drc_table parameter"
...
modparam("drouting", "drc_table", "my_dr_carriers")
...
```


#### ruri_avp (str)


The name of the avp for storing Request URIs to be later used 
		(alternative destiantions for the current one).


*Default value is "$avp(0xad346b2f)".*


```c title="Set ruri_avp parameter"
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


*Default value is "$avp(0xad346b30)".*


```c title="Set gw_id_avp parameter"
...
modparam("drouting", "gw_id_avp", '$avp(gw_id)')
modparam("drouting", "gw_id_avp", '$avp(334)')
...
	
```


#### gw_attrs_avp (str)


The name of the avp for storing the attributes of the current selected
		destination/gateway - once a new destination is selected (via the 
		use_next_gw() function), the AVP will be updated with the attrs of the
		new used destination.


*Default value is "NULL".*


```c title="Set gw_attrs_avp parameter"
...
modparam("drouting", "gw_attrs_avp", '$avp(gw_attrs)')
modparam("drouting", "gw_attrs_avp", '$avp(67)')
...
	
```


#### rule_id_avp (str)


The name of the avp for storing the id of the current matched
		routing rule (see dr_rules table).


*Default value is "NULL".*


```c title="Set rule_id_avp parameter"
...
modparam("drouting", "rule_id_avp", '$avp(rule_id)')
modparam("drouting", "rule_id_avp", '$avp(335)')
...
	
```


#### rule_attrs_avp (str)


The name of the avp for storing the attributes of the current matched
		routing rule (see dr_rules table).


*Default value is "NULL".*


```c title="Set rule_attrs_avp parameter"
...
modparam("drouting", "rule_attrs_avp", '$avp(rule_attrs)')
modparam("drouting", "rule_attrs_avp", '$avp(66)')
...
	
```


#### rule_prefix_avp (str)


The actual prefix that matched the routing rule (the part from RURI 
		username that matched the routing rule).


*Default value is "NULL".*


```c title="Set rule_prefix_avp parameter"
...
modparam("drouting", "rule_prefix_avp", '$avp(dr_prefix)')
...
	
```


#### carrier_id_avp (str)


AVP to be populate with the ID string for the carrier the 
		current GW belongs to.


*Default value is "NULL".*


```c title="Set carrier_id_avp parameter"
...
modparam("drouting", "carrier_id_avp", '$avp(carrier_id)')
...
	
```


#### carrier_attrs_avp (str)


AVP to be populate with the attributes string for the carrier the 
		current GW belongs to.


*Default value is "NULL".*


```c title="Set carrier_attrs_avp parameter"
...
modparam("drouting", "carrier_attrs_avp", '$avp(carrier_attrs)')
...
	
```


#### define_blacklist (str)


Defines a backlist based on a list of GW types - the list will contain
		the IPs (no port, all protocols) of the GWs with the specified types.


Multiple instances of this param are allowed.


*Default value is "NULL".*


```c title="Set define_blacklist parameter"
...
modparam("drouting", "define_blacklist", 'bl_name= 3,5,25,23')
modparam("drouting", "define_blacklist", 'list= 4,2')
...
	
```


#### default_group (int)


Group to be used if the caller (FROM user) is not found in the GROUP
		table.


*Default value is "NONE".*


```c title="Set default_group parameter"
...
modparam("drouting", "default_group", 4)
...
```


#### force_dns (int)


Force DNS resolving of GW/destination names (if not IPs) during 
		startup. If not enabled, the GW name will be blindly used during 
		routing.


*Default value is "1 (enabled)".*


```c title="Set force_dns parameter"
...
modparam("drouting", "force_dns", 0)
...
	
```


#### probing_interval (integer)


How often (in seconds) the probing of a destination should be done. If
		set to 0, the probing will be disabled as functionality (for all
		destinations)


*Default value is "30".*


```c title="Set probing_interval parameter"
...
modparam("drouting", "probing_interval", 60)
...
```


#### probing_method (string)


The SIP method to be used for the probing requests.


*Default value is ""OPTIONS"".*


```c title="Set probing_method parameter"
...
modparam("drouting", "probing_method", "INFO")
...
```


#### probing_from (string)


The FROM SIP URI to be advertised in the SIP probing requests.


*Default value is ""sip:prober@localhost"".*


```c title="Set probing_from parameter"
...
modparam("drouting", "probing_from", "sip:pinger@192.168.2.10")
...
```


#### probing_reply_codes (string)


A comma separted list of SIP reply codes. The codes defined here
		will be considered as valid reply codes for probing messages,
		apart for 200.


*Default value is "NULL".*


```c title="Set probing_reply_codes parameter"
...
modparam("drouting", "probing_reply_codes", "501, 403")
...
```


#### use_domain (int)


Flag to configure whether to use domain match when querying
			database for user's routing group.


*Default value is "1".*


```c title="Set use_domain parameter"
...
modparam("drouting", "use_domain", 0)
...
```


#### drg_user_col (str)


The name of the column in group db table where the username is stored.


*Default value is "username".*


```c title="Set drg_user_col parameter"
...
modparam("drouting", "drg_user_col", "user")
...
```


#### drg_domain_col (str)


The name of the column in group db table where the domain is stored.


*Default value is "domain".*


```c title="Set drg_domain_col parameter"
...
modparam("drouting", "drg_domain_col", "host")
...
```


#### drg_grpid_col (str)


The name of the column in group db table where the
			group id is stored.


*Default value is "groupid".*


```c title="Set drg_grpid_col parameter"
...
modparam("drouting", "drg_grpid_col", "grpid")
...
```


### Exported Functions


#### do_routing([[[groupID],flags],gw_whitelist])


Function to trigger routing of the message according to the 
		rules in the database table and the configured parameters.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


The function can take two optional parameters:


- groupID
- flags

  - W
  - F
  - L
  - C
- gw_whitelist


```c title="do_routing usage"
...
# all groups, sort on order
do_routing();
...
# group id 0, sort on order
do_routing("0");
...
# group id from $avp(10), sort on order
do_routing("$avp(10)");
...
# all groups, sort on weights
do_routing("","W");
...
# group id 2, sort on order, fallback rule
do_routing("2","F");
...
```


#### route_to_carrier(carrier_id)


Function to trigger the direct routing to a given carrier. In this case
		the routing is not done prefix based, but carrier based (call will be
		sent to the GWs of that carrier, based on carrier policy)


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


Function takes a single mandatory parameter, the ID of the carrier
		to be used (variables are accepted).


```c title="route_to_carrier usage"
...
if ( route_to_carrier("my_top_carrier") ) {
	t_on_failure("next_gw");
	t_relay();
	exit;
}
...
```


#### route_to_gw(gw_id)


Function to trigger the direct routing to a given gateway. Attributes 
		and per-gw preocessing will be available.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


Function takes a single mandatory parameter, the ID of the gateway
		to be used (variables are accepted).


```c title="route_to_gw usage"
...
if ( route_to_gw("gw_europe") ) {
	t_relay();
	exit;
}
...
```


#### use_next_gw()/next_routing()


The function takes the next available destination (set by do_routing, 
		as alternative destinations) and push it into RURI. Note that the 
		function just sets the RURI (nothing more).


If a new RURI is set, the used destination is removed from the 
		pending set of alternative destinations.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


The function returns true only if a new RURI was set. False
		is returned is no other alternative destinations are found or in case
		of internal processing error.


```c title="use_next_gw usage"
...
if (use_next_gw()) {
	t_relay();
	exit;
}
...
```


#### goes_to_gw([[type],flags])


Function returns true if the destination of the current request 
		(destination URI or Request URI) points (as IP) to one of the gateways.
		There no DNS lookups done if the domain part of the URI is not an IP.


This function does not change anything in the message.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


The function can take two optional parameters:


- type
- flags

  - 's'
  - 'p'
  - 'a'


```c title="goes_to_gw usage"
...
if (goes_to_gw("1")) {
	sl_send_reply("403","Forbidden");
	exit;
}
...
```


#### is_from_gw( [type, [flag]])


The function checks if the sender of the message is a gateway
		from a certain group.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


The function can take two optional parameters:


- type
- flags

  - 's'
  - 'p'
  - 'a'


```c title="is_from_gw usage"
...
if (is_from_gw("3","1") {
}
...
```


#### dr_disable()


Marks as disabled the last destination that was used for the current
		call. The disabling done via this function will prevent the
		destination to be used for usage from now on. The probing mechanism
		can re-enable this peer (see the probing section in the begining)


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="dr_disable() usage"
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	dr_disable();
	
}

...
```


### Exported MI Functions


#### dr_reload


Command to reload routing rules from database.


It takes no parameter.


MI FIFO Command Format:


```c
		:dr_reload:fifo_reply
		_empty_line_
		
```


#### dr_gw_status


Gets or sets the status (enabled or disabled) of a gateway. The
		function may take from 0 to 2 parameters. If none, it will list all
		gateways along with their status. If one parameter is provided, that 
		must be the id of a gateway and the function will return the status
		of that gateway. If 2 parameters are provided, first must be the ID of
		the ID of a GW and the second must be the new status to be forced for
		that GW (0 - disable, 1 - enable).


MI FIFO Command Format:


```c
		:dr_gw_status:_reply_fifo_file_
		GW_id
		status (optional)
		_empty_line_
		
```


```c title="dr_gw_status usage"
$ ./opensipsctl fifo dr_gw_status 2
Enabled:: no
$ ./opensipsctl fifo dr_gw_status 2 1
$ ./opensipsctl fifo dr_gw_status 2
Enabled:: yes
```


#### dr_carrier_status


Gets or sets the status (enabled or disabled) of a carrier. The
		function may take from 0 to 2 parameters. If none, it will list all
		carriers along with their status. If one parameter is provided, that 
		must be the id of a carrier and the function will return the status
		of that carrier. If 2 parameters are provided, first must be the ID of
		the ID of a carrier and the second must be the new status to be 
		forced for that carrier (0 - disable, 1 - enable).


MI FIFO Command Format:


```c
		:dr_carrier_status:_reply_fifo_file_
		carrier_id
		status (optional)
		_empty_line_
		
```


```c title="dr_carrier_status usage"
$ ./opensipsctl fifo dr_carrier_status CR1
Enabled:: no
$ ./opensipsctl fifo dr_carrier_status CR1 1
$ ./opensipsctl fifo dr_carrier_status CR1
Enabled:: yes
```


### Installation


The module requires 4 table in OpenSIPS database: dr_groups,
	dr_gateways, dr_carriers, dr_rules. The SQL syntax to create them can be
	found in drouting-create.sql script in the database directories
	in the opensips/scripts folder. You can also find the complete
	database documentation on the project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


## Developer Guide


The module provides no function to be used
		by other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
