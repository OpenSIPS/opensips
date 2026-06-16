---
title: "DISPATCHER Module"
description: "This modules implements a dispatcher for destination addresses. It computes hashes over parts of the request and selects an address from a destination set. The selected address is then used as outbound proxy."
---

## Admin Guide


### Overview


This modules implements a dispatcher for destination addresses. It 
		computes hashes over parts of the request and selects an address from
		a destination set. The selected address is then used as outbound
		proxy.


The module can be used as a stateless load balancer, having no
		guarantee of fair distribution.


For the distribution algotrithm, the module allows the definition of
		weights for the destination. This is useful in order to get a different
		ratio of traffic between destinations.


### Dependencies


#### OpenSIPS modules


The following modules must be loaded before this module:


- *TM - only if active recovery of failed hosts is required*.


#### External libraries or applications


The following libraries or applications must be installed before
		running OpenSIPS with this module:


- *none*.


### Exported Parameters


#### list_file (string)


Path to the file with destination sets.


This file shall contain linefeed delimited destinations and space delimited columns:


- setid (an integer)
- destination (a sip uri)
- flags (0|DS_INACTIVE_DST=1|DS_PROBING_DST=2|DS_RESET_FAIL_DST=4, optional)
- weight (an integer, optional)
- data (opaque data, see attrs_avp, optional)


*Default value is "/etc/opensips/dispatcher.list" or
			"/usr/local/etc/opensips/dispatcher.list".*


```c title="Set the 'list_file' parameter"
...
modparam("dispatcher", "list_file", "/var/run/opensips/dispatcher.list")
...
```


#### db_url (string)


If you want to load the sets of gateways from the database you must set
		this parameter.


*Default value is "NULL" (disable DB support).*


```c title="Set 'db_url' parameter"
...
modparam("dispatcher", "db_url", "mysql://user:passwb@localhost/database")
...
```


#### flags (int)


Various flags that affect dispatcher's behaviour. The flags are defined
		as a bitmask on an integer value.
		If flag 1 is set only the username
		part of the uri will be used when computing an uri based hash.
		If no flags are set the username, hostname and port will be used
		The port is used only if different from 5060 (normal sip uri) or 5061
		(in the sips case).


If flag 2 is set, then the failover support is enabled. The functions
		exported by the module will store the rest of addresses from the
		destination set in AVP, and use these AVPs to contact next address when
		the current-tried fails.


*Default value is "0".*


```c title="Set the 'flags' parameter"
 ...
 modparam("dispatcher", "flags", 3)
 ...
 
```


#### force_dst (int)


If set to 1, force overwriting of destination address when that is
		already set.


*Default value is "0".*


```c title="Set the 'force_dst' parameter"
...
modparam("dispatcher", "force_dst", 1)
...
```


#### use_default (int)


If the parameter is set to 1, the last address in destination set
		is used as last option to send the message. For example, it is good
		when wanting to send the call to an anouncement server saying:
		"the gateways are full, try later".


*Default value is "0".*


```c title="Set the 'use_default' parameter"
 ...
 modparam("dispatcher", "use_default", 1)
 ...
 
```


#### dst_avp (str)


The name of the avp which will hold the list with addresses, in the
		order
		they have been selected by the chosen algorithm. If use_default is 1,
		the value of last dst_avp_id is the last address in destination set. The
		first dst_avp_id is the selected destinations. All the other addresses
		from the destination set will be added in the avp list to be able to
		implement serial forking.


> [!NOTE]
> You must set this parameter if you want do do load balancing fail over.


*Default value is "null" - don't add AVPs.*


```c title="Set the 'dst_avp' parameter"
 ...
 modparam("dispatcher", "dst_avp", "$avp(271)")
 ...
 
```


#### attrs_avp (str)


The name of the avp to contain the attributes string of the current
		destination. When a destination is selected, automatically, this AVP
		will provide the attributes string - this is an opaque string (from 
		OpenSIPS point of view) : it is loaded from destination definition (
		DB or file) and blindly provided in the script.


*Default value is "null" - don't provide ATTRIBUTEs.*


```c title="Set the 'attrs_avp' parameter"
 ...
 modparam("dispatcher", "attrs_avp", "$avp(272)")
 ...
 
```


#### grp_avp (str)


The name of the avp storing the group id of the destination set. Good
		to have it for later usage or checks.


> [!NOTE]
> You must set this parameter if you want do do load balancing fail over.


*Default value is "null" - don't add AVP.*


```c title="Set the 'grp_avp' parameter"
...
modparam("dispatcher", "grp_avp", "$avp(273)")
...
```


#### cnt_avp (str)


The name of the avp storing the number of destination addresses kept in
		dst_avp avps.


> [!NOTE]
> You must set this parameter if you want do do load balancing fail over.


*Default value is "null" - don't add AVP.*


```c title="Set the 'cnt_avp' parameter"
...
modparam("dispatcher", "cnt_avp", "$avp(274)")
...
```


#### hash_pvar (str)


String with PVs used for the hashing algorithm 7.


> [!NOTE]
> You must set this parameter if you want do hashing over custom message
		parts.


*Default value is "null" - disabled.*


```c title="Use $avp(273) for hashing:"
...
modparam("dispatcher", "hash_pvar", "$avp(273)")
...
```


```c title="Use combination of PVs for hashing:"
...
modparam("dispatcher", "hash_pvar", "hash the $fU@$ci")
...
```


#### setid_pvar (str)


The name of the PV where to store the set ID (group ID) when calling
		ds_is_in_list() without group parameter (third parameter).


*Default value is "null" - don't set PV.*


```c title="Set the 'setid_pvar' parameter"
 ...
 modparam("dispatcher", "setid_pvar", "$var(setid)")
 ...
 
```


#### ds_ping_method (string)


With this Method you can define, with which method you want to probe 
		the failed gateways. This method is only available, if compiled with 
		the probing of failed gateways enabled.


*Default value is "OPTIONS".*


```c title="Set the 'ds_ping_method' parameter"
...
modparam("dispatcher", "ds_ping_method", "INFO")
...
```


#### ds_ping_from (string)


With this Method you can define the "From:"-Line for the request, 
		sent to the failed gateways. This method is only available, if 
		compiled with the probing of failed gateways enabled.


*Default value is "sip:dispatcher@localhost".*


```c title="Set the 'ds_ping_from' parameter"
...
modparam("dispatcher", "ds_ping_from", "sip:proxy@sip.somehost.com")
...
```


#### ds_ping_interval (int)


With this Method you can define the interval for sending a request to 
		a failed gateway. This parameter is only used, when the TM-Module is 
		loaded. If set to "0", the pinging of failed requests 
		is disabled.


*Default value is "10".*


```c title="Set the 'ds_ping_interval' parameter"
...
modparam("dispatcher", "ds_ping_interval", 30)
...
```


#### ds_probing_sock (str)


A socket description [proto:]host[:port] of the local socket (which
		is used by OpenSIPS for SIP traffic) to be used (if multiple) for 
		sending the probing messages from.


*Default value is "NULL(none)".*


```c title="Set the 'ds_probing_sock' parameter"
...
modparam("dispatcher", "ds_probing_sock", "udp:192.168.1.100:5077")
...
```


#### ds_probing_threshhold (int)


If you want to set a gateway into probing mode, you will need a 
		specific number of requests until it will change from "active" to 
		probing. The number of attempts can be set with this parameter.


*Default value is "3".*


```c title="Set the 'ds_probing_threshhold' parameter"
...
modparam("dispatcher", "ds_probing_threshhold", 10)
...
```


#### ds_probing_mode (int)


Controls what gateways are tested to see if they are reachable. If set
		to 0, only the gateways with state PROBING are tested, if set to 1, all
		gateways are tested. If set to 1 and the response is 408 (timeout),
		an active gateway is set to PROBING state.


*Default value is "0".*


```c title="Set the 'ds_probing_mode' parameter"
...
modparam("dispatcher", "ds_probing_mode", 1)
...
```


#### options_reply_codes (str)


This parameter must contain a list of SIP reply codes separated by 
		comma. The codes defined here will be considered as valid reply codes 
		for OPTIONS messages used for pinging, apart for 200.


*Default value is "NULL".*


```c title="Set the 'options_reply_codes' parameter"
...
modparam("dispatcher", "options_reply_codes", "501, 403")
...
```


#### table_name (string)


If you want to load the sets of gateways from the database you must set
		this parameter as the database name.


*Default value is "dispatcher".*


```c title="Set 'table_name' parameter"
...
modparam("dispatcher", "table_name", "my_dispatcher")
...
```


#### setid_col (string)


The column's name in the database storing the gateway's group id.


*Default value is "setid".*


```c title="Set 'setid_col' parameter"
...
modparam("dispatcher", "setid_col", "groupid")
...
```


#### destination_col (string)


The column's name in the database storing the destination's
			sip uri.


*Default value is "destination".*


```c title="Set 'destination_col' parameter"
...
modparam("dispatcher", "destination_col", "uri")
...
```


#### flags_col (string)


The column's name in the database storing the flags for
			destination uri.


*Default value is "flags".*


```c title="Set 'flags_col' parameter"
...
modparam("dispatcher", "flags_col", "dstflags")
...
```


#### weight_col (string)


The column's name in the database storing the weight for
			destination uri.


*Default value is "weight".*


```c title="Set 'weight_col' parameter"
...
modparam("dispatcher", "weight_col", "dstweight")
...
```


#### attrs_col (string)


The column's name in the database storing the attributes (opaque
			string) for destination uri.


*Default value is "attrs".*


```c title="Set 'attrs_col' parameter"
...
modparam("dispatcher", "attrs_col", "dstattrs")
...
```


### Exported Functions


#### ds_select_dst(set, alg [, max_results])


The method selects a destination from addresses set.


Meaning of the parameters is as follows:


- *set* - the id of the set from where to pick
			up destination address. It is the first column in destination
			list file.
- *alg* - the algorithm used to select the
			destination address.

  - "0" - hash over callid
  - "1" - hash over from uri.
  - "2" - hash over to uri.
  - "3" - hash over request-uri.
  - "4" - round-robin (next destination).
  - "5" - hash over authorization-username (Proxy-Authorization or "normal" authorization). If no username is found, round robin is used.
  - "6" - random (using rand()).
  - "7" - hash over the content of PVs string.
				Note: This works only when the parameter hash_pvar is set.
  - "8" - the first entry in set is chosen.
  - "X" - if the algorithm is not implemented, the
				first entry in set is chosen.
- *max_results* - If specified, only that many results
			will be put into the specified avp for failover. This allows having many
			destinations but limit the useless traffic in case of a number that is
			bound to fail everywhere.


If the bit 2 in 'flags' is set, the rest of the addresses from the
		destination set is stored in AVP list. You can use 'ds_next_dst()' to
		use next address to achieve serial forking to all possible
		destinations.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```c title="ds_select_dst usage"
...
ds_select_dst("1", "0");
...
ds_select_dst("1", "0", "5");
...
```


#### ds_select_domain(set, alg [, max_results])


The method selects a destination from addresses set  and rewrites the
		host and port from R-URI. The parameters have same meaning as for
		ds_select_dst().


If the bit 2 in 'flags' is set, the rest of the addresses from the
		destination set is stored in AVP list. You can use 'ds_next_domain()'
		to use next address to achieve serial forking to all possible
		destinations.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


#### ds_next_dst()


Takes the next destination address from the AVPs with id 'dst_avp_id'
		and sets the dst_uri (outbound proxy address).


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


#### ds_next_domain()


Takes the next destination address from the AVPs with id 'dst_avp_id'
		and sets the domain part of the request uri.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


#### ds_mark_dst()


Mark the last used address from destination set as inactive, in order
		to be ingnored in the future. In this way it can be implemented an
		automatic detection of failed gateways. When an address is marked as
		inactive, it will be ignored by 'ds_select_dst' and 'ds_select_domain'.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


#### ds_mark_dst("s")


Mark the last used address from destination set as inactive ("i"/"I"/"0"), active ("a"/"A"/"1") or probing ("p"/"P"/"2").
		With this function, an automatic detection of failed gateways can be implemented. When an address is marked as
		inactive or probing, it will be ignored by 'ds_select_dst' and 'ds_select_domain'.


possible parameters:


- *"i", "I" or "0"* - the last destination should be set to inactive and will be ignored in future requests.
- *"a", "A" or "1"* - the last destination should be set to active.
- *"p", "P" or "2"* - the last destination will be set to probing. Note: You will need to call this function "threshhold"-times, before it will be actually set to probing.


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


#### ds_is_in_list( ip, port [,set [,active_only]])


This function returns true, if the parameters ip and port point to a 
		host from the dispatcher-list; otherwise false.


Meaning of the parameters:


- *ip* - a PV (pseudo-variable) containing 
			(as string) the IP to test against the dispatcher list. This cannot
			be empty.
- *port* - a PV (pseudo-variable) containing
			 (as integer) the PORT to test against the dispatcher list. This 
			 can be empty - in this case the port will excluded from the 
			 matching of IP against the dispatcher list.
- *set* (optional) - the set ID of a 
			dispatcher list to test agaist - if missing, all the dispatching
			sets will the checked.
- *active_only* (optional) - search only 
			through the active destinations (ignore the ones in probing 
			and inactive mode).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, 
		BRANCH_ROUTE and ONREPLY_ROUTE.


```c title="ds_is_in_list usage"
...
if (ds_is_in_list("$si", "$sp")) {
	# source IP:PORT is in a dispatcher list
}
...
if (ds_is_in_list("$rd", "$rp", "2")) {
	# source RURI (ip and port) is in the dispatcher list id "2"
}
...
```


### Exported MI Functions


#### ds_set_state


Sets the status for a destination address (can be use to mark the destination 
		as active or inactive).


Name: *ds_set_state*


Parameters:


- _state_ : state of the destination address

  - "a": active
  - "i": inactive
  - "p": probing
- _group_: destination group id
- _address_: address of the destination in the _group_


MI FIFO Command Format:


```c
		:ds_set_state:_reply_fifo_file_
		_state_
		_group_
		_address_
		_empty_line_
		
```


#### ds_list


It lists the groups and included destinations.


Name: *ds_list*


Parameters: *none*


MI FIFO Command Format:


```c
		:ds_list:_reply_fifo_file_
		_empty_line_
		
```


#### ds_reload


It reloads the groups and included destinations.


Name: *ds_reload*


Parameters: *none*


MI DATAGRAM Command Format:


```c
		":ds_reload:\n."
		
```


### Exported Events


#### E_DISPATCHER_STATUS


This event is raised when the dispatcher module marks a destination as 
			activated or deactivated.


Parameters:


- *group* - the group of the destination.
- *address* - the address of the destination.
- *status* - *active* if
				the destination gets activated or *inactive* if the
				destination is detected unresponsive.


### Installation and Running


#### Destination List File


Each destination point must be on one line. First token is the set
		id, followed by destination address. Optionally, the third field can
		be flags value (1 - destination inactive, 2 - destination in probing
		mod -- you can do bitwise OR to set both flags). The set id must be
		an integer value. Destination address must be a valid SIP URI. Empty
		lines or lines starting with "#" are ignored.


```c title="dispatcher list file"
...
# $Id$
# dispatcher destination sets
#

# line format
# setit(integer) destination(sip uri) flags (integer, optional)

# proxies
2 sip:127.0.0.1:5080
2 sip:127.0.0.1:5082

# gateways
1 sip:127.0.0.1:7070
1 sip:127.0.0.1:7072
1 sip:127.0.0.1:7074

...
```


#### OpenSIPS config file


Next picture displays a sample usage of dispatcher.


[OpenSIPS config script - sample dispatcher usage](./samples.md "include")


## Frequently Asked Questions


**Q: Does *dispatcher* provide a fair distribution?**


There is no guarantee of that. You should do some measurements
			to decide what distribution algorithm fits better in your
			environment.


**Q: Is *dispatcher* dialog stateful?**


No. Dispatcher is stateless, although some distribution algorithms
			are designed to select same destination for subsequent requests of
			the same dialog (e.g., hashing the call-id).


**Q: What happend with the *ds_is_from_list()* 
			function?**


The function was replaced by the more generic 
			*ds_is_in_list()* function that takes as 
			parameters the IP and PORT to test against the dispatcher list.

ds_is_from_list() == ds_is_in_list("$si","$sp")


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable version should be sent to 
			users@lists.opensips.org and e-mail regarding development versions or SVN 
			snapshots should be send to devel@lists.opensips.org.

If you want to keep the mail private, send it to users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at: [https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues)
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
