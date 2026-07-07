---
title: "DISPATCHER Module"
description: "This modules implements a dispatcher for destination addresses. It computes hashes over parts of the request and selects an address from a destination set. The selected address is used then as outbound proxy."
---

## Admin Guide


### Overview


This modules implements a dispatcher for destination addresses. It 
		computes hashes over parts of the request and selects an address from
		a destination set. The selected address is used then as outbound
		proxy.


The module can be used as a stateless load balancer, having no
		guarantee of fair distribution.


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


*Default value is "/etc/opensips/dispatcher.list" or
			"/usr/local/etc/opensips/dispatcher.list".*


```opensips title="Set the 'list_file' parameter"
...
modparam("dispatcher", "list_file", "/var/run/opensips/dispatcher.list")
...
```


#### db_url (string)


If you want to load the sets of gateways from the database you must set
		this parameter.


*Default value is "NULL" (disable DB support).*


```opensips title="Set 'db_url' parameter"
...
modparam("dispatcher", "db_url", "mysql://user:passwb@localhost/database")
...
```


#### table_name (string)


If you want to load the sets of gateways from the database you must set
		this parameter as the database name.


*Default value is "dispatcher".*


```opensips title="Set 'table_name' parameter"
...
modparam("dispatcher", "table_name", "my_dispatcher")
...
```


#### setid_col (string)


The column's name in the database storing the gateway's group id.


*Default value is "setid".*


```opensips title="Set 'setid_col' parameter"
...
modparam("dispatcher", "setid_col", "groupid")
...
```


#### destination_col (string)


The column's name in the database storing the destination's
			sip uri.


*Default value is "destination".*


```opensips title="Set 'destination_col' parameter"
...
modparam("dispatcher", "destination_col", "uri")
...
```


#### flags_col (string)


The column's name in the database storing the flags for
			destination uri.


*Default value is "flags".*


```opensips title="Set 'flags_col' parameter"
...
modparam("dispatcher", "flags_col", "dstflags")
...
```


#### force_dst (int)


If set to 1, force overwriting of destination address when that is
		already set.


*Default value is "0".*


```opensips title="Set the 'force_dst' parameter"
...
modparam("dispatcher", "force_dst", 1)
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


```opensips title="Set the 'flags' parameter"
 ...
 modparam("dispatcher", "flags", 3)
 ...
 
```


#### use_default (int)


If the parameter is set to 1, the last address in destination set
		is used as last option to send the message. For example, it is good
		when wanting to send the call to an anouncement server saying:
		"the gateways are full, try later".


*Default value is "0".*


```opensips title="Set the 'use_default' parameter"
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


```opensips title="Set the 'dst_avp' parameter"
 ...
 modparam("dispatcher", "dst_avp", "$avp(i:271)")
 ...
 
```


#### grp_avp (str)


The name of the avp storing the group id of the destination set. Good
		to have it for later usage or checks.


> [!NOTE]
> You must set this parameter if you want do do load balancing fail over.


*Default value is "null" - don't add AVP.*


```opensips title="Set the 'grp_avp' parameter"
 ...
 modparam("dispatcher", "grp_avp", "$avp(i:272)")
 ...
 
```


#### cnt_avp (str)


The name of the avp storing the number of destination addresses kept in
		dst_avp avps.


> [!NOTE]
> You must set this parameter if you want do do load balancing fail over.


*Default value is "null" - don't add AVP.*


```opensips title="Set the 'cnt_avp' parameter"
 ...
 modparam("dispatcher", "cnt_avp", "$avp(i:273)")
 ...
 
```


#### hash_pvar (str)


String with PVs used for the hashing algorithm 7.


> [!NOTE]
> You must set this parameter if you want do hashing over custom message
		parts.


*Default value is "null" - disabled.*


```opensips title="Use $avp(i:273) for hashing:"
 ...
 modparam("dispatcher", "hash_pvar", "$avp(i:273)")
 ...
 
```


```opensips title="Use combination of PVs for hashing:"
 ...
 modparam("dispatcher", "hash_pvar", "hash the $fU@$ci")
 ...
 
```


#### setid_pvar (str)


The name of the PV where to store the set ID (group ID) when calling
		ds_is_from_list() with no parameter.


*Default value is "null" - don't set PV.*


```opensips title="Set the 'setid_pvar' parameter"
 ...
 modparam("dispatcher", "setid_pvar", "$var(setid)")
 ...
 
```


#### ds_ping_method (string)


With this Method you can define, with which method you want to probe the failed gateways.
 		This method is only available, if compiled with the probing of failed gateways enabled.


*Default value is "OPTIONS".*


```opensips title="Set the 'ds_ping_method' parameter"
 ...
 modparam("dispatcher", "ds_ping_method", "INFO")
 ...
 
```


#### ds_ping_from (string)


With this Method you can define the "From:"-Line for the request, sent to the failed gateways. 		
 		This method is only available, if compiled with the probing of failed gateways enabled.


*Default value is "sip:dispatcher@localhost".*


```opensips title="Set the 'ds_ping_from' parameter"
 ...
 modparam("dispatcher", "ds_ping_from", "sip:proxy@sip.somehost.com")
 ...
 
```


#### ds_ping_interval (int)


With this Method you can define the interval for sending a request to a failed gateway.
 		This parameter is only used, when the TM-Module is loaded.
		If set to "0", the pinging of failed requests is disabled.


*Default value is "10".*


```opensips title="Set the 'ds_ping_interval' parameter"
 ...
 modparam("dispatcher", "ds_ping_interval", 30)
 ...
 
```


#### ds_probing_threshhold (int)


If you want to set a gateway into probing mode, you will need a specific number of requests until it will change from "active" to probing.
		The number of attempts can be set with this parameter.


*Default value is "3".*


```opensips title="Set the 'ds_probing_threshhold' parameter"
 ...
 modparam("dispatcher", "ds_probing_threshhold", 10)
 ...
 
```


#### ds_probing_mode (int)


Controls what gateways are tested to see if they are reachable. If set
		to 0, only the gateways with state PROBING are tested, if set to 1, all
		gateways are tested. If set to 1 and the response is 407 (timeout),
		an active gateway is set to PROBING state.


*Default value is "0".*


```opensips title="Set the 'ds_probing_mode' parameter"
 ...
 modparam("dispatcher", "ds_probing_mode", 1)
 ...
 
```


### Exported Functions


#### ds_select_dst(set, alg)


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
  - "X" - if the algorithm is not implemented, the
				first entry in set is chosen.


If the bit 2 in 'flags' is set, the rest of the addresses from the
		destination set is stored in AVP list. You can use 'ds_next_dst()' to
		use next address to achieve serial forking to all possible
		destinations.


This function can be used from REQUEST_ROUTE.


```opensips title="ds_select_dst usage"
...
ds_select_dst("1", "0");
...
```


#### ds_select_domain(set, alg)


The method selects a destination from addresses set  and rewrites the
 		host and port from R-URI. The parameters have same meaning as for
 		ds_select_dst().


If the bit 2 in 'flags' is set, the rest of the addresses from the
		destination set is stored in AVP list. You can use 'ds_next_domain()'
		to use next address to achieve serial forking to all possible
		destinations.


This function can be used from REQUEST_ROUTE.


#### ds_next_dst()


Takes the next destination address from the AVPs with id 'dst_avp_id'
		and sets the dst_uri (outbound proxy address).


This function can be used from FAILURE_ROUTE.


#### ds_next_domain()


Takes the next destination address from the AVPs with id 'dst_avp_id'
		and sets the domain part of the request uri.


This function can be used from FAILURE_ROUTE.


#### ds_mark_dst()


Mark the last used address from destination set as inactive, in order
		to be ingnored in the future. In this way it can be implemented an
		automatic detection of failed gateways. When an address is marked as
		inactive, it will be ignored by 'ds_select_dst' and 'ds_select_domain'.


This function can be used from FAILURE_ROUTE.


#### ds_mark_dst("s")


Mark the last used address from destination set as inactive ("i"/"I"/"0"), active ("a"/"A"/"1") or probing ("p"/"P"/"2").
 		With this function, an automatic detection of failed gateways can be implemented. When an address is marked as
		inactive or probing, it will be ignored by 'ds_select_dst' and 'ds_select_domain'.


possible parameters:


- *"i", "I" or "0"* - the last destination should be set to inactive and will be ignored in future requests.
- *"a", "A" or "1"* - the last destination should be set to active.
- *"p", "P" or "2"* - the last destination will be set to probing. Note: You will need to call this function "threshhold"-times, before it will be actually set to probing.


This function can be used from FAILURE_ROUTE.


#### ds_is_from_list()


This function returns true, if the current request comes from a host from the dispatcher-list; otherwise false.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE and ONREPLY_ROUTE.


#### ds_is_from_list("group")


This function returns true, if the current request comes from a host in the given group of the dispatcher-list; otherwise false.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE and ONREPLY_ROUTE.


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


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
		    our mailing lists:

E-mails regarding any stable version should be sent to users@lists.opensips.org and e-mail
		    regarding development versions or CVS snapshots should be send to devel@lists.opensips.org.

If you want to keep the mail private, send it to users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at: [https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues)
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
