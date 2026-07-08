---
title: "Load-Balancer Module"
description: "The Load-Balancer module comes to provide traffic routing based on load. Shortly, when OpenSIPS routes calls to a set of destinations, it is able to keep the load status (as number of ongoing calls) of each destination and to choose to route to the less loaded destination (at that moment). ..."
---

## Admin Guide


### Overview


The Load-Balancer module comes to provide traffic routing based on load. 
	Shortly, when OpenSIPS routes calls to a set of destinations, it is able 
	to keep the load status (as number of ongoing calls) of each destination 
	and to choose to route to the less loaded destination (at that moment). 
	OpenSIPS is aware of the capacity of each destination - it is preconfigured 
	with the maximum load accepted by the destinations. To be more precise, 
	when routing, OpenSIPS will consider the less loaded destination not the 
	destination with the smallest number of ongoing calls, but the destination 
	with the largest available slot.


Also the module has the capability to do failover (to try a new destination
	if the selected one done not responde), to keep state of the destinations 
	(to remember the failed destination and avoid using them agai) and to 
	check the health of the destination (by doing probing of the destination 
	and auto re-enabling).


### How it works


Please refer to the Load-Balancer tutorial from the OpenSIPS website:
		[http://www.opensips.org/index.php?n=Resources.DocsTutLoadbalancing](http://www.opensips.org/index.php?n=Resources.DocsTutLoadbalancing).


### Probing and Disabling destinations


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


- *Dialog* - Dialog module
- *Dialog* - TM module (only if probing enabled)
- *database* - one of the DB modules


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


The URL pointing to the database where the load-balancing rules 
		are stored.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("load_balancer", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### db_table (string)


The name of the DB table containing the load-balancing rules.


*Default value is "load_balancer".*


```opensips title="Set db_table parameter"
...
modparam("load_balancer", "db_table", "lb")
...
```


#### probing_interval (integer)


How often (in seconds) the probing of a destination should be done. If
		set to 0, the probing will be disabled as functionality (for all 
		destinations)


*Default value is "30".*


```opensips title="Set probing_interval parameter"
...
modparam("load_balancer", "probing_interval", 60)
...
```


#### probing_method (string)


The SIP method to be used for the probing requests.


*Default value is ""OPTIONS"".*


```opensips title="Set probing_method parameter"
...
modparam("load_balancer", "probing_method", "INFO")
...
```


#### probing_from (string)


The FROM SIP URI to be advertised in the SIP probing requests.


*Default value is ""sip:prober@localhost"".*


```opensips title="Set probing_from parameter"
...
modparam("load_balancer", "probing_from", "sip:pinger@192.168.2.10")
...
```


#### probing_reply_codes (string)


A comma separted list of SIP reply codes. The codes defined here 
		will be considered as valid reply codes for probing messages,
		apart for 200.


*Default value is "NULL".*


```opensips title="Set probing_reply_codes parameter"
...
modparam("load_balancer", "probing_reply_codes", "501, 403")
...
```


#### lb_define_blacklist (string)


Defines a blacklist based on a lb group. This list will contain the IPs
		(no port, all protocols) of the destinations matching the given group.


Multiple instances of this param are allowed.


*Default value is "NULL".*


```opensips title="Set the lb_define_blacklist parameter"
...
modparam("load_balancer", "lb_define_blacklist", "list= 1,4,3")
modparam("load_balancer", "lb_define_blacklist", "blist2= 2,10,6")
...
```


### Exported Functions


#### load_balance(grp,resources[,alg])


The function performs load-balancing over the available destinations in
		order to find the less loaded destination that can provide the 
		requested resources and belong to a requested group.


Meaning of the parameters is as follows:


- *grp* - group id for the destinations; the
			destination may be grouped in several groups you can you for 
			differnet scenarios; this can be a number or a variable containing
			a numerical value.
- *resources* - string containing a 
			semi-colon list of resources required by the current call.
- *algorithm* - algorithm used for 
			computing the available load on the system:

  - *0* - Absolute value - the effective
				available load ( maximum_load - current_load) is used in
				computing the load of each pear/resource.
  - *1* - Relative value - the relative
				available load (how many percentages are free) is used in
				computing the load of each pear/resource.
If missing, the default algorithm in 0.


Function returns true is a new destination URI is set pointing to the 
		selected destiantion.
		NOTE that the RURI will not be changed by this function.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
		FAILURE_ROUTE.


```opensips title="load_balance usage"
...
if (load_balance("1","trascoding;conference")) {
	# dst URI points to the new destination
	xlog("sending call to $du\n");
	t_relay();
	exit;
}
...
```


#### lb_disable()


Marks as disabled the last destination that was used for the current
		call. The disabling done via this function will prevent the 
		destination to be used for usage from now on. The probing mechanism
		can re-enable this peer (see the probing section in the begining)


This function can be used from REQUEST_ROUTE and FAILURE_ROUTE.


```opensips title="lb_disable() usage"
...
if (t_check_status("(408)|(5[0-9][0-9])")) {
	lb_disable();
	if ( load_balance("1","pstn") ) {
		t_on_failure("1");
		xlog("-----------new dst is $du\n");
		t_relay();
	} else {
		t_reply("500","Error");
	}
}

...
```


#### lb_is_destination(ip,port[,group[,active]])


Checks if the given IP and PORT belongs to a destination configured in
		the load-balancer's list. Returns true if found and active (see the
		"active" parameter).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		ONREPLY_ROUTE, BRANCH_ROUTE and LOCAL_ROUTE.


Meaning of the parameters is as follows:


- *ip* and *port* - IP 
			and PORT to be checked (any kind of variables are allowed, but
			take care as the PORT variables should have an interger value); 
			A value 0 for the port means "any" - will match any port.
- *group* - in what LB group the destination
			should be looked for; If not specified, the search will be in
			all groups.
- *active* - if "1", the search will be
			performed only over "active" (not disabled) destinations. If 
			missing, the search will consider any kind of destinations.


```opensips title="lb_is_destination usage"
...
if (lb_is_destination("$si","$sp") ) {
	# request from a LB destination
}
...
```


#### lb_count_call(ip,port,grp,resources)


The function counts the current call as load for a given destination 
		with some given resources. Note that this call is not going through
		the load-balancing logic (there are not routing decision taken for the
		call); it is simply counted by LB as ongoing call for a destination;


Meaning of the parameters is as follows:


- *ip* and *port* - IP 
			and PORT to identify the destination the call has to be counted
			for.
- *grp* - group id for the destinations; if
			no knows, "-1" will mean all groups.
- *resources* - string containing a 
			semi-colon list of resources required by the current call.


Function returns true if the call was properly taken into consideration
		for estimating the load on the destination.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE and
		FAILURE_ROUTE.


```opensips title="lb_count_count usage"
...
# count as load also the calls orgininated by lb destinations
if (lb_is_destination("$si","$sp") ) {
	# inbound call from destination
	lb_count_count("$si","$sp","-1","conference");
} else {
	# outbound call to destinations
	if ( !load_balance("1","conference") ) {
		send_reply("503","unavailable");
		exit();
	}
	# dst URI points to the new destination
	xlog("sending call to $du\n");
	t_relay();
	exit;
}
...
```


### Exported Statistics


NONE


### Exported MI Functions


#### lb_reload


Trigers the reload of the load balancing data from the DB.


MI FIFO Command Format:


```bash
		:lb_reload:_reply_fifo_file_
		_empty_line_
		
```


#### lb_resize


Changes the capacity for a resource of a destination. The function 
		receives as parameters the ID (as per DB) of the destination along 
		with the name of the resource you want to resize.


MI FIFO Command Format:


```bash
		:lb_resize:_reply_fifo_file_
		11   /*dstination id*/
		voicemail  /*resource name*/
		56   /* new resource capacity*/
		_empty_line_
		
```


#### lb_list


Lists all the destinations and the maximum and current load for each 
		resource of the destination.


MI FIFO Command Format:


```bash
		:lb_list:_reply_fifo_file_
		_empty_line_
		
```


```bash title="lb_list usage"
$ ./opensipsctl fifo lb_list
Destination:: sip:127.0.0.1:5100 id=1 enabled=yes auto-re=on
        Resource:: pstn max=3 load=0
        Resource:: transc max=5 load=1
        Resource:: vm max=5 load=2
Destination:: sip:127.0.0.1:5200 id=2 enabled=no auto-re=on
        Resource:: pstn max=6 load=0
        Resource:: trans max=57 load=0
        Resource:: vm max=5 load=0
```


#### lb_status


Gets or sets the status (enabled or disabled) of a destination. The 
		function takes 2 parameters, first mandatory, the id of the destiantion
		and second, optional, the new status. If no new status is given, the
		function will return the current status. If a new status is given 
		(0 - disable, 1 - enable), this status will be forced for the 
		destination.


MI FIFO Command Format:


```bash
		:lb_status:_reply_fifo_file_
		id
		status (optional)
		_empty_line_
		
```


```bash title="lb_status usage"
$ ./opensipsctl fifo lb_status 2
enable:: no
$ ./opensipsctl fifo lb_status 2 1
$ ./opensipsctl fifo lb_status 2
enable:: yes
```


### Exported Pseudo-Variables


NONE


## Developer Guide


### Available Functions


NONE


## Frequently Asked Questions


**Q: Where can I find more about OpenSIPS?**


Take a look at [http://www.opensips.org/](http://www.opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
