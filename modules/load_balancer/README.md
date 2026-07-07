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


### How it works


Please refer to the Load-Balancer tutorial from the OpenSIPS website:
		[http://www.opensips.org/index.php?n=Resources.DocsTutLoadbalancing](http://www.opensips.org/index.php?n=Resources.DocsTutLoadbalancing).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Dialog* - Dialog module
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
modparam("", "db_table", "lb")
...
```


### Exported Functions


#### load_balance(grp,resources)


The function performs load-balancing over the available destinations in
		order to find the less loaded destination that can provide the 
		requested resources and belong to a requested group.


Meaning of the parameters is as follows:


- *grp* - group id for the destinations; the
			destination may be grouped in several groups you can you for 
			differnet scenarios.
- *resources* - string containing a 
			semi-colon list of resources required by the current call.


Function returns true is a new destination URI is set pointing to the 
		selected destiantion.
		NOTE that the RURI will not be changed by this function.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE,
			REPLY_ROUTE and FAILURE_ROUTE.


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


### Exported Statistics


NONE


### Exported MI Functions


#### lb_reload


Trigers the reload of the load balancing data from the DB.


MI FIFO Command Format:


```c
		:lb_reload:_reply_fifo_file_
		_empty_line_
		
```


#### lb_resize


Changes the capacity for a resource of a destination. The function 
		receives as parameters the ID (as per DB) of the destination along 
		with the name of the resource you want to resize.


MI FIFO Command Format:


```c
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


```c
		:lb_list:_reply_fifo_file_
		_empty_line_
		
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
