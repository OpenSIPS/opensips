---
title: "mqueue Module"
description: "The mqueue module offers a generic message queue system in shared memory for inter-process communication using the config file. One example of usage is to send time consuming operations to one or several timer processes that consumes items in the queue, without affecting SIP message handl..."
---

## Admin Guide


### Overview


The mqueue module offers a generic message queue system in shared
		memory for inter-process communication using the config file.
		One example of usage is to send time consuming operations to one or
		several timer processes that consumes items in the queue, without
		affecting SIP message handling in the socket-listening process.


There can be many defined queues. Access to queued values is done via
		pseudo variables.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *None*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (str)


The URL to connect to database for loading values
		in mqueue table at start up and/or saving values at shutdown.


*Default value is NULL (do not connect).*


```opensips title="Set db_url parameter"
...
modparam("mqueue", "db_url", "mysql://opensips:opensipsrw@localhost/opensips")

# Example of table in sqlite,
# you have the set the fields to support the length according
# to the data that will be present in the mqueue
CREATE TABLE mqueue_name (
id INTEGER PRIMARY KEY AUTOINCREMENT,
key character varying(64) DEFAULT "" NOT NULL,
val character varying(4096) DEFAULT "" NOT NULL
);
...
```


#### mqueue (string)


Definition of a memory queue


*Default value is "none".*


Value must be a list of parameters: attr=value;...


- Mandatory attributes:

  - *name*: name of the queue.
- Optional attributes:

  - *size*: size of the queue.
				Specifies the maximum number of items in queue.
				If exceeded the oldest one is removed.
				If not set the queue will be limitless.
  - *dbmode*: If set to 1, the content of the
				queue is written to database table when the SIP server is
				stopped (i.e., ensure persistency over restarts).
				If set to 2, it is written at shutdown but not read at startup.
				If set to 3, it is read at sartup but not written at shutdown.
				Default value is 0 (no db table interaction).
  - *addmode*: how to add new (key,value) pairs.
					
					
						*0*:
						Will push all new (key,value) pairs at the end of
						the queue. (default)
					
					
						*1*:
						Will keep oldest (key,value) pair in the queue,
						based on the key.
					
					
						*2*:
						Will keep newest (key,value) pair in the queue,
						based on the key.


The parameter can be set many times, each holding the
		definition of one queue.


```opensips title="Set mqueue parameter"
...
modparam("mqueue", "mqueue", "name=myq;size=20;")
modparam("mqueue", "mqueue", "name=myq;size=10000;addmode=2")
modparam("mqueue", "mqueue", "name=qaz")
modparam("mqueue", "mqueue", "name=qaz;addmode=1")
...
```


### Exported Functions


#### mq_add(queue, key, value)


Add a new item (key, value) in the queue. If max size of queue is
		exceeded, the oldest one is removed.


```opensips title="mq_add usage"
...
mq_add("myq", "$rU", "call from $fU");
...
```


#### mq_fetch(queue)


Take oldest item from queue and fill $mqk(queue) and
		$mqv(queue) pseudo variables.


Return: true on success (1); false on failure (-1) or
		no item fetched (-2).


```opensips title="mq_fetch usage"
...
while(mq_fetch("myq"))
{
	xlog("$mqk(myq) - $mqv(myq)\n");
}
...
```


#### mq_pv_free(queue)


Free the item fetched in pseudo-variables. It is optional,
		a new fetch frees the previous values.


```opensips title="mq_pv_free usage"
...
mq_pv_free("myq");
...
```


#### mq_size(queue)


Returns the current number of elements in the mqueue.


If the mqueue is empty, the function returns -1. If the
		mqueue is not found, the function returns -2.


```opensips title="mq_size usage"
...
$var(q_size) = mq_size("queue");
xlog("L_INFO", "Size of queue is: $var(q_size)\n");
...
```


### Exported MI Functions


#### mqueue:get_size


Replaces obsolete MI command: *mq_get_size*.


Get the size of a memory queue.


Parameters:


- name


```bash title="mqueue:get_size usage"
...
opensips-cli -x mqueue:get_size xyz
...
```


#### mqueue:fetch


Replaces obsolete MI command: *mq_fetch*.


Fetch one (or up to limit) key-value pair from a memory queue.


Parameters:


- name
- limit
limit


```bash title="mqueue:fetch usage"
...
opensips-cli -x mqueue:fetch xyz
...
```


#### mqueue:get_sizes


Replaces obsolete MI command: *mq_get_sizes*.


Get the size for all memory queues.


Parameters: none


```bash title="mqueue:get_sizes usage"
...
opensips-cli -x mqueue:get_sizes
...
```


### Exported Pseudo-Variables


#### $mqk(mqueue)


The variable is read-only and returns the most recent item key
			fetched from the specified mqueue.


#### $mqv(mqueue)


The variable is read-only and returns the most recent item value
			fetched from the specified mqueue.


#### $mq_size(mqueue)


The variable is read-only and returns the size of the specified
			mqueue.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
