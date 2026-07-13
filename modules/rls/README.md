---
title: "Resource List Server"
description: "The modules is a Resource List Server implementation following the specification in RFC 4662 and RFC 4826."
---

## Admin Guide


### Overview


The modules is a Resource List Server implementation following the
specification in RFC 4662 and RFC 4826.


The server is independent from local presence servers, retrieving presence
information with Subscribe-Notify messages.


The module uses the presence module as a library, as it requires a resembling
mechanism for handling Subscribe. Therefore, in case the local presence server
is not collocated on the same machine with the RL server, the presence module
should be loaded in a library mode only (see doc for presence module).


It handles subscription to lists in an event independent way.The default event
is presence, but if some other events are to be handled by the server, they
should be added using the module parameter "rls_events".


It works with XCAP server for storage. There is also the possibility to
configure it to work in an integrated_xcap server mode, when it only
queries database for the resource lists documents. This is useful in a
small architecture when all the clients use an integrated server and there
are no references to exterior documents in their lists.


The same as presence module, it has a caching mode with periodical update
in database for subscribe information. The information retrieved with Notify
messages is stored in database only.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *signaling*.
- *tm*.
- *presence- in a library mode*.
- *pua*.


#### External Libraries or Applications


- *libxml-dev*.


### Exported Parameters


#### db_url(str)


The database url.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
...
modparam("rls", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### xcap_table(str)


The name of the xcap table in which the integrated server
or the xcap_client module writes. If integrated_xcap_server
parameter not set, the name of the table must be the same as
the one set for the xcap_client module.


*Default value is "xcap".*


```opensips title="Set xcap_table parameter"
...
modparam("rls", "xcap_table", "xcaps");
...
```


#### rlsubs_table(str)


The name of the db table where resource lists subscription 
information is stored.


*Default value is "rls_watchers".*


```opensips title="Set rlsubs_table parameter"
...
modparam("rls", "rlsubs_table", "rls_subscriptions")
...
```


#### rlpres_table(str)


The name of the db table where notified event specific
information is stored.


*Default value is "rls_presentity".*


```opensips title="Set rlpres_table parameter"
...
modparam("rls", "rlpres_table", "rls_notify")
...
```


#### clean_period (int)


The period at which to check for expired information.


*Default value is "100".*


```opensips title="Set clean_period parameter"
...
modparam("rls", "clean_period", 100)
...
```


#### waitn_time (int)


The timer period at which the server should attempt to send
Notifies with the updated presence state of the subscribed list
or watcher information.


*Default value is "50".*


```opensips title="Set waitn_time parameter"
...
modparam("rls", "waitn_time", 10)
...
```


#### max_expires (int)


The maximum accepted expires for a subscription to a list.


*Default value is "7200".*


```opensips title="Set max_expires parameter"
...
modparam("rls", "max_expires", 10800)
...
		
```


#### hash_size (int)


The dimension of the hash table used to store subscription to a list.
This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set hash_size parameter"
...
modparam("rls", "hash_size", 11)
...
		
```


#### xcap_root (str)


The address of the xcap server.


*Default value is "NULL".*


```opensips title="Set hash_size parameter"
...
modparam("rls", "xcap_root", "http://192.168.2.132/xcap-root:800")
...
		
```


#### integrated_xcap_server (int)


This parameter should be set if only integrated xcap servers
are used to store resource lists.


*Default value is "0".*


```opensips title="Set integrated_xcap_server parameter"
...
modparam("rls", "integrated_xcap_server", 1)
...
		
```


#### to_presence_code (int)


The code to be returned by rls_handle_subscribe function 
if the processed Subscribe is not a resource list Subscribe.
This code can be used in an architecture with presence and rls
servers collocated on the same machine, to call handle_subscribe
on the message causing this code.


*Default value is "0".*


```opensips title="Set to_presence_code parameter"
...
modparam("rls", "to_presence_code", 10)
...
		
```


#### rls_event (str)


The default event that RLS handles is presence. If some other
events should also be handled by RLS they should be added using
this parameter. It can be set more than once.


*Default value is ""presence"".*


```opensips title="Set rls_event parameter"
...
modparam("rls", "rls_event", "dialog;sla")
...
		
```


#### presence_server (str)


The address of the presence server. It will be used as outbound proxy for
Subscribes requests sent by the RLS server to bouncing on and off the
proxy and having to include special processing for this messages
in the proxy's configuration file.


```opensips title="Set presence_server parameter"
...
modparam("rls", "presence_server", "sip:pres@opensips.org:5060")
...
		
```


#### server_address (str)


The address of the server that will be used as a contact in sent
Subscribe request and 200Ok replies for Subscribe messages for RLS.
It is compulosy.


```opensips title="Set server_address parameter"
...
modparam("rls", "server_address", "sip:rls@opensips.org:5060")
...
		
```


### Exported Functions


#### rls_handle_subscribe()


This function detects if a Subscribe message should be
handled by RLS. If not it replies with the configured 
to_presence_code. If it is, it extracts the dialog info and sends
aggregate Notify requests with information for the list.


This function can be used from REQUEST_ROUTE.


```opensips title="rls_handle_subscribe usage"
...
For presence and rls on the same machine:
	modparam(rls, "to_presence_code", 10)

	if(is_method("SUBSCRIBE"))
	{	
		$var(ret_code)= rls_handle_subscribe();

		if($var(ret_code)== 10)
				handle_subscribe();

		t_release();
	}

For rls only:
	if(is_method("SUBSCRIBE"))
	{
		rls_handle_subscribe();
		t_release();
	}

...
```


#### rls_handle_notify()


This function has to be called for Notify messages sent by presence
servers in reply to the Subscribe messages sent by RLS.


This function can be used from REQUEST_ROUTE.


It can return 3 codes:


- *1* - the Notify was inside a dialog that was
recognized by the RLS server and was processed successfully.
- *2* - the Notify did not belog to a dialog initiated
by the RLS server.
- *-1* - an error occurred during processing.


```opensips title="rls_handle_notify usage"
...
if(method=="NOTIFY")
    rls_handle_notify();
...
```


### Installation


The module requires 2 table in OpenSIPS database: rls_presentity
and rls_watchers.The SQL syntax to create them can be found in
rls-create.sql script in the database directories in
the opensips/scripts folder.
You can also find the complete database documentation on the
project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


## Developer Guide


The module provides no functions to be used	in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
