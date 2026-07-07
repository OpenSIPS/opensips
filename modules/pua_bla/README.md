---
title: "PUA Bridged Line Appearances"
description: "The pua_bla module enables Bridged Line Appearances support according to the specifications in draft-anil-sipping-bla-03.txt."
---

## Admin Guide


### Overview


The pua_bla module enables Bridged Line Appearances support according to 
		 the specifications in draft-anil-sipping-bla-03.txt.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *usrloc*.
- *pua*.
- *presence*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml*.


### Exported Parameters


#### default_domain(str)


The default domain for the registered users to be used when
		constructing the uri for the registrar callback.


*Default value is "NULL".*


```opensips title="Set default_domain parameter"
...
modparam("pua_bla", "default_domain", "opensips.org")
...
```


#### header_name(str)


The name of the header to be added to Publish requests.
		It will contain the uri of the user agent that sent the
		Notify that is transformed into Publish. It stops sending 
		a Notification with the same information to the sender.


*Default value is "NULL".*


```opensips title="Set header_name parameter"
...
modparam("pua_bla", "header_name", "Sender")
...
```


#### outbound_proxy(str)


The outbound_proxy uri to be used when sending Subscribe requests.


*Default value is "NULL".*


```opensips title="Set outbound_proxy parameter"
...
modparam("pua_bla", "outbound_proxy", "sip:proxy@opensips.org")
...
```


#### server_address(str)


The IP address of the server.


```opensips title="Set server_address parameter"
...
modparam("pua_bla", "server_address", "sip:bla@160.34.23.12")
...
```


#### presence_server(str)


The address of the presence server - will be used as
			an outbound proxy when sending PUBLISH requests. 
			It is optional.


*Default value is "NULL".*


```opensips title="Set presence_server parameter"
...
modparam("pua_bla", "presence_server", "sip:pa@opensips.org")
...
```


### Exported Functions


#### bla_set_flag()


The function is used to mark REGISTER requests made to a BLA AOR.
				The modules subscribes to the registered contacts for dialog;sla 
				event.


```opensips title="bla_set_flag usage"
...
if(is_method("REGISTER") && $tu=~"bla_aor@opensips.org") 
	bla_set_flag();		
...
```


#### bla_handle_notify()


The function handles Notify requests sent from phones on the
				same BLA to the server. The message is transformed in Publish 
				request and passed to presence module for further handling.
				in case of a successful processing a 2xx reply should be sent.


```opensips title="bla_handle_notify usage"
...
if(is_method("NOTIFY") && $tu=~"bla_aor@opensips.org") 
{
		if( bla_handle_notify() ) 
			t_reply(200, "OK");
}	
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
