---
title: "pua_reginfo Module"
description: "This module publishes information about \"reg\"-events according to to RFC 3680. This can be used distribute the registration-info status to the subscribed watchers."
---

## Admin Guide


### Overview


This module publishes information about "reg"-events according to
              to RFC 3680. This can be used distribute the registration-info
              status to the subscribed watchers.


This module "PUBLISH"es information when a new user registers
              at this server (e.g. when "save()" is called) to users, which have
              subscribed for the reg-info for this user.


This module can "SUBSCRIBE" for information at another server, so it
              will receive "NOTIFY"-requests, when the information about a user
              changes.


And finally, it can process received "NOTIFY" requests and it will 
              update the local registry accordingly.


Use cases for this might be:


- Keeping different Servers in Sync regarding
		the location database
- Get notified, when a user registers: A presence-server,
		which handles offline message storage for an account, would get
		notified, when the user comes online.
- A client could subscribe to its own registration-status,
		so he would get notified as soon as his account gets administratively
		unregistered.
- ...


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *pua*.
- *usrloc*.


#### External Libraries or Applications


None.


### Exported Parameters


#### default_domain(str)


The default domain for the registered users to be used when
		constructing the uri for the registrar callback.


*Default value is "NULL".*


```c title="Set default_domain parameter"
...
modparam("pua_reginfo", "default_domain", "kamailio.org")
...
```


#### publish_reginfo(int)


Whether or not to generate PUBLISH requests.


*Default value is "1" (enabled).*


```c title="Set publish_reginfo parameter"
...
modparam("pua_reginfo", "publish_reginfo", 0)
...
```


#### outbound_proxy(str)


The outbound_proxy uri to be used when sending Subscribe and Publish requests.


*Default value is "NULL".*


```c title="Set outbound_proxy parameter"
...
modparam("pua_reginfo", "outbound_proxy", "sip:proxy@kamailio.org")
...
```


#### server_address(str)


The IP address of the server.


```c title="Set server_address parameter"
...
modparam("pua_reginfo", "server_address", "sip:reginfo@160.34.23.12")
...
```


#### ul_domain(str)


The domain for for querying the usrloc-database.


*Default value is "NULL" (not set).*


```c title="Set ul_domain parameter"
...
modparam("pua_reginfo", "ul_domain", "location")
...
```


#### ul_identities_key(str)


The Key, which may be used for retrieving multiple public identies
		for a user.


*Default value is "NULL" (not set).*


```c title="Set ul_identities_key parameter"
...
modparam("pua_reginfo", "ul_identities_key", "identities")
...
onreply_route[register_reply] {
	if (t_check_status("200") && $hdr(P-Associated-URI)) {
        ul_add_key("location", "$tU@$td", "identities", "$hdr(P-Associated-URI)");
        reginfo_update("$tU@$td");
	}
}

...
		
```


### Exported Functions


#### reginfo_handle_notify(uldomain)


This function processes received "NOTIFY"-requests and updates
				the local registry accordingly.


This method does not create any SIP-Response, this has to be done
				by the script-writer.


The parameter has to correspond to user location table (domain)
				where to store the record.


Return codes:


- *2* - contacts successfully updated,
				but no more contacts online now.
*1* - contacts successfully updated and at
				at least one contact still registered.
*-1* - Invalid NOTIFY or other error (see log-file)


```c title="reginfo_handle_notify usage"
...
if(is_method("NOTIFY")) 
	if (reginfo_handle_notify("location"))
		send_reply("202", "Accepted");
...
				
```


#### reginfo_subscribe(uri[, expires])


This function will subscribe for reginfo-information at the given
				server URI.


Meaning of the parameters is as follows:


- *uri* - SIP-URI of the server, where to subscribe,
				may contain pseudo-variables.
*expires* - Expiration date for this subscription, in seconds (default 3600)


```c title="reginfo_subscribe usage"
...
route {
	t_on_reply("1");
	t_relay();
}

reply_route[1] {
	if (t_check_status("200")) 
		reginfo_subscribe("$ru");		
}
...
				
```


#### reginfo_update(aor)


Explicitly update the presence status, e.g., when new information
				is learned. This may trigger a new NOTIFY towards subscribed
				entities; at least it will update the internal information for
				subsequent subscribe and notifies.


This is done implicitly, when a registration is updated. However,
				when a registration was just updated with additional information like
				identities, this is not triggered automatically.


Meaning of the parameters is as follows:


- *aor* - The AOR to be updated.


```c title="reginfo_subscribe usage"
...
modparam("pua_reginfo", "ul_domain", "location")
modparam("pua_reginfo", "ul_identities_key", "identities")
...
onreply_route[register_reply] {
	if (t_check_status("200") && $hdr(P-Associated-URI)) {
        ul_add_key("location", "$tU@$td", "identities", "$hdr(P-Associated-URI)");
        reginfo_update("$tU@$td");
	}
}

...
				
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
