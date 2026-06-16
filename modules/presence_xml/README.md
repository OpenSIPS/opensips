---
title: "Presence_XML Module"
description: "The module does specific handling for notify-subscribe events using xml bodies. It is used with the general event handling module, presence. It constructs and adds 3 events to it: presence, presence.winfo, dialog;sla."
---

## Admin Guide


### Overview


The module does specific handling for notify-subscribe events using xml bodies.
	It is used with the general event handling module, presence. It constructs and adds
	3 events to it: presence, presence.winfo, dialog;sla.


This module takes the xcap permission rule documents from xcap_table.

	The presence permission rules are interpreted according to the specifications
	in RFC 4745 and RFC 5025.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *presence*.
- *signaling*.
- *xcap*.
- *xcap_client*.
Only compulsory if not using an integrated xcap server 
			(if 'integrated_xcap_server' parameter is not set).


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libxml-dev*.


### Exported Parameters


#### force_active (int)


This parameter is used for permissions when handling Subscribe messages.
		If set to 1, subscription state is considered active and the presentity
		is not queried for permissions(should be set to 1 if not using an xcap 
		server). 
		Otherwise,the xcap server is queried and the subscription states is
		according to user defined permission rules. If no rules are defined for
		a certain watcher, the subscriptions remains in pending state and the
		Notify sent will have no body.


Note: When switching from one value to another, the watchers table must
		be emptied.


*Default value is "0".*


```c title="Set force_active parameter"
...
modparam("presence_xml", "force_active", 1)
...
```


#### pidf_manipulation (int)


Setting this parameter to 1 enables the features described in RFC 4827.
		It gives the possibility to have a permanent state notified to the users
		even in the case in which the phone is not online. The presence document
		is taken from the xcap server and aggregated together with the other
		presence information, if any exist, for each Notify that is sent to the
		watchers. It is also possible to have information notified even if not 
		issuing any Publish (useful for services such as email, SMS, MMS).


*Default value is "0".*


```c title="Set pidf_manipulation parameter"
...
modparam("presence_xml", "pidf_manipulation", 1)
...
```


#### xcap_server (str)


The address of the xcap servers used for storage.
		This parameter is compulsory if the integrated_xcap_server parameter
		is not set. It can be set more that once, to construct an address
		list of trusted XCAP servers.


```c title="Set xcap_server parameter"
...
modparam("presence_xml", "xcap_server", "xcap_server.example.org")
modparam("presence_xml", "xcap_server", "xcap_server.ag.org")
...
```


#### pres_rules_auid (str)


This parameter should be configured if you are using the non integrated xcap
		mode and you need to use another pres-rules auid than the default 'pres-rules'.


```c title="Set pres_rules_auid parameter"
...
modparam("presence_xml", "pres_rules_auid", "org.openmobilealliance.pres-rules")
...
```


#### pres_rules_filename (str)


This parameter should be configured if you are using the non integrated xcap
		mode and you need to configure another filename than the default 'index'.


```c title="Set pres_rules_filename parameter"
...
modparam("presence_xml", "pres_rules_filename", "pres-rules")
...
```


#### generate_offline_body (str)


This parameter should be set to 0 if you want to prevent OpenSIPS from automatically
                generating a PIDF body when a publication expires or is explicitly terminated
                (a PUBLISH request is received with Expires: 0).


```c title="Set generate_offline_body parameter"
...
modparam("presence_xml", "generate_offline_body", 0)
...
```


### Exported Functions


None to be used in configuration file.


### Installation


The module requires 1 table in OpenSIPS database: xcap. The SQL 
	syntax to create it can be found in presence-create.sql     
	script in the database directories in the opensips/scripts folder.
	You can also find the complete database documentation on the
	project webpage, https://opensips.org/docs/db/db-schema-devel.html.


## Developer Guide


The module exports no function to be used in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
