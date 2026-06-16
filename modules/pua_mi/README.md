---
title: "PUA MI"
description: "The pua_mi offers the possibility to publish presence information and subscribe to presence information via MI transports."
---

## Admin Guide


### Overview


The pua_mi offers the possibility to publish presence
	         information and subscribe to presence information via MI
 	         transports.


Using this module you can create independent applications/scripts to
		publish not sip-related information (e.g., system resources like
		CPU-usage, memory, number of active subscribers ...).
	        Also, this module allows non-SIP speaking applications
		to subscribe presence information kept in a SIP presence
	        server.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *pua*


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### presence_server (str)


The the address of the presence server. If set, it will be
		used as outbound proxy when sending PUBLISH requests.


```c title="Set presence_server parameter"
...
modparam("pua_mi", "presence_server", "sip:pa@opensips.org:5075")
...
	
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Exported MI Functions


#### pua_mi:publish


Replaces obsolete MI command: *pua_publish*.


Command parameters:


- *presentity_uri*
					- e.g. sip:system@opensips.org
- *expires*
					- Relative expires time in
					seconds (e.g. 3600).
- *event_package*
					- Event package that is
		target of published information (e.g. presence).
- *content_type* (optional)
					- Content type of published
		information (e.g. application/pidf+xml). If this parameter
		is provided, the *body* parameter is also required.
- *etag* (optional)
					- ETag that publish should
		match.
- *extra_headers* (optional)
					- Extra headers added to PUBLISH
		request.
- *body* (optioanl)
					- The body of the publish
		request containing published information or missing if
		no published information.
		It has to be a single line for FIFO transport. If this parameter
		is provided, the *content_type* parameter is also required.


```c title="pua_mi:publish FIFO example"
...

opensips-cli -x mi pua_mi:publish sip:system@opensips.org 3600 presence application/pidf+xml <?xml version='1.0'?><presence xmlns='urn:ietf:params:xml:ns:pidf' xmlns:dm='urn:ietf:params:xml:ns:pidf:data-model' xmlns:rpid='urn:ietf:params:xml:ns:pidf:rpid' xmlns:c='urn:ietf:params:xml:ns:pidf:cipid' entity='system@opensips.org'><tuple id='0x81475a0'><status><basic>open</basic></status></tuple><dm:person id='pdd748945'><rpid:activities><rpid:away/>away</rpid:activities><dm:note>CPU:16 MEM:476</dm:note></dm:person></presence>
```


#### pua_mi:subscribe


Replaces obsolete MI command: *pua_subscribe*.


Command parameters:


- *presentity_uri*
					- e.g. sip:presentity@opensips.org
- *watcher_uri*
					- e.g. sip:watcher@opensips.org
- *event_package*
- *expires*
					- Relative time in seconds for the desired validity of the subscription.


```c title="pua_mi:subscribe FIFO example"
...

opensips-cli -x mi pua_mi:subscribe sip:system@opensips.org sip:400@opensips.org presence 3600
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
