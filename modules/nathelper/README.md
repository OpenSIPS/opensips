---
title: "nathelper Module"
description: "This is a module to help with NAT traversal. In particular, it helps symmetric UAs that don't advertise they are symmetric and are not able to determine their public address. fix_nated_contact rewrites Contact header field with request's source address:port pair. fix_nated_sdp adds the ac..."
---

## Admin Guide


### Overview


This is a module to help with NAT traversal. In particular,
		it helps symmetric UAs that don't advertise they are symmetric
		and are not able to determine their public address. fix_nated_contact
		rewrites Contact header field with request's source address:port pair.
		fix_nated_sdp adds the active direction indication to SDP (flag
		0x01) and updates source IP address too (flag 0x02).


Since version 2.2, stateful ping(only SIP Pings) for nathelper is available.
		This allows you to remove contacts from usrloc location table when
		*max_pings_lost* pings are not responded to, each ping
		having a response timeout of *ping_threshold* seconds.
		In order to have this functionality, contacts must have
		*remove_on_timeout_bflag* flag set when inserted into
		the location table.


Works with multipart messages that contain an SDP part,
		but not with multi-layered multipart messages.


### NAT pinging types


Currently, the nathelper module supports two types of NAT pings:


- *UDP package* - 4 bytes (zero filled) UDP
			packages are sent to the contact address.

  - *Advantages:* low bandwitdh traffic,
				easy to generate by OpenSIPS;
  - *Disadvantages:* unidirectional
				traffic through NAT (inbound - from outside to inside); As
				many NATs do update the bind timeout only on outbound traffic,
				the bind may expire and closed.
- *SIP request* - a stateless SIP request is
			sent to the contact address.

  - *Advantages:* bidirectional traffic
				through NAT, since each PING request from OpenSIPS (inbound
				traffic) will force the SIP client to generate a SIP reply
				(outbound traffic) - the NAT bind will be surely kept open.
				Since version 2.2, one can also choose to remove contacts
				from the location table if a certain threshold is detected.
  - *Disadvantages:* higher bandwitdh
				traffic, more expensive (as time) to generate by OpenSIPS;


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *usrloc* module - only if the NATed
				contacts are to be pinged.
- *clusterer* - only if "cluster_id"
				option is enabled.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### natping_interval (integer)


Period of time in seconds between sending the NAT pings to all
		currently registered UAs to keep their NAT bindings alive.
		Value of 0 disables this functionality.


> [!NOTE]
> Enabling the NAT pinging functionality will force the module to
		bind itself to USRLOC module.


*Default value is 0.*


```c title="Set natping_interval parameter"
...
modparam("nathelper", "natping_interval", 10)
...
```


#### ping_nated_only (integer)


If this variable is set then only contacts that have
		"behind_NAT" flag in user location database set will
		get ping.


*Default value is 0.*


```c title="Set ping_nated_only parameter"
...
modparam("nathelper", "ping_nated_only", 1)
...
```


#### natping_partitions (integer)


How many partitions/chunks to be used for sending the pingings.
		One partition means sending all pingings together. Two partitions
		means to send half pings and second half at a time.


*Default value is 1.*
		*Maximum allowed value is 8.*


```c title="Set natping_partitions parameter"
...
modparam("nathelper", "natping_partitions", 4)
...
```


#### natping_socket (string)


Spoof the natping's source-ip to this address. Works only for IPv4.


*Default value is NULL.*


```c title="Set natping_socket parameter"
...
modparam("nathelper", "natping_socket", "192.168.1.1:5006")
...
```


#### received_avp (str)


The name of the Attribute-Value-Pair (AVP) used to store the URI
		containing the received IP, port and protocol. The URI is created
		by the [fix nated register](#func_fix_nated_register) function and this data
		may then be also picked up by the registrar module, which will attach a
		"Received=" attribute to the registration.  Do not forget to change the
		value of corresponding parameter in the [registrar](../registrar)
		module whenever you change the value of this parameter.


> [!NOTE]
> You must set this parameter if you use [fix nated register](#func_fix_nated_register).
		Additionally, if you are using registrar, you must also set its symmetric
		[received_avp](../registrar#received_avp) module parameter
		to the **same value**.


*Default value is "NULL" (disabled).*


```c title="Set received_avp parameter"
...
modparam("nathelper", "received_avp", "$avp(received)")
...
```


#### force_socket (string)


Sending socket to be used for pinging contacts without local socket
		information (the local socket information may be lost during a restart 
		or contact replication). If no one specified, OpenSIPS will choose the
		first listening interface matching the destination protocol and
		AF family.


*Default value is "NULL".*


```c title="Set force_socket parameter"
...
modparam("nathelper", "force_socket", "localhost:33333")
...
```


#### sipping_bflag (string)


What branch flag should be used by the module to identify NATed
		contacts for which it should perform NAT ping via a SIP request
		instead if dummy UDP package.


*Default value is NULL (disabled).*


```c title="Set sipping_bflag parameter"
...
modparam("nathelper", "sipping_bflag", "SIPPING_ENABLE")
...
```


#### remove_on_timeout_bflag (string)


What branch flag to be used in order to activate usrloc contact removal when
		the [ping threshold](#param_ping_threshold) is exceeded.


*Default value is NULL (disabled).*


```c title="Set remove_on_timeout_bflag parameter"
...
modparam("nathelper", "remove_on_timeout_bflag", "SIPPING_RTO")
...
```


#### sipping_latency_flag (string)


The branch flag which will be used in order to enable contact pinging
		latency computation and reporting via the usrloc E_UL_LATENCY_UPDATE
		event.


*Default value is NULL (disabled).*


```c title="Set sipping_latency_flag parameter"
...
modparam("nathelper", "sipping_latency_flag", "SIPPING_CALC_LATENCY")
...
```


#### sipping_ignore_rpl_codes (CSV string)


A comma-separated list of SIP reply status codes to contact pings which
		are to be discarded. This may be useful for "full-sharing" user
		location topologies, where the location nodes are not directly facing
		the UAs, hence the intermediary SIP component may generate replies to
		offline contact ping attempts (e.g. 408 - Request Timeout) -- such ping
		replies should be ignored.


*Default value is "NULL" (all reply status codes are accepted).*


```c title="Set sipping_ignore_rpl_codes parameter"
...
modparam("nathelper", "sipping_ignore_rpl_codes", "408, 480, 404")
...
```


#### sipping_from (string)


The parameter sets the SIP URI to be used in generating the SIP
		requests for NAT ping purposes. To enable the SIP request pinging
		feature, you have to set this parameter. The SIP request pinging
		will be used only for requests marked so.


*Default value is "NULL".*


```c title="Set sipping_from parameter"
...
modparam("nathelper", "sipping_from", "sip:pinger@siphub.net")
...
```


#### sipping_method (string)


The parameter sets the SIP method to be used in generating the SIP
		requests for NAT ping purposes.


*Default value is "OPTIONS".*


```c title="Set sipping_method parameter"
...
modparam("nathelper", "sipping_method", "INFO")
...
```


#### nortpproxy_str (string)


The parameter sets the SDP attribute used by nathelper to mark
		the packet SDP informations have already been mangled.


If empty string, no marker will be added or checked.


> [!NOTE]
> The string must be a complete SDP line, including the EOH (\r\n).


*Default value is "a=nortpproxy:yes\r\n".*


```c title="Set nortpproxy_str parameter"
...
modparam("nathelper", "nortpproxy_str", "a=sdpmangled:yes\r\n")
...
```


#### natping_tcp (integer)


If the flag is set, TCP/TLS clients will also be pinged with
		SIP OPTIONS messages.


*Default value is 0 (not set).*


```c title="Set natping_tcp parameter"
...
modparam("nathelper", "natping_tcp", 1)
...
```


#### oldip_skip (string)


Parameter which specifies whether old media ip and old origin ip
		shall be put in the sdp body. The parameter has two values :
		'o' ("a=oldoip" field shall be skipped) and 'c' ("a=oldcip" field
		shall be skipped).


*Default value is 0 (not set).*


```c title="Set oldip_skip parameter"
...
modparam("nathelper", "oldip_skip", "oc")
...
```


#### ping_threshold (int)


If a contact does not respond in *ping_threshold*
			seconds since the ping has been sent, the contact shall be removed
			after [max pings lost](#param_max_pings_lost) unresponded pings.


*Default value is 3 (seconds).*


```c title="Set ping_threshold parameter"
...
modparam("nathelper", "ping_threshold", 10)
...
```


#### max_pings_lost (int)


Number of unresponded pings after which the contact shall be removed
		from the location table.


*Default value is 3 (pings).*


```c title="Set max_pings_lost parameter"
...
modparam("nathelper", "max_pings_lost", 5)
...
```


#### cluster_id (integer)


The ID of the cluster the module is part of. The clustering support is 
		used by the nathelper module for controlling the pinging process. When 
		part of a cluster of multiple nodes, the nodes can agree upon which node
		is the one responsible for pinging.


The clustering with sharing tag support may be used to control which 
		node in the cluster will perform the pinging/probing to the
		contacts. See the
		[cluster sharing tag](#param_cluster_sharing_tag) option.


For more info on how to define and populate a cluster (with OpenSIPS 
		nodes) see the "clusterer" module.


*Default value is "0 (none)".*


```c title="Set cluster_id parameter"
...
# Be part of cluster ID 9
modparam("nathelper", "cluster_id", 9)
...
```


#### cluster_sharing_tag (string)


The name of the sharing tag (as defined per clusterer modules) to 
		control which node is responsible for perform pinging of the 
		contacts.
		If defined, only the node with active status of this tag will 
		perform the pinging.


The [cluster id](#param_cluster_id) must be defined for this option
		to work.


This is an optional parameter. If not set, all the nodes in the cluster
		will individually do the pinging.


*Default value is "empty (none)".*


```c title="Set cluster_sharing_tag parameter"
...
# only the node with the active "vip" sharing tag will perform pinging
modparam("nathelper", "cluster_id", 9)
modparam("nathelper", "cluster_sharing_tag", "vip")
...
```


### Exported Functions


#### fix_nated_contact([uri_params [, flags]])


Rewrites the URI Contact HF to contain request's
		source address:port. If a list of URI parameter is provided, it will
		be added to the modified contact;


*IMPORTANT NOTE:* Changes made by this function shall
		not be seen in the async resume route. So make sure you call it in all the
		resume routes where you need the contact fixed.


Parameters:


- *uri_params (string, optional)*
- *flags (string, optional)* - CSV list of flags:
				
					*preserve-uri* - add an extra Contact URI
						parameter named "org". The org value is the Base64 encoding of
						the original Contact URI host:port part. Pair it with
						`restore_nated_ruri()` for restoring the
						original host:port into R-URI.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE.


```c title="fix_nated_contact usage"
...
if (search("User-Agent: Cisco ATA.*") {
    fix_nated_contact(";ata=cisco", "preserve-uri");
} else {
    fix_nated_contact();
}
...
```


#### fix_nated_sdp(flags [, ip_address [, sdp_fields]])


Alters the SDP information in orer to facilitate NAT traversal. What
		changes to be performed may be controled via the
		"flags" parameter. Since version 1.12 the name of the old
		ip fields are "a=oldoip" for old origin ip and "a=oldcip" for old meda
		ip.


Meaning of the parameters is as follows:


- *flags (string)* - the value may be a CSV of
			the following flags:

  - *add-dir-active* - (old
					*0x01* flag) adds
					"a=direction:active" SDP line;
  - *rewrite-media-ip* - (old
					*0x02* flag) rewrite media
					IP address (c=) with source address of the message
					or the provided IP address (the provided IP address takes
					precedence over the source address).
  - *add-no-rtpproxy* - (old
					*0x04* flag) adds
						"a=nortpproxy:yes" SDP line;
  - *rewrite-origin-ip* - (old
					*0x08* flag) rewrite IP from
					origin description (o=) with source address of the message
					or the provided IP address (the provided IP address takes
					precedence over the source address).
  - *rewrite-null-ips* - (old
					*0x10* flag) force rewrite of
					null media IP and/or origin IP address.
					Without this flag, null IPs are left untouched.
- *ip_address (string, optional)* - IP to be used for
			rewriting SDP. If not specified, the received signalling IP will be used.
			NOTE: For the IP to be used, you need to use 0x02 or 0x08 flags,
			otherwise it will have no effect.
- *sdp_fields (string, optional)* - SDP field(s) to be appended to SDP.
			Note: Each SDP field must be preceded by "\r\n".


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE,
		FAILURE_ROUTE, BRANCH_ROUTE.


```c title="fix_nated_sdp usage"
...
# Add "a=direction:active" SDP line
# Rewrite media IP (c= line)
# Add extra "a=x-attr1" SDP line
# Add extra "a=x-attr2" SDP line
if (search("User-Agent: Cisco ATA.*")
    {fix_nated_sdp(3,,"\r\na=x-attr1\r\na=x-attr2");};
...
```


#### add_rcv_param([flag]),


Add received parameter to Contact header fields or Contact URI.
		The parameter will
		contain URI created from the source IP, port, and protocol of the
		packet containing the SIP message. The parameter can be then
		processed by another registrar, this is useful, for example, when
		replicating register messages using t_replicate function to
		another registrar.


Meaning of the parameters is as follows:


- *flag (int, optional)* - flags to indicate if
			the parameter should be added to Contact URI or Contact header.
			If the flag is non-zero, the parameter will be added to the Contact
			URI. If not used or equal to zero, the parameter will go to the
			Contact header.


This function can be used from REQUEST_ROUTE.


```c title="add_rcv_paramer usage"
...
add_rcv_param(); # add the parameter to the Contact header
....
add_rcv_param(1); # add the parameter to the Contact URI
...
```


#### fix_nated_register()


The function creates a URI consisting of the source IP, port and
		protocol and stores it in the [received avp](#param_received_avp) AVP. The URI will
		be appended as "received" parameter to Contact in 200 OK and
		may also be stored in the user location database if the same AVP
		is also configured for the [registrar](../registrar) module.


This function can be used from REQUEST_ROUTE.


```c title="fix_nated_register usage"
...
fix_nated_register();
...
```


#### nat_uac_test(flags)


Determines whether the received SIP message originated behind a NAT,
			using one or more pre-defined checks.


The *flags* (string) parameter denotes a
			comma-separated list of checks to be performed, as follows:


- *private-contact* - (old *1* flag)
			Contact header field is searched for occurrence of RFC1918 / RFC6598
			addresses
- *diff-ip-src-via* - (old *2* flag)
			the "received" test is used: address in Via is compared against source
			IP address of signaling
- *private-via* - (old *4* flag)
			Top Most VIA is searched for occurrence of RFC1918 / RFC6598 addresses
- *private-sdp* - (old *8* flag)
			SDP is searched for occurrence of RFC1918 / RFC6598 addresses
- *diff-port-src-via* - (old *16*
			flag) test if the source port is different from the port in Via
- *diff-ip-src-contact* - (old *32*
			flag) address in Contact is compared against source IP address of
			signaling
- *diff-port-src-contact* - (old *64*
			flag) Port in Contact is compared against source port of signaling
- *carrier-grade-nat* - (old *128*
			flag) also include RFC 6333 addresses in the checks for
			*Contact*, *Via* and
			*SDP*


**Returns true if any of the tests passed**.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE.


```c title="nat_uac_test usage"
...
# check for private Contact or SDP media IP addresses
if (nat_uac_test("private-contact,private-sdp"))
	xlog("SIP message is NAT'ed (Call-ID: $ci)\n");
...
```


#### restore_nated_ruri()


Restores the original R-URI host:port from the "org" URI parameter
			generated by
			`fix_nated_contact("...", "preserve-uri")`.


Returns -1 on error or if "org" does not exist in R-URI. On success,
			returns 1 after removing "org" from R-URI, storing the resulting
			R-URI into D-URI, decoding the original host:port from "org", and
			rewriting R-URI host:port with the decoded value.


This function can be used from REQUEST_ROUTE, BRANCH_ROUTE.


### Exported MI Functions


#### nathelper:enable_ping


Replaces obsolete MI command: *nh_enable_ping*.


Gets or sets the natpinging status.


Parameters:


- *status* (optional) - if not provided the function
					returns the current natping status. Otherwise, enables natping if
					parameter value greater than 0 or disables natping if parameter value is 0.


```c title="nathelper:enable_ping usage"
...
$ opensips-cli -x mi nathelper:enable_ping
Status:: 1
$
$ opensips-cli -x mi nathelper:enable_ping 0
$
$ opensips-cli -x mi nathelper:enable_ping
Status:: 0
$
...
			
```


## Frequently Asked Questions


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


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
