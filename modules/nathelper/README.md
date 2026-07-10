---
title: "nathelper Module"
description: "This is a module to help with NAT traversal."
---

## Admin Guide


### Overview


This is a module to help with NAT traversal. In particular, 
it helps symmetric UAs that don't advertise they are symmetric 
and are not able to determine their public address. fix_nated_contact 
rewrites Contact header field with request's source address:port pair. 
fix_nated_sdp adds the active direction indication to SDP (flag
0x01) and updates source IP address too (flag 0x02).


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
  - *Disadvantages:* higher bandwitdh 
traffic, more expensive (as time) to generate by OpenSIPS;


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *usrloc* module - only if the NATed 
contacts are to be pinged.


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


```opensips title="Set natping_interval parameter"
...
modparam("nathelper", "natping_interval", 10)
...
```


#### ping_nated_only (integer)


If this variable is set then only contacts that have 
"behind_NAT" flag in user location database set will 
get ping.


*Default value is 0.*


```opensips title="Set ping_nated_only parameter"
...
modparam("nathelper", "ping_nated_only", 1)
...
```


#### natping_processes (integer)


How many timer processes should be created by the module for the
exclusive task of sending the NAT pings.


*Default value is 1.*


```opensips title="Set natping_processes parameter"
...
modparam("nathelper", "natping_processes", 3)
...
```


#### natping_socket (string)


Spoof the natping's source-ip to this address. Works only for IPv4.


*Default value is NULL.*


```opensips title="Set natping_socket parameter"
...
modparam("nathelper", "natping_socket", "192.168.1.1:5006")
...
```


#### received_avp (str)


The name of the Attribute-Value-Pair (AVP) used to store the URI 
containing the received IP, port, and protocol. The URI is created 
by fix_nated_register function of nathelper module and the attribute 
is then used by the registrar to store the received parameters. Do 
not forget to change the value of corresponding parameter in
registrar module if you change the value of this parameter.


> [!NOTE]
> You must set this parameter if you use "fix_nated_register". In such
case you must set the parameter with same name of "registrar"
module to same value.


*Default value is "NULL" (disabled).*


```opensips title="Set received_avp parameter"
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


```opensips title="Set force_socket parameter"
...
modparam("nathelper", "force_socket", "localhost:33333")
...
```


#### sipping_bflag (string/integer)


What branch flag should be used by the module to identify NATed 
contacts for which it should perform NAT ping via a SIP request 
instead if dummy UDP package.


*WARNING:*Setting INT flags is deprecated!
Use quoted strings instead!


*Default value is "NULL" (disabled).*


```opensips title="Set sipping_bflag parameter"
...
modparam("nathelper", "sipping_bflag", "SIP_PING_FLAG")
...
```


#### sipping_from (string)


The parameter sets the SIP URI to be used in generating the SIP
requests for NAT ping purposes. To enable the SIP request pinging
feature, you have to set this parameter. The SIP request pinging 
will be used only for requests marked so.


*Default value is "NULL".*


```opensips title="Set sipping_from parameter"
...
modparam("nathelper", "sipping_from", "sip:pinger@siphub.net")
...
```


#### sipping_method (string)


The parameter sets the SIP method to be used in generating the SIP
requests for NAT ping purposes.


*Default value is "OPTIONS".*


```opensips title="Set sipping_method parameter"
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


```opensips title="Set nortpproxy_str parameter"
...
modparam("nathelper", "nortpproxy_str", "a=sdpmangled:yes\r\n")
...
```


#### natping_tcp (integer)


If the flag is set, TCP/TLS clients will also be pinged with
SIP OPTIONS messages.


*Default value is 0 (not set).*


```opensips title="Set natping_interval parameter"
...
modparam("nathelper", "natping_tcp", 1)
...
```


### Exported Functions


#### fix_nated_contact([uri_params])


Rewrites the URI Contact HF to contain request's 
source address:port. If a list of URI parameter is provided, it will
be added to the modified contact;


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE.


```opensips title="fix_nated_contact usage"
...
if (search("User-Agent: Cisco ATA.*") {
    fix_nated_contact(";ata=cisco");
} else {
    fix_nated_contact();
}
...
```


#### fix_nated_sdp(flags [, ip_address])


Alters the SDP information in orer to facilitate NAT traversal. What
changes to be performed may be controled via the 
"flags" paramter.


Meaning of the parameters is as follows:


- *flags* - the value may be a bitwise OR of 
the following flags:

  - *0x01* - adds 
"a=direction:active" SDP line;
  - *0x02* - rewrite media
IP address (c=) with source address of the message
or the provided IP address (the provide IP address take
precedence over the source address).
  - *0x04* - adds 
"a=nortpproxy:yes" SDP line;
  - *0x08* - rewrite IP from
origin description (o=) with source address of the message
or the provided IP address (the provide IP address take
precedence over the source address).
- *ip_address* - IP to be used for rewriting SDP.
If not specified, the received signalling IP will be used. The
parameter allows pseudo-variables usage. NOTE: For the IP to be
used, you need to use 0x02 or 0x08 flags, otherwise it will have
no effect.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, 
FAILURE_ROUTE, BRANCH_ROUTE.


```opensips title="fix_nated_sdp usage"
...
if (search("User-Agent: Cisco ATA.*") {fix_nated_sdp("3");};
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


- *flag* - flags to indicate if the parameter
should be added to Contact URI or Contact header. If the flag is
non-zero, the parameter will be added to the Contact URI. If not
used or equal to zero, the parameter will go to the Contact 
header.


This function can be used from REQUEST_ROUTE.


```opensips title="add_rcv_paramer usage"
...
add_rcv_param(); # add the parameter to the Contact header
....
add_rcv_param("1"); # add the paramter to the Contact URI
...
```


#### fix_nated_register()


The function creates a URI consisting of the source IP, port, and 
protocol and stores the URI in an Attribute-Value-Pair. The URI will 
be appended as "received" parameter to Contact in 200 OK and 
registrar will store it in the user location database.


This function can be used from REQUEST_ROUTE.


```opensips title="fix_nated_register usage"
...
fix_nated_register();
...
```


#### nat_uac_test(flags)


Tries to guess if client's request originated behind a nat.
The parameter determines what heuristics is used.


Meaning of the flags is as follows:


- *1* -  Contact header field is searched 
for occurrence of RFC1918 / RFC6598 addresses.
- *2* -  the "received" test is used: address
in Via is compared against source IP address of signaling
- *4* -  Top Most VIA is searched 
for occurrence of RFC1918 / RFC6598 addresses
- *8* -  SDP is searched for occurrence of 
RFC1918 / RFC6598 addresses
- *16* -  test if the source port is different
from the port in Via
- *32* -  address in Contact is compared against 
source IP address of signaling
- *64* -  Port in Contact is compared against
source port of signaling


All flags can be bitwise combined, the test returns true if any of 
the tests identified a NAT.


This function can be used from REQUEST_ROUTE, ONREPLY_ROUTE, FAILURE_ROUTE, BRANCH_ROUTE.


### Exported MI Functions


#### nh_enable_ping


Enables natping if parameter value greater than 0.
Disables natping if parameter value is 0.
With no parameter, it returns the current natping status.


The function may takean optional parameter (for set operations) -
a number in decimal format.


```bash title="nh_enable_ping usage"
...
$ opensipsctl fifo nh_enable_ping
Status:: 1
$
$ opensipsctl fifo nh_enable_ping 0
$
$ opensipsctl fifo nh_enable_ping
Status:: 0
$
...
			
```


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
