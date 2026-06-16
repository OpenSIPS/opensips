---
title: "xmpp Module"
description: "This modules is a gateway between OpenSIPS and a jabber server. It enables the exchange of instant messages between SIP clients and XMPP(jabber) clients."
---

## Admin Guide


### Overview


This modules is a gateway between OpenSIPS and a jabber server. It enables the exchange of instant messages between
		SIP clients and XMPP(jabber) clients.


The gateway has two modes to run:


- **the component-mode** - the gateway requires a standalone XMPP server amd the 'xmpp' module acts as
			a XMPP component
- **the server-mode** - the module acts itself as a XMPP server, no requirement for another XMPP server in the system. NOTE: this is limited implementation of a XMPP server, it does not support SRV or TLS so far. This mode is in beta stage for the moment.


In the component mode, you need a local XMPP server (recommended jabberd2 or ejabberd); the xmpp module will relay all your connections to a tcp connection to the local jabber server.


After you have a running XMPP server, what you need to do is set the following parameters in the OpenSIPS configuration file:


- xmpp_domain and xmpp_host, which are explained in the
				[exported parameters](#exported_parameters) section;
- socket= your ip;
- alias=opensips domain and 
	alias=gateway domain;
- you can also change the jabber server password, which must be the same as the xmpp_password parameter.


A use case, for the component-mode, would look like this:


- OpenSIPS is running on sip-server.opensips.org;
- the jabber server is running on xmpp.opensips.org;
- the component is running on xmpp-sip.opensips.org.


In the server mode, the xmpp module is a minimal jabber server, thus you do not need to install another jabber server, the gateway will connect to the jabber servers, where the users you want to chat with have an account.


If you want to change to server-mode, you have to change the
	"backend" parameter, as shown in the
	[exported parameters](#exported_parameters) section, from component to server.


A use case, for the server-mode, would look like this:


- OpenSIPS is running on sip-server.opensips.org;
- the "XMPP server" is running on xmpp-sip.opensips.org.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *requires 'tm' module*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libexpat1-devel* - used for parsing/building XML.


### Exported Parameters


#### backend (string)


The mode you are using the module; it can be either component or server.


*Default value is "component".*


```c title="Set backend parameter"
...
 modparam("xmpp", "backend", "server")
...
```


#### xmpp_domain (string)


The xmpp domain of the component or the server, depending on the mode we are in.


*Default value is "127.0.0.1".*


```c title="Set xmpp_domain parameter"
...
 modparam("xmpp", "xmpp_domain", "xmpp.opensips.org")
...
```


#### xmpp_host (string)


The ip address or the name of the local jabber server, if the backend is set to "component"; or the address to bind to in the server mode.


*Default value is "127.0.0.1".*


```c title="Set xmpp_host parameter"
...
 modparam("xmpp", "xmpp_host", "xmpp.opensips.org")
...
```


#### sip_domain (string)


This parameter must be set only if the xmpp module is used in component mode and the domain
		that is the host for the jabber server is the same as the domain of the sip server(when using
		the same domain name for the SIP service and for the XMPP service). In this case,
		if we were to add buddies in xmpp accounts with that domain, then all the messages that will
		reach the jabber server will be considered to be for local xmpp users. It is necessary therefore
		to make a translate the sip domain name into another domain when sending messages in xmpp.
		This parameter is exactly the name that should be used as the SIP domain name in XMPP.
		Usage example: If the sip and xmpp domain is opensips.org and this parameter is set to sip.opensips.org,
		than in all the requests sent in xmpp the sip users will have the domain translated to sip.opensips.org.
		Also, in XMPP account the SIP buddies must have this domain: sip.opensips.org, and it will be
		translated to the real one opensips.org when traversing the gateway.


*Default value is NULL.*


```c title="Set xmpp_host parameter"
...
 modparam("xmpp", "sip_domain", "sip.opensips.org")
...
```


#### xmpp_port (integer)


In the component mode, this is the port of the jabber router we connect to. In the server mode, it is the transport address to bind to.


*Default value is "5347", if backend is set to "component" and "5269", if backend is set to "server".*


```c title="Set xmpp_port parameter"
...
 modparam("xmpp", "xmpp_port", 5269)
...
```


#### xmpp_password (string)


The password of the local jabber server.


*Default value is "secret"; if changed here, it must also be changed in the c2s.xml, added by the jabber server. This is how the default configuration for the jabberd2 looks like:*


```c
			<router>
	............... 
	;
    <pass>secret</pass>;           ;	
			
```


```c title="Set xmpp_password parameter"
...
 modparam("xmpp", "xmpp_password", "secret")
...
```


#### outbound_proxy (string)


The SIP address used as next hop when sending the message. Very
		useful when using OpenSIPS with a domain name not in DNS, or
		when using a separate OpenSIPS instance for xmpp processing. If
		not set, the message will be sent to the address in destination
		URI.


*Default value is NULL.*


```c title="Set outbound_proxy parameter"
...
 modparam("xmpp", "outbound_proxy", "sip:opensips.org;transport=tcp")
...
```


### Exported Functions


#### xmpp_send_message()


Converts SIP messages to XMPP(jabber) messages, in order to be relayed to a XMPP(jabber) client.


```c title="xmpp_send_message() usage"
...
xmpp_send_message();
...
```


### Configuration


Next is presented a sample configuration file one can use to implement a
		standalone SIP-to-XMPP gateway. You can run an instance of OpenSIPS on a
		separate machine or on different port with the following config, and have
		the main SIP server configured to forward all SIP requests for XMPP world
		to it.


[samples](./samples.md "include")
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
