---
title: "Options Module"
description: "This module provides a function to answer OPTIONS requests which are directed to the server itself. This means an OPTIONS request which has the address of the server in the request URI, and no username in the URI. The request will be answered with a 200 OK which the capabilities of th..."
---

## Admin Guide


### Overview


This module provides a function to answer OPTIONS requests which 
		are directed to the server itself. This means an OPTIONS request 
		which has the address of the server in the request URI, and no 
		username in the URI. The request will be answered with a 200 OK 
		which the capabilities of the server.


To answer OPTIONS request directed to your server is the easiest
		way for is-alive-tests on the SIP (application) layer from remote 
		(similar to	ICMP echo requests, also known as "ping", 
		on the network layer).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *sl* -- Stateless replies.
- *signaling* -- Stateless replies.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### accept (string)


This parameter is the content of the Accept header field. If
			"", the header is not added in the reply.
			Note: it is not clearly written in RFC3261 if a proxy should
			accept any content (the default "*/*") because 
			it does not care about content. Or if it does not accept 
			any content, which is "".


*Default value is "*/*".*


```opensips title="Set accept parameter"
...
modparam("options", "accept", "application/*")
...
```


#### accept_encoding (string)


This parameter is the content of the Accept-Encoding header field.
			If "", the header is not added in the reply.
			Please do not change the default value because OpenSIPS 
			does not support any encodings yet.


*Default value is "".*


```opensips title="Set accept_encoding parameter"
...
modparam("options", "accept_encoding", "gzip")
...
```


#### accept_language (string)


This parameter is the content of the Accept-Language header field.
			If "", the header is not added in the reply.
			You can set any language code which you prefer for error 
			descriptions from other devices, but presumably there are not
			much devices around which support other languages then the 
			default English.


*Default value is "en".*


```opensips title="Set accept_language parameter"
...
modparam("options", "accept_language", "de")
...
```


#### support (string)


This parameter is the content of the Support header field.
			If "", the header is not added in the reply.
			Please do not change the default value, because OpenSIPS currently 
			does not support any of the SIP extensions registered at the IANA.


*Default value is "".*


```opensips title="Set support parameter"
...
modparam("options", "support", "100rel")
...
```


### Exported Functions


#### options_reply()


This function checks if the request method is OPTIONS and
			if the request URI does not contain an username. If both
			is true the request will be answered stateless with 
			"200 OK" and the capabilities from the modules
			parameters.


It sends "500 Server Internal Error" for some errors
			and returns false if it is called for a wrong request.


The check for the request method and the missing username is
			optional because it is also done by the function itself. But
			you should not call this function outside the myself check
			because in this case the function could answer OPTIONS requests
			which are sent to you as outbound proxy but with an other
			destination then your proxy (this check is currently missing
			in the function).


This function can be used from REQUEST_ROUTE.


```opensips title="options_reply usage"
...
if (is_myself("$rd")) {
	if (is_method("OPTIONS") && (! $ru=~"sip:.*[@]+.*")) {
		options_reply();
	}
}
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
