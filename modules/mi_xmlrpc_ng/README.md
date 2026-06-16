---
title: "mi_xmlrpc_ng Module"
description: "This module implements a xmlrpc server that handles xmlrpc requests and generates xmlrpc responses. When a xmlrpc message is received a default method is executed."
---

## Admin Guide


### Overview


This module implements a xmlrpc server that handles xmlrpc
		requests and generates xmlrpc responses.
		When a xmlrpc message is received a default method is executed.


At first, it looks up the MI command.
		If found it parses the called procedure's parameters
		into a MI tree and the command is executed.
		A MI reply tree is returned that is formatted back in xmlrpc.
		The response is built in two ways - like a string that
		contains the MI tree nodes information (name, values and
		attributes) or like an array whose elements are consisted
		of each MI tree node stored information.


### Dependencies


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *libxml2*


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### mi_xmlrpc_ng_root(string)


Specifies the root path for xmlrpc requests:
		http://[opensips_IP]:[opensips_httpd_port]/[mi_xmlrpc_ng_root]


*The default value is "xmlrpc".*


```c title="Set mi_xmlrpc_ng_root parameter"
...
modparam("mi_xmlrpc_ng", "mi_xmlrpc_ng_root", "opensips_mi_xmlrpc")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Commands with large responses (like ul_dump) will fail if the
		configured size of the httpd buffer is to small (or if there
		isn't enough pkg memory configured).


Future realeases of the httpd and mi_xmlrpc_ng modules
		will address this issue.


### Example


This is an example showing the xmlrpc format for the
		"get_statistics net: uri:" MI commad:
		response.


```c title="XMLRPC request"
POST /xmlrpc HTTP/1.0
Host: my.host.com
User-Agent: My xmlrpc UA
Content-Type: text/xml
Content-Length: 216

<?xml version='1.0'?>
<methodCall>
	<methodName>get_statistics</methodName>
	<params>
		<param>
			<value><string>net:</string></value>
		</param>
		<param>
			<value><string>uri:</string></value>
		</param>
	</params>
</methodCall>


HTTP/1.0 200 OK
Content-Length: 236
Content-Type: text/xml; charset=utf-8
Date: Mon, 8 Mar 2013 12:00:00 GMT

<?xml version="1.0" encoding="UTF-8"?><methodResponse><params><param><value><string>
:: net:waiting_udp = 0
:: net:waiting_tcp = 0
:: uri:positive checks = 0
:: uri:negative_checks = 0
</string></value></param></params></methodResponse>
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
