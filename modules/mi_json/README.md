---
title: "mi_json Module"
description: "This module implements a JSON server that handles GET requests and generates JSON responses."
---

## Admin Guide


### Overview


This module implements a JSON server that handles GET
		requests and generates JSON responses.


### Dependencies


#### External Libraries or Applications


None


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### mi_json_root(string)


Specifies the root path for JSON requests:
		http://[opensips_IP]:[opensips_httpd_port]/[mi_json_root]


*The default value is "json".*


```opensips title="Set mi_json_root parameter"
...
modparam("mi_json", "mi_json_root", "opensips_mi_json")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Commands with large responses (like ul_dump) will fail if the
		configured size of the httpd buffer is to small (or if there
		isn't enough pkg memory configured).


Future realeases of the httpd and mi_json modules
		will address this issue.


### Examples


This is an example showing the JSON format for the
		"get_statistics net: uri:" MI command.
		Notice how the paramaters are comma-separated then URI-encoded.


```c title="JSON request"
GET /json/get_statistics?params=net%3A%2Curi%3A HTTP/1.1
Accept: application/json
Host: example.net

HTTP/1.1 200 OK
Content-Length: 49
Content-Type: application/json
Date: Fri, 01 Nov 2013 12:00:00 GMT

["net:waiting_udp = 0", "net:waiting_tcp = 0", "uri:positive checks = 0", "uri:negative_checks = 0"]
```


Here is another example showing the JSON format for the
		"ps" MI command.


```c title="JSON request"
GET /json/ps HTTP/1.1
Accept: application/json
Host: example.net

HTTP/1.1 200 OK
Content-Length: 428
Content-Type: application/json
Date: Fri, 01 Nov 2013 12:00:00 GMT

[{"name":"Process", "value":null, "attributes":{"ID": "0", "PID": "7400", "Type": "stand-alone SIP receiver udp:127.0.0.1:5060"}}, {"name":"Process", "value":null, "attributes":{"ID": "1", "PID": "7402", "Type": "HTTPD INADDR_ANY:8888"}}, {"name":"Process", "value":null, "attributes":{"ID": "2", "PID": "7403", "Type": "time_keeper"}}, {"name":"Process", "value":null, "attributes":{"ID": "3", "PID": "7404", "Type": "timer"}}]
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
