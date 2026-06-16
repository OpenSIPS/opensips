---
title: "mi_http Module"
description: "This module provides an HTTP transport layer implementation for OpenSIPS's Management Interface."
---

## Admin Guide


### Overview


This module provides an HTTP transport layer implementation
		for OpenSIPS's Management Interface.


### To-do


Features to be added in the future:


- possibility to authenticate connections.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *httpd* module.


### Exported Parameters


#### mi_http_root(string)


It specifies the root path for mi http requests.
		The link to the mi web interface must be constructed
		using the following patern:
		http://[opensips_IP]:[opensips_mi_port]/[mi_http_root]


*The default value is "mi".*


```c title="Set mi_http_root parameter"
...
modparam("mi_http", "mi_http_root", "opensips_mi")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Commands with large responses (like ul_dump) will fail if the
		configured size of the httpd buffer is to small (or if there isn't
		enough pkg memory configured).


Future realeases of the httpd and mi_httpd modules will address this issue.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
