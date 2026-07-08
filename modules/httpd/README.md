---
title: "httpd Module"
description: "This module provides an HTTP transport layer for OpenSIPS."
---

## Admin Guide


### Overview


This module provides an HTTP transport layer for OpenSIPS.


Implementation of httpd module's http server is based on 
		libmicrohttpd library.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *libmicrohttpd*.


### Exported Parameters


#### ip(string)


The IP address used by the HTTP server to listen for incoming 
		requests.


*The default value is an empty string.*
		If no IP address is set, then the http server
		will bind to all available IPs.


```opensips title="Set ip parameter"
...
modparam("httpd", "ip", "127.0.0.1")
...
```


#### port(integer)


The port number used by the HTTP server to listen for incoming 
		requests.


*The default value is 8888.*
		Ports lower than 1024 are not accepted.


```opensips title="Set port parameter"
...
modparam("httpd", "port", 8000)
...
```


#### buf_size (integer)


It specifies the maximum length (in bytes) of the buffer
		used to write in the html response.


If the size of the buffer is set to zero, it will be automatically
		set to a quarter of the size of the pkg memory.


*The default value is 0.*


```opensips title="Set buf_size parameter"
...
modparam("httpd", "buf_size", 524288)
...
```


#### post_buf_size (integer)


It specifies the length (in bytes) of the POST HTTP requests
		processing buffer.  For large POST request, the default value
		might require to be increased.


*The default value is 1024. The minumal value is 256.*


```opensips title="Set post_buf_size parameter"
...
modparam("httpd", "post_buf_size", 4096)
...
```


### Exported MI Functions


#### httpd_list_root_path


Lists all the registered http root paths into the httpd module.
		When a request comes in, if the root parth is in the list,
		the request will be sent to the module that register it.


Name: *httpd_list_root_path*


Parameters: none


MI FIFO Command Format:


```bash
opensips-cli -x mi httpd_list_root_path
		
```


### Exported Functions


No function exported to be used from configuration file.


### Known Issues


Due to the fact that OpenSIPS is a multiprocess application,
		the microhttpd library is used in "external select" mode.
		This ensures that the library is not running in
		multithread mode and the library is entirely controled
		by OpenSIPS.  Due to this particular mode of operations,
		for now, the entire http response is built in a pre-allocated
		buffer (see buf_size parameter).


Future realeases of this module will address this issue.


Running the http daemon as non root on ports below 1024 is
		forbidden by default in linux (kernel>=2.6.24).
		To allow the port binding, one can use
		*setcap* to give
		extra privilleges to opensips binary:


```c
setcap 'cap_net_bind_service=+ep' /usr/local/sbin/opensips
		
```


## Developer Guide


### Available Functions


#### register_httpdcb (module, root_path, httpd_acces_handler_cb, httpd_flush_data_cb, httpd_init_proc_cb)


Register a new http root with it's associated callbacks into the httpd module.


Meaning of the parameters is as follows:


- *const char *mod*
			- name of the module that register an http root path to be handled;
- *str *root_path*
			- the registered root path;
- *httpd_acces_handler_cb f1*
			- handler to the callback method to be called on root path match;
- *httpd_flush_data_cb f2*
			- handler to the callback method to be called for sending extra data (at a later time);
- *httpd_init_proc_cb f3*
			- handler to the callback method to be called during httpd process init;
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
