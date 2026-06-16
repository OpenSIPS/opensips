---
title: "httpd Module"
description: "This module provides an HTTP transport layer for OpenSIPS."
---

## Admin Guide


### Overview


This module provides an HTTP transport layer for OpenSIPS.


Implementation of httpd module's http server is based on
		libmicrohttpd library.


### Overview


TLS for the http server is enabled by setting  the `tls_cert_file`
			and `tls_key_file` parameters. If this is enabled, support for plain
			http is disabled.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *libmicrohttpd*, with EPOLL support. This
					typically means a version newer than **0.9.50**.


**WARNING!**  Please be aware about an
			EPOLL support regression in the *libmicrohttpd*
			library and packaging which affects the OpenSIPS httpd module, which
			was fixed according to the below timeline.  The effect of the
			regression is that the HTTP reply body is *sometimes*
			never written by the library, causing the client (e.g. opensips-cli)
			to hang indefinitely waiting for it:


- versions **0.9.51** - **0.9.52**
				have been tested and work correctly
- regression introduced in **0.9.53** (Apr 2017),
				lasting until **0.9.71** (May 2020)
- regression is fixed since **0.9.72** (Dec 2020)


### Exported Parameters


#### ip(string)


The IP address used by the HTTP server to listen for incoming 
		requests.


*The default value is "127.0.0.1"* (binds to loopback only).
		Use "*" to bind to all IPv6 and IPv4 interfaces.


```c title="Set ip parameter"
...
modparam("httpd", "ip", "127.0.0.1")
...
```


#### port(integer)


The port number used by the HTTP server to listen for incoming 
		requests.


*The default value is 8888.*
		Ports lower than 1024 are not accepted.


```c title="Set port parameter"
...
modparam("httpd", "port", 8000)
...
```


#### conn_timeout(integer)


Auto-close TCP connections which are idle for more than the designated
		timeout, in seconds.  Set to zero to never close any connections.


Note: the connection auto-close routine only seems to be executed
		in an "on-demand" fashion, during an HTTPD network event (e.g. on a new
		connection), which although not ideal, it should be good enough in
		practical terms.


*The default timeout is 30 seconds.*


```c title="Set conn_timeout parameter"
...
modparam("httpd", "conn_timeout", 10)
...
```


#### buf_size (integer)


It specifies the maximum length (in bytes) of the buffer
		used to write in the html response.


If the size of the buffer is set to zero, it will be automatically
		set to a quarter of the size of the pkg memory.


*The default value is 0.*


```c title="Set buf_size parameter"
...
modparam("httpd", "buf_size", 524288)
...
```


#### post_buf_size (integer)


It specifies the length (in bytes) of the POST HTTP requests
		processing buffer.  For large POST request, the default value
		might require to be increased.


*The default value is 1024. The minumal value is 256.*


```c title="Set post_buf_size parameter"
...
modparam("httpd", "post_buf_size", 4096)
...
```


#### receive_buf_size (integer)


It specifies the maximum length (in bytes) of the received HTTP requests.  
		For receiving large POST request, the default value might require to be increased.


*The default value is 1024.*


```c title="Set receive_buf_size parameter"
...
modparam("httpd", "receive_buf_size", 4096)
...
```


#### tls_cert_file (string)


Public certificate file for httpd. It will be used as server-side certificate for incoming TLS connections.


*The default value is ""*


```c title="Set tls_cert_file parameter"
...
modparam("httpd", "tls_cert_file", "/etc/opensips/tls/server.pem")
...
```


#### tls_key_file (string)


Private key of the above certificate. I must be kept in a safe place with tight permissions!


*The default value is ""*


```c title="Set tls_key_file parameter"
...
modparam("httpd", "tls_key_file", "/etc/opensips/tls/server.key")
...
```


#### tls_ciphers (string)


You can specify the list of algorithms for authentication and encryption that you allow.
		To obtain a list of ciphers
		and then choose, use the gnutls-cli application:


- gnutls-cli -l


> [!WARNING]
> Do not use the NULL algorithms (no encryption) ... never!!!


*The default value is  "SECURE256:+SECURE192:-VERS-ALL:+VERS-TLS1.2"*


```c title="Set tls_key_file parameter"
...
modparam("httpd", "tls_ciphers", "SECURE256:+SECURE192:-VERS-ALL:+VERS-TLS1.2")
...
```


#### auth_realm (string)


The realm string to be used for HTTP Basic Authentication
		challenges.  Only takes effect when both
		`auth_username` and
		`auth_password` are set.


*The default value is "OpenSIPS MI".*


```c title="Set auth_realm parameter"
...
modparam("httpd", "auth_realm", "OpenSIPS Management")
...
```


#### auth_username (string)


The username for HTTP Basic Authentication.  When set together
		with `auth_password`, all HTTP requests must
		present valid credentials.  Requests without credentials or
		with incorrect credentials receive a 401 Unauthorized response.


*The default value is "" (authentication disabled).*


```c title="Set auth_username parameter"
...
modparam("httpd", "auth_username", "admin")
...
```


#### auth_password (string)


The password for HTTP Basic Authentication.  Must be set
		together with `auth_username`.


> [!WARNING]
> When using HTTP Basic Authentication, it is strongly
		recommended to also enable TLS via
		`tls_cert_file` and
		`tls_key_file` to prevent credentials
		from being transmitted in plaintext.


*The default value is "" (authentication disabled).*


```c title="Set auth_password parameter"
...
modparam("httpd", "auth_password", "secretpass")
...
```


### Exported MI Functions


#### httpd:list_root_path


Replaces obsolete MI command: *httpd_list_root_path*.


Lists all the registered http root paths into the httpd module.
		When a request comes in, if the root parth is in the list,
		the request will be sent to the module that register it.


Name: *httpd:list_root_path*


Parameters: none


MI FIFO Command Format:


```c
opensips-cli -x mi httpd:list_root_path
		
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
