---
title: "rest_client Module"
description: "The *rest_client* module provides a means of interacting with an HTTP server by doing RESTful queries, such as GET and POST."
---

## Admin Guide


### Overview


The *rest_client* module provides a means of interacting
	with an HTTP server by doing RESTful queries, such as GET and POST.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules.*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *libcurl*.


### Exported Parameters


#### connection_timeout (integer)


Maximum time allowed to establish a connection with the server.


*Default value is "20" seconds.*


```opensips title="Setting the connection_timeout parameter"
...
modparam("rest_client", "connection_timeout", 300)
...
```


#### curl_timeout (integer)


Maximum time allowed for the libcurl transfer to complete.


*Default value is "20" seconds.*


```opensips title="Setting the curl_timeout parameter"
...
modparam("rest_client", "curl_timeout", 300)
...
```


### Exported Functions


#### rest_get(url, body_pv[, ctype_pv[, retcode_pv]])


Issues an HTTP GET request to the given 'url', and returns a representation
		of the resource.


The *body_pv* avp will hold the body of the HTTP
		response.


The optional *ctype_pv* avp will contain the value
		of the "Content-Type:" header.


The optional *retcode_pv* avp is used to retain the
		HTTP status code of the response message.


Possible parameter types


- *url* - String, pseudo-variable, or a String
				which includes pseudo-variables. (useful for specifying additional
				attribute-value fields in the URL)
- *body_pv, ctype_pv, retcode_pv* -
			pseudo-variables


This function can be used from the *startup, branch, failure,
				request* and *timer* routes.


```opensips title="rest_get usage"
...
# Example of querying a REST service to get the credit of an account

if (!rest_get("http://getcredit.org/?ruri=$fU", "$avp(credit)", "$avp(ct)", "$avp(rcode)")) {
	xlog("Error code $avp(rcode) in HTTP GET!\n");
	send_reply("403", "Not registered");
	exit;
}
...
```


#### rest_post(url, send_body_pv, send_ctype_pv, recv_body_pv[, recv_ctype_pv[, retcode_pv]])


Issues an HTTP POST request to the specified 'url'. The request body will
		be copied from the 'send_body_pv' pseudo-variable. Its MIME content type
		will be taken from 'send_ctype_pv'.


The *recv_body_pv* avp will hold the body of the HTTP
		response.


The optional *recv_ctype_pv* parameter will contain
		the value of the "Content-Type:" header of the response message.


The optional *retcode_pv* avp parameter can be given
		in order to save the HTTP status code of the response message.


Possible parameter types


- *url, send_body_pv, send_type_pv* -
			String, pseudo-variable, or a String which includes pseudo-variables.
- *recv_body_pv, recv_ctype_pv, retcode_pv* -
			pseudo-variables


This function can be used from the *startup, branch, failure,
				request* and *timer* routes.


```opensips title="rest_post usage"
...
# Storing data using a RESTful service with an HTTP POST request

if (!rest_post("http://myserver.org/register_user", "$fU", "text/plain", "$avp(body)", "$avp(ct)", "$avp(rcode)")) {
	xlog("Error code $avp(rcode) in HTTP POST!\n");
	send_reply("403", "POST Forbidden");
	exit;
}
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
