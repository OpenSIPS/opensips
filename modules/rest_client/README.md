---
title: "rest_client Module"
description: "The *rest_client* module provides a means of interacting with an HTTP server by doing RESTful queries, such as GET, POST and PUT."
---

## Admin Guide


### Overview


The *rest_client* module provides a means of interacting
	with an HTTP server by doing RESTful queries, such as GET, POST and PUT.


### TCP Connection Reusage


Unless specified otherwise by the server through a "Connection: close"
	indication, the module will keep and reuse the TCP connections it creates
	as much as possible, regardless if the script writer performs blocking or
	asynchronous HTTP requests.  These connections are not shared among OpenSIPS
	workers — each worker maintains its own set of connections.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules.*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *libcurl*.


### Exported Parameters


#### curl_timeout (integer)


The maximum allowed time for any HTTP(S) transfer to complete.  This
		interval is inclusive of the initial connect time window, hence the value
		of this parameter must be greater than or equal to
		[connection timeout](#param_connection_timeout).


*Default value is "20" seconds.*


```opensips title="Setting the curl_timeout parameter"
...
modparam("rest_client", "curl_timeout", 10)
...
```


#### connection_timeout (integer)


The maximum allowed time to establish a connection with the server.


*Default value is "20" seconds.*


```opensips title="Setting the connection_timeout parameter"
...
modparam("rest_client", "connection_timeout", 4)
...
```


#### connect_poll_interval (integer)


Only relevant with async requests.  Allows complete control over how
		quickly we want to detect libcurl's completed blocking TCP/TLS handshakes,
		so the async transfers can be put in the background.  A lower
		[connect poll interval](#param_connect_poll_interval) may speed up all async
		HTTP transfers, but will also increase CPU usage.


*Default value is "20" milliseconds.*


```opensips title="Setting the connect_poll_interval parameter"
...
modparam("rest_client", "connect_poll_interval", 2)
...
```


#### max_async_transfers (integer)


Maximum number of asynchronous HTTP transfers *a single*
		OpenSIPS worker is allowed to run simultaneously. As long as this threshold
		is reached for a worker, all new async transfers it attempts to perform
		will be done in a blocking manner, with appropriate logging warnings.


*Default value is "100".*


```opensips title="Setting the max_async_transfers parameter"
...
modparam("rest_client", "max_async_transfers", 300)
...
```


#### max_transfer_size (integer)


The maximum allowed size of a single transfer (download).  Reaching
		this limit during a transfer will cause the transfer to stop
		immediately, returning error -10 at script level.  A value of
		**0** will disable the check.


*Default value is "10240" (KB).*


```opensips title="Setting the max_transfer_size parameter"
...
modparam("rest_client", "max_transfer_size", 64)
...
```


#### ssl_verifypeer (integer)


Set this to 0 in order to disable the verification of the remote peer's
		certificate. Verification is done using a default bundle of CA certificates
		which come with libcurl.


*Default value is "1" (enabled).*


```opensips title="Setting the ssl_verifypeer parameter"
...
modparam("rest_client", "ssl_verifypeer", 0)
...
```


#### ssl_verifyhost (integer)


Set this to 0 in order to disable the verification that the remote peer
		actually corresponds to the server listed in the certificate.


*Default value is "1" (enabled).*


```opensips title="Setting the ssl_verifyhost parameter"
...
modparam("rest_client", "ssl_verifyhost", 0)
...
```


#### ssl_capath (integer)


An optional path for CA certificates to be used for host verifications.


```opensips title="Setting the ssl_capath parameter"
...
modparam("rest_client", "ssl_capath", "/home/opensips/ca_certificates")
...
```


#### curl_http_version (integer)


Use a specific HTTP version for all requests. Possible values:


- 0 (default) - use whatever is deemed fit by libcurl
- 1 - enforce HTTP 1.0 requests
- 2 - enforce HTTP 1.1 requests
- 3 - attempt HTTP 2 requests. Fall back to HTTP 1.1 if HTTP 2
				cannot be negotiated with the server. Requires libcurl 7.33.0+.
- 4 - attempt HTTP 2 over TLS (HTTPS) only. Fall back to HTTP
				1.1 if HTTP 2 cannot be negotiated with the HTTPS server.
				For clear text HTTP servers, use HTTP 1.1.
				Requires libcurl 7.47.0+.
- 5 - Issue non-TLS HTTP requests using HTTP 2 without HTTP 1.1
				Upgrade. It requires prior knowledge that the server supports
				HTTP 2 straight away. HTTPS requests will still do HTTP/2 the
				standard way with negotiated protocol version in the TLS
				handshake. Requires libcurl 7.49.0+.


*more details [here](https://curl.haxx.se/libcurl/c/CURLOPT_HTTP_VERSION.html), where the documentation for
			this setting was inspired (read: pilfered) from*


```opensips title="Setting the curl_http_version parameter"
...
modparam("rest_client", "curl_http_version", 3)
...
```


#### enable_expect_100 (boolean)


Include a "Expect: 100-continue" HTTP header field whenever the body
		size of a POST or PUT request exceeds 1024 bytes.  Once enabled, the
		timeout for waiting for a "100 Continue" reply from the server is 1
		second, after which the body upload will begin.


*Default value is "false" (disabled).*


```opensips title="Setting the enable_expect_100 parameter"
...
modparam("rest_client", "enable_expect_100", true)
...
```


#### no_concurrent_connects (boolean)


Set to *true* in order to only allow one OpenSIPS
		worker to connect to a given URL hostname at a time.  While a worker
		is connecting, all other workers will receive error code
		**-4 (already connecting)** when attempting
		to perform any rest_client operation to the same hostname, regardless if
		the operation is sync or async.


For sync transfers, the scope of the worker process serialization
		extends to the entire cURL transfer (TCP connect + upload + download),
		as all three phases take place within a single cURL library call.


This parameter may be useful in order to prevent system outages caused
		by concurrent blocking of all OpenSIPS workers on a failed (hanging)
		HTTP service, with no more free workers being left to process incoming
		SIP packets.


*Default value is "false" (disabled).*


```opensips title="Setting the no_concurrent_connects parameter"
...
modparam("rest_client", "no_concurrent_connects", true)
...
```


#### curl_conn_lifetime (integer)


Only relevant when [no concurrent connects](#param_no_concurrent_connects) is enabled.
		By setting this parameter, script developers can leverage the connection
		reusage capabilities of libcURL and entirely skip the "no concurrent transfers"
		logic on a given SIP worker, should that worker already be known to have a TCP
		connection to the target URL hostname
		(established by a previous rest_xxx() function call).


The parameter denotes the lifetime, in seconds, of TCP connections kept
		within libcURL for reusage, a setting which is often operating system
		dependant, and which may also be affected by enabling/disabling keepalives.
		Consult your operating system's and/or libcurl's documentation for further
		information on the max lifetime of your cURL TCP connections.


*Default value is *0* (disabled).*


```opensips title="Setting the curl_conn_lifetime parameter"
...
modparam("rest_client", "curl_conn_lifetime", 1800)
...
```


### Exported Functions


#### rest_get(url, body_pv, [ctype_pv], [retcode_pv])


Perform a blocking HTTP GET on the given *url* and
		return a representation of the resource.


Parameters:


- *url* (string)
- *body_pv* (var) - output variable which will hold the
				body of the HTTP response.
- *ctype_pv* (var, optional) - output variable which will
				contain the value of the "Content-Type:" header of the response.
- *retcode_pv* (var, optional) - output variable which will
				retain the status code of the HTTP response.
				A **0** status code value means no HTTP
				reply arrived at all.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
	(the [connection timeout](#param_connection_timeout) was exceeded
	before a TCP connection could be established)
- **-3** - Transfer Timeout
	(the [curl timeout](#param_curl_timeout) was exceeded before the
	last byte was received). The *retcode_pv* may
	be set to 200 or 0, depending whether a 200 OK was received or not.
	If it was, the *body_pv* will contain partially
	downloaded data, use at your own risk! (we recommend you only use
	this data for logging / debugging purposes)
- **-4** - Already Connecting
	(another OpenSIPS worker is already connecting to this URL hostname.
	Consult [no concurrent connects](#param_no_concurrent_connects) for more info).
- **-10** - Internal Error (out of
		memory, unexpected libcurl error, etc.)


This function can be used from any route.


```opensips title="rest_get usage"
...
# Example of querying a REST service to get the credit of an account
$var(rc) = rest_get("https://getcredit.org/?account=$fU",
                    $var(credit),
                    $var(ct),
                    $var(rcode));
if ($var(rc) < 0) {
	xlog("rest_get() failed with $var(rc), acc=$fU\n");
	send_reply(500, "Server Internal Error");
	exit;
}

if ($var(rcode) != 200) {
	xlog("L_INFO", "rest_get() rcode=$var(rcode), acc=$fU\n");
	send_reply(403, "Forbidden");
	exit;
}
...
```


#### rest_post(url, send_body, [send_ctype], recv_body_pv, [recv_ctype_pv], [retcode_pv])


Perform a blocking HTTP POST on the given *url*.


Note that the *send_body* parameter can also accept a format-string
		but it cannot be larger than 1024 bytes. For larger messages, you must build them in a
		pseudo-variable and pass it to the function.


Parameters:


- *url* (string)
- *send_body* (string) - The request body.
- *send_ctype* (string, optional) - The MIME
				Content-Type header for the request. The default is
				*"application/x-www-form-urlencoded"*
- *recv_body_pv* (var) - output variable which
				will hold the body of the HTTP response.
- *recv_ctype_pv* (var, optional) - output
				variable which will contain the value of the "Content-Type"
				header of the response
- *retcode_pv* (var, optional) - output variable
				which will retain the status code of the HTTP response.
				A **0** status code value means no HTTP
				reply arrived at all.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
	(the [connection timeout](#param_connection_timeout) was exceeded
	before a TCP connection could be established)
- **-3** - Transfer Timeout
	(the [curl timeout](#param_curl_timeout) was exceeded before the
	last byte was received). The *retcode_pv* may
	be set to 200 or 0, depending whether a 200 OK was received or not.
	If it was, the *body_pv* will contain partially
	downloaded data, use at your own risk! (we recommend you only use
	this data for logging / debugging purposes)
- **-4** - Already Connecting
	(another OpenSIPS worker is already connecting to this URL hostname.
	Consult [no concurrent connects](#param_no_concurrent_connects) for more info).
- **-10** - Internal Error (out of
		memory, unexpected libcurl error, etc.)


This function can be used from any route.


```opensips title="rest_post usage"
...
# Creating a resource using a RESTful service with an HTTP POST request
$var(rc) = rest_post("https://myserver.org/register_user",
                     $fU, , $var(body), $var(ct), $var(rcode));
if ($var(rc) < 0) {
	xlog("rest_post() failed with $var(rc), user=$fU\n");
	send_reply(500, "Server Internal Error 1");
	exit;
}

if ($var(rcode) != 200) {
	xlog("rest_post() rcode=$var(rcode), user=$fU\n");
	send_reply(500, "Server Internal Error 2");
	exit;
}
...
```


#### rest_put(url, send_body, [send_ctype], recv_body_pv[, [recv_ctype_pv][, [retcode_pv]]])


Perform a blocking HTTP PUT on the given *url*.


Similar to [rest post](#func_rest_post), the *send_body_pv*
		parameter can also accept a format-string but it cannot be larger than 1024 bytes. For
		larger messages, you must build them in a pseudo-variable and pass it to the function.


Parameters:


- *url* (string)
- *send_body* (string) - The request body.
- *send_ctype* (string, optional) - The MIME
				Content-Type header for the request. The default is
				*"application/x-www-form-urlencoded"*
- *recv_body_pv* (var) - output variable which
				will hold the body of the HTTP response.
- *recv_ctype_pv* (var, optional) - output variable
				which will contain the value of the "Content-Type" header of the response
- *retcode_pv* (var, optional) - output variable
				which will retain the status code of the HTTP response.
				A **0** status code value means no HTTP
				reply arrived at all.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
	(the [connection timeout](#param_connection_timeout) was exceeded
	before a TCP connection could be established)
- **-3** - Transfer Timeout
	(the [curl timeout](#param_curl_timeout) was exceeded before the
	last byte was received). The *retcode_pv* may
	be set to 200 or 0, depending whether a 200 OK was received or not.
	If it was, the *body_pv* will contain partially
	downloaded data, use at your own risk! (we recommend you only use
	this data for logging / debugging purposes)
- **-4** - Already Connecting
	(another OpenSIPS worker is already connecting to this URL hostname.
	Consult [no concurrent connects](#param_no_concurrent_connects) for more info).
- **-10** - Internal Error (out of
		memory, unexpected libcurl error, etc.)


This function can be used from any route.


```opensips title="rest_put usage"
...
# Creating/Updating a resource using a RESTful service with an HTTP PUT request
$var(rc) = rest_put("https://myserver.org/users/$fU",
                    $var(userinfo), , $var(body), $var(ct), $var(rcode));
if ($var(rc) < 0) {
	xlog("rest_put() failed with $var(rc), user=$fU\n");
	send_reply(500, "Server Internal Error 3");
	exit;
}

if ($var(rcode) != 200) {
	xlog("rest_put() rcode=$var(rcode), user=$fU\n");
	send_reply(500, "Server Internal Error 4");
	exit;
}
...
```


#### rest_append_hf(txt)


Append *txt* to the HTTP headers of the subsequent request.
		Multiple headers can be appended by making multiple calls
		before executing a request.


The contents of *txt* should adhere to the
		specification for HTTP headers (ex. Field: Value)


Parameters


- *txt* (string)


This function can be used from any route.


```opensips title="rest_append_hf usage"
...
# Example of querying a REST service requiring additional headers

rest_append_hf("Authorization: Bearer mF_9.B5f-4.1JqM");
$var(rc) = rest_get("http://getcredit.org/?account=$fU", $var(credit));
...
		
```


#### rest_init_client_tls(tls_client_domain)


Force a specific TLS domain to be used at most once, during the next
		GET/POST/PUT request.  Refer to the tls_mgm module for additional info
		regarding TLS client domains.


If using this function, you must also ensure that tls_mgm is loaded
		and properly configured.


Parameters


- *tls_client_domain* (string)


This function can be used from any route.


```opensips title="rest_init_client_tls usage"
...
rest_init_client_tls("dom1");
if (!rest_get("https://example.com"))
    xlog("query failed\n");
...
		
```


### Exported Asynchronous Functions


#### rest_get(url, body_pv[, [ctype_pv][, [retcode_pv]]])


Perform an asynchronous HTTP GET.  This function behaves exactly the same as
		**[rest get](#func_rest_get)**
		(in terms of input, output and processing),
		but in a non-blocking manner.  Script execution is suspended until the
		entire content of the HTTP response is available.


```opensips title="async rest_get usage"
route {
	...
	async(rest_get("http://getcredit.org/?account=$fU",
	               $var(credit), , $var(rcode)), resume);
}

route [resume] {
	$var(rc) = $rc;
	if ($var(rc) < 0) {
		xlog("async rest_get() failed with $var(rc), acc=$fU\n");
		send_reply(500, "Server Internal Error");
		exit;
	}

	if ($var(rcode) != 200) {
		xlog("L_INFO", "async rest_get() rcode=$var(rcode), acc=$fU\n");
		send_reply(403, "Forbidden");
		exit;
	}

	...
}
```


#### rest_post(url, send_body_pv, [send_ctype_pv], recv_body_pv[, [recv_ctype_pv][, [retcode_pv]]])


Perform an asynchronous HTTP POST.  This function behaves exactly the same as
		**[rest post](#func_rest_post)** (in
		terms of input, output and processing), but in a non-blocking manner.
		Script execution is suspended until the entire content of the HTTP
		response is available.


```opensips title="async rest_post usage"
route {
	...
	async(rest_post("http://myserver.org/register_user",
	                $fU, , $var(body), $var(ct), $var(rcode)), resume);
}

route [resume] {
	$var(rc) = $rc;
	if ($var(rc) < 0) {
		xlog("async rest_post() failed with $var(rc), user=$fU\n");
		send_reply(500, "Server Internal Error 1");
		exit;
	}
	if ($var(rcode) != 200) {
		xlog("async rest_post() rcode=$var(rcode), user=$fU\n");
		send_reply(500, "Server Internal Error 2");
		exit;
	}

	...
}
```


#### rest_put(url, send_body_pv, [send_ctype_pv], recv_body_pv[, [recv_ctype_pv][, [retcode_pv]]])


Perform an asynchronous HTTP PUT.  This function behaves exactly the same as
		**[rest put](#func_rest_put)** (in
		terms of input, output and processing), but in a non-blocking manner.
		Script execution is suspended until the entire content of the HTTP
		response is available.


```opensips title="async rest_put usage"
route {
	...
	async(rest_put("http://myserver.org/users/$fU", $var(userinfo), ,
	               $var(body), $var(ct), $var(rcode)), resume);
}

route [resume] {
	$var(rc) = $rc;
	if ($var(rc) < 0) {
		xlog("async rest_put() failed with $var(rc), user=$fU\n");
		send_reply(500, "Server Internal Error 3");
		exit;
	}
	if ($var(rcode) != 200) {
		xlog("async rest_put() rcode=$var(rcode), user=$fU\n");
		send_reply(500, "Server Internal Error 4");
		exit;
	}

	...
}
```


### Exported script transformations


The module also provides a way for encoding and decoding parameters
			contained in an arbitrary script variable, in accordance with
			RFC3986. This is done by applying a transformation to a script
			variable containing the data to be encoded. The value of the
			original variable is not altered and a corresponding string value
			is returned. The transformation is performed through libcurl API
			method curl_easy_escape (or curl_escape for libcurl < 7.15.4).


#### {rest.escape}


The result of this transformation is to produce percent encoded string value which can be safely used in URI construction.


There are no parameters for this transformation.


```opensips title="rest.escape usage"
...
# This example would produce log entry: "Output: call%40example.com%26safe%3Dfalse"
$var(tmp) = "call@example.com&safe=false";
xlog("Output: $(var(tmp){rest.escape})\n");

# Encode call ID before transmission:
$var(rc) = rest_get("https://call-info.org/?id=$(ci{rest.escape})", $var(body_pv));
...
                
```


#### {rest.unescape}


The result of this transformation is to decode percent encoded string values.


There are no parameters for this transformation.


```opensips title="rest.unescape usage"
...
# This example would produce log entry: "Output: 1+1=2!"
$var(tmp) = "1%2B1%3D2%21";
xlog("Output: $(var(tmp){rest.unescape})\n");

# This example would produce log entry: "OpenSIPs, tastes better with every SIP!"
$var(tmp) = "OpenSIPs%2C%20tastes%20better%20with%20every%20SIP%21";
xlog("$(var(tmp){rest.unescape})\n");
...
                
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
