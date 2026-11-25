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


### Response Caching


When [cachedb_url](#cachedb_url-string) is set, the module keeps a local
cache of the HTTP responses it receives and serves repeated queries from it
instead of going back to the origin server.


Only **GET** responses are stored, in both the blocking and the asynchronous
flavour. *rest_post()* and *rest_put()* accept the same output variable and
report *miss:method*, but nothing they fetch is ever cached: a POST or a PUT
is a request to change something, and the cache key does not cover the
request body, so two POSTs to one URL that differ only in what they send must
not be allowed to look alike.


The module does not replicate anything itself, so whether the cache is
private to one instance or shared by a cluster is decided entirely by the
backend you point it at, and both are useful:


- an **in-process** backend (*cachedb_local*, *cachedb_perf*) gives the
cheapest possible hit, at the cost of each instance having to warm its own
cache;
- a **shared** backend (one *cachedb_redis* instance used by the whole
cluster) means a response fetched by any one node is then served by all of
them, which raises the hit rate and cuts the load on the origin, at the cost
of a network round trip per hit.


The useful rule is not local-versus-remote but simply that the backend should
be cheaper than the call it is replacing.  Against an origin that answers in
milliseconds, a shared redis is a large win and shares the benefit across the
cluster; against one that answers in microseconds, only an in-process backend
is worth the trouble.


One backend requirement is not negotiable: it must actually honour the expiry
it is given.  **cachedb_mongodb does not** - it accepts the expiry argument
and ignores it, so an entry written there never expires and the cache would
grow without bound.  The module stores an absolute expiry inside each entry
and refuses to serve one that has passed, so it will not hand out a stale
response on such a backend, but it cannot reclaim the space either.  Use a
backend that expires what it is told to.


By default the module obeys the origin: a response is cached only if the
server's own *Cache-Control* and *Expires* headers permit it, and only for as
long as they allow.  A response carrying *no-store*, *no-cache*, *private*,
*Set-Cookie* or *Vary* is never stored; neither is a reply whose status falls
outside the small RFC-cacheable set (200, 203, 204, 300, 301, 308, 404, 405,
410, 414, 501 - with 206 deliberately excluded, as the cache does not handle
ranges), nor one larger than [cache_max_body](#cache_max_body-integer).  See
[cache_policy](#cache_policy-string) for the looser modes, and
[rest_cache_ctl()](#rest_cache_ctlttl) for overriding the decision on a
single call.


The cache key covers the method, the full URL and any headers queued with
*rest_append_hf()*.  The headers matter: they are what usually carries the
Authorization or the tenant identifier, so leaving them out of the key would
let one subscriber's answer be served to another.  Two calls that differ only
in an appended header are therefore two distinct cache entries.


Every function accepts an optional trailing output variable which reports
where the answer came from - see the *source_pv* parameter of
[rest_get()](#rest_geturl-body_pv-ctype_pv-retcode_pv-max_redirects-source_pv).
Together with the exported statistics this is the way to tell a cache that is
working from one that is quietly storing nothing because the origin forbids
it.


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
[connection_timeout](#connection_timeout-integer).


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
[connect_poll_interval](#connect_poll_interval-integer) may speed up all async
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


#### ssl_capath (string)


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


Only relevant when [no_concurrent_connects](#no_concurrent_connects-boolean) is enabled.
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


#### cachedb_url (string)


URL of a cachedb backend in which to cache HTTP responses.  Setting it is what
enables the response cache; without it, no caching is performed and the module
behaves exactly as before.


Any backend that expires what it is told to will do, since only the generic
*get* and *set* operations are used.  The choice decides whether the cache is
private to this instance or shared by the cluster, and what a hit costs - see
[Response Caching](#response-caching), which also explains why
*cachedb_mongodb* is not a suitable backend.


Only *GET* requests are ever cached.


*Default value is "NULL" (caching disabled).*


```opensips title="Setting the cachedb_url parameter"
...
modparam("rest_client", "cachedb_url", "perf:///rest")
...
```


#### cache_policy (string)


How far to go beyond what the origin server explicitly permits.  One of:


- *off* - never cache.  Useful to disable caching without removing
*cachedb_url* from the config.
- *strict* - cache only what the origin explicitly permits, taking the
lifetime from its *Cache-Control: max-age* (or *s-maxage*, or *Expires*).  A
response with no caching headers is not cached.
- *heuristic* - as strict, but a response whose origin said nothing about
caching is cached for *cache_ttl* seconds.  An explicit prohibition is still
honoured.
- *force* - as heuristic, but responses the origin asked not to store are
cached anyway, for *cache_ttl* seconds.


Under every policy, a response is refused if it is not a GET, if its status
code is not cacheable, if it carries a *Vary* header, or if it exceeds
*cache_max_body*.


*force* reinterprets every endpoint the module talks to, including ones added
later.  Prefer [rest_cache_ctl()](#rest_cache_ctlttl) to override a single
call site.


*Default value is "strict".*


```opensips title="Setting the cache_policy parameter"
...
modparam("rest_client", "cache_policy", "heuristic")
...
```


#### cache_ttl (integer)


Lifetime, in seconds, applied when the origin server gave none and the policy
allows caching anyway.  Required by the *heuristic* and *force* policies -
either is rejected at startup if this is not positive, since it would
otherwise silently cache nothing.


It is never used in place of a lifetime the origin did supply.


*Default value is "0" (do not cache silent responses).*


```opensips title="Setting the cache_ttl parameter"
...
modparam("rest_client", "cache_ttl", 300)
...
```


#### cache_max_body (integer)


Largest response body, in bytes, that will be stored.  Anything above it is
returned to the script as usual but not cached, and reported as
*miss:oversize*.


*Default value is "65536".*


Values above 64 KB are clamped to 64 KB with a startup warning - the encoded
entry lives in a fixed 64 KB buffer, so a larger setting would otherwise pass
startup and then silently store nothing.


```opensips title="Setting the cache_max_body parameter"
...
modparam("rest_client", "cache_max_body", 131072)
...
```


### Exported Functions


#### rest_get(url, body_pv, [ctype_pv], [retcode_pv], [max_redirects], [source_pv])


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
- *max_redirects* (integer, optional) - maximum number of HTTP redirects
to follow. A missing or **0** value preserves the previous behavior and does not
follow redirects. Values from **1** to **30** enable redirects up to the requested
limit. Only `http` and `https` redirect targets are accepted; values outside the
**0** to **30** range are invalid.
- *source_pv* (var, optional) - output variable reporting where the answer
came from, when the response cache is enabled: *hit* (served from the cache),
*miss* (fetched and stored), *miss:reason* (fetched but not storable - the
reason is one of *no-store*, *no-cache*, *private*, *set-cookie*, *vary*,
*silent*, *status*, *method*, *oversize* or *expired*), or *bypass* (the
cache was not consulted).

When redirects are enabled, libcurl applies its normal HTTP redirect method
semantics. In particular, POST requests may be converted to GET after some
3xx responses, as defined by libcurl.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
(the [connection_timeout](#connection_timeout-integer) was exceeded
before a TCP connection could be established)
- **-3** - Transfer Timeout
(the [curl_timeout](#curl_timeout-integer) was exceeded before the
last byte was received). The *retcode_pv* may
be set to 200 or 0, depending whether a 200 OK was received or not.
If it was, the *body_pv* will contain partially
downloaded data, use at your own risk! (we recommend you only use
this data for logging / debugging purposes)
- **-4** - Already Connecting
(another OpenSIPS worker is already connecting to this URL hostname.
Consult [no_concurrent_connects](#no_concurrent_connects-boolean) for more info).
- **-10** - Internal Error (out of
memory, unexpected libcurl error, etc.)


This function can be used from any route.


```opensips title="rest_get usage"
...
# Example of querying a REST service to get the credit of an account
$var(rc) = rest_get("https://getcredit.org/?account=$fU",
                    $var(credit),
                    $var(ct),
                    $var(rcode),
                    5);
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


#### rest_post(url, send_body, [send_ctype], recv_body_pv, [recv_ctype_pv], [retcode_pv], [max_redirects], [source_pv])


Perform a blocking HTTP POST on the given *url*.


> [!NOTE]
> The *send_body* parameter can also accept a format-string
> but it cannot be larger than 1024 bytes. For larger messages, you must build them in a
> pseudo-variable and pass it to the function.


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
- *max_redirects* (integer, optional) - maximum number of HTTP redirects
to follow. A missing or **0** value preserves the previous behavior and does not
follow redirects. Values from **1** to **30** enable redirects up to the requested
limit. Only `http` and `https` redirect targets are accepted; values outside the
**0** to **30** range are invalid.
- *source_pv* (var, optional) - output variable reporting where the answer
came from, when the response cache is enabled: *hit* (served from the cache),
*miss* (fetched and stored), *miss:reason* (fetched but not storable - the
reason is one of *no-store*, *no-cache*, *private*, *set-cookie*, *vary*,
*silent*, *status*, *method*, *oversize* or *expired*), or *bypass* (the
cache was not consulted).

When redirects are enabled, libcurl applies its normal HTTP redirect method
semantics. In particular, POST requests may be converted to GET after some
3xx responses, as defined by libcurl.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
(the [connection_timeout](#connection_timeout-integer) was exceeded
before a TCP connection could be established)
- **-3** - Transfer Timeout
(the [curl_timeout](#curl_timeout-integer) was exceeded before the
last byte was received). The *retcode_pv* may
be set to 200 or 0, depending whether a 200 OK was received or not.
If it was, the *body_pv* will contain partially
downloaded data, use at your own risk! (we recommend you only use
this data for logging / debugging purposes)
- **-4** - Already Connecting
(another OpenSIPS worker is already connecting to this URL hostname.
Consult [no_concurrent_connects](#no_concurrent_connects-boolean) for more info).
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


#### rest_put(url, send_body, [send_ctype], recv_body_pv, [recv_ctype_pv], [retcode_pv], [max_redirects], [source_pv])


Perform a blocking HTTP PUT on the given *url*.


Similar to [rest_post()](#rest_posturl-send_body-send_ctype-recv_body_pv-recv_ctype_pv-retcode_pv-max_redirects-source_pv), the *send_body_pv*
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
- *max_redirects* (integer, optional) - maximum number of HTTP redirects
to follow. A missing or **0** value preserves the previous behavior and does not
follow redirects. Values from **1** to **30** enable redirects up to the requested
limit. Only `http` and `https` redirect targets are accepted; values outside the
**0** to **30** range are invalid.
- *source_pv* (var, optional) - output variable reporting where the answer
came from, when the response cache is enabled: *hit* (served from the cache),
*miss* (fetched and stored), *miss:reason* (fetched but not storable - the
reason is one of *no-store*, *no-cache*, *private*, *set-cookie*, *vary*,
*silent*, *status*, *method*, *oversize* or *expired*), or *bypass* (the
cache was not consulted).

When redirects are enabled, libcurl applies its normal HTTP redirect method
semantics.


**Return Codes**


- **1** - Success
- **-1** - Connection Refused.
- **-2** - Connection Timeout
(the [connection_timeout](#connection_timeout-integer) was exceeded
before a TCP connection could be established)
- **-3** - Transfer Timeout
(the [curl_timeout](#curl_timeout-integer) was exceeded before the
last byte was received). The *retcode_pv* may
be set to 200 or 0, depending whether a 200 OK was received or not.
If it was, the *body_pv* will contain partially
downloaded data, use at your own risk! (we recommend you only use
this data for logging / debugging purposes)
- **-4** - Already Connecting
(another OpenSIPS worker is already connecting to this URL hostname.
Consult [no_concurrent_connects](#no_concurrent_connects-boolean) for more info).
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


#### rest_cache_ctl(ttl)


Overrides the cache decision for the *next* rest_get(), rest_post() or
rest_put() only, then reverts - the same "applies once" behaviour as
[rest_append_hf()](#rest_append_hftxt).  Requires *cachedb_url*; without it
the call is ignored.


Meaning of *ttl*:


- *0* - bypass the cache entirely for that call: no lookup, no store.  For
the one endpoint that must always be live.
- *greater than 0* - serve that call from the cache if present, and store its
response for that many seconds, regardless of *cache_policy* and of what the
origin's own cache headers say.


This is the recommended way to cache an endpoint whose server sends unhelpful
headers, in preference to *cache_policy* = *force*, because it affects one
call site rather than every endpoint the module talks to.


This function can be used from any route.


```opensips title="rest_cache_ctl usage"
...
# this rate lookup is safe to cache for five minutes, whatever it claims
rest_cache_ctl(300);
rest_get("http://rates/lookup", $var(body), $var(ct), $var(rc));

# ...but the fraud check must always be live
rest_cache_ctl(0);
rest_get("http://fraud/check", $var(body), $var(ct), $var(rc));
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


#### rest_get(url, body_pv, [ctype_pv], [retcode_pv], [max_redirects], [source_pv])


Perform an asynchronous HTTP GET.  This function behaves exactly the same as
**rest_get()**
(in terms of input, output and processing),
but in a non-blocking manner.  Script execution is suspended until the
entire content of the HTTP response is available. The optional *max_redirects* argument has the same behavior in asynchronous mode.


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


#### rest_post(url, send_body_pv, [send_ctype_pv], recv_body_pv, [recv_ctype_pv], [retcode_pv], [max_redirects], [source_pv])


Perform an asynchronous HTTP POST.  This function behaves exactly the same as
**rest_post()** (in
terms of input, output and processing), but in a non-blocking manner.
Script execution is suspended until the entire content of the HTTP
response is available. The optional *max_redirects* argument has the same behavior in asynchronous mode.


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


#### rest_put(url, send_body_pv, [send_ctype_pv], recv_body_pv, [recv_ctype_pv], [retcode_pv], [max_redirects], [source_pv])


Perform an asynchronous HTTP PUT.  This function behaves exactly the same as
**rest_put()** (in
terms of input, output and processing), but in a non-blocking manner.
Script execution is suspended until the entire content of the HTTP
response is available. The optional *max_redirects* argument has the same behavior in asynchronous mode.


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


### Exported Statistics


The statistics are always exported; while the response cache is disabled the
counters simply stay at 0 and the hit rate reads 0.


#### rest_cache_hits


Requests served from the cache, without contacting the origin.


#### rest_cache_misses


Requests that went to the origin.


#### rest_cache_stores


Responses actually written to the cache.


#### rest_cache_skipped


Responses fetched but not storable, because the policy, the origin's headers
or the size limit refused them.  Worth watching: a cache that stores nothing
because every origin sends *no-store* is otherwise indistinguishable from one
that is misconfigured, and neither the hit rate nor response times will tell
you apart.  The per-response reason is in the debug log and in the
*source_pv* output variable of each function.


#### rest_cache_hit_rate


Hits as a whole percentage of lookups, 0 when nothing has been looked up yet.
It covers the lifetime of the process, so a low value shortly after a restart
is a cold cache rather than a problem.


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

### Response Cache Examples


The examples below all assume an in-process backend, since the point of the
cache is to be cheaper than the HTTP call it replaces:


```opensips title="Response cache: loading the module with a cache backend"
loadmodule "cachedb_local.so"
loadmodule "rest_client.so"

modparam("rest_client", "cachedb_url", "local://")
```


#### An origin that sends cache headers


Nothing beyond *cachedb_url* is needed.  The default *strict* policy caches
the response for exactly as long as the server said it may, and re-fetches
after that:


```opensips title="Response cache: an origin that sends cache headers"
# origin answers with:  Cache-Control: max-age=300
$var(rc) = rest_get("http://rates.internal/lookup?prefix=$rU",
                    $var(body), $var(ct), $var(rcode));

# for the next 5 minutes this same prefix is answered locally
```


#### An origin that sends no cache headers


Many internal APIs send no *Cache-Control* at all.  Under the default policy
those responses are never cached - the module will not invent a lifetime the
server did not give it.  If you know the data is safe to hold for a while, say
so explicitly:


```opensips title="Response cache: an origin that sends no cache headers"
modparam("rest_client", "cache_policy", "heuristic")
modparam("rest_client", "cache_ttl", 60)
```


*heuristic* still obeys an origin that actively refuses caching; it only
fills in a lifetime where the origin was silent.  It is rejected at startup
without a positive *cache_ttl*, because a heuristic policy with nothing to
fall back on would silently behave like *strict*.


#### Overriding a single call


Different endpoints behind the same module often deserve different treatment.
Rather than loosening the policy globally - which reinterprets every endpoint
you have, including the ones that were right - override the individual call:


```opensips title="Response cache: overriding a single call"
# an expensive, rarely-changing lookup whose origin forgot the headers:
# cache it for 5 minutes regardless of policy or origin
rest_cache_ctl(300);
$var(rc) = rest_get("http://rates.internal/tariff?id=$var(tid)",
                    $var(tariff));

# a fraud check must never be answered from a cache, even a warm one
rest_cache_ctl(0);
$var(rc) = rest_get("http://fraud.internal/score?num=$fU", $var(score));
```


The override applies to the *next* REST call only and is consumed by it, in
the same way as [rest_append_hf()](#rest_append_hftxt).  This holds for
asynchronous calls too: the value is captured when the transfer is
dispatched, not when it completes, so a later request cannot change how an
in-flight one is cached.


#### Per-account queries


Headers queued with *rest_append_hf()* are part of the cache key, so a
per-tenant or per-subscriber credential separates the entries automatically -
the two calls below never see each other's response, even though the URL is
identical:


```opensips title="Response cache: per-account queries"
rest_append_hf("Authorization: Bearer $var(tenant_token)");
$var(rc) = rest_get("http://api.internal/limits", $var(limits));
```


The header values are hashed into the key rather than stored in it, so a
bearer token never appears in the backend's key space or in whatever
dump/inspection tooling the backend offers.


#### Asynchronous calls


The cache works identically for the asynchronous flavours.  A hit completes
the call inline - the resume route still runs, and the script sees the same
variables it would have seen after a real transfer.  The *source_pv* variable
comes after *max_redirects*, so leave that one empty to keep the default:


```opensips title="Response cache: asynchronous calls with the cache"
route {
	async(rest_get("http://rates.internal/lookup?prefix=$rU",
	               $var(body), $var(ct), $var(rcode), , $var(src)), resume);
}

route [resume] {
	if ($rc < 0) {
		xlog("rate lookup failed: $rc\n");
		send_reply(500, "Server Internal Error");
		exit;
	}
	xlog("rate for $rU came from: $var(src)\n");
	...
}
```


#### Knowing whether the cache is doing anything


A cache that stores nothing because every origin sends *no-store* looks
exactly like a working one from the outside: no errors, and a hit rate of zero
either way.  The trailing output variable says which it is, per call:


```opensips title="Response cache: reporting where a response came from"
$var(rc) = rest_get("http://rates.internal/lookup?prefix=$rU",
                    $var(body), $var(ct), $var(rcode), , $var(src));

# $var(src) is one of:
#   hit            served locally, the origin was not contacted
#   miss           fetched from the origin and stored
#   miss:no-store  fetched, but the origin forbade storing it
#   miss:silent    fetched, but the origin gave no lifetime and the
#                  policy is strict
#   bypass         the cache was not consulted (disabled, or
#                  rest_cache_ctl(0))
if ($var(src) =~ "^miss:") {
	xlog("L_INFO", "not cacheable ($var(src)): $rU\n");
}
```


The same reasons are counted in *rest_cache_skipped* and logged at debug
level, so the question can be answered from monitoring without touching the
script.


### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
