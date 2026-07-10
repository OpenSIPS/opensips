---
title: "cachedb_redis Module"
description: "This module is an implementation of a cache system designed to work with a Redis server."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a
Redis server. It uses hiredis client library to connect to either a single Redis
server instance, or to a Redis Server inside a Redis Cluster.
It uses the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
is virtually unlimited*
- *the cache is 100% persistent. A restart
of OpenSIPS server will not affect the DB. The Redis DB is also
persistent so it can also be restarted without loss of information.*
- *redis is an open-source project so
it can be used to exchange data
with various other applications*
- *By creating a Redis Cluster, multiple OpenSIPS
instances can easily share key-value information*


### Redis Stack Support


Starting with OpenSIPS **3.6**, the *cachedb_redis*
module implements the column-oriented cacheDB API functions.  This makes it a suitable
cacheDB storage in scenarios such as user location *federation*
and *full-sharing*, which require this API to be available.


The implementation makes use of *RedisJSON* and *RediSearch* --
these relatively new features are available in Redis Stack Server, instead of the usual Redis Server
(Redis OSS project).  More documentation is available on the Redis website.


OpenSIPS will auto-detect availability of the RedisJSON support when necessary and log
the appropriate messages.


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *If a [use tls](#param_use_tls) is defined, the **tls_mgm** module will need to be loaded as well*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *hiredis:*
On the latest Debian based distributions, hiredis can be installed
by running 'apt-get install libhiredis-dev'

Alternatively, if hiredis is not available on your OS repos,
hiredis can be downloaded from: https://github.com/antirez/hiredis .
Download the archive, extract sources, run make,sudo make install.
If TLS connections are enabled via the [use tls](#param_use_tls) modparam,
*hiredis* needs to be compiled with TLS support.


### Exported Parameters


#### cachedb_url (string)


The URLs of the server groups that OpenSIPS will connect to in order
to use, from script, the cache_store(), cache_fetch(), etc. operations.
It may be set more than once.  The prefix part of the URL will be
the identifier that will be used from the script.


```opensips title="Set cachedb_url parameter"
...
# single-instance URLs (Redis Server or Redis Cluster)
modparam("cachedb_redis", "cachedb_url", "redis:group1://localhost:6379/")
modparam("cachedb_redis", "cachedb_url", "redis:cluster1://random_url:8888/")

# multi-instance URL (will perform circular 
```


```opensips title="Use Redis servers"
...
cache_store("redis:group1", "key", "$ru value");
cache_fetch("redis:cluster1", "key", $avp(10));
cache_remove("redis:cluster1", "key");
...
		
```


#### connect_timeout (integer)


This parameter specifies how many milliseconds OpenSIPS should wait
for connecting to a Redis node.


*Default value is "5000 ms".*


```opensips title="Set connect_timeout parameter"
...
# wait 1 seconds for Redis to connect
modparam("cachedb_redis", "connect_timeout",1000)
...
		
```


#### query_timeout (integer)


This parameter specifies how many milliseconds OpenSIPS should wait
for a query response from a Redis node.


*Default value is "5000 ms".*


```opensips title="Set connect_timeout parameter"
...
# wait 1 seconds for Redis queries
modparam("cachedb_redis", "query_timeout",1000)
...
		
```


#### shutdown_on_error (integer)


By setting this parameter to 1, OpenSIPS will abort startup if
the initial connection to Redis is not possible. Runtime reconnect
behavior is unaffected by this parameter, and is always enabled.


*Default value is "0" (disabled).*


```opensips title="Set the shutdown_on_error parameter"
...
# abort OpenSIPS startup if Redis is down
modparam("cachedb_redis", "shutdown_on_error", 1)
...
		
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for Redis connections.
In order to enable TLS for a specific connection, you can use the
"tls_domain=*dom_name*" URL parameter in the cachedb_url
of this module (or other modules that use the CacheDB interface). This should
be placed at the end of the URL after the '?' character.


When using this parameter, you must also ensure that
*tls_mgm* is loaded and properly configured. Refer to
the the module for additional info regarding TLS client domains.


Note that TLS is supported by Redis starting with version 6.0. Also, it is
an optional feature enabled at compile time and might not be included in the
standard Redis packages available for your OS.


*Default value is **0** (not enabled)*


```opensips title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "redis")
modparam("tls_mgm", "certificate", "[redis]/etc/pki/tls/certs/redis.pem")
modparam("tls_mgm", "private_key", "[redis]/etc/pki/tls/private/redis.key")
modparam("tls_mgm", "ca_list",     "[redis]/etc/pki/tls/certs/ca.pem")
...
modparam("cachedb_redis", "use_tls", 1)
modparam("cachedb_redis", "cachedb_url","redis://localhost:6379/?tls_domain=redis")
...
```


#### ftsearch_index_name (string)


Only relevant with *RedisJSON* and
*RediSearch* server-side support.


A global index name to be used for all internal JSON full-text search operations.
Future extensions may add, e.g., a connection-level index name setting.


Default value is **"idx:usrloc"**.


```opensips title="Set the ftsearch_index_name parameter"
modparam("cachedb_redis", "ftsearch_index_name", "ix::usrloc")
```


#### ftsearch_json_prefix (string)


Only relevant with *RedisJSON* and
*RediSearch* server-side support.


A key naming prefix for all internally-created Redis JSON objects (e.g.
created with JSON.SET or JSON.MSET).


Default value is **"usrloc:"**.


```opensips title="Set the ftsearch_json_prefix parameter"
modparam("cachedb_redis", "ftsearch_json_prefix", "userlocation:")
```


#### ftsearch_max_results (integer)


Only relevant with *RedisJSON* and
*RediSearch* server-side support.


The maximum number of results returned by each internally-triggered
FT.SEARCH JSON lookup query.


Default value is **10000** max results.


```opensips title="Set the ftsearch_max_results parameter"
modparam("cachedb_redis", "ftsearch_max_results", 100)
```


#### ftsearch_json_mset_expire (integer)


Only relevant with *RedisJSON* and
*RediSearch* server-side support.


A Redis EXPIRE timer to set/refresh on the JSON key after each JSON.MSET operation
(create the JSON or add/remove subkeys), in seconds.  A value of **0**
disables the EXPIRE queries completely.


Default value is **3600** seconds.


```opensips title="Set the ftsearch_json_mset_expire parameter"
modparam("cachedb_redis", "ftsearch_json_mset_expire", 7200)
```


### Exported Functions


The module does not export functions to be used
in configuration script.


### Raw Query Syntax


The cachedb_redis module allows to run RAW queries, thus taking full advantage of the capabilities of the back-end.

The query syntax is the typical REDIS one.


Here are a couple examples of running some Redis queries :


```opensips title="Redis Raw Query Examples"
...
	$var(my_hash) = "my_hash_name";
	$var(my_key) = "my_key_name";
	$var(my_value) = "my_key_value";
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key) $var(my_value)");
	cache_raw_query("redis","HGET $var(my_hash) $var(my_key)","$avp(result)");
	xlog("We have fetched $avp(result) \n");
...
	$var(my_hash) = "my_hash_name";
	$var(my_key1) = "my_key1_name";
	$var(my_key2) = "my_key2_name";
	$var(my_value1) = "my_key1_value";
	$var(my_value2) = "my_key2_value";
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key1) $var(my_value1)");
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key2) $var(my_value2)");
	cache_raw_query("redis","HGETALL $var(my_hash)","$avp(result)");

	$var(it) = 0;
	while ($(avp(result_final)[$var(it)]) != NULL) {
		xlog("Multiple key reply: - we have fetched $(avp(result_final)[$var(it)]) \n");
		$var(it) = $var(it) + 1;
	}
...
			
```


## Frequently Asked Questions


**Q: My OpenSIPS is occasionally crashing in libhiredis, what to do?**


Make sure you've upgraded the Redis "libhiredis" client library to at
least version 0.14.1.  There was at least one significant vulnerability
reported in library versions prior to that one ([CVE-2020-7105](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-7105)),
so upgrading to latest stable may very well fix the crash!
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
