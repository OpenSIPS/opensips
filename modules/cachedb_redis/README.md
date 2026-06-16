---
title: "cachedb_redis Module"
description: "This module is an implementation of a cache system designed to work with a Redis server. It uses hiredis client library to connect to either a single Redis server instance, or to a Redis Server inside a Redis Cluster. It uses the Key-Value interface exported from the core."
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
				 with various other applicationsr*
- *By creating a Redis Cluster, multiple OpenSIPS
				instances can easily share key-value information*


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *hiredis:*
On the latest Debian based distributions, hiredis can be installed
				by running 'apt-get install libhiredis-dev'

				Alternatively, if hiredis is not available on your OS repos,
				hiredis can be downloaded from: https://github.com/antirez/hiredis .
				Download the archive, extract sources, run make,sudo make install.


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.


```c title="Set cachedb_url parameter"
...
modparam("cachedb_redis", "cachedb_url","redis:group1://localhost:6379/");
modparam("cachedb_redis", "cachedb_url","redis:cluster1://random_url:8888/");
...
	
```


```c title="Use Redis servers"
...
cache_store("redis:group1","key","$ru value");
cache_fetch("redis:cluster1","key",$avp(10));
cache_remove("redis:cluster1","key");
...
	
```


#### Exported Functions


The module does not export functions to be used
		in configuration script.


#### Raw Query Syntax


The cachedb_redis module allows to run RAW queries, thus taking full advantage of the capabilities of the back-end.

			The query syntax is the typical REDIS one.


Here are a couple examples of running some Redis queries :


```c title="Redis Raw Query Examples"
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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
