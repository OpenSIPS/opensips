---
title: "cachedb_couchbase Module"
description: "This module is an implementation of a cache system designed to work with a Couchbase server. It uses the libcouchbase client library to connect to the server instance, It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a 
		Couchbase server. It uses the libcouchbase client library to connect to the
		server instance,
		It uses the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
				is virtually unlimited*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The CouchBase DB is also
				persistent so it can also be restarted without loss of information.*
- *CouchBase is an open-source project so
				it can be used to exchange data
				 with various other applications*
- *By creating a CouchBase Cluster, multiple OpenSIPS
				instances can easily share key-value information*


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libcouchbase >= 3.0:*
libcoucbase can be downloaded from http://www.couchbase.com/develop/c/current


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.
			The format of the URL is
			couchbase[:identifier]://[username:password@]IP:Port/bucket_name


```c title="Set cachedb_url parameter"
...
modparam("cachedb_couchbase", "cachedb_url","couchbase:group1://localhost:6379/default")
modparam("cachedb_couchbase", "cachedb_url","couchbase:cluster1://random_url:8888/my_bucket")
# Multiple hosts
modparam("cachedb_couchbase", "cachedb_url","couchbase:cluster1://random_url1:8888,random_url2:8888,random_url3:8888/my_bucket")
...
	
```


#### timeout (int)


The max duration in microseconds that a couchbase op is expected to last.
			Default is 3000000 ( 3 seconds )


```c title="Set timeout parameter"
...
modparam("cachedb_couchbase", "timeout",5000000);
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a couchbase query can last.
			Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```c title="Set exec_threshold parameter"
...
modparam("cachedb_couchbase", "exec_threshold", 100000)
...
	
```


#### lazy_connect (int)


Delay connecting to a bucket until the first time it is used.
			Connecting to many buckets at startup can be time consuming. This option allows for
			faster startup by delaying connections until they are needed.
			This option can be dangerous for untested bucket configurations/settings. Always test
			first without lazy_connect.
			This option will show errors in the log during the first access made to a bucket.
			Default is 0 ( Connect to all buckets on startup )


```c title="Set lazy_connect parameter"
...
modparam("cachedb_couchbase", "lazy_connect", 1);
...
	
```


```c title="Use CouchBase servers"
...
cache_store("couchbase:group1","key","$ru value");
cache_fetch("couchbase:cluster1","key",$avp(10));
cache_remove("couchbase:cluster1","key");
...
	
```


#### Exported Functions


The module does not export functions to be used
		in configuration script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
