---
title: "cachedb_memcached Module"
description: "This module is an implementation of a cache system designed to work with a memcached server. It uses libmemcached client library to connect to several memcached servers that store data. It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a 
		memcached server. It uses libmemcached client library to connect to several memcached
		servers that store data. It uses the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *many servers may be used so the memory
				is virtually unlimited*
- *the cache is persistent so a restart
				of the server will not affect the cache*
- *memcached is an open-source project so
				it can be used to exchange data
				 with various other applications*
- *servers may be grouped together
				(e.g. for security purposes : some can be
				 inside a private network, some can be in
				 a public one)*


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libmemcached:*
libmemcached can be downloaded from: http://tangent.org/552/libmemcached.html.
				Download the archive, extract sources, run ./configure, make,sudo make install.
...
				wget http://download.tangent.org/libmemcached-0.31.tar.gz 
				tar -xzvf libmemcached-0.31.tar.gz
				cd libmemcached-0.31
				./configure
				make
				sudo make install
				...


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.


```opensips title="Set cachedb_url parameter"
...
modparam("cachedb_memcached", "cachedb_url","memcached:group1://localhost:9999,127.0.0.1/");
modparam("cachedb_memcached", "cachedb_url","memcached:y://random_url:8888/");
...
	
```


```opensips title="Use memcached servers"
...
cache_store("memcached:group1","key","$ru value");
cache_fetch("memcached:y","key",$avp(10));
cache_remove("memcached:group1","key");
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a local cache query can last.
			Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```opensips title="Set exec_threshold parameter"
...
modparam("cachedb_memcached", "exec_threshold", 100000)
...
	
```


#### Exported Functions


The module does not export functions to be used
		in configuration script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
