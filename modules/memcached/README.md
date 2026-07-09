---
title: "MEMCACHED"
description: "This module is an implementation of a cache system designed to work with a memcached server. It uses libmemcached client library to connect to several memcached servers that store data. It registers the three functions for storing, fetching and removing a value to the core memcache managem..."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a 
memcached server. It uses libmemcached client library to connect to several memcached
servers that store data. It registers the three functions for storing, fetching
and removing a value to the core memcache management interface.


### Advantages


- *memory costs are no longer on the server*
- *many servers may be used so the memory
is virtually unlimited*
- *the cache is persistent so a restart
of the server will not affect the cache*
- *memcached is an open-source project so
it can be used to exchange data
with various other applicationsr*
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


#### server (string)


The names of the servers to connect to.
It can be set more than one time. Each value represents a group of servers to connect to.
Each group of servers may be accessed using "memcached_$(GROUP_NAME)" as the first parameter 
of the cache_fetch, cache_store, cache_remove script functions.
Each group contains a list of comma separated url:[port].
If port is missing the default value is used(11211).


```opensips title="Set server parameter"
...
modparam("memcached", "server","group1 = localhost:9999,127.0.0.1" );
modparam("memcached", "server","y = random_url:8888" );
...
	
```


```opensips title="Use memcached servers"
...
cache_store("memcached_group1","key","$ru value");
cache_fetch("memcached_y","key",$avp(i:10));
cache_remove("memcached_group1","key");
...
	
```


#### Exported Functions


The module does not export functions to be used
in configuration script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
