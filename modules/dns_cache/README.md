---
title: "dns_cache Module"
description: "This module is an implementation of a cache system designed for DNS records. For successful DNS queries of all types, the module will store in a cache/db backend the mappings, for TTL number of seconds received in the DNS answer. Failed DNS queries will also be stored in the back-end, with ..."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed for DNS records.
		For successful DNS queries of all types, the module will store in a cache/db
		backend the mappings, for TTL number of seconds received in the DNS answer.
		Failed DNS queries will also be stored in the back-end, with a TTL that can be
		specified by the user.
		The module uses the Key-Value interface exported from the core.


### Dependencies


#### OpenSIPS Modules


A cachedb_* type module must be loaded before loading
		the dns_cache module.


### Exported Parameters


#### cachedb_url (string)


The url of the key-value back-end that will be used
			for storing the DNS records.


```c title="Set cachedb_url parameter"
...
#use internal cachedb_local module
modparam("dns_cache", "cachedb_url","local://")
#use cachedb_memcached module with memcached server at 192.168.2.130
modparam("dns_cache", "cachedb_url","memcached://192.168.2.130:8888/")
...
		
```


#### blacklist_timeout (int)


The number of seconds that a failed DNS query will be kept in cache.
			Default is 3600.


```c title="Set blacklist_timeout parameter"
...
modparam("dns_cache", "blacklist_timeout",7200) # 2 hours
...
		
```


#### min_ttl (int)


The minimum number of seconds that a DNS record will be kept in
			cache. If the TTL received in the DNS answer is lower than this
			value, the record will be cached for min_ttl seconds.


*Default value is **0** seconds (no minimum TTL is enforced).*


```c title="Set min_ttl parameter"
...
modparam("dns_cache", "min_ttl",300) # 5 minutes
...
		
```


### Exported Functions


The module does not export functions to be used
		in configuration script.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
