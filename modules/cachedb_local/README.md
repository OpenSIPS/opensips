---
title: "LOCALCACHE"
description: "This module is an implementation of a local cache system designed as a hash table. It uses the Key-Value interface exported by OpenSIPS core."
---

## Admin Guide


### Overview


This module is an implementation of a local cache system designed as
a hash table. It uses the Key-Value interface exported by OpenSIPS core.


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### cache_table_size (int)


The size of the hash table. 
This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set cache_table_size parameter"
...
modparam("cachedb_local", "cache_table_size", 10)
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a local cache query can last.
Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```opensips title="Set exec_threshold parameter"
...
modparam("cachedb_local", "exec_threshold", 100000)
...
	
```


#### cache_clean_period (int)


The time interval in seconds at which to go through all the
records and delete the expired ones.


*Default value is "600 (10 minutes)".*


```opensips title="Set cache_clean_period parameter"
...
modparam("cachedb_local", "cache_clean_period", 1200)
...
	
```


#### Exported Functions


##### cache_remove_chunk(glob)


Remove all keys from local cache that match the *glob* pattern


This function can be used from all routes


```opensips title="cache_remove_chunk usage"
	...
	cache_remove_chunk("myinfo_*");
	...
	
```


#### Exported MI Functions


##### cache_remove_chunk


Removes all local cache entries that match the provided glob param.


Parameters :


- *glob* - keys that match glob will be removed


MI FIFO Command Format:


```bash
		:cache_remove_chunk:_reply_fifo_file_
		keyprefix*
		_empty_line_
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
