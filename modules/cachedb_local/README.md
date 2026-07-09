---
title: "cachedb_local Module"
description: "This module is an implementation of a local cache system designed as a hash table. It uses the Key-Value interface exported by OpenSIPS core. Starting with version 2.3, the module can have multiple hash tables, called collections. Each url for cachedb_local module points to one collection..."
---

## Admin Guide


### Overview


This module is an implementation of a local cache system designed as
a hash table. It uses the Key-Value interface exported by OpenSIPS core.
Starting with version 2.3, the module can have multiple hash tables,
called collections. Each url for cachedb_local module points to one
collection. One collection can be shared between multiple urls.


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### cachedb_url (string)


URL parameter used to define cachedb_local collections. One collection
can belong to multiple URLs, but one URL can have only one collection.
Redefining an URL with the same schema and group name will result in overwriting
that URL. Each collection used in URL definition must be defined using
*cachedb_collection* parameter. The collection shall be defined
as a normal database, at the end of the URL as in the examples. In the script the
collection shall be identified using the schema and, if exists, the group name.


*"If no URL defined, the url with no group name and collection "default"
will be used.".*


```opensips title="Set cachedb_url parameter"
...
### for this example, if no collection is defined, the default collection named
### "default" shall be used
modparam("cachedb_local", "cachedb_url", "local://")
### this URL will use the collection named collection1; it will overwrite the
### previous url definition which was using the "default" collection
modparam("cachedb_local", "cachedb_url", "local:///collection1")
### this URL will use collection2; it will be referenced from the script
### with "local:group2"
modparam("cachedb_local", "cachedb_url", "local:group2:///collection2")

## how to use the URLs from the script
## as defined above, this call will use collection1
cache_store("local", ...)
## as defined above, this call will use collection2
cache_store("local:group2", ...)
...
	
```


#### cache_collections (string)


Using this parameter collections(hash tables) and their sizes can be defined. Each
collection definition must be separated one from another using ';'. Default size
for a hash is 512. The size must be separated from the name of the collection using
'='. Every collection that is defined in this parameter *SHOULD* be
used in at least one URL, else you'll receive a WARNING.


*"If no collection is defined, the collection with name "default" will be
created.".*


```opensips title="Set cache_collections parameter"
...
## creating collection1 with default size (512) and collection2 with custom size
## 2^5 (32); we also changed the size of the default collection, which would have been
## created anyway from 2^9 - 512 (default value) to 2^4 - 16
modparam("cachedb_local", "cache_collections", "collection1; collection2=5; default=4")
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


### Exported Functions


#### cache_remove_chunk([collection,] glob)


Remove all keys from local cache that match the *glob* pattern
corresponding to a certain *collection* or the 'default' collection
if none defined. Keep in mind that collection name is different than group name,
which identifies the engine in cachedb operations.


This function can be used from all routes


```opensips title="cache_remove_chunk usage"
	...
	cache_remove_chunk("myinfo_*");
	cache_remove_chunk("collection1", "myinfo_*");
	...
	
```


### Exported MI Functions


#### cache_remove_chunk


Removes all local cache entries that match the provided glob param.


Parameters :


- *collection(optional)* - collection from which the keys shall
be removed; if no collection set, the default collection will be used;
- *glob* - keys that match glob will be removed


MI FIFO Command Format:


```bash
		:cache_remove_chunk:_reply_fifo_file_
		collection*
		keyprefix*
		_empty_line_
		
```


## Frequently Asked Questions


**Q: What happened with old cache_table_size parameter?**


The parameter was removed because it was redundant. Since the
addition of collections, the old hash now belongs to the
default collection. This collection is created every time and
it has a default size of 512. The size can be changed by
setting the default collection size using cache_collections paramter.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
