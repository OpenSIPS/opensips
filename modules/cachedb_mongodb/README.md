---
title: "cachedb_mongodb Module"
description: "This module is an implementation of a cache system designed to work with MongoDB servers. It implements the Key-Value interface exposed by the OpenSIPS core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with
		MongoDB servers.
		It implements the Key-Value interface exposed by the OpenSIPS core.


The underlying client library is compatible with any of the following
		MongoDB server versions: 2.4, 2.6, 3.0, 3.2 and 3.4, as stated in 
		[the MongoDB documentation](https://docs.mongodb.com/ecosystem/drivers/driver-compatibility-reference/).


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
				is virtually unlimited*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The MongoDB is also
				persistent so it can also be restarted without loss of information.*
- *MongoDB is an open-source project so
				it can be used to exchange data
				 with various other applications*
- *By creating a MongoDB Cluster, multiple OpenSIPS
				instances can easily share key-value information*
- *This module also implements the CacheDB Raw query
				capability, thus you can run whatever query that the MongoDB
				back-end supports, taking full advatange of it.*


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following packages must be installed before running OpenSIPS with this module loaded:


```c title="Runtime requirements for 'cachedb_mongodb'"
# Debian / Ubuntu
sudo apt-get install libjson-c2 libmongoc-1.0

# Red Hat / CentOS
sudo yum install json-c mongo-c-driver
				
```


The following packages are required in order to compile this module:


```c title="Compilation requirements for 'cachedb_mongodb'"
# Debian / Ubuntu
sudo apt-get install libjson-c-dev libmongoc-dev libbson-dev

# Red Hat / CentOS
sudo yum install json-c-devel mongo-c-driver-devel
				
```


### Exported Parameters


#### cachedb_url (string)


The URLs of the server groups that OpenSIPS will connect to in order
			to allow the cache_store(), cache_fetch(), etc. functions to be used
			from the OpenSIPS script. It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.


The URL syntax is identical to the one used by MongoDB, including
			connect string options. For more info,
			please refer to [the official MongoDB connect string documentation](https://docs.mongodb.com/manual/reference/connection-string/).


```c title="Set cachedb_url parameter"
...
# Connect to a single 
```


```opensips title="Reference MongoDB connections"
...
cache_store("mongodb", "key", "$ru value");
cache_remove("mongodb:cluster", "key");
cache_fetch("mongodb:instance1", "key", $avp(10));
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a mongodb query can last.
			Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```opensips title="Set exec_threshold parameter"
...
modparam("cachedb_mongodb", "exec_threshold", 100000)
...
	
```


#### compat_mode_2.4 (int)


Switch the module into compatibility mode for MongoDB 2.4 servers.
			Specifically, this allows "insert/update/delete" raw queries to not fail,
			since they were introduced in MongoDB 2.6. The module will interpret
			the raw query JSON, convert it to its corresponding command and run it.


Caveat: only the minimally required raw query options are
			supported in this mode.


*Default value is "0 (disabled)".*


```opensips title="Setting the compat_mode_2.4 parameter"
...
modparam("cachedb_mongodb", "compat_mode_2.4", 1)
...
	
```


#### compat_mode_3.0 (int)


Switch the module into compatibility mode for MongoDB 2.6/3.0 servers.
			Specifically, this allows "find" raw queries to not fail,
			since they were introduced in MongoDB 3.2. The module will interpret
			the "find" raw query JSON, convert it to its corresponding command and run it.


Caveat: only the minimally required options for "find" raw queries are
			supported in this mode.


*Default value is "0 (disabled)".*


```opensips title="Setting the compat_mode_3.0 parameter"
...
modparam("cachedb_mongodb", "compat_mode_3.0", 1)
...
	
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Raw Query Syntax


The cachedb_mongodb module supports raw queries, thus taking
			full advantage of the capabilities of the back-end, including
			query-specific options such as read/write preference, timeouts,
			filtering options, etc.


The query syntax is identical to the mongo cli. Documentation for it
			can be found on the
			[MongoDB website](https://docs.mongodb.com/manual/reference/command/nav-crud/). Query results
			are returned as JSON documents, that one can further process
			in the OpenSIPS script by using the JSON module.


Some example raw queries:


```opensips title="MongoDB Raw Insert"
...
cache_raw_query("mongodb:cluster", "{ \
    \"insert\": \"ip_blacklist\", \
    \"documents\": [{ \
        \"username\": \"$fU\", \
        \"ip\": \"$si\", \
        \"attempts\": 1 \
     }]}",
 "$avp(out)");
xlog("INSERT RAW QUERY returned $rc, output: '$avp(out)'\n");
...
			
```


```opensips title="MongoDB Raw Update"
...
cache_raw_query("mongodb:cluster", "{ \
    \"update\": \"ip_blacklist\", \
    \"updates\": [{ \
        \"q\": { \
            \"username\": \"$fU\", \
            \"ip\": \"$si\" \
         }, \
        \"u\": { \
            \"$$inc\": {\"attempts\": 1} \
         } \
      }]}",
 "$avp(out)");
xlog("UPDATE RAW QUERY returned $rc, output: '$avp(out)'\n");
...
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
