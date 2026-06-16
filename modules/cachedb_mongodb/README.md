---
title: "cachedb_mongodb Module"
description: "This module is an implementation of a cache system designed to work with MongoDB servers. It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with
		MongoDB servers.
		It uses the Key-Value interface exported from the core.


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


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libjson*
The libjson library can be downloaded from: http://oss.metaparadigm.com/json-c/
- *mongo-c-driver*
The mongo C driver can be downloaded from MongoDB's GitHub repository. Make sure to get the 0.6 version:
				*"git clone https://github.com/mongodb/mongo-c-driver.git -b v0.6"*


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.

			If multiple addr:port pairs are passed, the connection is treated 
			as going to a replica set.


```c title="Set cachedb_url parameter"
...
modparam("cachedb_mongodb", "cachedb_url","mongodb:instance1://localhost:27017/db.collection")
modparam("cachedb_mongodb", "cachedb_url","mongodb:replicaset1://1.2.3.4:27017,2.3.4.5:27017,3.4.5.6:27017/replicaSetName.db.collection")
...
	
```


```c title="Use MongoDB servers"
...
cache_store("mongodb:group1","key","$ru value");
cache_fetch("mongodb:replicaset1","key",$avp(10));
cache_remove("mongodb:cluster1","key");
...
	
```


#### op_timeout (int)


The timeout in ms that will be triggered in case a MongoDB op takes too long.
			Default value is 3000 ( 3 seconds )


```c title="Set op_timeout parameter"
...
modparam("cachedb_mongodb", "op_timeout",5000)
...
	
```


#### slave_ok (int)


If set to 1, read operations are allowed to go to secondary MongoDB servers
			Default value is 0 ( read and write requests will go to primary nodes = full consistency )


```c title="Set slave_ok parameter"
...
modparam("cachedb_mongodb", "slave_ok",1);
...
	
```


#### write_concern (string)


The JSON containing the Mongo write concern that should affect all write
			operations. More info can be found at http://docs.mongodb.org/manual/core/write-operations/


```c title="Set write_concern parameter"
...
modparam("cachedb_mongodb","write_concern","{ \"getLastError\": 1, "j" : "true" }")
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a mongodb query can last.
			Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```c title="Set exec_threshold parameter"
...
modparam("cachedb_mongodb", "exec_threshold", 100000)
...
	
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Raw Query Syntax


The cachedb_mongodb module allows to run RAW queries, thus taking full advantage of the capabilities of the back-end.

			The query syntax is a JSON-based one, very similar to the one that one runs commands in the mongo cli. The query results are also returned as JSON documents, that one can further process in the OpenSIPS script by using the JSON module.


The syntax looks like the following :


```c title="Mongo Raw Query Syntax"
...
cache_raw_query("mongodb","{ \"op\" : \"desiredOP\", \"ns\" : \"db.collection\", \"query\": {\"_id\" : $rU} }","$avp(mongo_result)");
...
			
```


The \"op\" JSON entry specifies the actual operation ( find,update,remove, etc ) that you want to run on the Mongo server and the \"ns\" entry specifies the namespace where you want to run that query. The \"ns\" entry can be missing, and the query will be run on the db.collection that was passed at Connection time in the cachedb_url.


The \"query\" entry is the JSON document that specifies the raw query that you want to run.
			The last parameter is an optional AVP parameter, where the JSON documents will be returned ( a find query can return multiple JSON documents, which are correctly populated in the output AVP ). If the query does not return a result, you can ommit the last parameter.


The currently suported operations that you can pass in the \"op\" JSON entry are


- find - the find operation takes an optional \"fields\" JSON document, specifying the desired fields that should be returned from the mongoDB server.
- update - the update operations takes an optional \"match\" JSON document, specifying that only the mongoDB documents that match this JSON will be updated ( similar to the 'where' SQL clause ) . If no \"match\" is provided, all documents will be updated.
- insert
- remove
- count


Here are a couple examples of running some mongoDB queries :


```c title="Mongo Raw Query Examples"
...
/* find documents where my_key has the value 345, and return just the entry1 and entry2 values from the matching documents */
cache_raw_query("mongodb","{ \"op\" : \"find\", \"ns\" : \"my_db.my_col\", \"query\": {\"my_key\" : 345},\"fields\": { \"entry1\" : 1, \"entry2\" : 1 } }","$avp(mongo_result)");

$var(it) = 0;
while ($(avp(mongo_result)[$var(it)]) != NULL) {
	$json(json_res) := $(avp(mongo_result)[$var(it)]);
	xlog("Fetched a new mongo result=$json(json_res). entry1=$json(json_res/entry1) \n");
	$var(it) = $var(it) + 1;
	$json(json_res) = NULL;
}

...
/* insert the {_id: 993, vlad: "opensips",counter: 9000 } document */
cache_raw_query("mongodb","{ \"op\" : \"insert\", \"ns\" : \"some_db.coll\", \"query\": {\"_id\" : 993, \"vlad\" : \"opensips\", \"counter\": 9000} }");
...
/* remove all the documents where "mykey" has the "badvalue" */
cache_raw_query("mongodb","{ \"op\" : \"remove\", \"ns\" : \"db.coll\", \"query\": {\"mykey\" : "badvalue"} }");
...
/* set expired to have the value of 1 in the documents where the counter has the 345 value */
cache_raw_query("mongodb","{ \"op\" : \"update\", \"query\": { \"expired\" : 1}, \"match\" : { \"counter\" : 345 } }");
...
cache_raw_query("mongodb","{ \"op\" : \"count\",\"query\": { \"username\" : $rU} }","$avp(mongo_count_result)");
xlog("We have $avp(mongo_count_result) documents where username = $rU \n");
...
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
