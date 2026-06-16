---
title: "cachedb_cassandra Module"
description: "This module is an implementation of a cache system designed to work with Cassandra servers. It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with
		Cassandra servers.
		It uses the Key-Value interface exported from the core.


The underlying client library is compatible with Cassandra versions 2.1+.


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
				is virtually unlimited*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The Cassandra DB is also
				persistent so it can also be restarted without loss of information.*
- *Cassandra is an open-source project so
				it can be used to exchange data
				 with various other applications*
- *By creating a Cassandra Cluster, multiple OpenSIPS
				instances can easily share key-value information*


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


None.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libuv*
- *cassandra-cpp-driver*


The DataStax C/C++ driver for Cassandra and the libuv dependency
				can be downloaded from: [http://downloads.datastax.com/cpp-driver/](http://downloads.datastax.com/cpp-driver/).


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.


Cassandra does not support regular columns in a table that contains any
		counter columns so in order to use the add()/sub()/get_counter() methods
		in the Key-Value Interface you can specify an extra table reserved
		only for counters.


The database part of the URL needs to be in the format *Keyspace.Table[.CountersTable]*.


```c title="Set cachedb_url parameter"
...
modparam("cachedb_cassandra", "cachedb_url",
	"cassandra:group1://localhost:9042/keyspace1.users.counters")

# Defining multiple contact points for a Cassandra cluster
modparam("cachedb_cassandra", "cachedb_url",
	"cassandra:cluster1://10.0.0.10,10.0.0.15/keyspace2.keys.counters")
...
	
```


```c title="Use Cassandra servers"
...
cache_store("cassandra:group1","key","$ru value");
cache_fetch("cassandra:cluster1","key",$avp(10));
cache_remove("cassandra:cluster1","key");
...
	
```


#### connect_timeout (int)


The timeout in ms that will be triggered in case a connection attempt fails.


*Default value is "5000".*


```c title="Set connect_timeout parameter"
...
modparam("cachedb_cassandra", "connect_timeout",1000);
...
	
```


#### query_timeout (int)


The timeout in ms that will be triggered in case a Cassandra query takes too long.


*Default value is "5000".*


```c title="Set query_timeout parameter"
...
modparam("cachedb_cassandra", "query_timeout",1000);
...
	
```


#### wr_consistency_level (int)


The consistency level desired for write operations.
			Options are :


- *all* - A write must be written to the commit log and memtable on all replica nodes in the cluster for that partition.
- *each_quorum* - Strong consistency. A write must be written to the commit log and memtable on a quorum of replica nodes in each datacenter.
- *quorum* - A write must be written to the commit log and memtable on a quorum of replica nodes across all datacenters.
- *local_quorum* - Strong consistency. A write must be written to the commit log and memtable on a quorum of replica nodes in the same datacenter as the coordinator. Avoids latency of inter-datacenter communication.
- *one* - A write must be written to the commit log and memtable of at least one replica node.
- *two* - A write must be written to the commit log and memtable of at least two replica node.
- *three* - A write must be written to the commit log and memtable of at least three replica node.
- *local_one* - A write must be sent to, and successfully acknowledged by, at least one replica node in the local datacenter.
- *any* - A write must be written to at least one node. If all replica nodes for the given partition key are down, the write can still succeed after a hinted handoff has been written. If all replica nodes are down at write time, an ANY write is not readable until the replica nodes for that partition have recovered.


Default value is *one*.


```c title="Set wr_consistency_level parameter"
...
modparam("cachedb_cassandra", "wr_consistency_level", "each_quorum");
...
	
```


#### rd_consistency_level (int)


The consistency level desired for write operations.
			Options are :


- *all* - Returns the record after all replicas have responded. The read operation will fail if a replica does not respond.
- *quorum* - Returns the record after a quorum of replicas from all datacenters has responded.
- *local_quorum* - Returns the record after a quorum of replicas in the current datacenter as the coordinator has reported. Avoids latency of inter-datacenter communication.
- *one* - Returns a response from the closest replica, as determined by the snitch. By default, a read repair runs in the background to make the other replicas consistent.
- *two* - Returns the most recent data from two of the closest replicas.
- *three* - Returns the most recent data from three of the closest replicas.
- *local_one* - Returns a response from the closest replica in the local datacenter.
- *serial* - Allows reading the current (and possibly uncommitted) state of data without proposing a new addition or update. If a SERIAL read finds an uncommitted transaction in progress, it will commit the transaction as part of the read. Similar to QUORUM.
- *local_serial* - Same as SERIAL, but confined to the datacenter. Similar to LOCAL_QUORUM.


Default value is *one*.


```c title="Set rd_consistency_level parameter"
...
modparam("cachedb_cassandra", "rd_consistency_level", "quorum");
...
	
```


#### exec_threshold (int)


A cassandra cache query that lasts more than this threshold will
			trigger a warning message to the log.


This value, if set, only makes sense to be lower than the
			[query timeout](#param_query_timeout) since any query taking longer
			than that value will be dropped anyway.


*Default value is "0 ( unlimited - no warnings )".*


```c title="Set exec_threshold parameter"
...
modparam("cachedb_cassandra", "exec_threshold", 100000)
...
	
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Table Schema


The table required for supporting the cache_store()/cache_fetch()/cache_remove()
		functions of the Key-Value interface needs to have at least the following columns:


- *opensipskey* - as the primary key with type "text"
- *opensipsval* - with type "text"


The table required for supporting the cache_add()/cache_sub()/cache_counter_fetch()
		functions of the Key-Value interface needs to have at least the following columns:


- *opensipskey* - as the primary key with type "text"
- *opensipsval* - with type "counter"
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
