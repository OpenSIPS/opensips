---
title: "cachedb_cassandra Module"
description: "This module is an implementation of a cache system designed to work with Cassandra servers. It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with
		Cassandra servers.
		It uses the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
				is virtually unlimited*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The Cassandra DB is also
				persistent so it can also be restarted without loss of information.*
- *Cassandra is an open-source project so
				it can be used to exchange data
				 with various other applicationsr*
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


- *thrift 0.6.1*
Thrift 0.6.1 can be downloaded from http://archive.apache.org/dist/thrift/
				Download the archive, extract sources, run ./configure,make,sudo make install.


### Exported Parameters


#### cachedb_url (string)


The urls of the server groups that OpenSIPS will connect to in order
			to use the from script cache_store,cache_fetch, etc operations.
			It can be set more than one time.
			The prefix part of the URL will be the identifier that will be used
			from the script.

			The database part of the URL needs to be in the format Keyspace_ColumnFamily_CounterFamily


```c title="Set cachedb_url parameter"
...
modparam("cachedb_cassandra", "cachedb_url","cassandra:group1://localhost:9061/Keyspace1_Users_Counters");
modparam("cachedb_cassandra", "cachedb_url","cassandra:cluster1://random_url:8888/Keyspace2_Keys_CounterF");
...
	
```


```c title="Use Cassandra servers"
...
cache_store("cassandra:group1","key","$ru value");
cache_fetch("cassandra:cluster1","key",$avp(10));
cache_remove("cassandra:cluster1","key");
...
	
```


#### connection_timeout (int)


The timeout in ms that will be triggered in case a connection attempt fails.


```c title="Set connection_timeout parameter"
...
modparam("cachedb_cassandra", "connection_timeout",1000);
...
	
```


#### send_timeout (int)


The timeout in ms that will be triggered in case a Cassandra write takes too long


```c title="Set send_timeout parameter"
...
modparam("cachedb_cassandra", "send_timeout",1000);
...
	
```


#### receive_timeout (int)


The timeout in ms that will be triggered in case a Cassandra read takes too long


```c title="Set receive_timeout parameter"
...
modparam("cachedb_cassandra", "receive_timeout",1000);
...
	
```


#### wr_consistency_level (int)


The consistency level desired for write operations.
			Options are :


- *1* - Ensure that the write has been written to at least 1 replica's commit log and memory table before responding to the client.
- *2* - Ensure that the write has been written to N / 2 + 1 replicas before responding to the client.
- *3* - Ensure that the write has been written to ReplicationFactor / 2 + 1 nodes, within the local datacenter (requires NetworkTopologyStrategy)
- *4* - Ensure that the write has been written to ReplicationFactor / 2 + 1 nodes in each datacenter (requires NetworkTopologyStrategy)
- *5* - Ensure that the write is written to all N replicas before responding to the client. Any unresponsive replicas will fail the operation.
- *6* - Ensure that the write has been written to at least 1 node, including HintedHandoff recipients.
- *7* - Ensure that the write has been written to at least 2 replica's before responding to the client.
- *8* - Ensure that the write has been written to at least 3 replica's before responding to the client.


Default is 1


```c title="Set wr_consistency_level parameter"
...
modparam("cachedb_cassandra", "wr_consistency_level",7);
...
	
```


#### rd_consistency_level (int)


The consistency level desired for read operations.
			Options are the same as for write consistency level.


```c title="Set rd_consistency_level parameter"
...
modparam("cachedb_cassandra", "rd_consistency_level",7);
...
	
```


#### exec_threshold (int)


The maximum number of microseconds that a cassandra cache query can last.
			Anything above the threshold will trigger a warning message to the log


*Default value is "0 ( unlimited - no warnings )".*


```c title="Set exec_threshold parameter"
...
modparam("cachedb_cassandra", "exec_threshold", 100000)
...
	
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Known Issues


Due to the fact that Cassandra cannot store counters and regular columns in the same ColumnFamily, add() and sub() methods are not exported through the Key-Value interface.


Also, the module does not currently support Authentication.


Future realeases of this module will address this issue.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
