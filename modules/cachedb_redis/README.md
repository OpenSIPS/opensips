---
title: "cachedb_redis Module"
description: "This module is an implementation of a cache system designed to work with a Redis server. It uses hiredis client library to connect to either a single Redis server instance, or to a Redis Server inside a Redis Cluster. It uses the Key-Value interface exported from the core."
---

## Admin Guide


### Overview


This module is an implementation of a cache system designed to work with a
		Redis server. It uses hiredis client library to connect to either a single Redis
		server instance, or to a Redis Server inside a Redis Cluster.
		It uses the Key-Value interface exported from the core.


### Advantages


- *memory costs are no longer on the server*
- *many servers can be used inside a cluster, so the memory
				is virtually unlimited*
- *the cache is 100% persistent. A restart
					of OpenSIPS server will not affect the DB. The Redis DB is also
				persistent so it can also be restarted without loss of information.*
- *redis is an open-source project so
				it can be used to exchange data
				 with various other applications*
- *By creating a Redis Cluster, multiple OpenSIPS
				instances can easily share key-value information*


### Redis Stack Support


Starting with OpenSIPS **3.6**, the *cachedb_redis*
		module implements the column-oriented cacheDB API functions.  This makes it a suitable
		cacheDB storage in scenarios such as user location *federation*
		and *full-sharing*, which require this API to be available.


The implementation makes use of *RedisJSON* and *RediSearch* --
		these relatively new features are available in Redis Stack Server, instead of the usual Redis Server
		(Redis OSS project).  More documentation is available on the Redis website.


OpenSIPS will auto-detect availability of the RedisJSON support when necessary and log
		the appropriate messages.


### Redis Cluster Support (Topology)


When connecting to a Redis Cluster, the module automatically detects
		cluster mode and manages the full slot-to-node topology at runtime.
		No extra configuration is needed beyond the standard
		[cachedb url](#param_cachedb_url) parameter.


#### Topology Discovery


At startup, the module probes the Redis server using the
		*CLUSTER SHARDS* command (available in Redis 7.0+).
		If the server does not support this command, it falls back to
		*CLUSTER SLOTS* (available in Redis 3.0+).
		If neither command succeeds, the connection is treated as a
		single-instance (non-cluster) connection.


The discovered topology is stored internally in an O(1) slot lookup
		table (16384 slots), mapping each slot directly to its owning master
		node.


#### Automatic Topology Refresh


The module automatically refreshes the cluster topology at runtime
		when any of the following events occur:


- A *MOVED* redirection is received from a
				cluster node (indicating a permanent slot migration).
- A *connection failure* (NULL reply) occurs
				and the node cannot be reconnected.
- A *query targets a slot with no known owner*,
				suggesting the topology is stale.
- An operator triggers a manual refresh via the
				[mi redis cluster refresh](#mi_redis_cluster_refresh) MI command.


Automatic refreshes are rate-limited to at most once per second to
		avoid excessive load on the cluster.  The MI-triggered refresh
		bypasses this rate limit.


#### MOVED Redirection


The module transparently handles Redis Cluster MOVED
		redirections:


- *MOVED* — indicates a permanent slot
				migration. The module updates its slot map, redirects the
				query to the new node, and triggers a topology refresh so
				all future queries go directly to the correct node.


If a redirection points to a node that is not yet known, the module
		dynamically creates a new node entry, establishes a connection, and
		retries the query.


#### Hash Tags


The module supports Redis Cluster
		*hash tags*, which allow related keys to be
		co-located on the same cluster node.  If a key contains a
		*{...}* substring, only the content between the
		first *{* and the next *}* is
		used for hash slot calculation.  For example, the keys
		*{user1000}.profile* and
		*{user1000}.settings* will always land on the
		same node, enabling multi-key operations.


If the braces are empty (*{}*) or there is no
		closing brace, the entire key is hashed as usual.


### Limitations


- *keys (in key:value pairs) may not contain spaces or control characters*


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *If a [use tls](#param_use_tls) is defined, the **tls_mgm** and **tls_openssl** modules will need to be loaded as well*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *hiredis:*
On the latest Debian based distributions, hiredis can be installed
				by running 'apt-get install libhiredis-dev'

				Alternatively, if hiredis is not available on your OS repos,
				hiredis can be downloaded from: https://github.com/antirez/hiredis .
				Download the archive, extract sources, run make,sudo make install.
If TLS connections are enabled via the [use tls](#param_use_tls) modparam,
				*hiredis* needs to be compiled with TLS support.


### Exported Parameters


#### cachedb_url (string)


The URLs of the server groups that OpenSIPS will connect to in order
			to use, from script, the cache_store(), cache_fetch(), etc. operations.
			It may be set more than once.  The prefix part of the URL will be
			the identifier that will be used from the script.


```c title="Set cachedb_url parameter"
...
# single-instance URLs (Redis Server or Redis Cluster)
modparam("cachedb_redis", "cachedb_url", "redis:group1://localhost:6379/")
modparam("cachedb_redis", "cachedb_url", "redis:cluster1://random_url:8888/")

# multi-instance URL (will perform circular 
```


```c title="Use Redis servers"
...
cache_store("redis:group1", "key", "$ru value");
cache_fetch("redis:cluster1", "key", $avp(10));
cache_remove("redis:cluster1", "key");
...
		
```


##### Authentication


The module supports three authentication modes based on the URL format:


**URL Authentication Formats**


| URL Format | AUTH Command | Use Case |
| --- | --- | --- |
| `redis:group://:password@host:port/` | `AUTH password` | Classic Redis (< 6.0) with `requirepass` |
| `redis:group://username:password@host:port/` | `AUTH username password` | Redis 6+ ACL with per-user credentials |
| `redis:group://host:port/` | (none) | Non-authenticated Redis |


**Important**: For classic password-only
			authentication, the URL must include a colon before the password
			(`:password@host`). Writing
			`password@host` without the colon will place the
			credential in the username field of the URL parser, and authentication
			will be skipped.


When connecting to a Redis Cluster with authentication, all discovered
			cluster nodes use the same credentials from the URL.


##### Unix Socket


Starting with this version, the module supports connecting to a
			local Redis instance via a Unix domain socket instead of TCP.
			This can provide lower latency and avoid network overhead for
			co-located Redis instances.


To use a Unix socket, add a `socket=` parameter
			to the URL query string:


```c
# basic Unix socket (no auth)
modparam("cachedb_redis", "cachedb_url",
    "redis:local://localhost/?socket=/var/run/redis/redis.sock")

# Unix socket with password auth
modparam("cachedb_redis", "cachedb_url",
    "redis:local://:password@localhost/?socket=/var/run/redis/redis.sock")

# Unix socket with ACL auth (Redis 6+) and database selection
modparam("cachedb_redis", "cachedb_url",
    "redis:local://user:pass@localhost/2?socket=/var/run/redis/redis.sock")
		
```


**Constraints:**


- Unix socket connections are always treated as
				*single-instance* mode (no Redis Cluster
				support over Unix sockets).
- Unix socket cannot be combined with multiple hosts (failover).
				Specifying both will cause a startup error.
- TLS is not applicable to Unix socket connections and will be
				ignored with a warning if `use_tls` is enabled.
- TCP keepalive is not applicable to Unix sockets and is
				automatically skipped.


The [mi redis cluster info](#mi_redis_cluster_info) MI command will display
			Unix socket connections with `transport=unix` and
			the socket path. The [mi redis ping nodes](#mi_redis_ping_nodes) command
			works normally with Unix socket connections.


#### connect_timeout (integer)


This parameter specifies how many milliseconds OpenSIPS should wait
			for connecting to a Redis node.


*Default value is "5000 ms".*


```c title="Set connect_timeout parameter"
...
# wait 1 second for Redis to connect
modparam("cachedb_redis", "connect_timeout",1000)
...
		
```


#### query_timeout (integer)


This parameter specifies how many milliseconds OpenSIPS should wait
			for a query response from a Redis node.


*Default value is "5000 ms".*


```c title="Set query_timeout parameter"
...
# wait 1 second for Redis queries
modparam("cachedb_redis", "query_timeout",1000)
...
		
```


#### shutdown_on_error (integer)


By setting this parameter to 1, OpenSIPS will abort startup if
		the initial connection to Redis is not possible. Runtime reconnect
		behavior is unaffected by this parameter, and is always enabled.


*Default value is "0" (disabled).*


```c title="Set the shutdown_on_error parameter"
...
# abort OpenSIPS startup if Redis is down
modparam("cachedb_redis", "shutdown_on_error", 1)
...
		
```


#### lazy_connect (integer)


By setting this parameter to 1, OpenSIPS will defer establishing
		Redis connections until the first cache operation is actually
		performed by each worker process. This prevents idle worker
		processes (those that never use Redis) from holding open sockets,
		which avoids sockets getting stuck in CLOSE_WAIT state when Redis
		is restarted.


When this parameter is enabled, the
		[shutdown on error](#param_shutdown_on_error) parameter has no effect,
		since no connection is attempted at startup time.


*Default value is "0" (disabled — connect at
		startup, preserving existing behavior).*


```c title="Set the lazy_connect parameter"
...
# defer Redis connections until first use
modparam("cachedb_redis", "lazy_connect", 1)
...
		
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for Redis connections.
		In order to enable TLS for a specific connection, you can use the
		"tls_domain=*dom_name*" URL parameter in the cachedb_url
		of this module (or other modules that use the CacheDB interface). This should
		be placed at the end of the URL after the '?' character.


When using this parameter, you must also ensure that
		*tls_mgm* is loaded and properly configured. Refer to
		the tls_mgm module for additional info regarding TLS client domains.


Note that TLS is supported by Redis starting with version 6.0. Also, it is
		an optional feature enabled at compile time and might not be included in the
		standard Redis packages available for your OS.


*Default value is **0** (not enabled)*


```c title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "redis")
modparam("tls_mgm", "certificate", "[redis]/etc/pki/tls/certs/redis.pem")
modparam("tls_mgm", "private_key", "[redis]/etc/pki/tls/private/redis.key")
modparam("tls_mgm", "ca_list",     "[redis]/etc/pki/tls/certs/ca.pem")
...
modparam("cachedb_redis", "use_tls", 1)
modparam("cachedb_redis", "cachedb_url","redis:tls_group://localhost:6379/?tls_domain=redis")
...
```


#### ftsearch_index_name (string)


Only relevant with *RedisJSON* and
			*RediSearch* server-side support.


A global index name to be used for all internal JSON full-text search operations.
		Future extensions may add, e.g., a connection-level index name setting.


Default value is **"idx:usrloc"**.


```c title="Set the ftsearch_index_name parameter"
modparam("cachedb_redis", "ftsearch_index_name", "ix::usrloc")
```


#### ftsearch_json_prefix (string)


Only relevant with *RedisJSON* and
			*RediSearch* server-side support.


A key naming prefix for all internally-created Redis JSON objects (e.g.
		created with JSON.SET or JSON.MSET).


Default value is **"usrloc:"**.


```c title="Set the ftsearch_json_prefix parameter"
modparam("cachedb_redis", "ftsearch_json_prefix", "userlocation:")
```


#### ftsearch_max_results (integer)


Only relevant with *RedisJSON* and
			*RediSearch* server-side support.


The maximum number of results returned by each internally-triggered
		FT.SEARCH JSON lookup query.


Default value is **10000** max results.


```c title="Set the ftsearch_max_results parameter"
modparam("cachedb_redis", "ftsearch_max_results", 100)
```


#### redis_keepalive (integer)


TCP keepalive interval in seconds for Redis connections. When set
			to a positive value, the kernel sends TCP probes on idle connections
			to detect dead peers (e.g. due to NAT/firewall idle timeout or
			network partition). This allows the next query to fail immediately
			instead of waiting for the full query timeout, enabling faster
			recovery via the existing retry loop.


Set to 0 to disable TCP keepalive. Recommended to keep enabled
			for production deployments to prevent silent connection death.


*Default value is "10" (seconds).*


```c title="Set redis_keepalive parameter"
...
# set TCP keepalive interval to 15 seconds
modparam("cachedb_redis", "redis_keepalive", 15)

# disable TCP keepalive
modparam("cachedb_redis", "redis_keepalive", 0)
...
		
```


#### ftsearch_json_mset_expire (integer)


Only relevant with *RedisJSON* and
			*RediSearch* server-side support.


A Redis EXPIRE timer to set/refresh on the JSON key after each JSON.MSET operation
		(create the JSON or add/remove subkeys), in seconds.  A value of **0**
		disables the EXPIRE queries completely.


Default value is **3600** seconds.


```c title="Set the ftsearch_json_mset_expire parameter"
modparam("cachedb_redis", "ftsearch_json_mset_expire", 7200)
```


### Exported Functions


The module does not export functions to be used
		in configuration script.


### Exported MI Functions


#### redis_cluster_info


Displays detailed information about all Redis connections managed
			by the module, including cluster topology, per-node connection status,
			slot assignments, and per-node query counters.


Parameters:


- *group* (optional) - if specified, only
					connections belonging to this group will be listed (e.g.
					*"local"* from a
					*"redis:local://..."* URL). If omitted,
					all Redis connections are listed.


The response is a JSON array of connection objects. Each connection
			object includes:


- *group* - the connection group name
- *url* - the original cachedb_url
- *mode* - *"cluster"*
					or *"single"*
- *cluster_command* (cluster mode only) -
					*"SHARDS"* or
					*"SLOTS"*, depending on which Redis
					command is used for topology discovery
- *topology_refreshes* - number of topology
					refreshes performed on this connection
- *last_topology_refresh* - UNIX timestamp
					of the last topology refresh
- *nodes* - array of cluster node objects,
					each containing:
					*ip*, *port*,
					*status*
					(*"connected"*/*"disconnected"*),
					*slots_assigned* (cluster mode only),
					*queries*, *errors*,
					*moved*,
					*last_activity* (seconds since last
					successful query, -1 if never queried)
- *total_slots_mapped* (cluster mode only) -
					total number of slots with an assigned node (should be 16384
					for a healthy cluster)


MI FIFO Command Format:


```c
## list all Redis connections
opensips-cli -x mi redis_cluster_info

## list only the "local" group
opensips-cli -x mi redis_cluster_info group=local
			
```


#### redis_cluster_refresh


Forces an immediate topology refresh on Redis Cluster connections.
			This bypasses the normal once-per-second rate limit and queries the
			cluster for its current slot-to-node mapping. Useful after manual
			cluster rebalancing or node additions/removals.


For non-cluster (single instance) connections, the command returns
			a *"skipped (not cluster mode)"* status.


Parameters:


- *group* (optional) - if specified, only
					the connection belonging to this group will be refreshed.
					If omitted, all cluster connections are refreshed.


The response is a JSON array of objects, one per connection, each
			containing *group* and *status*
			(*"ok"*, *"error"*, or
			*"skipped (not cluster mode)"*).


MI FIFO Command Format:


```c
## refresh all cluster connections
opensips-cli -x mi redis_cluster_refresh

## refresh only the "local" group
opensips-cli -x mi redis_cluster_refresh group=local
			
```


#### redis_ping_nodes


Sends a PING command to each Redis node and reports per-node
			reachability status with round-trip latency. Useful for on-demand
			health checks without waiting for the next query.


Parameters:


- *group* (optional) - if specified, only
					nodes belonging to this group will be pinged. If omitted,
					all Redis connections are pinged.


The response is a JSON array of connection objects. Each connection
			object includes:


- *group* - the connection group name
- *nodes* - array of node objects, each
					containing:
					*ip*, *port*,
					*status*
					(*"reachable"*,
					*"unreachable"*, or
					*"disconnected"*),
					*latency_us* (round-trip time in
					microseconds, -1 if not reachable)


MI FIFO Command Format:


```c
## ping all Redis nodes
opensips-cli -x mi redis_ping_nodes

## ping only the "local" group
opensips-cli -x mi redis_ping_nodes group=local
			
```


### Exported Statistics


#### redis_queries


Total number of successful Redis queries executed across all
			connections and processes.


#### redis_queries_failed


Total number of failed Redis queries (NULL replies from hiredis
			or Redis error responses other than MOVED).


#### redis_moved


Total number of MOVED redirections received from Redis Cluster
			nodes. A MOVED response indicates a permanent slot migration -
			the module updates its slot map and retries the query on the
			correct node.


#### redis_topology_refreshes


Total number of cluster topology refreshes performed (via
			CLUSTER SHARDS or CLUSTER SLOTS). This counter increments both
			for automatic refreshes (triggered by MOVED responses or
			unreachable nodes) and manual refreshes (triggered via the
			[mi redis cluster refresh](#mi_redis_cluster_refresh) MI command).


### Raw Query Syntax


The cachedb_redis module allows to run RAW queries, thus taking full advantage of the capabilities of the back-end.

			The query syntax is the typical REDIS one.


Here are a couple examples of running some Redis queries :


```c title="Redis Raw Query Examples"
...
	$var(my_hash) = "my_hash_name";
	$var(my_key) = "my_key_name";
	$var(my_value) = "my_key_value";
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key) $var(my_value)");
	cache_raw_query("redis","HGET $var(my_hash) $var(my_key)","$avp(result)");
	xlog("We have fetched $avp(result) \n");
...
	$var(my_hash) = "my_hash_name";
	$var(my_key1) = "my_key1_name";
	$var(my_key2) = "my_key2_name";
	$var(my_value1) = "my_key1_value";
	$var(my_value2) = "my_key2_value";
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key1) $var(my_value1)");
	cache_raw_query("redis","HSET $var(my_hash) $var(my_key2) $var(my_value2)");
	cache_raw_query("redis","HGETALL $var(my_hash)","$avp(result)");

	$var(it) = 0;
	while ($(avp(result)[$var(it)]) != NULL) {
		xlog("Multiple key reply: - we have fetched $(avp(result)[$var(it)]) \n");
		$var(it) = $var(it) + 1;
	}
...
			
```


## Frequently Asked Questions


**Q: My OpenSIPS is occasionally crashing in libhiredis, what to do?**


Make sure you've upgraded the Redis "libhiredis" client library to at
		least version 0.14.1.  There was at least one significant vulnerability
		reported in library versions prior to that one ([CVE-2020-7105](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2020-7105)),
		so upgrading to latest stable may very well fix the crash!
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
