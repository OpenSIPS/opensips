---
title: "usrloc Module"
description: "A SIP user location implementation. Its main purpose is to store, manage and provide access to SIP registration bindings (contacts) for other modules (e.g. registrar, mid-registrar, nathelper, etc.). The module exports no functions that could be directly used from the OpenSIPS script."
---

## Admin Guide


### Overview


A SIP user location implementation. Its main purpose is to store,
		manage and provide access to SIP registration bindings (contacts) for
		other modules (e.g. registrar, mid-registrar, nathelper, etc.). The
		module exports no functions that could be directly used from the
		OpenSIPS script.


At runtime, the contacts may reside in memory, in an SQL database or in
		a NoSQL database. Combinations of two of the above are also possible.
		For example, contacts may only be directly manipulated in memory in
		order to guarantee fast interactions while being asynchronously
		synchronized to an SQL database. The latter helps achieve restart
		persistency. Consult the
		**[working mode preset](#param_working_mode_preset)**
		parameter for more details on all possible runtime behaviors of the
		module.


The OpenSIPS user location implementation is cluster-enabled. On top of
		supporting traditional "single instance" setups, it also allows multiple
		OpenSIPS user location nodes to form a single, global user location cluster.
		This allows high-level features such as startup synchronization (data
		tunneling) from a random, healthy "donor" node and evenly distributed
		NAT pinging workloads.


### Distributed SIP User Location


Starting with OpenSIPS 2.4, the user location module offers several optional
	data distribution models, each tailoring to specific real-life production use cases.
	Built on top of the OpenSIPS clustering module, these models take into
	account service concerns such as *high availability, geographical
	distribution, horizontal scalability and NAT traversal*.


Depending on data locality, the distribution models are split in two main
	categories:


#### "Federation" Topology


A *federated* user location keeps contact data local
		to the original OpenSIPS node the contact initially registered to. In
		order to share the reachability of these contacts with the global
		OpenSIPS user location cluster, registrar nodes will only publish some
		light "metadata" entries for any new Addresses-of-Record which are
		reachable from them. These entries will cause other nodes to also fork
		additional SIP branches pointing to the publisher registrar upon
		receiving calls for its advertised Addresses-of-Record.


The **federation** topology is an
		optimized solution for the following core problems:


- **IP address restrictions** - In some
			cases, calls routed towards registered contacts must necessarily
			pass through the original registration nodes of these contacts. A
			classic example of this situation is when an OpenSIPS registrar
			sitting at the edge of the platform is directly facing a NAT device
			on the way to the contact. Unless calls are sent out from this
			exact registrar, they will not be able to traverse the NAT device
			and reach the contact.
- **horizontal scalability** - Avoiding
			global replication/contact broadcasting within the cluster not only
			dramatically improves contact storage performance, but also leads
			to better service scalability. Different geographical locations can
			be sized according to their local subscriber populations (traffic
			may be balanced to them using DNS SRV weights, for example),
			without losing platform-wide reachability.


Currently, the metadata information may be published to NoSQL databases
		which support key/multi-value column-like associations. Example known
		backends to support these abstractions at the time of writing are
		MongoDB and Cassandra.


The [federated user location tutorial](https://docs.opensips.org/tutorials-distributed-user-location-federation)
		contains precise details on how to achieve this setup (including High
		Availability support).


#### "Full Sharing" Topology


A *fully sharing* user location broadcasts contact
		information to all data nodes (OpenSIPS or NoSQL).
		The main assumption behind this mode is that any routing
		restrictions have been alleviated beforehand. Consequently, either SIP
		traffic egressing from a "full sharing"
		OpenSIPS user location topology is being intermediated by an
		additional SIP edge endpoint of our platform, or there are no egress IP
		restrictions at all (for example, if all SIP UAs have public IPs). In
		this setup, all OpenSIPS user location nodes are
		*equivalent* to one another, as they each have
		access to the same dataset and have no routing restrictions.


The **full sharing** topology is
		an appropriate solution for multi-layer VoIP platforms, where the
		OpenSIPS registrar nodes do not directly interact with external SIP
		endpoints. Moreover, it can be configured to fully store contact data
		within a NoSQL cluster (zero in-memory storage), thus taking full
		advantage of the data sharing, sharding, migration and other
		capabilities of a specialized distributed data handling engine.


Additionally, a "full sharing" topology can be used to achieve a basic
		"hot backup" high-availability setup with an active-passive registrar
		nodes configuration, both of which make use of a shared virtual IP.


Registrations may optionally be fully managed inside NoSQL
		databases which support key/multi-value column-like associations.
		Example known backends to currently support these abstractions are MongoDB
		and Apache Cassandra.


The ["full sharing" user location tutorial](https://docs.opensips.org/tutorials-distributed-user-location-full-sharing)
		contains precise details on how to achieve this setup (including full
		NoSQL storage support).


#### "N Contact Pings" Problem


A long-standing problem caused by contact information being replicated
		to multiple SIP registrar instances directly through replication or
		indirectly through a globally reachable database. As long as
		traditionally clusterized nodes are not aware of
		each other, they will each scan the entire contact dataset, thus
		periodically sending "N pings" instead of "1 ping" for each contact.
		This difference directly affects service scalability, as well as the
		amount of consumed resources such as CPU and network
		bandwidth, both on the service and client side.


This problem is solved with the help of the OpenSIPS cluster layer,
		which makes all nodes aware of each others' presence. Thus, the
		distributed user location node topologies are able to collectively
		partition the pinging workload and spread it evenly across the current
		number of cluster nodes, at any given point in time.  The
		[pinging mode](#param_pinging_mode) module parameter describes the
		built-in pinging heuristics in more detail.


### Contact matching


Contact matching (for the same Address-of-Record, AoR) is an important
	aspect of a SIP user location service, especially in the context of NAT
	traversal. The latter raises more problems, since contacts from different
	phones of same users may overlap (if behind NATs with identical
	configurations) or the re-register Contact of the same SIP User Agent may
	be seen as a new one (due to the request arriving via a new NAT binding).


The SIP RFC 3261 publishes a matching algorithm based only on the
	contact string with Call-ID and CSeq number extra checking (if the Call-ID
	matches, it must have a higher CSeq number, otherwise the registration is
	invalid). But as argumented above, this is not enough in a NAT traversal
	context, so the OpenSIPS implementation of contact matching offers more
	algorithms:


- *Contact based only* - strict RFC 3261
			compliancy - the contact is matched as string and extra checked
			via Call-ID and CSeq (if Call-ID is the same, it must have a
			higher CSeq number, otherwise the registration is invalid).
- *Contact and Call-ID based* - an extension
			of the first case - the Contact and Call-ID header field values
			must match as strings; the CSeq must be higher than the previous
			one - so be careful how you deal with REGISTER retransmissions in
			this case.


For more details on how to control/select the contact matching algorithm,
	please go to
	**[matching mode](#param_matching_mode)**.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Optionally an SQL database module*.
- *Optionally a NoSQL database module*.
- *clusterer, if [cluster mode](#param_cluster_mode)
				is different than "none".*


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### nat_bflag (string)


The name of the branch flag to be used as NAT marker (if the contact
		is or not natted). This is a branch flag and it will be imported and
		used by all other modules depending on the usrloc module.


*Default value is NULL (not set).*


```c title="Set nat_bflag parameter"
...
modparam("usrloc", "nat_bflag", "NAT_BFLAG")
...
```


#### contact_id_column (string)


Name of the column holding the unique contact IDs.


*Default value is "contact_id".*


```c title="Set contact_id_column parameter"
...
modparam("usrloc", "contact_id_column", "ctid")
...
```


#### user_column (string)


Name of column containing usernames.


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("usrloc", "user_column", "username")
...
```


#### domain_column (string)


Name of column containing domains.


*Default value is "domain".*


```c title="Set user_column parameter"
...
modparam("usrloc", "domain_column", "domain")
...
```


#### contact_column (string)


Name of column containing contacts.


*Default value is "contact".*


```c title="Set contact_column parameter"
...
modparam("usrloc", "contact_column", "contact")
...
```


#### expires_column (string)


Name of column containing expires value.


*Default value is "expires".*


```c title="Set expires_column parameter"
...
modparam("usrloc", "expires_column", "expires")
...
```


#### q_column (string)


Name of column containing q values.


*Default value is "q".*


```c title="Set q_column parameter"
...
modparam("usrloc", "q_column", "q")
...
```


#### callid_column (string)


Name of column containing callid values.


*Default value is "callid".*


```c title="Set callid_column parameter"
...
modparam("usrloc", "callid_column", "callid")
...
```


#### cseq_column (string)


Name of column containing cseq numbers.


*Default value is "cseq".*


```c title="Set cseq_column parameter"
...
modparam("usrloc", "cseq_column", "cseq")
...
```


#### methods_column (string)


Name of column containing supported methods.


*Default value is "methods".*


```c title="Set methods_column parameter"
...
modparam("usrloc", "methods_column", "methods")
...
```


#### flags_column (string)


Name of column to save the internal flags of the record.


*Default value is "flags".*


```c title="Set flags_column parameter"
...
modparam("usrloc", "flags_column", "flags")
...
```


#### cflags_column (string)


Name of column to save the branch/contact flags of the record.


*Default value is "cflags".*


```c title="Set cflags_column parameter"
...
modparam("usrloc", "cflags_column", "cflags")
...
```


#### user_agent_column (string)


Name of column containing user-agent values.


*Default value is "user_agent".*


```c title="Set user_agent_column parameter"
...
modparam("usrloc", "user_agent_column", "user_agent")
...
```


#### received_column (string)


Name of column containing the source IP, port, and protocol from the REGISTER
		message.


*Default value is "received".*


```c title="Set received_column parameter"
...
modparam("usrloc", "received_column", "received")
...
```


#### socket_column (string)


Name of column containing the received socket information (IP:port)
		for the REGISTER message.


*Default value is "socket".*


```c title="Set socket_column parameter"
...
modparam("usrloc", "socket_column", "socket")
...
```


#### path_column (string)


Name of column containing the Path header.


*Default value is "path".*


```c title="Set path_column parameter"
...
modparam("usrloc", "path_column", "path")
...
```


#### sip_instance_column (string)


Name of column containing the SIP instance.


*Default value is "NULL".*


```c title="Set sip_instance_column parameter"
...
modparam("usrloc", "sip_instance_column", "sip_instance")
...
```


#### kv_store_column (string)


Name of column containing generic key-value data.


*Default value is "kv_store".*


```c title="Set kv_store_column parameter"
...
modparam("usrloc", "kv_store_column", "json_data")
...
```


#### attr_column (string)


Name of column containing additional registration-related information.


*Default value is "attr".*


```c title="Set attr_column parameter"
...
modparam("usrloc", "attr_column", "attributes")
...
```


#### use_domain (boolean)


Denotes whether the *domain* part of the user should
		also be saved and used for identifying the user, along with the
		*username* part.  Useful in multi-domain scenarios.


*Default value is *true* (enabled).*


```c title="Set use_domain parameter"
...
modparam("usrloc", "use_domain", true)
...
```


#### desc_time_order (integer)


If the user's contacts should be kept timestamp ordered; otherwise the
		contact will be ordered based on q value.
		Non 0 value means true.


*Default value is "0 (false)".*


```c title="Set desc_time_order parameter"
...
modparam("usrloc", "desc_time_order", 1)
...
```


#### timer_interval (integer)


Number of seconds between two timer runs.  During each run, the module
		will update/delete dirty/expired contacts from memory and/or mirror
		these operations to the database, if configured to do so.


> [!WARNING]
> In case of an OpenSIPS shutdown or even a crash, contacts which are in
		memory only and have not been flushed yet to disk will NOT get lost!
		OpenSIPS will try its best to do a last-minute sync to DB right before
		shutting down.


*Default value is 60.*


```c title="Set timer_interval parameter"
...
modparam("usrloc", "timer_interval", 120)
...
```


#### db_url (string)


URL of the database that should be used.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set db_url parameter"
...
modparam("usrloc", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### cachedb_url (string)


URL of a NoSQL database to be used. Only required in a
		cachedb-enabled
		**[cluster mode](#param_cluster_mode)**.


*Default value is "none".*


```c title="Set cachedb_url parameter"
...
modparam("usrloc", "cachedb_url", "mongodb://10.0.0.4:27017/opensipsDB.userlocation")
...
```


#### working_mode_preset (string)


A pre-defined working mode for the usrloc module.  Setting this
		parameter will override any [cluster mode](#param_cluster_mode),
		[restart persistency](#param_restart_persistency) and
		[sql write mode](#param_sql_write_mode) settings.


- **"single-instance-no-db"** - This
			disables database completely. Only memory will be used.
			Contacts will not survive restart. Use this value if you need a
			really fast usrloc and contact persistence is not necessary or
			is provided by other means.
- **"single-instance-sql-write-through"**
			- Write-Through scheme. All changes to usrloc are immediately
			reflected in database too. This is very slow, but very reliable.
			Use this scheme if speed is not your priority but need to make
			sure that no registered contacts will be lost during crash or
			reboot.
- **"single-instance-sql-write-back"**
			- Write-Back scheme. This is a combination of previous two
			schemes. All changes are made to memory and database
			synchronization is done in the timer. The timer deletes all
			expired contacts and flushes all modified or new contacts to
			database.  Use this scheme if you encounter high-load peaks
			and want them to process as fast as possible. The mode will
			not help at all if the load is high all the time.  The
			added latency on the SIP signaling when using this asynchronous
			preset is much lower than the one added by the safe but
			blocking, "single-instance-sql-write-through" preset.
- **"sql-only"** -
			DB-Only scheme. No memory cache is kept, all operations being
			directly performed with the database. The timer deletes all
			expired contacts from database - cleans after clients that didn't
			un-register or re-register. The mode is useful if you configure
			more servers sharing the same DB without any replication at SIP
			level. The mode may be slower due the high number of DB operation.
			For example NAT pinging is a killer since during each ping cycle
			all nated contact are loaded from the DB; The lack of memory
			caching also disable the statistics exports.
- **"federation-cachedb-cluster"** -
			OpenSIPS will run with a "federation-cachedb"
			[cluster mode](#param_cluster_mode) and
			"sync-from-cluster" [restart persistency](#param_restart_persistency).
			This will require the configuration of multiple "seed" nodes in
			the cluster. Refer to the [federated user location tutorial](https://docs.opensips.org/tutorials-distributed-user-location-federation) for more
			details.
- **"full-sharing-cluster"** -
			OpenSIPS will run with a "full-sharing"
			[cluster mode](#param_cluster_mode) and
			"sync-from-cluster" [restart persistency](#param_restart_persistency).
			This will require the configuration of one of the nodes in the cluster
			as a "seed" node in order to bootstrap the syncing process.
- **"full-sharing-cachedb-cluster"** -
			OpenSIPS will run with a "full-sharing-cachedb"
			[cluster mode](#param_cluster_mode), where all location data strictly
			resides in a NoSQL database, thus it will have natural restart
			persistency.


Refer to section
		[distributed sip user location](#distributed_sip_user_location) for details
		regarding the clustering topologies and their behavior.


*Default value is "single-instance-no-db".*


```c title="Set working_mode_preset parameter"
...
modparam("usrloc", "working_mode_preset", "full-sharing-cachedb-cluster")
...
```


#### cluster_mode (string)


**This parameter will get overridden if either
			[working mode preset](#param_working_mode_preset) or
			[db mode](#param_db_mode) is set.**


The behavior of the global OpenSIPS user location cluster. Refer to
		section [distributed sip user location](#distributed_sip_user_location) for details.


This parameter may take the following values:


- *"none"* - single instance mode.
- *"federation-cachedb"* -
				federation-based data sharing. Local AoR metadata is published
				inside a NoSQL database, so other cluster nodes can fork SIP
				traffic over to the current node. Consequently, the
				[location cluster](#param_location_cluster) and
				[cachedb url](#param_cachedb_url) parameters are mandatory.
- *"full-sharing"* -
				Broadcast contact updates (full-mesh mirroring) to all other
				OpenSIPS cluster participants.  Each node will hold the entire
				user location dataset.  Consequently, the
				[location cluster](#param_location_cluster) parameter is mandatory.
- *"full-sharing-cachedb"* -
				Full contact data management through the use of a NoSQL
				database (somewhat resembling the "sql-only" preset).
				The cluster layer is still required in order to
				be able to partition and spread the pinging workload evenly
				among participating OpenSIPS nodes. Consequently, the
				[location cluster](#param_location_cluster) and
				[cachedb url](#param_cachedb_url) parameters are mandatory.
- *"sql-only"* -
				Multiple OpenSIPS boxes using a common
				[db url](#param_db_url) without necessarily being aware
				of each other.


*Default value is *"none" (single instance mode)*.*


```c title="Set cluster_mode parameter"
...
modparam("usrloc", "cluster_mode", "federation-cachedb")
...
```


#### restart_persistency (string)


**This parameter will get overridden if either
			[working mode preset](#param_working_mode_preset) or
			[db mode](#param_db_mode) are set.**


Controls the behavior of the OpenSIPS user location following a
		restart. This parameter has no effect in some database-only working
		mode presets, where restart persistency is naturally ensured.


This parameter may take the following values:


- *"none"* - no explicit data
				synchronization following a restart. The node starts empty.
- *"load-from-sql"* - enable
				SQL-based restart persistency. This causes all runtime
				in-memory writes (i.e. new registrations, re-registrations or
				de-registrations) to also propagate to an SQL database, from
				which all data will be imported following a restart.
				Choosing this value will make the [db url](#param_db_url)
				parameter mandatory, as well as cause
				[sql write mode](#param_sql_write_mode) to default to "write-back"
				instead of "none".
- *"sync-from-cluster"* - enable
				cluster-based restart persistency. Following a restart,
				an OpenSIPS cluster node will search for a healthy "donor" node
				from which to mirror the entire user location dataset via
				direct cluster sync (TCP-based, binary-encoded data transfer).
				Depending on the clustering mode and cluster topology, this will
				require the configuration of one or multiple "seed" nodes in the cluster.
				Choosing this value will make the
				[location cluster](#param_location_cluster) parameter mandatory.


*Default value is
			*"none" (no restart persistency)*.*


```c title="Set restart_persistency parameter"
...
modparam("usrloc", "restart_persistency", "sync-from-cluster")
...
```


#### sql_write_mode (string)


**This parameter will get overridden if either
			[working mode preset](#param_working_mode_preset) or
			[db mode](#param_db_mode) are set.**


Only valid if [restart persistency](#param_restart_persistency) is enabled.
		Controls the runtime behavior of OpenSIPS writes to the SQL database.


This parameter may take the following values:


- *"none"* - do not perform any
				additional SQL writes at runtime to an SQL database in order
				to specifically ensure restart persistency.
- *"write-through"* - all in-memory
				writes (i.e. new registrations, re-registrations or
				de-registrations) also propagate into the SQL database, inline.
				While this will definitely slow down registration performance
				(lookups are served from memory!), it has the advantage of
				making the instance crash-safe.
- *"write-back"* - all in-memory
				writes (i.e. new registrations, re-registrations or
				de-registrations) eventually also propagate into the SQL
				database, thanks to a separate timer routine. This dramatically
				speeds up registrations, but also introduces the
				possibility of crashing before the latest contact changes are
				propagated to the database. See the
				[timer interval](#param_timer_interval) for additional configuration.


*Default value is *"none" (no added SQL writes)*.*


```c title="Set sql_write_mode parameter"
...
modparam("usrloc", "sql_write_mode", "write-back")
...
```


#### matching_mode (integer)


What contact matching algorithm to be used. Refer to section
		[contact matching](#contact_matching) for the description of the
		algorithms.


The parameter may take the following values:


- *0* - CONTACT ONLY based matching
				algorithm.
- *1* - CONTACT and CALLID based
				matching algorithm.


*Default value is *0 (CONTACT_ONLY)*.*


```c title="Set matching_mode parameter"
...
modparam("usrloc", "matching_mode", 1)
...
```


#### cseq_delay (integer)


Delay (in seconds) for accepting as retransmissions register requests
		with same Call-ID and Cseq. The delay is calculated starting from the
		receiving time of the first register with that Call-ID and Cseq.


Retransmissions within this delay interval will be accepted and replied
		as the original request, but no update will be done in location. If the
		delay is exceeded, error is reported.


A value of 0 disable the retransmission detection.


*Default value is "20 seconds".*


```c title="Set cseq_delay parameter"
...
modparam("usrloc", "cseq_delay", 5)
...
```


#### location_cluster (integer)


Specifies the cluster ID which this instance will send to and receive
		from all user-location related information
        (*addresses-of-record*, *contacts*),
		organized into specific events (inserts, deletes or updates).


This OpenSIPS cluster exposes the **"usrloc-contact-repl"**
capability in order to mark nodes as eligible for becoming data donors during an
arbitrary sync request. Consequently, the cluster must have *at least
one node* marked with the **"seed"** value
as the *clusterer.flags* column/property in order to be fully functional.
Consult the [clusterer - Capabilities](../clusterer#capabilities)
chapter for more details.


Default value is 0 (replication disabled).


More details on the user location distribution mechanisms are
		available under [distributed sip user location](#distributed_sip_user_location).


```c title="Setting the location_cluster parameter"
...
modparam("usrloc", "location_cluster", 1)
...
```


#### ha_cluster (integer)


Only relevant in **"federation-cachedb"**
		[cluster mode](#param_cluster_mode).  Denotes the HA cluster ID to use in
		order to establish the active node within the HA pair, such that only
		that node performs WRITE operations to CacheDB.


Default value is 0 (disabled).


```c title="Setting the ha_cluster parameter"
...
modparam("usrloc", "ha_cluster", 4)
...
```


#### ha_shtag (string)


Only relevant in **"federation-cachedb"**
		[cluster mode](#param_cluster_mode).  Denotes the HA cluster sharing tag to
		use in order to establish the active node within the HA pair, such that
		only that node performs WRITE operations to CacheDB.


Default value is NULL (disabled).


```c title="Setting the ha_shtag parameter"
...
modparam("usrloc", "ha_shtag", "vip2")
...
```


#### skip_replicated_db_ops (int)


Prevent OpenSIPS from performing any DB-related contact operations
		when events are received over the *Binary Interface*.
		This is commonly used to prevent unneeded duplicate operations.


Default value is "0" (upon receival of usrloc-related Binary Interface
		events, DB queries may be freely performed)


More details on the user location replication mechanism are available
		in [distributed sip user location](#distributed_sip_user_location)


```c title="Setting the skip_replicated_db_ops parameter"
...
modparam("usrloc", "skip_replicated_db_ops", 1)
...
```


#### max_contact_delete (int)


Relevant only in WRITE_THROUGH or WRITE_BACK schemes. The maximum
		number of contacts to be deleted from the database at once. Will delete
		all of them, if fewer after passing through all the contacts.


Default value is "10"


```c title="Setting the max_contact_delete parameter"
...
modparam("usrloc", "max_contact_delete", 10)
...
```


#### hash_size (integer)


The number of entries of the hash table used by usrloc to store the
		location records is 2^hash_size. For hash_size=4, the number of entries
		of the hash table is 16. Since version 2.2, the maximu size of this
		parameter is 16, meaning that the hash supports maximum 65536 entries.


*Default value is "9".*


```c title="Set hash_size parameter"
...
modparam("usrloc", "hash_size", 10)
...
```


#### regen_broken_contactid (integer)


Since version 2.2, **contact_id** concept
		was introduced. Since this parameter validates a contact each time OpenSIPS
		is started, there are times when the value of this parameter should be
		regenerated. That is when **location** table
		is being migrated from a version older than 2.2 or when
		**hash_size** module parameter is changed.
		Enabling this parameter will regenerate broken contact id's based on
		current configurations.


*Default value is "0(not enabled)"*


```c title="Set regen_broken_contactid parameter"
...
modparam("usrloc", "regen_broken_contactid", 1)
...
```


#### latency_event_min_us (integer)


Defines a minimal pinging latency threshold, in microseconds, past
		which contact pinging latency update events will get raised. By
		default, an event is raised for each ping reply (i.e. latency update).


If both [latency event min us](#param_latency_event_min_us) and
		[latency event min us delta](#param_latency_event_min_us_delta) are set, the event
		will get raised if either of them is true.


*Default value is "0 (no bottom limit set)".*


```c title="Set latency_event_min_us parameter"
...
# raise an event for any 425+ ms pinging latency
modparam("usrloc", "latency_event_min_us", 425000)
...
```


#### latency_event_min_us_delta (integer)


Defines a minimal, absolute pinging latency difference, in
		microseconds, past which contact pinging latency update events will get
		raised. The difference is computed using the latencies of the last two
		contact pinging replies. By default, an event is raised for each ping
		reply (i.e. latency update).


If both [latency event min us](#param_latency_event_min_us) and
		[latency event min us delta](#param_latency_event_min_us_delta) are set, the event
		will get raised if either of them is true.


*Default value is "0 (no minimal latency delta set)".*


```c title="Set latency_event_min_us_delta parameter"
...
# raise an event only if a contact has pinging latency swings of 300+ ms
modparam("usrloc", "latency_event_min_us_delta", 300000)
...
```


#### pinging_mode (string)


Depending on the [cluster mode](#param_cluster_mode), the module
		can perform contact pinging using one of two possible heuristics:


- **"ownership"** - this instance
				will only attempt to ping a contact if it decides it is the
				logical owner of the contact.  If a shared tag is attached to
				a contact, a node will keep sending pings to that contact as
				long as it owns the respective tag.  If no shared tag has been
				specified for a given contact, the default is to assume
				permanent ownership of the contact and ping it upon request.
- **"cooperation"** - the
				assumption behind this pinging heuristic is that all
				user location cluster nodes are symmetrical (possibly
				front-ended by a SIP traffic balancing entity), such that
				**either** of them can ping
				**any** contact.
				Under this assumption, all currently online user location
				cluster nodes will cooperate and evenly split the pinging
				workload between them by hashing AoRs modulo
				current_number_of_online_nodes, and only picking the ones that
				they are responsible for.


**Possible values for the "pinging_mode",
				depending on the current "cluster_mode"**


|  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- |
| [cluster mode](#param_cluster_mode) | none | federation-cachedb | full-sharing | full-sharing-cachedb | sql-only |
| [pinging mode](#param_pinging_mode) | **ownership** | **ownership** | **cooperation** / ownership | **cooperation** | *unmaintained* |


Notice that only the **"full-sharing"**
			clustering mode allows some flexibility -- all other modes are
			logically tied to a single pinging logic.  Any unaccepted value,
			according to the above table, set
			for those modes will be silently discarded.


```c title="Set pinging_mode parameter"
...
# prepare an active/backup "full-sharing" setup, with no front-end
modparam("usrloc", "pinging_mode", "ownership")
...
```


#### mi_dump_kv_store (integer)


Enable in order to include the "KV-Store" field in all usrloc MI
		commands which output AoR or Contact representations.  This verbose
		field contains custom data attached to each of these two entities.
		mid_registrar makes use of both of these holders, for example.


*Default value is "0 (disabled)".*


```c title="Set mi_dump_kv_store parameter"
...
# include the "KV-Store" key in all usrloc MI output
modparam("usrloc", "mi_dump_kv_store", 1)
...
```


#### contact_refresh_timer (boolean)


Enable a timer which will periodically scan a sorted list of contacts
		and raise the [E UL CONTACT REFRESH](#event_e_ul_contact_refresh) for any of
		them which are past their re-registration time interval limit.  This
		limit may given by registrar's *pn_trigger_interval*
		module parameter, for example.


*Default value is "false (disabled)".*


```c title="Set contact_refresh_timer parameter"
...
modparam("usrloc", "contact_refresh_timer", true)
...
```


### Exported Functions


#### ul_add_key(domain, aor, key_name, [key_value])


Append a Key/Value to the Key-Value-Store of a Usrloc-Record.


Returns false, if no record is found is usrloc.


Meaning of the parameters is as follows:


- *domain (string)* - Domain of the
			        AOR, e.g. "location"
- *aor (string)* - Address-of-Record,
			        save the key for a specific (registered) user.
- *key (string)* - The name of the
			        key to be stored.
- *value (string, optional)*
			        - The value to be stored. Not providing the value or
			        by providing an empty value, will delete the entry.


This function can be used in ANY route.


```c title="ul_add_key usage"
...
ul_add_key("location", "$tU@$td", "service_route", "$hdr(Service-Route)");
...
```


#### ul_get_key(domain, aor, key_name, destination)


Retrieve a Key/Value from the Key-Value-Store of a Usrloc-Record.


Returns false, if no record is found is usrloc or no according key is found.


Meaning of the parameters is as follows:


- *domain (string)* - Domain of the
			        AOR, e.g. "location"
- *aor (string)* - Address-of-Record,
			        save the key for a specific (registered) user.
- *key (string)* - The name of the
			        key to be retrieved.
- *destination (variable)*
			        - A variable, where to store the retrieved key.


This function can be used in ANY route.


```c title="ul_get_key usage"
...
if (ul_get_key("location", "$tU@$td", "service_route", $avp(service_route))) {
        append_to_reply("Service-Route: $avp(service_route)\r\n");
}
...
```


#### ul_del_key(domain, aor, key_name)


Deletes a Key/Value from the Key-Value-Store of a Usrloc-Record.


Returns false, if no record is found is usrloc.


Meaning of the parameters is as follows:


- *domain (string)* - Domain of the
			        AOR, e.g. "location"
- *aor (string)* - Address-of-Record,
			        save the key for a specific (registered) user.
- *key (string)* - The name of the
			        key to be deleted.


This function can be used in ANY route.


```c title="ul_del_key usage"
...
ul_del_key("location", "$tU@$td", "service_route");
...
```


### Exported MI Functions


#### usrloc:rm


Replaces obsolete MI command: *ul_rm*.


Deletes an entire AOR record (including its contacts).


Parameters:


- *table_name* - table where the AOR
				is removed from (Ex: location).
- *aor* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).


#### usrloc:rm_contact


Replaces obsolete MI command: *ul_rm_contact*.


Deletes a contact from an AOR record.


Parameters:


- *table name* - table where the AOR
				is removed from (Ex: location).
- *AOR* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).
- *contact* - exact contact to be removed


#### usrloc:dump


Replaces obsolete MI command: *ul_dump*.


Dumps the entire content of the USRLOC in memory cache


Parameters:


- *brief* - (optional, may not be present); if
				equals to string "brief", a brief dump will be
				done (only AOR and contacts, with no other details)


#### usrloc:flush


Replaces obsolete MI command: *ul_flush*.


Force a flush of all pending usrloc cache changes to the database.
		Normally, this routine runs every
		[timer interval](#param_timer_interval) seconds.


#### usrloc:add


Replaces obsolete MI command: *ul_add*.


Adds a new contact for an user AOR.


Parameters:


- *table name (string)* - table where the contact
				will be added (Ex: "location").
- *aor (string)* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).
- *contact (string)* - Contact URI to be added
- *expires (int)* - expires value of the contact
- *q (string)* - Q value of the contact
- *flags (int)* - internal USRLOC flags of the
				contact
- *cflags (int)* - per branch flags of the
				contact
- *methods (int)* - bitmask with supported requests
				of the contact.  To whitelist all SIP methods, simply use the
				value **32767**. For a breakdown
				of each method's value, see the "request_method" internal enum.


#### usrloc:show_contact


Replaces obsolete MI command: *ul_show_contact*.


Dumps the contacts of an user AOR.


Parameters:


- *table_name* - table where the AOR
				resides (Ex: location).
- *aor* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).


#### usrloc:sync


Replaces obsolete MI command: *ul_sync*.


Empty the location table, then synchronize it with all contacts from
		memory.  Note that this can not be used when no database is specified
		or with the DB-Only scheme.


Important: make sure that all your contacts are in memory
		(*usrloc:dump* MI function) before executing this
		command.


Parameters:


- *table name* - table where the AOR
				resides (Ex: location).
- *AOR (optional)* - only delete/sync this
				user AOR, not the whole table.  Format: "username[@domain]"
				(*domain* is required only if
				[use domain](#param_use_domain) option is on).


#### usrloc:cluster_sync


Replaces obsolete MI command: *ul_cluster_sync*.


This command will only take effect if the target OpenSIPS instance is
		paired with a hot backup instance, while running under a
		cluster-enabled [working mode preset](#param_working_mode_preset).


The current node will locate a healthy donor node within the
		[location cluster](#param_location_cluster) and issue a sync request to
		it. The donor node will then proceed to push all of its user location
		data over to the current node, via the binary interface. The received
		data will be merged with existing data. Conflicting contacts (matched
		according to [matching mode](#param_matching_mode)) are overwritten
		only if the sync data is newer than the current data.


### Exported Statistics


Exported statistics are listed in the next sections.


#### users


Number of AOR existing in the USRLOC memory cache for that domain
			- can not be resetted; this statistic will be register for each
			used domain (Ex: location).


#### contacts


Number of contacts existing in the USRLOC memory cache for that
			domain - can not be resetted; this statistic will be register for
			each used domain (Ex: location).


#### expires


Total number of expired contacts for that domain - can be resetted;
			 this statistic will be register for each used domain
			(Ex: location).


#### registered_users


Total number of AOR existing in the USRLOC memory cache for all
			domains - can not be resetted.


### Exported Events


#### E_UL_AOR_INSERT


This event is raised when a new AOR is inserted in the USRLOC
			memory cache.


Parameters:


- *domain* - The name of the table.
- *aor* - The AOR of the inserted record.


#### E_UL_AOR_DELETE


This event is raised when a new AOR is deleted from the USRLOC
			memory cache.


Parameters:


- *domain* - The name of the table.
- *aor* - The AOR of the deleted record.


#### E_UL_CONTACT_INSERT


This event is raised when a new contact is inserted in any of the
			existing AOR's contact list. For each new contact, if its AOR does
			not exist in the memory, then both the E_UL_AOR_CREATE and
			E_UL_CONTACT_INSERT events will be raised.


Parameters:


- *domain* - The name of the table.
- *aor* - The AOR of the inserted contact.
- *uri* - The contact URI of the inserted
				contact.
- *received* - IP, port and protocol the
				registration message was received from. If these have the
				same value as the contact's address (see the address parameter)
				then the received parameter will be an empty string.
- *path* - The PATH header value of the
				registration message.(empty string if not present)
- *qval* - The Q value (priority) of the
				contact (as integer value from 0 to 10).
- *user_agent* - The User-Agent header
				value.
*NOTICE:*Can contain spaces.
- *socket* - The SIP socket/listener
				(as string) used by OpenSIPS to receive the contact
				registations.
- *bflags* - The branch flags (bflags) of the
				contact (in integer value of the bitmask)
- *expires* - The expires value of the
				contact (as UNIX timestamp integer).
- *callid* - The Call-ID header of the
				registration message.
- *cseq* - The cseq number as an int value.
- *attr* - The attributes string attached
				to the contact (the custom attributes attached from the
				script level). As this string is options, if missing in the
				contact, the event will push the empty string for this event
				field.
- *latency* - The latency of the last
				successful ping for this contact, in microseconds. Until the
				first ping reply for a given contact arrives, its pinging
				latency will be 0.
- *shtag* - The shared tag of the contact,
				which helps determine if the current node owns the contact
				(e.g. possibly using the **$cluster.sh_tag** pseudo-variable in order to perform the check).
*NOTICE:*If a contact has no shared tag
				attached to it, the value of this parameter will be "" (empty
				string)!


#### E_UL_CONTACT_DELETE


This event is raised when a contact is deleted from an
			existing AOR's contact list. If the contact is the only one in
			the list then both the E_UL_AOR_DELETE and
			E_UL_CONTACT_DELETE events will be raised.


Parameters: same as the
			[E UL CONTACT INSERT](#event_e_ul_contact_insert) event


#### E_UL_CONTACT_UPDATE


This event is raised when a contact's info is updated by receiving
			another registration message.


Parameters: same as the
			[E UL CONTACT INSERT](#event_e_ul_contact_insert) event


#### E_UL_CONTACT_REFRESH


This event may only be raised for RFC 8599 (Push Notification)
			enabled contacts.


Set [contact refresh timer](#param_contact_refresh_timer) to
		*true* in order to enable this event.  The event is
		raised within reasonable time before an RFC 8599 enabled contact
		will expire, such that the script writer can take action,
		possibly force a registration refresh from the endpoint.


Parameters:


- *domain* - The name of the table.
- *aor* - The AOR of the inserted contact.
- *uri* - The contact URI of the inserted
				contact.
- *received* - IP, port and protocol the
				registration message was received from. If these have the
				same value as the contact's address (see the address parameter)
				then the received parameter will be an empty string.
- *user_agent* - The User-Agent header
				value.
*NOTICE:*Can contain spaces.
- *socket* - The SIP socket/listener
				(as string) used by OpenSIPS to receive the contact
				registations.
- *bflags* - The branch flags (bflags) of the
				contact (in integer value of the bitmask)
- *expires* - The expires value of the
				contact (as UNIX timestamp integer).
- *callid* - The Call-ID header of the
				registration message.
- *attr* - The attributes string attached
				to the contact (the custom attributes attached from the
				script level). As this string is options, if missing in the
				contact, the event will push the empty string for this event
				field.
- *shtag* - The shared tag of the contact,
				which helps determine if the current node owns the contact
				(e.g. possibly using the **$cluster.sh_tag** pseudo-variable in order to perform the check).
- *reason* - the reason why the binding refresh
				event was triggered.  Possible values:
				
					"reg-refresh" - periodic refresh triggered by OpenSIPS

					"ini-INVITE", "ini-SUBSCRIBE", etc. - a refresh
						triggered by an incoming initial SIP request

					"mid-INVITE", "mid-BYE", etc. - a refresh triggered
						by an incoming mid-dialog SIP request
- *req_callid* - the Call-ID of the SIP request
				which triggered this event, if any.  This gives the ability to
				logically link the pending request with the current event and
				access useful data from that request (e.g. caller identity,
				dialed number, etc.).
Using the *req_callid*, if a dialog has been
				created for the pending request, this dialog may be temporarily
				loaded inside the event_route using the
				[load_dialog_ctx()](../dialog#func_load_dialog_ctx) and
				[unload_dialog_ctx()](../dialog#func_unload_dialog_ctx)
				functions of the dialog module.


#### E_UL_LATENCY_UPDATE


This event is raised when a contact pinging latency matches either
		of the [latency event min us](#param_latency_event_min_us) or
		[latency event min us delta](#param_latency_event_min_us_delta) filters. If none of
		these filters is set, this event will get raised for each successful
		contact ping operation.


Parameters: same as the
			[E UL CONTACT INSERT](#event_e_ul_contact_insert) event


## Developer Guide


### Available Functions


#### ul_register_domain(name)


The function registers a new domain. Domain is just another name for
		table used in registrar. The function is called from fixups in
		registrar. It gets name of the domain as a parameter and returns
		pointer to a new domain structure. The fixup than 'fixes' the
		parameter in registrar so that it will pass the pointer instead of the
		name every time save() or lookup() is called. Some usrloc functions
		get the pointer as parameter when called. For more details see
		implementation of save function in registrar.


Meaning of the parameters is as follows:


- *const char* name* - Name of the domain
				(also called table) to be registered.


#### ul_insert_urecord(domain, aor, rec, is_replicated)


The function creates a new record structure and inserts it in the
		specified domain. The record is structure that contains all the
		contacts for belonging to the specified username.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain
				returned by ul_register_udomain.
- *str* aor* - Address of Record (aka
			username) of the new record (at this time the record will
			contain no contacts yet).
- *urecord_t** rec* - The newly created
			record structure.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_delete_urecord(domain, aor, is_replicated)


The function deletes all the contacts bound with the given Address
		Of Record.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain
			returned by ul_register_udomain.
- *str* aor* - Address of record (aka
			username) of the record, that should be deleted.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_get_urecord(domain, aor)


The function returns pointer to record with given Address of Record.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain
			returned by ul_register_udomain.


- *str* aor* - Address of Record of request
			record.


#### ul_lock_udomain(domain)


The function lock the specified domain, it means, that no other
		processes will be able to access during the time. This prevents race
		conditions. Scope of the lock is the specified domain, that means,
		that multiple domain can be accessed simultaneously, they don't block
		each other.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Domain to be locked.


#### ul_unlock_udomain(domain)


Unlock the specified domain previously locked by ul_lock_udomain.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Domain to be
			unlocked.


#### ul_release_urecord(record, is_replicated)


Do some sanity checks - if all contacts have been removed, delete
		the entire record structure.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record to be
			released.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_insert_ucontact(record, contact, contact_info, contact, is_replicated)


The function inserts a new contact in the given record with
		specified parameters.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record in which
			the contact should be inserted.
- *str* contact* - Contact URI.
- *ucontact_info_t* contact_info* -
				Single structure containing the new contact information
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_delete_ucontact (record, contact, is_replicated)


The function deletes given contact from record.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record from which
			the contact should be removed.


- *ucontact_t* contact* - Contact to be
			deleted.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_delete_ucontact_from_id (domain, contact_id)


The function deletes a contact with the given contact_id from
			the given domain.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Domain where
			the contact can be found.


- *uint64_t contact_id* - Contact_id
			identifying the contact to be deleted.


#### ul_get_ucontact(record, contact)


The function tries to find contact with given Contact URI and
		returns pointer to structure representing the contact.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record to be
			searched for the contact.


- *str_t* contact* - URI of the request
			contact.


#### ul_get_domain_ucontacts (domain, buf, len, flags)


The function retrieves all contacts of all registered users from the
		given doamin and returns them in the caller-supplied buffer. If the
		buffer is too small, the function returns positive value indicating
		how much additional space would be necessary to accommodate all of
		them. Please note that the positive return value should be used only
		as a "hint", as there is no guarantee that during the time
		between two subsequent calls number of registered contacts will
		remain the same.


If flag parameter is set to non-zero value then only contacts that
		have the specified flags set will be returned. It is, for example,
		possible to list only contacts that are behind NAT.


Meaning of the parameters is as follows:


- *udomaint_t* domain* - Domain from which
			to get the contacts


- *void* buf* - Buffer for returning
			contacts.


- *int len* - Length of the buffer.


- *unsigned int flags* - Flags that must
			be set.


#### ul_get_all_ucontacts (buf, len, flags)


The function retrieves all contacts of all registered users and
		returns them in the caller-supplied buffer. If the buffer is too small,
		the function returns positive value indicating how much additional
		space would be necessary to accommodate all of them. Please note
		that the positive return value should be used only as a
		"hint", as there is no guarantee that during the time
		between two subsequent calls number of registered contacts will
		remain the same.


If flag parameter is set to non-zero value then only contacts that
		have the specified flags set will be returned. It is, for example,
		possible to list only contacts that are behind NAT.


Meaning of the parameters is as follows:


- *void* buf* - Buffer for returning
			contacts.


- *int len* - Length of the buffer.


- *unsigned int flags* - Flags that must
			be set.


#### ul_update_ucontact(record, contact, contact_info, is_replicated)


The function updates contact with new values.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record in which
			the contact should be inserted.
- *ucontact_t* contact* - Contact URI.
- *ucontact_info_t* contact_info* -
				Single structure containing the new contact information
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_bind_ursloc( api )


The function imports all functions that are exported by the
		USRLOC module. Overs for other modules which want to user the
		internal USRLOC API an easy way to load and access the functions.


Meaning of the parameters is as follows:


- *usrloc_api_t* api* - USRLOC API


#### ul_register_ulcb(type ,callback, param)


The function register with USRLOC a callback function to be called
		when some event occures inside USRLOC.


Meaning of the parameters is as follows:


- *int types* - type of event for which
			the callback should be called (see usrloc/ul_callback.h).
- *ul_cb f* - callback function; see
			usrloc/ul_callback.h for prototype.
- *void *param* - some parameter to be
			passed to the callback each time when it is called.


#### ul_get_num_users()


The function loops through all domains summing up the number of users.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
