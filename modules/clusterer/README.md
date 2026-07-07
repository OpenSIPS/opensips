---
title: "CLUSTERER Module"
description: "The *clusterer* module is used to organize multiple OpenSIPS instances into groups that can communicate with each other in order to replicate, share information or perform distributed tasks. The module itself only stores information about the nodes in a group/cluster and provides an inter..."
---

## Admin Guide


### Overview


The *clusterer* module is used to organize
		multiple OpenSIPS instances into groups that can communicate with each
		other in order to replicate, share information or perform
		distributed tasks. The module itself only stores information about the
		nodes in a group/cluster and provides an interface to check or tune
		their state and parameters. The distributed logic is performed by
		different modules that use this interface (i.e. the
		*dialog* module can replicate profiles, the
		*ratelimit* module can share pipes across multiple
		instances, etc). Provisioning the nodes within a cluster is done over
		the database but, for efficiency, the node-related information is cached
		into OpenSIPS memory. This information can be checked or updated by
		sending commands over the MI interface.


The *clusterer* module can also detect node
		availability, by using certain parameters provisioned in the database.
		When a destination is not reachable, it is put in a
		*probing* state - it is periodically pinged until
		a maximum number of failed attempts is reached, when it is marked as
		temporarily disabled. It stays in this state for a period (equal to the
		*duration* parameter), and then the number of
		retries reset to 0 and the node is considered up again.


Modules (like *dialog* or
		*ratelimit* can use nodes within the cluster to
		replicate information. They also register a specific timeout to
		invalidate data from specific nodes, in case no updates have been
		within an interval. The *clusterer* notifies
		the module if the timeout is reached and puts the node in a
		temporary disabled state.
		If a packet has arrived for a temporary disabled server, the packet
		is dropped and a temporary disabled notification is sent to the
		registered module. After the disabled period (2 * timeout) has passed,
		the server is up again.


By default, the state information of the nodes is not persistent. To
		make them persistent via a database, one must set the
		*persistent_mode* parameter.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url


The database url.


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("clusterer", "db_url",
	"mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### db_table


The name of the table storing the clustering information.


*Default value is "clusterer".*


```opensips title="Set db_table parameter"
...
modparam("clusterer", "db_table", "clusterer")
...
```


#### server_id


It specifies the *server_id* the current
				instance has. this field should correspond with one of the
				*machine_id* fields in the database.


*Default value is 0.*


```opensips title="Set server_id parameter"
...
modparam("clusterer", "server_id", 2)
...
```


#### persistent_mode


If persistent mode is enabled, a timer synchronizes the
				information used by the clusterer module and the information
				stored in the database.


*Default value is 0 (disabled).*


```opensips title="Set persistent_mode parameter"
...
modparam("clusterer", "persistent_mode", 1)
...
```


#### cluster_id_col


The name of the column in the db_table where the cluster_id is stored.


*Default value is "cluster_id".*


```opensips title="Set cluster_id_col parameter"
...
modparam("clusterer", "cluster_id_col", "cluster_id")
...
```


#### machine_id_col


The name of the column in the db_table where the machine_id is stored.


*Default value is "machine_id".*


```opensips title="Set machine_id_col parameter"
...
modparam("clusterer", "machine_id_col", "machine_id")
...
```


#### clusterer_id_col


The name of the column in the db_table where the machine_id is stored.


*Default value is "id".*


```opensips title="Set clusterer_id_col parameter"
...
modparam("clusterer", "clusterer_id_col", "clusterer_id")
...
```


#### state_col


The name of the column in the db_table where the state is stored.


*Default value is "state".*


```opensips title="Set state_col parameter"
...
modparam("clusterer", "state_col", "state")
...
```


#### url_col


The name of the column in the db_table where the url is stored.


*Default value is "url".*


```opensips title="Set url_col parameter"
...
modparam("clusterer", "url_col", "url")
...
```


#### description_col


The name of the column in the db_table where the machine's description is stored.


*Default value is "description".*


```opensips title="Set description_col parameter"
...
modparam("clusterer", "description_col", "description")
...
```


#### failed_attempts_col


The name of the column in the db_table where the maximum allowed number
                of failed attempts is stored.


*Default value is "failed_attempts".*


```opensips title="Set failed_attempts_col parameter"
...
modparam("clusterer", "failed_attempts_col", "failed_attempts")
...
```


#### last_attempt_col


The name of the column in the db_table where the UNIX time of last
                last failed attempt is stored.


*Default value is "last_attempt".*


```opensips title="Set last_attempt_col parameter"
...
modparam("clusterer", "last_attempt_col", "last_attempt")
...
```


#### duration_col


The name of the column in the db_table where the duration of a
                machine belonging to a certain cluster temporary disabled state
                is stored.


*Default value is "duration".*


```opensips title="Set duration_col parameter"
...
modparam("clusterer", "duration_col", "duration")
...
```


#### no_tries_col


The name of the column in the db_table where the number of failed
                connecting tries is stored.


*Default value is "no_tries".*


```opensips title="Set no_tries_col parameter"
...
modparam("clusterer", "no_tries_col", "no_tries")
...
```


### Exported Functions


none


### Exported MI Functions


#### clusterer_reload


Reloads data from the clusterer database. If the persistent
                    mode is disabled the changes made to the locally stored
                    data are lost.


Name: *clusterer_reload*


Parameters:*none*


MI FIFO Command Format:


```c
		:clusterer_reload
		_empty_line_
		
```


#### clusterer_list


Lists in a table format all the data stored in OpenSIPS cache.


Name: *clusterer_list*


Parameters:*none*


MI FIFO Command Format:


```c
		:clusterer_list
		_empty_line_
		
```


#### clusterer_set_status


Sets the status(UP, DOWN) of a machine belonging to a certain cluster.


Name: *clusterer_set_status*


Parameters:


- *cluster_id* - indicates the id of the cluster.
- *machine_id* - indicates the id of the machine.
- *status* - indicates the new status( 0 - permanent down, 1 - up).
- *protocol* - indicates the protocol.


MI FIFO Command Format:


```c
		:clusterer_set_status:
		1
		2
		0
		bin
		_empty_line_
		
```


### Usage Example


This section provides an usage example for replicating ratelimit
		pipes between two OpenSIPS instances. It uses the clusterer module to
		manage the replicating nodes, and the proto_bin modules to send the
		replicated information.


The setup topology is simple: we have two OpenSIPS nodes running on
		two separate machines (although they could run on the same machine as
		well): *Node A* has IP 192.168.0.5 and
		*Node B* has IP 192.168.0.6. Both have, besides the
		traffic listeners (UDP, TCP, etc.), bin listeners bound on port
		*5566*. These listeners will be used by the
		*ratelimit* module to replicate the pipes.
		Therefore, we have to provision them in the
		*clusterer* table.


```c title="Example database content - clusterer table"
+----+------------+------------+----------------------+-------+--------------+-----------------+----------+----------+-------------+
| id | cluster_id | machine_id | url                  | state | last_attempt | failed_attempts | no_tries | duration | description |
+----+------------+------------+----------------------+-------+--------------+-----------------+----------+----------+-------------+
|  1 |          1 |          1 | bin:192.168.0.5:5566 |     1 |            0 |               0 |        0 |       30 | Node A      |
|  2 |          1 |          2 | bin:192.168.0.6:5566 |     1 |            0 |               0 |        0 |       30 | Node B      |
+----+------------+------------+----------------------+-------+--------------+-----------------+----------+----------+-------------+
		
```


- "cluster_id" - this column represents the
					identifier of the cluster. All nodes within a
					group/cluster should have the same id (in our example,
					both nodes have ID *1*)
- "machine_id" - this represents the
					identifier of the machine/node, and each instance within a
					cluster should have a different ID. In our example,
					*Node A* will have ID 1, and
					*Node B* ID 2
- "url" - this indicates the URL where the
					instance will receive the replication information. In our
					example, each node will receive the date over the bin
					protocol
- "state" - this is the state of the machine:
					1 means on, 0 means off, and 2 means it is in probing.
					Note that if you want the node to be active right away,
					you have to set it in *state 1*
- "last_attempt",
					"failed_attempts" and "no_tries"
					- are fields used for the probing mechanisms, and should
					be set to *0* by default. They are
					automatically updated by the clusterer module if the
					*persistent_mode* parameter is set to
					*1*
- "duration" - is used to specify the period
					a node stays in the temporary disabled state. In our
					example, if the node does not respond, it is disabled for
					30 seconds before retrying to send data again
- "description" - is an opaque value used to
					identify the node


After provisioning the two nodes in the database, we have to configure
		the two instances of OpenSIPS. First, we configure *Node
			A*:


```opensips title="*Node A* configuration"
...
listen = bin:192.168.0.5:5566 # bin listener for Node A

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "db_url", "mysql://opensips@192.168.0.7/opensips")
modparam("clusterer", "server_id", 1) # machine_id for Node A

loadmodule "ratelimit.so"
# replicate pipes to cluster id 1
modparam("ratelimit", "replicate_pipes_to", 1)
# accept replicated data from nodes within cluster 1
modparam("ratelimit", "accept_pipes_from", 1)
# if a node does not reply in a 5 seconds interval,
#the information from that node is invalidated
modparam("ratelimit", "accept_pipes_timeout", 5)
...
		
```


Similarly, the configuration for *Node B* is as follows:


```opensips title="*Node B* configuration"
...
listen = bin:192.168.0.6:5566 # bin listener for Node B

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
# ideally, use the same database for both nodes
modparam("clusterer", "db_url", "mysql://opensips@192.168.0.7/opensips")
modparam("clusterer", "server_id", 2) # machine_id for Node B

loadmodule "ratelimit.so"
# replicate pipes to cluster id 1
modparam("ratelimit", "replicate_pipes_to", 1)
# accept replicated data from nodes within cluster 1
modparam("ratelimit", "accept_pipes_from", 1)
# if a node does not reply in a 5 seconds interval,
# the information from that node is invalidated
modparam("ratelimit", "accept_pipes_timeout", 5)
...
		
```


*Note* that the *server_id*
	parameter for *Node B* is *2*.
	Starting the two OpenSIPS instances with the above configurations provides
	your platform the ability to used shared ratelimit pipes in a very
	efficient and scalable way.


## Developer Guide


### Available Functions


#### get_nodes(cluster_id, proto)


The function will return all a copy of all the needed information
                from the nodes (machine_id, state, description, sock address)
                stored in shm, whos state is up(1) and have a certain cluster_id and
                protocol.


This function is usually used for replication purposes.


This function returns NULL on error.


Meaning of the parameters is as follows:


- *int cluster_id* - the cluster id
- *int proto* - the protocol


```opensips title="get_nodes usage"
...
get_nodes(cluster_id, proto);
...
```


#### free_nodes(nodes)


This function will free the allocated data for the copy.


Meaning of the parameters is as follows:


- *clusterer_node_t *nodes* - the data
                        returned by the get_nodes function


```opensips title="free_nodes usage"
...
free_nodes(nodes);
...
```


#### set_state(cluster_id, machine_id, state, proto)


The function sets the state of a machine belonging to a certain cluster,
                which have the specified protocol.


This function is usually used for replication purposes.


Meaning of the parameters is as follows:


- *int cluster_id* - cluster_id
- *int machine_id* - machine_id
- *int state* - the server state
- *int proto* - protocol


```opensips title="set_state usage"
...
set_state(1,1,2,PROTO_BIN);
...
```


#### check(cluster_id, sockaddr, server_id, proto)


This function is used to check if the source of a receiving packet
                is known.


It returns 1 if the source is known, else it returns 0.


Meaning of the parameters is as follows:


- *int cluster_id* - cluster id
- *union sockaddr_union* sockaddr* - incoming connexion
                        socket address
- *int server_id* - incoming connexion
                        server_id
- *int proto* - protocol


```c title="check usage"
...
check(1, sockaddr, 2, PROTO_BIN)
...
```


#### get_my_id()


This function will return the server id's.


```c title="get_my_id usage"
...
get_my_id()
...
```


#### send_to(cluster_id, protocol)


This function will replicate information to the nodes belonging to 
                a cluster_id that have a specific protocol.


Meaning of the parameters is as follows:


- *int cluster_id* - cluster_id
- *int protocol* - protocol


```c title="send_to usage"
...
send_to(cluster_id, protocol)
...
```


#### register_module(module_name, protocol, callback_function, timeout, auth_check, cluster_id)


This function registers a module to a certain protocol. It acts like an
                intermediary: when a valid packet has arrived, if the auth_check parameter is specified
                then it is checked for authenticity. After that, the timestamps are updated and the callback
                function from the registered module is called.
                The clusterer module checks for every registered module if the duration between
                the last receiving packet and the current time is greater than the module specified timeout.
                If it is, the servers are temporary disabled for a period of timestamp * 2. If any packets
                are received for the temporary disabled servers the registered module is notified.


Meaning of the parameters is as follows:


- *char *module_name* - module name
- *int protocol* - protocol
- *void (*callback_function)(int, struct receive_info *, int)*
                        - the registered module callback function
- *int timeout* - timeput
- *int auth_check* - 0 if the authentication
                        check is disabled, 1 if the authentication check is enabled
- *int cluster_id* - cluster_id


```c title="register_module usage"
...
register_module(dialog, PROTO_BIN, cb, timeout, auth_check, cluster_id)
...
```


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
