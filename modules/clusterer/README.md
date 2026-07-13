---
title: "CLUSTERER Module"
description: "The clusterer module is used to organize multiple OpenSIPS instances into groups (clusters) in which the nodes can communicate with each other in order to replicate, share information or perform distributed tasks."
---

## Admin Guide


### Overview


The *clusterer* module is used to organize multiple OpenSIPS instances into groups(clusters) in which the nodes can communicate with each other in order to replicate, share information or perform distributed tasks. The distributed logic is performed by different modules that use the *clusterer* interface (i.e. the *dialog* module can replicate dialogs/profiles, the *ratelimit* module can share pipes across multiple 
instances etc.). The *clusterer* module itself only provides an interface to send/receive BIN packets and get notifications about node availability. It does this by internally learning the cluster topology and state of the nodes. Provisioning the nodes within a cluster is done over the database. The node-related information can be checked and triggered to be reloaded by sending commands over the MI interface.


The topology established by the *clusterer* module is an overlay of nodes where the "links" represent communication availability at BIN interface level. For this purpose, a probing mechanism is used, consisting of regular pings to all nodes which must receive a reply within a given interval. All nodes in the cluster exchange information about the state of their links with other nodes and compute a "routing table" which gives a next hop for each destination. The metric for the shortest path is the number of hops. When there is no direct link to a destination, the BIN packet sent by a module is transparently routed through the cluster.


Note that an OpenSIPS instance can belong to multiple clusters, communicating and establishing the topology separately for each one. In order to provision this in the database, each node has an unique ID at global level, which can be referenced by each cluster.


While existing nodes can learn about newly added nodes without additional provisioning, the new nodes must be fully aware of the existing components of the cluster they are joining, in order to properly advertise themselves.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *proto_bin module*.


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


#### id_col


The name of the column storing an id for the table rows.


*Default value is "id".*


```opensips title="Set id_col parameter"
...
modparam("clusterer", "id_col", "id")
...
		
```


#### cluster_id_col


The name of the column to store the id of a cluster.


*Default value is "cluster_id".*


```opensips title="Set cluster_id_col parameter"
...
modparam("clusterer", "cluster_id_col", "cluster_id")
...
		
```


#### node_id_col


The name of the column to store the id of an instance. The values must be greater than 0.


*Default value is "node_id".*


```opensips title="Set node_id_col parameter"
...
modparam("clusterer", "node_id_col", "node_id")
...
		
```


#### url_col


The name of the column containing the instance url. The values must be greater than 0.


*Default value is "url".*


```opensips title="Set url_col parameter"
...
modparam("clusterer", "url_col", "url")
...
		
```


#### state_col


The name of the column storing the state of the node(enabled/disabled).


*Default value is "state".*


```opensips title="Set state_col parameter"
...
modparam("clusterer", "state_col", "state")
...
		
```


#### ls_seq_no_col


The name of the column storing the sequence number of the last link state update message sent by the node.


*Default value is "ls_seq_no".*


```opensips title="Set ls_seq_no_col parameter"
...
modparam("clusterer", "ls_seq_no_col", "ls_seq_no")
...
		
```


#### top_seq_no_col


The name of the column storing the sequence number of the last topology update message sent by the node.


*Default value is "top_seq_no".*


```opensips title="Set top_seq_no_col parameter"
...
modparam("clusterer", "top_seq_no_col", "top_seq_no")
...
		
```


#### no_ping_retries_col


The name of the column containing the maximum number of ping retries before the link with the neighbour node is considered down.


*Default value is "no_ping_retries".*


```opensips title="Set no_ping_retries_col parameter"
...
modparam("clusterer", "no_ping_retries_col", "no_ping_retries")
...
		
```


#### priority_col


The name of the column storing the node priority to be chosen as next hop in case of same length(number of hops) paths when rerouting messages.


*Default value is "priority".*


```opensips title="Set priority_col parameter"
...
modparam("clusterer", "priority_col", "priority")
...
		
```


#### sip_addr_col


The name of the column containing a SIP address for the node.


*Default value is "sip_addr".*


```opensips title="Set sip_addr_col parameter"
...
modparam("clusterer", "sip_addr_col", "sip_addr")
...
		
```


#### description_col


The name of the column containing a node description.


*Default value is "description".*


```opensips title="Set description_col parameter"
...
modparam("clusterer", "description_col", "description")
...
		
```


#### current_id


The id of the current instance. This parameter must be equal with one of the
*node_id* fields in the database.


*No default value. This parameter must be explicitly set to a value greater than zero.*


```opensips title="Set current_id parameter"
...
modparam("clusterer", "current_id", 1)
...
		
```


#### ping_interval


The interval in seconds between regular pings sent to a neighbour node.


*Default value is "4"*


```opensips title="Set ping_interval parameter"
...
modparam("clusterer", "ping_interval", 1)
...
		
```


#### ping_timeout


The time in milliseconds to wait for a reply to a previously sent ping before retrying or considering the link with the neighbour node down. This is also the interval between successive retries if the send fails.


*Default value is "1000"*


```opensips title="Set ping_timeout parameter"
...
modparam("clusterer", "ping_timeout", 500)
...
		
```


#### node_timeout


The time in seconds to wait before pinging is restarted for a failed node.


*Default value is "60"*


```opensips title="Set node_timeout parameter"
...
modparam("clusterer", "node_timeout", 10)
...
		
```


### Exported Functions


none


### Exported MI Functions


#### clusterer_reload


Reloads data from the clusterer database. The currently established topology will be lost and the node will rediscover the new topology.


Name: *clusterer_reload*


Parameters:*none*


MI FIFO Command Format:


```bash
:clusterer_reload
_empty_line_
```


#### clusterer_list


Lists information(node id, URL, link state with that node etc.) about the other nodes in each cluster.


Name: *clusterer_list*


Parameters:*none*


MI FIFO Command Format:


```bash
:clusterer_list
_empty_line_
```


```bash title="clusterer_list usage"
$ ./opensipsctl fifo clusterer_list
Cluster:: 1
	Node:: 4 DB_ID=4 URL=bin:127.0.0.4:7774 Enabled=1 Link_state=Up      Next_hop=4 Description=none
	Node:: 3 DB_ID=3 URL=bin:127.0.0.3:7773 Enabled=1 Link_state=Down    Next_hop=4 Description=none
	Node:: 2 DB_ID=2 URL=bin:127.0.0.2:7772 Enabled=1 Link_state=Probe   Next_hop=4 Description=none
Cluster:: 2
	Node:: 5 DB_ID=5 URL=bin:127.0.0.4:7775 Enabled=1 Link_state=Up      Next_hop=5 Description=none
```


#### clusterer_list_topology


Lists each cluster's topology from the current node's perspective as an adjacency list. A node appears as a neighbour if the link with that node is up.


Note that if a node id appears in multiple clusters, it refers to the same instance that belongs to different clusters, for which it has a different topology.


Name: *clusterer_list_topology*


Parameters:*none*


MI FIFO Command Format:


```bash
		:clusterer_list_topology
		_empty_line_
		
```


```bash title="clusterer_list_topology usage"
$ ./opensipsctl fifo clusterer_list_topology
Cluster:: 1
	Node:: 1 Neighbours=4
	Node:: 4 Neighbours=1 2 3
	Node:: 3 Neighbours=2 4
	Node:: 2 Neighbours=3 4
Cluster:: 2
	Node:: 1 Neighbours=5
	Node:: 5 Neighbours=1
```


#### clusterer_set_status


Sets the status(Enabled/Disabled) of the current node in a specified cluster. A disabled node does not send any messages and ignores received ones thus appearing as a failed node in the topology.


Name: *clusterer_set_status*


Parameters:


- *cluster_id* - indicates the id of the cluster.
- *status* - indicates the new status(0 - Disabled, 1 - Enabled).


MI FIFO Command Format:


```bash
:clusterer_set_status:
1
0
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
+----+------------+---------+----------------------+-------+-----------+------------+-----------------+----------+------------------------+
| id | cluster_id | node_id | url                  | state | ls_seq_no | top_seq_no | no_ping_retries | priority | sip_addr | description |
+----+------------+---------+----------------------+-------+-----------+------------+-----------------+----------+------------------------+
|  1 |          1 |       1 | bin:192.168.0.5:5566 |     1 |         0 |          0 |               3 |       50 | NULL     | Node A      |
|  2 |          1 |       2 | bin:192.168.0.6:5566 |     1 |         0 |          0 |               3 |       50 | NULL     | Node B      |
+----+------------+---------+----------------------+-------+-----------+------------+-----------------+----------+------------------------+
		
```


- "cluster_id" - this column represents the
identifier of the cluster. All nodes within a
group/cluster should have the same id (in our example,
both nodes have ID *1*). The values must be greater than 0.
- "node_id" - this represents the
identifier of the machine/node, and each instance within a
cluster should have a different ID. The values must be greater than 0. In our example,
*Node A* will have ID 1, and
*Node B* ID 2.
- "url" - this indicates the URL where the
instance will receive the replication information. In our
example, each node will receive the date over the bin
protocol
- "state" - this is the state of the machine:
1 means Enabled, 0 means Disabled; if we had a third machine that
we didn't want to use for the moment, we would have set the state to 0
- "ls_seq_no" and "top_seq_no"
are fields used for the probing and topology discovery mechanisms,
and should be set to *0* by default; they are
automatically updated by the clusterer module and you shouldn't change them
even if a node fails or you disable it
- "no_ping_retries" - is used to specify the maximum number of ping
retries before the link with a node is considered down
- "priority" - is used to specify the node priority to be chosen
as next hop in case of same length(number of hops) paths when rerouting messages;
it is not relevant for this two-node topology example
- "sip_addr" - is a SIP address for the node with currently no
application in replication scenarios; reserved for further development of other modules
which might use the clusterer module for communication
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
modparam("clusterer", "current_id", 1) # node_id for Node A

loadmodule "ratelimit.so"
# replicate pipes to cluster id 1
modparam("ratelimit", "replicate_pipes_to", 1)
# accept replicated data from nodes within cluster 1
modparam("ratelimit", "accept_pipes_from", 1)
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
modparam("clusterer", "current_id", 2) # node_id for Node B

loadmodule "ratelimit.so"
# replicate pipes to cluster id 1
modparam("ratelimit", "replicate_pipes_to", 1)
# accept replicated data from nodes within cluster 1
modparam("ratelimit", "accept_pipes_from", 1)
...
		
```


*Note* that the *node_id*
parameter for *Node B* is *2*.
Starting the two OpenSIPS instances with the above configurations provides
your platform the ability to used shared ratelimit pipes in a very
efficient and scalable way.


## Developer Guide


### Available Functions


#### get_nodes(cluster_id)


This function will return a list of all the reachable nodes(if the direct link is down/probing, a path through intermediary nodes is considered) in the specified cluster.


The returned nodes structure:


```c
...
typedef struct clusterer_node {
    int node_id;
    union sockaddr_union addr;
    str sip_addr;
    str description;
    struct clusterer_node *next;
} clusterer_node_t;
...
        
```


Meaning of the parameters is as follows:


- *int cluster_id* - the cluster id


#### free_nodes(list)


This function will free the lits of nodes returned by *get_nodes*.


Meaning of the parameters is as follows:


- *clusterer_node_t *list* - list header


#### set_state(cluster_id, state)


This function sets the state(enabled/disabled) of the current node in the specified cluster.


Meaning of the parameters is as follows:


- *int cluster_id* - the cluster id
- *enum cl_node_state state* - the new state; possible values:

  - *STATE_DISABLED*
  - *STATE_ENABLED*


#### check_addr(cluster_id, su)


This function checks if a given address belongs to one of the nodes in the cluster.


Meaning of the parameters is as follows:


- *int cluster_id* - the cluster id
- *union sockaddr_union* su* - socket address


#### get_my_id()


This function will return the id of the current node.


#### send_to(packet, cluster_id, node_id)


This functon will send the given BIN packet to the specified node in the cluster. If the direct link is down/probing, it will send the packet to an intermediary node if the destination node is reachable through another path in the cluster topology.


Meaning of the parameters is as follows:


- *bin_packet_t packet* - the packet to be sent
- *int cluster_id* - the cluster id
- *int node_id* - the id of the destination node


The function returns one of the following:


- *CLUSTERER_SEND_SUCCES* - successfuly sent packet to destination node or a valid next hop
- *CLUSTERER_CURR_DISABLED* - current node is disabled so sending is impossbile
- *CLUSTERER_DEST_DOWN* - destination node is not reachable through any path according to the discovered topology
- *CLUSTERER_SEND_ERR* - destination node or valid next hop appear to be reachable but send failed


#### send_all(packet, cluster_id)


Send the given BIN packet to all the nodes in the specified cluster. The function operates similarly to *send_to*.


Meaning of the parameters is as follows:


- *bin_packet_t packet* - the packet to be sent
- *int cluster_id* - the cluster id


The function returns one of the following:


- *CLUSTERER_SEND_SUCCES* - successfuly sent packet to at least one node
- *CLUSTERER_CURR_DISABLED* - current node is disabled so sending is impossbile
- *CLUSTERER_DEST_DOWN* - all nodes in the cluster are unreachable according to the discovered topology
- *CLUSTERER_SEND_ERR* - send failed for all nodes in the cluster


#### get_next_hop(cluster_id, node_id)


This function returns the next hop from the computed shortest path to the given destination node in the specified cluster. This is the node that is the actual destination for the *send_to* and *send_all* functions when the direct link with the intended destination is down. The function returns the same structure as *get_nodes*.


Meaning of the parameters is as follows:


- *int cluster_id* - the cluster id
- *int node_id* - the node id of the destination for which the next hop is returned.


#### free_next_hop(next_hop)


This function will free the next hop returned by *get_next_hop*.


Meaning of the parameters is as follows:


- *clusterer_node_t *next_hop* - next hop to be freed


#### register_module(mod_name, cb, auth_check, accept_clusters_ids, no_accept_clusters)


This function registers an OpenSIPS module in order to receive BIN packets and cluster notifications. A certain module can accept packets from multiple clusters and provides a single callback function that will be called for each received packet. This function will also be called to notify cluster events like nodes becoming reachable/unreachable.


Meaning of the parameters is as follows:


- *char *mod_name* - module name
- *clusterer_cb_f cb* - callback function
- *int auth_check* - 0 - no check, 1 - for every BIN packet received check if source IP belongs to one of the nodes in the cluster
- *int* accept_clusters_ids* - array of cluster ids from which packets are accepted
- *int no_accept_clusters* - length of *accept_clusters_ids* array


The callback function prototype:


```c
...
typedef void (*clusterer_cb_f)(enum clusterer_event ev,bin_packet_t *, int packet_type,
                struct receive_info *ri, int cluster_id, int src_id, int dest_id);
...
```


Possble values for the event signaled through *ev* parameter of the callback funtion:


- *CLUSTER_RECV_MSG* - received BIN message
- *CLUSTER_ROUTE_FAILED* - failed to route a received BIN packet destined for another node in the cluster
- *CLUSTER_NODE_UP* - a node became reachable
- *CLUSTER_NODE_DOWN* - a node became unreachable


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
