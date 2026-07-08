---
title: "CLUSTERER Module"
description: "The *clusterer* module is used to organize multiple OpenSIPS instances into groups(clusters) in which the nodes can communicate with each other in order to replicate, share information or perform distributed tasks. The distributed logic is performed either by different modules that use the *clust..."
---

## Admin Guide


### Overview


The *clusterer* module is used to organize multiple OpenSIPS instances into groups(clusters) in which the nodes can communicate with each other in order to replicate, share information or perform distributed tasks. The distributed logic is performed either by different modules that use the *clusterer* interface (i.e. the *dialog* module can replicate dialogs/profiles, the *ratelimit* module can share pipes across multiple 
		instances etc.) or at the script level. The *clusterer* module itself only provides an interface to send/receive BIN packets and get notifications about node availability. It achieves this by internally learning the cluster topology and state of the nodes. Provisioning the nodes within a cluster is done over the database or through the configuration script. The node-related information can be checked and triggered to be reloaded by sending commands over the MI interface.


The topology established by the *clusterer* module is an overlay of nodes where the "links" represent communication availability at BIN interface level. For this purpose, a probing mechanism is used, consisting of regular pings to all nodes in a cluster for which replies must be received within a given interval. All nodes in the cluster exchange information about the state of their links with other nodes and compute a "routing table" which gives a next hop for each destination. The metric for the shortest path is the number of hops. When there is no direct link to a destination, the BIN packet sent by a module is transparently routed through the cluster.


Note that an OpenSIPS instance can belong to multiple clusters, communicating and establishing the topology separately for each one. In order to provision this in the database or the script, each node has an unique ID at global level, which can be referenced in each cluster.


An OpenSIPS instance can dynamically learn all the nodes in the cluster if database provisioning is not desired. It is enough to define at least one neigbour in the script in order to discover all the cluster components.


### Capabilities layer


The clusterer module also keeps track of the state of the nodes in terms of data synchronization for the functionalities (or "capabilities") implemented on top by other modules. Some capabilities require a full data sync(at OpenSIPS startup or at runtime via MI) from a valid "donor" node in the cluster that has the full data set. Furthermore, a capability can query the clusterer module in order to partition some distributed logic only over the synchronized nodes in the cluster.


Each node in the cluster starts with an empty dataset and tries to find
		a suitable node to pull data from. In order to help "bootstrap" the
		cluster, a "seed" node should be defined. This is done by setting the value
		*seed* for the **flags**
		column in the clusterer table(or the property with the same name in the
		*my_node_info* parameter). The seed node will simply
		fall back to a "synced" state after a configurable interval(
		[seed fallback interval](#param_seed_fallback_interval) parameter). Note that
		this mechanism is required only for capabilities that synchronize data
		at startup, so check the corresponding modules documentation.


The clusterer module transparently exposes the *sip_addr* column from the clusterer table(or the property with the same name in the *my_node_info* parameter) to the modules on top so check the corresponding modules documentation for the use of this node related information.


### Cluster-Bridge Replication


*(added in OpenSIPS 4.0)*


Cluster-Bridge Replication (or "bridge replication") allows modules to
		exchange data across *different* clusters.  This
		is meant to serve as a topology/data flow optimization feature, and it
		could be useful in some OpenSIPS cluster setups with multiple data
		centers.  In such cases, it might be desirable to minimize the amount
		of inter-DC replication channels, for example:


```c
      Before (standard, full-mesh replication):

                    DC #1         DC #2
                          WAN link
                      A <─────────> C
                      ^ \        /  ^
                      │   \   /     │         4 x OpenSIPS nodes, 1 x cluster
                      │      X      │       (8 inter-DC replication channels)
                      │    /   \    │         AC, AD, BC, BD, CA, CB, DA, DB
                      v  /       \  v
                      B <─────────> D
                          WAN link
                       cluster_id: 1

      After (cluster-bridged replication):

                    DC #1         DC #2
                          WAN link
                      A ──────────> C
                      ^             ^
                      │             │          4 x OpenSIPS nodes, 2 x clusters
                      │             │       (2 inter-DC replication channels)
                      │             │                   AC, DB
                      v             v
                      B <────────── D
                          WAN link
            cluster_id: 1           cluster_id: 2
            sender: 
```


A *new table* has been added to represent the
		inter-cluster replication bridges, named
		[clusterer_bridge](#param_db_bridge_table):


```c
    mysql> select * from clusterer_bridge;
    +----+-----------+-----------+------------+-------------------------------+
    | id | cluster_a | cluster_b | send_shtag | dst_node_csv                  |
    +----+-----------+-----------+------------+-------------------------------+
    |  1 |         1 |         2 | wan1       | bin:10.0.0.213,bin:10.0.0.214 |
    |  2 |         2 |         1 | wan1       | bin:10.0.0.210,bin:10.0.0.212 |
    +----+-----------+-----------+------------+-------------------------------+
    2 rows in set (0,00 sec)
		
```


*Example of a bi-directional bridge between clusters "1" and "2".*


The "send_shtag" controls the originator node for each cluster bridge defined in the table.
		Only the node with the "active" tag will actually send data over the network.
		Sharing tags can be defined using the [sharing tag](#param_sharing_tag) module parameter.


The "dst_node_csv" functions as a list of remote cluster nodes to try.
		The module will attempt a single TCP send per node, in failover fashion (always same order).


At the time of writing, the only module using the new bridge replication
		feature is [ratelimit](../ratelimit#bridge_replication),
		in order to optimize its "CPS pipes broadcasting" replication mechanism.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module* - if [db mode](#param_db_mode)
				is *1*.
- *proto_bin module*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### my_node_id


The id of the local instance. This parameter must be equal to one of the
				*node_id* fields in the database.


*No default value. This parameter must be explicitly set to a value greater than zero.*


```opensips title="Set my_node_id parameter"
...
modparam("clusterer", "my_node_id", 1)
...
		
```


#### db_mode


Specifies whether the node information for the local instance,
				as well as other instances in the cluster, should be loaded from
				the database or configured in the script(see [my node info](#param_my_node_info)
				and [neighbor node info](#param_neighbor_node_info)). A value of "0"
				means that DB is not used and the cluster topology in terms of node
				information will be discovered dynamically at runtime.


If DB mode is enabled, only the nodes defined in the database will be
				accepted by this instance.


*Default value is "1"*


```opensips title="Set db_mode parameter"
...
modparam("clusterer", "db_mode", 0)
...
		
```


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


#### db_bridge_table


The name of the table storing the inter-cluster bridge definitions.


*Default value is "clusterer_bridge".*


```opensips title="Set db_bridge_table parameter"
...
modparam("clusterer", "db_bridge_table", "clusterer_bridge")
...
		
```


#### sharing_tag


The definition of a sharing tag. The sharing tag is 
			managed by the clusterer module, but can be used (in terms
			of reading its state) by any module build on top of 
			clusterer engine, like dialog or presence.


Note that other tags may be dynamically learned during runtime via 
			clustering communication with other nodes.


The format for this value is "tag_name / cluster_id = active/backup".


Multiple definitions of this parameter are allowed. The default value is "none".


```opensips title="Set sharing_tag parameter"
...
modparam("clusterer", "sharing_tag", "vip1/2=active")
modparam("clusterer", "sharing_tag", "node/10=backup")
...
```


#### my_node_info


Node specification similar to the information provided by a row in
				the clusterer DB table corresponding to the local instance. This
				parameter can be set multiple times in order to include the local
				node in multiple clusters.


Parameter format: multiple "*prop=value*" property
				definitions separated by '*,*' where the name of the
				properties is the same as the DB column names. At least the
				*cluster_id* and *url*
				properties must be defined.


This parameter is required if [db mode](#param_db_mode) is set
			to "0" in order to properly advertise information about
			the local instance in the dynamic node learning process.


```opensips title="Set my_node_info parameter"
...
modparam("clusterer", "my_node_info", "cluster_id=1, url=bin:192.168.0.5:5566")
...
		
```


#### neighbor_node_info


Node specification similar to the information provided by a row in
				the clusterer DB table corresponding to another instance in the
				cluster. This node will be the entry point in the cluster for the
				local instance in the dynamic node learning process. This parameter
				can be set multiple times to define multiple neigbors to connect to (or
				the same neighbor but in different clusters).


Parameter format: multiple "*prop=value*" property
				definitions separated by '*,*' where the name of
				the properties is the same as the DB column names. At least the
				*cluster_id*, *node_id*
				and *url* properties must be defined.


This parameter should be set at least once if
			[db mode](#param_db_mode) is set to *0* in order
			to properly learn the cluster topology. If not set, the only way to learn
			the node topology is by other nodes connecting to the local instance.


```opensips title="Set neighbor_node_info parameter"
...
modparam("clusterer", "neighbor_node_info", "cluster_id=1,node_id=2,url=bin:192.168.0.6:5566")
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


#### seed_fallback_interval


Only relevant for "seed" nodes.  The time, in seconds, to wait
                for a suitable donor node before falling back to a "synced"
                state, following a node restart or an MI cluster sync command.


*Default value is "5".*


```opensips title="Set seed_fallback_interval parameter"
...
modparam("clusterer", "seed_fallback_interval", 10)
...
		
```


#### sync_timeout


The inteval, in seconds, since the last sync data packet received
                after which to consider the sync process as failed and revert the
                node to the not synced state.


*Default value is "15".*


```opensips title="Set sync_timeout parameter"
...
modparam("clusterer", "sync_timeout", 5)
...
		
```


#### sync_packet_size


The maximum size of the BIN packets sent while doing data synchronization. This is only a suggested value as the actual size of the packets may be slightly larger.


*Default value is "65535".*


```opensips title="Set sync_packet_size parameter"
...
modparam("clusterer", "sync_packet_size", 32765)
...
		
```


#### dispatch_jobs


Enables the dispatching of jobs(processing replicated data packets)
            from the receiving TCP worker process to free opensips workers
            (including UDP, timer processes etc.).


This generally improves the performance of handling replication packets
            in high traffic scenarios and should not be disabled.


Nevertheless there are cases where the "thundering herd" problem occurs
            which causes abnormaly high CPU loads. Disabling this dispatching
            mechanism solves such issues.


*Default value is "1" (enabled).*


```opensips title="Set dispatch_jobs parameter"
...
modparam("clusterer", "dispatch_jobs", 0)
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


#### flags_col


The name of the column containing the node flags.


*Default value is "flags".*


```opensips title="Set flags_col parameter"
...
modparam("clusterer", "flags_col", "flags")
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


#### enable_stats (integer)


If the statistics support should be enabled or not. Via statistic
				variables, the module provide information about the cluster nodes.
				Set it to zero to disable or to non-zero to enable it.


*Default value is "1 (enabled)".*


```opensips title="Set enable_stats parameter"
...
modparam("clusterer", "enable_stats", 0)
...
				
```


#### enable_rerouting (integer)


If packets should be rerouted via another node if a direct route
				to destination is unavailible. Disabling may improve stability in
				two-node topologies.
				Set it to zero to disable or to non-zero to enable it.


*Default value is "1 (enabled)".*


```opensips title="Set enable_rerouting parameter"
...
modparam("clusterer", "enable_rerouting", 0)
...
				
```


### Exported Functions


#### cluster_send_req(cluster_id, dst_id, msg, [tag])


This function is used to send a generic, request-like message, containing custom data, to a specific node in a cluster, directly from the script. The message is not a "request" per se but according to the logic on the receiving side, that node can send back a reply. In order to correlate a received reply with the request sent out, the function returns, through the *tag* parameter, a randomly generated communication tag, which is sent along in the the original message, that can be checked against the tag received in a reply.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster ID of the destination node;
- *dst_id* (int) - the ID of the destiantion node;
- *msg* (string) - actual message payload;
- *tag* (var, optional) - randomly generated communication tag.


The function can return the following values:


- *1* - successfully sent message to destination node or a valid next hop
- *-1* - local node is disabled so sending is impossbile
- *-2* - destination node is not reachable through any path according to the discovered topology
- *-3* - destination node or valid next hop appear to be reachable but send failed or other OpenSIPS internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, LOCAL_ROUTE and EVENT_ROUTE.


```opensips title="cluster_send_req() usage"
...
# send a request
cluster_send_req(1, 1, "Check USER: $fU", $var(req_tag));
# wait for reply
$avp(filter) = "tag=" + $var(req_tag);
async(wait_for_event("E_CLUSTERER_RPL_RECEIVED", $avp(filter), 5), rpl_resume);
# done
...
route[rpl_resume] {
  xlog("Received reply: $avp(msg)\n");
}
...
				
```


#### cluster_send_rpl(cluster_id, dst_id, msg, tag)


This function is used to send a generic, reply-like message, containing custom data, to a specific node in a cluster, directly from the script. The message is marked as a "reply" so this function should ony be used for replying to a previously request-like message received. In order for the other node, which initially sent a request, to be able to correlate it with this reply, a communication tag, received along with the request, should be passed to the function.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster ID of the destination node;
- *dst_id* (int) - the ID of the destiantion node;
- *msg* (string) - actual message payload;
- *tag* (var) - communication tag.


The function can return the following values:


- *1* - successfully sent message to destination node or a valid next hop
- *-1* - local node is disabled so sending is impossbile
- *-2* - destination node is not reachable through any path according to the discovered topology
- *-3* - destination node or valid next hop appear to be reachable but send failed or other OpenSIPS internal error


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, LOCAL_ROUTE and EVENT_ROUTE.


```opensips title="cluster_send_rpl() usage"
...
event_route[E_CLUSTERER_REQ_RECEIVED] {
  cluster_send_rpl($param(cluster_id), $param(src_id), $var(my_reply), $param(tag));
}
...
				
```


#### cluster_broadcast_req(cluster_id, msg, [tag], [include_self])


This function has a similar behaviour to the `cluster_send_req()` function with the exception that the message is sent to all the nodes in the specified cluster.


- *include_self* (bool, optional, default: *false*) - raise the event for current node as well, but without actually sending a packet (both req and rpl).


The function can return the following values:


- *1* - successfully sent message to at least one node;
- *-1* - local node is disabled so sending is impossbile;
- *-2* - all nodes in the cluster are unreachable according to the discovered topology;
- *-3* - send failed for all nodes in the cluster or other OpenSIPS internal error.


The meaning of the parameters is the same as for `cluster_send_req()`.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, LOCAL_ROUTE and EVENT_ROUTE.


```opensips title="cluster_broadcast_req() usage"
...
# also raise the event for current node
cluster_broadcast_req($var(cl_id), $var(share_data), , true);
...
				
```


#### cluster_check_addr(cluster_id, ip, addr_type)


This function checks whether the given IP address belongs
					to one of the nodes in the cluster.


Parameters:


- *cluster_id* (int)
- *ip* (string)
- *addr_type* (string, optional) -
						select the address of the node that the comparison
						is made against, with the possible values of:
						
							
								*"sip"* (default) - a node's DB provisioned SIP address
							
							
								*"bin"* - a node's BIN interface listener


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, LOCAL_ROUTE and EVENT_ROUTE.


```opensips title="cluster_check_addr() usage"
...
if (cluster_check_addr(1, $si)) {
	...
}
...
				
```


### Exported MI Functions


#### clusterer:reload


Replaces obsolete MI command: *clusterer_reload*.


Reloads data from the clusterer database. The currently established topology will be lost and the node will rediscover the new topology.


Name: *clusterer:reload*


Parameters:*none*


MI FIFO Command Format:


```bash
		opensips-cli -x mi clusterer:reload
		
```


#### clusterer:list


Replaces obsolete MI command: *clusterer_list*.


Lists information(node id, URL, link state with that node etc.) about the other nodes in each cluster.


Name: *clusterer:list*


Parameters:*none*


```bash title="clusterer:list usage"
$ opensips-cli -x mi clusterer:list
{
    "Clusters": [
        {
            "cluster_id": 1,
            "Nodes": [
                {
                    "node_id": 1,
                    "db_id": 1,
                    "url": "bin:127.0.0.1",
                    "link_state": "Up",
                    "next_hop": "1",
                    "description": "none"
                }
            ]
        }
    ]
}
```


#### clusterer:list_topology


Replaces obsolete MI command: *clusterer_list_topology*.


Lists each cluster's topology from the local node's perspective as an adjacency list. A node appears as a neighbour if the link with that node is up.


Note that if a node id appears in multiple clusters, it refers to the same instance that belongs to different clusters, for which it has a different topology.


Name: *clusterer:list_topology*


Parameters:*none*


```bash title="clusterer:list_topology usage"
$ opensips-cli -x mi clusterer:list_topology
{
    "Clusters": [
        {
            "cluster_id": 1,
            "Nodes": [
                {
                    "node_id": 2,
                    "Neighbours": [
                        1
                    ]
                },
                {
                    "node_id": 1,
                    "Neighbours": [
                        2
                    ]
                }
            ]
        }
    ]
}
```


#### clusterer:set_status


Replaces obsolete MI command: *clusterer_set_status*.


Sets the status(Enabled/Disabled) of a node. If the local instance is disabled, the node will not send any messages and ignore received ones thus appearing as a failed node in the topology (from the other node's perspective). If a different node is disabled, the specified node will simply be ignored by the local instance in terms of sending/receiving any messages, as if no longer part of the topology.


Name: *clusterer:set_status*


Parameters:


- *cluster_id* - indicates the id of the cluster.
- *node_id* (optional) - indicates the id of the node to be disabled.
			If missing, the local instance will be disalbed.
- *status* - indicates the new status(0 - Disabled, 1 - Enabled).


MI FIFO Command Format:


```bash
		#disable the local instance
		opensips-cli -x mi clusterer:set_status 1 0
		#disable node ID 3
		opensips-cli -x mi clusterer:set_status 1 3 0
		
```


#### clusterer:remove_node


Replaces obsolete MI command: *clusterer_remove_node*.


Removes a node from the cluster's topology. It is enough to run the function
			on a single node in order to remove the target node from all the other
			nodes in the cluster. If the node to be removed is running when triggering
			this function, it will be automatically disabled (equivalent to running
			[mi set status](#mi_set_status) on that specific node).


This function can only be used when [db mode](#param_db_mode) is set to
			*0* (disabled).


Name: *clusterer:remove_node*


Parameters:


- *cluster_id* - cluster ID
- *node_id* - ID of the node to be removed.


MI FIFO Command Format:


```bash
		opensips-cli -x mi clusterer:remove_node 1 3
		
```


#### clusterer:send_mi


Replaces obsolete MI command: *cluster_send_mi*.


Dispatches a given MI command to be run on a specific node in the cluster.


Name: *clusterer:send_mi*


Parameters:


- *cluster_id* - id of the cluster.
- *destination* - id of the destination node
- *cmd_name* - name of the MI command to be run
- *cmd_params* (optional) - array of parameters for
			the MI command to be run


Note that MI commands that require named parameters or arrays as
			parameter values are not currently supported.


MI FIFO Command Format:


```bash
opensips-cli -x mi clusterer:send_mi 1 3 lb_reload
		
```


#### clusterer:broadcast_mi


Replaces obsolete MI command: *cluster_broadcast_mi*.


Dispatches a given MI command to be run on all the nodes in a cluster. The command is also executed locally.


Name: *clusterer:broadcast_mi*


Parameters:


- *cluster_id* - id of the cluster.
- *cmd_name* - name of the MI command to be run
- *cmd_params* (optional) - array of parameters for
			the MI command to be run


Note that MI commands that require named parameters or arrays as
			parameter values are not currently supported.


MI FIFO Command Format:


```bash
opensips-cli -x mi clusterer:broadcast_mi 1 dr_reload partition_5
		
```


#### clusterer:list_cap


Replaces obsolete MI command: *clusterer_list_cap*.


Lists the registered capabilities and their states.


Name: *clusterer:list_cap*


Parameters:*none*


```bash title="clusterer:list_cap usage"
$ opensips-cli -x mi clusterer:list_cap
{
    "Clusters": [
        {
            "cluster_id": 1,
            "Capabilities": [
                {
                    "name": "dialog-dlg-repl",
                    "state": "Ok",
                    "enabled": "yes"
                },
                {
                    "name": "dialog-prof-repl",
                    "state": "Ok",
                    "enabled": "yes"
                }
            ]
        }
    ]
}
```


#### clusterer:set_cap_status


Replaces obsolete MI command: *clusterer_set_cap_status*.


Sets the status(Enabled/Disabled) of a capability. If a capability is disabled, the node will not send any replication/sync messages belonging to that capability. Likewise, received messages will be dropped. Also, the cabability will transition to a "not synced" state and the node will no longer be able to be a donor for syncing.


Name: *clusterer:set_cap_status*


Parameters:


- *cluster_id* - the id of the cluster
- *capability* - name of the capability, as listed by
			[mi list cap](#mi_list_cap)
- *status* - indicates the new status(0 - Disabled, 1 - Enabled).


MI FIFO Command Format:


```bash
		#disable dialog replication in cluster 1
		opensips-cli -x mi clusterer:set_cap_status 1 dialog-dlg-repl 0
		#enable dialog profile replication in cluster 2
		opensips-cli -x mi clusterer:set_cap_status 2 dialog-prof-repl 1
		
```


#### clusterer:shtag_set_active


Replaces obsolete MI command: *clusterer_shtag_set_active*.


Set the given sharing tag to the *active* state.
		The information about this change is also broadcasted in the cluster 
		in order to force any other node that may be active on this tag to 
		step down to backup.


Name: *clusterer:shtag_set_active*


Parameters: *tag* - the name of
		the tag to be set active and the cluster it belogs to, in the
		format 'tag/cluster_id'.


MI FIFO Command Format:


```bash
		opensips-cli -x mi clusterer:shtag_set_active vip1/3
		
```


#### clusterer:list_shtags


Replaces obsolete MI command: *clusterer_list_shtags*.


Lists all known sharing tags and their states.


Name: *clusterer:list_shtags*


Parameters: *Command takes no parameters*


MI FIFO Command Format:


```bash
		opensips-cli -x mi clusterer:list_shtags
		
```


### Exported Script Variables


#### $cluster.sh_tag


This is a read/write variable that allows access to the
			sharing tags managed by the clusterer module.


The name of such a variable has the format of 
			*tag_name/cluster_id*, like 
			*$cluster.sh_tag(vip/3)* accessing the
			sharing tag "vip" from cluster ID 3.


When setting, a sharing tag may be only switched to active by
			assigned it:


- "active"
- 1


When reading it value, a sharing tag returns:


- "active" or 1
- "backup" or 0


A NULL value may returned only as a result of an internal error
			(like memory errors).


### Exported Events


#### E_CLUSTERER_REQ_RECEIVED


This event is raised when a generic, request-like, clusterer message is received. This type of message is sent directly from the script and not by an OpenSIPS module.


Parameters:


- *cluster_id* - The cluster ID of the source node.
- *src_id* - The ID of the source node.
- *msg* - The actual message payload.
- *tag* - The communication tag of this message, generated by the source node. This could be used to send a reply corresponding to the received message by providing the tag to the `cluster_send_rpl()` function.


#### E_CLUSTERER_RPL_RECEIVED


This event is raised when a generic, reply-like, clusterer message is received. This type of message is sent directly from the script and not by an OpenSIPS module.


Parameters:


- *cluster_id* - The cluster ID of the source node.
- *src_id* - The ID of the source node.
- *msg* - The actual message payload.
- *tag* - The communication tag of this message. This could be used to match the received reply with a request sent with the `cluster_send_req()` or `cluster_broadcast_req()` functions.


#### E_CLUSTERER_NODE_STATE_CHANGED


This event is raised when the state of a node changes in terms of
			availability.


Parameters:


- *cluster_id* - The cluster ID.
- *node_id* - The ID of the node.
- *new_state* - The new state of the node, with
				the possible values: 0 - down, 1 - up.


#### E_CLUSTERER_SHARING_TAG_CHANGED


This event is raised when the state of a sharing tag changes.


Parameters:


- *name* - The name of the sharing tag.
- *cluster* - The cluster ID.
- *state* - The new state of the sharing tag,
				the possible values: "active" or "backup".
- *reason* - short text describing what
				triggered the change of the state, like a another node
				stepping as active, an MI command or script variable.


### Exported Status/Report Identifiers


The module provides the *clusterer* Status/Report group.


#### sharing_tags


The *sharing_tags* identifier is provided for reporting state
	changes of the sharing_tags (between active and backup), along with the reason of
	the change. This identifier has a 200 records history before discarding the old ones.


```json
{
    "Name": "sharing_tags",
    "Reports": [
        {
            "Timestamp": 1652367224,
            "Date": "Thu May 12 17:53:44 2022",
            "Log": "TAG <HA>, cluster 1, became backup due to cluster broadcast from 2"
        },
        {
            "Timestamp": 1652367326,
            "Date": "Thu May 12 17:55:26 2022",
            "Log": "TAG <HA>, cluster 1, became active due to MI command"
        }
    ]
}

	
```


#### node_states


The *node_states* identifier is used for reporting node state
	changes (in terms of availability). This identifier has a 200 records history
	before discarding the old ones.


```json
{
    "Name": "node_states",
    "Reports": [
        {
            "Timestamp": 1656489246,
            "Date": "Wed Jun 29 10:54:06 2022",
            "Log": "Node [2], cluster [1] is UP"
        },
        {
            "Timestamp": 1656489261,
            "Date": "Wed Jun 29 10:54:21 2022",
            "Log": "Node [2], cluster [1] is DOWN"
        }
    ]
}

	
```


#### cap:[capability_name]


Each capability registered to the clusterer module has a corresponding
	identifier, named *cap:[capability_name]*, used for
	providing the status of the data syncing for that capability. This status
	reflects the progress of the syncing process and can have the following values:


- *-3* - not synced
- *-2* - sync pending (waiting for either a suitable
			donor node or actual sync data)
- *-1* - sync in progress
- *1* - synced (either sync has completed or the
			capability does not require data syncing at all)


```json
{
    "Name": "cap:dialog-dlg-repl",
    "Readiness": true,
    "Status": 1,
    "Details": "synced"
},
	
```


The capability identifiers also provide reports regarding the main stages of
	the sync process. These identifiers have a 200 records history before discarding
	the old ones.


```json
{
    "Name": "cap:dialog-dlg-repl",
    "Reports": [
        {
            "Timestamp": 1656966903,
            "Date": "Mon Jul  4 23:35:03 2022",
            "Log": "Sync requested"
        },
        {
            "Timestamp": 1656966904,
            "Date": "Mon Jul  4 23:35:04 2022",
            "Log": "Sync started from node [1]"
        },
        {
            "Timestamp": 1656966906,
            "Date": "Mon Jul  4 23:35:06 2022",
            "Log": "Sync completed, received [10000] chunks"
        }
    ]
},

	
```


For how to access and use the Status/Report information, please see
	[Status/Report Interface documentation](https://docs.opensips.org/manual/3-4/interface-statusreport).


### Usage Example


This section provides an usage example for replicating ratelimit
		pipes between two OpenSIPS instances. It uses the clusterer module to
		manage the replicating nodes, and along with the
		*proto_bin* module, to send the replicated information.


The setup topology is simple: we have two OpenSIPS nodes running on
		two separate machines (although they could run on the same machine as
		well): *Node A* has IP 192.168.0.5 and
		*Node B* has IP 192.168.0.6. Both have, besides the
		traffic listeners (UDP, TCP, etc.), BIN listeners bound on port
		*5566*. These listeners will be used for the binary
		communication.


We insert in the the *clusterer* table the following:


```c title="Example database content - clusterer table"
+----+------------+---------+----------------------+-------+-----------------+----------+----------+-------+-------------+
| id | cluster_id | node_id | url                  | state | no_ping_retries | priority | sip_addr | flags | description |
+----+------------+---------+----------------------+-------+-----------------+----------+----------+-------+-------------+
| 10 |          1 |       1 | bin:192.168.0.5:5566 |     1 |                3|       50 | NULL     | NULL  | Node A      |
| 20 |          1 |       2 | bin:192.168.0.6:5566 |     1 |                3|       50 | NULL     | NULL  | Node B      |
+----+------------+---------+----------------------+-------+-----------------+----------+----------+-------+-------------+
		
```


- "cluster_id" - identifier of the cluster. All nodes within a
					group/cluster should have the same id (in our example,
					both nodes have ID *1*). The values must be greater than 0.
- "node_id" - identifier of the machine/node so each instance within a
					cluster should have a different ID. The values must be greater than 0. In our example,
					*Node A* will have ID 1, and
					*Node B* ID 2.
- "url" - address where all the BIN packets for that instance will be
				sent to.
- "state" - state of the node: *1* means Enabled,
				*0* means Disabled. A disabled node will not send any BIN packets
				and will drop received ones.
- "no_ping_retries" - maximum number of ping retries before the link
				with a node is considered down.
- "priority" - the priority of a node to be chosen
				as next hop in case of same length(number of hops) paths when rerouting messages;
				it is not relevant for this two-node topology example.
- "sip_addr" - SIP address for the node that is transparently
				provided to modules; it has no use for the ratelimit module in our example.
- "flags" - used to define a seed node; it has no use in our example.
- "description" - an opaque value used to
					describe the node


After provisioning the two nodes in the database, we have to configure
		the two instances of OpenSIPS. First, we configure *Node
			A*:


```opensips title="*Node A* configuration"
...
socket= bin:192.168.0.5:5566 # bin listener for Node A

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
modparam("clusterer", "db_url", "mysql://opensips@192.168.0.7/opensips")
modparam("clusterer", "my_node_id", 1) # node_id for Node A

loadmodule "ratelimit.so"
modparam("ratelimit", "pipe_replication_cluster", 1)
...
		
```


Similarly, the configuration for *Node B* is as follows:


```opensips title="*Node B* configuration"
...
socket= bin:192.168.0.6:5566 # bin listener for Node B

loadmodule "proto_bin.so"

loadmodule "clusterer.so"
# ideally, use the same database for both nodes
modparam("clusterer", "db_url", "mysql://opensips@192.168.0.7/opensips")
modparam("clusterer", "my_node_id", 2) # node_id for Node B

loadmodule "ratelimit.so"
modparam("ratelimit", "pipe_replication_cluster", 1)
...
		
```


Starting the two OpenSIPS instances with the above configurations provides
	your platform the ability to used shared ratelimit pipes in a very
	efficient and scalable way.


### Exported Statistics


#### clusterer_nodes


Returns the total number of cluster nodes.


#### clusterer_nodes_up


Returns the total number of cluster nodes in the UP state.


#### clusterer_nodes_down


Returns the total number of cluster nodes not in the UP state.


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


- *CLUSTERER_SEND_SUCCESS* - successfully sent packet to destination node or a valid next hop
- *CLUSTERER_CURR_DISABLED* - current node is disabled so sending is impossbile
- *CLUSTERER_DEST_DOWN* - destination node is not reachable through any path according to the discovered topology
- *CLUSTERER_SEND_ERR* - destination node or valid next hop appear to be reachable but send failed


#### send_all(packet, cluster_id)


Send the given BIN packet to all the nodes in the specified cluster. The function operates similarly to *send_to*.


Meaning of the parameters is as follows:


- *bin_packet_t packet* - the packet to be sent
- *int cluster_id* - the cluster id


The function returns one of the following:


- *CLUSTERER_SEND_SUCCESS* - successfully sent packet to at least one node
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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
