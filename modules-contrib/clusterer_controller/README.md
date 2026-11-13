---
title: "CLUSTERER_CONTROLLER Module"
description: "The clusterer module with a controller added: the nodes of a cluster find each other over encrypted UDP multicast and elect a master, which assigns their node IDs and moves the sharing tags on failover. It is loaded instead of clusterer."
---

## Admin Guide


### Overview


The *clusterer* module is used to organize multiple OpenSIPS instances into groups(clusters) in which the nodes can communicate with each other in order to replicate, share information or perform distributed tasks. The distributed logic is performed either by different modules that use the *clusterer* interface (i.e. the *dialog* module can replicate dialogs/profiles, the *ratelimit* module can share pipes across multiple 
instances etc.) or at the script level. The *clusterer* module itself only provides an interface to send/receive BIN packets and get notifications about node availability. It achieves this by internally learning the cluster topology and state of the nodes. Provisioning the nodes within a cluster is done over the database or through the configuration script. The node-related information can be checked and triggered to be reloaded by sending commands over the MI interface.


The topology established by the *clusterer* module is an overlay of nodes where the "links" represent communication availability at BIN interface level. For this purpose, a probing mechanism is used, consisting of regular pings to all nodes in a cluster for which replies must be received within a given interval. All nodes in the cluster exchange information about the state of their links with other nodes and compute a "routing table" which gives a next hop for each destination. The metric for the shortest path is the number of hops. When there is no direct link to a destination, the BIN packet sent by a module is transparently routed through the cluster.


Note that an OpenSIPS instance can belong to multiple clusters, communicating and establishing the topology separately for each one. In order to provision this in the database or the script, each node has an unique ID at global level, which can be referenced in each cluster.


An OpenSIPS instance can dynamically learn all the nodes in the cluster if database provisioning is not desired. It is enough to define at least one neighbour in the script in order to discover all the cluster components.


*clusterer_controller.so* is this *clusterer* module with a controller added. It registers as *clusterer*, so it is loaded instead of *clusterer.so* (loading both is refused at startup), it is configured with *modparam("clusterer", ...)*, and the modules and scripts that use *clusterer* work with it unchanged. Apart from the controller - its own *cl_ctr_* and *clusterer_ctrl* files and the hooks that call them - the code is kept the same as *clusterer*'s, so a fix to one applies to both.


The controller runs the clusters declared with *use_controller=1* in [cluster_options](#cluster_options-string), each described by a [cluster](#cluster-string) entry. Their nodes find each other over encrypted UDP multicast and elect a master, which gives every node its node ID and tells the others its BIN address - no database, *my_node_info* or *neighbor_node_info* is needed, and every node uses the same configuration. By default the master also holds the cluster's sharing tags, which move to the new master on failover. All other clusters work exactly as with *clusterer*; without a *cluster* parameter the controller starts no process.


```opensips title="A controller-managed cluster"
...
socket=bin:10.0.0.1:5566	# the only line that differs between the nodes

loadmodule "proto_bin.so"
loadmodule "clusterer_controller.so"
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
modparam("clusterer", "cluster", "id=1,multicast=239.0.0.1:3333")
modparam("clusterer", "password", "<long random secret>")
modparam("clusterer", "sharing_tag", "vip/1=backup")

loadmodule "dialog.so"
modparam("dialog", "dialog_replication_cluster", 1)
...
```


How a controller-managed cluster runs - the three planes it uses, a node's states from its first JOIN_REQ, how the master admits joiners, heartbeats and node events, elections, module broadcasts, and the key that seals each packet:


![How a controller-managed cluster runs](doc/clusterer_controller-overview.svg)


Measurements - forming 64 and 128 node clusters, replicating dialogs and contacts over multicast and over TCP - are in [doc/benchmarks.md](doc/benchmarks.md).


### Capabilities layer


The clusterer module also keeps track of the state of the nodes in terms of data synchronization for the functionalities (or "capabilities") implemented on top by other modules. Some capabilities require a full data sync(at OpenSIPS startup or at runtime via MI) from a valid "donor" node in the cluster that has the full data set. Furthermore, a capability can query the clusterer module in order to partition some distributed logic only over the synchronized nodes in the cluster.


Each node in the cluster starts with an empty dataset and tries to find
a suitable node to pull data from. In order to help "bootstrap" the
cluster, a "seed" node should be defined. This is done by setting the value
*seed* for the **flags**
column in the clusterer table(or the property with the same name in the
*my_node_info* parameter). The seed node will simply
fall back to a "synced" state after a configurable interval(
[seed_fallback_interval](#seed_fallback_interval) parameter). Note that
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
inter-cluster replication bridges. Its name is configured using the
[db_bridges_table](#db_bridges_table) parameter (default: "clusterer_bridge"):


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
Sharing tags can be defined using the [sharing_tag](#sharing_tag) module parameter.


The "dst_node_csv" functions as a list of remote cluster nodes to try.
The module will attempt a single TCP send per node, in failover fashion (always same order).


At the time of writing, the only module using the new bridge replication
feature is ratelimit, through its
[bridge_replication](../ratelimit/README.md#bridge_replication-boolean)
parameter, in order to optimize its "CPS pipes broadcasting" replication
mechanism.


### Discovery and master election


Every node runs a controller process for each controller-managed cluster it is in. A starting node multicasts a join request; the master checks it (password, MTU and the settings named in [on_config_mismatch](#on_config_mismatch-string)), assigns the node an ID and announces it, with its BIN address, to every member, whose *clusterer* then links to it. Every node of such a cluster is a *seed* node. When no master answers within [query_time](#query_time-integer) seconds, the node founds the cluster as its master. A node that stops says goodbye; one that goes silent drops out of the election after 3 x *query_time* and is removed after 6 x *query_time*.


The master is the node with the highest IP among those heard lately, except that with [master_stickiness](#master_stickiness-integer) a live master keeps the role; the *backup* is the highest-IP other node. The master multicasts a keepalive every second. A member that stops hearing it - after 3 to 15 seconds, a wait learned from the gaps between keepalives - first asks the other members, and holds the election (for up to 30 seconds) while one of them still hears the master. A master asked about itself by more than half of the other members within 5 seconds - they do not hear it while it hears them, as when only its outgoing multicast is cut - steps down at once: its sharing tags go to *backup*, and it stands for no election until a master hears it again. A master that stops or enters maintenance hands over at once. When a network split heals, the master that hears more members wins, then the more recent mastership, and the other side rejoins it. A node that elects itself while nobody confirms the old master gone - most likely the node cut off - keeps the old term, and at the same term loses to a master that raised it; only between two of a kind does the higher IP win.


### Admission


The master admits joining nodes a few at a time: one at a time below 16 live members, four at a time from 16 on. A node told to wait keeps asking, and does not found a cluster of its own while the master answers. An admitted node is *connecting* until its BIN links to every member are up both ways, as *clusterer*'s link map shows them; meanwhile it is never master or backup and holds no sharing tag, and once *online* it syncs its replicated data again.


The messages of one admission, from the joining node's first JOIN_REQ until it is *online*:


![A node joining a controller-managed cluster](doc/clusterer_controller-join.svg)


A node still connecting after 10 seconds - its links blocked, say, or a host's neighbour (ARP) table full - is reported with a warning naming the links that are not up, the [E_CL_CTR_ADMISSION](#e_cl_ctr_admission) event and the [admissions_stuck](#admissions_stuck-cluster_id) statistic, and no more nodes are admitted until it goes online, as soon as its links come up, or leaves: more nodes would only need more of what it lacks. One still connecting after 60 seconds is *parked*, with another warning and the event: it stays connecting, with no role or sharing tag, and goes online once its links come up, but the queue moves on past it - past at most two parked nodes, so a fault that keeps every new node from connecting still stops admission. A new master admits nobody until it has heard every member, nor, when it could not confirm that the old master is gone, for 3 x [query_time](#query_time-integer) seconds: a master that is still live would admit nodes at the same time.


### Heartbeats and links


Every member multicasts a heartbeat each second, naming the nodes it has a BIN link up with and the state of each of its capabilities, so every node sees the whole cluster's links and which node can serve a sync, first-hand. *clusterer* does not ping the nodes of such a cluster at regular intervals, floods no link changes and exchanges no topology: a link is probed when a node is admitted and when it fails, and a node's link state reaches the others in its next heartbeat. To the modules, a node is up while its heartbeats arrive and the link to it is up; one silent for 4 seconds, or whose link stays down through its probes, is down. A node that suddenly stops hearing many members at once takes itself for the slow one and waits up to 16 seconds before reporting them down. A member whose heartbeats arrive while the link to it is down is reported with a warning naming it: the path to its BIN socket needs fixing.


Messages go to a node directly or not at all - never through another node. Every packet already travels over TCP on a routed IP network, so a path around a failure is the network's job (routing, multipath, bonding, VRRP), done once for every application and in well under a second; relaying through a third node would make it acknowledge data the destination never got, send it twice, and hide the fault from the operator. A send to a node whose link is down returns *destination down*, as it does when no path exists at all.


While no master is heard (an election in progress), members tell a joining node to wait, so it never founds a cluster of its own; a node runs no election of its own until it has been a member for 4 seconds.


### Broadcasts


A module's broadcast to a controller-managed cluster (*send_all*, *send_all_having*, [cluster_broadcast_req()](#cluster_broadcast_reqcluster_id-msg-tag-include_self), [clusterer:broadcast_mi](#clustererbroadcast_mi)) goes out as one encrypted multicast datagram instead of a TCP send to every node; one bigger than a datagram goes as numbered fragments. It travels on the cluster's group, on the port after the cluster's own unless *data_port=* in [cluster](#cluster-string) sets another, and [mcast_workers](#mcast_workers-integer) processes receive it. Messages to one node, sync data and bridges stay on TCP.


Each node numbers its broadcasts, and its heartbeat carries the last number. A node that misses one asks the sender for it by unicast and dispatches every sender's broadcasts in the order they were sent; a TCP message is dispatched after the broadcasts its sender sent before it (waiting up to 500 ms for them). With [dispatch_jobs](#dispatch_jobs) on, the handlers then run in SIP workers, side by side, as for messages by TCP; script event routes always do. The sender keeps its last [mcast_window](#mcast_window-integer) datagrams for this. Broadcasts that cannot be recovered within 2 seconds are reported in a warning and in [mcast_gaps](#mcast_gaps-cluster_id), and the sender is reported down and then up to this node's modules, as after a broken TCP connection; every capability that syncs at startup then syncs again, from that sender when it can serve it.


So the order holds, and a loss is either repaired or followed by a sync, except in four cases, where order is relaxed but nothing is lost: a TCP message that waited 500 ms goes without the broadcasts sent before it (counted in [mcast_barrier_late](#mcast_barrier_late-cluster_id), with a warning at most once a minute per sender); one that arrives while no shared memory is left to hold it goes at once; one from a sender whose broadcasts this node does not track yet - before its first heartbeat or broadcast arrives - is not held; and those still waiting when their sender restarts go then.


Broadcasts go by multicast only while every live member takes them so; a node with [mcast_broadcasts](#mcast_broadcasts-integer) off, one that could not open its broadcast socket, or one that lacks the *mcast-data* capability, makes the whole cluster send them by TCP.


### Node IDs


The master assigns the node IDs of a controller-managed cluster, 1 to 256, so such a cluster has at most 256 nodes. A joining node proposes one: [my_node_id](#my_node_id) when it is set, otherwise an ID derived from the machine (its SMBIOS product UUID outside containers, else its first MAC address, else a random value) and its controller IP, so that it stays the same across restarts. The master gives a returning node its previous ID - the ID of a node that left is held for its address for an hour - otherwise the proposed ID if it is free, otherwise the lowest free one. Derived IDs may collide, so set *my_node_id* where an ID must never change. A node proposes the same ID in all its clusters but may get different ones - when its ID is taken in one of them; [get_my_id()](#get_my_id) then returns -1, so *tm*'s anycast Via cid, which needs one ID per node, is off on that node (a warning says so) until its IDs agree, e.g. with a *my_node_id* free in all of them. Every node needs its own IP address (no NAT between the nodes).


### Sharing tags and maintenance


With [manage_shtags](#manage_shtags-integer) on (the default), the sharing tags of a controller-managed cluster follow its master: every node starts with them in *backup*, whatever [sharing_tag](#sharing_tag) says, and the master activates them, so a restarted node never takes a tag from the node holding it. [clusterer:shtag_force](#clusterershtag_force) pins the tags to another node, and [release_tag_when_isolated](#release_tag_when_isolated-integer) makes a master cut off from most of the cluster release them.


Maintenance ([clusterer:maintenance](#clusterermaintenance), [cl_ctr_set_maintenance()](#cl_ctr_set_maintenancecluster_id-state)) drains a node, e.g. before an upgrade: it stays a member, with its node ID and BIN links, but it is never master or backup and holds no sharing tag. At the *full* level the other nodes also stop replicating to it. When every node is in maintenance, one of them is still master. The state is announced by the node itself, survives a master failover and ends when the node restarts.


### Multiple clusters


A node can be in up to 16 controller-managed clusters, each with its own *cluster_options* and *cluster* entries, controller process, master and node IDs. Each needs its own multicast group and port (clusters may share a group on different ports, or a port on different groups). With more than one, every *cluster* entry names its *bin_socket*; one BIN socket can serve them all.


Controller-managed and native clusters (database, or *my_node_info* / *neighbor_node_info*) can be mixed on one node. A cluster ID is either one or the other; the database and *db_mode* concern only the native clusters, whose sharing tags keep their usual handling.


### Network requirements


- IPv4 multicast (IPv6 is not supported) between all nodes, on each cluster's group and port, with a TTL of 32, all the time: every member's heartbeat travels on it each second. The group is joined on the interface of [my_ip](#my_ip-string). With IGMP snooping the VLAN needs an IGMP querier; across routers, multicast routing is needed.
- Unicast UDP between the nodes on the same port, and TCP to every node's BIN socket.
- Plain BIN, for now: a controller-managed cluster advertises and connects to BIN sockets only; BINS (TLS) may be added later if needed. What goes by BIN - syncs, messages to one node, broadcasts while they go by TCP - is neither encrypted nor authenticated; the controller's own packets and the multicast broadcasts are.
- The same for broadcasts, multicast and unicast UDP, on the port after the cluster's own (or *data_port=* in [cluster](#cluster-string)), unless [mcast_broadcasts](#mcast_broadcasts-integer) is off. When only these datagrams are filtered, every broadcast has to be repaired by unicast: the sender then logs a warning naming the node that keeps asking, and [mcast_repairs](#mcast_repairs-cluster_id) grows.
- The same MTU on every node of a cluster: it is read from the interface, and a node with a different one is refused.
- Fragmented UDP must pass: above about 80 nodes (1500-byte MTU) the member list no longer fits one datagram.
- A firewall must let in, from the other nodes, UDP to the group and to the node's own address on the cluster's port and on its broadcast port, IGMP where it is filtered, and TCP to the BIN port.
- The kernel's neighbour (ARP) table must hold every node besides the other hosts on the segment: Linux refuses new entries past *net.ipv4.neigh.default.gc_thresh3* (1024 by default) and may expire entries above *gc_thresh1* (128). With more than about 100 nodes on one segment, raise *gc_thresh1/2/3* above the number of hosts on it; a full table shows as nodes stuck connecting.
- One OpenSIPS instance per host and cluster port.


### Security


The controller's packets are encrypted and authenticated (XChaCha20-Poly1305) with keys derived from the cluster's [password](#password-string), and protected against replay. The password is the only credential: whoever holds it can join the cluster and can become its master, and every node holding it is trusted - the packets prove who sent them, not that the sender behaves, so the controller does not defend against a member that misbehaves. Use a long random secret, the same on every node. A node with another password cannot join and shuts down, so changing it means stopping every node, changing it everywhere and starting them again. In controller-managed clusters, *clusterer* ignores the BIN messages that would change membership or sharing tags, since BIN is not authenticated - nor encrypted, as these clusters use plain BIN for now ([Network requirements](#network-requirements)).


Each cluster also has an identity, a UUID chosen by its first master or pinned with *uuid=* in [cluster](#cluster-string), so another deployment using the same group, password and cluster ID is not merged with it.


### Upgrading


All nodes of a cluster must speak the same controller wire version (4 in this build, which brought the heartbeats); a node refuses packets of another version and logs the sender once a minute. A change of wire version needs the whole cluster upgraded at once - stop every node, upgrade, start again - because the two versions do not see each other and each side would elect a master. Within a wire version, nodes can be upgraded one at a time: each advertises its capabilities - *probe*, *maint_set*, *maint_full*, *admission* and *heartbeat*, which every build of wire version 4 has, and *mcast-data* - and one that needs the other members, such as multicast broadcasts, is used only once every live member has it ([clusterer:list_config](#clustererlist_config) shows what they share).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module* - if [db_mode](#db_mode)
is *1*.
- *proto_bin module*.


With a [cluster](#cluster-string) parameter, at least one BIN listener is needed, and none may be a wildcard (`socket=bin:IP:PORT`, not `bin:*:PORT`).


#### External Libraries or Applications


The following libraries or applications must be installed before
running OpenSIPS with this module loaded:


- *libsodium* - the cryptography of the controller; its development files are needed to build the module.


The module builds on Linux only. It is a contrib module, built and installed explicitly:


```bash title="build and install"
make modules=modules-contrib/clusterer_controller modules-contrib
make modules=modules-contrib/clusterer_controller install-modules-all
```


### Exported Parameters


#### my_node_id


The id of the local instance. This parameter must be equal to one of the
*node_id* fields in the database.


*No default value. It must be set, to a value greater than zero, for native (database or my_node_info) clusters; in a controller-managed cluster it is only the node ID this node proposes (see [Node IDs](#node-ids)).*


```opensips title="Set my_node_id parameter"
...
modparam("clusterer", "my_node_id", 1)
...
		
```


#### db_mode


Specifies whether the node information for the local instance,
as well as other instances in the cluster, should be loaded from
the database or configured in the script(see [my_node_info](#my_node_info)
and [neighbor_node_info](#neighbor_node_info)). A value of "0"
means that DB is not used and the cluster topology in terms of node
information will be discovered dynamically at runtime.


If DB mode is enabled, only the nodes defined in the database will be
accepted by this instance.


Controller-managed clusters never use the database.


*Default value is "1", or "0" when neither db_url nor the core's default database URL is set.*


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


#### db_bridges_table


The name of the table storing the inter-cluster bridge definitions.


*Default value is "clusterer_bridge".*


```opensips title="Set db_bridges_table parameter"
...
modparam("clusterer", "db_bridges_table", "clusterer_bridge")
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


This parameter is required if [db_mode](#db_mode) is set
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
can be set multiple times to define multiple neighbors to connect to (or
the same neighbor but in different clusters).


Parameter format: multiple "*prop=value*" property
definitions separated by '*,*' where the name of
the properties is the same as the DB column names. At least the
*cluster_id*, *node_id*
and *url* properties must be defined.


This parameter should be set at least once if
[db_mode](#db_mode) is set to *0* in order
to properly learn the cluster topology. If not set, the only way to learn
the node topology is by other nodes connecting to the local instance.


```opensips title="Set neighbor_node_info parameter"
...
modparam("clusterer", "neighbor_node_info", "cluster_id=1,node_id=2,url=bin:192.168.0.6:5566")
...
		
```


#### ping_interval


The interval in seconds between regular pings sent to a neighbour node. Nodes of a controller-managed cluster are not pinged at intervals (see [Heartbeats and links](#heartbeats-and-links)), so it does not apply to them.


*Default value is "4"*


```opensips title="Set ping_interval parameter"
...
modparam("clusterer", "ping_interval", 1)
...
		
```


#### ping_timeout


The time in milliseconds to wait for a reply to a previously sent ping before retrying or considering the link with the neighbour node down. This is also the interval between successive retries if the send fails. In a controller-managed cluster it is how long each probe of a link waits.


*Default value is "1000", or "3000" with a controller-managed cluster: a shorter timeout makes a loaded node's links flap, and in a full mesh each flap reaches every node*


```opensips title="Set ping_timeout parameter"
...
modparam("clusterer", "ping_timeout", 500)
...
		
```


#### node_timeout


The time in seconds to wait before pinging is restarted for a failed node. In a controller-managed cluster a down link is probed again after it only while the node's heartbeats arrive, and at once when they come back; a probe that was running then starts over, as the node may not have been able to answer it.


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


The interval, in seconds, since the last sync data packet received
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
which causes abnormally high CPU loads. Disabling this dispatching
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
to destination is unavailable. Disabling may improve stability in
two-node topologies. Ignored in a controller-managed cluster, whose
nodes are always reached directly (see [Heartbeats and links](#heartbeats-and-links)).
Set it to zero to disable or to non-zero to enable it.


*Default value is "1 (enabled)".*


```opensips title="Set enable_rerouting parameter"
...
modparam("clusterer", "enable_rerouting", 0)
...
				
```


#### cluster_options (string)


Puts a cluster under the controller: *"cluster_id=N, use_controller=1"*. Set once per controller-managed cluster; each needs a matching [cluster](#cluster-string) entry and the reverse, or startup fails. A cluster ID cannot be both controller-managed and native (database or *my_node_info*); *use_controller=0*, the default, leaves the cluster native.


*No default value.*


```opensips title="Set cluster_options parameter"
...
modparam("clusterer", "cluster_options", "cluster_id=1, use_controller=1")
...
```


#### cluster (string)


How the controller runs one controller-managed cluster, as comma-separated *key=value* pairs:


- *id* (required) - the cluster ID, 1 to 65535, as in *cluster_options*.
- *multicast* (required) - the IPv4 multicast group and UDP port, *A.B.C.D:PORT* (port 3333 when omitted); each cluster of a node needs its own.
- *password* - this cluster's [password](#password-string).
- *bin_socket* - the BIN listener advertised for this cluster, *bin:IP:PORT* (plain BIN only, for now). Required when several clusters are defined (they may all name the same one); otherwise the only BIN listener is used, or the first one, with a warning.
- *manage_shtags*, *master_stickiness* - this cluster's value of the parameter of that name.
- *uuid* - pins the cluster's identity: a UUID, or any string, which is hashed into one. All nodes of the cluster must use the same value.
- *data_port* - the UDP port of this cluster's [broadcasts](#broadcasts), the same on every node; by default the port after the cluster's own. It must not be any cluster's *multicast* port.


Set it once per cluster, up to 16 times.


*No default value.*


```opensips title="Set cluster parameter"
...
modparam("clusterer", "cluster",
	"id=1,multicast=239.0.0.1:3333,bin_socket=bin:10.0.0.1:5566")
modparam("clusterer", "cluster",
	"id=2,multicast=239.0.0.1:3334,bin_socket=bin:10.0.0.1:5566,manage_shtags=0")
...
```


#### password (string)


The shared secret of the controller-managed clusters, from which the keys of their traffic are derived; *password=* in a [cluster](#cluster-string) entry overrides it. Every node of a cluster must use the same one: a node with another one, hearing traffic it cannot read and never let in, shuts down after about half a minute - not sooner, as a master that would admit it may just have failed. A startup warning flags the default or a weak password; use a long random string, e.g. from *openssl rand -base64 32*.


*Default value is "3eCrEt\*5629" (change it).*


```opensips title="Set password parameter"
...
modparam("clusterer", "password", "<long random secret>")
...
```


#### my_ip (string)


The IPv4 address of this node's controller: its identity among the peers (the election compares it), and through the interface that owns it, where it joins the multicast groups. Startup fails if no local interface has it. It does not change the BIN socket advertised to *clusterer*.


*Default value is auto-detected: the first IPv4 address of [interface](#interface-string) when that is set, else the address the kernel picks to reach the first cluster's multicast group.*


```opensips title="Set my_ip parameter"
...
modparam("clusterer", "my_ip", "10.0.0.1")
...
```


#### interface (string)


The network interface of the controller's traffic; the controller uses its first IPv4 address (with a warning when it has several). Ignored when [my_ip](#my_ip-string) is set.


*Default value is auto-detected (see my_ip).*


```opensips title="Set interface parameter"
...
modparam("clusterer", "interface", "eth0")
...
```


#### query_time (integer)


Seconds between the heartbeats each node sends. A node not heard for 3 x *query_time* drops out of the election, and after 6 x *query_time* it is removed. From 1 to 60, and the same on every node of a cluster (see [on_config_mismatch](#on_config_mismatch-string)). A failed master is detected by its one-second keepalive, not by this.


*Default value is "5".*


```opensips title="Set query_time parameter"
...
modparam("clusterer", "query_time", 3)
...
```


#### manage_shtags (integer)


With *1*, the controller decides which node holds the sharing tags of each controller-managed cluster (see [Sharing tags and maintenance](#sharing-tags-and-maintenance)); with *0*, the cluster's tags are handled as with *clusterer*. Can be set per cluster in [cluster](#cluster-string), and must be the same on every node of a cluster.


*Default value is "1".*


```opensips title="Set manage_shtags parameter"
...
modparam("clusterer", "manage_shtags", 0)
...
```


#### master_stickiness (integer)


With *1*, a live master keeps its role when a node with a higher IP joins; with *0*, the node with the highest IP always becomes master, at the cost of more handovers. Can be set per cluster in [cluster](#cluster-string), and must be the same on every node of a cluster.


*Default value is "1".*


```opensips title="Set master_stickiness parameter"
...
modparam("clusterer", "master_stickiness", 0)
...
```


#### release_tag_when_isolated (integer)


With *1*, a master that hears fewer than half of the members it last had, for 3 x *query_time*, releases the active sharing tags until it hears a majority again - the others have most likely elected another master. It does not help when a cluster splits in even halves, a node left alone releases too, and a two-node cluster never releases.


*Default value is "0".*


```opensips title="Set release_tag_when_isolated parameter"
...
modparam("clusterer", "release_tag_when_isolated", 1)
...
```


#### on_config_mismatch (string)


What happens when a node's *manage_shtags*, *master_stickiness* or *query_time* differ from the cluster's:


- *reject* - the master refuses the node, which logs the difference and shuts down; two partitions whose masters differ do not merge.
- *warn* - the node joins, and a *CONFIG MISMATCH* warning is logged for each peer that differs.
- *adopt* - the node joins and takes the master's values.


A different MTU is always refused. It applies to the whole node, not per cluster.


*Default value is "reject".*


```opensips title="Set on_config_mismatch parameter"
...
modparam("clusterer", "on_config_mismatch", "warn")
...
```


#### mcast_broadcasts (integer)


Set to *0* to keep [broadcasts](#broadcasts) on TCP: this node opens no broadcast socket and stops advertising *mcast-data*, so every node of its controller-managed clusters sends its broadcasts by TCP.


*Default value is "1".*


```opensips title="Set mcast_broadcasts parameter"
...
modparam("clusterer", "mcast_broadcasts", 0)
...
```


#### mcast_workers (integer)


The number of processes that receive [broadcasts](#broadcasts), 1 to 32, for all controller-managed clusters together. With [dispatch_jobs](#dispatch_jobs) off, the modules' handlers run in them.


*Default value is "2".*


```opensips title="Set mcast_workers parameter"
...
modparam("clusterer", "mcast_workers", 4)
...
```


#### mcast_window (integer)


How many of its last broadcast datagrams a node keeps to resend to a node that missed them, 64 to 65536, per controller-managed cluster; each takes about 1.5 KB of shared memory. At 1000 broadcasts a second the default covers 2 seconds.


*Default value is "2048".*


```opensips title="Set mcast_window parameter"
...
modparam("clusterer", "mcast_window", 8192)
...
```


### Exported Functions


#### cluster_send_req(cluster_id, dst_id, msg, [tag])


This function is used to send a generic, request-like message, containing custom data, to a specific node in a cluster, directly from the script. The message is not a "request" per se but according to the logic on the receiving side, that node can send back a reply. In order to correlate a received reply with the request sent out, the function returns, through the *tag* parameter, a randomly generated communication tag, which is sent along in the the original message, that can be checked against the tag received in a reply.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster ID of the destination node;
- *dst_id* (int) - the ID of the destination node;
- *msg* (string) - actual message payload;
- *tag* (var, optional) - randomly generated communication tag.


The function can return the following values:


- *1* - successfully sent message to destination node or a valid next hop
- *-1* - local node is disabled so sending is impossible
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


This function is used to send a generic, reply-like message, containing custom data, to a specific node in a cluster, directly from the script. The message is marked as a "reply" so this function should only be used for replying to a previously request-like message received. In order for the other node, which initially sent a request, to be able to correlate it with this reply, a communication tag, received along with the request, should be passed to the function.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster ID of the destination node;
- *dst_id* (int) - the ID of the destination node;
- *msg* (string) - actual message payload;
- *tag* (var) - communication tag.


The function can return the following values:


- *1* - successfully sent message to destination node or a valid next hop
- *-1* - local node is disabled so sending is impossible
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
- *-1* - local node is disabled so sending is impossible;
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
    * *"sip"* (default) - a node's DB provisioned SIP address
    * *"bin"* - a node's BIN interface listener


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE, LOCAL_ROUTE and EVENT_ROUTE.


```opensips title="cluster_check_addr() usage"
...
if (cluster_check_addr(1, $si)) {
	...
}
...
				
```


#### cl_ctr_set_maintenance(cluster_id, state)


Puts this node in or out of maintenance in a controller-managed cluster, as [clusterer:maintenance](#clusterermaintenance) does.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *state* (string) - *evicted* (or *on*) or *full* to enter maintenance, *none* (or *off*) to leave it.


Returns *1* on success, *-1* if the state or the cluster is unknown, or the controller is not running yet.


This function can be used from any route.


```opensips title="cl_ctr_set_maintenance() usage"
...
cl_ctr_set_maintenance(1, "evicted");
...
```


#### cl_ctr_node_is_master(cluster_id, node_id)


Checks whether a node is the master of a controller-managed cluster.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node.


Returns *1* if it is, *-1* otherwise.


This function can be used from any route.


```opensips title="cl_ctr_node_is_master() usage"
...
if (cl_ctr_node_is_master(1, 3))
	xlog("node 3 is the master of cluster 1\n");
...
```


#### cl_ctr_node_present(cluster_id, node_id)


Checks whether a node is a member of a controller-managed cluster, as [clusterer:list_members](#clustererlist_members) lists them.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node.


Returns *1* if it is, *-1* otherwise.


This function can be used from any route.


```opensips title="cl_ctr_node_present() usage"
...
if (!cl_ctr_node_present(1, $var(peer)))
	xlog("node $var(peer) is not in cluster 1\n");
...
```


#### cl_ctr_get_node_role(cluster_id, node_id, role_var)


Writes a member's role into a variable: *master*, *backup*, *maintenance* or *member*.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node;
- *role_var* (var) - receives the role.


Returns *1* on success, *-1* if the node is not a member.


This function can be used from any route.


```opensips title="cl_ctr_get_node_role() usage"
...
if (cl_ctr_get_node_role(1, 2, $var(role)))
	xlog("node 2 is $var(role)\n");	# node 2 is backup
...
```


#### cl_ctr_get_node_maint(cluster_id, node_id, maint_var)


Writes a member's maintenance state into a variable: *none*, *evicted* or *full*.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node;
- *maint_var* (var) - receives the state.


Returns *1* on success, *-1* if the node is not a member.


This function can be used from any route.


```opensips title="cl_ctr_get_node_maint() usage"
...
if (cl_ctr_get_node_maint(1, 3, $var(m)) && $var(m) != "none")
	xlog("node 3 is in maintenance ($var(m))\n");	# node 3 is in maintenance (full)
...
```


#### cl_ctr_get_node_ip(cluster_id, node_id, ip_var)


Writes a member's controller IP into a variable.


Meaning of the parameters is as follows:


- *cluster_id* (int) - the cluster;
- *node_id* (int) - the node;
- *ip_var* (var) - receives the IP.


Returns *1* on success, *-1* if the node is not a member.


This function can be used from any route.


```opensips title="cl_ctr_get_node_ip() usage"
...
if (cl_ctr_get_node_ip(1, 3, $var(ip)))
	xlog("node 3 is $var(ip)\n");	# node 3 is 10.0.0.3
...
```


### Exported MI Functions


#### clusterer:reload


Replaces obsolete MI command: *clusterer_reload*.


Reloads data from the clusterer database. The currently established topology will be lost and the node will rediscover the new topology.

Controller-managed clusters are not in the database: a reload keeps them as they are, and fails when the database defines a cluster with the id of one of them.


Name: *clusterer:reload*


Parameters:*none*


MI FIFO Command Format:


```bash
$ opensips-cli -x mi clusterer:reload
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


Refused (403) for a controller-managed cluster - use [clusterer:maintenance](#clusterermaintenance).


Name: *clusterer:set_status*


Parameters:


- *cluster_id* - indicates the id of the cluster.
- *node_id* (optional) - indicates the id of the node to be disabled.
If missing, the local instance will be disabled.
- *status* - indicates the new status(0 - Disabled, 1 - Enabled).


MI FIFO Command Format:


```bash
#disable the local instance
$ opensips-cli -x mi clusterer:set_status 1 0
#disable node ID 3
$ opensips-cli -x mi clusterer:set_status 1 3 0

```


#### clusterer:remove_node


Replaces obsolete MI command: *clusterer_remove_node*.


Removes a node from the cluster's topology. It is enough to run the function
on a single node in order to remove the target node from all the other
nodes in the cluster. If the node to be removed is running when triggering
this function, it will be automatically disabled (equivalent to running
[clusterer:set_status](#clustererset_status) on that specific node).


This function can only be used when [db_mode](#db_mode) is set to
*0* (disabled). It is refused (403) for a controller-managed cluster, whose
departed nodes the controller removes.


Name: *clusterer:remove_node*


Parameters:


- *cluster_id* - cluster ID
- *node_id* - ID of the node to be removed.


MI FIFO Command Format:


```bash
$ opensips-cli -x mi clusterer:remove_node 1 3

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
$ opensips-cli -x mi clusterer:send_mi 1 3 lb_reload

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
$ opensips-cli -x mi clusterer:broadcast_mi 1 dr_reload partition_5

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


Sets the status(Enabled/Disabled) of a capability. If a capability is disabled, the node will not send any replication/sync messages belonging to that capability. Likewise, received messages will be dropped. Also, the capability will transition to a "not synced" state and the node will no longer be able to be a donor for syncing.


Name: *clusterer:set_cap_status*


Parameters:


- *cluster_id* - the id of the cluster
- *capability* - name of the capability, as listed by
[clusterer:list_cap](#clustererlist_cap)
- *status* - indicates the new status(0 - Disabled, 1 - Enabled).


MI FIFO Command Format:


```bash
#disable dialog replication in cluster 1
$ opensips-cli -x mi clusterer:set_cap_status 1 dialog-dlg-repl 0
#enable dialog profile replication in cluster 2
$ opensips-cli -x mi clusterer:set_cap_status 2 dialog-prof-repl 1

```


#### clusterer:shtag_set_active


Replaces obsolete MI command: *clusterer_shtag_set_active*.


Set the given sharing tag to the *active* state.
The information about this change is also broadcasted in the cluster 
in order to force any other node that may be active on this tag to 
step down to backup.


Refused (403) for a cluster whose tags the controller manages
([manage_shtags](#manage_shtags-integer)).


Name: *clusterer:shtag_set_active*


Parameters: *tag* - the name of
the tag to be set active and the cluster it belongs to, in the
format 'tag/cluster_id'.


MI FIFO Command Format:


```bash
$ opensips-cli -x mi clusterer:shtag_set_active vip1/3

```


#### clusterer:list_shtags


Replaces obsolete MI command: *clusterer_list_shtags*.


Lists all known sharing tags and their states.


Name: *clusterer:list_shtags*


Parameters: *Command takes no parameters*


MI FIFO Command Format:


```bash
$ opensips-cli -x mi clusterer:list_shtags

```


#### clusterer:list_members


Lists the members of each controller-managed cluster as this node knows them: IP, node ID, MTU, *status* (*master*, *backup* or *member*), *maintenance* (*none*, *evicted* or *full*), *admission* (*connecting* or *online*, see [Admission](#admission)) and BIN sockets. *capabilities* (see [Upgrading](#upgrading)) appear where this node knows them first-hand: for every member on the master, for itself and the master on the other nodes.


Name: *clusterer:list_members*


Parameters: *none*


```bash title="clusterer:list_members usage"
$ opensips-cli -x mi clusterer:list_members
[
    {
        "cluster_id": 1,
        "members": [
            {
                "mtu": 1500,
                "ip": "10.0.0.3",
                "node_id": 3,
                "status": "master",
                "maintenance": "none",
                "admission": "online",
                "capabilities": [
                    "probe",
                    "maint_set",
                    "maint_full",
                    "admission"
                ],
                "bin_sockets": [
                    "bin:10.0.0.3:5566"
                ]
            },
            {
                "mtu": 1500,
                "ip": "10.0.0.1",
                "node_id": 1,
                "status": "member",
                "maintenance": "none",
                "admission": "online",
                "capabilities": [
                    "probe",
                    "maint_set",
                    "maint_full",
                    "admission"
                ],
                "bin_sockets": [
                    "bin:10.0.0.1:5566"
                ]
            },
            {
                "mtu": 1500,
                "ip": "10.0.0.2",
                "node_id": 2,
                "status": "backup",
                "maintenance": "none",
                "admission": "online",
                "capabilities": [
                    "probe",
                    "maint_set",
                    "maint_full",
                    "admission"
                ],
                "bin_sockets": [
                    "bin:10.0.0.2:5566"
                ]
            }
        ]
    }
]
```


#### clusterer:node_info


Shows a member of a controller-managed cluster by its node ID - the first one found when several clusters have that ID - or error 404.


Name: *clusterer:node_info*


Parameters:


- *node_id* - the node ID.


```bash title="clusterer:node_info usage"
$ opensips-cli -x mi clusterer:node_info node_id=2
{
    "mtu": 1500,
    "node_id": 2,
    "ip": "10.0.0.2",
    "cluster_id": 1,
    "status": "backup",
    "admission": "online",
    "bin_sockets": [
        "bin:10.0.0.2:5566"
    ]
}
```


#### clusterer:list_config


Shows, for each controller-managed cluster, the settings in effect (after the per-cluster values and *on_config_mismatch=adopt*) and the controller's state; the password is never shown. Besides the settings:


- *identity_source*, *proposed_node_id* - what this node's proposed ID is derived from (*smbios*, *mac* or *random*) and the ID it proposes (see [Node IDs](#node-ids));
- *shtag_mode* - *auto*, or *override:N* while the tags are pinned to node N;
- *member_count* - the members this node knows; *term* - the current master's term, which grows with each new mastership;
- *cluster_uuid*, *cluster_uuid_state* (*none*, *provisional*, *established* or *pinned*) - the cluster's identity; *foreign_packets*, *foreign_clusters* - what was heard from other clusters on the same group;
- *master_ka_mean_ms*, *master_ka_dev_ms*, *master_ka_margin_ms*, *master_timeout_ms*, *master_false_suspicions* - the gaps between the master's keepalives, and the wait before suspecting the master that this node learned from them;
- *local_health* - this node's own trouble count (0 to 8), which lengthens its timeouts; *self_stalls*, *self_stall_max_ms* - how often this node's controller process stopped for more than 2 seconds, and the longest stop;
- *election_holds* - elections held because other members still heard the master; *terms_refused* - implausible terms refused; *peers_refused* - new nodes refused because the peer table (*peer_capacity*) was full;
- *tag_released* - *1* while this master has released the tags (*release_tag_when_isolated*);
- *rcvbuf_bytes*, *rx_kernel_drops* - the socket receive buffer, and the datagrams the kernel dropped because it was full;
- *cluster_capabilities* - the capabilities every live member has (see [Upgrading](#upgrading)).


Name: *clusterer:list_config*


Parameters: *none*


```bash title="clusterer:list_config usage"
$ opensips-cli -x mi clusterer:list_config
[
    {
        "cluster_id": 1,
        "multicast": "239.0.0.1:3333",
        "my_ip": "10.0.0.1",
        "bin_socket": "bin:10.0.0.1:5566",
        "mtu": 1500,
        "identity_source": "smbios",
        "proposed_node_id": 1,
        "interface": "eth0",
        "query_time": 5,
        "master_stickiness": 1,
        "manage_shtags": 1,
        "shtag_mode": "auto",
        "member_count": 3,
        "term": 2,
        "cluster_uuid": "019a3c5e-8f21-7b4d-a6c2-5e0f9d3b7a14",
        "cluster_uuid_state": "established",
        "foreign_packets": 0,
        "peer_capacity": 256,
        "peers_refused": 0,
        "self_stalls": 0,
        "self_stall_max_ms": 0,
        "terms_refused": 0,
        "election_holds": 0,
        "master_ka_mean_ms": 1000,
        "master_ka_dev_ms": 2,
        "master_ka_margin_ms": 0,
        "master_timeout_ms": 3000,
        "master_false_suspicions": 0,
        "local_health": 0,
        "release_tag_when_isolated": 0,
        "tag_released": 0,
        "rcvbuf_bytes": 212992,
        "rx_kernel_drops": 0,
        "cluster_capabilities": [
            "probe",
            "maint_set",
            "maint_full"
        ],
        "foreign_clusters": []
    }
]
```


#### clusterer:maintenance


Puts this node - or, with *node_id*, another member - in or out of maintenance (see [Sharing tags and maintenance](#sharing-tags-and-maintenance)). A request for another node is multicast to the cluster and applied by that node, so it needs the node reachable.


Name: *clusterer:maintenance*


Parameters:


- *cluster_id* - the cluster.
- *state* - *evicted* (or *on*) or *full* to enter maintenance, *none* (or *off*) to leave it.
- *node_id* (optional) - the member; this node when missing.


```bash title="clusterer:maintenance usage"
$ opensips-cli -x mi clusterer:maintenance cluster_id=1 state=full node_id=3
"OK"
```


#### clusterer:shtag_force


Pins the active sharing tags of a controller-managed cluster to one member; every other node, the master included, keeps them in backup. Issue it on the master. The pin survives a master failover, and ends with [clusterer:shtag_auto](#clusterershtag_auto) or when the node leaves or enters maintenance. Refused (409) when *manage_shtags* is off for the cluster, on a node that is not the master, or for a node in maintenance, and (404) for a node that is not a member.


Name: *clusterer:shtag_force*


Parameters:


- *cluster_id* - the cluster.
- *node_id* - the member that will hold the tags.


```bash title="clusterer:shtag_force usage"
$ opensips-cli -x mi clusterer:shtag_force cluster_id=1 node_id=2
"OK"
```


#### clusterer:shtag_auto


Ends a [clusterer:shtag_force](#clusterershtag_force) pin, so the tags follow the master again. Issue it on the master.


Name: *clusterer:shtag_auto*


Parameters:


- *cluster_id* - the cluster.


```bash title="clusterer:shtag_auto usage"
$ opensips-cli -x mi clusterer:shtag_auto cluster_id=1
"OK"
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


Assigning it fails for a cluster whose tags the controller manages
([manage_shtags](#manage_shtags-integer)).


#### $cl_ctr_role(cluster_id)


This node's role in a controller-managed cluster: *master*, *backup*, *member*, *maintenance* (see [clusterer:maintenance](#clusterermaintenance)) or *joining* (not admitted yet).


The *$cl_ctr_* variables are read-only and can be read in any process. The cluster ID may be left out when only one controller-managed cluster is defined; they are NULL for an unknown cluster, for a value not known yet, and without a cluster ID when several clusters are defined (a warning is logged once). The examples run on the backup, 10.0.0.2.


```opensips title="$cl_ctr_role usage"
xlog("role: $cl_ctr_role(1)\n");	# role: backup
```


#### $cl_ctr_is_master(cluster_id)


*1* on the master of the cluster, *0* elsewhere.


```opensips title="$cl_ctr_is_master usage"
if ($cl_ctr_is_master(1) == 1)
	route(master_only_job);
xlog("master: $cl_ctr_is_master(1)\n");	# master: 0
```


#### $cl_ctr_master_ip(cluster_id)


The controller IP of the cluster's master; NULL while there is none.


```opensips title="$cl_ctr_master_ip usage"
xlog("master: $cl_ctr_master_ip(1)\n");	# master: 10.0.0.3
```


#### $cl_ctr_backup_ip(cluster_id)


The controller IP of the cluster's backup; NULL while there is none.


```opensips title="$cl_ctr_backup_ip usage"
xlog("backup: $cl_ctr_backup_ip(1)\n");	# backup: 10.0.0.2
```


#### $cl_ctr_node_id(cluster_id)


This node's ID in the cluster; NULL until it is assigned.


```opensips title="$cl_ctr_node_id usage"
xlog("node id: $cl_ctr_node_id(1)\n");	# node id: 2
```


#### $cl_ctr_my_ip(cluster_id)


This node's controller IP ([my_ip](#my_ip-string)).


```opensips title="$cl_ctr_my_ip usage"
xlog("my ip: $cl_ctr_my_ip(1)\n");	# my ip: 10.0.0.2
```


#### $cl_ctr_members(cluster_id)


The number of members this node knows in the cluster, as [clusterer:list_members](#clustererlist_members) lists them.


```opensips title="$cl_ctr_members usage"
xlog("members: $cl_ctr_members(1)\n");	# members: 3
```


#### $cl_ctr_shtag_mode(cluster_id)


*auto* while the sharing tags follow the master, *forced* while [clusterer:shtag_force](#clusterershtag_force) pins them.


```opensips title="$cl_ctr_shtag_mode usage"
xlog("tags: $cl_ctr_shtag_mode(1)\n");	# tags: auto
```


#### $cl_ctr_forced_node(cluster_id)


The node the sharing tags are pinned to by [clusterer:shtag_force](#clusterershtag_force); NULL in *auto* mode.


```opensips title="$cl_ctr_forced_node usage"
xlog("tags pinned to node $cl_ctr_forced_node(1)\n");
# after clusterer:shtag_force cluster_id=1 node_id=2: tags pinned to node 2
```


#### $cl_ctr_maintenance(cluster_id)


This node's maintenance state: *none*, *evicted* or *full*.


```opensips title="$cl_ctr_maintenance usage"
xlog("maintenance: $cl_ctr_maintenance(1)\n");	# maintenance: none
```


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


#### E_CL_CTR_MAINTENANCE


This event is raised on every node when the maintenance state of a member, this node included, changes. This event and the ones below are raised by the controller's process after it has handled the change, so their routes can read the *$cl_ctr_* variables.


Parameters:


- *cluster_id* - the cluster.
- *node_id* - the member.
- *state* - its new state: *none*, *evicted* or *full*.


```opensips title="E_CL_CTR_MAINTENANCE usage"
event_route[E_CL_CTR_MAINTENANCE] {
	xlog("cluster $param(cluster_id): node $param(node_id) maintenance $param(state)\n");
	# cluster 1: node 3 maintenance full
}
```


#### E_CL_CTR_ROLE


This event is raised when this node's role changes.


Parameters:


- *cluster_id* - the cluster.
- *role* - the new role: *master*, *backup* or *member*.
- *old_role* - the previous role.


```opensips title="E_CL_CTR_ROLE usage"
event_route[E_CL_CTR_ROLE] {
	xlog("cluster $param(cluster_id): $param(old_role) -> $param(role)\n");
	# cluster 1: backup -> master
}
```


#### E_CL_CTR_MASTER


This event is raised when the master of the cluster changes, as this node sees it.


Parameters:


- *cluster_id* - the cluster.
- *master_ip* - the new master's controller IP.
- *node_id* - its node ID.


```opensips title="E_CL_CTR_MASTER usage"
event_route[E_CL_CTR_MASTER] {
	xlog("cluster $param(cluster_id): master is $param(master_ip) (node $param(node_id))\n");
	# cluster 1: master is 10.0.0.2 (node 2)
}
```


#### E_CL_CTR_MEMBER


This event is raised when a node joins or leaves the members this node knows.


Parameters:


- *cluster_id* - the cluster.
- *node_id* - the node's ID; *0* when it joins, as it gets its ID afterwards.
- *ip* - its controller IP.
- *state* - *joined* or *left*.
- *reason* - *new* when joined; *goodbye* (it stopped), *timeout* (it went silent) or *dropped* (it was refused) when left.


```opensips title="E_CL_CTR_MEMBER usage"
event_route[E_CL_CTR_MEMBER] {
	xlog("cluster $param(cluster_id): $param(ip) (node $param(node_id)) $param(state), $param(reason)\n");
	# cluster 1: 10.0.0.1 (node 1) left, timeout
}
```


#### E_CL_CTR_REFUSED


This event is raised on the master when it refuses a node, at most once a minute per address and reason.


Parameters:


- *cluster_id* - the cluster.
- *ip* - the refused node's controller IP.
- *reason* - *config* (different settings, with *on_config_mismatch=reject*), *mtu* (a different MTU) or *refused* (a wrong password, or a full peer table).


```opensips title="E_CL_CTR_REFUSED usage"
event_route[E_CL_CTR_REFUSED] {
	xlog("cluster $param(cluster_id) refused $param(ip): $param(reason)\n");
	# cluster 1 refused 10.0.0.9: mtu
}
```


#### E_CL_CTR_MERGE


This event is raised when, after a network split heals, this node leaves its side to follow a master that outranks its own.


Parameters:


- *cluster_id* - the cluster.
- *master_ip* - the master it now follows.
- *was_master* - *1* if this node was a master itself, else *0*.


```opensips title="E_CL_CTR_MERGE usage"
event_route[E_CL_CTR_MERGE] {
	xlog("cluster $param(cluster_id): following $param(master_ip), was master: $param(was_master)\n");
	# cluster 1: following 10.0.0.3, was master: 1
}
```


#### E_CL_CTR_ADMISSION


This event is raised on the master as it moves a joining node through [admission](#admission).


Parameters:


- *cluster_id* - the cluster.
- *node_id* - the node's ID.
- *ip* - its controller IP.
- *state* - *connecting* (admitted), *online* (its links to every member are up), *stuck* (still connecting after 10 seconds) or *parked* (still connecting after 60 seconds: the queue moves on past it); *stuck* and *parked* are raised once per admission.


```opensips title="E_CL_CTR_ADMISSION usage"
event_route[E_CL_CTR_ADMISSION] {
	xlog("cluster $param(cluster_id): $param(ip) (node $param(node_id)) $param(state)\n");
	# cluster 1: 10.0.0.4 (node 4) online
}
```


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
[Status/Report Interface](../../docs/manual/Interface-StatusReport.md).


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

loadmodule "clusterer_controller.so"
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

loadmodule "clusterer_controller.so"
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


Besides the three statistics of *clusterer*, the controller registers the others below once per controller-managed cluster, whatever *enable_stats* says, in the *clusterer_controller* group and named *statistic-cluster_id* (e.g. *members-1*). Its counters only grow and cannot be reset.


```bash title="statistics:get usage"
$ opensips-cli -x mi statistics:get clusterer_controller:
{
    "clusterer_controller:role-1": 1,
    "clusterer_controller:is_master-1": 0,
    "clusterer_controller:members-1": 3,
    "clusterer_controller:maintenance-1": 0,
    "clusterer_controller:term-1": 2,
    "clusterer_controller:local_health-1": 0,
    "clusterer_controller:master_timeout_ms-1": 3000,
    "clusterer_controller:tag_released-1": 0,
    "clusterer_controller:master_changes-1": 1,
    "clusterer_controller:role_changes-1": 1,
    "clusterer_controller:members_joined-1": 2,
    "clusterer_controller:members_left-1": 0,
    "clusterer_controller:joins_refused-1": 0,
    "clusterer_controller:config_mismatches-1": 0,
    "clusterer_controller:auth_failures-1": 0,
    "clusterer_controller:merges-1": 0,
    "clusterer_controller:connecting-1": 0,
    "clusterer_controller:admitted-1": 2,
    "clusterer_controller:admissions_stuck-1": 0,
    "clusterer_controller:election_holds-1": 0,
    "clusterer_controller:master_false_suspicions-1": 0,
    "clusterer_controller:self_stalls-1": 0,
    "clusterer_controller:terms_refused-1": 0,
    "clusterer_controller:peers_refused-1": 0,
    "clusterer_controller:foreign_packets-1": 0,
    "clusterer_controller:rx_kernel_drops-1": 0
}
```


#### clusterer_nodes


Returns the total number of cluster nodes.


#### clusterer_nodes_up


Returns the total number of cluster nodes in the UP state.


#### clusterer_nodes_down


Returns the total number of cluster nodes not in the UP state.


#### role-[cluster_id]


This node's role: *2* master, *1* backup, *0* member.


#### is_master-[cluster_id]


*1* on the master, *0* elsewhere.


#### members-[cluster_id]


The members heard within the last 3 x *query_time*.


#### maintenance-[cluster_id]


This node's maintenance state: *0* none, *1* evicted, *2* full.


#### term-[cluster_id]


The highest mastership term this node has heard.


#### local_health-[cluster_id]


This node's own trouble count, 0 to 8 (see [clusterer:list_config](#clustererlist_config)).


#### master_timeout_ms-[cluster_id]


How long this node waits for the master's keepalive before suspecting it, in milliseconds.


#### tag_released-[cluster_id]


*1* while this master has released the sharing tags ([release_tag_when_isolated](#release_tag_when_isolated-integer)).


#### master_changes-[cluster_id]


Times the master changed, as this node saw it.


#### role_changes-[cluster_id]


Times this node's role changed.


#### members_joined-[cluster_id]


Nodes that joined the members this node knows.


#### members_left-[cluster_id]


Nodes that left them: by goodbye, timeout, or dropped after a refusal.


#### joins_refused-[cluster_id]


Join requests this node refused as master.


#### config_mismatches-[cluster_id]


Peers seen with settings that differ from this node's, once per change of their settings.


#### auth_failures-[cluster_id]


Packets that failed authentication: a wrong password, or a key this node does not hold yet.


#### merges-[cluster_id]


Times this node left its side of a healed split to follow a master that outranked its own.


#### connecting-[cluster_id]


Nodes in the *connecting* state of [admission](#admission), as the master relays them.


#### admitted-[cluster_id]


Nodes this node, as master, moved to *online*.


#### admissions_stuck-[cluster_id]


Nodes this node, as master, found still connecting 10 seconds after admitting them.


#### election_holds-[cluster_id]


Elections held because other members still heard the master.


#### master_false_suspicions-[cluster_id]


Times this node suspected the master while it was still alive.


#### self_stalls-[cluster_id]


Times this node's controller process stopped for more than 2 seconds.


#### terms_refused-[cluster_id]


Announced terms refused as implausible.


#### peers_refused-[cluster_id]


New nodes refused because the peer table was full.


#### foreign_packets-[cluster_id]


Authenticated packets of another cluster identity refused.


#### rx_kernel_drops-[cluster_id]


Cluster datagrams the kernel dropped because the socket receive buffer was full.


#### mcast_sent-[cluster_id]


[Broadcast](#broadcasts) datagrams this node sent by multicast.


#### mcast_received-[cluster_id]


Broadcasts this node received by multicast and dispatched.


#### mcast_repairs-[cluster_id]


Broadcast datagrams this node sent again to a node that missed them.


#### mcast_nacks-[cluster_id]


Requests this node sent for broadcast datagrams it missed.


#### mcast_gaps-[cluster_id]


Broadcast datagrams this node missed and could not recover.


#### mcast_tcp-[cluster_id]


Broadcasts this node sent by TCP instead: not every live member takes them by multicast, or this node has no cluster key yet.


#### mcast_barrier_waits-[cluster_id]


TCP messages that waited for broadcasts their sender had sent before them.


#### mcast_barrier_late-[cluster_id]


TCP messages dispatched after waiting 500 ms without those broadcasts.


## Developer Guide


### Available Functions


#### get_nodes(cluster_id)


This function will return a list of all the reachable nodes(if the direct link is down/probing, a path through intermediary nodes is considered) in the specified cluster. In a controller-managed cluster only directly linked nodes are reachable.


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


This function will free the list of nodes returned by *get_nodes*.


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


This function will return the id of the current node. When the node is in
controller-managed clusters, it returns the id only while all its clusters
give it the same one, and -1 otherwise.


#### send_to(packet, cluster_id, node_id)


This function will send the given BIN packet to the specified node in the cluster. If the direct link is down/probing, it will send the packet to an intermediary node if the destination node is reachable through another path in the cluster topology (not in a controller-managed cluster, where a message goes to the node directly or not at all).


Meaning of the parameters is as follows:


- *bin_packet_t packet* - the packet to be sent
- *int cluster_id* - the cluster id
- *int node_id* - the id of the destination node


The function returns one of the following:


- *CLUSTERER_SEND_SUCCESS* - successfully sent packet to destination node or a valid next hop
- *CLUSTERER_CURR_DISABLED* - current node is disabled so sending is impossible
- *CLUSTERER_DEST_DOWN* - destination node is not reachable through any path according to the discovered topology
- *CLUSTERER_SEND_ERR* - destination node or valid next hop appear to be reachable but send failed


#### send_all(packet, cluster_id)


Send the given BIN packet to all the nodes in the specified cluster. The function operates similarly to *send_to*.


Meaning of the parameters is as follows:


- *bin_packet_t packet* - the packet to be sent
- *int cluster_id* - the cluster id


The function returns one of the following:


- *CLUSTERER_SEND_SUCCESS* - successfully sent packet to at least one node
- *CLUSTERER_CURR_DISABLED* - current node is disabled so sending is impossible
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


Possible values for the event signaled through *ev* parameter of the callback function:


- *CLUSTER_RECV_MSG* - received BIN message
- *CLUSTER_ROUTE_FAILED* - failed to route a received BIN packet destined for another node in the cluster
- *CLUSTER_NODE_UP* - a node became reachable
- *CLUSTER_NODE_DOWN* - a node became unreachable
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
