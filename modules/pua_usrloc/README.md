---
title: "PUA Usrloc"
description: "The pua_usrloc is the connector between usrloc and pua modules."
---

## Admin Guide


### Overview


The pua_usrloc is the connector between usrloc and pua modules.
It creates the environment to send PUBLISH requests for user
location records, on specific events (e.g., when new record is
added in usrloc, a PUBLISH with status open (online) is issued;
when expires, it sends closed (offline)).


Using this module, phones which have no support for presence can
be seen as online/offline.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *usrloc*.
- *pua*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libxml*.


### Exported Parameters


#### default_domain (str)


The default domain to use when constructing the presentity
uri if it is missing from recorded aor.


*Default value is "NULL".*


```opensips title="Set default_domain parameter"
...
modparam("pua_usrloc", "default_domain", "opensips.org")
...
```


#### entity_prefix (str)


The prefix when construstructing entity attribute to be added to
presence node in xml pidf.
(ex: pres:user@domain ).


*Default value is "NULL".*


```opensips title="Set presentity_prefix parameter"
...
modparam("pua_usrloc", "entity_prefix", "pres")
...
```


#### presence_server (str)


The the address of the presence server. If set, it will be
used as outbound proxy when sending PUBLISH requests.


```opensips title="Set presence_server parameter"
...
modparam("pua_usrloc", "presence_server", "sip:pa@opensips.org:5075")
...
	
```


#### cluster_id (int)


The ID of the cluster (clusterer module) this node shares its location
table with (usrloc `full-sharing-cluster`). Used only together with
`cluster_sharing_tag`.


*Default value is "0" (no clustering).*


```opensips title="Set cluster_id parameter"
...
modparam("pua_usrloc", "cluster_id", 1)
...
```


#### cluster_sharing_tag (str)


In a cluster sharing the location table every node expires every
contact, so every node would PUBLISH the same expiry. When this
sharing tag is set (with `cluster_id`), an expired contact is
published only by the node where the tag is active. Insert, update
and delete are not affected (they are driven by `pua_set_publish()`
on the node that processed the REGISTER).


*Default value is "NULL" (every node publishes expiries).*


```opensips title="Set cluster_sharing_tag parameter"
...
modparam("pua_usrloc", "cluster_sharing_tag", "vip")
...
```


### Exported Functions


#### pua_set_publish()


The function is used to mark REGISTER requests that have to
issue a PUBLISH. The PUBLISH is issued when REGISTER is saved
in location table.


```opensips title="pua_set_publish usage"
...
if(is_method("REGISTER") && $fu=~"john@opensips.org") 
	pua_set_publish();
...
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
