---
title: "TCP Management Module (tcp_mgm)"
description: "This module provides optional, SQL-based support for fine-grained management of all TCP connections taking place on OpenSIPS."
---

## Admin Guide


### Overview


This module provides optional, SQL-based support for fine-grained
		management of all TCP connections taking place on OpenSIPS.


### Dependencies


#### OpenSIPS Modules


At least one SQL database module must be loaded (e.g. "db_xxx").


#### External Libraries or Applications


None.


### Exported Parameters


#### db_url (string)


Mandatory URL to the SQL database.


```c title="Setting the db_url parameter"
modparam("tcp_mgm", "db_url", "mysql://opensips:opensipsrw@localhost/opensips")
```


#### db_table (string)


The name of the table holding the TCP paths (rules).


Default value is *"tcp_mgm"*.


```c title="Setting the db_table parameter"
modparam("tcp_mgm", "db_table", "tcp_mgm")
```


#### [column-name]_col (string)


Use a different name for column *"column-name"*.


```c title="Setting the [column-name]_col parameter"
modparam("tcp_mgm", "connect_timeout_col", "connect_to")
```


### Exported MI Functions


#### tcp_mgm:reload


Replaces obsolete MI command: *tcp_reload*.


Reload all TCP paths from the *tcp_mgm* table
		without disrupting ongoing traffic.  Note that the reloaded rules will
		NOT immediately apply to existing TCP connections, rather only to
		newly established ones.


Example:


```c
# reload all TCP paths
$ opensips-cli -x mi tcp_mgm:reload
$ "OK"
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
