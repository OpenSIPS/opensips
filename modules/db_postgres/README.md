---
title: "db_postgres Module"
description: "Module description"
---

## Admin Guide


### Overview


Module description


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *PostgreSQL library* - e.g., libpq5.
- *PostgreSQL devel library* - to compile
				the module (e.g., libpq-dev).


### Exported Parameters


#### exec_query_threshold (integer)


If queries take longer than 'exec_query_threshold' microseconds, warning
		messages will be written to logging facility.


*Default value is 0 - disabled.*


```c title="Set exec_query_threshold parameter"
...
modparam("db_postgres", "exec_query_threshold", 60000)
...
```


#### max_db_queries (integer)


The maximum number of database queries to be executed. 
                If this parameter is set improperly, it is set to default value.


*Default value is 2.*


```c title="Set max_db_queries parameter"
...
modparam("db_postgres", "max_db_queries", 2)
...
```


#### timeout (integer)


The number of seconds the PostgreSQL library waits to connect and query
			the server. If the connection does not succeed within the given timeout,
			the connection fails.


*Note:*If the timeout is a negative value and
			connection does not succeed, OpenSIPS will block until the connection
			becomes back available and gets successfully established. This is the
			default behavior of the library and is the behavior prior to the
			adition of this parameter.


*Default value is 5.*


```c title="Set timeout parameter"
...
modparam("db_postgres", "timeout", 2)
...
```


### Exported Functions


NONE


### Installation and Running


Notes about installation and running.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
