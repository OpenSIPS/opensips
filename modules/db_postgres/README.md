---
title: "postgres Module"
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


```opensips title="Set exec_query_threshold parameter"
...
modparam("db_postgres", "exec_query_threshold", 60000)
...
```


### Exported Functions


NONE


### Installation and Running


Notes about installation and running.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
