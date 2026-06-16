---
title: "mysql Module"
description: "This is a module which provides MySQL connectivity for OpenSIPS. It implements the DB API defined in OpenSIPS."
---

## Admin Guide


### Overview


This is a module which provides MySQL connectivity for OpenSIPS.
		It implements the DB API defined in OpenSIPS.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libmysqlclient-dev* - the development libraries of mysql-client.


### Exported Parameters


#### exec_query_threshold (integer)


If queries take longer than 'exec_query_threshold' microseconds, warning
		messages will be written to logging facility.


*Default value is 0 - disabled.*


```c title="Set exec_query_threshold parameter"
...
modparam("db_mysql", "exec_query_threshold", 60000)
...
```


#### timeout_interval (integer)


Time interval after which a connection attempt (read or write request)
		is aborted. The value counts three times, as several retries are done
		from the driver before it gives up.


The read timeout parameter is ignored on driver versions prior to
		"5.1.12", "5.0.25" and "4.1.22".
		The write timeout parameter is ignored on version prior to "5.1.12"
		and "5.0.25", the "4.1" release don't support it at all.


*Default value is 2 (6 sec).*


```c title="Set timeout_interval parameter"
...
modparam("db_mysql", "timeout_interval", 2)
...
```


#### max_db_queries (integer)


The maximum number of retries to execute a failed query due to connections problems.
            If this parameter is set improperly, it is set to default value.


*Default value is 2.*


```c title="Set max_db_queries parameter"
...
modparam("db_mysql", "max_db_queries", 2)
...
```


#### max_db_retries (integer)


The maximum number of database connection retries. If this parameter
                is set improperly, it is set to default value.


*Default value is 3.*


```c title="Set max_db_retries parameter"
...
modparam("db_mysql", "max_db_retries", 2)
...
```


### Exported Functions


No function exported to be used from configuration file.


### Installation


Because it dependes on an external library, the mysql module is not
		compiled and installed by default. You can use one of the next options.


- - edit the "Makefile" and remove "db_mysql" from "excluded_modules"
			list. Then follow the standard procedure to install OpenSIPS:
			"make all; make install".
- - from command line use: 'make all include_modules="db_mysql";
			make install include_modules="db_mysql"'.


### Exported Events


#### E_MYSQL_CONNECTION


This event is raised when a MySQL connection is lost or recovered.


Parameters:


- *url* - the URL of the connection as specified by the *db_url* parameter.
- *status* - *connected* if the connection recovered, or 
				*disconnected* if the connection was lost.


*doc copyrights:*
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
