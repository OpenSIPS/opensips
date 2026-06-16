---
title: "unixodbc Module"
description: "This module allows to use the unixodbc package with OpenSIPS. It have been tested with mysql and the odbc connector, but it should work also with other database. The auth_db module works."
---

## Admin Guide


### Overview


This module allows to use the unixodbc package with OpenSIPS. It have been 
	tested with mysql and the odbc connector, but it should work also with 
	other database. The auth_db module works.


For more information, see the [http://www.unixodbc.org/](http://www.unixodbc.org/) project web page.


To see what DB engines can be used via unixodbc, look at 
	[http://www.unixodbc.org/drivers.html](http://www.unixodbc.org/drivers.html).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### auto_reconnect (int)


Turns on or off the auto_reconnect mode.


*Default value is "1", this means it is enabled.*


```c title="Set the 'auto_reconnect' parameter"
...
modparam("db_unixodbc", "auto_reconnect", 0)
...
```


#### use_escape_common (int)


Escape values in query using internal escape_common() function.
		It escapes single quote ''', double quote '"', backslash '\',
		and NULL characters.


You should enable this parameter if you know that the ODBC driver
		considers the above characters as special (for marking begin and end
		of a value, escape other characters ...). It prevents against SQL
		injection.


*Default value is "0" (0 = disabled; 1 = enabled).*


```c title="Set the 'use_escape_common' parameter"
...
modparam("db_unixodbc", "use_escape_common", 1)
...
```


### Exported Functions


NONE


### Installation and Running


#### Installing


Prerequirement: you should first install unixodbc (or another program that 
	implements the odbc standard, such iodbc), your database, and the right 
	connector. Set the DSN in the odbc.ini file and the connector drivers in 
	the odbcinst.ini file.


#### Configuring and Running


In the opensips.conf file, add the line:


```c
....
loadmodule "/usr/local/lib/opensips/modules/db_unixodbc.so"
....
```


You should also uncomment this:


```c
....
loadmodule "/usr/local/lib/opensips/modules/auth.so"
loadmodule "/usr/local/lib/opensips/modules/auth_db.so"
modparam("usrloc", "working_mode_preset", "single-instance-sql-write-back")
modparam("auth_db", "calculate_ha1", yes)
modparam("auth_db", "password_column", "password")
....
```


and setting the DSN specified in the odbc.ini, inserting this with the 
	url adding this line:


```c
....
modparam("usrloc|auth_db", "db_url", 
    "unixodbc://opensips:opensipsrw@localhost/my_dsn")
....
```


replacing my_dsn with the correct value.


HINT: if unixodbc don't want to connect to mysql server, try restarting 
	mysql server with:


```c
shell>safe_mysqld --user=mysql --socket=/var/lib/mysql/mysql.sock
```


The connector search the socket in /var/lib/mysql/mysql.sock and not 
	in /tmp/mysql.sock


## Developer Guide


The module implements the OpenSIPS DB API, in order to 
	be used by other modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
