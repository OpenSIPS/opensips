---
title: "db_sqlite Module"
description: "This is a module which provides SQLite support for OpenSIPS. It implements the DB API defined in OpenSIPS."
---

## Admin Guide


### Overview


This is a module which provides SQLite support for OpenSIPS.
		It implements the DB API defined in OpenSIPS.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


Also this module provides two ways of creating the query. One is to use
		sqlite3_bind_* functions after opensips creates the prepared statement query.
		The second one directly uses only sqlite3_snprintf function to print the
		values into the opensips created query. In theory, the second one should
		be faster and should allow you to make more queries to the database in
		the same time, so by default this one will be active. You can use the
		sqlite3_bind_* interface by simply uncommenting the SQLITE_BIND line
		the Makefile.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libsqlite3-dev* - the development libraries of sqlite.


### Exported Parameters


#### alloc_limit (integer)


Since the library does not support a function to return the number of rows
		in a query, this number is obtained using "count(*)" query. If we use multiple
		processes there is the risk ,since "count(*)" query and the actual "select"
		query, the number of rows in the result query to have changed, so realloc
		will be needed if the number is bigger. Using *alloc_limit*
		parameter you can specify the number with which the number of allocated rows in the
		result is raised.


*Default value is 10.*


```opensips title="Set alloc_limit parameter"
...
modparam("db_sqlite", "alloc_limit", 25)
...
```


#### load_extension (string)


This parameter enables extension loading, similiar to ".load" functionality in sqlite3,
		extenions like sqlite3-pcre which enables REGEX function. In order to use this functionality
		you must specify the library path (.so file) and the entry point which represents the function
		to be called by the sqlite library (read more at sqlite
		[load_extension](https://www.sqlite.org/capi3ref.html#sqlite3_load_extension)
		official documentation), separated by   ";"   delimiter. The entry point paramter
		can miss, so you won't need to use the delimitier in this case.


*By default, no extension is loaded.*


```opensips title="Set load_extension parameter"
...
modparam("db_sqlite", "load_extension", "/usr/lib/sqlite3/pcre.so")
modparam("db_sqlite", "load_extension", "/usr/lib/sqlite3/pcre.so;sqlite3_extension_init")
...
```


#### busy_timeout (integer)


This parameter sets the default busy_handler for the SQLite library, that sleeps for 
		a specified amount of time when a table is locked. The handler will sleep multiple 
		times until at least the specified "busy_timeout" duration (in milliseconds) has been 
		reached. Setting this parameter to a value less than or equal to zero turns off all 
		busy handlers. (read more in the  
		[SQLite 
		official documentation](https://www.sqlite.org/capi3ref.html#sqlite3_busy_timeout))


*Default value is 500.*


```opensips title="Set busy_timeout parameter"
...
modparam("db_sqlite", "busy_timeout", 5000)
...
```


#### exec_pragma (string)


This parameter allows configuring an SQLite database with "PRAGMA" statements, (read 
		more in the [SQLite official documentation](https://sqlite.org/pragma.html))
		To use this functionality you must specify the exec_pragma parameter value as
		"pragma-name=pragma-value". Multiple parameters with the same name can be specified, 
		and they will be executed one by one on every database connection. If a parameter has an 
		incorrect name or syntax, it will be ignored by SQLite without any error messages.


*By default, no PRAGMA statements are executed.*


```opensips title="Set exec_pragma parameter"
...
modparam("db_sqlite", "exec_pragma", "journal_mode=wal")
modparam("db_sqlite", "exec_pragma", "synchronous=normal")
modparam("db_sqlite", "exec_pragma", "cache_size=-2000")
...
```


### Exported Functions


No function exported to be used from configuration file.


### Installation


Because it dependes on an external library, the sqlite module is not
		compiled and installed by default. You can use one of the next options.


- - edit the "Makefile" and remove "db_sqlite" from "excluded_modules"
			list. Then follow the standard procedure to install OpenSIPS:
			"make all; make install".
- - from command line use: 'make all include_modules="db_sqlite";
			make install include_modules="db_sqlite"'.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
