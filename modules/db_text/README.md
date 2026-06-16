---
title: "db_text Module"
description: "The module implements a simplified database engine based on text files. It can be used by OpenSIPS DB interface instead of other database module (like MySQL)."
---

## Admin Guide


### Overview


The module implements a simplified database engine based on text
		files. It can be used by OpenSIPS DB interface instead of other
		database module (like MySQL).


The module is meant for use in demos or small devices that do not
		support other DB modules. It keeps everything in memory and if you deal
		with large amount of data you may run quickly out of memory. Also, it
		has not implemented all standard database facilities (like order by),
		it includes minimal functionality to work properly with OpenSIPS


NOTE: the timestamp is printed in an integer value from time_t
		structure. If you use it in a system that cannot do this conversion,
		it will fail (support for such situation is in to-do list).


NOTE: even when is in non-caching mode, the module does not write
		back to hard drive after changes. In this mode, the module checks if
		the corresponding file on disk has changed, and reloads it. The write
		on disk happens at OpenSIPS shut down.


#### Design of db_text engine


The db_text database system architecture:


- a database is represented by a directory in the local file
				system.
				NOTE: when you use *db_text* in OpenSIPS,
				the	database URL for modules must be the path to the directory
				where the table-files are located, prefixed by 
				"text://", e.g., 
				"text:///var/dbtext/opensips". If there is no
				"/" after "text://" then
				"CFG_DIR/" is inserted at the beginning of the
				database path. So, either you provide an absolute path to
				database directory or a relative one to "CFG_DIR"
				directory.
- a table is represented by a text file inside database directory.


#### Internal format of a db_text table


First line is the definition of the columns. Each column must be
		declared as follows:


- the name of column must not include white spaces.
- the format of a column definition is: 
				*name(type,attr)*.
- between two column definitions must be a white space, e.g., 
				"first_name(str) last_name(str)".
- the type of a column can be: 
					
					
					*int* - integer numbers.
					
					
					*double* - real numbers with two
					decimals.
					
					
					*str* - strings with maximum size of 4KB.
- a column can have one of the attributes: 
					
					
					*auto* - only for 'int' columns,
					the maximum value in that column is incremented and stored
					in this field if it is not provided in queries.
					
					
					*null* - accept null values in column
					fields.
					
					
					if no attribute is set, the fields of the column cannot have
					null value.
- each other line is a row with data. The line ends with
				"\n".
- the fields are separated by ":".
- no value between two ':' (or between ':' and start/end of a row)
				means "null" value.
- next characters must be escaped in strings: "\n",
				"\r", "\t", ":".
- *0* -- the zero value must be escaped too.


```c title="Sample of a db_text table"
...
id(int,auto) name(str) flag(double) desc(str,null)
1:nick:0.34:a\tgood\: friend
2:cole:-3.75:colleague
3:bob:2.50:
...
```


```c title="Minimal OpenSIPS location db_text table definition"
...
username(str) contact(str) expires(int) q(double) callid(str) cseq(int)
...
```


```c title="Minimal OpenSIPS subscriber db_text table example"
...
username(str) password(str) ha1(str) domain(str) ha1b(str)
suser:supasswd:xxx:alpha.org:xxx
...
```


#### Existing limitations


This database interface don't support the data insertion with
				default values. All such values specified in the database template
				are ignored. So its advisable to specify all data for a column at
				insertion operations.


### Dependencies


#### OpenSIPS modules


The next modules must be loaded before this module:


- *none*.


#### External libraries or applications


The next libraries or applications must be installed before running
			OpenSIPS with this module:


- *none*.


### Exported Parameters


#### db_mode (integer)


Set caching mode (0) or non-caching mode (1). In caching mode, data
		is loaded at startup. In non-caching mode, the module check every time
		a table is requested whether the corresponding file on disk has
		changed, and if yes, will re-load table from file.


*Default value is "0".*


```c title="Set db_mode parameter"
...
modparam("db_text", "db_mode", 1)
...
```


#### buffer_size (integer)


Size of the buffer used to read the text file.


*Default value is "4096".*


```c title="Set buffer_size parameter"
...
modparam("db_text", "buffer_size", 8192)
...
```


### Exported Functions


*None*.


### Exported MI Functions


#### db_text:dump


Replaces obsolete MI command: *dbt_dump*.


Write back to hard drive modified tables.


Name: *db_text:dump*.


Parameters: none


MI FIFO Command Format:


```c
opensips-cli -x mi db_text:dump
		
```


#### db_text:reload


Replaces obsolete MI command: *dbt_reload*.


Causes db_text module to reload cached tables from disk.
			Depending on parameters it could be a whole cache or a specified
			database or a single table.
			If any table cannot be reloaded from disk - the old version
			preserved and error reported.


Name: *db_text:reload*.


Parameters:


- *db_name* (optional) - database name to reload.
- *table_name* (optional, but cannot be present
				without the db_name parameter) - specific table to reload.


MI FIFO Command Format:


```c
opensips-cli -x mi db_text:reload
		
```


```c
opensips-cli -x mi db_text:reload /path/to/dbtext/database
		
```


```c
opensips-cli -x mi db_text:reload /path/to/dbtext/database table_name
		
```


### Installation and Running


Compile the module and load it instead of mysql or other DB modules.


REMINDER: when you use *db_text* in OpenSIPS,
		the	database URL for modules must be the path to the directory
		where the table-files are located, prefixed by
		"text://", e.g., 
		"text:///var/dbtext/opensips". If there is no "/"
		after "text://" then "CFG_DIR/" is inserted
		at the beginning of the database path. So, either you provide an
		absolute path to database directory or a relative one to 
		"CFG_DIR" directory.


```c title="Load the db_text module"
...
loadmodule "/path/to/opensips/modules/db_text.so"
...
modparam("module_name", "database_URL", "text:///path/to/dbtext/database")
...
```


#### Using db_text with basic OpenSIPS configuration


Here are the definitions for most important table as well as a basic 
		configuration file to use db_text with OpenSIPS. The table structures
		may change in time and you will have to adjust next examples.


You have to populate the table 'subscriber' by hand with user profiles 
		in order to have authentication. To use with the given configuration
		file, the table files must be placed in the '/tmp/opensipsdb' directory.


```c title="Definition of 'subscriber' table (one line)"
...
username(str) domain(str) password(str) first_name(str) last_name(str) phone(str) email_address(str) datetime_created(int) datetime_modified(int) confirmation(str) flag(str) sendnotification(str) greeting(str) ha1(str) ha1b(str) perms(str) allow_find(str) timezone(str,null) rpid(str,null)
...
```


```c title="Definition of 'location' and 'aliases' tables (one line)"
...
username(str) domain(str,null) contact(str,null) received(str) expires(int,null) q(double,null) callid(str,null) cseq(int,null) last_modified(str) flags(int) user_agent(str) socket(str) 
...
```


```c title="Definition of 'version' table and sample records"
...
table_name(str) table_version(int)
subscriber:3
location:6
aliases:6
...
```


[Configuration file](./samples.md "include")


## Developer Guide


Once you have the module loaded, you can use the API specified by OpenSIPS DB
	interface.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
