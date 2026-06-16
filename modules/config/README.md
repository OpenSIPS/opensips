---
title: "Config Module"
description: "The *config* module enables dynamic, runtime configuration of OpenSIPS parameters by loading them from persistent storage at startup and exposing them to the script level via the [config](#pv_config) pseudo-variable."
---

## Admin Guide


### Overview


The *config*
		module enables dynamic, runtime configuration of OpenSIPS
		parameters by loading them from persistent storage at startup and
		exposing them to the script level via the [config](#pv_config)
		pseudo-variable.


All configuration variables are stored in OpenSIPS' internal
		cache, allowing fast access during SIP processing to maintain high
		performance. The cache can be updated in three ways:


- *Script* – Assigning a value to the
			[config](#pv_config) pseudo-variable updates the
			in-memory cache, but this change is not persisted to the database.
- *MI Commands* – Using
			[mi push](#mi_push) or
			[mi push bulk](#mi_push_bulk) updates one or more variables
			in the runtime cache. These updates are also not saved to the database.
- *Database* – Manually modifying values in the
				database, then triggering the [mi reload](#mi_reload)
				command, will refresh the in-memory cache with updated values from
				the database.


#### Restart Persistent Memory


By default, the configuration cache is initialized
			at startup by reading from the database and
			persists only during the runtime. Any temporary
			changes made through the script or MI commands
			that are not explicitly flushed to the database
			using the
			[mi flush](#mi_flush)
			command will be lost after a restart.


In such cases, restart persistent memory becomes useful. When enabled
			via the [enable rpm](#param_enable_restart_persistency) parameter, OpenSIPS no longer
			loads configuration values from the database on startup. Instead, it
			restores the previously saved in-memory cache, preserving runtime changes
			across restarts.


If needed, you can still manually re-initialize the cache from the
			database by running the [mi reload](#mi_reload) MI command.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *A database module is needed to read the initial cache*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (string)


Database URL used to load the initial configuration values,
			and flush them at runtime using the
			[mi flush](#mi_flush) MI command.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set 'db_url' parameter"
...
modparam("config", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### table_name (string)


Name of the table where configuration entries are stored.


*Default value is "config".*


```c title="Set 'table_name' parameter"
...
modparam("config", "table_name", "configuration")
...
```


#### name_column (string)


Name of the column storing configuration variable names.


*Default value is "name".*


```c title="Set 'name_column' parameter"
...
modparam("config", "name_column", "key")
...
```


#### value_column (string)


Name of the column storing configuration variable values.


*Default value is "value".*


```c title="Set 'value_column' parameter"
...
modparam("config", "value_column", "val")
...
```


#### description_column (string)


Name of the column storing variable descriptions.


*Default value is "description".*


```c title="Set 'desctiption_column' parameter"
...
modparam("config", "description_column", "desc")
...
```


#### enable_restart_persistency (integer)


Enables restart persistency. Check the
			[restart persistent memory](#restart_persistent_memory) for more information.


*Default value is "0 / disabled".*


```c title="Set 'restart_persistent_memory' parameter"
...
modparam("config", "restart_persistent_memory", yes)
...
```


#### hash_size (integer)


Size of the internal hash table used to store config variables.
		Must be a power of 2 number, otherwise its value will be rounded to the
		closest value of 2 smaller than the provided value.


*Default value is "16".*


```c title="Set 'hash_size' parameter"
...
modparam("config", "hash_size", 32)
...
```


### Exported Pseudo-Variables


#### $config(name)


Returns the value of the given config variable by name.
			Can also be used for temporarily changing the value.


```c title="Usage of $config(...)"
			...
			xlog("Config value: $config(debug_mode)\n"); # reading the value
			$config(debug_mode) = 1; # temporarily changing the value
			...
			
```


#### $config.description(name)


Returns the description of a config variable if available.


This variable is read-only.


```c title="Usage of $config.description(name)"
			...
			xlog("Description: $config.description(debug_mode)\n");
			...
			
```


### Exported MI Functions


#### config:reload


Replaces obsolete MI command: *config_reload*.


Reloads all configuration variables from the database.


MI FIFO Command Format:


```c
		## reload configuration cache from the database
		opensips-mi config:reload
		opensips-cli -x mi config:reload
		
```


#### config:list


Replaces obsolete MI command: *config_list*.


Lists all config variables currently loaded in cache,
		printing temporary values as well.
		If the optional *description* parameter
		is provided and different than *0*, it
		returns an array containing the description of the values
		as well.


MI FIFO Command Format:


```c
		## list all configuration cache
		opensips-mi config:list
		opensips-cli -x mi config:list 1
		
```


#### config:push


Replaces obsolete MI command: *config_push*.


Temporarily pushes a single configuration variable.


Expected parameters are:


- *name* – (string) the name of the variable
- *value* – (string) the value of the variable
- *description* – (string, optional) the
				description of the variable; if missing the description is
				inheritted, or a null value is used if the variable is new.


MI FIFO Command Format:


```c
		## push temporarily debug_mode configuration value
		opensips-mi config:push debug_mode 1 "Enable Debug mode"
		opensips-cli -x mi config:list 1
		
```


#### config:push_bulk


Replaces obsolete MI command: *config_push_bulk*.


Pushes multiple temporarily configuration variables in memory.


Expected parameters are:


- *configs* – (json) a JSON
				array containing a set of variables to be pushed. Each
				variable should be described as a JSON object with the following
				keys:
				
				
					*name* – (string) the
					name of the variable to be changed.
				
				
					*value* – (string or null) the
					new value of the variable.
				
				
					*description* – (string, optional)
					the description of the variable.


MI FIFO Command Format:


```c
		## push bulk temporarily values to the config cache
		opensips-mi config:push_bulk -j '[[{"name":"debug_mode","value":"1"},{"name":"debug_level","value":"5"}]]'
		
```


The command returns the number of values successfully pushed.


#### config:flush


Replaces obsolete MI command: *config_flush*.


Flushes the variables from the memory to the database.


Expected parameters are:


- *name* – (string, optional) if present,
				flushes only a specific config variable in database, otherwise
				the entire cache.


MI FIFO Command Format:


```c
		## Flush config variables to the database
		opensips-mi config:flush
		opensips-cli -x mi config:flush debug_mode
		
```


The command returns the number of values successfully flushed.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
