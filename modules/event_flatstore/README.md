---
title: "event_flatstore Module"
description: "The *event_flatstore* module provides a logging facility for different events, triggered through the OpenSIPS Event Interface, directly from the OpenSIPS script. The module logs the events along with their parameters in plain text files."
---

## Admin Guide


### Overview


The *event_flatstore*
		module provides a logging facility for different events,
		triggered through the OpenSIPS Event Interface, directly from the OpenSIPS
		script. The module logs the events along with their parameters in plain
		text files.


### Flatstore socket syntax


*flatstore:path_to_file*


Meanings:


- *flatstore:* - informs the Event Interface that the
					events sent to this subscriber should be handled by the
					*event_flatstore* module.
- *path_to_file* - path to the file where the logged events will be appended to. The file will be created if it does not exist. It must be a valid path and not a directory.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### max_open_sockets (integer)


Defines the maximum number of simultaneously opened files by the
			module. If the maximum limit is reached, an error message will be
			thrown, and further subscriptions will only be possible after at
			least one of the current subscriptions will expire.


*Default value is "100".*


```c title="Set max_open_sockets parameter"
...
modparam("event_flatstore", "max_open_sockets", 200)
...
```


#### delimiter (string)


Sets the separator between the parameters of the event in the logging file.


*Default value is ",".*


```c title="Set delimiter parameter"
...
modparam("event_flatstore", "delimiter", ";")
...
```


#### escape_delimiter (string)


Optional replacement sequence that will be written *instead
			of* the [`delimiter`](#param_delimiter)
			whenever this character (or sequence) occurs inside a string
			parameter.
			This allows you to keep the log file parse-friendly even when user
			data itself may contain delimiter symbols.


If set, its length *must be exactly equal* to the
			length of `delimiter`.


*Default value is """" (escaping disabled).*


```c title="Enable escaping of ',' with '|'"
...
modparam("event_flatstore", "delimiter", ",")
modparam("event_flatstore", "escape_delimiter", "|")
...
	
```


#### file_permissions (string)


Sets the permissions for the newly created logs. It
			expects a string representation of a octal value.


*Default value is "644".*


```c title="Set file_permissions parameter"
...
modparam("event_flatstore", "file_permissions", "664")
...
```


#### suppress_event_name (int)


Suppresses the name of the event in the log file.


*Default value is "0/OFF" (the event's name is printed).*


```c title="Set suppress_event_name parameter"
...
modparam("event_flatstore", "suppress_event_name", 1)
...
```


#### rotate_period (int)


When used, it triggers a file auto-rotate. The period is matched
			against the absolute time of the machine, can be useful to trigger
			auto-rotate every minute, or every hour.


*Default value is "0/OFF" (the file is never auto-rotated)*


```c title="Set rotate_period parameter"
...
modparam("event_flatstore", "rotate_period", 60) # rotate every minute
modparam("event_flatstore", "rotate_period", 3660) # rotate every hour
...
```


#### rotate_count (int|string)


Defines after how many written lines the log file is rotated.
			The value may exceed the 32-bit integer limit; in that case pass
			it *as a string*, e.g. "5000000000".


*Default value is "0/OFF".*


```c title="Rotate after five billion lines"
...
modparam("event_flatstore", "rotate_count", "5000000000")
...
		
```


#### rotate_size (int|string)


Sets the maximum size of a file before it is rotated.  A size
		suffix of "k", "m" or "g"
		(multiples of 1024) may be provided.
		Very large values can be supplied as strings, e.g.
		"8589934592" for 8 GiB.


*Default value is "0/OFF".*


```c title="Rotate at 2 GiB"
...
modparam("event_flatstore", "rotate_size", "2g")
...
```


#### suffix (string)


Modifies the file that OpenSIPS writes events into by
			appending a suffix to the the file specified in the flatstore
			*socket*.


The suffix can contain string formats (i.e. variables mixed with
			strings). The path of the resulted file is evaluated when the first
			event is raised/written in the file after a reload happend, or when
			the *rotate_period*, if specified, triggers a rotate.


This parameter does not affect the matching of the event socket -
			the matching will be done exclusively using the flatstore
			*socket* registered.


*Default value is """" (no suffix is added)*


```c title="Set suffix parameter"
...
modparam("event_flatstore", "suffix", "$time(%Y)")
...
```


### Exported Functions


No exported functions to be used in the configuration file.


### Exported MI Functions


#### event_flatstore:rotate


Replaces obsolete MI command: *evi_flat_rotate*.


It makes the processes reopen the file specified as a parameter to the command in order to be compatible with a logrotate command. If the function is not called after the mv command is executed, the module will continue to write in the renamed file.


Name: *event_flatstore:rotate*


Parameters: *path_to_file*


MI FIFO Command Format:


```c
opensips-cli -x mi event_flatstore:rotate _path_to_log_file_
		
```


### Exported Events


#### E_FLATSTORE_ROTATION


The event is raised every time *event_flatstore*
		opens a new log file (manual `event_flatstore:rotate`,
		auto-rotate by `rotate_period`, or
		thresholds `rotate_count`/`rotate_size`).
		External apps can subscribe to monitor log-rotation activity.


Parameters:


- *timestamp* – Unix epoch (seconds) when the
		rotation was performed.
- *reason* – one of the strings
		*count*, *size*,
		*period* or *mi*.
- *filename* – full path of the new log file.
- *old_filename* – full path of the previous
		log file, or empty string if none existed.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
