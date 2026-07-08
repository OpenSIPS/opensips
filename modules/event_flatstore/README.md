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


```opensips title="Set max_open_sockets parameter"
...
modparam("event_flatstore", "max_open_sockets", 200)
...
```


#### delimiter (string)


Sets the separator between the parameters of the event in the logging file.


*Default value is ",".*


```opensips title="Set delimiter parameter"
...
modparam("event_flatstore", "delimiter", ";")
...
```


#### file_permissions (string)


Sets the permissions for the newly created logs. It
			expects a string representation of a octal value.


*Default value is "644".*


```opensips title="Set file_permissions parameter"
...
modparam("event_flatstore", "file_permissions", "664")
...
```


#### suppress_event_name (int)


Suppresses the name of the event in the log file.


*Default value is "0/OFF" (the event's name is printed).*


```opensips title="Set suppress_event_name parameter"
...
modparam("event_flatstore", "suppress_event_name", 1)
...
```


### Exported Functions


No exported functions to be used in the configuration file.


### Exported MI Functions


#### evi_flat_rotate


It makes the processes reopen the file specified as a parameter to the command in order to be compatible with a logrotate command. If the function is not called after the mv command is executed, the module will continue to write in the renamed file.


Name: *evi_flat_rotate*


Parameters: *path_to_file*


MI FIFO Command Format:


```bash
		opensips-cli -x mi evi_flat_rotate _path_to_log_file_
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
