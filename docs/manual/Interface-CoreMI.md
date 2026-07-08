---
title: "Core MI Functions"
description: "MI (management interface) functions which are exported by OpenSIPS core."
---

MI (management interface) functions which are exported by **OpenSIPS** core.

## Core

### arg
Returns the full list of arguments used when **OpenSIPS** was started. As in UNIX, the first argument is the name of executable binary.

**Arguments**: none

**Output**: an array with multiple strings representing the arguments.

Example of usage:
```bash

    $ opensips-cli -x mi arg
    [
        "./opensips",
        "-f",
        "/etc/openser/test.cfg"
    ]

```

### kill
The command will terminate **OpenSIPS** (and internal shutdown).

**Arguments**: none

**Output**: none

Examples of usage:
```bash

    $ opensips-cli -x mi kill

```

### log_level [level] [pid]
Get or set the logging level of one or all OpenSIPS processes. If no argument is passed to the **log_level** command, it will print a table with the current logging levels of all processes. If a logging **level** is given, it will be set for each process. If **pid** is also given, the logging level will change only for that process.

**Arguments**:
* *level* (optional) - logging level (-3...4) (see [meaning of the values](Script-CoreParameters.md#log_level))
* *pid* (optional) - Unix pid (validated by OpenSIPS)

Examples of usage:
```bash

    $ opensips-cli -x mi log_level
    {
        "Processes": [
            {
                "PID": 10670,
                "Log level": 2,
                "Type": "attendant"
            },
            {
                "PID": 10672,
                "Log level": 3,
                "Type": "MI FIFO"
            },
            {
                "PID": 10673,
                "Log level": 1,
                "Type": "SIP receiver udp:193.168.3.133:5060"
            },
        ]
    }
    $ opensipsctl fifo log_level 1
    {
        "New global log level": 1
    }
    $ opensipsctl fifo log_level 4 10670
    {
        "Log level": 1
    }

```

### ps
The command will list all all **OpenSIPS** processes, along with type and description.

**Arguments**: none

**Output**: multiple objects, each one containing a process ID (internal), PID (OS) and Type.

Examples of usage:
```bash

    $ opensips-cli -x mi ps
{
    "Processes": [
        {
            "ID": 0,
            "PID": 27271,
            "Type": "attendant"
        },
        {
            "ID": 1,
            "PID": 27272,
            "Type": "MI FIFO"
        },
        {
            "ID": 2,
            "PID": 27273,
            "Type": "time_keeper"
        },
        {
            "ID": 3,
            "PID": 27274,
            "Type": "timer"
        },
        {
            "ID": 4,
            "PID": 27275,
            "Type": "SIP receiver udp:127.0.0.1:5060"
        },
        {
            "ID": 5,
            "PID": 27276,
            "Type": "Timer handler"
        }
    ]
}

```

### pwd
Prints the working directory of **OpenSIPS** instance.

**Arguments**: none

**Output**: a single item containing the working directory full path.

Examples of usage:
```bash

    $ opensips-cli -x mi pwd
    {
        "WD": "/"
    }

```

### reload_routes
Triggers the reload of the routing block (the routes) from the script during the runtime.
**Arguments**: none

**Output**: none

Please note that there are some limitations of when a reload is possible or not. Depending on the initial configuration of your modules, the reload may be rejected as the usage of the functions in the new script is not compatible with the original module setting and initialization.

If the reload fails, take a look at the logs to understand why - it may have been a syntax error or maybe a module related constraint. Anyhow, if the reload fails, there is no impact on your running OpenSIPS.

### uptime
Prints various time information about **OpenSIPS** - when it started to run, for how long it runs.

**Arguments**: none

**Output**: three items: "Now" - current time; "Up since" - start time ; "Up time" - number of seconds since started.

Examples of usage:
```bash

    $ opensips-cli -x mi uptime
{
    "Now": "Mon Jul 21 17:41:03 2008",
    "Up since": "Mon Jul 21 17:36:33 2008",
    "Up time": "270 [sec]"
}

```

### version
Prints the version string of a running**OpenSIPS**.

**Arguments**: none

**Output**: one item (named "Server") containing the version string.

Examples of usage:
```bash

    $ opensips-cli -x mi version
{
    "Server": "OpenSIPS (3.0.0-dev (x86_64/linux))"
}

```

### which
Prints all available MI commands from the queried **OpenSIPS**instance.

**Arguments**: none

**Output**: an array of the names of available MI commands. NOTE that the list of available MI commands may differ depending of what modules your **OpenSIPS** is using.

Examples of usage:
```bash

    $ opensips-cli -x mi which
[
    "get_statistics",
    "list_statistics",
    "reset_statistics",
    "uptime",
    "version",
    "pwd",
    "arg",
    "which",
    "ps",
    "kill",
    "log_level",
    "xlog_level",
    "shm_check",
    "cache_store",
    "cache_fetch",
    "cache_remove",
    "event_subscribe",
    "events_list",
...

```

### xlog_level [level]
Get or set the global xlogging level in OpenSIPS processes. If no argument is passed to the **xlog_level** command, it will print the current **xlog_level**. If a logging **level** is given, it will be globally set for all OpenSIPS processes.

**Arguments**:
* *level* (otpional)

Example of usage:
```bash

    $ opensips-cli -x mi xlog_level -2

```

## Blacklists

### list_blacklists
The command lists all the defined (static or learned) blacklists from **OpenSIPS**.

**Arguments**: none

**Output**: an array with each object describing the list (name, owner, flags); the "Rules" item is an array with each object member describing the rules (blacklists) for each list (IP/mask, protocol, port, matching regexp, flags).

Examples of usage:
```bash

    $ opensips-cli -x mi list_blacklists

```

## TCP connections

### list_tcp_conns
The command lists all ongoing TCP/TLS connection from **OpenSIPS**.

**Arguments**: none

**Output**: an array with one object per connection with the following attributes : ID, type, state, source, destination, lifetime, alias port.

Examples of usage:
```bash

    $ opensips-cli -x mi list_tcp_conns

```

## Statistics

### get_statistics
Prints the statistics (all, group or one) realtime values.

**Arguments**:
* *statistics* - an array of the following possible values:
  * "all" - print all available statistics;
  * "group_name:" - print only statistics from a certain group named "group_name"; the **OpenSIPS** core defines the following groups: *core*, *shmem*; Modules export groups typically named like the module itself.
  * "name" - print only the statistic named "name".
**Output**: an object containing the names and values of statistic variables.

Examples of usage:
```bash

    $ opensips-cli -x mi get_statistics rcv_requests
   {
       "core:rcv_requests": 35243
   }
    $ opensipsc-cli -x mi get_statistics shmem:
    {
        "shmem:total_size": 1073741824,
        "shmem:max_used_size": 3389232,
        "shmem:free_size": 1070352592,
        "shmem:used_size": 2808952,
        "shmem:real_used_size": 3389232,
        "shmem:fragments": 3769
    }
    $ opensips-cli -x mi get_statistics shmem: core:
    ....

```

### list_statistics
Prints a list of available statistics in the current configuration of OpenSIPS.
**Arguments**:
* *statistics* (optional) - an array of the same possible values as for **get_statistics** MI command, with the exception of "all". Omitting the parameter will list all available statistics.

Examples of usage:
```bash

    $ opensips-cli -x mi list_statistics
{
    "shmem:total_size": "non-incremental",
    "shmem:max_used_size": "non-incremental",
    "shmem:free_size": "non-incremental",
    "shmem:used_size": "non-incremental",
    "shmem:real_used_size": "non-incremental",
    "shmem:fragments": "non-incremental",
    "rpmem:rpm_total_size": "non-incremental",
    "rpmem:rpm_used_size": "non-incremental",
...

```

### reset_statistics
Reset (to zero) the value of a statistic variable. Note that not all variables allow reset (depending of the nature of the information they carry - example "shmem:used_size").

**Arguments**:
* *statistics* - an array of the names of the variables to be reset.
**Output**: none.

Examples of usage:
```bash

    $ opensips-cli -x mi get_statistics received_replies
   {
       "tm:received_replies": 14543
   }
    $ opensips-cli -x mi reset_statistics received_replies
    $ opensips-cli -x mi get_statistics received_replies
   {
       "tm:received_replies": 0
   }

```

## CacheDB interface

### cache_store
This command stores in a cache system a string value.

**Arguments**:
* *system* - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local';
* *attr* - the label to be associated with this value;
* *value* - the string to be stored;
* *expire* (optional) - expire time for the stored value;
**Output**: none.

Examples of usage:
```bash

    $ opensips-cli -x mi cache_store local password_user1 password

```

### cache_fetch
This command queries for a stored value.

**Arguments**:
* *system* - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local'
* *attr* - the label associated with the value
**Output**: object containing the value if a record is found or 'Value not found' string otherwise.

Examples of usage:
```bash

    $ opensips-cli -x mi cache_fetch local password_user1

```

### cache_remove
This command removes a record from the cache system.

**Arguments**:
* *system* - cache system to use;
* *attr* - the label associated with the stored value;
**Output**: None.

Examples of usage:
```bash

    $ opensips-cli -x mi cache_remove local password_user1

```

## Event Interface

### event_subscribe
Subscribes an external application to a certain event.

**Arguments**:
* *event* - event name
* *socket* - external application socket
* *expire* (optional) - expire time, in seconds - if absent, the subscription is valid only one hour (3600 s)
**Output**: None.

Examples of usage:
```bash

    $ opensips-cli -x mi event_subscribe E_PIKE_BLOCKED udp:127.0.0.1:8888 1200

```

### events_list
Lists all the events published through the Event Interface.

**Arguments**: None.

**Output**: None.

Examples of usage:
```bash

    $ opensips-cli -x mi events_list
{
    "Events": [
        {
            "name": "E_CORE_THRESHOLD",
            "id": 0
        },
        {
            "name": "E_CORE_SHM_THRESHOLD",
            "id": 1
        },
        {
            "name": "E_CORE_PKG_THRESHOLD",
            "id": 2
        },
...

```

### subscribers_list
Lists information about the subscribers

**Arguments**:
* *event* - event name
* *socket* (optional) - external application socket
**Output**: If no parameter is specified, then the command returns information about all events and their subscribers. If the event is specified, only the external applications subscribed for that event are returned. If the socket is also specified, only one subscriber information is returned.

Examples of usage:
```bash

    $ opensips-cli -x mi subscribers_list
{
  "Events": [{
	  "name": "E_RTPPROXY_STATUS",
	  "id": 1,
	  "subscribers": [
		...
	  ]
	},
	{
	  "name": "E_PIKE_BLOCKED",
	  "id": 2,
	  "subscribers": [
		...
	  ]
	}
  ]
}

    $ opensips-cli -x mi subscribers_list E_RTPPROXY_STATUS
{
  "Event": {
	"name": "E_RTPPROXY_STATUS",
	"id": 1,
	"subscribers": [{
		  "socket": "unix:/tmp/event.sock",
		  "expire": "never",
		},
		{
		  "socket": "udp:127.0.0.1:8888",
		  "expire": 1100
		}
	]
  }
}

    $ opensips-cli -x mi subscribers_list E_RTPPROXY_STATUS unix:/tmp/event.sock
{
  "Event": {
	"name": "E_RTPPROXY_STATUS",
	"id": 1,
	"Subscriber": {
	  "socket": "unix:/tmp/event.sock",
	  "expire": "never"
	}
  }
}

```

## Memory

### mem_pkg_dump
Triggers a pkg memory dump for a given process. The memory dump will written to OpenSIPS's log (syslog or stderr) using the 'memdump' logging level. The global 'memdump' log level may be overwritten by a custom value provided as argument to this command.

**Arguments**:
* *pid* - the PID of the process to perform the pkg dump
* *log_level* (optional) - a log level to be used for this dump
**Output**: None.

Examples of usage:
```bash

    $ opensips-cli -x mi mem_pkg_dump 11854 -1

```

> [!IMPORTANT]
> The processes without IPC support (like timer and per-module processes) will not be able to generate a memory dump.

### mem_shm_dump
Triggers a shm memory dump. The memory dump will written to OpenSIPS's log (syslog or stderr) using the 'memdump' logging level. The global 'memdump' log level may be overwritten by a custom value provided as argument to this command.

**Arguments**:
* *log_level* (otpional) - a log level to be used for this dump
**Output**: None.

Examples of usage:
```bash

    $ opensips-cli -x mi mem_shm_dump -1

```

### shm_check
Only available with *QM_MALLOC* + *DBG_MALLOC*.  Fully scans the shared memory pool in order to locate any inconsistencies.  If any sign of memory corruption is detected, OpenSIPS will immediately abort.

**Arguments**: None

**Output**: current number of fragments.

Example of usage:
```bash

    $ opensips-cli -x mi shm_check

```
