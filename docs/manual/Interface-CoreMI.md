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

    $ opensips-mi arg
    [
        "./opensips",
        "-f",
        "/etc/openser/test.cfg"
    ]

```

### help
Prints MI command usage information. When *mi_cmd* is provided, the response includes the command description and the module which exports it.

**Arguments**:
* *mi_cmd* (optional) - MI command name

Examples of usage:
```bash

    $ opensips-mi help
    $ opensips-mi help core:version

```

### kill
The command will terminate **OpenSIPS** (and internal shutdown).  

**Arguments**: none  

**Output**: none

Examples of usage:
```bash

    $ opensips-mi kill

```

### log_level
Get or set the logging level of one or all OpenSIPS processes. If no argument is passed to the **log_level** command, it will print a table with the current logging levels of all processes. If a logging **level** is given, it will be set for each process. If **pid** is also given, the logging level will change only for that process.  

**Arguments**:
* *level* (optional) - logging level (-3...4) (see [meaning of the values](Script-CoreParameters.md#log_level))
* *pid* (optional) - Unix pid (validated by OpenSIPS)

Examples of usage:
```bash

    $ opensips-mi log_level
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
                "Type": "SIP receiver udp:194.168.4.133:5060"
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

### log_level_filter
Get or set the level of the extra filtering applied to log messages for a specific logging "consumer"(*stderror*, *syslog* or *event*). If **log_level_filter** is not given, the command will print the current level filter for the specified consumer.

**Arguments**:
* *consumer* (optional) - logging consumer: *stderror*, *syslog* or *event*;
* *log_level_filter* (optional) - the log level filter.

Examples of usage:
```bash

    $ opensips-mi log_level_filter stderror
    {
        "Log level filter": 3
    }
    $ opensips-mi log_level_filter stderror 1
    "OK"

```

### log_mute_state
Get or set the mute state (printing enabled/disabled) of a specific logging "consumer"(*stderror*, *syslog* or *event*). If **mute_state** is not given, the command will print the current mute state for the specified consumer.

**Arguments**:
* *consumer* (optional) - logging consumer: *stderror*, *syslog* or *event*;
* *mute_state* (optional) - the new mute state: *1* - muted or *0* - unmuted (enabled)

Examples of usage:
```bash

    $ opensips-mi log_mute_state syslog
    {
        "mmute state": 0
    }
    $ opensips-mi log_mute_state syslog 1
    "OK"

```

### profiling_proc
Get or set the profiling level globally or per process. If no **level** is given, the function will list the current profiling level of the specified processes. If **level** is given, it gives the incremental verbosity level - from the lowest to higher level, we have: **0** OFF, **1** SIP level (I/O reactor, SIP stack -TM, dialog, b2b-, scripting), **2** Extra Processes too (like MI, RTPproxy, HTTPD) and **3** TIMER/FULL (timer job execution).
What are the impacted processes may be controlled via the **ID** (internal ID) or **PID** ids. If none given, all processes will be impacted by the set/get operation.
Also see the [E_PROFILING_PROC event](Interface-CoreEvents.md#E_PROFILING_PROC) used for reporting the profiling data.

**Arguments**:
* *ID* or *PID* (optional) - processes to work with;
* *level* (optional) - the new verbosity level (if to be set)
Examples of usage:
```bash

    $ opensips-mi mi core:profiling_proc id=8
    {
        "Processes": [
            {
                "ID": 8,
                "PID": 3568378,
                "Profiling level": 0,
                "Type": "SIP receiver udp:127.10.0.1:5060"
            }
         ]
    }
    $ opensips-mi core:profiling_proc id=8 level=2
    "OK"

```

### ps
The command will list all all **OpenSIPS** processes, along with type and description.  

**Arguments**: none  

**Output**: multiple objects, each one containing a process ID (internal), PID (OS) and Type. 

Examples of usage:
```bash

    $ opensips-mi ps
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

    $ opensips-mi pwd
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

    $ opensips-mi uptime
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

    $ opensips-mi version
    {
        "Server": "OpenSIPS (4.1.0-dev (x86_64/linux))"
    }

```

### which
Prints all available MI commands from the queried **OpenSIPS**instance.

**Arguments**: none

**Output**: an array of the names of available MI commands. NOTE that the list of available MI commands may differ depending of what modules your **OpenSIPS** is using.

Examples of usage:
```bash

    $ opensips-mi which
    [
        "statistics:get",
        "statistics:list",
        "statistics:reset",
        "uptime",
        "version",
        "pwd",
        "arg",
        "which",
        "ps",
        "kill",
        "log_level",
        "xlog_level",
        "mem:shm_check",
        "cache:store",
        "cache:fetch",
        "cache:remove",
        "evi:subscribe",
        "evi:list",
    ...

```

### xlog_level [level]
Get or set the global xlogging level in OpenSIPS processes. If no argument is passed to the **xlog_level** command, it will print the current **xlog_level**. If a logging **level** is given, it will be globally set for all OpenSIPS processes.

**Arguments**:
* *level* (optional)

Example of usage:
```bash

    $ opensips-mi xlog_level -2

```

## Blacklists

### blacklists:list
The command lists all the defined (static or learned) blacklists from **OpenSIPS**.

**Arguments**:
* *name* (optional) - filter and print only rules in a specific blacklist
**Output**: an array with each object describing the list (name, owner, flags); the "Rules" item is an array with each object member describing the rules (blacklists) for each list (IP/mask, protocol, port, matching regexp, flags).

Examples of usage:
```bash

    $ opensips-mi blacklists:list

```

### blacklists:check_all
The command returns all the blacklists that match an proto:IP:port+pattern.

**Arguments**:
* *proto* (optional) - protocol of the check rule - if missing, "any" protocol is used. Note that an "any" protocol check can only match an "any" protocol rule.
* *ip* - the mandatory IP that is used to match the rules
* *port* (optional) - the port of the check rule - if missing, 0/any port is used. Note that a 0 port will only match a 0 port rule.
* *pattern* (optional) - optional pattern to check against the rules
**Output**: an array with the names of each blacklist that matched.

Examples of usage:
```bash

    $ opensips-mi blacklists:check_all 127.0.0.1
    $ opensips-mi blacklists:check_all udp 127.0.0.1 5060

```

### blacklists:check
The command check whether a proto:IP:port+pattern matches any rule of a blacklist.

**Arguments**:
* *name* = the name of the blacklist to check against
* *proto* (optional) - protocol of the check rule - if missing, "any" protocol is used. Note that an "any" protocol check can only match an "any" protocol rule.
* *ip* - the mandatory IP that is used to match the rules
* *port* (optional) - the port of the check rule - if missing, 0/any port is used. Note that a 0 port will only match a 0 port rule.
* *pattern* (optional) - optional pattern to check against the rules
**Output**: an object containing the first rule that matched, or an error if nothing matched.

Examples of usage:
```bash

    $ opensips-mi blacklists:check net_dynamic 127.0.0.1
    $ opensips-mi blacklists:check_all net_dynamic udp 127.0.0.1 5060

```

### blacklists:add_rule
Adds a rule to a non-readonly blacklist.

**Arguments**:
* *name*- the name of the blacklist to add to
* *rule* - a string containing a blacklist rule, according to [**dst_blacklist**](https://docs.opensips.org/manual/devel/script-coreparameters#dst_blacklist) parameter
* *expire* (optional) - indicates the number of seconds the rule should expire
**Output**: success or failed object.

Examples of usage:
```bash

    $ opensips-mi blacklists:add_rule net_dynamic '!tcp,127.0.0.1,5060'
    $ opensips-mi blacklists:add_rule net_dynamic '!tcp,127.0.0.1,5060' 3600

```

### blacklists:del_rule
Removes a rule from a non-readonly blacklist.

**Arguments**:
* *name* - the name of the blacklist to remove from
* *rule* - a string containing a blacklist rule, according to [**dst_blacklist**](https://docs.opensips.org/manual/devel/script-coreparameters#dst_blacklist) parameter
**Output**: success or failed object.

Examples of usage:
```bash

    $ opensips-mi blacklists:del_rule net_dynamic '!tcp,127.0.0.1,5060'

```

## TCP connections

### tcp:list
The command lists all ongoing TCP/TLS connection from **OpenSIPS**.

**Arguments**:

* *proto* (optional) - list TCP connections for that specific protocol
**Output**: an array with one object per connection with the following attributes : ID, type, state, source, destination, lifetime, alias port. For TLS connections, cipher information is also dumped.

Examples of usage:
```bash

    $ opensips-mi tcp:list

```

### tcp:close
Command that terminates an ongoing TCP/TLS connection from **OpenSIPS**.

**Arguments**:

* *ipport* - **ip:port** coordinates of the connection

Examples of usage:
```bash

    $ opensips-mi tcp:close 127.0.0.1:9

```
you can also terminate by id:
```bash

    $ opensips-mi tcp:close 31646848

```
## Status Report

### status_report:get
The MI equivalent of the [sr_check_status() script function](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status) - to get the status of an 'status/report' identifier/group.

**Arguments**: a mandatory *group* and optional *identifier*, see the parameters of the [sr_check_status() script function](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status).
**Output**: the readiness, the status and details of the identifier/group (see the aggregation note for the return code of the [sr_check_status() script function](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status)

Examples of usage:
```bash

$ opensips-mi status_report:get core
{
    "Readiness": true,
    "Status": 1,
    "Details": "running"
}

$ opensips-mi status_report:get drouting all
{
    "Readiness": true,
    "Status": 1,
    "Details": "aggregated"
}

```

### status_report:status
Command to list the status of the identifiers within one or all 'status/report' groups.

**Arguments**: an optional 'status/report'  *group*, see the [sr_check_status() script function](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status) for more details.
**Output**: the readiness, the status and details for all the identifiers within the requested group, or within all defined/registered groups.

Examples of usage:
```bash

$ opensips-mi status_report:status 
[
    {
        "Name": "drouting",
        "Identifiers": [
            {
                "Name": "Default",
                "Readiness": true,
                "Status": 1,
                "Details": "data available"
            }
        ]
    },
    {
        "Name": "test",
        "Identifiers": [
            {
                "Name": "main",
                "Readiness": true,
                "Status": 1
            }
        ]
    },
    {
        "Name": "core",
        "Identifiers": [
            {
                "Name": "main",
                "Readiness": true,
                "Status": 1,
                "Details": "running"
            }
        ]
    }
]

```

### status_report:reports
Command to list the full set of reports (logs) collected by 'status/report' identifiers.

**Arguments**:
* an optional 'status/report'  *group*, see the [sr_check_status() script function](https://docs.opensips.org/manual/devel/script-corefunctions#sr_check_status) for more details. If missing, all the groups will be listed.
* an optional 'identifier'. If missing, all the identifiers within the group will be listed.
**Output**: the reports/logs for the requested identifiers, or for all identifiers within the groups.

Examples of usage:
```bash

$ opensips-mi status_report:reports 
[
    {
        "Name": "drouting",
        "Identifiers": [
            {
                "Name": "Default",
                "Reports": [
                    {
                        "Timestamp": 1644396830,
                        "Date": "Wed Feb  9 10:53:50 2022",
                        "Log": "starting DB data loading"
                    },
                    {
                        "Timestamp": 1644396830,
                        "Date": "Wed Feb  9 10:53:50 2022",
                        "Log": "DB data loading successfully completed"
                    },
                    {
                        "Timestamp": 1644396830,
                        "Date": "Wed Feb  9 10:53:50 2022",
                        "Log": "2 gateways loaded (0 discarded), 2 carriers loaded (0 discarded), 1 rules loaded (0 discarded)"
                    }
                ]
            }
        ]
    },
    {
        "Name": "test",
        "Identifiers": [
            {
                "Name": "main",
                "Reports": []
            }
        ]
    },
    {
        "Name": "core",
        "Identifiers": [
            {
                "Name": "main",
                "Reports": [
                    {
                        "Timestamp": 1644396830,
                        "Date": "Wed Feb  9 10:53:50 2022",
                        "Log": "initializing"
                    },
                    {
                        "Timestamp": 1644396830,
                        "Date": "Wed Feb  9 10:53:50 2022",
                        "Log": "initialization completed, ready now"
                    }
                ]
            }
        ]
    }
]

```

### status_report:identifiers
Command to list all the existing identifiers in OpenSIPS or only from a certain group.

**Arguments**:
* an optional 'status/report'  *group*, see the [sr_check_status() script function](https://docs.opensips.org/manual/3-3/script-corefunctions#sr_check_status) for more details. If missing, the identifiers from all the groups will be listed.
**Output**: an array of groups, each group being an array of identifiers .

Examples of usage:
```bash

$ opensips-mi status_report:identifiers
[
    {
        "Group": "clusterer",
        "Identifiers": [
            "sharing_tags"
        ]
    },
    {
        "Group": "dispatcher",
        "Identifiers": [
            "default;events",
            "default"
        ]
    },
    {
        "Group": "drouting",
        "Identifiers": [
            "Default;events",
            "Default"
        ]
    },
    {
        "Group": "dialplan",
        "Identifiers": [
            "default"
        ]
    },
    {
        "Group": "core",
        "Identifiers": [
            "main"
        ]
    }
]
$ opensips-mi status_report:identifiers drouting
{
    "Group": "drouting",
    "Identifiers": [
        "Default;events",
        "Default"
    ]
}

```

## Statistics

### statistics:get
Prints the statistics (all, group or one) realtime values.  

**Arguments**:
* *statistics* - an array of the following possible values:
  * "all" - print all available statistics;
  * "group_name:" - print only statistics from a certain group named "group_name"; the **OpenSIPS** core defines the following groups: *core*, *shmem*; Modules export groups typically named like the module itself.
  * "name" - print only the statistic named "name".
**Output**: an object containing the names and values of statistic variables.

Examples of usage:
```bash

    $ opensips-mi statistics:get rcv_requests
    {
        "core:rcv_requests": 35243
    }

    $ opensipsc-cli -x mi statistics:get shmem:      
    {
        "shmem:total_size": 1073741824,
        "shmem:max_used_size": 3389232,
        "shmem:free_size": 1070352592,
        "shmem:used_size": 2808952,
        "shmem:real_used_size": 3389232,
        "shmem:fragments": 3769
    }

    $ opensips-mi statistics:get shmem: core:
    ....

```

### statistics:list
Prints a list of available statistics in the current configuration of OpenSIPS.
**Arguments**:
* *statistics* (optional) - an array of the same possible values as for **statistics:get** MI command, with the exception of "all". Omitting the parameter will list all available statistics.

Examples of usage:
```bash

    $ opensips-mi statistics:list
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

### statistics:reset
Reset (to zero) the value of a statistic variable. Note that not all variables allow reset (depending of the nature of the information they carry - example "shmem:used_size").  

**Arguments**: 
* *statistics* - an array of the names of the variables to be reset. 
**Output**: none.

Examples of usage:
```bash

    $ opensips-mi statistics:get received_replies
    {
        "tm:received_replies": 14543
    }

    $ opensips-mi statistics:reset received_replies

    $ opensips-mi statistics:get received_replies
    {
        "tm:received_replies": 0
    }

```

### statistics:reset_all
Reset (to zero) the value of all statistic variables that can be reset. Note that not all variables allow reset (depending of the nature of the information they carry - example "shmem:used_size").  

**Output**: none.

Examples of usage:
```bash

    $ opensips-mi statistics:reset_all

```

## CacheDB interface

### cache:store
This command stores in a cache system a string value.  

**Arguments**:
* *system* - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local';
* *attr* - the label to be associated with this value;
* *value* - the string to be stored;
* *expire* (optional) - expire time for the stored value;
**Output**: none.   

Examples of usage:
```bash

    $ opensips-mi cache:store local password_user1 password

```

### cache:fetch
This command queries for a stored value.  

**Arguments**:
* *system* - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local'
* *attr* - the label associated with the value
**Output**: object containing the value if a record is found or 'Value not found' string otherwise.  

Examples of usage:
```bash

    $ opensips-mi cache:fetch local password_user1

```

### cache:remove
This command removes a record from the cache system.  

**Arguments**:
* *system* - cache system to use;
* *attr* - the label associated with the stored value;
**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi cache:remove local password_user1

```

## Event Interface

### evi:subscribe
Subscribes an external application to a certain event.  

**Arguments**:
* *event* - event name
* *socket* - external application socket
* *expire* (optional) - expire time, in seconds - if absent, the subscription is valid only one hour (3600 s)
**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi evi:subscribe E_PIKE_BLOCKED udp:127.0.0.1:8888 1200

```

### evi:list
Lists all the events published through the Event Interface.  

**Arguments**: None.   

**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi evi:list
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

### evi:raise
Raises an event through the Event Interface using an MI command.  

**Arguments**:
* *event* - event name
* *params* (optional) - array of elements, or a string consisting of a JSON object containing key-value pairs
**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi evi:raise E_PIKE_BLOCKED 127.0.0.1 # array mode
    $ opensips-mi evi:raise -j '{"event":"E_PIKE_BLOCKED", "params": {"ip":"127.0.0.1"}}' # json Mode
    $ opensips-cli -x mi -j evi:raise event=E_PIKE_BLOCKED params='{"ip":"127.0.0.1"}' # cli json mode

```

### evi:subscribers
Lists information about the subscribers  

**Arguments**:
* *event* - event name
* *socket* (optional) - external application socket
**Output**: If no parameter is specified, then the command returns information about all events and their subscribers. If the event is specified, only the external applications subscribed for that event are returned. If the socket is also specified, only one subscriber information is returned.  

Examples of usage:
```bash

    $ opensips-mi evi:subscribers
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

    $ opensips-mi evi:subscribers E_RTPPROXY_STATUS
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
            "expire": 1100,
            "ttl": 1046
            }
        ]
    } 
    }

    $ opensips-mi evi:subscribers E_RTPPROXY_STATUS unix:/tmp/event.sock
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

### mem:pkg_dump
Triggers a pkg memory dump for a given process. The memory dump will written to OpenSIPS's log (syslog or stderr) using the 'memdump' logging level. The global 'memdump' log level may be overwritten by a custom value provided as argument to this command.  

**Arguments**:
* *pid* - the PID of the process to perform the pkg dump
* *log_level* (optional) - a log level to be used for this dump
**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi mem:pkg_dump 11854 -1

```

> [!IMPORTANT]
> The processes without IPC support (like timer and per-module processes) will not be able to generate a memory dump.

### mem:rpm_dump
Triggers a restart-persistent memory dump. The memory dump is written to OpenSIPS's log (syslog or stderr) using the `memdump` logging level. The global `memdump` level may be overridden by the optional argument.

**Arguments**:
* *log_level* (optional) - logging level used for this dump

Examples of usage:
```bash

    $ opensips-mi mem:rpm_dump
    $ opensips-mi mem:rpm_dump -1

```

### mem:shm_dump
Triggers a shm memory dump. The memory dump will written to OpenSIPS's log (syslog or stderr) using the 'memdump' logging level. The global 'memdump' log level may be overwritten by a custom value provided as argument to this command.  

**Arguments**:
* *log_level* (optional) - a log level to be used for this dump
**Output**: None.  

Examples of usage:
```bash

    $ opensips-mi mem:shm_dump -1

```

### mem:shm_check
Only available with *QM_MALLOC* + *DBG_MALLOC*.  Fully scans the shared memory pool in order to locate any inconsistencies.  If any sign of memory corruption is detected, OpenSIPS will immediately abort.   

**Arguments**: None  

**Output**: current number of fragments.  

Example of usage:
```bash

    $ opensips-mi mem:shm_check

```
