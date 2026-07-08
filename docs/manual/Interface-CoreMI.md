---
title: "Core MI Functions"
description: "MI (management interface) functions which are exported by OpenSIPS core."
---

MI (management interface) functions which are exported by **OpenSIPS** core.

## Core

### arg
Returns the full list of arguments used when **OpenSIPS** was started. As in UNIX, the first argument is the name of executable binary.

**Arguments**: none

**Output**: multiple MI nodes where each node contains an argument. The MI nodes have no name, but only value.

Example of usage:
```bash

    $ opensipsctl fifo arg
    ./opensips
    -f
    /etc/openser/test.cfg

```

### debug [level] [pid]
Get or set the logging level of one or all OpenSIPS processes. If no argument is passed to the **debug** command, it will print a table with the current logging levels of all processes. If a logging **level** is given, it will be set for each process. If **pid** is given, the logging level will be changed only for that process.
**Arguments**:
* debug level (-3...4)
* Unix pid (validated by OpenSIPS)

Examples of usage:
```bash

    $ opensipsctl fifo debug
    Process::  PID=10670 Debug=2 Type=attendant
    Process::  PID=10672 Debug=3 Type=MI FIFO
    Process::  PID=10673 Debug=1 Type=SIP receiver udp:192.168.2.133:5060
    $ opensipsctl fifo debug 1
    New global debug:: 1
    $ opensipsctl fifo debug 4 10670
    New debug:: 4

```

### kill
The command will terminate **OpenSIPS** (and internal shutdown).

**Arguments**: none

**Output**: none

Examples of usage:
```bash

    $ opensipsctl fifo kill

```

### ps
The command will list all all **OpenSIPS** processes, along with type and description.

**Arguments**: none

**Output**: multiple MI nodes (named "Process") - each node contains process ID (internal), PID (OS), Type and description

Examples of usage:
```bash

    $ opensipsctl fifo ps
    Process::  ID=0 PID=16224 Type=attendant
    Process::  ID=1 PID=16225 Type=SIP receiver udp:192.168.1.2:5060
    Process::  ID=2 PID=16226 Type=timer
    Process::  ID=3 PID=16227 Type=MI FIFO
    Process::  ID=4 PID=16228 Type=TCP receiver
    Process::  ID=5 PID=16230 Type=TCP main

```

### pwd
Prints the working directory of **OpenSIPS** instance.

**Arguments**: none

**Output**: a single MI node with name "WD" containing the working directory full path.

Examples of usage:
```bash

    $ opensipsctl fifo pwd
    WD:: /

```

### uptime
Prints various time information about **OpenSIPS** - when it started to run, for how long it runs.

**Arguments**: none

**Output**: three MI nodes: "Now" - current time; "Up since" - start time ; "Up time" - number of seconds since started.

Examples of usage:
```bash

    $ opensipsctl fifo uptime
    Now:: Mon Jul 21 17:41:03 2008
    Up since:: Mon Jul 21 17:36:33 2008
    Up time:: 270 [sec]

```

### version
Prints the version string of a running**OpenSIPS**.

**Arguments**: none

**Output**: one MI node (named "Server") containing the version string.

Examples of usage:
```bash

    $ opensipsctl fifo version
    Server:: OpenSIPS (1.4.0dev14-notls (i386/linux))

```

### which
Prints all available MI commands from the queried **OpenSIPS**instance.

**Arguments**: none

**Output**: multiple MI nodes (no name), each node containing (as value) the name of an available MI command. NOTE that the list of available MI commands may differ depending of what modules your **OpenSIPS** is using.

Examples of usage:
```bash

    $ opensipsctl fifo which
    get_statistics
    list_statistics
    reset_statistics
    uptime
    version
    pwd
    arg
    which
    ps
    kill
    debug
    list_blacklists
    ul_rm
    ul_rm_contact
    ul_dump
    ul_flush
    ul_add
    ul_show_contact
    nh_enable_ping

```

## Blacklists

### list_blacklists
The command lists all the defined (static or learned) blacklists from **OpenSIPS**.

**Arguments**: none

**Output**: an MI tree - first level (nodes named "List") will describe the list (name, owner, flags); Second level (nodes named "Rules) will describe the rules (blacklists) for each list (IP/mask, protocol, port, matching regexp, flags)

Examples of usage:
```bash

    $ opensipsctl fifo list_blacklists

```

## TCP connections

### list_tcp_conns
The command lists all ongoing TCP/TLS connection from **OpenSIPS**.

**Arguments**: none

**Output**: an MI tree - one record per connection with the following attributes : ID, state, proto, source, destination, timeout, lifetime

Examples of usage:
```bash

    $ opensipsctl fifo list_tcp_conns

```

## Statistics

### get_statistics
Prints the statistics (all, group or one) realtime values.

**Arguments**: input may be "all" - print all available statistics; "group:" - print only statistics from a certain group; "name" - print only this statistic. The **OpenSIPS** core defines the following groups: *core*, *shmem*; Modules export groups typically named like the module itself.

**Output**: list of MI nodes (no name) - each MI mode contains the name and value of a single statistic variable.

Examples of usage:
```bash

    $ opensipsctl fifo get_statistics rcv_requests
    core:rcv_requests = 35243
    $ opensipsctl fifo get_statistics shmem:
    shmem:total_size = 33554432
    shmem:used_size = 1686952
    shmem:real_used_size = 1704592
    shmem:max_used_size = 1704592
    shmem:free_size = 31849840
    shmem:fragments = 1
    $ opensipsctl fifo get_statistics all
    ....

```

### list_statistics
Prints a list of all available statistics in the current configuration of OpenSIPS

Examples of usage:
```bash

    $ opensipsctl fifo list_statistics
shmem:total_size:: incremental
shmem:used_size:: incremental
shmem:real_used_size:: incremental
shmem:max_used_size:: incremental
shmem:free_size:: incremental
shmem:fragments:: incremental
core:rcv_requests:: incremental
core:rcv_replies:: incremental
core:fwd_requests:: incremental
core:fwd_replies:: incremental
core:drop_requests:: incremental
    ....

```

### reset_statistics
Reset (to zero) the value of a statistic variable. Note that not all variables allow reset (depending of the nature of the information they carry - example "shmem:used_size").

**Arguments**: name of the variable to be reset.

**Output**: none.

Examples of usage:
```bash

    $ opensipsctl fifo get_statistics received_replies
    core:received_replies = 14543
    $ opensipsctl fifo reset_statistics received_replies
    $ opensipsctl fifo get_statistics received_replies
    core:received_replies = 0

```

## CacheDB interface

### cache_store
This command stores in a cache system a string value.

**Arguments**:

   - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local'

```bash
- the label to be associated with this value \\
- the string to be stored \\
```
**Output**: none.

Examples of usage:
```bash

    $ opensipsctl fifo cache_store local password_user1 password

```

### cache_fetch
This command queries for a stored value.

**Arguments**:

   - cache system to use - for the cache system implemented by **OpenSIPS** module 'localcache' the value of this parameter should be 'local'

```bash
- the label associated with the value \\
```
**Output**: MI tree containing the value if a record is found or 'Value not found' string otherwise.

Examples of usage:
```bash

    $ opensipsctl fifo cache_fetch local password_user1

```

### cache_remove
This command removes a record from the cache system.

**Arguments**:

```bash
- cache system to use\\
- the label associated with the stored value \\
```
**Output**: None.

Examples of usage:
```bash

    $ opensipsctl fifo cache_remove local password_user1

```

## Event Interface

### event_subscribe
Subscribes an external application to a certain event.

**Arguments**:

```bash
- event name\\
- external application socket \\
- expire time, in seconds - if absent, the subscription is valid only one hour (3600 s)\\
```
**Output**: None.

Examples of usage:
```bash

    $ opensipsctl fifo event_subscribe E_PIKE_BLOCKED udp:127.0.0.1:8888 1200

```

### events_list
Lists all the events published through the Event Interface.

**Arguments**: None.

**Output**: None.

Examples of usage:
```bash

    $ opensipsctl fifo events_list
    Event:: E_CORE_THRESHOLD id=0
    Event:: E_RTPPROXY_STATUS id=1
    Event:: E_PIKE_BLOCKED id=2

```

### subscribers_list
Lists information about the subscribers

**Arguments**:

```bash
- event name\\
- external application socket \\
```
**Output**: If no parameter is specified, then the command returns information about all events and their subscribers. If the event is specified, only the external applications subscribed for that event are returned. If the socket is also specified, only one subscriber information is returned.

Examples of usage:
```bash

    $ opensipsctl fifo subscribers_list
    Event:: E_CORE_THRESHOLD id=0
    Event:: E_RTPPROXY_STATUS id=1
	Subscriber::  socket=unix:/tmp/event.sock expire=never
	Subscriber::  socket=udp:127.0.0.1:8888 expire=1100
    Event:: E_PIKE_BLOCKED id=2
	Subscriber::  socket=rabbitmq:guest@127.0.0.1/hello expire=never

    $ opensipsctl fifo subscribers_list E_RTPPROXY_STATUS
    Event:: E_RTPPROXY_STATUS id=1
	Subscriber::  socket=unix:/tmp/event.sock expire=never
	Subscriber::  socket=udp:127.0.0.1:8888 expire=1100

    $ opensipsctl fifo subscribers_list E_RTPPROXY_STATUS unix:/tmp/event.sock
    Event:: E_RTPPROXY_STATUS id=1
	Subscriber::  socket=unix:/tmp/event.sock expire=never

```

## Memory

### shm_check
Only available with *QM_MALLOC* + *DBG_MALLOC*.  Fully scans the shared memory pool in order to locate any inconsistencies.  If any sign of memory corruption is detected, OpenSIPS will immediately abort.

**Arguments**: None

**Output**: current number of fragments.

Example of usage:
```bash

    $ opensipsctl fifo shm_check

```
