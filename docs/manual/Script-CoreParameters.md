---
title: "Core Parameters"
description: "This section lists the all the parameters exported by OpenSIPS core for script usage (to be used in opensips.cfg)."
---

This section lists the all the parameters exported by **OpenSIPS** core for script usage (to be used in opensips.cfg).

## Core parameters

Global parameters that can be set in configuration file. Accepted values are, depending on the actual parameters strings, numbers and yes/ no. If you need to specify either "yes" or "no" as part of a string, wrap this in double quotes.

### abort_on_assert
Default value: false

  

Only relevant if [asserts](https://docs.opensips.org/manual/3-4/script-corefunctions#assert) are enabled. Set to *true* in order to make OpenSIPS shut down immediately in case a script assert fails.

Example of usage:
```text

    abort_on_assert = true

```

### advertised_address

It can be an IP address or string and represents the address advertised in Via header and
other destination lumps (e.g RR header). If empty or not set (default value) the socket
address from where the request will be sent is used.

> [!WARNING]
> Don't set it unless you know what you are doing (e.g. nat traversal).
> You can set anything here, no check is made (e.g. foo.bar will be accepted even if foo.bar doesn't exist).

Example of usage:
```text

    advertised_address="opensips.org"

```

> [!NOTE]
> Aside this global approach, you can also define an advertise IP and port in a per-interface manner (see the [socket](#socket) parameter). When advertise values are defined per interface, they will be used only for traffic leaving that interface only.

### advertised_port

The port advertised in Via header and other destination lumps (e.g. RR). If empty or not set (default value) the port from where the message will be sent is used. Same warnings as for 'advertised_address'.

Example of usage:
```text

    advertised_port=5080

```

> [!NOTE]
> Aside this global approach, you can also define an advertise IP and port in a per-interface manner (see the [socket](#socket) parameter). When advertise values are defined per interface, they will be used only for traffic leaving that interface only.

### alias

Parameter to set alias hostnames for the server. It can be set many times, each value being added in a list to match the hostname when 'myself' is checked.

If the ":port" part is omitted, **all** ports of the given "hostname" will be considered an alias (similar behavior to port 0).

> [!IMPORTANT]
> It is necessary to include the port (the port value used in the "socket=" definitions) in the alias definition otherwise the loose_route() function will not work as expected for local forwards!


Example of usage:

```text

    alias=udp:other.domain.com:5060
    alias=tcp:another.domain.com:5060

```

### auto_aliases

This parameter controls if aliases should be automatically discovered and added during fixing listening sockets. The auto discovered aliases are result of the DNS lookup (if the 'socket' definition has a name and not IP) or of a reverse DNS lookup on the socket IP.

Far backward compatibility reasons, the default value is "off"/0.

Example of usage:
```text

    auto_aliases=yes
    auto_aliases=1

```

### auto_scaling_cycle
The number of seconds defining a auto-scaling cycle - the auto-scaling engine, at each cycle, is evaluating the internal load of the groups and decided if more processes needs to be created or if existing processes need to be terminated. Also see [auto_scaling_profile](#auto_scaling_profile) for more details on how the auto-scaling works.  

The default value is 1 second.
Example of usage:
```text

    auto_scaling_cycle=3  # do auto-scaling checks once every 3 seconds

```

### auto_scaling_profile
Defines the behavior of the auto-scaling support, in terms of how many processes should be allowed and when to terminate or create new processes. These profiles may be used for the UDP processes (see [udp_workers](#udp_workers) or [socket](#socket) options) , TCP processes (see [tcp_workers](#tcp_workers) option) or TIMER processes (see [timer_workers](#timer_workers) option).  

For more, see [this external description of auto-scaling](https://blog.opensips.org/2019/02/25/auto-process-scaling-a-cure-for-load-and-resources-concerns/).

Example of usage:
```text

    auto_scaling_profile = PROFILE_SIP
     scale up to 6 on 70% for 4 cycles within 5   
     scale down to 2 on 18% for 10 cycles

```
This profile will allow the group to fork up to 6 processes. A new process will be forked when the overall load of the group will be higher than 70% for more than 4 cycles during a 5 cycles monitoring window. A cycle is a time unit used for monitoring (like 2 seconds).  

Also the profile will allow the group to scale down to a minimum of 2 processes. A process will be terminated when the overall load of the group will be lower than 20% during 10 cycles. The down scaling part of the profile is optional. If not defined, OpenSIPS will never down scale, but only up scale.

### check_via

Check if the address in top most via of replies is local. Default value is 0 (check disabled).

Example of usage:

```text
check_via=1 
```

### chroot

The value must be a valid path in the system. If set, **OpenSIPS** will chroot (change root directory) to its value.

Example of usage:

```text
chroot=/other/fakeroot
```

### debug_mode
Enabling the **debug_mode** option is a fast way to debug your **OpenSIPS**. This option will automatically force:
* staying in foreground (do not detach from console)
* set logging level to 4 (debug)
* set logging to standard error
* enable core dumping
* set UDP worker processes to 2
* set TCP worker processes to 2

Default value is false/0 (disabled).

NOTE that enabling this option will override all the other individual parameters like foreground mode, log level, udp_workers, tcp_workers, etc.

### db_version_table

The name of the table version to be used by the DB API to check the version of the used tables.  

Default value is **"version"**

Example of usage:

```text
db_version_table="version_1_8"
```

### db_default_url

The default DB URL to be used by modules if no per-module URL is given. Default is NULL (not defined)

Example of usage:

```text
db_default_url="mysql://opensips:opensipsrw@localhost/opensips"
```

### db_max_async_connections

Maximum number of TCP connections opened from a single OpenSIPS worker to each individual SQL backend. Default value is 10.

Individual backends are determined from DB URLs as follows:
```text
[ scheme, user, pass, host, port, database ]
```

Example of usage:

```text

    db_max_async_connections=220

```

### disable_503_translation

If 'yes', OpenSIPS will not translate the received 503 replies into 500 replies (RFC 3261 clearly states that a proxy should never relay a 503 response, but instead it must transform it into a 500).

Default value is 'no' (do translation).

### disable_core_dump

Can be 'yes' or 'no'. By default core dump limits are set to unlimited or
a high enough value. Set this config variable to 'yes' to disable core dump-ing
(will set core limits to 0).

Default value is 'no'.

Example of usage:

```opensips
disable_core_dump=yes
```

### disable_dns_blacklist

The DNS resolver, when configured with failover, can automatically store in a temporary blacklist the failed destinations. This will prevent (for a limited period of time) **OpenSIPS** to send requests to destination known as failed. So, the blacklist can be used as a memory for the DNS resolver. 

The temporary blacklist created by DNS resolver is named "dns" and it is by default selected for usage (no need use the use_blacklist()) function. The rules from this list have a life time of 4 minutes - you can change it at compile time, from resolve.c .

Can be 'yes' or 'no'. By default the blacklist is disabled (Default value is 'yes').

Example of usage:

```text
disable_dns_blacklist=no
```

### disable_dns_failover

Can be 'yes' or 'no'. By default DNS-based failover is enabled. Set this config variable to 'yes' to disable the DNS-based failover. This is a global option, affecting the core and the modules also.

Default value is 'no'.

Example of usage:

```text
disable_dns_failover=yes
```

### disable_stateless_fwd

Can be 'yes' or 'no'. This parameter controls the handling of stateless replies:
```text

    yes - drop stateless replies if stateless fwd functions (like forward) are not used in script
    no - forward stateless replies

```
Default value is 'yes'.

### dns

This parameter controls if the SIP server should attempt to lookup its own domain name in DNS. If this parameter is set to yes and the domain name is not in DNS a warning is printed on syslog and a "received=" field is added to the via header. 

Default is no.

### dns_retr_time

Time in seconds before retrying a dns request. Default value is system specific,
depends also on the '/etc/resolv.conf' content (usually 5s).

Example of usage:

```text
dns_retr_time=3
```

### dns_retr_no

Number of dns retransmissions before giving up. Default value is system specific,
depends also on the '/etc/resolv.conf' content (usually 4).

Example of usage:

```text
dns_retr_no=3
```

### dns_servers_no

How many dns servers from the ones defined in '/etc/resolv.conf' will be used. 
Default value is to use all of them.

Example of usage:

```text
dns_servers_no=2
```

### dns_try_ipv6

Can be 'yes' or 'no'. If it is set to 'yes' and a DNS lookup fails, it will retry it
for ipv6 (AAAA record). Default value is 'no'.

Example of usage:

```text
dns_try_ipv6=yes
```

### dns_try_naptr

Disables the NAPTR lookups when doing DNS based routing for SIP requests - if disabled, the DNS lookup will start with SRV lookups.
Can be 'yes' or 'no'. By default it is enabled, value 'yes'.

Example of usage:

```text
dns_try_naptr=no
```

### dns_use_search_list

Can be 'yes' or 'no'. If set to 'no', the search list in '/etc/resolv.conf'
will be ignored (=> fewer lookups => gives up faster). Default value is 'yes'.

HINT: even if you don't have a search list defined, setting this option
to 'no' will still be "faster", because an empty search list is in 
fact search "" (so even if the search list is empty/missing there will
still be 2 dns queries, eg. foo+'.' and foo+""+'.')

Example of usage:

```text
dns_use_search_list=no
```

### dst_blacklist

Definition of a IP/destination blacklist. These lists can be selected from script (at runtime) to filter  the outgoing requests, based on IP, protocol, port, etc.

Its primary purposes is be to prevent sending requests to critical IPs (like GWs), due bad DNS entries or to avoid sending to destinations that are known to be unavailable (temporary or permanent).

The grammar to specify a list is as it follows:

```text

  "dst_blacklist" = id [/bl_flags] [: bl_rules] 

```

* **id** is a unique identifier of the blacklist
* **bl_flags** contains a set of optional modifiers:
```text

  bl_flags = bl_flag [, bl_flag]*
  bl_flag = "expire" | "default" | "readonly"

```

* **bl_rules** contains one or more blacklists rules
```text

  bl_rules = [!] ipnet | { bl_rule [, bl_rule]* }
  bl_rule = [!] ( [bl_proto, ] ipnet [, port [, bl_pattern]] )

```

The blacklist modifiers meanings are as follows:
* "expire": the blacklist may contain entries that expire
* "default": the blacklist is used by default when sending requests, without having to explicitly set it (using the **use_blacklist** function)
* "readonly": the blacklist is statically defined in script and cannot change at runtime

When **dst_flags** are missing, the "readonly" flag is explicitly set.

A rule is defined of the following properties:
* if "!" is at the beginning of the rule, it negates the entire rule
* bl_proto : any supported protocol, or "any" for any protocol; if missing, default is "any"
* ipnet: IP or IP/MASK that should match the rule
* port : number or 0 for any
* bl_pattern - is a filename like matching (see  "man 3 fnmatch") applied on the outgoing request buffer (first_line+hdrs+body) 

Example of usage:

```text

   # filter out requests going to ips of my gws
   dst_blacklist = gw:{( tcp , 192.168.3.400 , 5060 , "" ),( any , 192.168.3.401 , 0 , "" )}
   # block requests going to "evil" networks
   dst_blacklist = net_filter:{ ( any , 192.168.1.120/255.255.255.0 , 0 , "" )}
   # block message requests with nasty words
   dst_blacklist = msg_filter:{ ( any , 192.168.20.0/255.255.255.0 , 0 , "MESSAGE*ugly_word" )}
   # block requests not going to a specific subnet
   dst_blacklist = net_filter2:{ !( any , 193.468.30.0/255.255.255.0 , 0 , "" )}
   # define a dynamic list that is built at runtime and has expire entries
   dst_blacklist = net_dynamic/expire

```

### enable_asserts
Default value: false

  

Set to *true* in order to enable the [assert](https://docs.opensips.org/manual/3-4/script-corefunctions#assert) script statement.

Example of usage:
```text

    enable_asserts = true

```

### event_pkg_threshold

A number representing the percentage threshold above which the E_CORE_PKG_THRESHOLD event is raised, warning about low amount of free private memory. It accepts integer values between 0 and 100.

Default value is 0 ( event disabled ).

Example of usage:

```text
event_pkg_threshold = 90
```

### event_shm_threshold

A number representing the percentage threshold above which the E_CORE_SHM_THRESHOLD event is raised, warning about low amount of free shared memory. It accepts integer values between 0 and 100.

Default value is 0 ( event disabled ).

Example of usage:

```text
event_shm_threshold = 90
```

### exec_dns_threshold

A number representing the maximum number of microseconds a DNS query is expected to last. Anything above the set number will trigger a warning message to the logging facility.

Default value is 0 ( logging disabled ).

Example of usage:

```text
exec_dns_threshold = 60000
```

### exec_msg_threshold

A number representing the maximum number of microseconds the processing of a SIP msg is expected to last. Anything above the set number will trigger a warning message to the logging facility.
Aside from the message and the processing time, the most time consuming function calls from the script will also be logged.

Default value is 0 ( logging disabled ).

Example of usage:

```text
exec_msg_threshold = 60000
```

### include_file

Can be called from outside route blocks to load additional routes/blocks or from inside them to simply perform more functions.  The file path can be relative or absolute.  If it is a relative path, first attempt to locate it is relative to the directory from which OpenSIPS is started.  If that fails, second try is relative to directory of the file that includes it.  Will throw an error if file is not found.

Example of usage:

```text

    include_file "proxy_regs.cfg"

```

### import_file

Same as include_file.

Example of usage:

```text

    import_file "proxy_regs.cfg"

```

### listen

> [!WARNING]
> Replaced in OpenSIPS 3.1


This parameter was replaced by the [#socket|socket]] parameter, preserving exactly the same format and behavior.

### log_facility

> [!WARNING]
> Replaced in OpenSIPS 3.4


This parameter was replaced by the [syslog_facility](Script-CoreParameters.md#syslog_facility) parameter, preserving exactly the same format and behavior.

### log_event_enabled

Enables the triggering of the E_CORE_LOG event for every log message generated by opensips. By default this is disabled.

Example of usage:

```text

    log_event_enabled = yes

```

### log_event_level_filter

Extra log level filtering for the E_CORE_LOG event. This parameter may be useful when different levels of verbosity are desired between syslog/standard error logs  and the logs delivered through the E_CORE_LOG event.

The *log_event_level_filter* should be used in concordance with the [log_level](Script-CoreParameters.md#log_level) parameter, i.e. a level lower than *log_level*.

Default value is *0* (no filtering).

Example of usage:

```text

    log_event_level_filter = 3

```

### log_json_buf_size

Default value: 6144

Size of the buffer used for printing the JSON document corresponding to a log message. This parameter makes sense when the *json* or *json_cee* log formats are used. If the buffer is too small, the log message will be truncated.

Usage example:
```text

    log_json_buf_size = 8192 #given in bytes

```

### log_level

Set the logging level (how verbose OpenSIPS should be). Higher values make **OpenSIPS** print more  messages.

Examples of usage:

```text

    log_level=1 -- print only important messages (like errors or more critical situations) 
    - recommended for running proxy as daemon

    log_level=4 -- print a lot of debug messages - use it only when doing debugging sessions

```

Actual values are:
* -3 - Alert level
* -2 - Critical level
* -1 - Error level
* 1 - Warning level
* 2 (default) - Notice level
* 3 - Info level
* 4 - Debug level

The value of the *log_level* parameter can also be get and set dynamically using the [log_level](Interface-CoreMI.md#log_level) Core MI function or [`$log_level`](Script-CoreVar.md#log_level) script variable.

### log_msg_buf_size

Default value: 4096

Size of the buffer used for printing the log message's payload. This is used for printing the "message" field from a JSON document, when the *json* or *json_cee* log formats are used or when the *E_CORE_LOG* event is raised, if enabled. If the buffer is too small, the log message will be truncated.

Usage example:
```text

    log_msg_buf_size = 8192 #given in bytes

```

### log_name

> [!WARNING]
> Replaced in OpenSIPS 3.4


This parameter was replaced by the [syslog_name](Script-CoreParameters.md#syslog_name) parameter, preserving exactly the same format and behavior.

### log_stdout

Although all OpenSIPS logs are done via standard error, enabling this parameter may be still be useful when trying to extract logs from 3rd party libraries.

- "no" (default) - drop all standard output logs

- "yes" - let all standard output logs pass through

Example of usage:

```text

    log_stdout = yes

```

### log_stderror

> [!WARNING]
> Deprecated in OpenSIPS 3.4


This parameter is deprecated and it's behavior starting with OpenSIPS 3.4 is equivalent to setting the [stderror_enabled](Script-CoreParameters.md#stderror_enabled) and [syslog_enabled](Script-CoreParameters.md#syslog_enabled) parameters, as following:

- "no" - **stderror_enabled=no**, **syslog_enabled=yes**

- "yes" (default) - **stderror_enabled=yes**, **syslog_enabled=no**

Example of usage:

```text

    log_stderror = yes

```

### log_prefix

A string prefix which will be prepended to all logs produced by OpenSIPS (from both C code and script xlog() statements).  Default: *""*

Example of usage:

```text

    log_prefix = "opensips-backup"

```

### max_while_loops

The parameters set the value of maximum loops that can be done within a "while". Comes as a protection to avoid infinite loops in config file execution. Default is 100.

Example of usage:

```text
max_while_loops=200
```

### maxbuffer

The size in bytes not to be exceeded during the auto-probing procedure of discovering the maximum buffer size for receiving UDP messages. Default value is 262144.

Example of usage:

```text
maxbuffer=65536
```

### mem-group

Defines a group of modules (by name) to get separate memory statistics. OpenSIPS will provide per-group memory information - the number of allocated fragments, the amount of used memory and the amount of real used memory (with memory manager overhead). This is useful if you want to monitor the memory usage of a certain module (or group of modules).

In order for the feature to work you have to run "make generate-mem-stats" and complile with the variable SHM_EXTRA_STATS defined.

Usage example:
```text

    mem-group = "interest": "core" "tm"
    mem-group = "runtime": "dialog" "usrloc" "tm"

```

For the above example the generated statistics will be named: shmem_group_interest:fragments, shmem_group_interest:memory_used, shmem_group_interest:real_used.

Multiple groups can be defined, but they must not have the same name.

If you want to generate the statistics for the default group (all the other modules not included in a group) you have to complile with the variable SHM_SHOW_DEFAULT_GROUP defined.

### mem_warming

Default value: off

  

Only relevant when the HP_MALLOC compile flag is enabled. If set to "on", on each startup, OpenSIPS will attempt to restore the memory fragmentation pattern it had before the stop/restart. If no [pattern_file](https://docs.opensips.org/manual/3-4/script-coreparameters#server_signature) from a previous run is found, memory warming is skipped, and the memory allocator simply starts with a big chunk of memory, like all other allocators.

  

Memory warming is useful when dealing with high volumes of traffic (thousands of cps on multi-core machines - the more cores, the more useful), because processes must mutually exclude themselves when chopping up the initial big memory chunk. By performing fragmentation on startup, OpenSIPS will also behave optimally in the first minute(s) after a restart. Fragmentation usually lasts a few seconds (e.g. ~5 seconds on an 8GB shm pool and 3.4Ghz CPU) - traffic will not be processed at all during this period.

Example of usage:
```text

    mem_warming = on

```

### mem_warming_percentage

Default value: 75

  

How much of OpenSIPS's memory should be fragmented with the pattern of the previous run, upon a restart. Used at startup, if [mem_warming](https://docs.opensips.org/manual/3-4/script-coreparameters#rev_dns) is enabled.

Example of usage:
```text

    mem_warming_percentage = 50

```

### mem_warming_pattern_file

Default value: "CFG_DIR/mem_warming_pattern"

  

Only relevant if [mem_warming](https://docs.opensips.org/manual/3-4/script-coreparameters#rev_dns) is enabled. It contains the memory fragmentation pattern of a previous OpenSIPS run. This file is overwritten during each OpenSIPS shutdown, and is used during startup in order to restore the service behavior as soon as possible.

Example of usage:
```text

    mem_warming_pattern_file = "/var/tmp/my_memory_pattern"

```

### memdump | mem_dump

Log level to print memory status information (runtime and shutdown). It has to be less than the value of 'log_level' parameter if you want memory info to be logged. Default: memdump=L_DBG (4)

Example of usage:

```text
memdump=2
```

NOTE that setting memlog (see below), will also set the memdump parameter - if you want different values for memlog and memdump, you need to first set memlog and then memdump.

### memlog | mem_log

Log level to print memory debug info. It has to be less than the value of 'log_level' parameter if you want memory info to be logged. Default: memlog=L_DBG (4)

Example of usage:

```text
memlog=2
```

> [!NOTE]
> by setting memlog parameter, the memdump will automatically be set to the same value (see memdump docs).

### mcast_loopback

It can be 'yes' or 'no'. If set to 'yes', multicast datagram are sent over loopback. Default value is 'no'.

Example of usage:

```text
mcast_loopback=yes
```

### mcast_ttl

Set the value for multicast ttl. Default value is OS specific (usually 1).

Example of usage:

```text
mcast_ttl=32
```

### mhomed

Set the server to try to locate outbound interface on multihomed host. By default is not (0) - it is rather time consuming.

Example of usage:

```text
mhomed=1
```

### mpath

Set the module search path.  This can be used to simplify the loadmodule parameter

Example of usage:

```opensips

    mpath="/usr/local/lib/opensips/modules"
    loadmodule "mysql.so"
    loadmodule "uri.so"
    loadmodule "uri_db.so"
    loadmodule "sl.so"
    loadmodule "tm.so"
    ...

```

### open_files_limit

If set and bigger than the current open file limit, **OpenSIPS** will try
to increase its open file limit to this number. Note: **OpenSIPS** must be
started as root to be able to increase a limit past the hard limit
(which, for open files, is 1024 on most systems).

Example of usage:

```text
open_files_limit=2048
```

### poll_method

The poll method to be used by the I/O internal reactor - by default the best one for the current OS is selected. The available types are: poll, epoll, sigio_rt, select, kqueue, /dev/poll.

Example of usage:

```text
poll_method=select
```

### port

The port the SIP server listens to. The default value for it is 5060.

Example of usage:

```text
port=5080
```

### pv_print_buf_size

The maximum size of an expanded formatted string containing variables and/or pseudo-variables.  Default: 20,000 bytes.

Example of usage:

```text
pv_print_buf_size = 60000
```

### query_buffer_size

If set to a value greater than 1, inserts to DB will not be flushed one by one. Rows to be inserted will be kept in memory until until they gather up to query_buffer_size rows, and only then they will be flushed to the database.

Example of usage:

```text
query_buffer_size=5
```

### query_flush_time

If query_buffer_size is set to a value greater than 1, a timer will trigger once every query_flush_time seconds,
ensuring that no row will be kept for too long in memory.

Example of usage:

```text
query_flush_time=10
```

### restart_persistency_cache_file

This parameter controls the name of the cache file that is used to store restart persistence memory.

Default value is ".restart_persistency.cache".

### restart_persistency_size

This parameter controls the size of the cache file. If this parameter is not specified, it defaults to the size of the shared memory.

Default value is the value of the shared memory, 32MB.

### rev_dns

This parameter controls if the SIP server should attempt to lookup its own IP address in DNS. If this parameter is set to yes and the IP address is not in DNS a warning is printed on syslog and a "received=" field is added to the via header. 

Default is no.

### server_header

The body of Server header field generated by **OpenSIPS** when it sends a request as UAS.  It defaults to "OpenSIPS (`<version>` (`<arch>`/`<os>`))".  

Example of usage:

```text

server_header="Server: My Company SIP Proxy"

```

Please note that you have to add the header name "Server:", otherwise **OpenSIPS** will just write a header like:

```text

My Company SIP Proxy

```

### server_signature

This parameter controls the "Server" header in any locally generated message. 

Example of usage:

```text
server_signature=no
```

If it is enabled (default=yes) a header is generated as in the following example:

```text
Server: OpenSIPS (0.9.5 (i386/linux))
```

### shm_hash_split_percentage

Only relevant when the HP_MALLOC compile flag is enabled. It controls how many memory buckets will be optimized. (e.g. setting it to 2% will optimize the first 81 most used buckets as frequency). The default value is 1.

### shm_memlog_size

Configures the maximum number of shm operations to keep in the in-memory history. A separate memory block, dedicated for this shm debug info will be allocated. As such, OpenSIPS will actually take up more system memory than the configured shm pool (*-m* command line option). For example, for a shm_memlog_size=1000000, approximately 750 MB more will be used. This option is intended for debugging purposes and is disabled by default, i.e. shm_memlog_size=0. 

### shm_secondary_hash_size

Only relevant when the HP_MALLOC compile flag is enabled. It represents the optimization factor of a single bucket (e.g. setting it to 4 will cause the optimized buckets to be further split into 4). The default value is 8.

### sip_warning

Can be 0 or 1. If set to 1 (default value is 0) a 'Warning' header is added to each reply generated by **OpenSIPS**.
The header contains several details that help troubleshooting using the network traffic dumps.

Example of usage:

```text
sip_warning=0
```

### socket

Set the network addresses/sockets the OpenSIPS server should listen on. Its syntax is `protocol:address[:port]`, where:
* protocol: should be one of the transport modules loaded in the config file (e.g., udp, tcp, tls, bin, hep)
* address: can be an IP address, a hostname, a network interface id, or the ***** wildcard which makes OpenSIPS listen on all possible interfaces for that protocol
* port: optional, the port used by the listening socket - if absent, the default port exported by the transport module is used.
This parameter can be set multiple times in same configuration file, the server listening on all specified sockets.

The *socket* definition may accept several optional parameters:
* "AS ip:port" - to configure an advertised IP and port only for an interface. Example "AS 11.23.43.44:5060"
* "USE_WORKERS n" - to set a different number of workers for this socket only (for UDP, SCTP and HEP_UDP interfaces only). This will override the global "udp_worker" parameter. Example "use_workers 5"
* "ANYCAST" - to marke the socket as an anycast IP
* "USE_AUTO_SCALING_PROFILE" - to enforce a certain governing policy on how many UDP workers you have at runtime. Dynamically, UDP processes my be created or terminated, depending on the load/traffic. This parameter may be used ONLY for UDP sockets. Note that the per-socket defined auto-scaling profile will override this global UDP auto-scaling profile.
* "TAG" - this is a non SIP name/tag of the socket to be used when replicating the socket identify across an OpenSIPS cluster, with other OpenSIPS nodes. By using same TAG value, you can correlate/link listening sockets with different IPs on different OpenSIPS nodes. This is useful when replicating dialogs between OpenSIPS instances with different IPs.
* "FRAG" - indicates that the socket should not use PMTU (Path MTU) discovery to determine whether fragmentation should be done, but always allow fragmentation (i.e. do not force DF bit to 1 in UDP packets).
* "REUSE_PORT" - for TCP-based sockets only ; it allows outgoing TCP connections to reuse the listening port (of the socket) as the source port (rather than getting an emphemerous port).

Remember that the above parameters only affect the sockets they are configured for; if they are not defined for a given socket, the global values will be used instead.

Examples of usage:

```text

    socket = udp:*
    socket = udp:eth1
    socket = tcp:eth1:5062
    socket = tls:localhost:5061
    socket = hep_udp:10.10.10.10:5064
    socket = ws:127.0.0.1:5060 use_workers 5
    socket = sctp:127.0.0.1:5060 as 99.88.44.33:5060 use_workers 3
    socket = udp:10.10.10.10:5060 anycast
    socket = udp:10.10.10.10:5060 use_workers 4 use_auto_scaling_profile PROFILE_SIP
    

```

On startup, OpenSIPS reports all the sockets that it is listening on.

### stderror_enabled

Enables writing log messages to standard error. Default value is *yes*/*1*.

Example of usage:

```text

    stderror_enabled = no

```

### stderror_level_filter

Extra log level filtering for the messages written to the standard error. This parameter may be useful when different levels of verbosity are desired for syslog and standard error logging.

The *stderror_level_filter* should be used in concordance with the [log_level](Script-CoreParameters.md#log_level) parameter, i.e. a level lower than *log_level*.

Default value is *0* (no filtering).

Example of usage:

```text

    stderror_level_filter = 2

```

### syslog_enabled

Enables writing log messages to syslog. Default value is *no*/*disabled*.

Example of usage:

```text

    syslog_enabled = yes

```

### stderror_log_format

Format of the log messages printed to standard error. Possible values are:

* *plain_text* (default) - standard, plain text log message;

* *json* - basic JSON document

* *json_cee* - JSON document following the [CEE(Common Event Expression)](https://cee.mitre.org/language/1.0-beta1/core-profile.html) schema.

Default value is *plain_text*.

Example of usage:

```text

    stderror_log_format = "json"

```

### syslog_facility

If **OpenSIPS** logs to syslog, you can control the facility for logging. Very
useful when you want to divert all **OpenSIPS** logs to a different log file.
See the man page syslog(3) for more details.

Default value is LOG_DAEMON.

Example of usage:

```text
syslog_facility=LOG_LOCAL0
```

### syslog_level_filter

Extra log level filtering for the messages sent to syslog. This parameter may be useful when different levels of verbosity are desired for syslog and standard error logging.

The *stderror_level_filter* should be used in concordance with the [log_level](Script-CoreParameters.md#log_level) parameter, i.e. a level lower than *log_level*.

Default value is *0* (no filtering).

Example of usage:

```text

    syslog_level_filter = 1

```

### syslog_log_format

Format of the log messages sent to syslog. Possible values are:

* *plain_text* (default) - standard, plain text log message;

* *json* - basic JSON document

* *json_cee* - JSON document following the [CEE(Common Event Expression)](https://cee.mitre.org/language/1.0-beta1/core-profile.html) schema.

Default value is *plain_text*.

Example of usage:

```text

    syslog_log_format = "json"

```

### syslog_name

Set the id to be printed in syslog. The value must be a string and has
effect only when **OpenSIPS** runs in daemon mode (fork=yes), after daemonize.
Default value is argv[0].

Example of usage:

```text
syslog_name="osips-5070"
```

### tcp_workers
Number of worker processes to be created for reading from TCP connections. These workers are responsible for handling any traffic over any TCP based protocol, like SIP-TCP, SIP-TLS, SIP-WS, SIP-WSS, BIN or HEP.
If no value is explicitly set, 8 TCP workers will be created.
Optionally, you can define a auto-scaling profile to govern in a dynamic way the number of TCP workers (by creating or terminating processes, depending on load). See [auto_scaling_profile](#auto_scaling_profile) parameter for more.

Example of usage:

```text
tcp_workers= 4
tcp_workers= 3 use_auto_scaling_profile PROFILE_SIP
```

### tcp_accept_aliases

Default value *0* (disabled). If enabled, OpenSIPS will enforce RFC 5923 behaviour when detecting an *";alias"* Via header field parameter and will reuse **any** TCP (or TLS, WS, WSS) connection opened for such SIP requests (source IP + Via port + proto) when sending other SIP requests backwards, towards the same (source IP + Via port + proto) pair. The final purpose of RFC 5923, after all, is to minimize the number of TLS connections a SIP proxy must open, due to the large CPU overhead of the connection setup phase.

  

On top of RFC 5923's connection reusage (aliasing) mechanism, TCP connections in OpenSIPS are also persistent across multiple SIP dialogs. This can be controlled with the [tcp_connection_lifetime](#tcp_connection_lifetime) global parameter.

  

> [!WARNING]
> Enabling the global **tcp_accept_aliases** parameter (RFC 5923) for end-user initiated connections (who are most likely grouped by one or more public IPs) is an open vector for call hijacking! In such platforms, we recommend using the [force_tcp_alias()](https://docs.opensips.org/manual/3-4/script-corefunctions#force_tcp_alias) core function, in order to employ RFC 5923 behaviour only in conjunction with adjacent SIP proxies.

### tcp_connect_timeout

Time in milliseconds before an ongoing blocking attempt to connect will be aborted. Default value is 100ms.

Example of usage:
```text

    tcp_connect_timeout = 5

```

### tcp_connection_lifetime

Lifetime in seconds for TCP sessions. TCP sessions which are inactive for >tcp_connection_lifetime will be closed by **OpenSIPS**. Default value is defined in tcp_conn.h: #define DEFAULT_TCP_CONNECTION_LIFETIME 120. Setting this value to 0 will close the TCP connection pretty quick ;-). You can also set the TCP lifetime to the expire value of the REGISTER by using the tcp_persistent_flag parameter of the registrar module.

Example of usage:
```text

    tcp_connection_lifetime = 3600

```

### tcp_max_connections

Maximum number of active TCP **accepted** connections (i.e. initiated by remote endpoints).  Once the limit is reached, any new incoming TCP connections will be rejected. The default is **2048**.  For outgoing TCP connections (initiated by OpenSIPS), there is currently no limit.

Example of usage:
```text

    tcp_max_connections = 4096

```

### tcp_max_msg_time

The maximum number of seconds that a SIP message is expected to arrive via TCP. If a single SIP packet is still not fully received after this number of seconds, the connection is dropped ( either the connection is very overloaded and this leads to high fragmentation - or we are the victim of an ongoing attack where the attacker is sending the traffic very fragmented in order to decrease our performance ). Default value is 4

Example of usage:
```text

    tcp_max_msg_time = 8

```

### tcp_no_new_conn_bflag

A branch flag to be used as marker to instruct OpenSIPS not to attempt to open a new TCP connection when delivering a request, but only to reuse an existing one (if available). If no existing conn, a generic send error will be returned.

This is intended to be used in NAT scenarios, where makes no sense to open a TCP connection towards a destination behind a NAT (like TCP connection created during registration was lost, so there is no way to contact the device until it re-REGISTER). Also this can be used to detect when a NATed registered user lost his TCP connection, so that opensips can disable his registration as useless.

Example of usage:
```text

     tcp_no_new_conn_bflag = TCP_NO_CONNECT
     ...
     route {
         ...
         if (isflagset(DST_NATED) && $socket_in(proto) == "TCP")
             setbflag(TCP_NO_CONNECT);
         ...
         t_relay("no-auto-477 ");
         $var(retcode) = $rc;
         if ($var(retcode) == -6) {
             #send error
             xlog("unable to send request to destination");
             send_reply("404", "Not Found");
             exit;
         } else if ($var(retcode) < 0) {
             sl_reply_error();
             exit;
         }
     }

```

### tcp_no_new_conn_rplflag

A message flag, similar to [tcp_no_new_conn_bflag](#tcp_no_new_conn_bflag), for preventing OpenSIPS to try to open a new TCP connection (if none available) when sending back a reply for the current request.

Example of usage:
```text

     tcp_no_new_conn_msgflag = TCP_NO_RPL_CONNECT
     ...
     route {
         ...
         # if source is detected as NAT'ed, prevent opening back
         # TCP conns for replying
         if (isflagset(SRC_NATED) && $socket_in(proto) == "TCP")
             setbflag(TCP_NO_RPL_CONNECT);
         ...
         # this may fail at transport layer if no
         # TCP conn exists
         t_reply(302,"Redirected");         
     }

```

### tcp_parallel_read_on_workers

This option will allow a TCP conn to perform read operations from different processes, not only from one. So far, upon creation, a TCP conn was assigned to a TCP workers which was doing all the reading for that TCP conn. This may become a bootleneck. With "tcp_parallel_read_on_workers", after a read is completed, the TCP conn is passed back to the TCP Main processes, which will perform a re-balancing for the next read operations, passing the TCP conn potentially to another worker.

> [!NOTE]
> at TCP conn level, the read ops are still performed in serial way, one at a time (even if from different processes)

### tcp_socket_backlog

The backlog argument defines the maximum length to which the queue of pending connections for the TCP listening sockets may grow. If a connection  request arrives when the queue is full, the client may receive an error with an indication  of  ECONNREFUSED  or,  if  the underlying protocol supports retransmission, the request may be ignored so that a later reattempt at connection succeeds.

Default configured value is 10.

### tcp_threshold
A number representing the maximum number of microseconds sending of a TCP request is expected to last. Anything above the set number will trigger a warning message to the logging facility.

Default value is 0 ( logging disabled ).

Example of usage:

```text
tcp_threshold = 60000
```

### tcp_keepalive

Enable or disable TCP keepalive (OS level).

*Enabled by default.*

Example of usage:

```text

    tcp_keepalive = 1

```

### tcp_keepcount

Number of keepalives to send before closing the connection (Linux only). Default value is Operating System dependent and can be found using `cat /proc/sys/net/ipv4/tcp_keepalive_probes`. Common value is *9*.

*Setting [tcp_keepcount](Script-CoreParameters.md#udp_workers) to any value will enable [tcp_keepalive](Script-CoreParameters.md#tos).*

Example of usage:
```text

    tcp_keepcount = 5

```

### tcp_keepidle

Amount of time before OpenSIPS will start to send keepalives if the connection is idle (Linux only). Default value is Operating System dependent and can be found using `cat /proc/sys/net/ipv4/tcp_keepalive_time`. Common value is *7200* seconds.

*Setting [tcp_keepidle](Script-CoreParameters.md#user_agent_header) to any value will enable [tcp_keepalive](Script-CoreParameters.md#tos).*

Example of usage:
```text

    tcp_keepidle = 30

```

### tcp_keepinterval

Interval between keepalive probes, if the previous one failed (Linux only). Default value is Operating System dependent and can be found using `cat /proc/sys/net/ipv4/tcp_keepalive_intvl`. Common value is *75* seconds.

*Setting [tcp_keepinterval](Script-CoreParameters.md#wdir) to any value will enable [tcp_keepalive](Script-CoreParameters.md#tos).*

Example of usage:
```text

    tcp_keepinterval = 10

```

### timer_workers
The number of worker processes to be created exclusively for timer related tasks/processing. The default and minimum number is '1'.
Optionally, you can define a auto-scaling profile to govern in a dynamic way the number of timer workers (by creating or terminating processes, depending on load). See [auto_scaling_profile](#auto_scaling_profile) parameter for more.

Example of usage:
```text

    timer_workers = 3
    timer_workers = 3 use_auto_scaling_profile PROFILE_TIMER

```

### tos

The TOS (Type Of Service) to be used for the sent IP packages (both TCP and UDP).

Example of usage:

```text

    tos=IPTOS_LOWDELAY
    tos=0x10
    tos=IPTOS_RELIABILITY

```

### udp_workers

Number of worker processes to be created for **each** UDP or SCTP interface you have defined. Default value is 8.
Optionally, you can define a auto-scaling profile to govern in a dynamic way the number of UDP workers (by creating or terminating processes, depending on load). Note that the per-interface defined auto-scaling profile will override this global UDP auto-scaling profile.
See [auto_scaling_profile](#auto_scaling_profile) parameter for more.

Example of usage:
```text

    udp_workers=16
    udp_workers=4 use_auto_scaling_profile PROFILE_SIP 

```

> [!NOTE]
> this global value (applicable for all UDP/SCTP interfaces) can be override if you set a different number of workers in the definition of a specific interface - so actually you can define a different number of workers for each interface (see the [listen](#listen) parameter for syntax).

### user_agent_header

The body of User-Agent header field generated by **OpenSIPS** when it sends a request as UAC.  It defaults to "OpenSIPS (`<version>` (`<arch>`/`<os>`))". 
Example of usage:

```text

user_agent_header="User-Agent: My Company SIP Proxy"

```

Please note that you have to include the header name "User-Agent:" as **OpenSIPS** does not add it and you will get an erroneous header like:
```text

My Company SIP Proxy

```

### wdir

The working directory used by **OpenSIPS** at runtime. You might find it usefull when come to generating core files :)

Example of usage:
```text

     wdir="/usr/local/opensips"
     or
     wdir=/usr/opensips_wd

```

### xlog_buf_size

Default value: 4096

  

Size of the buffer used to print a single line on the chosen logging facility of OpenSIPS. If the buffer is too small, an overflow error will be printed, and the concerned line will be skipped.

Usage example:
```text

    xlog_buf_size = 8388608 #given in bytes

```

### xlog_force_color

Default value: false

  

Only relevant when [xlog](https://docs.opensips.org/manual/3-4/script-corefunctions#add_blacklist_rule) is set to *true*. Enables the use of the [color escape sequences](https://docs.opensips.org/manual/3-4/script-corevar#route.name), otherwise they will have no effect.

Usage example:
```text

    xlog_force_color = true

```

### xlog_level

Similar to  [log_level](#log_level) this parameter independently controls (from the rest of the OpenSIPS code) the verbosity of the xlog() functions. This give you the possibility to separately control the verbosity level for logs from code versus logs from xlog().

Default value is 2 / L_NOTICE

Usage example:
```text

    xlog_level = 3 #L_DBG

```

### xlog_print_level

Default value: 2 (L_NOTICE)

  

Default level for printing the logs generated by [xlog](https://docs.opensips.org/manual/3-4/script-corefunctions#xlog) core function, when the log_level parameter is omitted.

Usage example:
```text

    xlog_print_level = 2 #L_NOTICE

```
