---
title: "Core Parameters"
description: "This section lists all parameters exported by OpenSIPS core for script usage (to be used in opensips.cfg)."
---

This section lists all parameters exported by **OpenSIPS** core for script usage (to be used in opensips.cfg).

## Core parameters

Global parameters available in the *opensips.cfg* configuration file. Accepted values depend on the parameter type: double-quoted strings, numbers or booleans (`true`/`false`).

### abort_on_assert
Default value is `false`.

  

Only relevant if [asserts](https://docs.opensips.org/manual/devel/script-corefunctions#assert) are enabled. Set to `true` to make OpenSIPS shut down immediately when a script assert fails.

Example of usage:
```text

    abort_on_assert = true

```

### advertised_address

This can be an IP address or string and represents the address advertised in the Via header and other destination lumps, such as Record-Route headers. If empty or not set, the socket address used to send the request is advertised.

> [!WARNING]
> Do not set this unless you know what you are doing, for example when handling NAT traversal.
> OpenSIPS does not validate this value; for example, `foo.bar` is accepted even if it does not exist.

Example of usage:
```text

    advertised_address = "opensips.org"

```

> [!NOTE]
> Besides this global approach, you can also define an advertised IP and port per interface using the [socket](#socket) parameter. Per-interface advertised values are used only for traffic leaving that interface.

### advertised_port

The port advertised in the Via header and other destination lumps, such as Record-Route headers. If empty or not set, the port used to send the message is advertised. The same warnings as for [advertised_address](#advertised_address) apply.

Example of usage:
```text

    advertised_port = 5080

```

> [!NOTE]
> Besides this global approach, you can also define an advertised IP and port per interface using the [socket](#socket) parameter. Per-interface advertised values are used only for traffic leaving that interface.

### alias

Sets alias hostnames for the server. It can be set multiple times, with each value added to the list used to match the hostname when `myself` is checked.

If the `:port` part is omitted, **all** ports of the given hostname are considered aliases, similar to port `0`.

It may take an optional **accept_subdomain** indicator to also match any subdomain of the defined domain.

> [!IMPORTANT]
> It is necessary to include the port used in the `socket` definitions in the alias definition otherwise the `loose_route()` function will not work as expected for local forwards!


Example of usage:

```text

    alias = udp:other.domain.com:5060
    alias = tcp:another.domain.com:5060
    # accept subdomains like sip.domainX.com
    alias = udp:domainX.com:5060 accept_subdomain

```

### auto_aliases

This parameter controls whether aliases should be automatically discovered and added while fixing listening sockets. The auto-discovered aliases are the result of a DNS lookup, when the [socket](#socket) definition uses a hostname, or of a reverse DNS lookup on the socket IP.

For backwards compatibility, the default value is `false`.

Example of usage:
```text

    auto_aliases = true

```

### auto_scaling_cycle
The number of seconds defining an auto-scaling cycle. During each cycle, the auto-scaling engine evaluates the internal load of the process groups and decides whether more processes need to be created or existing processes need to be terminated. See [auto_scaling_profile](#auto_scaling_profile) for more details on how auto-scaling works.

The default value is `1` second.

Example of usage:
```text

    auto_scaling_cycle = 3  # do auto-scaling checks once every 3 seconds

```

### auto_scaling_profile
Defines the auto-scaling behavior: how many processes are allowed and when to create or terminate processes. These profiles may be used for UDP processes (see the [udp_workers](#udp_workers) or [socket](#socket) options), TCP processes (see the [tcp_workers](#tcp_workers) option) or timer processes (see the [timer_workers](#timer_workers) option).

For more, see [this external description of auto-scaling](https://blog.opensips.org/2019/02/25/auto-process-scaling-a-cure-for-load-and-resources-concerns/).

Example of usage:
```text

    auto_scaling_profile = PROFILE_SIP
        scale up to 6 on 70% for 4 cycles within 5
        scale down to 2 on 18% for 10 cycles

```
This profile allows the group to fork up to 6 processes. A new process is forked when the overall load of the group is higher than 70% for more than 4 cycles during a 5-cycle monitoring window. A cycle is the monitoring time unit, as defined by [auto_scaling_cycle](#auto_scaling_cycle).

The profile also allows the group to scale down to a minimum of 2 processes. A process is terminated when the overall load of the group is lower than 18% during 10 cycles. The down-scaling part of the profile is optional. If not defined, OpenSIPS will only scale up.

### check_via

Checks whether the address in the topmost Via header of replies is local. Default value is `false` (check disabled).

Example of usage:

```text

    check_via = true

```

### chroot

The value must be a valid path in the system. If set, **OpenSIPS** will chroot, changing its root directory to this path.

Example of usage:

```text

    chroot = "/other/fakeroot"

```

### debug_mode
Enabling **debug_mode** is a fast way to debug **OpenSIPS**. This option automatically forces:
* foreground mode (do not detach from the console)
* logging level 4 (debug)
* logging to standard error
* core dumping
* UDP worker processes to 2, if UDP is enabled
* TCP worker processes to 2, or the maximum configured value if lower than 2, if TCP is enabled

Default value is `false` (disabled).

> [!NOTE]
> Enabling this option overrides individual parameters such as foreground mode, log level, `udp_workers` and `tcp_workers`.

Example of usage:
```text

    debug_mode = true

```

### db_version_table

The name of the database table used by the DB API to check table versions.

Default value is `"version"`.

Example of usage:
```text

    db_version_table = "version_4_0"

```

### db_default_url

The default DB URL used by modules when no per-module URL is configured.

Default value is `NULL` (not defined).

Example of usage:
```text

    db_default_url = "mysql://opensips:opensipsrw@localhost/opensips"

```

### db_max_async_connections

Maximum number of TCP connections opened from a single OpenSIPS worker to each individual SQL backend.

Default value is `10`.

Individual backends are determined from DB URLs as follows:
```text

    [ scheme, user, pass, host, port, database ]

```

Example of usage:
```text

    db_max_async_connections = 220

```

### disable_503_translation

If set to `true`, OpenSIPS will not translate received 503 replies into 500 replies. RFC 3261 states that a proxy should never relay a 503 response, but transform it into a 500 response instead.

Default value is `false` (translation enabled).

Example of usage:
```text

    disable_503_translation = true

```

### disable_core_dump

If set to `true`, OpenSIPS disables core dumps by setting the core dump size limit to 0. By default, core dump limits are set to unlimited or to a high enough value.

Default value is `false`.

Example of usage:
```text

    disable_core_dump = true

```

### disable_dns_blacklist

When DNS failover is configured, the DNS resolver can temporarily blacklist failed destinations. This prevents **OpenSIPS**, for a limited time, from sending requests to destinations known to have failed. The blacklist acts as a memory for the DNS resolver.

The temporary blacklist created by the DNS resolver is named `dns` and is selected by default for failover usage, so there is no need to call `use_blacklist()` for it. The rules in this list have a lifetime of 4 minutes; this can be changed at compile time in `resolve.c`.

If set to `true`, this DNS blacklist is disabled.

Default value is `true` (DNS blacklist disabled).

Example of usage:
```text

    disable_dns_blacklist = false

```

### disable_dns_failover

If set to `true`, OpenSIPS disables DNS-based failover. This is a global option, affecting both the core and the modules.

Default value is `false` (DNS-based failover enabled).

Example of usage:
```text

    disable_dns_failover = true

```

### disable_stateless_fwd

Controls the handling of stateless replies:

```text

    true  - drop stateless replies if stateless forwarding functions, such as forward(), are not used in the script
    false - forward stateless replies

```

Default value is `true`.

Example of usage:
```text

    disable_stateless_fwd = false

```

### dns

This parameter controls whether the SIP server should attempt to look up its own domain name in DNS. If this parameter is set to `true` and the domain name is not in DNS, a warning is printed to syslog and a `received=` field is added to the Via header.

Default value is `false`.

Example of usage:
```text

    dns = true

```

### dns_retr_time

Time in seconds before retrying a DNS request. Default value is system-specific and also depends on the `/etc/resolv.conf` content, usually 5 seconds.

Example of usage:
```text

    dns_retr_time = 3

```

### dns_retr_no

Number of DNS retransmissions before giving up. Default value is system-specific and also depends on the `/etc/resolv.conf` content, usually `4`.

Example of usage:
```text

    dns_retr_no = 3

```

### dns_servers_no

How many DNS servers from `/etc/resolv.conf` will be used.

Default value is to use all of them.

Example of usage:
```text

    dns_servers_no = 2

```

### dns_try_ipv6

If set to `true` and a DNS lookup fails, OpenSIPS retries the lookup for IPv6 using an AAAA record.

Default value is `false`.

Example of usage:
```text

    dns_try_ipv6 = true

```

### dns_try_naptr

Controls whether NAPTR lookups are performed when doing DNS-based routing for SIP requests. If disabled, DNS lookup starts with SRV lookups.

Default value is `true`.

Example of usage:
```text

    dns_try_naptr = false

```

### dns_use_search_list

If set to `false`, the search list in `/etc/resolv.conf` is ignored, which means fewer lookups and faster DNS failure handling.

Default value is `true`.

> [!NOTE]
> Even if you do not have a search list defined, setting this option to `false` can still be faster because an empty search list still causes two DNS queries, for example `foo.` and `foo`.

Example of usage:
```text

    dns_use_search_list = false

```

### dst_blacklist

Defines an IP/destination blacklist. These lists can be selected from the script, at runtime, to filter outgoing requests based on IP, protocol, port, etc.

The primary purpose is to prevent sending requests to critical IPs, such as gateways, because of bad DNS entries or to avoid sending requests to destinations known to be unavailable, either temporarily or permanently.

The grammar for specifying a list is:

```text

    dst_blacklist = id [/bl_flags] [: bl_rules]

```

* **id** is a unique identifier of the blacklist.
* **bl_flags** contains a set of optional modifiers:

```text

    bl_flags = bl_flag [, bl_flag]*
    bl_flag = "expire" | "default" | "readonly"

```

* **bl_rules** contains one or more blacklist rules:

```text

    bl_rules = [!] ipnet | { bl_rule [, bl_rule]* }
    bl_rule = [!] ( [bl_proto, ] ipnet [, port [, bl_pattern]] )

```

The blacklist modifiers have the following meanings:
* `expire`: the blacklist may contain entries that expire.
* `default`: the blacklist is used by default when sending requests, without having to explicitly set it using the `use_blacklist()` function.
* `readonly`: the blacklist is statically defined in the script and cannot change at runtime.

When **bl_flags** is missing, the `readonly` flag is explicitly set.

A rule has the following properties:
* if `!` is at the beginning of the rule, it negates the entire rule.
* **bl_proto**: any supported protocol, or `any` for any protocol; if missing, the default is `any`.
* **ipnet**: IP or IP/MASK that should match the rule.
* **port**: port number or `0` for any port.
* **bl_pattern**: filename-like matching, see `man 3 fnmatch`, applied on the outgoing request buffer (`first_line + hdrs + body`).

Example of usage:
```text

    # filter out requests going to IPs of my gateways
    dst_blacklist = gw:{(tcp, 192.168.4.100, 5060, ""), (any, 192.168.4.101, 0, "")}
    # block requests going to "evil" networks
    dst_blacklist = net_filter:{(any, 192.168.1.120/255.255.255.0, 0, "")}
    # block message requests with nasty words
    dst_blacklist = msg_filter:{(any, 192.168.20.0/255.255.255.0, 0, "MESSAGE*ugly_word")}
    # block requests not going to a specific subnet
    dst_blacklist = net_filter2:{!(any, 194.168.30.0/255.255.255.0, 0, "")}
    # define a dynamic list that is built at runtime and has expiring entries
    dst_blacklist = net_dynamic/expire

```

### enable_asserts
Default value is `false`.

Set to `true` to enable the [assert](https://docs.opensips.org/manual/devel/script-corefunctions#assert) script statement.

Example of usage:
```text

    enable_asserts = true

```

### event_pkg_threshold

A number representing the percentage threshold above which the E_CORE_PKG_THRESHOLD event is raised, warning about a low amount of free private memory. It accepts integer values between `0` and `100`.

Default value is `0` (event disabled).

Example of usage:
```text

    event_pkg_threshold = 90

```

### event_shm_threshold

A number representing the percentage threshold above which the E_CORE_SHM_THRESHOLD event is raised, warning about a low amount of free shared memory. It accepts integer values between `0` and `100`.

Default value is `0` (event disabled).

Example of usage:
```text

    event_shm_threshold = 90

```

### exec_dns_threshold

A number representing the maximum number of microseconds a DNS query is expected to take. Anything above the set number triggers a warning message to the logging facility.

Default value is `0` (logging disabled).

Example of usage:
```text

    exec_dns_threshold = 60000

```

### exec_msg_threshold

A number representing the maximum number of microseconds the processing of a SIP message is expected to take. Anything above the set number triggers a warning message to the logging facility. Aside from the message and the processing time, the most time-consuming function calls from the script are also logged.

Default value is `0` (logging disabled).

Example of usage:
```text

    exec_msg_threshold = 60000

```

### include_file

Can be called outside route blocks to load additional routes or blocks, or inside route blocks to load additional script actions. The file path can be relative or absolute. If the path is relative, OpenSIPS first tries to locate it relative to the directory from which OpenSIPS was started. If that fails, it tries the directory of the file that includes it. An error is raised if the file is not found.

Example of usage:
```text

    include_file "proxy_regs.cfg"

```

### import_file

Alias for [include_file](#include_file).

Example of usage:
```text

    import_file "proxy_regs.cfg"

```

### log_event_enabled

Enables the E_CORE_LOG event for every log message generated by OpenSIPS.

Default value is `false`.

Example of usage:
```text

    log_event_enabled = true

```

### log_event_level_filter

Extra log level filtering for the E_CORE_LOG event. This parameter is useful when different verbosity levels are desired between syslog/standard error logs and the logs delivered through E_CORE_LOG.

The `log_event_level_filter` parameter should be used together with the [log_level](#log_level) parameter, with a value lower than `log_level`.

Default value is `0` (no filtering).

Example of usage:
```text

    log_event_level_filter = 3

```

### log_json_buf_size

Size of the buffer used for printing the JSON document corresponding to a log message. This parameter makes sense when the `json` or `json_cee` log formats are used. If the buffer is too small, the log message is truncated.

Default value is `6144` bytes.

Example of usage:
```text

    log_json_buf_size = 8192  # given in bytes

```

### log_level

Sets the logging level, controlling how verbose OpenSIPS should be. Higher values make **OpenSIPS** print more messages.

Default value is `2` (notice level).

Example of usage:
```text

    # print only important messages, such as errors or more critical situations;
    # recommended for running a proxy as a daemon
    log_level = 1

    # print many debug messages; use only during debugging sessions
    log_level = 4

```

Actual values are:
* `-3`: alert level
* `-2`: critical level
* `-1`: error level
* `1`: warning level
* `2`: notice level
* `3`: info level
* `4`: debug level

The value of the `log_level` parameter can also be read and set dynamically using the [log_level](Interface-CoreMI.md#log_level) Core MI function or the [`$log_level`](Script-CoreVar.md#log_level) script variable.

### log_msg_buf_size

Size of the buffer used for printing the log message payload. This is used for printing the `message` field from a JSON document when the `json` or `json_cee` log formats are used, or when the E_CORE_LOG event is raised, if enabled. If the buffer is too small, the log message is truncated.

Default value is `4096` bytes.

Example of usage:
```text

    log_msg_buf_size = 8192  # given in bytes

```

### log_stdout

Controls whether OpenSIPS preserves standard output. This may be useful when trying to extract logs from third-party libraries.

* `false` (default): drop all standard output logs.
* `true`: let all standard output logs pass through.

Default value is `false`.

Example of usage:
```text

    log_stdout = true

```

### log_prefix

A string prefix prepended to all logs produced by OpenSIPS, from both C code and script `xlog()` statements. A non-empty value automatically gets a trailing `:`.

Default value is `""`.

Example of usage:
```text

    log_prefix = "opensips-backup"

```

### max_while_loops

Sets the maximum number of loop iterations allowed within a `while` statement. This protects against infinite loops during configuration script execution.

Default value is `10000`.

Example of usage:
```text

    max_while_loops = 200

```

### maxbuffer

The maximum receive buffer size, in bytes, that OpenSIPS will accept during the auto-probing procedure used to discover the maximum buffer size for receiving UDP messages.

Default value is `262144` bytes.

Example of usage:
```text

    maxbuffer = 65536

```

### mem-group

Defines a group of modules, by name, for separate memory statistics. OpenSIPS provides per-group memory information: number of allocated fragments, amount of used memory and amount of real used memory, including memory manager overhead. This is useful when monitoring memory usage for a specific module or group of modules.

This feature requires running `make generate-mem-stats` and compiling with the `SHM_EXTRA_STATS` variable defined.

Example of usage:
```text

    mem-group = "interest": "core" "tm"
    mem-group = "runtime": "dialog" "usrloc" "tm"

```

For the above example, the generated statistics are named `shmem_group_interest:fragments`, `shmem_group_interest:memory_used` and `shmem_group_interest:real_used`.

Multiple groups can be defined, but they must not have the same name.

To generate statistics for the default group, which includes all modules not included in another group, compile with the `SHM_SHOW_DEFAULT_GROUP` variable defined.

### mem_warming

Only relevant when the `HP_MALLOC` compile flag is enabled. If set to `true`, on each startup, OpenSIPS attempts to restore the memory fragmentation pattern it had before the stop/restart. If no [mem_warming_pattern_file](#mem_warming_pattern_file) from a previous run is found, memory warming is skipped and the memory allocator starts with a large memory chunk, like all other allocators.

Memory warming is useful when dealing with high volumes of traffic, such as thousands of CPS on multi-core machines. The more cores are used, the more useful memory warming becomes, because processes must mutually exclude themselves when chopping up the initial large memory chunk. By performing fragmentation on startup, OpenSIPS also behaves optimally in the first minutes after a restart. Fragmentation usually lasts a few seconds, for example about 5 seconds on an 8GB shared memory pool and 4.1GHz CPU; traffic is not processed during this period.

Default value is `false`.

Example of usage:
```text

    mem_warming = true

```

### mem_warming_percentage

How much of OpenSIPS memory should be fragmented with the pattern of the previous run, upon restart. Used at startup if [mem_warming](#mem_warming) is enabled.

Default value is `75`.

Example of usage:
```text

    mem_warming_percentage = 50

```

### mem_warming_pattern_file

Only relevant if [mem_warming](#mem_warming) is enabled. It contains the memory fragmentation pattern of a previous OpenSIPS run. This file is overwritten during each OpenSIPS shutdown and is used during startup in order to restore service behavior as soon as possible.

Default value is `"CFG_DIR/mem_warming_pattern"`.

Example of usage:
```text

    mem_warming_pattern_file = "/var/tmp/my_memory_pattern"

```

### memdump | mem_dump

Log level used to print memory status information at runtime and shutdown. It must be lower than the value of the [log_level](#log_level) parameter in order for memory information to be logged.

Default value is `14` (`L_DBG + 10`), which effectively disables memory dump logging because it is above the normal debug log level.

Example of usage:
```text

    memdump = 2

```

> [!NOTE]
> Setting [memlog](#memlog--mem_log) also sets `memdump` to the same value. If you want different values for `memlog` and `memdump`, set `memlog` first, then set `memdump`.

### memlog | mem_log

Log level used to print memory debug information. It must be lower than the value of the [log_level](#log_level) parameter in order for memory debug information to be logged.

Default value is `15` (`L_DBG + 11`), which effectively disables memory debug logging because it is above the normal debug log level.

Example of usage:
```text

    memlog = 2

```

> [!NOTE]
> Setting `memlog` automatically sets `memdump` to the same value.

### mcast_loopback

If set to `true`, multicast datagrams are sent over loopback.

Default value is `false`.

Example of usage:
```text

    mcast_loopback = true

```

### mcast_ttl

Sets the multicast TTL.

Default value is OS-specific, usually `1`.

Example of usage:
```text

    mcast_ttl = 32

```

### mhomed

If set to `true`, OpenSIPS tries to locate the outbound interface on multihomed hosts. This lookup is time-consuming, so it is disabled by default.

Default value is `false`.

Example of usage:
```text

    mhomed = true

```

### mpath

Sets the module search path. This can be used to simplify `loadmodule` statements.

Example of usage:
```text

    mpath = "/usr/local/lib/opensips/modules"
    loadmodule "mysql.so"
    loadmodule "uri.so"
    loadmodule "uri_db.so"
    loadmodule "sl.so"
    loadmodule "tm.so"
    ...

```

The parameter can be set multiple times, with paths evaluated in declaration order.

### open_files_limit

If set and greater than the current open file limit, **OpenSIPS** tries to increase its open file limit to this number. **OpenSIPS** must be started as root in order to increase a limit past the hard limit, which is `1024` on most systems for open files.

Default value is `-1` (do not change the open file limit).

Example of usage:
```text

    open_files_limit = 2048

```

### poll_method

The poll method used by the internal I/O reactor. By default, the best method for the current OS is selected.

Available values are `poll`, `epoll`, `sigio_rt`, `select`, `kqueue` and `/dev/poll`.

Example of usage:
```text

    poll_method = select

```

### pv_print_buf_size

The maximum size, in bytes, of an expanded formatted string containing variables or pseudo-variables.

Default value is `20000` bytes.

Example of usage:
```text

    pv_print_buf_size = 60000

```

### query_buffer_size

If set to a value greater than `1`, DB inserts are not flushed one by one. Rows to be inserted are kept in memory until they gather up to `query_buffer_size` rows, and only then are they flushed to the database.

Default value is `0` (buffering disabled).

Example of usage:
```text

    query_buffer_size = 5

```

### query_flush_time

If [query_buffer_size](#query_buffer_size) is set to a value greater than `1`, a timer triggers once every `query_flush_time` seconds, ensuring that no row is kept in memory for too long.

Default value is `0`.

Example of usage:
```text

    query_flush_time = 10

```

### restart_persistency_cache_file

The name of the cache file used to store restart persistency memory.

Default value is `".restart_persistency.cache"`.

Example of usage:
```text

    restart_persistency_cache_file = "/var/tmp/opensips_restart.cache"

```

### restart_persistency_size

The size of the restart persistency cache file, in megabytes. If this parameter is not specified, it defaults to the size of the shared memory.

Default value is the shared memory size, `32` MB by default.

Example of usage:
```text

    restart_persistency_size = 64

```

### rev_dns

Controls whether the SIP server should attempt to look up its own IP address in DNS. If this parameter is set to `true` and the IP address is not in DNS, a warning is printed to syslog and a `received=` field is added to the Via header.

Default value is `false`.

Example of usage:
```text

    rev_dns = true

```

### server_header

The body of the Server header field generated by **OpenSIPS** when it sends a reply as UAS.

Default value is `"Server: OpenSIPS (<version> (<arch>/<os>))"`.

Example of usage:
```text

    server_header = "Server: My Company SIP Proxy"

```

> [!NOTE]
> The value must include the header name, `Server:`. Otherwise, **OpenSIPS** writes only the configured body.

### server_signature

Controls whether the Server header is added to locally generated messages.

Default value is `true`.

Example of usage:
```text

    server_signature = false

```

When enabled, the generated header looks like:
```text

    Server: OpenSIPS (4.0.0 (x86_64/linux))

```

### shm_hash_split_percentage

Only relevant when the `HP_MALLOC` compile flag is enabled. It controls how many memory buckets are optimized. For example, setting it to `2` optimizes the first `2%` of the most frequently used buckets.

Default value is `1`.

Example of usage:
```text

    shm_hash_split_percentage = 2

```

### shm_memlog_size

Configures the maximum number of shared memory operations to keep in the in-memory history. A separate memory block, dedicated to this shared memory debug information, is allocated. As a result, **OpenSIPS** uses more system memory than the configured shared memory pool, set with the `-m` command-line option. For example, `shm_memlog_size = 1000000` uses approximately 750 MB more memory. This option is intended for debugging.

Default value is `0` (disabled).

Example of usage:
```text

    shm_memlog_size = 1000000

```

### shm_secondary_hash_size

Only relevant when the `HP_MALLOC` compile flag is enabled. It represents the optimization factor of a single bucket. For example, setting it to `4` causes optimized buckets to be further split into `4`.

Default value is `8`.

Example of usage:
```text

    shm_secondary_hash_size = 4

```

### sip_warning

If set to `true`, a Warning header is added to each reply generated by **OpenSIPS**. The header contains details that help troubleshooting using network traffic dumps.

Default value is `false`.

Example of usage:
```text

    sip_warning = true

```

### socket

Sets the network addresses/sockets the OpenSIPS server should listen on. Its syntax is `protocol:address[:port|portrange]`, where:
* **protocol**: one of the transport modules loaded in the configuration file, such as `udp`, `tcp`, `tls`, `bin` or `hep`.
* **address**: an IP address, hostname, network interface name or the `*` wildcard, which makes OpenSIPS listen on all possible interfaces for that protocol.
* **port**: optional listening socket port; if absent, the default port exported by the transport module is used.
* **portrange**: optional set of ports that should listen for the same IP address.

This parameter can be set multiple times in the same configuration file, with the server listening on all specified sockets.

The `socket` definition may accept several optional parameters:
* `as ip[:port]`: configure an advertised IP and port only for this interface. Example: `as 11.24.14.14:5060`.
* `use_workers n`: set a different number of workers for this socket only, for UDP, SCTP and HEP_UDP interfaces. This overrides the global `udp_workers` parameter.
* `anycast`: mark the socket as an anycast IP.
* `use_auto_scaling_profile PROFILE`: enforce an auto-scaling profile for this UDP socket. This option is only available for UDP sockets, and the per-socket profile overrides the global UDP auto-scaling profile.
* `tag ID`: set a non-SIP name/tag for the socket, used when replicating socket identity across an OpenSIPS cluster.
* `frag`: do not use PMTU discovery to determine whether fragmentation should be done; always allow fragmentation.
* `reuse_port`: for TCP-based sockets only, allow outgoing TCP connections to reuse the listening port as the source port instead of using an ephemeral port.
* `tos n`: optional TOS value to use when sending SIP traffic through this interface. This overrides the global [tos](#tos) core parameter.
* `accept_subdomain`: also match subdomains of this SIP domain, when the socket is defined as an FQDN.
* `allow_proxy_protocol`: allow receiving Proxy Protocol information.
* `send_proxy_protocol`: provide Proxy Protocol information on outbound UDP messages/connections.
* `proxy_protocol`: both allow receiving Proxy Protocol information and provide it on outbound messages.

These options only affect the sockets they are configured for; if they are not defined for a given socket, the global values are used instead.

Example of usage:
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

On startup, OpenSIPS reports all sockets that it is listening on.

#### socket bond

A bond socket is a special case of [socket](#socket): a collection of regular sockets. When used for outbound routing, the bond socket is automatically evaluated and a matching regular socket, by protocol and address family, is picked for sending. For more details, see this [blog post](https://blog.opensips.org/2026/03/11/bond-sockets-in-opensips-4-0/).

Example of usage:
```text

    # the external interface
    socket = udp:1.2.3.4:5060
    socket = tcp:1.2.3.9:5060
    socket = tls:[2001:db8:1234:5678::1]:5061

    # define the "external" bond socket over all external sockets
    socket = bond:extern {"udp:10.10.0.3:5060", "tcp:10.10.0.5:5060", "tls:[2001:db8:1234:5678::1]:5061"}

```

### stderror_enabled

Enables writing log messages to standard error.

Default value is `true`.

Example of usage:
```text

    stderror_enabled = false

```

### stderror_level_filter

Extra log level filtering for messages written to standard error. This parameter is useful when different verbosity levels are desired for syslog and standard error logging.

The `stderror_level_filter` parameter should be used together with the [log_level](#log_level) parameter, with a value lower than `log_level`.

Default value is `0` (no filtering).

Example of usage:
```text

    stderror_level_filter = 2

```

### syslog_enabled

Enables writing log messages to syslog.

Default value is `false`.

Example of usage:
```text

    syslog_enabled = true

```

### stderror_log_format

Format of the log messages printed to standard error. Possible values are:
* `plain_text`: standard plain-text log message.
* `json`: basic JSON document.
* `json_cee`: JSON document following the [CEE (Common Event Expression)](https://cee.mitre.org/language/1.0-beta1/core-profile.html) schema.

Default value is `plain_text`.

Example of usage:
```text

    stderror_log_format = "json"

```

### syslog_facility

If **OpenSIPS** logs to syslog, this parameter controls the syslog facility. It is useful when diverting all **OpenSIPS** logs to a different log file. See `syslog(3)` for more details.

Default value is `LOG_DAEMON`.

Example of usage:
```text

    syslog_facility = LOG_LOCAL0

```

### syslog_level_filter

Extra log level filtering for messages sent to syslog. This parameter is useful when different verbosity levels are desired for syslog and standard error logging.

The `syslog_level_filter` parameter should be used together with the [log_level](#log_level) parameter, with a value lower than `log_level`.

Default value is `0` (no filtering).

Example of usage:
```text

    syslog_level_filter = 1

```

### syslog_log_format

Format of the log messages sent to syslog. Possible values are:
* `plain_text`: standard plain-text log message.
* `json`: basic JSON document.
* `json_cee`: JSON document following the [CEE (Common Event Expression)](https://cee.mitre.org/language/1.0-beta1/core-profile.html) schema.

Default value is `plain_text`.

Example of usage:
```text

    syslog_log_format = "json"

```

### syslog_name

Sets the identifier printed in syslog. The value must be a string and has effect only when **OpenSIPS** runs in daemon mode, after daemonizing.

Default value is `argv[0]`.

Example of usage:
```text

    syslog_name = "osips-5070"

```

### tcp_workers

Number of worker processes created for reading from TCP connections. These workers handle traffic over any TCP-based protocol, such as SIP-TCP, SIP-TLS, SIP-WS, SIP-WSS, BIN or HEP.

Default value is `8`.

Optionally, you can define an auto-scaling profile to dynamically govern the number of TCP workers by creating or terminating processes depending on load. See [auto_scaling_profile](#auto_scaling_profile) for more details.

Example of usage:
```text

    tcp_workers = 4
    tcp_workers = 3 use_auto_scaling_profile PROFILE_SIP

```

### tcp_threads

Number of TCP I/O threads used by the TCP pool. If this parameter is not set, OpenSIPS uses the number of online CPUs. If the CPU count cannot be detected, it falls back to [tcp_workers](#tcp_workers), or to `1` if no TCP workers are configured.

Default value is `0`, which enables auto-detection.

Example of usage:
```text

    tcp_threads = 4

```

### tcp_accept_aliases

If set to `true`, OpenSIPS enforces RFC 5923 behavior when detecting an `;alias` Via header field parameter, and reuses any TCP, TLS, WS or WSS connection opened for such SIP requests when sending other SIP requests backwards towards the same source IP, Via port and protocol tuple. The purpose of RFC 5923 is to minimize the number of TLS connections a SIP proxy must open, due to the large CPU overhead of connection setup.

Default value is `false`.

On top of RFC 5923 connection reuse, TCP connections in OpenSIPS are also persistent across multiple SIP dialogs. This can be controlled with the [tcp_connection_lifetime](#tcp_connection_lifetime) global parameter.

> [!WARNING]
> Enabling the global `tcp_accept_aliases` parameter for end-user initiated connections, which are most likely grouped by one or more public IPs, is an open vector for call hijacking. In such platforms, use the [force_tcp_alias()](https://docs.opensips.org/manual/devel/script-corefunctions#force_tcp_alias) core function to employ RFC 5923 behavior only with adjacent SIP proxies.

Example of usage:
```text

    tcp_accept_aliases = true

```

### tcp_connect_timeout

Time in milliseconds before an ongoing blocking connection attempt is aborted.

Default value is `100` milliseconds.

Example of usage:
```text

    tcp_connect_timeout = 100

```

### tcp_connection_lifetime

Lifetime in seconds for TCP sessions. TCP sessions inactive for more than `tcp_connection_lifetime` seconds are closed by **OpenSIPS**. Setting this value to `0` closes TCP connections quickly. You can also set the TCP lifetime to the expire value of the REGISTER by using the `tcp_persistent_flag` parameter of the registrar module.

Default value is `120` seconds.

Example of usage:
```text

    tcp_connection_lifetime = 3600

```

### tcp_max_connections

Maximum number of active TCP accepted connections, meaning connections initiated by remote endpoints. Once the limit is reached, new incoming TCP connections are rejected. There is currently no limit for outgoing TCP connections initiated by OpenSIPS.

Default value is `2048`.

Example of usage:
```text

    tcp_max_connections = 4096

```

### tcp_max_msg_time

The maximum number of seconds that a SIP message is expected to take to fully arrive over TCP. If a single SIP packet is still not fully received after this number of seconds, the connection is dropped. This may happen when the connection is overloaded and traffic is highly fragmented, or during attacks that intentionally fragment traffic in order to reduce performance.

Default value is `4` seconds.

Example of usage:
```text

    tcp_max_msg_time = 8

```

### tcp_no_new_conn_bflag

A branch flag used to instruct OpenSIPS not to open a new TCP connection when delivering a request, but only to reuse an existing one, if available. If no existing connection is available, a generic send error is returned.

This is intended for NAT scenarios where opening a TCP connection towards a destination behind NAT makes no sense, for example when the TCP connection created during registration was lost and the device cannot be contacted until it re-registers. It can also be used to detect when a NATed registered user lost its TCP connection, so OpenSIPS can disable that registration as unusable.

Example of usage:
```text

    tcp_no_new_conn_bflag = TCP_NO_CONNECT
    ...
    route {
        ...
        if (isflagset("DST_NATED") && $socket_in(proto) == "TCP")
            setbflag("TCP_NO_CONNECT");
        ...
        t_relay("no-auto-477");
        $var(retcode) = $rc;
        if ($var(retcode) == -6) {
            # send error
            xlog("unable to send request to destination");
            send_reply(404, "Not Found");
            exit;
        } else if ($var(retcode) < 0) {
            sl_reply_error();
            exit;
        }
    }

```

### tcp_no_new_conn_rplflag

A message flag, similar to [tcp_no_new_conn_bflag](#tcp_no_new_conn_bflag), used to prevent OpenSIPS from opening a new TCP connection when sending back a reply for the current request. If no existing connection is available, sending the reply may fail at transport level.

Example of usage:
```text

    tcp_no_new_conn_rplflag = TCP_NO_RPL_CONNECT
    ...
    route {
        ...
        # if source is detected as NATed, prevent opening TCP connections for replies
        if (isflagset("SRC_NATED") && $socket_in(proto) == "TCP")
            setflag("TCP_NO_RPL_CONNECT");
        ...
        t_reply(302, "Redirected");
    }

```

### tcp_socket_backlog

The maximum length to which the queue of pending connections for TCP listening sockets may grow. If a connection request arrives when the queue is full, the client may receive an error such as `ECONNREFUSED`; if the underlying protocol supports retransmission, the request may be ignored so a later connection attempt can succeed.

Default value is `10`.

Example of usage:
```text

    tcp_socket_backlog = 20

```

### tcp_threshold

A number representing the maximum number of microseconds sending a TCP request is expected to take. Anything above the set number triggers a warning message to the logging facility.

Default value is `0` (logging disabled).

Example of usage:
```text

    tcp_threshold = 60000

```

### tcp_keepalive

Enables or disables TCP keepalive at OS level.

Default value is `true` if TCP keepalive is supported by the OS, `false` otherwise.

Example of usage:
```text

    tcp_keepalive = true

```

### tcp_keepcount

Number of keepalive probes to send before closing the connection. This option is available on Linux and other platforms with `TCP_KEEPCNT` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_probes`; a common value is `9`.

Default value is OS-dependent.

Setting `tcp_keepcount` to any value also enables [tcp_keepalive](#tcp_keepalive).

Example of usage:
```text

    tcp_keepcount = 5

```

### tcp_keepidle

Amount of idle time, in seconds, before OpenSIPS starts sending keepalive probes. This option is available on Linux and other platforms with `TCP_KEEPIDLE` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_time`; a common value is `7200` seconds.

Default value is OS-dependent.

Setting `tcp_keepidle` to any value also enables [tcp_keepalive](#tcp_keepalive).

Example of usage:
```text

    tcp_keepidle = 30

```

### tcp_keepinterval

Interval, in seconds, between keepalive probes when the previous probe failed. This option is available on Linux and other platforms with `TCP_KEEPINTVL` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_intvl`; a common value is `75` seconds.

Default value is OS-dependent.

Setting `tcp_keepinterval` to any value also enables [tcp_keepalive](#tcp_keepalive).

Example of usage:
```text

    tcp_keepinterval = 10

```

### timer_workers

The number of worker processes created exclusively for timer-related tasks. The minimum number is `1`.

Default value is `1`.

Optionally, you can define an auto-scaling profile to dynamically govern the number of timer workers by creating or terminating processes depending on load. See [auto_scaling_profile](#auto_scaling_profile) for more details.

Example of usage:
```text

    timer_workers = 3
    timer_workers = 3 use_auto_scaling_profile PROFILE_TIMER

```

### tos

The TOS (Type Of Service) to be used for the sent IP packets, for both TCP and UDP. The default value is `IPTOS_LOWDELAY`. To disable TOS setting, use `0`.

This global value may be overwritten by the per-socket `tos` option of the [socket](#socket) parameter.

Example of usage:

```text
tos = IPTOS_LOWDELAY
tos = 0x10
```

### udp_workers

Number of worker processes to be created for each UDP or SCTP interface. The default value is `8`.

Optionally, you can define an auto-scaling profile to dynamically govern the number of UDP workers by creating or terminating processes depending on load. A per-interface auto-scaling profile overrides this global UDP auto-scaling profile.
See the [auto_scaling_profile](#auto_scaling_profile) parameter for more details.

Example of usage:

```text
udp_workers = 16
udp_workers = 4 use_auto_scaling_profile PROFILE_SIP
```

> [!NOTE]
> This global value applies to all UDP/SCTP interfaces, but it can be overridden by setting a different number of workers in a specific interface definition. This allows defining a different number of workers for each interface; see the [socket](#socket) parameter for syntax.

### user_agent_header

The body of the User-Agent header field generated by **OpenSIPS** when it sends a request as UAC. It defaults to `OpenSIPS (<version> (<arch>/<os>))`.

Example of usage:

```text
user_agent_header = "User-Agent: My Company SIP Proxy"
```

Please note that you have to include the `User-Agent:` header name, as **OpenSIPS** does not add it. Otherwise, you will get an erroneous header like:

```text
My Company SIP Proxy
```

### wdir

The working directory used by **OpenSIPS** at runtime. If not explicitly configured, **OpenSIPS** changes the working directory to `/`.

Example of usage:

```text
wdir = "/usr/local/opensips"
wdir = /usr/opensips_wd
```

### xlog_buf_size

Size of the buffer used to print a single line through the selected **OpenSIPS** logging facility. If the buffer is too small, an overflow error will be printed and the line will be skipped. The default value is `4096` bytes.

Usage example:

```text
xlog_buf_size = 8388608 # given in bytes
```

### xlog_force_color

Enables the use of [$C(xy)](Script-CoreVar.md#foreground-and-background-colors) color escape sequences in [xlog()](https://docs.opensips.org/manual/devel/script-corefunctions#xlog). Otherwise, color escape sequences have no effect. The default value is `false`.

Usage example:

```text
xlog_force_color = true
```

### xlog_level

Similar to [log_level](#log_level), this parameter independently controls the verbosity of the [xlog()](https://docs.opensips.org/manual/devel/script-corefunctions#xlog) functions. This allows you to separately control the verbosity level for logs generated by code and logs generated by `xlog()`. The default value is `2` / `L_NOTICE`.

Usage example:

```text
xlog_level = 3 # L_DBG
```

### xlog_print_level

Default level for printing logs generated by the [xlog()](https://docs.opensips.org/manual/devel/script-corefunctions#xlog) core function when the `log_level` parameter is omitted. The default value is `2` / `L_NOTICE`.

Usage example:

```text
xlog_print_level = 2 # L_NOTICE
```
