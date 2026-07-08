---
title: "Core Parameters"
description: "This section lists all parameters exported by OpenSIPS core for script usage (to be used in opensips.cfg)."
---

This section lists all parameters exported by **OpenSIPS** core for script usage (to be used in opensips.cfg).

* [Core keywords](#core_keywords)
* [Core values](#core_values)
* [Core parameters](#core_parameters)

---


## Core Keywords

Keywords specific to SIP messages which can be used mainly in 'if' expressions.

### af

The address family of the received SIP message. It is INET if the message was received over IPv4 or INET6 if the message was received over IPv6.

Example of usage:

```opensips
if(af==INET6) {
log("Message received over IPv6 link\n");
};
```

### dst_ip

The IP of the local interface where the SIP message was received. When the proxy listens on many network interfaces, makes possible to detect which was the one that received the packet.

Example of usage:

```opensips
if(dst_ip==127.0.0.1) {
log("message received on loopback interface\n");
};
```

### dst_port

The local port where the SIP packet was received. When **OpenSIPS** is listening on many ports, it is useful to learn which was the one that received the SIP packet.

Example of usage:
```opensips
if(dst_port==5061)
{
log("message was received on port 5061\n");
};
```

### from_uri

This script variable is a reference to the URI of 'From' header. It can be used to test 'From'- header URI value.

Example of usage:

```opensips
if(is_method("INVITE") && from_uri=~".*@opensips.org")
{
log("the caller is from opensips.org\n");
};
```

### method

The variable is a reference to the SIP method of the message.

Example of usage:

```opensips
if(method=="REGISTER")
{
log("this SIP request is a REGISTER message\n");
};
```

### msg:len

The variable is a reference to the size of the message. It can be used in 'if' constructs to test message's size.

Example of usage:

```opensips
if(msg:len>2048)
{
sl_send_reply("413", "message too large");
exit;
};
```

### $retcode

It represents the value returned by last function executed (similar to $? from bash -- if you wish, you can use also $? in OpenSIPS config, both names '`$retcode`' and '$?' are supported). If tested after a call of a route, it is the value retuned by that route.

Example of usage:

```opensips
route {
route(1);
if($retcode==1)
{
log("The request is an INVITE\n");
};
}

route[1] {
if(is_method("INVITE"))
return(1);
return(2);
}
```

### proto

This variable can be used to test the transport protocol of the SIP message.

Example of usage:

```opensips
if(proto==UDP)
{
log("SIP message received over UDP\n");
};
```

### status

If used in onreply_route, this variable is a reference to the status code of the reply. If it used in a standard route block, the variable is a reference to the status of the last reply sent out for the current request.

Example of usage:

```opensips
if(status=="200")
{
log("this is a 200 OK reply\n");
};
```

### src_ip

Reference to source IP address of the SIP message.

Example of usage:

```opensips
if(src_ip==127.0.0.1)
{
log("the message was sent from localhost!\n");
};
```

### src_port

Reference to source port of the SIP message (from which port the message was sent by previous hop).

Example of usage:

```opensips
if(src_port==5061)
{
log("message sent from port 5061\n");
}
```

### to_uri

This variable can be used to test the value of URI from To header.

Example of usage:

```opensips
if(to_uri=~"sip:.+@opensips.org")
{
log("this is a request for opensips.org users\n");
};
```

### uri

This variable can be used to test the value of the request URI.

Example of usage:

```opensips
if(uri=~"sip:.+@opensips.org")
{
log("this is a request for opensips.org users\n");
};
```

---

## Core Values

Values that can be used in 'if' expressions to check against Core Keywords

### INET

This keyword can be used to test whether the SIP packet was received over an IPv4 connection.

Example of usage:

```opensips
if(af==INET)
{
log("the SIP message was received over IPv4\n");
};
```

### INET6

This keyword can be used to test whether the SIP packet was received over an IPv6 connection.

Example of usage:

```opensips
if(af==INET6)
{
log("the SIP message was received over IPv6\n");
};
```

### TCP

This keyword can be used to test the value of 'proto' and check whether the SIP packet was received over TCP or not.

Example of usage:

```opensips
if(proto==TCP)
{
log("the SIP message was received over TCP\n");
};
```

### UDP

This keyword can be used to test the value of 'proto' and check whether the SIP packet was received over UDP or not.

Example of usage:

```opensips
if(proto==UDP)
{
log("the SIP message was received over UDP\n");
};
```

### max_len

This keyword is set to the maximum size of an UDP packet. It can be used to test message's size.

Example of usage:

```opensips
if(msg:len>max_len)
{
sl_send_reply("413", "message too large to be forwarded over UDP without fragmentation");
exit;
}
```

### myself

It is a reference to the list of local IP addresses, hostnames and aliases that has been set in **OpenSIPS** configuration file. This lists contain the domains served by **OpenSIPS**.

The variable can be used to test if the host part of an URI is in the list. The usefulness of this test is to select the messages that has to be processed locally or has to be forwarded to another server.

See "alias" to add hostnames,IP addresses and aliases to the list.

Example of usage:

```opensips
if(uri==myself) {
log("the request is for local processing\n");
};
```

### null

Can be used in assignment to reset the value of a per-script variable or to delete an avp.

Example of usage:

```opensips
$avp(i:12) = null;
$var(x) = null;
```

---

## Core parameters

Global parameters available in the *opensips.cfg* configuration file. Accepted values depend on the parameter type: double-quoted strings, numbers or booleans (`true`/`false`).

### abort_on_assert
Default value is `false`.


Only relevant if [asserts](https://docs.opensips.org/manual/2-3/script-corefunctions#assert) are enabled. Set to `true` to make OpenSIPS shut down immediately when a script assert fails.


Example of usage:
```opensips

    abort_on_assert = true

```

### advertised_address

This can be an IP address or string and represents the address advertised in the Via header and other destination lumps, such as Record-Route headers. If empty or not set, the listener address used to send the request is advertised.

> [!WARNING]
> Do not set this unless you know what you are doing, for example when handling NAT traversal.
> OpenSIPS does not validate this value; for example, `foo.bar` is accepted even if it does not exist.

Example of usage:
```opensips

    advertised_address = "opensips.org"

```

> [!NOTE]
> Besides this global approach, you can also define an advertised IP and port per interface using the [listen](#listen) parameter. Per-interface advertised values are used only for traffic leaving that interface.


### advertised_port

The port advertised in the Via header and other destination lumps, such as Record-Route headers. If empty or not set, the port used to send the message is advertised. The same warnings as for [advertised_address](#advertised_address) apply.

Example of usage:
```opensips

    advertised_port = 5080

```

> [!NOTE]
> Besides this global approach, you can also define an advertised IP and port per interface using the [listen](#listen) parameter. Per-interface advertised values are used only for traffic leaving that interface.


### alias

Sets alias hostnames for the server. It can be set multiple times, with each value added to the list used to match the hostname when `myself` is checked.

If the `:port` part is omitted, **all** ports of the given hostname are considered aliases, similar to port `0`.

> [!IMPORTANT]
> It is necessary to include the port used in the `listen` definitions in the alias definition otherwise the `loose_route()` function will not work as expected for local forwards!


Example of usage:

```opensips

    alias = udp:other.domain.com:5060
    alias = tcp:another.domain.com:5060

```

### auto_aliases

This parameter controls whether aliases should be automatically discovered and added while fixing listening interfaces. The auto-discovered aliases are the result of a DNS lookup when a [listen](#listen) definition uses a hostname, or of a reverse DNS lookup on the listener IP.

For backwards compatibility, the default value is `true`.

Example of usage:
```opensips

    auto_aliases = false

```

### bin_listen

> [!WARNING]
> Removed in OpenSIPS 2.3


Replaced by the [bin_port](../../modules/proto_bin/README.md#id284096) module parameter from **proto_bin** module (as a result of migrating the BIN implementation from core into a separate module).

### bin_children

> [!WARNING]
> Removed in OpenSIPS 2.3


Obsolete, simply removed.

### cfg_file
Returns the name of the corresponding OpenSIPS config file, useful when multiple config files are included.

### cfg_line
Returns the corresponding line inside the OpenSIPS config file.


### check_via

Checks whether the address in the topmost Via header of replies is local. Default value is `false` (check disabled).

Example of usage:

```opensips

    check_via = true

```

### children

Number of child processes to be created for each UDP or SCTP interface.

Default value is `8`.

Example of usage:
```opensips

    children = 16

```

> [!NOTE]
> This global value applies to all UDP/SCTP interfaces, but it can be overridden by setting a different number of children in a specific interface definition. This allows defining a different number of children for each interface; see the [listen](#listen) parameter for syntax.

### chroot

The value must be a valid path in the system. If set, **OpenSIPS** will chroot, changing its root directory to this path.

Example of usage:

```opensips

    chroot = "/other/fakeroot"

```

### debug_mode
Enabling **debug_mode** is a fast way to debug **OpenSIPS**. This option automatically forces:
* foreground mode (do not detach from the console)
* logging level 4 (debug)
* logging to standard error
* core dumping
* UDP child processes to 2, if UDP is enabled
* TCP child processes to 2, capped by the configured `tcp_children` value, if TCP is enabled

Default value is `false` (disabled).

> [!NOTE]
> Enabling this option overrides individual parameters such as foreground mode, log level and `children`.

This parameter was introduced as a replacement for the old [fork](#fork) option.

Example of usage:
```opensips

    debug_mode = true

```


### db_version_table

The name of the database table used by the DB API to check table versions.

Default value is `"version"`.

Example of usage:
```opensips

    db_version_table = "version_2_3"

```

### db_default_url

The default DB URL used by modules when no per-module URL is configured.

Default value is `NULL` (not defined).

Example of usage:
```opensips

    db_default_url = "mysql://opensips:opensipsrw@localhost/opensips"

```

### db_max_async_connections

Maximum number of TCP connections opened from a single OpenSIPS child to each individual SQL backend.

Default value is `10`.

Individual backends are determined from DB URLs as follows:
```opensips

    [ scheme, user, pass, host, port, database ]

```

Example of usage:
```opensips

    db_max_async_connections = 220

```

### debug

> [!WARNING]
> Removed in OpenSIPS 2.3


Replaced by [log_level](#log_level) parameter.

### disable_503_translation

If set to `true`, OpenSIPS will not translate received 503 replies into 500 replies. RFC 3261 states that a proxy should never relay a 503 response, but transform it into a 500 response instead.

Default value is `false` (translation enabled).

Example of usage:
```opensips

    disable_503_translation = true

```

### disable_core_dump

If set to `true`, OpenSIPS disables core dumps by setting the core dump size limit to 0. By default, core dump limits are set to unlimited or to a high enough value.

Default value is `false`.

Example of usage:
```opensips

    disable_core_dump = true

```

### disable_dns_blacklist

When DNS failover is configured, the DNS resolver can temporarily blacklist failed destinations. This prevents **OpenSIPS**, for a limited time, from sending requests to destinations known to have failed. The blacklist acts as a memory for the DNS resolver.

The temporary blacklist created by the DNS resolver is named `dns` and is selected by default for failover usage, so there is no need to call `use_blacklist()` for it. The rules in this list have a lifetime of 4 minutes; this can be changed at compile time in `resolve.c`.

If set to `true`, this DNS blacklist is disabled.

Default value is `true` (DNS blacklist disabled).

Example of usage:
```opensips

    disable_dns_blacklist = false

```

### disable_dns_failover

If set to `true`, OpenSIPS disables DNS-based failover. This is a global option, affecting both the core and the modules.

Default value is `false` (DNS-based failover enabled).

Example of usage:
```opensips

    disable_dns_failover = true

```

### disable_stateless_fwd

Controls the handling of stateless replies:

```opensips

    true  - drop stateless replies if stateless forwarding functions, such as forward(), are not used in the script
    false - forward stateless replies

```

Default value is `true`.

Example of usage:
```opensips

    disable_stateless_fwd = false

```

### dns

This parameter controls whether the SIP server should attempt to look up its own domain name in DNS. If this parameter is set to `true` and the domain name is not in DNS, a warning is printed to syslog and a `received=` field is added to the Via header.

Default value is `false`.

Example of usage:
```opensips

    dns = true

```

### dns_retr_time

Time in seconds before retrying a DNS request. By default, this value is system-specific and also depends on the `/etc/resolv.conf` content, usually `5` seconds.

Example of usage:
```opensips

    dns_retr_time = 3

```

### dns_retr_no

Number of DNS retransmissions before giving up. By default, this value is system-specific and also depends on the `/etc/resolv.conf` content, usually `4`.

Example of usage:
```opensips

    dns_retr_no = 3

```

### dns_servers_no

How many DNS servers from `/etc/resolv.conf` will be used.

By default, all DNS servers are used.

Example of usage:
```opensips

    dns_servers_no = 2

```

### dns_try_ipv6

If set to `true` and a DNS lookup fails, OpenSIPS retries the lookup for IPv6 using an AAAA record.

Default value is `false`.

Example of usage:
```opensips

    dns_try_ipv6 = true

```

### dns_try_naptr

Controls whether NAPTR lookups are performed when doing DNS-based routing for SIP requests. If disabled, DNS lookup starts with SRV lookups.

Default value is `true`.

Example of usage:
```opensips

    dns_try_naptr = false

```

### dns_use_search_list

If set to `false`, the search list in `/etc/resolv.conf` is ignored, which means fewer lookups and faster DNS failure handling.

Default value is `true`.

> [!NOTE]
> Even if you do not have a search list defined, setting this option to `false` can still be faster because an empty search list still causes two DNS queries, for example `foo.` and `foo`.

Example of usage:
```opensips

    dns_use_search_list = false

```

### dst_blacklist

Defines an IP/destination blacklist. These lists can be selected from the script, at runtime, to filter outgoing requests based on IP, protocol, port, etc.

The primary purpose is to prevent sending requests to critical IPs, such as gateways, because of bad DNS entries or to avoid sending requests to destinations known to be unavailable, either temporarily or permanently.

The grammar for specifying a list is:

```opensips

    dst_blacklist = id [/bl_flags] [: bl_rules]

```

* **id** is a unique identifier of the blacklist.
* **bl_flags** contains a set of optional modifiers:

```opensips

    bl_flags = bl_flag [, bl_flag]*
    bl_flag = "expire" | "default" | "readonly"

```

* **bl_rules** contains one or more blacklist rules:

```opensips

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
```opensips

    # filter out requests going to IPs of my gateways
    dst_blacklist = gw:{(tcp, 192.168.3.100, 5060, ""), (any, 192.168.3.101, 0, "")}
    # block requests going to "evil" networks
    dst_blacklist = net_filter:{(any, 192.168.1.120/255.255.255.0, 0, "")}
    # block message requests with nasty words
    dst_blacklist = msg_filter:{(any, 192.168.20.0/255.255.255.0, 0, "MESSAGE*ugly_word")}
    # block requests not going to a specific subnet
    dst_blacklist = net_filter2:{!(any, 193.168.30.0/255.255.255.0, 0, "")}
    # define a dynamic list that is built at runtime and has expiring entries
    dst_blacklist = net_dynamic/expire

```

### enable_asserts
Default value is `false`.

Set to `true` to enable the [assert](https://docs.opensips.org/manual/2-3/script-corefunctions#assert) script statement.


Example of usage:
```opensips

    enable_asserts = true

```

### event_pkg_threshold

A number representing the percentage threshold above which the E_CORE_PKG_THRESHOLD event is raised, warning about a low amount of free private memory. It accepts integer values between `0` and `100`.

Default value is `0` (event disabled).

Example of usage:
```opensips

    event_pkg_threshold = 90

```

### event_shm_threshold

A number representing the percentage threshold above which the E_CORE_SHM_THRESHOLD event is raised, warning about a low amount of free shared memory. It accepts integer values between `0` and `100`.

Default value is `0` (event disabled).

Example of usage:
```opensips

    event_shm_threshold = 90

```

### exec_dns_threshold

A number representing the maximum number of microseconds a DNS query is expected to take. Anything above the set number triggers a warning message to the logging facility.

Default value is `0` (logging disabled).

Example of usage:
```opensips

    exec_dns_threshold = 60000

```

### exec_msg_threshold

A number representing the maximum number of microseconds the processing of a SIP message is expected to take. Anything above the set number triggers a warning message to the logging facility. Aside from the message and the processing time, the most time-consuming function calls from the script are also logged.

Default value is `0` (logging disabled).

Example of usage:
```opensips

    exec_msg_threshold = 60000

```

### fork

> [!WARNING]
> Removed in OpenSIPS 2.3


Replaced by [debug_mode](#debug_mode) parameter.

### group gid

> [!WARNING]
> Removed in OpenSIPS 2.3


Use the **-u** command line parameter instead.

### include_file

Can be called outside route blocks to load additional routes or blocks, or inside route blocks to load additional script actions. The file path can be relative or absolute. If the path is relative, OpenSIPS first tries to locate it relative to the directory from which OpenSIPS was started. If that fails, it tries the directory of the file that includes it. An error is raised if the file is not found.


Example of usage:
```opensips

    include_file "proxy_regs.cfg"

```

### import_file

Alias for [include_file](#include_file).


Example of usage:
```opensips

    import_file "proxy_regs.cfg"

```

### listen

Sets the network addresses/listeners the OpenSIPS server should listen on. Its syntax is `protocol:address[:port]`, where:
* **protocol**: one of the transport modules loaded in the configuration file, such as `udp`, `tcp`, `tls`, `bin` or `hep`.
* **address**: an IP address, hostname, network interface name or the `*` wildcard, which makes OpenSIPS listen on all possible interfaces for that protocol.
* **port**: optional listener port; if absent, the default port exported by the transport module is used.

This parameter can be set multiple times in the same configuration file, with the server listening on all specified interfaces.

The `listen` definition may accept several optional parameters:
* `as ip[:port]`: configure an advertised IP and port only for this interface. Example: `as 11.24.14.14:5060`.
* `use_children n`: set a different number of children for this interface only, for UDP, SCTP and HEP_UDP interfaces. This overrides the global [children](#children) parameter.

These options only affect the interfaces they are configured for; if they are not defined for a given interface, the global values are used instead.


These options only affect the interfaces they are configured for; if they are not defined for a given interface, the global values are used instead.


Example of usage:
```opensips

    listen = udp:*
    listen = udp:eth1
    listen = tcp:eth1:5062
    listen = tls:localhost:5061
    listen = hep_udp:10.10.10.10:5064
    listen = ws:127.0.0.1:5060 use_children 5
    listen = sctp:127.0.0.1:5060 as 99.88.44.33:5060 use_children 3


```

On startup, OpenSIPS reports all interfaces that it is listening on. The TCP engine processes are created even if only UDP interfaces are specified.


### log_facility

If **OpenSIPS** logs to syslog, this parameter controls the syslog facility. It is useful when diverting all **OpenSIPS** logs to a different log file. See `syslog(3)` for more details.

Default value is `LOG_DAEMON`.


Example of usage:
```opensips

    log_facility = LOG_LOCAL0

```

### log_level

Sets the logging level, controlling how verbose OpenSIPS should be. Higher values make **OpenSIPS** print more messages.


Default value is `2` (notice level).

Example of usage:
```opensips

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

The `log_level` parameter is usually used together with [log_stderror](#log_stderror).

The value of the `log_level` parameter can also be read and set dynamically using the [log_level](Interface-CoreMI.md#log_level) Core MI function or the [`$log_level`](Script-CoreVar.md#opensips_log_level) script variable.


### log_name

Sets the identifier printed in syslog. The value must be a string and has effect only when **OpenSIPS** runs in daemon mode, after daemonizing.

Default value is `argv[0]`.

Example of usage:
```opensips

    log_name = "osips-5070"

```

### log_stderror

Controls whether **OpenSIPS** writes log messages to standard error.

* `false` (default): write messages to syslog.
* `true`: write messages to standard error.

Default value is `false`.

Example of usage:
```opensips

    log_stderror = true

```

### max_while_loops

Sets the maximum number of loop iterations allowed within a `while` statement. This protects against infinite loops during configuration script execution.

Default value is `10000`.

Example of usage:
```opensips

    max_while_loops = 200

```

### maxbuffer

The maximum receive buffer size, in bytes, that OpenSIPS will accept during the auto-probing procedure used to discover the maximum buffer size for receiving UDP messages.

Default value is `262144` bytes.

Example of usage:
```opensips

    maxbuffer = 65536

```

### mem-group

Defines a group of modules, by name, for separate memory statistics. OpenSIPS provides per-group memory information: number of allocated fragments, amount of used memory and amount of real used memory, including memory manager overhead. This is useful when monitoring memory usage for a specific module or group of modules.

This feature requires running `make generate-mem-stats` and compiling with the `SHM_EXTRA_STATS` variable defined.

Example of usage:
```opensips

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
```opensips

    mem_warming = true

```

### mem_warming_percentage

How much of OpenSIPS memory should be fragmented with the pattern of the previous run, upon restart. Used at startup if [mem_warming](#mem_warming) is enabled.

Default value is `75`.


Example of usage:
```opensips

    mem_warming_percentage = 50

```

### mem_warming_pattern_file

Only relevant if [mem_warming](#mem_warming) is enabled. It contains the memory fragmentation pattern of a previous OpenSIPS run. This file is overwritten during each OpenSIPS shutdown and is used during startup in order to restore service behavior as soon as possible.

Default value is `"CFG_DIR/mem_warming_pattern"`.

Example of usage:
```opensips

    mem_warming_pattern_file = "/var/tmp/my_memory_pattern"

```

### memdump | mem_dump

Log level used to print memory status information at runtime and shutdown. It must be lower than the value of the [log_level](#log_level) parameter in order for memory information to be logged.

Default value is `14` (`L_DBG + 10`), which effectively disables memory dump logging because it is above the normal debug log level.

Example of usage:
```opensips

    memdump = 2

```

> [!NOTE]
> Setting [memlog](#memlog--mem_log) also sets `memdump` to the same value. If you want different values for `memlog` and `memdump`, set `memlog` first, then set `memdump`.

### memlog | mem_log

Log level used to print memory debug information. It must be lower than the value of the [log_level](#log_level) parameter in order for memory debug information to be logged.

Default value is `15` (`L_DBG + 11`), which effectively disables memory debug logging because it is above the normal debug log level.

Example of usage:
```opensips

    memlog = 2

```

> [!NOTE]
> Setting `memlog` automatically sets `memdump` to the same value.

### mcast_loopback

If set to `true`, multicast datagrams are sent over loopback.

Default value is `false`.

Example of usage:
```opensips

    mcast_loopback = true

```

### mcast_ttl

Sets the multicast TTL.

Default value is `OS-specific`, usually `1`.

Example of usage:
```opensips

    mcast_ttl = 32

```

### mhomed

If set to `true`, OpenSIPS tries to locate the outbound interface on multihomed hosts. This lookup is time-consuming, so it is disabled by default.

Default value is `false`.

Example of usage:
```opensips

    mhomed = true

```

### mpath

Sets the module search path. This can be used to simplify `loadmodule` statements.

Example of usage:
```opensips

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
```opensips

    open_files_limit = 2048

```

### poll_method

The poll method used by the internal I/O reactor. By default, the best method for the current OS is selected.

Available values are `poll`, `epoll_lt`, `sigio_rt`, `select`, `kqueue` and `/dev/poll`.

> [!IMPORTANT]
> Starting with version 2.2, `epoll_et` is deprecated and if it is used in the script, it will be automatically replaced by `epoll_lt`.


Example of usage:
```opensips

    poll_method = select

```


### query_buffer_size

If set to a value greater than `1`, DB inserts are not flushed one by one. Rows to be inserted are kept in memory until they gather up to `query_buffer_size` rows, and only then are they flushed to the database.

Default value is `0` (buffering disabled).

Example of usage:
```opensips

    query_buffer_size = 5

```

### query_flush_time

If [query_buffer_size](#query_buffer_size) is set to a value greater than `1`, a timer triggers once every `query_flush_time` seconds, ensuring that no row is kept in memory for too long.

Default value is `0`.

Example of usage:
```opensips

    query_flush_time = 10

```


### rev_dns

Controls whether the SIP server should attempt to look up its own IP address in DNS. If this parameter is set to `true` and the IP address is not in DNS, a warning is printed to syslog and a `received=` field is added to the Via header.

Default value is `false`.

Example of usage:
```opensips

    rev_dns = true

```

### server_header

The body of the Server header field generated by **OpenSIPS** when it sends a reply as UAS.

Default value is `"Server: OpenSIPS (<version> (<arch>/<os>))"`.

Example of usage:
```opensips

    server_header = "Server: My Company SIP Proxy"

```

> [!NOTE]
> The value must include the header name, `Server:`. Otherwise, **OpenSIPS** writes only the configured body.

### server_signature

Controls whether the Server header is added to locally generated messages.

Default value is `true`.

Example of usage:
```opensips

    server_signature = false

```

When enabled, the generated header looks like:
```opensips

    Server: OpenSIPS (4.0.0 (x86_64/linux))

```

### shm_hash_split_percentage

Only relevant when the `HP_MALLOC` compile flag is enabled. It controls how many memory buckets are optimized. For example, setting it to `2` optimizes the first `2%` of the most frequently used buckets.

Default value is `1`.

Example of usage:
```opensips

    shm_hash_split_percentage = 2

```


### shm_secondary_hash_size

Only relevant when the `HP_MALLOC` compile flag is enabled. It represents the optimization factor of a single bucket. For example, setting it to `4` causes optimized buckets to be further split into `4`.

Default value is `8`.

Example of usage:
```opensips

    shm_secondary_hash_size = 4

```

### sip_warning

If set to `true`, a Warning header is added to each reply generated by **OpenSIPS**. The header contains details that help troubleshooting using network traffic dumps.

Default value is `false`.

Example of usage:
```opensips

    sip_warning = true

```

### tcp_children

Number of child processes created for reading from TCP connections. If no value is explicitly set, the same number of TCP children as UDP children, set through the [children](#children) parameter, is used.


Example of usage:
```opensips

    tcp_children = 4

```

### tcp_accept_aliases

If set to `true`, OpenSIPS enforces RFC 5923 behavior when detecting an `;alias` Via header field parameter, and reuses any TCP, TLS, WS or WSS connection opened for such SIP requests when sending other SIP requests backwards towards the same source IP, Via port and protocol tuple. The purpose of RFC 5923 is to minimize the number of TLS connections a SIP proxy must open, due to the large CPU overhead of connection setup.

Default value is `false`.

On top of RFC 5923 connection reuse, TCP connections in OpenSIPS are also persistent across multiple SIP dialogs. This can be controlled with the [tcp_connection_lifetime](#tcp_connection_lifetime) global parameter.

> [!WARNING]
> Enabling the global `tcp_accept_aliases` parameter for end-user initiated connections, which are most likely grouped by one or more public IPs, is an open vector for call hijacking. In such platforms, use the [force_tcp_alias()](https://docs.opensips.org/manual/2-3/script-corefunctions#force_tcp_alias) core function to employ RFC 5923 behavior only with adjacent SIP proxies.

Example of usage:
```opensips

    tcp_accept_aliases = true

```

### tcp_listen_backlog

The maximum length to which the queue of pending connections for TCP listeners may grow. If a connection request arrives when the queue is full, the client may receive an error such as `ECONNREFUSED`; if the underlying protocol supports retransmission, the request may be ignored so a later connection attempt can succeed.

Default value is `10`.

Example of usage:
```opensips

    tcp_listen_backlog = 20

```

### tcp_connect_timeout

Time in milliseconds before an ongoing blocking connection attempt is aborted.

Default value is `100` milliseconds.

Example of usage:
```opensips

    tcp_connect_timeout = 100

```

### tcp_connection_lifetime

Lifetime in seconds for TCP sessions. TCP sessions inactive for more than `tcp_connection_lifetime` seconds are closed by **OpenSIPS**. Setting this value to `0` closes TCP connections quickly. You can also set the TCP lifetime to the expire value of the REGISTER by using the `tcp_persistent_flag` parameter of the registrar module.

Default value is `120` seconds.

Example of usage:
```opensips

    tcp_connection_lifetime = 3600

```

### tcp_max_connections

Maximum number of active TCP accepted connections, meaning connections initiated by remote endpoints. Once the limit is reached, new incoming TCP connections are rejected. There is currently no limit for outgoing TCP connections initiated by OpenSIPS.

Default value is `2048`.

Example of usage:
```opensips

    tcp_max_connections = 4096

```

### tcp_max_msg_time

The maximum number of seconds that a SIP message is expected to take to fully arrive over TCP. If a single SIP packet is still not fully received after this number of seconds, the connection is dropped. This may happen when the connection is overloaded and traffic is highly fragmented, or during attacks that intentionally fragment traffic in order to reduce performance.

Default value is `4` seconds.

Example of usage:
```opensips

    tcp_max_msg_time = 8

```

### tcp_no_new_conn_bflag

A branch flag used to instruct OpenSIPS not to open a new TCP connection when delivering a request, but only to reuse an existing one, if available. If no existing connection is available, a generic send error is returned.

This is intended for NAT scenarios where opening a TCP connection towards a destination behind NAT makes no sense, for example when the TCP connection created during registration was lost and the device cannot be contacted until it re-registers. It can also be used to detect when a NATed registered user lost its TCP connection, so OpenSIPS can disable that registration as unusable.

Example of usage:
```opensips

    tcp_no_new_conn_bflag = TCP_NO_CONNECT
    ...
    route {
        ...
        if (isflagset(DST_NATED) && $socket_in(proto) == "TCP")
            setbflag(TCP_NO_CONNECT);
        ...
        t_relay("no-auto-477");
        $var(retcode) = $rc;
        if ($var(retcode) == -6) {
            # send error
            xlog("unable to send request to destination");
            send_reply("404", "Not Found");
            exit;
        } else if ($var(retcode) < 0) {
            sl_reply_error();
            exit;
        }
    }

```

### tcp_threshold

A number representing the maximum number of microseconds sending a TCP request is expected to take. Anything above the set number triggers a warning message to the logging facility.

Default value is `0` (logging disabled).

Example of usage:
```opensips

    tcp_threshold = 60000

```

### tcp_keepalive

Enables or disables TCP keepalive at OS level.

Default value is `true` if TCP keepalive is supported by the OS, `false` otherwise.

Example of usage:
```opensips

    tcp_keepalive = true

```

### tcp_keepcount

Number of keepalive probes to send before closing the connection. This option is available on Linux and other platforms with `TCP_KEEPCNT` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_probes`; a common value is `9`.

Default value is `OS-dependent`.

Setting `tcp_keepcount` to any value also enables [tcp_keepalive](#tcp_keepalive).


Example of usage:
```opensips

    tcp_keepcount = 5

```

### tcp_keepidle

Amount of idle time, in seconds, before OpenSIPS starts sending keepalive probes. This option is available on Linux and other platforms with `TCP_KEEPIDLE` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_time`; a common value is `7200` seconds.

Default value is `OS-dependent`.

Setting `tcp_keepidle` to any value also enables [tcp_keepalive](#tcp_keepalive).


Example of usage:
```opensips

    tcp_keepidle = 30

```

### tcp_keepinterval

Interval, in seconds, between keepalive probes when the previous probe failed. This option is available on Linux and other platforms with `TCP_KEEPINTVL` support. The OS default can usually be found using `cat /proc/sys/net/ipv4/tcp_keepalive_intvl`; a common value is `75` seconds.

Default value is `OS-dependent`.

Setting `tcp_keepinterval` to any value also enables [tcp_keepalive](#tcp_keepalive).

Example of usage:
```opensips

    tcp_keepinterval = 10

```

### tls_ca_list

### tls_certificate

### tls_ciphers_list

### tls_domain

### tls_handshake_timeout

### tls_log

### tls_method

### tls_port_no

### tls_private_key

### tls_require_certificate

### tls_send_timeout

### tls_verify

### tos

The TOS (Type Of Service) to be used for the sent IP packets, for both TCP and UDP. The default value is `IPTOS_LOWDELAY`. To disable TOS setting, use `0`.

Example of usage:
```opensips

    tos = IPTOS_LOWDELAY
    tos = 0x10

```

### user uid

> [!WARNING]
> Removed in OpenSIPS 2.3.

Replaced by the script variable `$socket_in(proto)`.

> [!TIP]
> More information is available on the [OpenSIPS 2.2 to 2.3 migration page](https://www.opensips.org/Documentation/Migration-2-2-0-to-2-3-0#toc3).


### user_agent_header

The body of the User-Agent header field generated by **OpenSIPS** when it sends a request as UAC. It defaults to `OpenSIPS (<version> (<arch>/<os>))`.

Example of usage:
```opensips

    user_agent_header = "User-Agent: My Company SIP Proxy"

```

Please note that you have to include the `User-Agent:` header name, as **OpenSIPS** does not add it. Otherwise, you will get an erroneous header like:

```opensips
My Company SIP Proxy
```

### wdir

The working directory used by **OpenSIPS** at runtime. If not explicitly configured, **OpenSIPS** changes the working directory to `/`.

Example of usage:
```opensips

    wdir = "/usr/local/opensips"
    wdir = /usr/opensips_wd

```

### xlog_buf_size

Size of the buffer used to print a single line through the selected **OpenSIPS** logging facility. If the buffer is too small, an overflow error will be printed and the line will be skipped. The default value is `4096` bytes.

Example of usage:
```opensips

    xlog_buf_size = 8388608 # given in bytes

```

### xlog_force_color

Enables the use of [$C(xy)](Script-CoreVar.md#foreground-and-background-colors) color escape sequences in [xlog()](https://docs.opensips.org/manual/2-3/script-corefunctions#xlog). Otherwise, color escape sequences have no effect. The default value is `false`.


Example of usage:

```opensips

    xlog_force_color = true

```

### xlog_default_level

Default level for printing logs generated by the [xlog()](https://docs.opensips.org/manual/2-3/script-corefunctions#xlog) core function when the `log_level` parameter is omitted. The default value is `-1` / `L_ERR`.

Example of usage:
```opensips

    xlog_default_level = 2 # L_NOTICE

```
