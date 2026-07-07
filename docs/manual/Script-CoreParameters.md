---
title: "Core Parameters"
description: "This section lists the all the parameters exported by OpenSIPS core for script usage (to be used in opensips.cfg)"
---

This section lists the all the parameters exported by **OpenSIPS** core for script usage (to be used in opensips.cfg)

* [Core keywords](#core_keywords)
* [Core values](#core_values)
* [Core parameters](#core_parameters)

---

## Core Keywords

Keywords specific to SIP messages which can be used mainly in 'if' expressions.

### af

The address family of the received SIP message. It is INET if the message was received over IPv4 or INET6 if the message was received over IPv6.

Exampe of usage:

```text
if(af==INET6) {
log("Message received over IPv6 link\n");
};
```

### dst_ip

The IP of the local interface where the SIP message was received. When the proxy listens on many network interfaces, makes possible to detect which was the one that received the packet.

Example of usage:

```text
if(dst_ip==127.0.0.1) {
log("message received on loopback interface\n");
};
```

### dst_port

The local port where the SIP packet was received. When **OpenSIPS** is listening on many ports, it is useful to learn which was the one that received the SIP packet.

Example of usage:
```text
if(dst_port==5061)
{
log("message was received on port 5061\n");
};
```

### from_uri

This script variable is a reference to the URI of 'From' header. It can be used to test 'From'- header URI value.

Example of usage:

```text
if(is_method("INVITE") && from_uri=~".*@opensips.org")
{
log("the caller is from opensips.org\n");
};
```

### method

The variable is a reference to the SIP method of the message.

Example of usage:

```text
if(method=="REGISTER")
{
log("this SIP request is a REGISTER message\n");
};
```

### msg:len

The variable is a reference to the size of the message. It can be used in 'if' constructs to test message's size.

Example of usage:

```text
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

```text
if(proto==UDP)
{
log("SIP message received over UDP\n");
};
```

### status

If used in onreply_route, this variable is a reference to the status code of the reply. If it used in a standard route block, the variable is a reference to the status of the last reply sent out for the current request.

Example of usage:

```text
if(status=="200")
{
log("this is a 200 OK reply\n");
};
```

### src_ip

Reference to source IP address of the SIP message.

Example of usage:

```text
if(src_ip==127.0.0.1)
{
log("the message was sent from localhost!\n");
};
```

### src_port

Reference to source port of the SIP message (from which port the message was sent by previous hop).

Example of usage:

```text
if(src_port==5061)
{
log("message sent from port 5061\n");
}
```

### to_uri

This variable can be used to test the value of URI from To header.

Example of usage:

```text
if(to_uri=~"sip:.+@opensips.org")
{
log("this is a request for opensips.org users\n");
};
```

### uri

This variable can be used to test the value of the request URI.

Example of usage:

```text
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

```text
if(af==INET)
{
log("the SIP message was received over IPv4\n");
};
```

### INET6

This keyword can be used to test whether the SIP packet was received over an IPv6 connection.

Example of usage:

```text
if(af==INET6)
{
log("the SIP message was received over IPv6\n");
};
```

### TCP

This keyword can be used to test the value of 'proto' and check whether the SIP packet was received over TCP or not.

Example of usage:

```text
if(proto==TCP)
{
log("the SIP message was received over TCP\n");
};
```

### UDP

This keyword can be used to test the value of 'proto' and check whether the SIP packet was received over UDP or not.

Example of usage:

```text
if(proto==UDP)
{
log("the SIP message was received over UDP\n");
};
```

### max_len

This keyword is set to the maximum size of an UDP packet. It can be used to test message's size.

Example of usage:

```text
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

```text
if(uri==myself) {
log("the request is for local processing\n");
};
```

### null

Can be used in assignment to reset the value of a per-script variable or to delete an avp.

Example of usage:

```text
$avp(i:12) = null;
$var(x) = null;
```

---

## Core parameters

Global parameters that can be set in configuration file. Accepted values are, depending on the actual parameters strings, numbers and yes/ no. If you need to specify either "yes" or "no" as part of a string, wrap this in double quotes.

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
> Aside this global approach, you can also define an advertise IP and port in a per-interface manner (see the "listen" parameter). When advertise values are defined per interface, they will be used only for traffic leaving that interface only.

### advertised_port

The port advertised in Via header and other destination lumps (e.g. RR). If empty or not set (default value) the port from where the message will be sent is used. Same warnings as for 'advertised_address'.

Example of usage:
```text

    advertised_port=5080

```

> [!NOTE]
> Aside this global approach, you can also define an advertise IP and port in a per-interface manner (see the "listen" parameter). When advertise values are defined per interface, they will be used only for traffic leaving that interface only.

### alias

Parameter to set alias hostnames for the server. It can be set many times, each value being added in a list to match the hostname when 'myself' is checked.

It is necessary to include the port (the port value used in the "port=" or "listen=" definitions) in the alias definition otherwise the loose_route() function will not work as expected for local forwards

Example of usage:

```text

    alias=other.domain.com:5060
    alias=another.domain.com:5060

```

### auto_aliases

This parameter controls if aliases should be automatically discovered and added during fixing listening sockets. The auto discovered aliases are result of the DNS lookup (if listen is a name and not IP) or of a reverse DNS lookup on the listen IP.

Far backward compatibility reasons, the default value is "on".

Example of usage:
```text

    auto_aliases=no
    auto_aliases=0

```

### check_via

Check if the address in top most via of replies is local. Default value is 0 (check disabled).

Example of usage:

```text
check_via=1 
```

### children

Number of children to fork for **each** UDP or SCTP interface you have defined. Default value is 8.

Example of usage:
```text

    children=16

```

> [!NOTE]
> this global value (applicable for all UDP/SCTP interfaces) can be override if you set a different number of children in the definition of a specific interface - so actually you can define a different number of children for each interface (see the "listen" parameter for syntax).

### chroot

The value must be a valid path in the system. If set, **OpenSIPS** will chroot (change root directory) to its value.

Example of usage:

```text
chroot=/other/fakeroot
```

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

### debug

Set the debug level. Higher values make **OpenSIPS** to print more debug messages.

Examples of usage:

```text

    debug=1 -- print only important messages (like errors or more critical situations) 
    - recommended for running proxy as daemon

    debug=4 -- print a lot of debug messages - use it only when doing debugging sessions

```

Actual values are:
* -3 - Alert level
* -2 - Critical level
* -1 - Error level
* 1 - Warning level
* 2 - Notice level
* 3 - Info level
* 4 - Debug level

The 'debug' parameter is usually used in concordance with 'log_stderror' parameter.

Value of 'debug' parameter can also be get and set dynamically using 'debug' Core MI function.

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

The temporary blacklist created by DNS resolver is named "dns" and it is by default selected for usage (no need use the use_blacklist()) function. The rules from this list have a life time of 4 minutes - you can change it at compile time, from blacklists.h .

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

### disable_tcp

Global parameter to disable TCP support in the SIP server. Default value is 'no'.

Example of usage:

```text
disable_tcp=yes
```

### disable_tls

Global parameter to disable TLS support in the SIP server. Default value is 'yes'.

Example of usage:

```text
disable_tcp=no
```

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

Definition of a static (read-only) IP/destination blacklist. These lists can be selected from script (at runtime) to filter  the outgoing requests, based on IP, protocol, port, etc.

Its primary purposes will be to prevent sending requests to critical IPs (like GWs) due DNS or to avoid sending to destinations that are known to be unavailable (temporary or permanent). 

Example of usage:

```text

   # filter out requests going to ips of my gws
   dst_blacklist = gw:{( tcp , 192.168.2.100 , 5060 , "" ),( any , 192.168.2.101 , 0 , "" )}
   # block requests going to "evil" networks
   dst_blacklist = net_filter:{ ( any , 192.168.1.100/255.255.255.0 , 0 , "" )}
   # block message requests with nasty words
   dst_blacklist = msg_filter:{ ( any , 192.168.20.0/255.255.255.0 , 0 , "MESSAGE*ugly_word" )}
   # block requests not going to a specific subnet
   dst_blacklist = net_filter2:{ !( any , 192.168.30.0/255.255.255.0 , 0 , "" )}

```

Each rule is defined by:
* protocol : TCP, UDP, TLS or "any" for anything
* port : number or 0 for any
* ip/mask
* test patter - is a filename like matching (see  "man 3 fnmatch") applied on the outgoing request buffer (first_line+hdrs+body) 

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

### fork

If set to 'yes' the proxy will fork and run in daemon mode - one process will be created for each network interface the proxy listens to and for each protocol (TCP/UDP), multiplied with the value of 'children' parameter.

When set to 'no', the proxy will stay bound to the terminal and runs as single process. First interface is used for listening to. OpenSIPS will only listen on UDP. Since the process is attached to the controlling terminal, not PID file will be created even if the -P command line option was specified.

Default value is 'yes'.

Example of usage:

```opensips
fork=no
```

### group gid

The group id to run **OpenSIPS**.

Example of usage:

```text
group="opensips"
```

### include_file

Can be called from outside route blocks to load additional routes/blocks or from inside them to simply preform more functions. The file path can be relative or absolute. If it is not an absolute path, first attempt is to locate it relative to current directory. If that fails, second try is relative to directory of the file that includes it. Will throw an error if file is not found.

Example of usage:

```text

    include_file "proxy_regs.cfg"

```

### import_file

Same as include_file but will not throw an error if file is not found.

Example of usage:

```text

    import_file "proxy_regs.cfg"

```

### listen

Set the network addresses the SIP server should listen to. It can be an IP address, hostname or network interface id or combination of protocol:address:port (e.g., udp:10.10.10.10:5060). This parameter can be set multiple times in same configuration file, the server listening on all addresses specified.

The listen definition may accept several optional parameters for:
* configuring an advertise IP and port only for this interface. Syntax "AS 11.22.33.44:5060"
* setting a different number of children for this interface only (for UDP and SCTP interfaces only). This will override the global "children" parameter. Syntax "use_children 5"
Remember that this parameters have affect only for the interface they are configured for; if not defined per interface, the global values will be used.

Example of usage:

```text

    listen=10.10.10.10
    listen=eth1:5062
    listen=udp:10.10.10.10:5064
    listen=udp:127.0.0.1:5060 use_children 5
    listen=udp:127.0.0.1:5060 as 99.88.44.33:5060 use_children 3
    listen=127.0.0.1 use_children 3

```

If you omit this directive then the SIP server will listen on all interfaces. On start the SIP server reports all the interfaces that it is listening on. Even if you specify only UDP interfaces here, the server will start the TCP engine too. If you don't want this, you need to disable the TCP support completely with the core parameter disable_tcp.

### log_facility

If **OpenSIPS** logs to syslog, you can control the facility for logging. Very
useful when you want to divert all **OpenSIPS** logs to a different log file.
See the man page syslog(3) for more details.

For more see: http://www.voice-system.ro/docs/ser-syslog/

Default value is LOG_DAEMON.

Example of usage:

```text
log_facility=LOG_LOCAL0
```

### log_name

Set the id to be printed in syslog. The value must be a string and has
effect only when **OpenSIPS** runs in daemon mode (fork=yes), after daemonize.
Default value is argv[0].

Example of usage:

```text
log_name="osips-5070"
```

### log_stderror

With this parameter you can make **OpenSIPS** to write log and debug messages to standard error. Possible values are:

- "yes" - write the messages to standard error

- "no" - write the messages to syslog

Default value is "no".

For more see: http://www.voice-system.ro/docs/ser-syslog/

Example of usage:

```opensips
log_stderror=yes
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

### memdump | mem_dump

Log level to print memory status information (runtime and shutdown). It has to be less than the value of 'debug' parameter if you want memory info to be logged. Default: memdump=L_DBG (4)

Example of usage:

```text
memdump=2
```

NOTE that setting memlog (see below), will also set the memdump parameter - if you want different values for memlog and memdump, you need to first set memlog and then memdump.

### memlog | mem_log

Log level to print memory debug info. It has to be less than the value of 'debug' parameter if you want memory info to be logged. Default: memlog=L_DBG (4)

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

### port

The port the SIP server listens to. The default value for it is 5060.

Example of usage:

```text
port=5080
```

### reply_to_via

If it is set to 1, any local reply is sent to the address advertised in top most Via of the request. Default value is 0 (off).

Example of usage:

```text
reply_to_via=0
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

### sip_warning

Can be 0 or 1. If set to 1 (default value is 0) a 'Warning' header is added to each reply generated by **OpenSIPS**.
The header contains several details that help troubleshooting using the network traffic dumps.

Example of usage:

```text
sip_warning=0
```

### tcp_children

Number of children processes to be created for reading from TCP connections. If no value is explicitly set, the same number of TCP children as UDP children (see "children" parameter) will be used.

Example of usage:

```text
tcp_children=4
```

### tcp_accept_aliases

### tcp_send_timeout

Time in milliseconds after a TCP connection will be closed if it is not available
for writing in this interval (and **OpenSIPS** wants to send something on it).
Default is 100ms

Example of usage:

```text
tcp_send_timeout=200
```

### tcp_connect_timeout

Time in milliseconds before an ongoing attempt to connect will be aborted.
Default is 100ms

Example of usage:

```text
tcp_connect_timeout=50
```

### tcp_connection_lifetime!!!!

Lifetime in seconds for TCP sessions. TCP sessions which are inactive for >tcp_connection_lifetime will be closed by **OpenSIPS**. Default value is defined in tcp_conn.h: #define DEFAULT_TCP_CONNECTION_LIFETIME 120. Setting this value to 0 will close the TCP connection pretty quick ;-). You can also set the TCP lifetime to the expire value of the REGISTER by using the tcp_persistent_flag parameter of the registrar module.

Example of usage:

```text
tcp_connection_lifetime=3600
```

### tcp_max_connections

maximum number of tcp connections (if the number is exceeded no new tcp connections will be accepted). Default is defined in tcp_conn.h: #define DEFAULT_TCP_MAX_CONNECTIONS 2048

Example of usage:

```text
tcp_max_connections=4096
```

### tcp_poll_method

poll method used (by default the best one for the current OS is selected). For available types see io_wait.c and poll_types.h: none, poll, epoll_lt, epoll_et, sigio_rt, select, kqueue, /dev/poll

Example of usage:

```text
tcp_poll_method=select
```

### tcp_no_new_conn_bflag

A branch flag to be used as marker to instruct OpenSIPS not to attempt to open a new TCP connection when delivering a request, but only to reuse an existing one (if available). If no existing conn, a generic send error will be returned.

This is intended to be used in NAT scenarios, where makes no sense to open a TCP connection towards a destination behind a NAT (like TCP connection created during registration was lost, so there is no way to contact the device until it re-REGISTER). Also this can be used to detect when a NATed registered user lost his TCP connection, so that opensips can disable his registration as useless.

Example of usage:

```bash
tcp_no_new_conn_bflag = 6
....
route{
....
if( destination_behin_nat && proto==TCP )
setbflag(6);
....
t_relay("0x02"); # no auto error reply
$var(retcode) = $rc;
if ($var(retcode)==-6) {
#send error
xlog("unable to send request to destination");
send_reply("404","Not found");
exit;
} else if ($var(retcode)<0) {
sl_reply_error();
exit;
}
....
}
```

### tcp_threshold
A number representing the maximum number of microseconds sending of a TCP request is expected to last. Anything above the set number will trigger a warning message to the logging facility.

Default value is 0 ( logging disabled ).

Example of usage:

```text
tcp_threshold = 60000
```

### tcp_keepalive

Enable / disable TCP keepalive

Example of usage:

```text
tcp_keepalive = 1
```

### tcp_keepcount

Number of keepalives to send before closing the connection (Linux only)

Example of usage:

```text
tcp_keepcount = 5
```

### tcp_keepidle

Amount of time before OpenSIPS will start to send keepalives if the connection is idle (Linux only)

Example of usage:

```text
tcp_keepidle = 30
```

### tcp_keepinterval

Interval between keepalive probes, if the previous one failed (Linux only)

Example of usage:

```text
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

The TOS (Type Of Service) to be used for the sent IP packages (both TCP and UDP).

Example of usage:

```text

    tos=IPTOS_LOWDELAY
    tos=0x10
    tos=IPTOS_RELIABILITY

```

### user uid

The user id to run **OpenSIPS** (OpenSIPS will suid to it).

Example of usage:

```text
user="opensips"
```

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

  

Only relevant when [log_stderror](https://docs.opensips.org/manual/1-8/script-coreparameters#log_stderror) is set to *true*. Enables the use of the [color escape sequences](https://docs.opensips.org/manual/1-8/script-corevar#escape_sequences), otherwise they will have no effect.

Usage example:
```text

    xlog_force_color = true

```
