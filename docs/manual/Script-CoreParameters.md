---
title: "Core functions"
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

```text
WARNING: 
- don't set it unless you know what you are doing (e.g. nat traversal)
- you can set anything here, no check is made (e.g. foo.bar will be
accepted even if foo.bar doesn't exist)
```

Example of usage:

```text
advertised_address="opensips.org"
```

### advertised_port

The port advertised in Via header and other destination lumps (e.g. RR). If empty or not set (default value) the port from where the message will be sent is used. Same warnings as for 'advertised_address'.

Example of usage:

```text
advertised_port=5080
```

### alias

Parameter to set alias hostnames for the server. It can be set many times, each value being added in a list to match the hostname when 'myself' is checked.

It is necessary to include the port (the port value used in the "port=" or "listen=" definitions) in the alias definition otherwise the loose_route() function will not work as expected for local forwards

Example of usage:

```text

    alias=other.domain.com:5060
    alias=another.domain.com:5060

```

### avp_aliases

Contains a multiple definition of aliases for AVP names.

Example of usage:

```text

    avp_aliases="uuid=I:660;email=s:email_addr;fwd=i:753"

```

### auto_aliases

This parameter controls if aliases should be automatically discovered and added during fixing listening sockets. The auto discovered aliases are result of the DNS lookup (if listen is a name and not IP) or of a reverse DNS lookup on the listen IP.

Far backward compatibility reasons, the default value is "on".

Example of usage:

```opensips
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

Number of children to fork for the UDP interfaces (one set for each interface - ip:port). Default value is 8.

Example of usage:

```opensips
children=16
```

### chroot

The value must be a valid path in the system. If set, **OpenSIPS** will chroot (change root directory) to its value.

Example of usage:

```text
chroot=/other/fakeroot
```

### debug

Set the debug level. Higher values make **OpenSIPS** to print more debug messages.

Examples of usage:

```text

    debug=3 -- print only important messages (like errors or more critical situations) 
    - recommended for running proxy as daemon

    debug=9 -- print a lot of debug messages - use it only when doing debugging sessions

```

The 'debug' parameter is usually used in concordance with 'log_stderror' parameter.

Value of 'debug' parameter can also be get and set dynamically using 'debug' Core MI function.

For more see: [http://www.voice-system.ro/docs/ser-syslog/](http://www.voice-system.ro/docs/ser-syslog/)

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

### disable_tcp

Global parameter to disable TCP support in the SIP server. Default value is 'no'.

Example of usage:

```text
disable_tcp=yes
```

## disable_tls

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

### fork

If set to 'yes' the proxy will fork and run in daemon mode - one process will be created for each network interface the proxy listens to and for each protocol (TCP/UDP), multiplied with the value of 'children' parameter.

When set to 'no', the proxy will stay bound to the terminal and runs as single process. First interface is used for listening to.

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

### listen

Set the network addresses the SIP server should listen to. It can be an IP address, hostname or network interface id or combination of protocol:address:port (e.g., udp:10.10.10.10:5060). This parameter can be set multiple times in same configuration file, the server listening on all addresses specified.

Example of usage:

```text

    listen=10.10.10.10
    listen=eth1:5062
    listen=udp:10.10.10.10:5064

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

### memlog

Log level to print memory debug info. It has be less than the value of 'debug' parameter if you want memory info to be logged. Default: memlog=L_DBG (4)

Example of usage:

```text
memlog=2
```

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

Time in seconds after a TCP connection will be closed if it is not available
for writing in this interval (and **OpenSIPS** wants to send something on it).

Example of usage:

```text
tcp_send_timeout=3
```

### tcp_connect_timeout

Time in seconds before an ongoing attempt to connect will be aborted.

Example of usage:

```text
tcp_connect_timeout=5
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

### tls_ca_list

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_certificate

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_ciphers_list

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_domain

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_handshake_timeout

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_log

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_method

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_port_no

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_private_key

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_require_certificate

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_send_timeout

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_verify_client

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

### tls_verify_server

->See : [TLS tutorial](http://www.opensips.org/html/docs/tutorials/tls-1.4.x.html).

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
