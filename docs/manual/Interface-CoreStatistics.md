---
title: "Core Statistics"
description: "Statistics which are exported by the OpenSIPS core."
---

Statistics which are exported by the **OpenSIPS** core.

---

## "CORE" Class

### rcv_requests
Returns the total number of received requests by OpenSIPS.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics rcv_requests

```

Example of usage from script
```opensips

xlog("Total number of received requests = $stat(rcv_requests) \n");

```

### rcv_replies
Returns the total number of received replies by OpenSIPS.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics rcv_replies

```

Example of usage from script
```opensips

xlog("Total number of received replies = $stat(rcv_replies) \n");

```

### fwd_requests
Returns the number of stateless forwarded requests by OpenSIPS.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics fwd_requests

```

Example of usage from script
```opensips

xlog("Total number of forwarded requests = $stat(fwd_requests) \n");

```

### fwd_replies
Returns the number of stateless forwarded replies by OpenSIPS.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics fwd_replies

```

Example of usage from script
```opensips

xlog("Total number of forwarded replies = $stat(fwd_replies) \n");

```

### drop_requests
Returns the number of requests dropped even before entering the script routing logic.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics drop_requests

```

Example of usage from script
```opensips

xlog("Total number of dropped requests = $stat(drop_requests) \n");

```

### drop_replies
Returns the number of replies dropped even before entering the script routing logic, or explicitly dropped in the
onreply_route.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics drop_replies

```

Example of usage from script
```opensips

xlog("Total number of dropped replies = $stat(drop_replies) \n");

```

### err_requests
Returns the number of bogus requests from SIP point of view ( eg. : No VIA header found )

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics err_requests

```

Example of usage from script
```opensips

xlog("Total number of error requests = $stat(err_requests) \n");

```

### err_replies
Returns the number of bogus replies from SIP point of view ( eg. : No VIA header found )

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics err_replies

```

Example of usage from script
```opensips

xlog("Total number of error replies = $stat(err_replies) \n");

```

### bad_URIs_rcvd
Returns the number of URIs that OpenSIPS failed to parse.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics bad_URIs_rcvd

```

Example of usage from script
```opensips

xlog("Total number of bad URIs detected = $stat(bad_URIs_rcvd) \n");

```

### unsupported_methods
Returns the number of non-standard methods encountered by OpenSIPS while parsing SIP methods.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics unsupported_methods

```

Example of usage from script
```opensips

xlog("Total number of unsupported methods detected = $stat(unsupported_methods) \n");

```

### bad_msg_hdr
Returns the number of SIP headers that OpenSIPS failed to parse.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics bad_msg_hdr

```

Example of usage from script
```opensips

xlog("Total number of headers that failed to parse = $stat(bad_msg_hdr) \n");

```

### timestamp
Returns the number of seconds elapsed from OpenSIPS starting.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics timestamp

```

Example of usage from script
```opensips

xlog("OpenSIPS has been alive for $stat(timestamp) seconds \n");

```

---

## "LOAD" class

Statistics giving information on OpenSIPS load (busy children).

### tcp-load
Returns the percentage of TCP children that are awake and processing SIP messages.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics tcp-load

```

Example of usage from script
```opensips

xlog("The TCP load is $stat(tcp-load) \n");

```

### udp:int_ip:int_port-load
Returns the percentage of UDP children that are awake and processing SIP messages on the specific UDP interface

Example of usage through MI FIFO:
```opensips

If OpenSIPS has two listen directives :
listen=udp:192.168.2.134:5060
listen=udp:192.168.10.13:5090

Then there will be two exported statistics, udp:192.168.2.134:5060-load and udp:192.168.10.13:5090-load, and each 
will show the percentage of working children on the respective interfaces.

opensipsctl fifo get_statistics udp:192.168.2.134:5060-load

```

Example of usage from script
```opensips

xlog("The UDP load on 192.168.2.134:5060 is $stat(udp:192.168.2.134:5060-load) \n");

```

---

## "NET" Class

Statistics giving information about UDP, TCP and TLS buffers on interfaces that OpenSIPS is listening on.

### waiting_udp
Returns the number of bytes waiting to be consumed on UDP interfaces that OpenSIPS is listening on.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics waiting_udp

```

Example of usage from script
```opensips

xlog("The UDP waiting buffer size is $stat(waiting_udp) \n");

```

### waiting_tcp
Returns the number of bytes waiting to be consumed on TCP interfaces that OpenSIPS is listening on.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics waiting_tcp

```

Example of usage from script
```opensips

xlog("The TCP waiting buffer size is $stat(waiting_tcp) \n");

```

### waiting_tls
Returns the number of bytes waiting to be consumed on TLS interfaces that OpenSIPS is listening on.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics waiting_tls

```

Example of usage from script
```opensips

xlog("The TLS waiting buffer size is $stat(waiting_tls) \n");

```

---

## "SHMEM" Class

Statistics giving information on the shared memory that OpenSIPS is using.

### total_size
Returns the total size of shared memory available to OpenSIPS processes.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics total_size

```

Example of usage from script
```opensips

xlog("Total size of SHMEM available is $stat(total_size) \n");

```

### used_size
Returns the amount of shared memory requested and used by OpenSIPS processes.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics used_size

```

Example of usage from script
```opensips

xlog("SHMEM in use = $stat(used_size) \n");

```

### real_used_size
Returns the amount of shared memory requested by OpenSIPS processes + malloc overhead

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics real_used_size

```

Example of usage from script
```opensips

xlog("Real SHMEM used size is $stat(real_used_size) \n");

```

### max_used_size
Returns the maximum amount of shared memory ever used by OpenSIPS processes.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics max_used_size

```

Example of usage from script
```opensips

xlog("The max SHMEM ever used is $stat(max_used_size) \n");

```

### free_size
Returns the free memory available. Computed as total_size - real_used_size

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics free_size

```

Example of usage from script
```opensips

xlog("Free SHMEM available is $stat(free_size) \n");

```

### fragments
Returns the total number of fragments in the shared memory.

Example of usage through MI FIFO
```opensips

opensipsctl fifo get_statistics fragments

```

Example of usage from script
```opensips

xlog("The total number of SHMEM fragments is $stat(fragments) \n");

```
