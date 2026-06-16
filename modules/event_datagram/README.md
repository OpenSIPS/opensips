---
title: "event_datagram Module"
description: "This is a module which provides a UNIX/UDP SOCKET transport layer implementation for the Event Interface."
---

## Admin Guide


### Overview


This is a module which provides a UNIX/UDP SOCKET transport layer 
		implementation for the Event Interface.


### DATAGRAM events syntax


The event payload is formated as a JSON-RPC notification, with the event
		name as the *method* field and the event parameters as
		the *params* field.


### DATAGRAM socket syntax


There are two types of sockets used by this module, based on the
		sockets type. An UNIX socket should follow this syntax:
		*['unix:'] unix_socket_path*


An UDP socket should follow this syntax:
		*'udp:' address ':' port*


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *none*


### Exported Parameters


No parameter exported by this module.


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example of an event raised by the pike module
			when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED event"
{
  "jsonrpc": "2.0",
  "method": "E_PIKE_BLOCKED",
  "params": {
    "ip": "192.168.2.11"
  }
}
```


```c title="UNIX socket"
unix:/tmp/opensips_event.sock
```


```c title="UDP socket"
udp:127.0.0.1:8081
```


## Frequently Asked Questions


**Q: Both UNIX and UDP type of socket can be
				used to notify the events?**


Yes, you can use the both types.


**Q: What is the maximum lenght of a datagram event?**


The maximum length of a datagram event is 65457 bytes.


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


**Q: Where can I post a question about this module?**


First at all check if your question was already answered on one of
			our mailing lists:

E-mails regarding any stable OpenSIPS release should be sent to 
			users@lists.opensips.org and e-mails regarding development versions
			should be sent to devel@lists.opensips.org.

If you want to keep the mail private, send it to 
			users@lists.opensips.org.


**Q: How can I report a bug?**


Please follow the guidelines provided at:
			[https://github.com/OpenSIPS/opensips/issues](https://github.com/OpenSIPS/opensips/issues).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
