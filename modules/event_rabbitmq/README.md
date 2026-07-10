---
title: "event_rabbitmq Module"
description: "*RabbitMQ* ([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) is an open source messaging server."
---

## Admin Guide


### Overview


*RabbitMQ*
([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) 
is an open source messaging server. It's purpose is to
manage received messages in queues, taking advantage of
the flexible AMQP protocol.


This module provides the implementation of a RabbitMQ client for the
Event Interface. It is used to send AMQP messages to a RabbitMQ server
each time the Event Interface triggers an event subscribed for.


The AMQP protocol is only used as the transport layer for notifications.
The content of a message is presented in the next section.


### RabbitMQ events syntax


The raised events will follow the following grammar:


- *event = event_name (argument '\n')**
- *event_name = non-quoted_string'\n'*
- *argument = ((arg_name '::')? arg_value)? | (arg_value)*
- *arg_name = not-quoted_string*
- *arg_value = not-quoted_string | '"' string '"'*
- *not-quoted_string = string - {',",\n,\r}*


The event name can contain any non-quoted string character, but
it is recommended to follow the syntax:
E_*MODULE_NAME*_*EXTRA_NAME*


### RabbitMQ socket syntax


*'rabbitmq:' [user[':'password] '@' host [':' port] '/' [exchange '?'] routing_key*


Meanings:


- *'rabbitmq:'* - informs the Event Interface that the
events sent to this subscriber should be handled by the
*event_rabbitmq* module.
- *user* - username used for RabbitMQ server
authentication. The default value is 'guest'.
- *password* - password used for RabbitMQ server
authentication. The default value is 'guest'.
- *host* - host name of the RabbitMQ server.
- *port* - port of the RabbitMQ server. The
default value is '5672'.
- *exchange* - exchange of the RabbitMQ server. The
default value is ''.
- *routing_key* - this is the routing key
used by the AMQP protocol and it is used to identify the queue
where the event should be sent.

> [!NOTE]
> If the queue does not exist, this module will not 
> try to create it.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *librabbitmq-dev*


### Exported Parameters


#### heartbeat (integer)


Enables heartbeat support for the AMQP communication. If the
client does not receive a heartbeat from server within the
specified interval, the socket is automatically closed by the
rabbitmq-client. This prevents OpenSIPS from blocking while
waiting for a response from a dead rabbitmq-server. The value
represents the heartbit interval in seconds.


*Default value is "0 (disabled)".*


```opensips title="Set heartbeat parameter"
...
modparam("event_rabbitmq", "heartbeat", 3)
...
```


#### sync_mode (integer)


Specifies whether an event raise operates synchronous or asynchronous relative to the process where the raise is triggered.In synchronous mode the process waits for the status of the raise from the actual worker process.In asynchronous mode the process continues its operation without receiving any confirmation.


*Default value is "0 (asynchronous)".*


```opensips title="Set sync_mode parameter"
...
modparam("event_rabbitmq", "sync_mode", 1)
...
```


#### connect_timeout (integer)


The maximally allowed duration (in milliseconds) for the establishment
of a TCP connection with a RabbitMQ server.


*Default value is "10000" (10 seconds).*


**NOTE:** This parameter is only
available since OpenSIPS 3.0.1.


```opensips title="Setting the connect_timeout parameter"
...
modparam("event_rabbitmq", "connect_timeout", 500)
...
	
```


### Exported Functions


No function exported to be used from configuration file.


### Example


This is an example of an event raised by the pike module
when it decides an ip should be blocked:


```c title="E_PIKE_BLOCKED event"
	E_PIKE_BLOCKED
	ip::192.168.2.11
```


```c title="RabbitMQ socket"
rabbitmq:guest:guest@127.0.0.1:5672/pike

# same socket can be written as
rabbitmq:127.0.0.1/pike
```


## Samples

[samples](./samples/samples.md "include")


## Frequently Asked Questions


**Q: What is the maximum lenght of a AMQP message?**


The maximum length of a datagram event is 16384 bytes.


**Q: Where can I find more about OpenSIPS?**


Take a look at [https://opensips.org/](https://opensips.org/).


**Q: What is the vhost used by the AMQP server?**


Currently, the only vhost supported is *'/'*.


**Q: How can I set a vhost in the socket?**


This version doesn't support a different vhost.


**Q: How can I send an event to my RabbitMQ server?**


This module acts as a transport module for the OpenSIPS
Event Interface. Therefore, this module should follow the
Event Interface behavior:

The first step is to subscribe the RabbitMQ server to
the OpenSIPS Event Interface. This can be done using the
*subscribe_event* core function:

The next step is to raise the event from the script,
using the *raise_event* core function:

NOTE that the event used above is only to exemplify the
usage from the script. Any event published through the
OpenSIPS Event Interface can be raised using this module.


**Q: Where can I find more information about RabbitMQ?**


You can find more information about RabbitMQ  on
their official website
([http://www.rabbitmq.com/](http://www.rabbitmq.com/)).


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
