---
title: "event_rabbitmq Module"
description: "*RabbitMQ* ([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) is an open source messaging server. It's purpose is to manage received messages in queues, taking advantage of the flexible AMQP protocol."
---

## Admin Guide


### Overview


*RabbitMQ*
		([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) 
		is an open source messaging server. It's purpose is to
		manage received messages in queues, taking advantage of
		the flexible AMQP protocol.


This module provides the implementation of a RabbitMQ client 
		that supports two primary functionalities:


- *Event-Driven Messaging:*
		It is used to send AMQP messages to a RabbitMQ server
		each time the Event Interface triggers an event subscribed for.
- *General Message Publishing:*
		This module also enables sending AMQP messages directly to a RabbitMQ
		server. Messages can be easily customized according to the AMQP specifications,
		as well the RabbitMQ extensions.


### RabbitMQ events syntax


The event payload is formated as a JSON-RPC notification, with the event
		name as the *method* field and the event parameters as
		the *params* field.


### RabbitMQ socket syntax


*'rabbitmq:' [user[':'password] '@' host [':' port] '/' [params '?'] routing_key*


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
- *params* - extra parameters specified as
					*key[=value]*, separated by ';':
					
						*exchange* - exchange of the RabbitMQ server.
						The default value is ''.
						*tls_domain* - indicates which TLS domain (as
						defined using the *tls_mgm* module) to use for
						this connection. The [use tls](#param_use_tls) module parameter
						must be enabled.
						*persistent* - indicates that the message should be
						published as persistent *delivery_mode=2*. This
						parameter does not have a value.
- *routing_key* - this is the routing key
					used by the AMQP protocol and it is used to identify the queue
					where the event should be sent.
					NOTE: if the queue does not exist, this module will not 
						try to create it.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if [use tls](#param_use_tls) is enabled.


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


```c title="Set heartbeat parameter"
...
modparam("event_rabbitmq", "heartbeat", 3)
...
```


#### connect_timeout (integer)


The maximally allowed duration (in milliseconds) for the establishment
			of a TCP connection with a RabbitMQ server.


*Default value is "500" (milliseconds).*


```c title="Setting the connect_timeout parameter"
...
modparam("event_rabbitmq", "connect_timeout", 1000)
...
	
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for broker connections.
		In order to enable TLS for a specific connection, you can use the
		"tls_domain=*dom_name*" parameter in the configuration
		specified through the [socket syntax](#rabbitmq_socket_syntax).


When using this parameter, you must also ensure that
		*tls_mgm* is loaded and properly configured. Refer to
		the the module for additional info regarding TLS client domains.


*Default value is **0** (not enabled)*


```c title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "rmq")
modparam("tls_mgm", "certificate", "[rmq]/etc/pki/tls/certs/rmq.pem")
modparam("tls_mgm", "private_key", "[rmq]/etc/pki/tls/private/rmq.key")
modparam("tls_mgm", "ca_list",     "[rmq]/etc/pki/tls/certs/ca.pem")
...
modparam("event_rabbitmq", "use_tls", 1)
...
```


#### timeout (integer)


Indicates the timeout (in milliseconds) of any command (i.e. publish)
		sent to the RabbitMQ server.


*NOTE* that this parameter is available only starting with
		RabbitMQ library version *0.9.0*; setting it when using an
		earlier version will have no effect, and the publish command will run in
		blocking mode.


*Default value is **0** (no timeout - blocking mode)*


```c title="Set the timeout parameter"
...
modparam("event_rabbitmq", "timeout", 1000) # timeout after 1s
...
```


#### server_id (string)


Specify configuration for a RabbitMQ server. It contains a set
			of parameters used to customize the connection to the server,
			as well as to the messages sent. The format of the parameter is
			*[id_name] param1=value1; param2=value2;*.
			The *uri* parameter is mandatory.


This parameter can be set multiple times, for each RabbitMQ
			server.


The following parameters can be used:


- *uri* - Mandatory parameter - a full
				*amqp* URI as described
				[here](https://www.rabbitmq.com/uri-spec.html).
				Missing fields in the URI will receive default values,
				such as: *user: guest*,
				*password: guest*,
				*host: localhost*,
				*vhost: /*,
				*port: 5672*. TLS connections are specified
				using an *amqps* URI.
- *frames* - the maximum size of an AMQP
				frame. Optional parameter, default size is 131072.
- *retries* - the number of retries in case
				a connection is down. Optional parameter, default is disabled
				(do not retry).
- *exchange* - exchange used to send AMQP
				messages to. Optional parameter, default is *""*.
- *heartbeat* - interval in seconds used
				to send heartbeat messages. Optional parameter, default is
				disabled.
- *immediate* - indicate to the broker that
				the message MUST be delivered to a consumer immediately.
				Optional parameter, default is not immediate.
- *mandatory* - indicate to the broker that
				the message MUST be routed to a queue. Optional parameter,
				default is not mandatory.
- *non-persistent* - indicates that the
				message should not be persistent in case the RabbitMQ
				server restarts. Optional parameter, default is persistent.
- *tls_domain* - indicates which TLS domain (as
				defined using the *tls_mgm* module) to use for
				this connection. This must be an *amqps* URI and the
				[use tls](#param_use_tls) module parameter must be enabled.


```c title="Set server_id parameter"
...
# connection to a RabbitMQ server on localhost, default port
modparam("event_rabbitmq", "server_id","[ID1] uri = amqp://127.0.0.1")
...
# connection with a 5 seconds interval for heartbeat messages
modparam("event_rabbitmq", "server_id","[ID2] uri = amqp://127.0.0.1;
heartbeat = 5")
...
# TLS connection
modparam("event_rabbitmq", "server_id","[ID3] uri = amqps://127.0.0.1; tls_domain=rmq")
...
		
```


### Exported Functions


#### rabbitmq_publish(server_id, routing_key, message [, [content_type [, headers, headers_vals]]])


Sends a publish message to a RabbitMQ server.


This function also allows you to attach AMQP headers and values
				in the AMQP message. This is done by specifying a set of headers
				names (in the *headers* parameter) and the
				corresponding values (in the *headers_vals*
				parameter). The number of AVP values in the
				*headers* must be the same as the one in the
				*headers_vals*.


This function can be used from any route.


The function has the following parameters:


- *server_id* (string) - the id of the RabbitMQ server.
						Must be one of the parameters defined in the
						*server_id* modparam.
- *routing_key* (string) - routing key used to
						deliver the AMQP message.
- *message* (string) - the body of the message.
- *content_type* (string, optional) - content type
						of the message sent. By default it is *none*.
- *headers* (string, optional) - an AVP containing
						the names of the headers within the AMQP message. If set,
						*headers_vals* parameter must also be specified.
- *headers_vals* (string, optional) - an AVP containing
						the corresponding values of the AMQP headers. If set,
						*headers* parameter must also be specified.


```c title="rabbitmq_publish() function usage"
	...
	rabbitmq_publish("ID1", "call", "$fU called $rU");
	...
	rabbitmq_publish("ID1", "call", "{ \'caller\': \'$fU\',
					\'callee\; \'$rU\'", "application/json");
	...
	$avp(hdr_name) = "caller";
	$avp(hdr_value) = $fU;
	$avp(hdr_name) = "callee";
	$avp(hdr_value) = $rU;
	rabbitmq_publish("ID2", "call", $rb, , $avp(hdr_name), $avp(hdr_value));
	...
	
```


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


```c title="RabbitMQ socket"
	rabbitmq:guest:guest@127.0.0.1:5672/pike

	# same socket can be written as
	rabbitmq:127.0.0.1/pike

	# TLS broker connection
	rabbitmq:127.0.0.1/tls_domain=rmq?pike
```


### Installation and Running


#### OpenSIPS config file


This configuration file presents the usage of the event_rabbitmq
			module. In this scenario, a message is sent to a RabbitMQ server
			everytime OpenSIPS receives a MESSAGE request. The parameters 
			passed to the server are the R-URI username and the message
			body.


[OpenSIPS config script - sample event_rabbitmq usage](./samples.md "include")


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
