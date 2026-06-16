---
title: "RabbitMQ Consumer Module"
description: "*RabbitMQ Consumer* ([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) is an open source messaging server. It's purpose is to manage received messages in queues, taking advantage of the flexible AMQP protocol."
---

## Admin Guide


### Overview


*RabbitMQ Consumer*
		([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) 
		is an open source messaging server. It's purpose is to
		manage received messages in queues, taking advantage of
		the flexible AMQP protocol.


Using this module you can subscribe consumers to a RabbitMQ broker in order
		to receive AMQP messages for specified queues. The messages will be delivered
		by triggering events through the OpenSIPS Event Interface.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if [use tls](#param_use_tls) is enabled.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *librabbitmq-dev*


NOte that the module is not compatible with versions 0.4 or below of
			the librabbitmq-dev library.


### Exported Parameters


#### connection_id (string)


Specify the configuration for a RabbitMQ connection. It contains a set
			of parameters used to customize the connection to the server as well as
			the consumer subscription. The format of the parameter is
			*param1=value1; param2=value2;*.
			The *uri*, *queue* and
			*event* parameters are mandatory.


This parameter can be set multiple times, for each RabbitMQ
			connection.


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
- *queue* - Mandatory parameter - the name of the
				RabbitMQ queue to subscribe a consumer to. This parameter is mandatory.
- *event* - Mandatory parameter - the name of the OpenSIPS
				event that will be triggered for each AMQP message received.
- *ack* - flag that indicates to the broker
				that messages will be acknowledged upon receival. If you do not
				set this flag, the server will not expect ACKs and OpenSIPS will not
				send them.
- *exclusive* - flag that indicates to the broker
				that exclusive consumer access is requested, meaning only this consumer
				can access the queue.
- *frame_max* - the maximum size of an AMQP
				frame. Default size is 131072.
- *heartbeat* - interval in seconds used
				to send heartbeat messages. Default is disabled.
- *tls_domain* - indicates which TLS domain (as
				defined using the *tls_mgm* module) to use for
				this connection. This must be an *amqps* URI and
				the [use tls](#param_use_tls) module parameter must be enabled.


```c title="Set connection_id parameter"
...
# connection to a RabbitMQ server on localhost, default port
# with a 5 seconds interval for heartbeat messages
modparam("rabbitmq_consumer", "connection_id",
    "uri = amqp://127.0.0.1; queue = myqueue1; event = E_Q1_MSG; heartbeat = 5;")
...
# consumer that acknowledges messages
modparam("rabbitmq_consumer", "connection_id",
    "uri = amqp://127.0.0.1; queue = myqueue2; event = E_Q2_MSG; ack;")
...
# TLS connection
modparam("rabbitmq_consumer", "connection_id",
    "uri = amqps://127.0.0.1; queue = myqueue3; event = E_Q3_MSG; tls_domain=rmq;")
...
		
```


#### connect_timeout (integer)


The maximally allowed duration (in milliseconds) for the establishment
		of a TCP connection with a RabbitMQ server.


*Default value is "500" (milliseconds).*


```c title="Setting the connect_timeout parameter"
...
modparam("rabbitmq_consumer", "connect_timeout", 1000)
...
```


#### retry_timeout (integer)


The interval (in milliseconds) after which OpenSIPS will try to
		re-establish a failed AMQP connection to a RabbitMQ server.


*Default value is "5000" (milliseconds).*


```c title="Setting the retry_timeout parameter"
...
modparam("rabbitmq_consumer", "retry_timeout", 10000)
...
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for broker connections.
		In order to enable TLS for a specific connection, you can use the
		"tls_domain=*dom_name*" parameter in the configuration
		specified through the [connection id](#param_connection_id) module parameter.


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
modparam("rabbitmq_consumer", "use_tls", 1)
...
```


### Exported Functions


The module does not export any script functions.


### Exported Events


An event with a custom name, as set in the *event*
		field of the [connection id](#param_connection_id) parameter,
		will be raised for each AMQP message received.


Parameters:


- *body* - the AMQP message body.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
