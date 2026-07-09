---
title: "RabbitMQ Module"
description: "*RabbitMQ* ([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) is an open source messaging server. It's purpose is to manage received messages in queues, taking advantage of the flexible AMQP protocol."
---

## Admin Guide


### Overview


*RabbitMQ*
([http://www.rabbitmq.com/](http://www.rabbitmq.com/)) 
is an open source messaging server. It's purpose is to
manage received messages in queues, taking advantage of
the flexible AMQP protocol.


Using this module you can send AMQP messages to a RabbitMQ server.
Messages can be easily customized according to the AMQP specifications,
as well the RabbitMQ extensions.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *tls_mgm* if [use tls](#param_use_tls) is enabled.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *librabbitmq-dev*


### Exported Parameters


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


```opensips title="Set server_id parameter"
...
# connection to a RabbitMQ server on localhost, default port
modparam("rabbitmq", "server_id","[ID1] uri = amqp://127.0.0.1")
...
# connection with a 5 seconds interval for heartbeat messages
modparam("rabbitmq", "server_id","[ID2] uri = amqp://127.0.0.1;
heartbeat = 5")
...
# TLS connection
modparam("rabbitmq", "server_id","[ID3] uri = amqps://127.0.0.1; tls_domain=rmq")
...
		
```


#### use_tls (integer)


Setting this parameter will allow you to use TLS for broker connections.
In order to enable TLS for a specific connection, you can use the
"tls_domain=*dom_name*" parameter in the configuration
specified through the [server id](#param_server_id) module parameter.


When using this parameter, you must also ensure that
*tls_mgm* is loaded and properly configured. Refer to
the the module for additional info regarding TLS client domains.


*Default value is **0** (not enabled)*


```opensips title="Set the use_tls parameter"
...
modparam("tls_mgm", "client_domain", "rmq")
modparam("tls_mgm", "certificate", "[rmq]/etc/pki/tls/certs/rmq.pem")
modparam("tls_mgm", "private_key", "[rmq]/etc/pki/tls/private/rmq.key")
modparam("tls_mgm", "ca_list",     "[rmq]/etc/pki/tls/certs/ca.pem")
...
modparam("rabbitmq", "use_tls", 1)
...
```


#### connect_timeout (integer)


The maximally allowed duration (in milliseconds) for the establishment
of a TCP connection with a RabbitMQ server.


*Default value is "500" (milliseconds).*


```c title="Setting the connect_timeout parameter"
aram("rabbitmq", "connect_timeout", 1000)
```


#### timeout (integer)


Indicates the timeout (in milliseconds) of any command (i.e. publish)
sent to the RabbitMQ server.


*NOTE* that this parameter is available only starting with
RabbitMQ library version *0.9.0*; setting it when using an
earlier version will have no effect, and the publish command will run in
blocking mode.


*Default value is **0** (no timeout - blocking mode)*


```opensips title="Set the timeout parameter"
...
modparam("rabbitmq", "timeout", 1000) # timeout after 1s
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


```opensips title="rabbitmq_publish() function usage"
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
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
