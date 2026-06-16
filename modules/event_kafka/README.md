---
title: "event_kafka Module"
description: "This module is an implementation of an [Apache Kafka](https://kafka.apache.org/) producer. It serves as a transport backend for the Event Interface and also provides a stand-alone connector to be used from the OpenSIPS script in order to publish messages to Kafka brokers."
---

## Admin Guide


### Overview


This module is an implementation of an
		[Apache Kafka](https://kafka.apache.org/) producer.
		It serves as a transport backend for the Event Interface and also provides a
		stand-alone connector to be used from the OpenSIPS script in order to
		publish messages to Kafka brokers.


### Kafka socket syntax


*'kafka:' brokers '/' topic ['?' properties]*


Meaning of the socket fields:


- *brokers* - comma-separated list of the addresses (as
			host:port) of the Kafka brokers to connect to. These are the "bootstrap"
			servers used by the client to discover the Kafka cluster. This
			corresponds to the *bootstrap.servers* /
			*metadata.broker.list* configuration property.
- *topic* - Kafka topic used to publish messages to.
- *properties* - configuration properties to be
			transparently passed to the Kafka client library. The syntax is:
			*'g.'|'t.' property '=' value ['&' 'g.'|'t.' property '=' value] ...*
			The *g.* or *t.* prefix before
				each property name specifies whether it's a global or topic level
				property, as classified by the Kafka library. Documentation for the
				supported properties can be found
				[here](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md).
			Note that some library properties have the *topic.*
				prefix as part of their name, but still fall under the global category.
			*key=callid* is an extra property that is not
				passed to the Kafka library and is interpreted by OpenSIPS itself.
				When enabling this property the record published to Kafka will also
				include the Call-ID of the current SIP message as key.


### Kafka events syntax


The event payload is formated as a JSON-RPC notification, with the event
		name as the *method* field and the event parameters as
		the *params* field.


The record published to Kafka will also include the Call-ID of the current
		SIP message as key, if the *key=callid* property is
		provided in the event socket.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *none*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *librdkafka-dev*


*librdkafka-dev* can be installed from the Confluent
			[APT](https://docs.confluent.io/current/installation/installing_cp/deb-ubuntu.html#get-the-software) or
			[YUM](https://docs.confluent.io/current/installation/installing_cp/rhel-centos.html#get-the-software)
			repositories.


### Exported Parameters


#### broker_id (string)


This parameter specifies the configuration for a Kafka broker
			(or cluster) that can be used to publish messages directly
			from the script, using the [kafka publish](#func_kafka_publish) function.


The format of the parameter is: *[ID]kafka_socket*,
			where *ID* is an identifier for this broker instance and
			*kafka_socket* is a specification similar to the
			[kafka socket syntax](#kafka_socket_syntax).


The *key=callid* property does not have an effect for
			brokers configured through this parameter.


This parameter can be set multiple times.


```c title="Set broker_id parameter"
...
modparam("event_kafka", "broker_id", "[k1]127.0.0.1:9092/topic1?g.linger.ms=100&t.acks=all")
...
```


### Exported Functions


#### kafka_publish(broker_id, message, [key], [report_route])


Publishes a message to a Kafka broker (or cluster). As the actual
			send operation is done in an asynchronous manner, a report route
			may be provided in order to check the message delivery status.


Returns *1* if the message was succesfully queued
			for sending or *-1* otherwise.


This function can be used from any route.


The function has the following parameters:


- *broker_id* (string) - the ID of the Kafka broker
					(or cluster).
					Must be one of the IDs defined through the
					[broker id](#param_broker_id) modparam.
- *message* (string) - the payload of the Kafka
					message to publish.
- *key* (string, optional) - the key of the Kafka
					record to publish.
- *report_route* (string, static, optional) -
					name of a script route to be executed when the message delivery
					status is available. Information about the message publishing will
					be available in this route through the following AVP variables:
					
					*$avp(kafka_id)* - broker ID
					*$avp(kafka_status)* - delivery status,
						0 if succesfull, -1 othewise
					*$avp(kafka_key)* - message key
					*$avp(kafka_msg)* - message payload


```c title="kafka_publish() function usage"
	...
	$var(msg) = "my msg content";
	kafka_publish("k1", $var(kmsg), $ci, "kafka_report");
	...
	route[kafka_report] {
		xlog("Delivery status: $avp(kafka_status) for broker: $avp(kafka_id)\n");
	}
	...
	
```


### Examples


```c title="Kafka socket"
	kafka:127.0.0.1:9092/topic1?t.message.timeout.ms=1000&key=callid
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
