---
title: "event_sqs Module"
description: "The event_sqs module is an implementation of an Amazon SQS producer. It serves as a transport backend for the Event Interface and also provides a stand-alone connector to be used from the OpenSIPS script in order to publish messages to SQS queues. [https://aws.amazon.com/sqs/](https://aws.a..."
---

## Admin Guide


### Overview


The event_sqs module is an implementation of an Amazon SQS producer.
		It serves as a transport backend for the Event Interface and also provides a stand-alone
		connector to be used from the OpenSIPS script in order to publish messages to SQS queues.
		[https://aws.amazon.com/sqs/](https://aws.amazon.com/sqs/)


### Dependencies


#### OpenSIPS Modules


There is no need to load any module before this module.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *AWS SDK for C++:*
By following these steps, you'll have the AWS SDK for C++ installed and 
				configured on your Linux system, allowing you to integrate with SQS:
				[AWS SDK for C++ Installation Guide](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup-linux.html)
Additional instructions for installation can be found at:
				[AWS SDK for C++ GitHub Repository](https://github.com/aws/aws-sdk-cpp)


#### Deploying Amazon SQS locally on your computer


For testing purposes, you can run SQS locally. To achieve this, you start localstack on your computer:


```c
pip install localstack
localstack start
		
```


Don't forget to set the necessary environment variables for testing, for example:


```c
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
		
```


Here you can find some cli commands such as create-queue, send/receive-message, etc.:
		[https://docs.aws.amazon.com/cli/latest/reference/sqs/](https://docs.aws.amazon.com/cli/latest/reference/sqs/)


### Exported Parameters


#### queue_url (string)


This parameter specifies the configuration for an SQS queue that can be used
			to publish messages directly from the script, using the sqs_publish_message() function
			or to send messages using raise_event function.


The format of the parameter is: [ID]sqs_url, where ID is an identifier
		for this SQS queue instance and sqs_url is the full url of the queue.


The queue_url contains:


- *endpoint*
- *region*


This parameter can be set multiple times.


```c title="Set queue_url parameter"
...

modparam("event_sqs", "queue_url",
	  "[q1]https://sqs.us-west-2.amazonaws.com/123456789012/Queue1")

modparam("event_sqs", "queue_url",
	  "[q2]http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/Queue2")

...
		
```


### Exported Functions


#### sqs_publish_message(queue_id, message)


Publishes a message to an SQS queue. As the actual 
		send operation is done asynchronously, this function does not block and returns 
		immediately after queuing the message for sending.


This function can be used from any route.


The function has the following parameters:


- *queue_id (string)* The ID of the SQS queue. Must be one of the IDs defined through the `queue_url` modparam.
- *message (string)* - The payload of the message to publish.


```c title="sqs_publish_message() function usage"
...

$var(msg) = "Hello, this is a message to SQS!";
sqs_publish_message("q1", $var(msg));

...
		
```


### Examples


#### Event-Driven Messaging with *Event Interface*


OpenSIPS' event interface can be utilized to send messages to SQS by subscribing to an event and raising it when needed.


Steps:


- *Event Subscription:*
First, register the event subscription in your OpenSIPS configuration file within the `startup_route`:

  ```
  subscribe_event("MY_EVENT",
  	"sqs:http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/Queue2");
  		
  ```
- *Event Subscription via CLI:*
After starting OpenSIPS, you can subscribe to the event from another terminal using the OpenSIPS CLI:

  ```
  opensips-cli -x mi event_subscribe MY_EVENT \
  	  sqs:http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/Queue2
  		
  ```
- *Raise the Event and Send Message:*
Finally, to send a message, raise the subscribed event with the desired message content:

  ```
  opensips-cli -x mi raise_event MY_EVENT 'OpenSIPS Message'
  		
  ```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
