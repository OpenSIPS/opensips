### OpenSIPS Config Script - EVENT_RABBITMQ usage

This configuration file presents the usage of the event_rabbitmq
module. In this scenario, a message is sent to a RabbitMQ server
everytime OpenSIPS receives a MESSAGE request. The parameters 
passed to the server are the R-URI username and the message
body.

[event_rabbitmq.cfg](./event_rabbitmq.cfg "include")

