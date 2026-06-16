---
title: "MSILO Module"
description: "This modules provides offline message storage for the Open SIP Server. It stores received messages for an offline user and sends them when the user becomes online."
---

## Admin Guide


### Overview


This modules provides offline message storage for the Open SIP Server. It 
		stores received messages for an offline user and sends them when the 
		user becomes online.


For each message, the modules stores "Request-URI" 
		("R-URI") only if it is a complete address of record 
		("username@hostname"), URI from "To" 
		header, URI from "From" header, incoming time,
		expiration time, content type and body of the message. If 
		"R-URI" is not an address of record (it might be the 
		contact address for current SIP session) the URI
		from "To" header will be used as R-URI.


When the expiration time passed, the message is discarded from 
		database.  Expiration time is computed based on incoming time and 
		one of the module's parameters.


Every time when a user registers with OpenSIPS, the module is looking in 
		database for offline messages intended for that user. All of them will 
		be sent to contact address provided in REGISTER request.


It may happen the SIP user to be registered but his SIP User Agent 
		to have no support for MESSAGE request. In this case it should be used 
		the "failure_route" to store the undelivered requests.


Another functionality provided by the modules is to send messages at
		a certain time -- the reminder functionality. Using config logic, a
		received message can be stored and delivered at a time specified while
		storing with the 'snd_time_avp'.


### Dependencies


#### OpenSIPS modules


The following modules must be loaded before this module:


- *database module* - mysql, dbtext or other 
				module that implements the "db" interface and 
				provides support for storing/receiving data to/from a 
				database system.
- *TM*--transaction module--is used to 
				send SIP requests.


#### External libraries or applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module:


- *none*.


### Exported Parameters


#### db_url (string)


Database URL.


*Default value is 
			"mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set the 'db_url' parameter"
...
modparam("msilo", "db_url", "mysql://user:passwd@host.com/dbname")
...
```


#### db_table (string)


The name of table where to store the messages.


*Default value is "silo".*


```c title="Set the 'db_table' parameter"
...
modparam("msilo", "db_table", "silo")
...
```


#### from_address (string)


The SIP address used to inform users that destination of their 
		message is not online and the message will be delivered next time 
		when that user goes online. If the parameter is not set, the module 
		will not send any notification. It can contain pseudo-variables.


*Default value is "NULL".*


```c title="Set the 'from_address' parameter"
...
modparam("msilo", "from_address", "sip:registrar@example.org")
modparam("msilo", "from_address", "sip:$rU@example.org")
...
```


#### contact_hdr (string)


The value of the Contact header (including header name and ending
		\r\n) to be added in notification messages.
		It can contain pseudo-variables.


*Default value is "NULL".*


```c title="Set the 'contact_hdr' parameter"
...
modparam("msilo", "contact_hdr", "Contact: <sip:null@example.com>\r\n")
...
```


#### offline_message (string)


The body of the notification message.
		It can contain pseudo-variables.


*Default value is "NULL".*


```c title="Set the 'offline_message' parameter"
...
modparam("msilo", "offline_message", "*** User $rU is offline!")
modparam("msilo", "offline_message", "<em>I am offline!</em>")
...
```


#### content_type_hdr (string)


The value of the Content-Type header (including header name and ending
		\r\n) to be added in notification messages. It must reflect what the
		'offline_message' contains.
		It can contain pseudo-variables.


*Default value is "NULL".*


```c title="Set the 'content_type_hdr' parameter"
...
modparam("msilo", "content_type_hdr", "Content-Type: text/plain\r\n")
modparam("msilo", "content_type_hdr", "Content-Type: text/html\r\n")
...
```


#### reminder (string)


The SIP address used to send reminder messages. If this value
		is not set, the reminder feature is disabled.


*Default value is "NULL".*


```c title="Set the 'reminder' parameter"
...
modparam("msilo", "reminder", "sip:registrar@example.org")
...
```


#### outbound_proxy (string)


The SIP address used as next hop when sending the message. Very
		useful when using OpenSIPS with a domain name not in DNS, or when
		using a separate OpenSIPS instance for msilo processing. If not set,
		the message will be sent to the address in destination URI.


*Default value is "NULL".*


```c title="Set the 'outbound_proxy' parameter"
...
modparam("msilo", "outbound_proxy", "sip:opensips.org;transport=tcp")
...
```


#### expire_time (int)


Expire time of stored messages - seconds. When this time passed, the message is
		silently discarded from database.


*Default value is "259200 (72 hours = 3 days)".*


```c title="Set the 'expire_time' parameter"
...
modparam("msilo", "expire_time", 36000)
...
```


#### check_time (int)


Timer interval to check if dumped messages are sent OK - seconds. The module keeps
		each request send by itself for a new online user and if the reply is 2xx then the
		message is deleted from database.


*Default value is "30".*


```c title="Set the 'check_time' parameter"
...
modparam("msilo", "check_time", 10)
...
```


#### send_time (int)


Timer interval in seconds to check if there are reminder messages.
		The module takes all reminder messages that must be sent at that moment 
		or before that moment.


If the value is 0, the reminder feature is disabled.


*Default value is "0".*


```c title="Set the 'send_time' parameter"
...
modparam("msilo", "send_time", 60)
...
```


#### clean_period (int)


Number of "check_time" cycles when to check if
		there are expired messages in database.


*Default value is "5".*


```c title="Set the 'clean_period' parameter"
...
modparam("msilo", "clean_period", 3)
...
```


#### use_contact (int)


Turns on/off the usage of the Contact address to send notification
		back to sender whose message is stored by MSILO.


*Default value is "1 (0 = off, 1 = on)".*


```c title="Set the 'use_contact' parameter"
...
modparam("msilo", "use_contact", 0)
...
```


#### sc_mid (string)


The name of the column in silo table, storing message id.


Default value is "mid".


```c title="Set the 'sc_mid' parameter"
...
modparam("msilo", "sc_mid", "other_mid")
...
```


#### sc_from (string)


The name of the column in silo table, storing the source address.


Default value is "src_addr".


```c title="Set the 'sc_from' parameter"
...
modparam("msilo", "sc_from", "source_address")
...
```


#### sc_to (string)


The name of the column in silo table, storing the destination address.


Default value is "dst_addr".


```c title="Set the 'sc_to' parameter"
...
modparam("msilo", "sc_to", "destination_address")
...
```


#### sc_uri_user (string)


The name of the column in silo table, storing the user name.


Default value is "username".


```c title="Set the 'sc_uri_user' parameter"
...
modparam("msilo", "sc_uri_user", "user")
...
```


#### sc_uri_host (string)


The name of the column in silo table, storing the domain.


Default value is "domain".


```c title="Set the 'sc_uri_host' parameter"
...
modparam("msilo", "sc_uri_host", "domain")
...
```


#### sc_body (string)


The name of the column storing the message body in silo table.


Default value is "body".


```c title="Set the 'sc_body' parameter"
...
modparam("msilo", "sc_body", "message_body")
...
```


#### sc_ctype (string)


The name of the column in silo table, storing content type.


Default value is "ctype".


```c title="Set the 'sc_ctype' parameter"
...
modparam("msilo", "sc_ctype", "content_type")
...
```


#### sc_exp_time (string)


The name of the column in silo table, storing the expire time of the message.


Default value is "exp_time".


```c title="Set the 'sc_exp_time' parameter"
...
modparam("msilo", "sc_exp_time", "expire_time")
...
```


#### sc_inc_time (string)


The name of the column in silo table, storing the incoming time of the message.


Default value is "inc_time".


```c title="Set the 'sc_inc_time' parameter"
...
modparam("msilo", "sc_inc_time", "incoming_time")
...
```


#### sc_snd_time (string)


The name of the column in silo table, storing the send time for the reminder.


Default value is "snd_time".


```c title="Set the 'sc_snd_time' parameter"
...
modparam("msilo", "sc_snd_time", "send_reminder_time")
...
```


#### snd_time_avp (str)


The name of an AVP which may contain the time when to sent
		the received message as reminder.The AVP is used ony by m_store().


If the parameter is not set, the module does not look for this AVP. If
		the value is set to a valid AVP name, then the module expects in the AVP
		to be a time value in format YYYYMMDDHHMMSS (e.g., 20060101201500).


*Default value is "null".*


```c title="Set the 'snd_time_avp' parameter"
...
modparam("msilo", "snd_time_avp", "$avp(snd_time)")
...
```


#### add_date (int)


Wheter to add as prefix the date when the message was stored.


*Default value is "1" (1==on/0==off).*


```c title="Set the 'add_date' parameter"
...
modparam("msilo", "add_date", 0)
...
```


#### max_messages (int)


Maximum number of stored message for an AoR.  Value 0
		equals to no limit.


*Default value is 0.*


```c title="Set the 'max_messages' parameter"
...
modparam("msilo", "max_messages", 0)
...
```


### Exported Functions


#### m_store([owner])


The method stores certain parts of the current SIP request (it 
		should be called when the request type is MESSAGE and the destination 
		user is offline or his UA does not support MESSAGE requests). If the 
		user is registered with a UA which does not support MESSAGE requests 
		you should not use mode="0" if you have
		changed the request uri with the contact address of user's UA.


Meaning of the parameters is as follows:


- *owner* (string, optional) - a SIP URI in whose
			inbox the message will be stored. If "owner" is missing,
			the SIP address is taken from R-URI.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE.


```c title="m_store usage"
...
m_store();
m_store($tu);
...
```


#### m_dump([owner], [maxmsg])


The method sends stored messages for the SIP user that is going to 
		register to his actual contact address. The method should be called 
		when a REGISTER request is received and the "Expire" 
		header has a value greater than zero.


Meaning of the parameters is as follows:


- *owner* (string, optional) - 
			a SIP URI whose inbox will be dumped. If "owner" is missing,
			the SIP address is taken from To URI.
- *maxmsg* (int, optional) - is a maximum number of messages
			to be dumped.


This function can be used from REQUEST_ROUTE, STARTUP_ROUTE,
		TIMER_ROUTE, EVENT_ROUTE


```c title="m_dump usage"
...
m_dump();
m_dump($fu);
m_dump($fu, 10);
...
```


### Exported Statistics


#### stored_messages


The number of messages stored by msilo.


#### dumped_messages


The number of dumped messages.


#### failed_messages


The number of failed dumped messages.


#### dumped_reminders


The number of dumped reminder messages.


#### failed_reminders


The number of failed reminder messages.


### Installation and Running


#### OpenSIPS config file


Next picture displays a sample usage of msilo.


[OpenSIPS config script - sample msilo usage](./samples.md "include")
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
