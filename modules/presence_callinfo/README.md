---
title: "Presence_CallInfo Module"
description: "The module enables the handling of \"call-info\" and \"line-seize\" events inside the presence module. It is used with the general event handling module: presence and it constructs and adds \"Call-Info\" headers to notification events. To send \"call-info\" notification to wat..."
---

## Admin Guide


### Overview


The module enables the handling of "call-info" and "line-seize"
events inside the presence module.
It is used with the general event handling module: presence and
it constructs and adds "Call-Info" headers to notification events.
To send "call-info" notification to watchers, a third-party
application must publish "call-info" events to the presence server.


The module does not currently implement any authorization
rules.  It assumes that publish requests are only issued by
a third-party application and subscribe requests only by
subscriber to call-info and line-seize events.  Authorization
can thus be easily done by OpenSIPS configuration file before
calling handle_publish() and handle_subscribe() functions.


The module implements a simple check for the presence of
Call-Info headers in received PUBLISH requests.


To get better understanding on how the module works please take a
look at the follwing figure:


```c
   caller       proxy &   callee        watcher        publisher
alice@example  presence  bob@example  watcher@example
                 server                       
     |             |           |           |              |
     |             |<-----SUBSCRIBE bob----|              |
     |             |------200 OK---------->|              |
     |             |------NOTIFY---------->|              |
     |             |<-----200 OK-----------|              |
     |             |           |           |              |
     |--INV bob--->|           |           |              |
     |             |--INV bob->|           |              |
     |             |<-100------|           |              |
     |             |<-----PUBLISH(alerting)---------------|
     |             |------200 OK------------------------->|
     |             |------NOTIFY---------->|              |
     |             |<-----200 OK-----------|              |
     |             |           |           |              |
     |             |<-180 ring-|           |              |
     |<--180 ring--|           |           |              |
     |             |           |           |              |
     |             |           |           |              |
     |             |<-200 OK---|           |              |
     |<--200 OK----|           |           |              |
     |             |<-----PUBLISH(active)-----------------|
     |             |------200 OK------------------------->|
     |             |------NOTIFY---------->|              |
     |             |<-----200 OK-----------|              |
     |             |           |           |              |

	
```


- The watcher subscribes the "Event: dialog" of Bob.
- Alice calls Bob.
- The publisher is publishing the "alerting" state for Bob.
- PUBLISH is received and handled by presence module.
Presence module updates the "presentity".
Presence module checks for active watchers of the presentity.
The active watcher is notified via a NOTIFY SIP request.
- Bob answers the call.
- The publisher is publishing the "active" state for Bob.
- PUBLISH is received and handled by presence module.
Presence module updates the "presentity".
Presence module checks for active watchers of the presentity.
The active watcher is notified via a NOTIFY SIP request.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *presence*.


#### External Libraries or Applications


None.


### Exported Parameters


#### call_info_timeout_notification (int)


Enables or disables call_info event timeout notifications.


*Default value is "1"* (enabled).


```opensips title="Set call_info_timeout_notification parameter"
...
modparam("presence_callinfo", "call_info_timeout_notification", 0)
...
		
```


#### line_seize_timeout_notification (int)


Enables or disables line_seize event timeout notifications.


*Default value is "0"* (disabled).


```opensips title="Set line_seize_timeout_notification parameter"
...
modparam("presence_callinfo", "line_seize_timeout_notification", 1)
...
		
```


### Exported Functions


None to be used in configuration file.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
