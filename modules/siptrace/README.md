---
title: "SipTrace Module"
description: "Offer a possibility to store incoming/outgoing SIP messages in database."
---

## Admin Guide


### Overview


Offer a possibility to store incoming/outgoing SIP messages in database.


There are two ways of storing information.


- by calling explicitely the sip_trace() method in OpenSIPS configuration
file. In this case the original message is processed.
- by setting the flag equal with the value of 'trace_flag' (e.g.,
setflag(__trace_flag__)) parameter of the module. In this case, the\
message sent forward is processed. The logging mechanism is based on
TM/SL callbacks, so only messages processed with TM/SL are logged.


The tracing can be turned on/off using fifo commad.


opensipsctl fifo sip_trace on


opensipsctl fifo sip_trace off


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *database module* - mysql, postrgress,
dbtext, unixodbc...
- *tm and sl modules* - optional, only if
you want to trace messages forwarded by these modules.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### db_url (str)


Database URL.


*Default value is "".*


```opensips title="Set db_url parameter"
...
modparam("siptrace", "db_url", "mysql://user:passwd@host/dbname")
...
```


#### trace_flag (integer)


Which flag is used to mark messages to trace


*Default value is "0".*


```opensips title="Set trace_flag parameter"
...
modparam("siptrace", "trace_flag", 22)
...
```


#### trace_on (integer)


Parameter to enable/disable trace (on(1)/off(0))


*Default value is "0".*


```opensips title="Set trace_on parameter"
...
modparam("siptrace", "trace_on", 1)
...
```


#### enable_ack_trace (integer)


Parameter to enable/disable tracing of statelessly received ACKs
(on(1)/off(0))


*Default value is "0".*


```opensips title="Set enable_ack_trace parameter"
...
modparam("siptrace", "enable_ack_trace", 1)
...
```


#### traced_user_avp (str)


The name of the AVP storing the SIP URI of the traced user. If
the AVP is set, messages are stored in database table and
'traced_user' column is filled with AVP's value. You can store
the message many times for many users by having multiple values
for this AVP.


*Default value is "NULL" (feature disabled).*


```opensips title="Set traced_user_avp parameter"
...
modparam("siptrace", "traced_user_avp", "$avp(123)")
modparam("siptrace", "traced_user_avp", "$avp(user)")
...
```


#### trace_table_avp (str)


The name of the AVP storing the name of the table where to
store the SIP messages. If it is not set, the value of
'table' parameter is used. In this way one can select
dynamically where to store the traced messages. The table
must exists, and must have the same structure as 'sip_trace'
table.


*Default value is "NULL" (feature disabled).*


```opensips title="Set trace_table_avp parameter"
...
modparam("siptrace", "trace_table_avp", "$avp(345)")
modparam("siptrace", "trace_table_avp", "$avp(siptrace_table)")
...
```


#### duplicate_uri (str)


The address in form of SIP uri where to send a duplicate
of traced message. It uses UDP all the time.


*Default value is "NULL".*


```opensips title="Set duplicate_uri parameter"
...
modparam("siptrace", "duplicate_uri", "sip:10.1.1.1:5888")
...
```


#### trace_local_ip (str)


The address to be used in fromip field for local generated
messages. If not set, the module sets it to the address
of the socket that will be used to send the message.


*Default value is "NULL".*


```opensips title="Set trace_local_ip parameter"
...
modparam("siptrace", "trace_local_ip", "10.1.1.1:5064")
...
```


#### table (str)


Name of the table where to store the SIP messages.


*Default value is "sip_trace".*


```opensips title="Set sip_trace parameter"
...
modparam("siptrace", "table", "strace")
...
```


### Exported Functions


#### sip_trace()


Store current processed SIP message in database. It is stored in the
form prior applying chages made to it.


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE, ONREPLY_ROUTE, BRANCH_ROUTE.


```opensips title="sip_trace() usage"
...
sip_trace();
...
```


#### trace_dialog()


The function triggers the tracing of all messages belonging to a
dialog. The function must be called for the initial request (that 
starts the dialog) and it will automatically take care of tracing
evertyhing related to that dialog.


When using this function, you do not have to explicity set any tracing
flag or to explicitly call anothe trace function.


This function can be used from REQUEST_ROUTE.


```opensips title="trace_dialog() usage"
...
if(is_method("INVITE") && !has_totag())
	trace_dialog();
...
```


#### trace_to_database (integer)


Parameter to enable/disable inserts to the Database from this
OpenSIPS.


In case we only want to send the SIP-Messages to the
duplicate_uri and not store the information to the local
database we can set this to "0".


*Default value is "1".*


```opensips title="Set trace_to_databaseparameter"
...
modparam("siptrace", "trace_to_database", 0)
...
```


#### duplicate_with_hep (integer)


Parameter to enable/disable homer encapsulate mode
(on(1)/off(0))


*Default value is "0".*


```opensips title="Set duplicate_with_hep parameter"
...
modparam("siptrace", "duplicate_with_hep", 1)
...
```


#### hep_version (integer)


The parameter indicate the version of HEP protocol. 
Can be 1 or 2. In HEPv2 the timestamp and capture agent ID will
be included to HEP header.


*Default value is "1".*


```opensips title="Set hep_version parameter"
...
modparam("siptrace", "hep_version", 2)
...
```


#### hep_capture_id (integer)


The parameter indicate the capture agent ID for HEPv2 protocol. 
Limitation: 16-bit integer.


*Default value is "1".*


```opensips title="Set hep_capture_id parameter"
...
modparam("siptrace", "hep_capture_id", 234)
...
```


### Exported MI Functions


#### sip_trace


Name: *sip_trace*


Parameters:


- trace_mode : turns on/off SIP message tracing.
Possible values are:

  - on
  - off
The parameter is optional - if missing, the command will
return the status of the SIP message tracing (as string 
"on" or "off" ) without changing
anything.


MI FIFO Command Format:


```bash
		:sip_trace:_reply_fifo_file_
		trace_mode
		_empty_line_
		
```


#### trace_to_database


Name: *trace_to_database*


Parameters:


- trace_to_db_mode : turns on/off SIP message tracing into DB.
Possible values are:

  - on
  - off
The parameter is optional - if missing, the command will
return the status of the SIP message tracing (as string 
"on" or "off" ) without changing
anything. The parameter can be switched from off to on, 
if db connection was before inizialized


MI FIFO Command Format:


```bash
		:trace_to_database:_reply_fifo_file_
		trace_to_db_mode
		_empty_line_
		
```


### Database setup


Before running OpenSIPS with siptrace, you have to setup the database 
tables where the module will store the data. For that, if the 
table were not created by the installation script or you choose
to install everything by yourself you can use the siptrace-create.sql
SQL script in the database directories in the 
opensips/scripts folder as template. 
You can also find the complete database documentation on the
project webpage, [http://www.opensips.org/html/docs/db/db-schema-devel.html](http://www.opensips.org/html/docs/db/db-schema-devel.html).


### Known Issues


Stateless forwarded messages (forward()) are not logged if you set the
flag, use sip_trace().
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
