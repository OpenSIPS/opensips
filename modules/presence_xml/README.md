---
title: "Presence_XML Module"
description: "The module does specific handling for notify-subscribe events using xml bodies."
---

## Admin Guide


### Overview


The module does specific handling for notify-subscribe events using xml bodies.
It is used with the general event handling module, presence. It constructs and adds
3 events to it: presence, presence.winfo, dialog;sla.


This module takes the xcap permission rule documents from xcap_table.

The presence permission rules are interpreted according to the specifications
in RFC 4745 and RFC 5025.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *presence*.
- *sl*.
- *xcap_client*.
Only compulsory if not using an integrated xcap server 
(if 'integrated_xcap_server' parameter is not set).


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libxml-dev*.


### Exported Parameters


#### db_url(str)


The database url.


*Default value is "mysql://opensips:opensipsrw@localhost/osips".*


```opensips title="Set db_url parameter"
...
modparam("presence_xml", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### xcap_table(str)


The name of the db table where XCAP documents are stored.


*Default value is "xcap".*


```opensips title="Set xcap_table parameter"
...
modparam("presence_xml", "xcap_table", "xcaps")
...
```


#### force_active (int)


This parameter is used for permissions when handling Subscribe messages.
If set to 1, subscription state is considered active and the presentity
is not queried for permissions(should be set to 1 if not using an xcap 
server). 
Otherwise,the xcap server is queried and the subscription states is
according to user defined permission rules. If no rules are defined for
a certain watcher, the subscriptions remains in pending state and the
Notify sent will have no body.


> [!NOTE]
> When switching from one value to another, the watchers table must be emptied.


*Default value is "0".*


```opensips title="Set force_active parameter"
...
modparam("presence_xml", "force_active", 1)
...
```


#### pidf_manipulation (int)


Setting this parameter to 1 enables the features described in RFC 4827.
It gives the possibility to have a permanent state notified to the users
even in the case in which the phone is not online. The presence document
is taken from the xcap server and aggregated together with the other
presence information, if any exist, for each Notify that is sent to the
watchers. It is also possible to have information notified even if not 
issuing any Publish (useful for services such as email, SMS, MMS).


*Default value is "0".*


```opensips title="Set pidf_manipulation parameter"
...
modparam("presence_xml", "pidf_manipulation", 1)
...
```


#### integrated_xcap_server (int)


This parameter is a flag for the type of XCAP server or servers 
used. If integrated ones, like XCAP-lite from AG Projects, 
with direct access to database table, the parameter should be
set to a positive value. Apart from updating in xcap table,
the integrated server must send an MI command refershWatchers 
[pres_uri] [event] when a user modifies a rules document.


Otherwise, it uses xcap_client module to fetch documents 
from the XCAP servers with HTTP requests.


*Default value is "0".*


```opensips title="Set integrated_xcap_server parameter"
...
modparam("presence_xml", "integrated_xcap_server", 1)
...
```


#### xcap_server (str)


The address of the xcap servers used for storage.
This parameter is compulsory if the integrated_xcap_server parameter
is not set. It can be set more that once, to construct an address
list of trusted XCAP servers.


```opensips title="Set xcap_server parameter"
...
modparam("presence_xml", "xcap_server", "xcap_server.example.org")
modparam("presence_xml", "xcap_server", "xcap_server.ag.org")
...
```


### Exported Functions


None to be used in configuration file.


### Installation


The module requires 1 table in OpenSIPS database: xcap. The SQL 
syntax to create it can be found in presence-create.sql     
script in the database directories in the opensips/scripts folder.
You can also find the complete database documentation on the
project webpage, http://www.opensips.org/html/docs/db/db-schema-1.4.x.html.


## Developer Guide


The module exports no function to be used in other OpenSIPS modules.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
