---
title: "B2B_ENTITIES"
description: "The B2BUA implementation in OpenSIPS is separated in two layers: a lower one(coded in this module)- which implements the basic functions of a UAS and UAC a upper one - which represents the logic engine of B2BUA, responsible of actually implementing the B2BUA services using ..."
---

## Admin Guide


### Overview


The B2BUA implementation in OpenSIPS is separated in two layers:


- a lower one(coded in this module)- which implements the basic functions of a UAS and UAC
- a upper one - which represents the logic engine of B2BUA, responsible of actually
			implementing the B2BUA services using the functions offered by the low level.


This module stores records corresponding to the dialogs in which the B2BUA
		is involved. It exports an API to be called from other modules which offers functions for
		creating a new dialog record, for sending requests or replies in one dialog and will also
		notify the upper level module when a request or reply is received inside one stored dialog.

		The records are separated in two types: b2b server entities and b2b client entities depending
		on the mode they are created. An entity created for a received initial message will be a server entity,
		while a entity that will send an initial request(create a new dialog) will be a b2b client entity.
		The name corresponds to the behavior in the first transaction - if UAS - server entity and if UAC - client entity.

		This module does not implement a B2BUA alone, but needs a B2B logic implementing module.


The module is able to respond to authentication challanges if the
		uac_auth module is loaded first.  The list of credentials for
		b2b authentication is also provided by the uac_auth module.


### Dependencies


#### OpenSIPS Modules


- *tm*
- *a db module*
- *uac_auth*
				(mandatory if authentication is required)


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *none*


### Exported Parameters


#### server_hsize (int)


The size of the hash table that stores the b2b server entities.
			It is the 2 logarithmic value of the real size.


*Default value is "9"*
		 (512 records).


```opensips title="Set server_hsize parameter"
...
modparam("b2b_entities", "server_hsize", 10)
...
	
```


#### client_hsize (int)


The size of the hash table that stores the b2b client entities.
			It is the 2 logarithmic value of the real size.


*Default value is "9"*
		 (512 records).


```opensips title="Set client_hsize parameter"
...
modparam("b2b_entities", "client_hsize", 10)
...
	
```


#### script_req_route (str)


The name of the b2b script route that will be called when
			B2B requests are received.


```opensips title="Set script_req_route parameter"
...
modparam("b2b_entities", "script_req_route", "b2b_request")
...
	
```


#### script_reply_route (str)


The name of the b2b script route that will be called when
			B2B replies are received.


```opensips title="Set script_repl_route parameter"
...
modparam("b2b_entities", "script_reply_route", "b2b_reply")
...
	
```


#### db_url (str)


Database URL. It is not compulsory, if not set
			data is not stored in database.


```opensips title="Set db_url parameter"
...
modparam("b2b_entities", "db_url", "mysql://opensips:opensipsrw@127.0.0.1/opensips")
...
	
```


#### cachedb_url (str)


URL of a NoSQL database to be used. Only Redis is supported
			at the moment.


```opensips title="Set cachedb_url parameter"
...
modparam("b2b_entities", "cachedb_url", "redis://localhost:6379/")
...
	
```


#### cachedb_key_prefix (string)


Prefix to use for every key set in the NoSQL database.


*Default value is "b2be$".*


```opensips title="Set cachedb_key_prefix parameter"
...
modparam("b2b_entities", "cachedb_key_prefix", "b2b")
...
```


#### update_period (int)


The time interval at which to update the info in database.


*Default value is "100".*


```opensips title="Set update_period parameter"
...
modparam("b2b_entities", "update_period", 60)
...
	
```


#### b2b_key_prefix (string)


The string to use when generating the key ( it is inserted
			in the SIP messages as callid or to tag. It is useful to set
			this prefix if you use more instances of opensips B2BUA cascaded
			in the same architecture. Sometimes opensips B2BUA looks at the
			callid or totag to see if it has the format it uses to determine
			if the request was sent by it.


*Default value is "B2B".*


```opensips title="Set b2b_key_prefix parameter"
...
modparam("b2b_entities", "b2b_key_prefix", "B2B1")
...
	
```


#### db_mode (int)


The B2B modules have support for the 3 type of database storage


- NO DB STORAGE - set this parameter to 0
- WRITE THROUGH (synchronous write in database) - set this parameter to 1
- WRITE BACK (update in db from time to time) - set this parameter to 2


*Default value is "2" (WRITE BACK).*


```opensips title="Set db_mode parameter"
...
modparam("b2b_entities", "db_mode", 1)
...
	
```


#### db_table (str)


The name of the table that will be used for storing B2B entities


*Default value is "b2b_entities"*


```opensips title="Set db_table parameter"
...
modparam("b2b_entities", "db_table", "some table name")
...
	
```


#### cluster_id (int)


The ID of the cluster this instance belongs to. Setting this parameter
		enables clustering support for the OpenSIPS B2BUA by replicating the
		B2B entities (B2B dialogs) between instances. This also ensures restart
		persistency through the *clusterer* module's
		data "sync" mechanism.


This OpenSIPS cluster exposes the **"b2be-entities-repl"**
capability in order to mark nodes as eligible for becoming data donors during an
arbitrary sync request. Consequently, the cluster must have *at least
one node* marked with the **"seed"** value
as the *clusterer.flags* column/property in order to be fully functional.
Consult the [clusterer - Capabilities](../clusterer#capabilities)
chapter for more details.


*Default value is "0" (clustering disabled)*


```opensips title="Set cluster_id parameter"
...
modparam("b2b_entities", "cluster_id", 10)
...
	
```


#### passthru_prack (int)


This parameter allows to control, whether a PRACK should be generated locally (=0)
		or if we request it to be end-to-end (=1).


*Default value is "0" (generate PRACK locally)*


```opensips title="Set passthru_prack parameter"
...
modparam("b2b_entities", "passthru_prack", 1)
...
	
```


#### advertised_contact (str)


Contact to use in generated messages for UA session started with the
		[mi ua session client start](#mi_ua_session_client_start) MI function.


```opensips title="Set advertised_contact parameter"
...
modparam("b2b_entities", "advertised_contact", "opensips@10.10.10.10:5060")
...
	
```


#### ua_default_timeout (str)


Default timeout, in seconds, for UA session started with the
		[ua session server init](#func_ua_session_server_init) function or the
		[mi ua session client start](#mi_ua_session_client_start) MI function. After this
		interval a BYE will be sent and the session will be deleted.


If not set the default is 43200 (12 hours).


```opensips title="Set ua_default_timeout parameter"
...
modparam("b2b_entities", "ua_default_timeout", 7200)
...
	
```


### Exported Functions


#### ua_session_server_init([key], [flags], [extra_params])


This function initializes a new UA session by processing an initial INVITE.
		Further requests/replies received belonging to this session will only
		be handled via the [E UA SESSION](#event_e_ua_session) event.


Parameters:


- *key (var, optional)* - Variable to return the
				b2b entity key of the new UA session.
- *flags (string, optional)* - configures options
				for this UA session via the following flags:
				
					*t[nn]* - maximum duration of
					this session in seconds. After this timeout a BYE
					will be sent and the session will be deleted. If this
					is not set, the default timeout, configured with
					[ua default timeout](#param_ua_default_timeout) will be used.
					Example: *t3600*
					*a* - report the receving of ACK requests
					via the [E UA SESSION](#event_e_ua_session) event.
					*r* - report the receving of replies via
					the [E UA SESSION](#event_e_ua_session) event.
					*d* - disable the automatic sending of ACK
					upon receving a 200 OK reply for INVITE (in case of UAC session)
					or re-INVITE.
					*h* - provide the headers of the SIP request/reply
					in the [E UA SESSION](#event_e_ua_session) event.
					*b* - provide the body of the SIP request/reply
					in the [E UA SESSION](#event_e_ua_session) event.
					*n* - do not trigger the
					[E UA SESSION](#event_e_ua_session) event (with event_type
					*NEW*)  for initial INVITES
					handled with this function.
- *extra_params (string, optional)* - An arbitrary
				value to be passed to the *extra_params* parameter
				in the [E UA SESSION](#event_e_ua_session) event.


This function can be used from REQUEST_ROUTE.


```opensips title="ua_session_server_init usage"
...
if(is_method("INVITE") && !has_totag()) {
   ua_session_server_init($var(b2b_key), "arhb");

   ua_session_reply($var(b2b_key), "INVITE", 200, "OK", $var(my_sdp));
   
   exit;
}
...
		
```


#### ua_session_update(key, method, [body], [extra_headers], [content_type])


Sends a sequential request for a UA session started with the 
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Parameters:


- *key (string)* - b2b entity key of the UA session.
- *method (string)* - name of the SIP method for this
				request.
- *body (string, optional)* - body to include in the
				SIP message.
- *extra_headers (string, optional)* - extra headers
				to include in the SIP message.
- *content_type (string, optional)* - Content-Type
				header. If the parameter is missing and a body is provided,
				"Content-Type: application/sdp" will be used.


This function can be used from REQUEST_ROUTE, EVENT_ROUTE.


```opensips title="ua_session_update usage"
...
ua_session_update($var(b2b_key), "OPTIONS");
...
		
```


#### ua_session_reply(key, method, code, [reason], [body], [extra_headers], [content_type])


Sends a reply for a UA session started with the 
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Parameters:


- *key (string)* - b2b entity key of the UA session.
- *method (string)* - name of the SIP method that is
				replied to.
- *code (int)* - reply code.
- *reason (string, optional)* - reply reason string.
- *body (string, optional)* - body to include in the
				SIP message.
- *extra_headers (string, optional)* - extra headers
				to include in the SIP message.
- *content_type (string, optional)* - Content-Type header.
				If the parameter is missing and a body is provided,
				"Content-Type: application/sdp" will be used.


This function can be used from REQUEST_ROUTE, EVENT_ROUTE.


```opensips title="ua_session_reply usage"
...
ua_session_reply($var(b2b_key), "INVITE", 180, "Ringing");
...
		
```


#### ua_session_terminate(key, [extra_headers])


Terminate a UA session started with the
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Parameters:


- *key (string)* - b2b entity key of the UA session.
- *extra_headers (string, optional)* - extra headers
				to include in the SIP message


This function can be used from REQUEST_ROUTE, EVENT_ROUTE.


```opensips title="ua_session_terminate usage"
...
ua_session_terminate($var(b2b_key));
...
		
```


### Exported MI Functions


#### b2b_entities:list


Replaces obsolete MI command: *b2be_list*.


This command can be used to list the internals of the b2b entities.


Name: *b2b_entities:list*


Parameters: *none*


MI FIFO Command Format:


```bash
	opensips-cli -x mi b2b_entities:list
	
```


#### ua_session_client_start


This command starts a new UAC session by sending an initial INVITE.
		Further requests/replies received belonging to this session will only
		be handled via the [E UA SESSION](#event_e_ua_session) event.


Name: *ua_session_client_start*


Parameters:


- *ruri* - Request URI
- *to* - To URI; can also be specified as:
				*display_name,uri* in order to set a Display Name,
				eg. *Alice,sip:alice@opensips.org*.
- *from* - From URI; can also be specified as:
				*display_name,uri* in order to set a Display Name,
				eg. *Alice,sip:alice@opensips.org*
- *proxy (optional)* - URI of the
				outbound proxy to send the INVITE to
- *body (optional)* - message body
- *content_type (optional)* - Content Type
				header to use. If missing and a body is provided,
				"Content-Type: application/sdp" will be used.
- *extra_headers (optional)* - extra headers
- *flags (optional)* - flags with the same meaning
				as for the *flags* paramater of
				[ua session server init](#func_ua_session_server_init).
- *socket (optional)* - OpenSIPS sending socket


opensips-cli Command Format:


```bash
opensips-cli -x mi ua_session_client_start ruri=sip:bob@opensips.org \
to=sip:bob@opensips.org from=sip:alice@opensips.org flags=arhb
```


#### ua_session_update


Sends a sequential request for a UA session started with the
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Name: *ua_session_update*


Parameters:


- *key* - b2b entity key of the UA session.
- *method* - name of the SIP method for this
				request.
- *body (optional)* - body to include in the
				SIP message.
- *extra_headers (optional)* - extra headers
				to include in the SIP message.
- *content_type (string)* - Content-Type header.
				If the parameter is missing and a body is provided,
				"Content-Type: application/sdp" will be used.


opensips-cli Command Format:


```bash
opensips-cli -x mi ua_session_update key=B2B.436.1925389.1649338095 method=OPTIONS
```


#### ua_session_reply


Sends a reply for a UA session started with the
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Name: *ua_session_reply*


Parameters:


- *key* - b2b entity key of the UA session.
- *method* - name of the SIP method that is
				replied to.
- *code* - reply code
- *reason* - reply reason string
- *body (optional)* - body to include in the
				SIP message
- *extra_headers (optional)* - extra headers
				to include in the SIP message
- *content_type (optional)* - Content-Type header.
				If the parameter is missing and a body is provided,
				"Content-Type: application/sdp" will be used.


opensips-cli Command Format:


```bash
opensips-cli -x mi ua_session_reply key=B2B.436.1925389.1649338095 method=OPTIONS code=200 reason=OK
```


#### ua_session_terminate


Terminate a UA session started with the
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Name: *ua_session_terminate*


Parameters:


- *key* - b2b entity key of the UA session.
- *extra_headers (optional)* - extra headers
				to include in the SIP message


opensips-cli Command Format:


```bash
opensips-cli -x mi ua_session_terminate key=B2B.436.1925389.1649338095
```


#### ua_session_list


List information about UA sessions started with
		[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Name: *ua_session_list*


Parameters:


- *key (optional)* - b2b entity key of the UA session
				to list. If missing, all sessions will be listed.


MI FIFO Command Format:


```bash
	opensips-cli -x mi ua_session_list
	
```


### Exported Events


#### E_UA_SESSION


This event is triggered for requests/replies belonging to an ongoing UA
			session started with the
			[ua session server init](#func_ua_session_server_init) function or
		the [mi ua session client start](#mi_ua_session_client_start) MI function.


Note that replies will not be reported at all unless the
			*r* flag was set when initiating the UA session. Also
			ACK requests are only reported if the *a* flag was set.


Parameters:


- *key* - b2b entity key of the UA session.
- *entity_type* - indicates whether this is a
				*UAS* or *UAc* entity.
- *event_type* - the type of event:
				
					*NEW* - for initial INVITE requests,
						handled with the [ua session server init](#func_ua_session_server_init)
						function.
					*EARLY* - for 1xx provisional
						responses
					*ANSWERED* - for 2xx successful
						responses
					*REJECTED* - for 3xx-6xx failure
						responses
					*UPDATED* - for any sequential requests,
						including ACK but excluding BYE/CANCEL
					*TERMINATED* - for BYE or CANCEL
						requests
- *status* - the reply status code if the message is
				a SIP reply
- *reason* - the reply reason if the message is
				a SIP reply
- *method* - the SIP method name
- *body* - SIP message body
- *headers* - full list of all SIP headers in the
				message.
- *extra_params* - an arbitrary value. Currently only
				the [ua session server init](#func_ua_session_server_init) function passes this
				if the *extra_params* argument is used, and it only
				appears in the *NEW* event_type.


## Developer Guide


The module provides an API that can be used from other
		OpenSIPS modules. The API offers the functions for creating and handing dialogs.
		A dialog can be created on a receipt initial message, and this will correspond to
		a b2b server entity, or initiated by the server and in this case a client entity
		will be created in b2b_entities module.


### b2b_load_api(b2b_api_t* api)


This function binds the b2b_entities modules and fills the structure 
				the exported functions that will be described in detail.


```c title="b2b_api_t structure"
...
typedef struct b2b_api {
	b2b_server_new_t          server_new;
	b2b_client_new_t          client_new;

	b2b_send_request_t        send_request;
	b2b_send_reply_t          send_reply;

	b2b_entity_delete_t       entity_delete;

	b2b_restore_linfo_t       restore_logic_info;
	b2b_update_b2bl_param_t   update_b2bl_param;
}b2b_api_t;
...
```


### server_new


Field type:


```opensips
...
typedef str* (*b2b_server_new_t) (struct sip_msg* , str* local_contact,
		b2b_notify_t , str *mod_name, str* logic_key, struct b2b_tracer *tracer,
		void *param, b2b_param_free_cb free_param);
...
```


This function asks the b2b_entities modules to create a new server 
			entity record. The internal processing actually extracts the dialog information
			from the message and constructs a record that will be stored in a hash table.
			The second parameters is a pointer to a function that the b2b_entities module
			will call when a event will come for that dialog (a request or reply). The third
			parameter is a pointer to a value that will be stored and given as a parameter
			when the notify function will be called(it has to be allocated in shared memory).


The return value is an identifier for the record that will be mentioned when 
			calling other functions that represent actions in the dialog(send request,
			send reply).


The notify function has the following prototype:


```c
...
typedef int (*b2b_notify_t)(struct sip_msg* msg, str* id, int type, void* param);
...
```


This function is called when a request or reply is received for a dialog 
		handled by b2b_entities. The first parameter is the message, the second is the
		identifier for the dialog, the third is a flag that says which is the type of
		the message(it has two possible values - B2B_REQUEST and B2B_REPLY). The last
		parameter is the parameter by the upper module when the entity was created.


### client_new


Field type:


```c
...
typedef str* (*b2b_client_new_t) (client_info_t* , b2b_notify_t b2b_cback,
				b2b_add_dlginfo_t add_dlginfo_f, str *mod_name, str *logic_key,
				struct b2b_tracer *tracer, void *param, b2b_param_free_cb free_param);
...
```


This function asks the b2b_entities modules to create a new client 
			entity record and also create a new dialog by sending an initial message. 
			The parameters are all the values needed for the initial request to which
			the notify function and parameter are added.
			The b2b_cback parameter is a pointer to the callback that must be called when
			an event happens(receiving a reply or request) in the dialog created with
			this function.
			The add_dlginfo_f parameter is also a function pointer to a callback that will
			be called when a final success response will be received for the created dialog.
			The callback will receive as parameter the complete dialog information for the
			record. It should be stored and used when calling send_request or send_reply functions.


The return value is an identifier for the record that will be mentioned when 
			calling other functions that represent actions in the dialog(send request,
			send reply).


### send_request


Field type:


```c
...
typedef int (*b2b_send_request_t)(enum b2b_entity_type ,str* b2b_key, str* method,
		str* extra_headers, str* body, b2b_dlginfo_t*);
...
```


This function asks the b2b_entities modules to send a request inside a b2b dialog
			identified by b2b_key. The first parameter is the entity type and can have two values:
			B2B_SERVER and B2B_CLIENT. The second is the identifier returned by the create 
			function(server_new or client_new) and the next are the informations needed for
			the new request: method, extra_headers, body.
			The last parameter contains the dialog information - callid, to tag, from tag. These
			are needed to make a perfect match to of b2b_entities record for which a new request
			must be sent.


The return value is 0 for success and a negative value for error.


### send_reply


Field type:


```c
...
typedef int (*b2b_send_reply_t)(enum b2b_entity_type et, str* b2b_key, int code, str* text,
		str* body, str* extra_headers, b2b_dlginfo_t* dlginfo);
...
```


This function asks the b2b_entities modules to send a reply inside a b2b dialog
			identified by b2b_key. The first parameter is the entity type and can have two values:
			B2B_SERVER and B2B_CLIENT. The second is the identifier returned by the create 
			function(server_new or client_new) and the next are the informations needed for
			the new reply: code, text, body, extra_headers. The last parameter contains the
			dialog information used for matching the right record.


The return value is 0 for success and a negative value for error.


### entity_delete


Field type:


```c
...
typedef void (*b2b_entity_delete_t)(enum b2b_entity_type et, str* b2b_key,
	 b2b_dlginfo_t* dlginfo);
...
```


This function must be called by the upper level function to delete the
		records in b2b_entities. The records are not cleaned up by the b2b_entities
		module and the upper level module must take care to delete them.


### restore_logic_info


Field type:


```c
...
typedef int (*b2b_restore_linfo_t)(enum b2b_entity_type type, str* key,
		b2b_notify_t cback, void *param, b2b_param_free_cb free_param);
...
```


This function is used at startup when loading the data from the database to
			restore the pointer to the callback function.


### update_b2bl_param


Field type:


```c
...
typedef int (*b2b_update_b2bl_param_t)(enum b2b_entity_type type, str* key,
		str* param, int replicate);
...
```


This function can be used to change the logic param stored for an 
			entity ( useful in case an entity is moved between logic records).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
