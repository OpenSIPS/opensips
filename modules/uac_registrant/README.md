---
title: "UAC Registrant Module"
description: "The module enable OpenSIPS to register itself on a remote SIP registrar."
---

## Admin Guide


### Overview


The module enable OpenSIPS to register itself on a remote SIP registrar.


At startup, the registrant records are loaded into
		a hash table in memory and a timer is started.
		The hash index is computed over the AOR field.


The timer interval for checking records in a hash bucket is computed
		by dividing the timer_interval module param by the number of hash buckets.
		When the timer fires for the first time, the first hash bucket will be checked and
		REGISTERs will be sent out for each record that is found.
		On the next timeout fire, the second hash bucket will be checked and so on.
		If the configured timer_interval module param is lower then the number of buckets,
		the module will fail to start.


Example: setting the timer_interval module to 8 with a hash_size of 2, will result
	    in having 4 hash buckets (2^2=4) and buckets will be checked one by one every 2s (8/4=2).


Each registrant has it's own state.
	    Registrant's status can be inspected via "uac_registrant:list" MI command.


UAC registrant states:


- *0*
				- NOT_REGISTERED_STATE -
				the initial state (no REGISTER has been sent out yet);
- *1*
				- REGISTERING_STATE - waiting for a reply from the registrar
				after a REGISTER without authentication header was sent;
- *2*
				- AUTHENTICATING_STATE - waiting for a reply from the registrar
			 	after a REGISTER with authentication header was sent;
- *3*
				- REGISTERED_STATE - the uac is successfully registered;
- *4*
				- REGISTER_TIMEOUT_STATE :
				no reply received from the registrar;
- *5*
				- INTERNAL_ERROR_STATE -
				some errors were found/encountered during the
				processing of a reply;
- *6*
				- WRONG_CREDENTIALS_STATE -
				credentials rejected by the registrar;
- *7*
				- REGISTRAR_ERROR_STATE -
				error reply received from the registrar;
- *8*
				- UNREGISTERING_STATE - waiting for a reply from the registrar
				after an unREGISTER without authentication header was sent;
- *9*
				- AUTHENTICATING_UNREGISTER_STATE - waiting for a reply from the registrar
				after an unREGISTER with authentication header was sent;


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *uac_auth - UAC authentication module*


#### External Libraries or Applications


None.


### Exported Parameters


#### hash_size (integer)


The size of the hash table internally used to keep the registrants.
		A larger table distributes better the registration load in time but consumes more memory.
		The hash size is a power of number two.


*Default value is 1.*


```opensips title="Set hash_size parameter"
...
modparam("uac_registrant", "hash_size", 2)
...
```


#### timer_interval (integer)


Defines the periodic timer for checking the registrations status.


*Default value is 100.*


```opensips title="Set timer_interval parameter"
...
modparam("uac_registrant", "timer_interval", 120)
...
```


#### failure_retry_interval (integer)


Defines a custom interval to retry the registration upon error/failure.
		Normally, after any kind of failure (timeout, credentials, internal 
		error), the registration is re-taken after "expires" seconds. The 
		parameter here, if set, overrides that value.


*Default value is 0 (not set).*


```opensips title="Set failure_retry_interval parameter"
...
modparam("uac_registrant", "failure_retry_interval", 3600)
...
```


#### enable_clustering (integer)


This parameter enables the clustering support in the module. This is
		used to share this registration between all the nodes in the cluster.
		When using this option, you should define (for each registrant record)
		a sharing tag - this sharing tag will control at the cluster level
		which node is entitled to perform the registation (only the node having
		that tag as active will do the registation, the onther nodes being
		idle).


*Default value is 0 / off.*


```opensips title="Set enable_clustering parameter"
...
modparam("uac_registrant", "enable_clustering", 1)
...
```


#### db_url (string)


Database where to load the registrants from.


*Default value is "NULL" (use default DB URL from core).*


```opensips title="Set 'db_url' parameter"
...
modparam("uac_registrant", "db_url", "mysql://user:passw@localhost/database")
...
```


#### table_name (string)


The database table that holds the registrant records.


*Default value is "registrant".*


```opensips title="Set 'table_name' parameter"
...
modparam("uac_registrant", "table_name", "my_registrant")
...
```


#### registrar_column (string)


The column's name in the database storing the
		URI pointing to the remote registrar (mandatory field).
		OpenSIPS expects a valid URI.


*Default value is "registrar".*


```opensips title="Set 'registrar_column' parameter"
...
modparam("uac_registrant", "registrar_column", "registrant_uri")
...
```


#### proxy_column (string)


The column's name in the database storing the
		URI pointing to the outbond proxy (not mandatory field).
		An empty or NULL value means no outbound proxy,
		otherwise OpenSIPS expects a valid URI.


*Default value is "proxy".*


```opensips title="Set 'proxy_column' parameter"
...
modparam("uac_registrant", "proxy_column", "proxy_uri")
...
```


#### aor_column (string)


The column's name in the database storing the
		URI defining the address of record (mandatory field).
		The URI stored here will be used in the To URI of the REGISTER.
		OpenSIPS expects a valid URI.


*Default value is "aor".*


```opensips title="Set 'aor_column' parameter"
...
modparam("uac_registrant", "aor_column", "to_uri")
...
```


#### third_party_registrant_column (string)


The column's name in the database storing the
		URI defining the third party registrant (not mandatory field).
		The URI stored here will be used in the From URI of the REGISTER.
		An empty or NULL value means no third party registration
		(the From URI will be identical to To URI),
		otherwise OpenSIPS expects a valid URI.


*Default value is "third_party_registrant".*


```opensips title="Set 'third_party_registrant_column' parameter"
...
modparam("uac_registrant", "third_party_registrant_column", "from_uri")
...
```


#### username_column (string)


The column's name in the database storing the
		username for authentication (mandatory if the registrar requires authentication).


*Default value is "username".*


```opensips title="Set 'username_column' parameter"
...
modparam("uac_registrant", "username_column", "auth_username")
...
```


#### password_column (string)


The column's name in the database storing the
		password for authentication (mandatory if the registrar requires authntication).


*Default value is "password".*


```opensips title="Set 'password_column' parameter"
...
modparam("uac_registrant", "password_column", "auth_passowrd")
...
```


#### binding_URI_column (string)


The column's name in the database storing the
		binding URI in REGISTER (mandatory field).
		The URI stored here will be used in the Contact URI of the REGISTER.
		OpenSIPS expects a valid URI.


*Default value is "binding_URI".*


```opensips title="Set 'binding_URI_column' parameter"
...
modparam("uac_registrant", "binding_URI_column", "contact_uri")
...
```


#### binding_params_column (string)


The column's name in the database storing the
		binding params in REGISTER (not mandatory field).
		If not NULL or not empty, the string stored here will be added
		as params to the Contact URI in REGISTER (it MUST start with ";".


If the following two params are present, then the binding will be enforced
		to be unique (if two bindings are received in a 200ok, a complete binding
		removal will be performed before re-registering):


- *reg-id*
- *+sip.instance*


Example of params that will force unique binding:


```c
;reg-id=1;+sip.instance="<urn:uuid:11111111-AABBCCDDEEFF>"
		
```


*Default value is "binding_params".*


```opensips title="Set 'binding_params_column' parameter"
...
modparam("uac_registrant", "binding_params_column", "contact_params")
...
```


#### expiry_column (string)


The column's name in the database storing the
		expiration time (not mandatory).


*Default value is "expiry".*


```opensips title="Set 'expiry_column' parameter"
...
modparam("uac_registrant", "expiry_column", "registration_timeout")
...
```


#### forced_socket_column (string)


The column's name in the database storing the
		socket for sending the REGISTER (not mandatory).
		If a forced socket is provided, the socket MUST be
		explicitely set as a global listening socket in the config
		(see "socket" core parameter).


*Default value is "forced_socket".*


```opensips title="Set 'forced_socket_column' parameter"
...
modparam("uac_registrant", "forced_socket_column", "fs")
...
```


#### cluster_shtag_column (string)


The column's name in the database storing the
		cluster sharing tag in [tag_name/cluster_id] format (not mandatory).
		If a cluster sharing tag is provided, the REGISTER requests will
		be fired out only when the tag is active.


*Default value is "cluster_shtag".*


```opensips title="Set 'cluster_shtag_column' parameter"
...
modparam("uac_registrant", "cluster_shtag_column", "sh")
...
```


#### state_column (string)


The column's name in the database storing the current state of the
		registrant. When a registrant is disabled, OpenSIPS will no longer send
		REGISTERs for it. A value of *0* for this column means
		enabled and *1* disabled.


*Default value is "state".*


```opensips title="Set 'state_column' parameter"
...
modparam("uac_registrant", "state_column", "status")
...
```


#### reregister_expiry_percentage (integer)


Percentage describing how much sooner a RE-REGISTER needs to be send based on the Expiry. a 100 value means the RE-REGISTER will be send right on the edge of expiry ( old behavior ), which might lead to registration loss. a 90 value means the RE-REGISTER will be sent sooner , at 90% of the Expiry, etc.


*Default value is "100".*


```opensips title="Set 'reregister_expiry_percentage' parameter"
...
modparam("uac_registrant", "reregister_expiry_percentage", 90)
...
```


### Exported Functions


None to be used in configuration file.


### Exported MI Functions


#### uac_registrant:list


Replaces obsolete MI command: *reg_list*.


Lists the registrant records and their status.


Name: *uac_registrant:list*


Parameters:


- *aor* (optional) - URI defining the address
				of record. If provided, *contact* and
				*registrar* parameters are also required and
				only a specific record will be listed.
- *contact* (optional) - Contact URI. If 
				provided,
				*aor* and *registrar*
				parameters are also required and only a specific record will
				be listed.
- *registrar* (optional) - URI pointing to the
				remote registrar. If provided, *aor* and
				*contact* parameters are also required and
				only a specific record will be listed.


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:list
...
opensips-cli -x mi uac_registrant:list sip:alice@opensips.org  sip:alice@127.0.0.1:5060 sip:opensips.org
		
```


#### uac_registrant:reload


Replaces obsolete MI command: *reg_reload*.


Reloads the registrant records from the database.


Name: *uac_registrant:reload*


Parameters: *none*


- *aor* (optional) - URI defining the address
				of record. If provided, *contact* and
				*registrar* parameters are also required and
				only a specific record will be reloaded.
- *contact* (optional) - Contact URI. If 
				provided,
				*aor* and *registrar*
				parameters are also required and only a specific record will
				be reloaded.
- *registrar* (optional) - URI pointing to the
				remote registrar. If provided, *aor* and
				*contact* parameters are also required and
				only a specific record will be reloaded.


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:reload
...
opensips-cli -x mi reg_leload sip:alice@opensips.org  sip:alice@127.0.0.1:5060 sip:opensips.org
		
```


#### uac_registrant:enable


Replaces obsolete MI command: *reg_enable*.


Enables a specific registrant. OpenSIPS will immediately send
		a REGISTER if the registrant was previously disabled and will update
		the state in the database.


Name: *uac_registrant:enable*


Parameters: *none*


- *aor* - URI defining the address of record.
- *contact* - Contact URI.
- *registrar* - URI pointing to the remote registrar.


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:enable sip:alice@opensips.org  sip:alice@127.0.0.1:5060 sip:opensips.org
		
```


#### uac_registrant:disable


Replaces obsolete MI command: *reg_disable*.


Disables a specific registrant. OpenSIPS will immediately send
		an unREGISTER if the registrant was previously enabled and will update
		the state in the database.


Name: *uac_registrant:disable*


Parameters: *none*


- *aor* - URI defining the address
				of record. If provided, *contact* and
				*registrar* parameters are also required and
				only a specific record will be disabled.
- *contact* - Contact URI. If provided,
				*aor* and *registrar*
				parameters are also required and only a specific record will
				be disabled.
- *registrar* - URI pointing to the remote
				registrar. If provided, *aor* and
				*contact* parameters are also required and
				only a specific record will be disabled.


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:disable sip:alice@opensips.org  sip:alice@127.0.0.1:5060 sip:opensips.org
		
```


#### uac_registrant:force_register


Replaces obsolete MI command: *reg_force_register*.


Forces the re-registration (or registation) of a specific 
		registrant (depending on its state). Note that the registrant must be
		enabled.


Name: *uac_registrant:force_register*


Parameters:


- *aor* - URI defining the address
				of record. If provided, *contact* and
				*registrar* parameters are also required and
				only a specific record will be forced to re-register.
- *contact* - Contact URI. If provided,
				*aor* and *registrar*
				parameters are also required and only a specific record will be
				forced to re-register.
- *registrar* - URI pointing to the remote
				registrar. If provided, *aor* and
				*contact* parameters are also required and
				only a specific record will be forced to re-register.


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:force_register sip:alice@opensips.org  sip:alice@127.0.0.1:5060 sip:opensips.org
		
```


#### uac_registrant:upsert


Replaces obsolete MI command: *reg_upsert*.


Inserts or updates the in-memory contents of the AOR/Contact/Registrar. No Database queries are done when calling this MI command, all parameters are passed via MI


Name: *uac_registrant:upsert*


Parameters:


- *aor* - URI defining the address
- *contact* - Contact URI
- *registrar* - URI pointing to the remote registrar
- *proxy* - URI of a registration proxy
- *third_party_registrant* - 3rd party registrant
- *username* - the username for auth purposes
- *password* - the password for auth purposes
- *binding_params* - params to be added to the registration
- *expiry* - number of seconds that the registration will be valid
- *forced_socket* - opensips socket to send out the register out through
- *cluster_shtag* - the sharing tag for this registration
- *state* - 0 for enabled, 1 for disabled


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:upsert aor=sip:vlad@test.com contact=sip:test@localhost registrar=sip:127.0.0.1:5061 proxy="" third_party_registrant="" username="vlad" password="1234" binding_params="" expiry=60 forced_socket="" cluster_shtag="" state=0
		
```


#### uac_registrant:delete


Replaces obsolete MI command: *reg_delete*.


Deletes the in-memory contents of the AOR/Contact/Registrar. No Database queries are done when calling this MI command, all parameters are passed via MI


Name: *uac_registrant:delete*


Parameters:


- *aor* - URI defining the address
- *contact* - Contact URI
- *registrar* - URI pointing to the remote registrar


MI FIFO Command Format:


```bash
opensips-cli -x mi uac_registrant:delete aor=sip:vlad@test.com contact=sip:test@localhost registrar=sip:127.0.0.1:5061 
		
```


### Exported Events


#### E_REGISTRANT_REGISTERING


This event is raised when the module sent the initial REGISTER and started the registration process.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_AUTHENTICATING


This event is raised when the initial REGISTER has been challenged and a new REGISTER with credentials has been sent out.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_REGISTERED


This event is raised when a REGISTER has been 200 OKd.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_REGISTER_TIMEOUT


This event is raised when a REGISTER received no reply from the registrar.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_INTERNAL_ERROR


This event is raised when a REGISTER procesing was stopped due to an internal OpenSIPS error.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_WRONG_CREDENTIALS


This event is raised when a REGISTER with credentials was still rejected by the registrar


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_REGISTRAR_ERROR


This event is raised when a REGISTER is rejected by the registrar with a non-standard sip code.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_UNREGISTERING


This event is raised when a de-REGISTER is sent by OpenSIPS.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


#### E_REGISTRANT_AUTHENTICATING_UNREGISTER


This event is raised when a de-REGISTER is challenged and auth is sent by OpenSIPS.


Parameters:


- *aor* - the AOR
- *contact* - the Contact
- *registrar* - the Registrar


### Exported Status/Report Identifiers


The module provides the "uac_registrant" Status/Report group, where each
	UAC registrant is defined as a separate SR identifier.


The name of each individual identitfier is built as follows:


```c
   "aor=_AOR_;contact=_SIP_CONTACT_URI_;registrar=_SIP_REGISTAR_URI_"
   Ex:
   "aor=sip:vlad@test.com;contact=sip:test@mycontact.com;registrar=sip:127.0.0.1:5061"
	
```


In terms of status, the following values will be reported:


- STATUS_READY, if REGISTERED
- STATUS_LOADING_DATA, if REGISTERING, UNREGISTERING, AUTHENTICATING
- STATUS_NOT_READY, any other state of the registrant


As reports, each identifier may provide information like:


```json
# opensips-cli -x mi  sr_list_reports uac_registrant
[
   {
       "Name": "aor=sip:vlad@test.com;contact=sip:test@mycontact.com;registrar=sip:127.0.0.1:5061",
       "Reports": [
           {
               "Timestamp": 1769604697,
               "Date": "Wed Jan 28 14:51:37 2026",
               "Log": "created with state NOT_REGISTERED_STATE\n"
           },
           {
               "Timestamp": 1769604707,
               "Date": "Wed Jan 28 14:51:47 2026",
               "Log": "state changed to REGISTERING_STATE\n"
           },
           {
               "Timestamp": 1769604712,
               "Date": "Wed Jan 28 14:51:52 2026",
               "Log": "state changed to REGISTER_TIMEOUT_STATE\n"
           }
       ]
   }
]
	
```


For how to access and use the Status/Report information, please see
	[https://www.opensips.org/Documentation/Interface-StatusReport-3-6](>https://www.opensips.org/Documentation/Interface-StatusReport-3-6).
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
