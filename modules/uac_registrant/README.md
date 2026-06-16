---
title: "UAC Registrant Module"
description: "The module enable OpenSIPS to register itself on a remote SIP registrar. Several registrant accounts can be defined, each account is specified by the \"uac\" parameter."
---

## Admin Guide


### Overview


The module enable OpenSIPS to register itself on a remote SIP registrar.
		Several registrant accounts can be defined, each account is
		specified by the "uac" parameter.


At startup, the registrant records are loaded into
		a hash table in memory and a timer is started.
		The hash index is computed over the AOR field.
		For better hash distribution, the size of the hash table is configurable.
		When the timer fires for the first time, the first hash table will be checked and
		REGISTERs will be sent out for each record that is found.
		On the next timeout fire, the second hash table will be checked and so on.
		The timer interval is configurable.


Each registrant has it's own state.
		Registranr's status can be inspected via "reg_list" MI comand.


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


```c title="Set hash_size parameter"
...
modparam("uac_registrant", "hash_size", 2)
...
```


#### timer_interval (integer)


Defines the periodic timer for checking the registrations status.


*Default value is 100.*


```c title="Set timer_interval parameter"
...
modparam("uac_registrant", "timer_interval", 120)
...
```


#### uac (csv string)


Defines the field parameters of a registration.
		Each field is separated by ','.


Meaning of the fields is as follows:


- *registrar*
				- URI pointing to the remote registrar (mandatory field);
- *outbound proxy*
				- URI pointing to the outbond proxy.
				An empty value means no putbound proxy (not mandatory);
- *aor*
				- URI defining the address of record (mandatory field);
- *third party registrant*
				- URI defining the third party registrant (not mandatory);
- *username*
				- username for authentication
				(mandatory if the registrar requires authentication);
- *password*
				- password for authentication
				(mandatory if the registrar requires authntication);
- *binding URI*
				- contact URI in REGISTER (mandatory field);
- *binding params*
				- contact params in REGISTER (not mandatory);
- *expiry*
				- expiration time  (not mandatory).  Default value: 3600;
- *forced socket*
				- socket for sending the REGISTER (not mandatory).


*There is no default value.
			There can be several uac defined in the config file.*


```c title="Set uac parameter"
...
modparam("uac_registrant", "uac",
"sip:opensips.org,,sip:user@opensips.org,,user,password,sip:user@ip,,,")
...
```


### Exported Functions


None to be used in configuration file.


### Exported MI Functions


#### reg_list


Lists the registrant records and their status.


Name: *reg_list*


Parameters: *none*


MI FIFO Command Format:


```c
:reg_list:_reply_fifo_file_
_empty_line_
		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
