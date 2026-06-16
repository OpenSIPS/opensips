---
title: "usrloc Module"
description: "User location module. The module keeps a user location table and provides access to the table to other modules. The module exports no functions that could be used directly from scripts."
---

## Admin Guide


### Overview


User location module. The module keeps a user location table and 
		provides access to the table to other modules. The module exports no 
		functions that could be used directly from scripts.


#### Contact matching


How the contacts are matched (for same AOR - Address of Record) is an
		important aspect of the usrloc modules, especialy in the context of NAT
		traversal - this raise mre problems since contacts from different 
		phones of same users may overlap (if behind NATs with same
		configuration) or the re-register contact of same phone may be
		seen as a new one (due different binding via NAT).


The SIP RFC 3261 publishes a matching algorithm based only on the 
		contact string with callid and cseq number extra checking (if callid
		is the same, it must have a higher cseq number, otherwise invalid).
		But as argumented above, this is not enough in NAT traversal context, 
		so the OpenSIPS implementation of contact machting offers more algorithms:


- *contact based only* - strict RFC 3261
				compliancy - the contact is matched as string and extra checked
				via callid and cseq (if callid is the same, it must have a
				higher cseq number, otherwise invalid).
- *contact and callid based* - an extension
				of the first case - the contact and callid must match as
				strings; the cseq must be higher than the previous one - so be
				careful how you deal with REGISTER retransmissions in this 
				case.


For more details on how to control/select the contact matching algorithm,
		please see the module parameter matching_mode at
		[matching mode](#param_matching_mode).


#### Contact replication


Starting from OpenSIPS 1.11, the *usrloc* module
		offers the possibility of performing real-time mirroring of the entire
		in-memory user location information of one OpenSIPS instance to one or more
		other instances. This module-to-module communication is UDP-based, and
		it is done through the *Binary Interface*.


Advantages of replicating user-location data using this feature
		instead of sending duplicated SIP REGISTER requests:


- no message parsing required
- reduced bandwith usage
- no additional script logic needed


In order to control the DB operations performed by the receiving instance(s),
		the **[skip replicated db ops](#param_skip_replicated_db_ops)**
		parameter can be set. To summarise, the replication logic works together
		with the DB modes as follows:


- **0 (No DB)** - only in-memory
					data is replicated (no DB operations are performed at all)
- **1 (Write through) and 2 (Write back)**
					- default behaviour on all instances, **[skip replicated db ops](#param_skip_replicated_db_ops)** can be set
					on the receiving ones
- **3 (DB only)** -
						data replication is **OFF**


Configuring both receival and sending of usrloc replication packets is
		trivial and can be done by using the
		**[accept replicated contacts](#param_accept_replicated_contacts)** and
		**[replicate contacts to](#param_replicate_contacts_to)** parameters of the
		module.


*Note* that for certain scenarios, where NAT or
		multihomed interfaces are involved, you might need to preserve the
		same interface among all the OpenSIPS servers within the replication
		cluster. Otherwise when an instance receives a replicated contact
		for whom it does not have a listener, it will use a different
		listener of his.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Optionally a database module*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### nat_bflag (string/integer)


The name of the branch flag to be used as NAT marker (if the contact 
		is or not natted). This is a branch flag and it will be imported and 
		used by all other modules depending of usrloc module.


*WARNING:*Setting INT flags is deprecated!
		Use quoted strings instead!
		*Default value is "NULL" (not set).*


```c title="Set nat_bflag parameter"
...
modparam("usrloc", "nat_bflag", "NAT_BFLAG")
...
```


#### user_column (string)


Name of column containing usernames.


*Default value is "username".*


```c title="Set user_column parameter"
...
modparam("usrloc", "user_column", "username")
...
```


#### domain_column (string)


Name of column containing domains.


*Default value is "domain".*


```c title="Set user_column parameter"
...
modparam("usrloc", "domain_column", "domain")
...
```


#### contact_column (string)


Name of column containing contacts.


*Default value is "contact".*


```c title="Set contact_column parameter"
...
modparam("usrloc", "contact_column", "contact")
...
```


#### expires_column (string)


Name of column containing expires value.


*Default value is "expires".*


```c title="Set expires_column parameter"
...
modparam("usrloc", "expires_column", "expires")
...
```


#### q_column (string)


Name of column containing q values.


*Default value is "q".*


```c title="Set q_column parameter"
...
modparam("usrloc", "q_column", "q")
...
```


#### callid_column (string)


Name of column containing callid values.


*Default value is "callid".*


```c title="Set callid_column parameter"
...
modparam("usrloc", "callid_column", "callid")
...
```


#### cseq_column (string)


Name of column containing cseq numbers.


*Default value is "cseq".*


```c title="Set cseq_column parameter"
...
modparam("usrloc", "cseq_column", "cseq")
...
```


#### methods_column (string)


Name of column containing supported methods.


*Default value is "methods".*


```c title="Set methods_column parameter"
...
modparam("usrloc", "methods_column", "methods")
...
```


#### flags_column (string)


Name of column to save the internal flags of the record.


*Default value is "flags".*


```c title="Set flags_column parameter"
...
modparam("usrloc", "flags_column", "flags")
...
```


#### cflags_column (string)


Name of column to save the branch/contact flags of the record.


*Default value is "cflags".*


```c title="Set cflags_column parameter"
...
modparam("usrloc", "cflags_column", "cflags")
...
```


#### user_agent_column (string)


Name of column containing user-agent values.


*Default value is "user_agent".*


```c title="Set user_agent_column parameter"
...
modparam("usrloc", "user_agent_column", "user_agent")
...
```


#### received_column (string)


Name of column containing the source IP, port, and protocol from the REGISTER
		message.


*Default value is "received".*


```c title="Set received_column parameter"
...
modparam("usrloc", "received_column", "received")
...
```


#### socket_column (string)


Name of column containing the received socket information (IP:port)
		for the REGISTER message.


*Default value is "socket".*


```c title="Set socket_column parameter"
...
modparam("usrloc", "socket_column", "socket")
...
```


#### path_column (string)


Name of column containing the Path header.


*Default value is "path".*


```c title="Set path_column parameter"
...
modparam("usrloc", "path_column", "path")
...
```


#### sip_instance_column (string)


Name of column containing the SIP instance.


*Default value is "NULL".*


```c title="Set sip_instance_column parameter"
...
modparam("usrloc", "sip_instance_column", "sip_instance")
...
```


#### attr_column (string)


Name of column containing additional registration-related information.


*Default value is "NULL".*


```c title="Set attr_column parameter"
...
modparam("usrloc", "attr_column", "attr")
...
```


#### use_domain (integer)


If the domain part of the user should be also saved and used for
		identifing the user (along with the username part). Useful in 
		multi domain scenarios. Non 0 value means true.


*Default value is "0 (false)".*


```c title="Set use_domain parameter"
...
modparam("usrloc", "use_domain", 1)
...
```


#### desc_time_order (integer)


If the user's contacts should be kept timestamp ordered; otherwise the
		contact will be ordered based on q value.
		Non 0 value means true.


*Default value is "0 (false)".*


```c title="Set desc_time_order parameter"
...
modparam("usrloc", "desc_time_order", 1)
...
```


#### timer_interval (integer)


Number of seconds between two timer runs. The module uses timer to 
		delete expired contacts, synchronize with database and other tasks, 
		that need to be run periodically.


*Default value is 60.*


```c title="Set timer_interval parameter"
...
modparam("usrloc", "timer_interval", 120)
...
```


#### db_url (string)


URL of the database that should be used.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```c title="Set db_url parameter"
...
modparam("usrloc", "db_url", "dbdriver://username:password@dbhost/dbname")
...
```


#### db_mode (integer)


The usrloc module can utilize database for persistent contact storage.
		If you use database, your contacts will survive machine restarts or 
		SW crashes. The disadvantage is that accessing database can be very 
		time consuming. Therefore, usrloc module implements four database 
		accessing modes:


- 0 - This disables database completely. Only memory will be used. 
			Contacts will not survive restart. Use this value if you need a 
			really fast usrloc and contact persistence is not necessary or 
			is provided by other means.
- 1 - Write-Through scheme. All changes to usrloc are immediately 
			reflected in database too. This is very slow, but very reliable. 
			Use this scheme if speed is not your priority but need to make 
			sure that no registered contacts will be lost during crash or 
			reboot.
- 2 - Write-Back scheme. This is a combination of previous two 
			schemes. All changes are made to memory and database 
			synchronization is done in the timer. The timer deletes all 
			expired contacts and flushes all modified or new contacts to 
			database.  Use this scheme if you encounter high-load peaks 
			and want them to process as fast as possible. The mode will 
			not help at all if the load is high all the time.  Also, latency 
			of this mode is much lower than latency of mode 1, but slightly 
			higher than latency of mode 0.
- 3 - DB-Only scheme. No memory cache is kept, all operations being
			directly performed with the database. The timer deletes all 
			expired contacts from database - cleans after clients that didn't
			un-register or re-register. The mode is useful if you configure
			more servers sharing the same DB without any replication at SIP
			level. The mode may be slower due the high number of DB operation.
			For example NAT pinging is a killer since during each ping cycle
			all nated contact are loaded from the DB; The lack of memory 
			caching also disable the statistics exports.


> [!WARNING]
> In case of crash or restart contacts that are in memory only and 
			haven't been flushed yet will get lost. If you want minimize the 
			risk, use shorter timer interval.


*Default value is 0.*


```c title="Set db_mode parameter"
...
modparam("usrloc", "db_mode", 2)
...
```


#### matching_mode (integer)


What contact matching algorithm to be used. Refer to section 
		[contact matching algs](#contact_matching) for the description of the 
		algorithms.


The parameter may take the following values:


- *0* - CONTACT ONLY based matching
				algorithm.
- *1* - CONTACT and CALLID based 
				matching algorithm.


*Default value is *0 (CONTACT_ONLY)*.*


```c title="Set matching_mode parameter"
...
modparam("usrloc", "matching_mode", 1)
...
```


#### cseq_delay (integer)


Delay (in seconds) for accepting as retransmissions register requests
		with same Call-ID and Cseq. The delay is calculated starting from the 
		receiving time of the first register with that Call-ID and Cseq.


Retransmissions within this delay interval will be accepted and replied
		as the original request, but no update will be done in location. If the
		delay is exceeded, error is reported.


A value of 0 disable the retransmission detection.


*Default value is "20 seconds".*


```c title="Set cseq_delay parameter"
...
modparam("usrloc", "cseq_delay", 5)
...
```


#### accept_replicated_contacts (integer)


Set this to 1 in order to accept and process user-location related
		information received from other OpenSIPS instances through the
		**Binary Interface**.


Default value is "0" - Binary Interface listeners (if any)
		will simply ignore any usrloc-related packets


More details on the user location replication mechanism are available in [usrloc replication](#contact_replication)


```c title="Setting the accept_replicated_contacts parameter"
...
modparam("usrloc", "accept_replicated_contacts", 1)
...
```


#### replicate_contacts_to (string)


Define a new OpenSIPS instance which will receive all the user-location
		related information from this machine
		(*addresses-of-record*, *contacts*),
		organized into specific events (inserts, deletes or updates)


This parameter may be set multiple times. It does
		**not** ignore duplicate entries.


Default value is "none" (no replication destinations)


More details on the user location replication mechanism are available in [usrloc replication](#contact_replication)


```c title="Setting the replicate_contacts_to parameter"
...
modparam("usrloc", "replicate_contacts_to", "192.168.2.182:5062")
...
```


#### skip_replicated_db_ops (int)


Prevent OpenSIPS from performing any DB-related contact operations
		when events are received over the *Binary Interface*.
		This is commonly used to prevent unneeded duplicate operations.


Default value is "0" (upon receival of usrloc-related Binary Interface
		events, DB queries may be freely performed)


More details on the user location replication mechanism are available
		in [usrloc replication](#contact_replication)


```c title="Setting the skip_replicated_db_ops parameter"
...
modparam("usrloc", "skip_replicated_db_ops", 1)
...
```


#### hash_size (integer)


The number of entries of the hash table used by usrloc to store the
		location records is 2^hash_size. For hash_size=4, the number of entries
		of the hash table is 16.


*Default value is "9".*


```c title="Set hash_size parameter"
...
modparam("usrloc", "hash_size", 10)
...
```


### Exported Functions


There are no exported functions that could be used in scripts.


### Exported MI Functions


#### ul_rm


Deletes an entire AOR record (including its contacts).


Parameters:


- *table name* - table where the AOR
				is removed from (Ex: location).
- *AOR* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).


#### ul_rm_contact


Deletes a contact from an AOR record.


Parameters:


- *table name* - table where the AOR
				is removed from (Ex: location).
- *AOR* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).
- *contact* - exact contact to be removed


#### ul_dump


Dumps the entire content of the USRLOC in memory cache


Parameters:


- *brief* - (optional, may not be present); if
				equals to string "brief", a brief dump will be
				done (only AOR and contacts, with no other details)


#### ul_flush


Triggers the flush of USRLOC memory cache into DB.


#### ul_add


Adds a new contact for an user AOR.


Parameters:


- *table name* - table where the contact
				will be added (Ex: location).
- *AOR* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).
- *contact* - contact string to be added
- *expires* - expires value of the contact
- *Q* - Q value of the contact
- *unused* - unused attribute (kept for
				backword compatibility)
- *flags* - internal USRLOC flags of the 
				contact
- *cflags* - per branch flags of the 
				contact
- *methods* - mask with supported requests
				of the contact


#### ul_show_contact


Dumps the contacts of an user AOR.


Parameters:


- *table name* - table where the AOR
				resides (Ex: location).
- *AOR* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).


#### ul_sync


Synchronizes the contacts from memory with the ones from database.
		Note that this can not be used when no database is specified or with the
		DB-Only scheme.

		Important: make sure that all your contacts are in memory
		(*ul_dump* MI function) before executing this
		command. If the AOR is not specified, the whole table will be
		synchronized.


Parameters:


- *table name* - table where the AOR
				resides (Ex: location).
- *AOR (optional)* - user AOR in username[@domain]
				format (domain must be supplied only if use_domain option
				is on).


### Exported Statistics


Exported statistics are listed in the next sections.


#### users


Number of AOR existing in the USRLOC memory cache for that domain
			- can not be resetted; this statistic will be register for each 
			used domain (Ex: location).


#### contacts


Number of contacts existing in the USRLOC memory cache for that 
			domain - can not be resetted; this statistic will be register for 
			each used domain (Ex: location).


#### expires


Total number of expired contacts for that domain - can be resetted;
			 this statistic will be register for each used domain 
			(Ex: location).


#### registered_users


Total number of AOR existing in the USRLOC memory cache for all
			domains - can not be resetted.


### Exported Events


#### E_UL_AOR_INSERT


This event is raised when a new AOR is inserted in the USRLOC
			memory cache.


Parameters:


- *aor* - The AOR of the inserted record.


#### E_UL_AOR_DELETE


This event is raised when a new AOR is deleted from the USRLOC
			memory cache.


Parameters:


- *aor* - The AOR of the deleted record.


## Developer Guide


### Available Functions


#### ul_register_domain(name)


The function registers a new domain. Domain is just another name for 
		table used in registrar. The function is called from fixups in 
		registrar. It gets name of the domain as a parameter and returns 
		pointer to a new domain structure. The fixup than 'fixes' the 
		parameter in registrar so that it will pass the pointer instead of the
		name every time save() or lookup() is called. Some usrloc functions 
		get the pointer as parameter when called. For more details see 
		implementation of save function in registrar.


Meaning of the parameters is as follows:


- *const char* name* - Name of the domain 
				(also called table) to be registered.


#### ul_insert_urecord(domain, aor, rec, is_replicated)


The function creates a new record structure and inserts it in the 
		specified domain. The record is structure that contains all the 
		contacts for belonging to the specified username.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain 
				returned by ul_register_udomain.
- *str* aor* - Address of Record (aka 
			username) of the new record (at this time the record will 
			contain no contacts yet).
- *urecord_t** rec* - The newly created 
			record structure.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_delete_urecord(domain, aor, is_replicated)


The function deletes all the contacts bound with the given Address 
		Of Record.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain 
			returned by ul_register_udomain.
- *str* aor* - Address of record (aka 
			username) of the record, that should be deleted.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_get_urecord(domain, aor)


The function returns pointer to record with given Address of Record.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain 
			returned by ul_register_udomain.


- *str* aor* - Address of Record of request 
			record.


#### ul_lock_udomain(domain)


The function lock the specified domain, it means, that no other 
		processes will be able to access during the time. This prevents race 
		conditions. Scope of the lock is the specified domain, that means, 
		that multiple domain can be accessed simultaneously, they don't block 
		each other.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Domain to be locked.


#### ul_unlock_udomain(domain)


Unlock the specified domain previously locked by ul_lock_udomain.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Domain to be 
			unlocked.


#### ul_release_urecord(record, is_replicated)


Do some sanity checks - if all contacts have been removed, delete 
		the entire record structure.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record to be 
			released.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_insert_ucontact(record, contact, contact_info, contact, is_replicated)


The function inserts a new contact in the given record with 
		specified parameters.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record in which 
			the contact should be inserted.
- *str* contact* - Contact URI.
- *ucontact_info_t* contact_info* -
				Single structure containing the new contact information
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_delete_ucontact (record, contact, is_replicated)


The function deletes given contact from record.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record from which 
			the contact should be removed.


- *ucontact_t* contact* - Contact to be 
			deleted.
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_get_ucontact(record, contact)


The function tries to find contact with given Contact URI and 
		returns pointer to structure representing the contact.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record to be 
			searched for the contact.


- *str_t* contact* - URI of the request
			contact.


#### ul_get_all_ucontacts (buf, len, flags)


The function retrieves all contacts of all registered users and 
		returns them in the caller-supplied buffer. If the buffer is too small,
		the function returns positive value indicating how much additional 
		space would be necessary to accommodate all of them. Please note 
		that the positive return value should be used only as a 
		"hint", as there is no guarantee that during the time 
		between two subsequent calls number of registered contacts will 
		remain the same.


If flag parameter is set to non-zero value then only contacts that 
		have the specified flags set will be returned. It is, for example, 
		possible to list only contacts that are behind NAT.


Meaning of the parameters is as follows:


- *void* buf* - Buffer for returning 
			contacts.


- *int len* - Length of the buffer.


- *unsigned int flags* - Flags that must
			be set.


#### ul_update_ucontact(record, contact, contact_info, is_replicated)


The function updates contact with new values.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record in which 
			the contact should be inserted.
- *ucontact_t* contact* - Contact URI.
- *ucontact_info_t* contact_info* -
				Single structure containing the new contact information
- *char is_replicated* - Specifies whether
			this function will be called from the context of a Binary Interface
			callback. If uncertain, simply use 0.


#### ul_bind_ursloc( api )


The function imports all functions that are exported by the 
		USRLOC module. Overs for other modules which want to user the
		internal USRLOC API an easy way to load and access the functions.


Meaning of the parameters is as follows:


- *usrloc_api_t* api* - USRLOC API


#### ul_register_ulcb(type ,callback, param)


The function register with USRLOC a callback function to be called
		when some event occures inside USRLOC.


Meaning of the parameters is as follows:


- *int types* - type of event for which
			the callback should be called (see usrloc/ul_callback.h).
- *ul_cb f* - callback function; see
			usrloc/ul_callback.h for prototype.
- *void *param* - some parameter to be
			passed to the callback each time when it is called.


#### ul_get_num_users()


The function loops through all domains summing up the number of users.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
