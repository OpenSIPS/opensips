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


How the contacts are matched (dor same AOR - Address of Record) is an 
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


- *contact based only* - it strict RFC 3261
compiancy - the contact is matched as string and extra checked
via callid and cseg (if callid is the same, it must have a 
higher cseq number, otherwise invalid).
- *contact nad callid based* - it an extension
of the first case - the contact and callid must matched as 
string; the cseg must be higher than the previous one - so be
careful how you deal with REGISTER retransmissions in this 
case.


How to control/select the contact maching algorithm, please see the
module parameter matching_mode at [matching mode](#param_matching_mode).


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *Optionally a database module*.


#### External Libraries or Applications


The following libraries or applications must be installed before 
running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### nat_bflag (integer)


The index of the branch flag to be used as NAT marker (if the contact 
is or not natted). This is a branch flag and it will be imported and 
used by all other modules depending of usrloc module.


*Default value is "not set".*


```opensips title="Set nat_bflag parameter"
...
modparam("usrloc", "nat_bflag", 3)
...
```


#### user_column (string)


Name of column containing usernames.


*Default value is "username".*


```opensips title="Set user_column parameter"
...
modparam("usrloc", "user_column", "username")
...
```


#### domain_column (string)


Name of column containing domains.


*Default value is "domain".*


```opensips title="Set user_column parameter"
...
modparam("usrloc", "domain_column", "domain")
...
```


#### contact_column (string)


Name of column containing contacts.


*Default value is "contact".*


```opensips title="Set contact_column parameter"
...
modparam("usrloc", "contact_column", "contact")
...
```


#### expires_column (string)


Name of column containing expires value.


*Default value is "expires".*


```opensips title="Set expires_column parameter"
...
modparam("usrloc", "expires_column", "expires")
...
```


#### q_column (string)


Name of column containing q values.


*Default value is "q".*


```opensips title="Set q_column parameter"
...
modparam("usrloc", "q_column", "q")
...
```


#### callid_column (string)


Name of column containing callid values.


*Default value is "callid".*


```opensips title="Set callid_column parameter"
...
modparam("usrloc", "callid_column", "callid")
...
```


#### cseq_column (string)


Name of column containing cseq numbers.


*Default value is "cseq".*


```opensips title="Set cseq_column parameter"
...
modparam("usrloc", "cseq_column", "cseq")
...
```


#### methods_column (string)


Name of column containing supported methods.


*Default value is "methods".*


```opensips title="Set methods_column parameter"
...
modparam("usrloc", "methods_column", "methods")
...
```


#### flags_column (string)


Name of column to save the internal flags of the record.


*Default value is "flags".*


```opensips title="Set flags_column parameter"
...
modparam("usrloc", "flags_column", "flags")
...
```


#### cflags_column (string)


Name of column to save the branch/contact flags of the record.


*Default value is "cflags".*


```opensips title="Set cflags_column parameter"
...
modparam("usrloc", "cflags_column", "cflags")
...
```


#### user_agent_column (string)


Name of column containing user-agent values.


*Default value is "user_agent".*


```opensips title="Set user_agent_column parameter"
...
modparam("usrloc", "user_agent_column", "user_agent")
...
```


#### received_column (string)


Name of column containing the source IP, port, and protocol from the REGISTER
message.


*Default value is "received".*


```opensips title="Set received_column parameter"
...
modparam("usrloc", "received_column", "received")
...
```


#### socket_column (string)


Name of column containing the received socket information (IP:port)
for the REGISTER message.


*Default value is "socket".*


```opensips title="Set socket_column parameter"
...
modparam("usrloc", "socket_column", "socket")
...
```


#### path_column (string)


Name of column containing the Path header.


*Default value is "path".*


```opensips title="Set path_column parameter"
...
modparam("usrloc", "path_column", "path")
...
```


#### use_domain (integer)


If the domain part of the user should be also saved and used for
identifing the user (along with the username part). Useful in 
multi domain scenarios. Non 0 value means true.


*Default value is "0 (false)".*


```opensips title="Set use_domain parameter"
...
modparam("usrloc", "use_domain", 1)
...
```


#### desc_time_order (integer)


If the user's contacts should be kept timestamp ordered; otherwise the
contact will be ordered based on q value.
Non 0 value means true.


*Default value is "0 (false)".*


```opensips title="Set desc_time_order parameter"
...
modparam("usrloc", "desc_time_order", 1)
...
```


#### timer_interval (integer)


Number of seconds between two timer runs. The module uses timer to 
delete expired contacts, synchronize with database and other tasks, 
that need to be run periodically.


*Default value is 60.*


```opensips title="Set timer_interval parameter"
...
modparam("usrloc", "timer_interval", 120)
...
```


#### db_url (string)


URL of the database that should be used.


*Default value is "mysql://opensips:opensipsrw@localhost/opensips".*


```opensips title="Set db_url parameter"
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


```opensips title="Set db_mode parameter"
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


```opensips title="Set matching_mode parameter"
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


```opensips title="Set cseq_delay parameter"
...
modparam("usrloc", "cseq_delay", 5)
...
```


#### fetch_rows (integer)


The number of the rows to be fetched at once from database
when loading the location records. This value can be used
to tune the load time at startup. For 1MB of private memory (default)
it should be below 4000. The database driver must support
fetch_result() capability.


*Default value is "2000".*


```opensips title="Set fetch_rows parameter"
...
modparam("usrloc", "fetch_rows", 3000)
...
```


#### hash_size (integer)


The number of entries of the hash table used by usrloc to store the
location records is 2^hash_size. For hash_size=4, the number of entries
of the hash table is 16.


*Default value is "9".*


```opensips title="Set hash_size parameter"
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


#### ul_insert_urecord(domain, aor, rec)


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


#### ul_delete_urecord(domain, aor)


The function deletes all the contacts bound with the given Address 
Of Record.


Meaning of the parameters is as follows:


- *udomain_t* domain* - Pointer to domain 
returned by ul_register_udomain.


- *str* aor* - Address of record (aka 
username) of the record, that should be deleted.


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


#### ul_release_urecord(record)


Do some sanity checks - if all contacts have been removed, delete 
the entire record structure.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record to be 
released.


#### ul_insert_ucontact(record, contact, expires, q, callid, cseq, flags, cont, ua, sock)


The function inserts a new contact in the given record with 
specified parameters.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record in which 
the contact should be inserted.
- *str* contact* - Contact URI.
- *time_t expires* - Expires of the 
contact in absolute value.
- *float q* - q value of the contact.
- *str* callid* - Call-ID of the REGISTER 
message that contained the contact.
- *int cseq* - CSeq of the REGISTER 
message that contained the contact.
- *unsigned int flags* - Flags to be set.
- *ucontact_t* cont* - Pointer to newly 
created structure.
- *str* ua* - User-Agent of the REGISTER 
message that contained the contact.
- *struct socket_info *sock* - socket on
which the REGISTER message was received on.


#### ul_delete_ucontact (record, contact)


The function deletes given contact from record.


Meaning of the parameters is as follows:


- *urecord_t* record* - Record from which 
the contact should be removed.


- *ucontact_t* contact* - Contact to be 
deleted.


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


#### ul_update_ucontact(contact, expires, q, callid, cseq, set, res, ua, sock)


The function updates contact with new values.


Meaning of the parameters is as follows:


- *ucontact_t* contact* - Contact URI.
- *time_t expires* - Expires of the 
contact in absolute value.
- *float q* - q value of the contact.
- *str* callid* - Call-ID of the REGISTER 
message that contained the contact.
- *int cseq* - CSeq of the REGISTER message 
that contained the contact.
- *unsigned int set* - OR value of flags to 
be set.
- *unsigned int res* - OR value of flags to be 
reset.
- *str* ua* - User-Agent of the REGISTER 
message that contained the contact.
- *struct socket_info *sock* - socket on
which the REGISTER message was received on.


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
