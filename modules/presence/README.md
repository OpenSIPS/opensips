---
title: "Presence Module"
description: "The modules handles PUBLISH and SUBSCRIBE messages and generates NOTIFY messages in a general, event independent way. It allows registering events to it from other OpenSIPS modules. Events that can currently be added to it are: presence, presence.winfo, dialog;sla from presence_xml module an..."
---

## Admin Guide


### Overview


The modules handles PUBLISH and SUBSCRIBE messages and generates
	NOTIFY messages in a general, event independent way. It allows registering 
	events to it from other OpenSIPS modules. Events that can currently be added to
	it are: presence, presence.winfo, dialog;sla from presence_xml
	module and message-summary from presence_mwi module.


The modules uses database storage. 
	It has later been improved with memory caching operations to improve
	performance. The Subscribe dialog information are stored in memory and 
	are periodically updated in database, while for Publish only the presence
	or absence of stored info for a certain resource is maintained in memory
	to avoid unnecessary, costly db operations. 
	It is possible to configure a fallback to database mode(by setting module
	parameter "fallback2db"). In this mode, in case a searched record is not 
	found in cache, the search is continued	in database. This is useful for
	an architecture in which processing and memory load might be divided on 
	more machines using the same database.


The module can also work only with the functionality of a library,
	with no message processing and generation, but used only for the exported
	functions.
	This mode of operation is enabled if the db_url parameter is not set to any value.


The server follows the specifications in: RFC3265, RFC3856, RFC3857, 
	RFC3858.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *a database module*.
- *sl*.
- *tm*.


#### External Libraries or Applications


- *libxml-dev*.


### Exported Parameters


#### db_url(str)


The database url.


If set, the module is a fully operational
		presence server. Otherwise, it is used as a 'library', for 
		its exported functions.


*Default value is "NULL".*


```opensips title="Set db_url parameter"
...
modparam("presence", "db_url", 
	"mysql://opensips:opensipsrw@192.168.2.132/opensips")
...
```


#### presentity_table(str)


The name of the db table where Publish information are stored.


*Default value is "presentity".*


```opensips title="Set presentity_table parameter"
...
modparam("presence", "presentity_table", "presentity")
...
```


#### active_watchers_table(str)


The name of the db table where active subscription information are 
		stored.


*Default value is "active_watchers".*


```opensips title="Set active_watchers_table parameter"
...
modparam("presence", "active_watchers_table", "active_watchers")
...
```


#### watchers_table(str)


The name of the db table where subscription states are stored.


*Default value is "watchers".*


```opensips title="Set watchers_table parameter"
...
modparam("presence", "watchers_table", "watchers")
...
```


#### clean_period (int)


The period at which to verify if there are expired messages stored in
		database.


*Default value is "100".*


```opensips title="Set clean_period parameter"
...
modparam("presence", "clean_period", 100)
...
```


#### to_tag_pref (str)


The prefix used when generating to_tag when sending replies for
		SUBSCRIBE requests.


*Default value is "10".*


```opensips title="Set to_tag_pref parameter"
...
modparam("presence", "to_tag_pref", 'pres')
...
	
```


#### expires_offset (int)


The value that should be subtracted from the expires value when
		sending a 200OK for a publish. It is used for forcing the client
		cu send an update before the old publish expires.


*Default value is "0".*


```opensips title="Set expires_offset parameter"
...
modparam("presence", "expires_offset", 10)
...
```


#### max_expires (int)


The the maximum admissible expires value for PUBLISH/SUBSCRIBE
               message.


*Default value is "3600".*


```opensips title="Set max_expires parameter"
...
modparam("presence", "max_expires", 3600)
...
```


#### server_address (str)


The presence server address which will become the value of Contact header filed 
		for 200OK replies to Subscribe and Publish and in Notify messages.


```opensips title="Set server_address parameter"
...
modparam("presence", "server_address", "sip:10.10.10.10:5060")
...
```


#### fallback2db (int)


Setting this parameter enables a fallback to db mode of operation.
		In this mode, in case a searched record is not found in cache, 
		the search is continued	in database. Useful for an architecture in
		which processing and memory load might be divided on more machines
		using the same database.


```opensips title="Set fallback2db parameter"
...
modparam("presence", "fallback2db", 1)
...
```


#### subs_htable_size (int)


The size of the hash table to store subscription dialogs.
        This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set subs_htable_size parameter"
...
modparam("presence", "subs_htable_size", 11)
...
	
```


#### pres_htable_size (int)


The size of the hash table to store publish records.
        This parameter will be used as the power of 2 when computing table size.


*Default value is "9 (512)".*


```opensips title="Set pres_htable_size parameter"
...
modparam("presence", "pres_htable_size", 11)
...
	
```


#### enable_sphere_check (int)


This parameter is a flag that should be set if permission rules include
		sphere checking.
		The sphere information is expected to be present in the RPID body
		published by the presentity. The flag is introduced as this check requires
		extra processing that should be avoided if this feature is not supported
		by the clients.


*Default value is "0 ".*


```opensips title="Set enable_sphere_check parameter"
...
modparam("presence", "enable_sphere_check", 1)
...
	
```


### Exported Functions


#### handle_publish(char* sender_uri)


The function handles PUBLISH requests. It stores and updates 
		published information in database and calls functions to send 
		NOTIFY messages when changes in the published information occur.
		It takes one argument -> sender_uri. The parameter was added 
		for enabling BLA implementation. If present, Notification of
		a change in published state is not sent to the respective uri
		even though a subscription exists.
		It should be taken from the Sender header. It was left at the
		decision of the administrator whether or not to transmit the 
		content of this header as parameter for handle_publish, to 
		prevent security problems.


This function can be used from REQUEST_ROUTE.


*Return code:*


- *1 - if success*.
- *-1 - if error*.


The module sends an appropriate stateless reply
			in all cases.


```opensips title="handle_publish usage"
...
	if(is_method("PUBLISH"))
	{
		if($hdr(Sender)!= NULL)
			handle_publish("$hdr(Sender)");
		else
			handle_publish();
		t_release();
	} 
...
```


#### handle_subscribe()


The function which handles SUBSCRIBE requests. It stores or 
		updates information in database and calls functions to send Notify 
		messages when a Subscribe which initiate a dialog is received


This function can be used from REQUEST_ROUTE.


*Return code:*


- *1 - if success*.
- *-1 - if error*.


The module sends an appropriate stateless reply
			in all cases.


```opensips title="handle_subscribe usage"
...
if(method=="SUBSCRIBE")
    handle_subscribe();
...
```


### Exported MI Functions


#### refreshWatchers


Triggers sending Notify messages to watchers if a change in watchers
		authorization or in published state occurred.


Name: *refreshWatchers*


Parameters:


- presentity_uri : the uri of the user who made the change
				and whose watchers should be informed
- event : the event package
- refresh type : it distinguishes between the two different types of events
									that can trigger a refresh: 
									
									
									a change in watchers authentication: refresh type= 0 ;
									
									
									a statical update in published state (either through direct 
									update in db table or by modifying the pidf manipulation document,
									if pidf_manipulation parameter is set): refresh type!= 0.


MI FIFO Command Format:


```c
		:refreshWatchers:fifo_reply
		sip:11@192.168.2.132
		presence
		1
		_empty_line_
		
```


### Installation


The module requires 3 table in OpenSIPS database: presentity,
	active_watchers and watchers tables. The SQL 
	syntax to create them can be found in presence-create.sql     
	script in the database directories in the opensips/scripts folder.
	You can also find the complete database documentation on the
	project webpage, [http://www.opensips.org/html/docs/db/db-schema-1.4.x.html](http://www.opensips.org/html/docs/db/db-schema-1.4.x.html).


## Developer Guide


The module provides the following functions that can be used
		in other OpenSIPS modules.


### bind_presence(presence_api_t* api)


This function binds the presence modules and fills the structure 
				with one exported function -> add_event, which when called adds a 
				new event to be handled by presence.


```c title="presence_api_t structure"
...
typedef struct presence_api {
	add_event_t add_event;
	contains_event_t contains_event;
	search_event_t search_event;
	get_event_list_t get_event_list;
	
	update_watchers_t update_watchers_status;
	
	/* subs hash table handling functions */
	new_shtable_t new_shtable;
	destroy_shtable_t destroy_shtable;
	insert_shtable_t insert_shtable;
	search_shtable_t search_shtable;
	delete_shtable_t delete_shtable;
	update_shtable_t update_shtable;
	/* function to duplicate a subs structure*/
	mem_copy_subs_t  mem_copy_subs;
	/* function used for update in database*/
	update_db_subs_t update_db_subs;
	/* function to extract dialog information from a
	SUBSCRIBE message */
	extract_sdialog_info_t extract_sdialog_info;
	/* function to request sphere defition for a presentity */
	pres_get_sphere_t get_sphere;

}presence_api_t;
...
```


### add_event


Field type:


```c
...
typedef int (*add_event_t)(pres_ev_t* event);
...
```


This function receives as a parameter a structure with event specific
			information and adds it to presence event list.


The structure received as a parameter:


```c
...
typedef struct pres_ev
{
	str name;
	event_t* evp;
	str content_type;
	int default_expires;
	int type;
	int etag_not_new;
	/*
	 *  0 - the standard mechanism (allocating new etag
			for each Publish)
	 *  1 - allocating an etag only
			for an initial Publish 
	*/
	int req_auth;
	get_rules_doc_t* get_rules_doc;
	apply_auth_t*  apply_auth_nbody;
	is_allowed_t*  get_auth_status;
	
	/* an agg_body_t function should be registered
	 * if the event permits having multiple published
	 * states and requires an aggregation of the information
	 * otherwise, this field should be NULL and the last
	 * published state is taken when constructing Notify msg
	 */
	agg_nbody_t* agg_nbody;
	publ_handling_t  * evs_publ_handl;
	subs_handling_t  * evs_subs_handl;
	free_body_t* free_body;
	struct pres_ev* wipeer;			
	struct pres_ev* next;
	
}pres_ev_t;
...
```


### get_rules_doc


Filed type:


```c
...
typedef int (get_rules_doc_t)(str* user, str* domain, str** rules_doc);
...
			
```


This function returns the authorization rules document that will be
		used in obtaining the status of the subscription and processing the
		notified body. A reference to the document should be put in the 
		auth_rules_doc of the subs_t structure given as a parameter to the
		functions described bellow.


### get_auth_status


This filed is a function to be called for a subscription request
			to return the state for that subscription according to
			authorization rules. In the auth_rules_doc field of the subs_t
			structure received as a parameter should contain the rules 
			document of the presentity in case, if it exists.


It is called only if the req_auth field is not 0.


Filed type:


```c
...
typedef int (is_allowed_t)(struct subscription* subs);
...
			
```


### apply_auth_nbody


This parameter should be a function to be called for an event 
			that requires authorization, when constructing final body. 
			The authorization document is taken from the auth_rules_doc
			field of the subs_t structure given as a parameter.
			It is called only if the req_auth field is not 0.


Filed type:


```c
...
typedef int (apply_auth_t)(str* , struct subscription*, str** );
...
			
```


### agg_nbody


If present, this field marks that the events requires aggregation
			of states. This function receives a body array and should return
			the final body.	If not present, it is considered that the event
			does not require aggregation and the most recent published
			information is used when constructing Notifies.


Filed type:


```c
...
typedef str* (agg_nbody_t)(str* pres_user, str* pres_domain, 
str** body_array, int n, int off_index);
..
			
```


### free_body


This field must be field in if subsequent processing is performed
			on the info from database before being inserted in Notify
			message body(if agg_nbody or apply_auth_nbody fields are
			filled in). It should match the allocation function used when
			processing the body.


Filed type:


```c
...
typedef void(free_body_t)(char* body);
..
			
```


### evs_publ_handl


This function is called when handling Publish requests. Most contain 
		body correctness check.


```c
...
typedef int (publ_handling_t)(struct sip_msg*);
..
			
```


### evs_subs_handl


It is not compulsory. Should contain event specific handling for
		Subscription requests.


Filed type:


```c
...
typedef int (subs_handling_t)(struct sip_msg*);
..
```


### contains_event


Field type:


```c
..
typedef pres_ev_t* (*contains_event_t)(str* name,
event_t* parsed_event);
...
```


The function parses the event name received as a parameter and searches
	the result in the list. It returns the found event or NULL, if not found. 
	If the second argument is an allocated event_t* structure it fills it
	with the result of the parsing.


### get_event_list


Field type:


```c
...
typedef int (*get_event_list_t) (str** ev_list);
...
```


This function returns a string representation of the events registered
	in presence module.( used for Allowed-Events header).


### update_watchers_status


Field type:


```c
...
typedef int (*update_watchers_t)(str pres_uri, pres_ev_t* ev,
str* rules_doc);
...
```


This function is an external command that can be used to announce a change
	in authorization rules for a presentity. It updates the stored status and
	sends a Notify to the watchers whose status has changes. (used by
	presence_xml module when notified through an MI command of a change in
	an xcap document).


### get_sphere


Field type:


```c
...
typedef char* (*pres_get_sphere_t)(str* pres_uri);
...
```


This function searches for a sphere definition in the published information
	if this has type RPID. If not found returns NULL. (the return value is
	allocated in private memory and should be freed)
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
